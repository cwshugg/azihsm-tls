//! Authority initialization, recovery, validation, issuance, and quarantine.

use crate::cert::{CertificateBacking, certificate_not_after};
use crate::cli::{InitArgs, InitMode, ServeArgs};
use crate::crypto::{hash_sha256, random};
use crate::csr::ParsedCsr;
use crate::encoding::{canonical_json, is_lower_hex_32};
use crate::error::{Error, ErrorClass, Result};
use crate::policy::CLOCK_SKEW_SECONDS;
use crate::state::{
    AuditRecord, Authority, CompleteRecord, IdempotencyRecord, InitGeneration, InitPhase,
    InitPublication, IssuanceCommit, IssuanceIntent, IssuanceRecord, RootSigningIntent,
    SCHEMA_VERSION, SerialReservation, StateLock, append_audit, create_protected_dir,
    durable_bytes, durable_json, finalize_pending_publication, hex, numbered_json_entries,
    parse_utc, pending_entries, publish_state_format, read_bounded, read_json,
    read_pending_publication, utc_now, validate_state_dir, validate_state_format,
};
use crate::win::crypt32::{
    CertContext, spki_der_from_blob, verify_certificate_signature, verify_exclusive_chain,
};
use azihsm_ncrypt::{AzihsmKey, AzihsmProvider, E_UNEXPECTED_STATUS};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const AUTHORITY_CAP: usize = 64 * 1024;
const ROOT_CAP: usize = 64 * 1024;
const JOURNAL_CAP: usize = 64 * 1024;

#[derive(Debug)]
pub struct LoadedAuthority {
    pub state_dir: PathBuf,
    pub authority: Authority,
    pub root_der: Vec<u8>,
    pub key: AzihsmKey,
}

#[derive(Debug)]
pub struct Issued {
    pub status: u16,
    pub issuance_id: String,
    pub certificate: Vec<u8>,
}

pub fn initialize(args: InitArgs) -> Result<()> {
    let recover = matches!(
        &args.mode,
        InitMode::Fresh { .. } | InitMode::Reconcile { .. }
    );
    let result = match args.mode {
        InitMode::Fresh {
            provider,
            key_name,
            root_valid_days,
        } => {
            let _lock = StateLock::acquire(&args.state_dir, true)?;
            fresh_init(&args.state_dir, provider, key_name, root_valid_days)
        }
        InitMode::Reconcile { operation_id } => {
            validate_state_format(&args.state_dir)?;
            let _lock = StateLock::acquire(&args.state_dir, false)?;
            reconcile(&args.state_dir, &operation_id)
        }
        InitMode::Abandon { operation_id } => {
            validate_state_format(&args.state_dir)?;
            let _lock = StateLock::acquire(&args.state_dir, false)?;
            abandon(&args.state_dir, &operation_id)
        }
    };
    finish_initialization(
        result,
        recover,
        crate::logging::enabled(),
        || -> Result<(Authority, (usize, usize, usize))> {
            let authority: Authority =
                read_json(&args.state_dir.join("authority.json"), AUTHORITY_CAP)?;
            Ok((authority, recovery_counts(&args.state_dir)?))
        },
    )
}

fn finish_initialization<F>(
    result: Result<()>,
    recover: bool,
    logging_enabled: bool,
    enrich: F,
) -> Result<()>
where
    F: FnOnce() -> Result<(Authority, (usize, usize, usize))>,
{
    result?;
    if logging_enabled {
        tracing::info!(
            event = "state_format_validated",
            version = crate::state::STATE_FORMAT_VERSION,
            producer = crate::state::STATE_PRODUCER
        );
        if recover && let Ok((authority, (issuances, reservations, audits))) = enrich() {
            tracing::info!(
                event = "recovery_completed",
                authority_id = authority.authority_id,
                completed_issuances = issuances,
                serial_reservations = reservations,
                audit_records = audits
            );
        }
    }
    Ok(())
}

fn fresh_init(
    state_dir: &Path,
    provider_name: String,
    key_name: String,
    root_valid_days: u16,
) -> Result<()> {
    if state_dir.join("authority.json").exists() || state_dir.join("root.der").exists() {
        return Err(Error::new(
            ErrorClass::AlreadyInitialized,
            "authority state already exists",
        ));
    }
    let active = state_dir.join("init-intents").join("active");
    if numbered_json_entries(&active)?
        .iter()
        .any(|entry| entry.is_dir())
    {
        return Err(Error::new(
            ErrorClass::PendingInitialization,
            "an active initialization journal requires operator action",
        ));
    }
    assert_empty_product_namespaces(state_dir)?;
    publish_state_format(state_dir)?;
    let provider = AzihsmProvider::open_named(&provider_name)?;
    provider.require_absent(&key_name)?;
    let operation_id = hex(&random::<16>()?);
    let journal = active.join(&operation_id);
    create_protected_dir(&journal)?;
    let mut writer = JournalWriter::new(
        journal.clone(),
        operation_id.clone(),
        provider_name.clone(),
        key_name.clone(),
        root_valid_days,
    );
    writer.append(InitPhase::Prepared, None, None)?;
    let key = provider.create_named_staged(&key_name)?;
    writer.append(InitPhase::FinalizeStarted, None, None)?;
    let finalize_status = key.finalize();
    if finalize_status < 0 {
        let phase = if finalize_status == E_UNEXPECTED_STATUS {
            InitPhase::FinalizeUnexpected
        } else {
            InitPhase::FinalizeFailed
        };
        let reopen = provider
            .open_key(&key_name)
            .map(|_| "exact-name reopen succeeded".to_owned())
            .unwrap_or_else(|status| format!("exact-name reopen status 0x{:08x}", status as u32));
        writer.append(phase, Some(finalize_status), Some(reopen))?;
        return Err(Error::new(
            ErrorClass::PendingInitialization,
            "named-key finalization failed without trustworthy ownership attribution; preserve evidence and use a new key name and state directory",
        ));
    }
    writer.append(InitPhase::FinalizeSucceeded, Some(finalize_status), None)?;
    key.kat()?;
    let public_blob = key.public_blob()?;
    writer.append(
        InitPhase::KeyValidated,
        None,
        Some(hex(&hash_sha256(&public_blob)?)),
    )?;
    let root_intent = create_root_signing_intent(
        &operation_id,
        &provider_name,
        &key_name,
        root_valid_days,
        &public_blob,
    )?;
    durable_json(&journal.join("root-signing.json"), &root_intent)?;
    writer.append(InitPhase::RootSigningPrepared, None, None)?;
    let root_der = ensure_journal_root(&journal, &root_intent, &key, &public_blob)?;
    let publication = create_init_publication(&root_intent, &root_der, &public_blob)?;
    let publication_bytes = durable_json(&journal.join("publication.json"), &publication)?;
    writer.append(
        InitPhase::RootValidated,
        None,
        Some(hex(&hash_sha256(&publication_bytes)?)),
    )?;
    publish_init_transaction(state_dir, &publication, &key)?;
    writer.append(InitPhase::AuthorityPublished, None, None)?;
    writer.append(InitPhase::Completed, None, None)?;
    ensure_initialization_audit(state_dir, &publication.authority)?;
    archive_journal(state_dir, &operation_id, "completed")
}

fn reconcile(state_dir: &Path, operation_id: &str) -> Result<()> {
    let mut generations = validate_journal(state_dir, operation_id)?;
    if !generations
        .iter()
        .any(|generation| generation.phase == InitPhase::FinalizeSucceeded)
    {
        return Err(Error::new(
            ErrorClass::Precondition,
            "reconcile requires documented successful finalization",
        ));
    }
    let first = generations
        .first()
        .cloned()
        .ok_or_else(|| Error::new(ErrorClass::Precondition, "empty journal"))?;
    let last = generations
        .last()
        .cloned()
        .ok_or_else(|| Error::new(ErrorClass::Precondition, "empty journal"))?;
    let provider = AzihsmProvider::open_named(&last.provider)?;
    let key = provider.open_key(&last.key_name).map_err(|status| {
        Error::new(
            ErrorClass::Provider,
            format!(
                "reconcile key reopen failed with status 0x{:08x}",
                status as u32
            ),
        )
    })?;
    key.kat()?;
    let public_blob = key.public_blob()?;
    let journal = journal_directory(state_dir, operation_id)?;
    let mut writer = JournalWriter::resume(journal.clone(), generations.clone())?;
    let root_intent_path = journal.join("root-signing.json");
    let root_intent = if root_intent_path.exists() {
        read_json::<RootSigningIntent>(&root_intent_path, 256 * 1024)?
    } else if let Some(bytes) = read_pending_publication(&root_intent_path, 256 * 1024)? {
        if bytes.is_empty() {
            let intent = create_root_signing_intent(
                operation_id,
                &first.provider,
                &first.key_name,
                first.root_valid_days,
                &public_blob,
            )?;
            durable_json(&root_intent_path, &intent)?;
            intent
        } else {
            let intent: RootSigningIntent = serde_json::from_slice(&bytes).map_err(|error| {
                Error::new(
                    ErrorClass::State,
                    format!("invalid pending root signing intent: {error}"),
                )
            })?;
            root_backing_from_intent(&intent, operation_id, &first, &public_blob)?;
            finalize_pending_publication(&root_intent_path)?;
            intent
        }
    } else {
        if last.phase != InitPhase::KeyValidated {
            return Err(Error::new(
                ErrorClass::State,
                "root signing transaction is missing after signing became possible",
            ));
        }
        let intent = create_root_signing_intent(
            operation_id,
            &first.provider,
            &first.key_name,
            first.root_valid_days,
            &public_blob,
        )?;
        durable_json(&root_intent_path, &intent)?;
        intent
    };
    root_backing_from_intent(&root_intent, operation_id, &first, &public_blob)?;
    if generations.last().map(|value| value.phase) == Some(InitPhase::KeyValidated) {
        writer.append(InitPhase::RootSigningPrepared, None, None)?;
        generations = validate_journal(state_dir, operation_id)?;
    }
    let root_der = ensure_journal_root(&journal, &root_intent, &key, &public_blob)?;
    let publication_path = journal.join("publication.json");
    let publication = if publication_path.exists() {
        read_json::<InitPublication>(&publication_path, 256 * 1024)?
    } else if let Some(bytes) = read_pending_publication(&publication_path, 256 * 1024)? {
        if bytes.is_empty() {
            let publication = create_init_publication(&root_intent, &root_der, &public_blob)?;
            durable_json(&publication_path, &publication)?;
            publication
        } else {
            let publication: InitPublication = serde_json::from_slice(&bytes).map_err(|error| {
                Error::new(
                    ErrorClass::State,
                    format!("invalid pending initialization publication: {error}"),
                )
            })?;
            validate_init_publication(&publication, operation_id, &first, &key, &public_blob)?;
            finalize_pending_publication(&publication_path)?;
            publication
        }
    } else {
        let publication = create_init_publication(&root_intent, &root_der, &public_blob)?;
        durable_json(&publication_path, &publication)?;
        publication
    };
    validate_init_publication(&publication, operation_id, &first, &key, &public_blob)?;
    if generations.last().map(|value| value.phase) == Some(InitPhase::RootSigningPrepared) {
        let bytes = read_bounded(&publication_path, 256 * 1024)?;
        writer.append(
            InitPhase::RootValidated,
            None,
            Some(hex(&hash_sha256(&bytes)?)),
        )?;
        generations = validate_journal(state_dir, operation_id)?;
    }
    publish_init_transaction(state_dir, &publication, &key)?;
    if generations.last().map(|value| value.phase) == Some(InitPhase::RootValidated) {
        writer.append(InitPhase::AuthorityPublished, None, None)?;
        generations = validate_journal(state_dir, operation_id)?;
    }
    if generations.last().map(|value| value.phase) == Some(InitPhase::AuthorityPublished) {
        writer.append(InitPhase::Completed, None, None)?;
        generations = validate_journal(state_dir, operation_id)?;
    }
    if generations.last().map(|value| value.phase) != Some(InitPhase::Completed) {
        return Err(Error::new(
            ErrorClass::State,
            "initialization journal is not at a reconcilable terminal phase",
        ));
    }
    ensure_initialization_audit(state_dir, &publication.authority)?;
    archive_journal(state_dir, operation_id, "completed")
}

fn create_root_signing_intent(
    operation_id: &str,
    provider: &str,
    key_name: &str,
    root_valid_days: u16,
    public_blob: &[u8; 72],
) -> Result<RootSigningIntent> {
    let serial = positive_serial()?;
    let reference_time = SystemTime::now();
    let since_epoch = reference_time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::new(ErrorClass::Validation, "root time precedes Unix epoch"))?;
    let root = CertificateBacking::root(public_blob, serial, reference_time, root_valid_days)?;
    let tbs_der = root.to_be_signed_der()?;
    let spki = spki_der_from_blob(public_blob)?;
    Ok(RootSigningIntent {
        schema_version: SCHEMA_VERSION,
        operation_id: operation_id.to_owned(),
        provider: provider.to_owned(),
        key_name: key_name.to_owned(),
        root_valid_days,
        serial: serial_hex(&serial),
        reference_time_unix_seconds: since_epoch.as_secs(),
        reference_time_subsec_nanos: since_epoch.subsec_nanos(),
        public_blob_hex: hex(public_blob),
        public_key_sha256: hex(&hash_sha256(public_blob)?),
        spki_sha256: hex(&hash_sha256(&spki)?),
        tbs_der_hex: hex(&tbs_der),
        tbs_sha256: hex(&hash_sha256(&tbs_der)?),
        authority_id: hex(&random::<16>()?),
        created_at: utc_now()?,
    })
}

fn root_backing_from_intent(
    intent: &RootSigningIntent,
    operation_id: &str,
    generation: &InitGeneration,
    public_blob: &[u8; 72],
) -> Result<CertificateBacking> {
    if intent.schema_version != SCHEMA_VERSION
        || intent.operation_id != operation_id
        || intent.provider != generation.provider
        || intent.key_name != generation.key_name
        || intent.root_valid_days != generation.root_valid_days
        || intent.public_blob_hex != hex(public_blob)
        || intent.public_key_sha256 != hex(&hash_sha256(public_blob)?)
        || intent.spki_sha256 != hex(&hash_sha256(&spki_der_from_blob(public_blob)?)?)
    {
        return Err(Error::new(
            ErrorClass::Validation,
            "root signing intent does not match journal or named key",
        ));
    }
    let serial = decode_serial(&intent.serial)?;
    let reference_time = UNIX_EPOCH
        .checked_add(Duration::new(
            intent.reference_time_unix_seconds,
            intent.reference_time_subsec_nanos,
        ))
        .ok_or_else(|| Error::new(ErrorClass::Validation, "root reference time overflow"))?;
    let backing =
        CertificateBacking::root(public_blob, serial, reference_time, intent.root_valid_days)?;
    let tbs = backing.to_be_signed_der()?;
    if intent.tbs_der_hex != hex(&tbs) || intent.tbs_sha256 != hex(&hash_sha256(&tbs)?) {
        return Err(Error::new(
            ErrorClass::Validation,
            "root signing intent TBS binding mismatch",
        ));
    }
    parse_utc(&intent.created_at)?;
    Ok(backing)
}

fn ensure_journal_root(
    journal: &Path,
    intent: &RootSigningIntent,
    key: &AzihsmKey,
    public_blob: &[u8; 72],
) -> Result<Vec<u8>> {
    let generation = InitGeneration {
        schema_version: SCHEMA_VERSION,
        operation_id: intent.operation_id.clone(),
        sequence: 0,
        phase: InitPhase::RootSigningPrepared,
        prior_sha256: None,
        provider: intent.provider.clone(),
        key_name: intent.key_name.clone(),
        root_valid_days: intent.root_valid_days,
        utc: intent.created_at.clone(),
        ncrypt_status: None,
        evidence: None,
    };
    let backing = root_backing_from_intent(intent, &intent.operation_id, &generation, public_blob)?;
    let root_path = journal.join("root.der");
    if root_path.exists() {
        let root_der = read_bounded(&root_path, ROOT_CAP)?;
        validate_journal_root(&root_der, intent, key, public_blob)?;
        return Ok(root_der);
    }
    if let Some(pending) = read_pending_publication(&root_path, ROOT_CAP)?
        && !pending.is_empty()
    {
        validate_journal_root(&pending, intent, key, public_blob)?;
        finalize_pending_publication(&root_path)?;
        return Ok(pending);
    }
    let root_der = backing.sign(key)?;
    validate_journal_root(&root_der, intent, key, public_blob)?;
    durable_bytes(&root_path, &root_der)?;
    Ok(root_der)
}

fn validate_journal_root(
    root_der: &[u8],
    intent: &RootSigningIntent,
    key: &AzihsmKey,
    public_blob: &[u8; 72],
) -> Result<()> {
    let tbs = crate::cert::certificate_tbs(root_der)?;
    if hex(&tbs) != intent.tbs_der_hex || hex(&hash_sha256(&tbs)?) != intent.tbs_sha256 {
        return Err(Error::new(
            ErrorClass::Validation,
            "journal root does not match the persisted TBS transaction",
        ));
    }
    key.kat()?;
    let root_context = CertContext::create(root_der)?;
    root_context.validate_p256_public_blob(public_blob)?;
    verify_certificate_signature(root_der, &root_context)
}

fn create_init_publication(
    intent: &RootSigningIntent,
    root_der: &[u8],
    public_blob: &[u8; 72],
) -> Result<InitPublication> {
    let reference_time = UNIX_EPOCH
        .checked_add(Duration::new(
            intent.reference_time_unix_seconds,
            intent.reference_time_subsec_nanos,
        ))
        .ok_or_else(|| Error::new(ErrorClass::Validation, "root reference time overflow"))?;
    let root_context = CertContext::create(root_der)?;
    let authority = Authority {
        schema_version: SCHEMA_VERSION,
        authority_id: intent.authority_id.clone(),
        provider: intent.provider.clone(),
        key_name: intent.key_name.clone(),
        scope: "current_user".to_owned(),
        algorithm: "ECDSA_P256".to_owned(),
        signature_oid: "1.2.840.10045.4.3.2".to_owned(),
        public_key_sha256: hex(&hash_sha256(public_blob)?),
        spki_sha256: intent.spki_sha256.clone(),
        root_sha256: hex(&hash_sha256(root_der)?),
        root_serial: intent.serial.clone(),
        root_subject: "CN=AziHSM Demo Root".to_owned(),
        root_subject_der_hex: hex(root_context.subject()?),
        root_ski_hex: hex(&root_context.subject_key_identifier()?),
        not_before: time_from_system(
            reference_time
                .checked_sub(Duration::from_secs(CLOCK_SKEW_SECONDS as u64))
                .ok_or_else(|| Error::new(ErrorClass::Validation, "root time underflow"))?,
        )?,
        not_after: time_from_system(
            reference_time
                .checked_add(Duration::from_secs(
                    u64::from(intent.root_valid_days) * 86_400,
                ))
                .ok_or_else(|| Error::new(ErrorClass::Validation, "root time overflow"))?,
        )?,
        profile: "azihsm-demo-root-v1".to_owned(),
        init_operation_id: intent.operation_id.clone(),
        created_at: intent.created_at.clone(),
    };
    Ok(InitPublication {
        schema_version: SCHEMA_VERSION,
        operation_id: intent.operation_id.clone(),
        root_der_hex: hex(root_der),
        root_sha256: authority.root_sha256.clone(),
        authority,
    })
}

fn decode_serial(value: &str) -> Result<[u8; 16]> {
    let bytes = decode_hex_vec(value)?;
    if bytes.len() != 16 {
        return Err(Error::new(
            ErrorClass::Validation,
            "root serial must be exactly 128 bits",
        ));
    }
    let mut serial = [0_u8; 16];
    for (destination, source) in serial.iter_mut().zip(bytes.into_iter().rev()) {
        *destination = source;
    }
    Ok(serial)
}

fn validate_init_publication(
    publication: &InitPublication,
    operation_id: &str,
    generation: &InitGeneration,
    key: &AzihsmKey,
    public_blob: &[u8; 72],
) -> Result<()> {
    if publication.schema_version != SCHEMA_VERSION
        || publication.operation_id != operation_id
        || publication.authority.init_operation_id != operation_id
        || publication.authority.provider != generation.provider
        || publication.authority.key_name != generation.key_name
        || publication.authority.root_sha256 != publication.root_sha256
        || publication.authority.public_key_sha256 != hex(&hash_sha256(public_blob)?)
        || publication.authority.spki_sha256
            != hex(&hash_sha256(&spki_der_from_blob(public_blob)?)?)
    {
        return Err(Error::new(
            ErrorClass::Validation,
            "initialization publication does not match journal or named key",
        ));
    }
    key.kat()?;
    let root_der = decode_hex_vec(&publication.root_der_hex)?;
    if hex(&hash_sha256(&root_der)?) != publication.root_sha256 {
        return Err(Error::new(
            ErrorClass::Validation,
            "journal-bound root hash mismatch",
        ));
    }
    let root = CertContext::create(&root_der)?;
    root.validate_p256_public_blob(public_blob)?;
    verify_certificate_signature(&root_der, &root)?;
    validate_authority_fields(&publication.authority)?;
    Ok(())
}

fn publish_init_transaction(
    state_dir: &Path,
    publication: &InitPublication,
    key: &AzihsmKey,
) -> Result<()> {
    let public_blob = key.public_blob()?;
    let generation = InitGeneration {
        schema_version: SCHEMA_VERSION,
        operation_id: publication.operation_id.clone(),
        sequence: 0,
        phase: InitPhase::RootValidated,
        prior_sha256: None,
        provider: publication.authority.provider.clone(),
        key_name: publication.authority.key_name.clone(),
        root_valid_days: 30,
        utc: publication.authority.created_at.clone(),
        ncrypt_status: None,
        evidence: None,
    };
    validate_init_publication(
        publication,
        &publication.operation_id,
        &generation,
        key,
        &public_blob,
    )?;
    let root_der = decode_hex_vec(&publication.root_der_hex)?;
    publish_exact_or_validate(&state_dir.join("root.der"), &root_der)?;
    let authority_bytes = canonical_json(&publication.authority, "authority")?;
    publish_exact_or_validate(&state_dir.join("authority.json"), &authority_bytes)
}

fn publish_exact_or_validate(path: &Path, bytes: &[u8]) -> Result<()> {
    if path.exists() {
        if read_bounded(path, bytes.len().max(1))? != bytes {
            return Err(Error::new(
                ErrorClass::Validation,
                "partial initialization publication was substituted",
            ));
        }
        return Ok(());
    }
    durable_bytes(path, bytes)
}

fn decode_hex_vec(value: &str) -> Result<Vec<u8>> {
    if !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Error::new(
            ErrorClass::State,
            "noncanonical encoded root bytes",
        ));
    }
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16)
                .map_err(|_| Error::new(ErrorClass::State, "invalid encoded root bytes"))
        })
        .collect()
}

fn abandon(state_dir: &Path, operation_id: &str) -> Result<()> {
    let generations = validate_journal(state_dir, operation_id)?;
    if generations.iter().any(|generation| {
        matches!(
            generation.phase,
            InitPhase::FinalizeSucceeded
                | InitPhase::FinalizeUnexpected
                | InitPhase::KeyValidated
                | InitPhase::RootValidated
                | InitPhase::AuthorityPublished
                | InitPhase::Completed
                | InitPhase::AbandonVerified
                | InitPhase::Abandoned
        )
    }) {
        return Err(Error::new(
            ErrorClass::Precondition,
            "journal evidence forbids abandonment",
        ));
    }
    if state_dir.join("authority.json").exists() || state_dir.join("root.der").exists() {
        return Err(Error::new(
            ErrorClass::Precondition,
            "authority publication forbids abandonment",
        ));
    }
    assert_empty_product_namespaces(state_dir)?;
    let last = generations
        .last()
        .ok_or_else(|| Error::new(ErrorClass::Precondition, "empty journal"))?;
    let provider = AzihsmProvider::open_named(&last.provider)?;
    provider.require_absent(&last.key_name)?;
    let mut writer = JournalWriter::resume(
        state_dir
            .join("init-intents")
            .join("active")
            .join(operation_id),
        generations,
    )?;
    writer.append(
        InitPhase::AbandonVerified,
        Some(windows_sys::Win32::Foundation::NTE_BAD_KEYSET),
        Some("exact current-user key absence proved".to_owned()),
    )?;
    writer.append(InitPhase::Abandoned, None, None)?;
    append_audit(
        state_dir,
        AuditRecord {
            schema_version: SCHEMA_VERSION,
            sequence: 0,
            prior_sha256: None,
            kind: "init_abandoned".to_owned(),
            authority_id: None,
            issuance_id: None,
            operation_id: Some(operation_id.to_owned()),
            source_ip: None,
            outcome: "accepted".to_owned(),
            detail: "key absence proved; no key or state deleted".to_owned(),
            utc: utc_now()?,
        },
    )?;
    archive_journal(state_dir, operation_id, "abandoned")
}

pub fn load(state_dir: &Path) -> Result<LoadedAuthority> {
    let loaded = load_for_serve(state_dir)?;
    full_scan(state_dir, &loaded.authority)?;
    Ok(loaded)
}

pub fn load_for_serve(state_dir: &Path) -> Result<LoadedAuthority> {
    validate_state_format(state_dir)?;
    let authority: Authority = read_json(&state_dir.join("authority.json"), AUTHORITY_CAP)?;
    validate_authority_fields(&authority)?;
    let root_der = read_bounded(&state_dir.join("root.der"), ROOT_CAP)?;
    if hex(&hash_sha256(&root_der)?) != authority.root_sha256 {
        return Err(Error::new(
            ErrorClass::Validation,
            "root hash does not match authority state",
        ));
    }

    let provider = AzihsmProvider::open_named(&authority.provider)?;
    let key = provider.open_key(&authority.key_name).map_err(|status| {
        Error::new(
            ErrorClass::Provider,
            format!("named authority key unavailable: 0x{:08x}", status as u32),
        )
    })?;
    key.kat()?;
    let public_blob = key.public_blob()?;
    if hex(&hash_sha256(&public_blob)?) != authority.public_key_sha256
        || hex(&hash_sha256(&spki_der_from_blob(&public_blob)?)?) != authority.spki_sha256
    {
        return Err(Error::new(
            ErrorClass::Validation,
            "named key identity does not match authority state",
        ));
    }
    let root_context = CertContext::create(&root_der)?;
    if hex(root_context.subject()?) != authority.root_subject_der_hex
        || hex(&root_context.subject_key_identifier()?) != authority.root_ski_hex
    {
        return Err(Error::new(
            ErrorClass::Validation,
            "persisted root subject or SKI does not match root.der",
        ));
    }
    root_context.validate_p256_public_blob(&public_blob)?;
    verify_certificate_signature(&root_der, &root_context)?;
    let generations = validate_journal(state_dir, &authority.init_operation_id)?;
    let first = generations
        .first()
        .ok_or_else(|| Error::new(ErrorClass::Validation, "initialization journal is empty"))?;
    let journal = journal_directory(state_dir, &authority.init_operation_id)?;
    let root_intent: RootSigningIntent = read_json(&journal.join("root-signing.json"), 256 * 1024)?;
    let reconstructed = root_backing_from_intent(
        &root_intent,
        &authority.init_operation_id,
        first,
        &public_blob,
    )?;
    if reconstructed.to_be_signed_der()? != crate::cert::certificate_tbs(&root_der)? {
        return Err(Error::new(
            ErrorClass::Validation,
            "reconstructed root TBSCertificate does not match root.der",
        ));
    }
    Ok(LoadedAuthority {
        state_dir: state_dir.to_path_buf(),
        authority,
        root_der,
        key,
    })
}

pub fn revalidate(loaded: &LoadedAuthority) -> Result<()> {
    validate_state_dir(&loaded.state_dir)?;
    validate_state_format(&loaded.state_dir)?;
    let authority: Authority = read_json(&loaded.state_dir.join("authority.json"), AUTHORITY_CAP)?;
    if authority != loaded.authority {
        return Err(Error::new(
            ErrorClass::Validation,
            "runtime authority state changed",
        ));
    }
    let root_der = read_bounded(&loaded.state_dir.join("root.der"), ROOT_CAP)?;
    if root_der != loaded.root_der || hex(&hash_sha256(&root_der)?) != loaded.authority.root_sha256
    {
        return Err(Error::new(
            ErrorClass::Validation,
            "runtime root state changed",
        ));
    }
    loaded.key.kat()?;
    let public_blob = loaded.key.public_blob()?;
    if hex(&hash_sha256(&public_blob)?) != loaded.authority.public_key_sha256 {
        return Err(Error::new(
            ErrorClass::Validation,
            "runtime named-key identity changed",
        ));
    }
    full_scan(&loaded.state_dir, &loaded.authority)
}

pub fn inspect(state_dir: &Path) -> Result<String> {
    validate_state_format(state_dir)?;
    let _lock = StateLock::acquire(state_dir, false)?;
    let loaded = load(state_dir)?;
    let completed = completed_issuance_ids(state_dir)?.len();
    let reservations = numbered_json_entries(&state_dir.join("serial-reservations"))?.len();
    let audit = numbered_json_entries(&state_dir.join("audit"))?.len();
    serde_json::to_string_pretty(&serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "authority_id": loaded.authority.authority_id,
        "key_name": loaded.authority.key_name,
        "root_sha256": loaded.authority.root_sha256,
        "spki_sha256": loaded.authority.spki_sha256,
        "completed_issuances": completed,
        "serial_reservations": reservations,
        "audit_records": audit,
        "ready": true
    }))
    .map(|value| format!("{value}\n"))
    .map_err(|error| Error::new(ErrorClass::State, format!("inspect output failed: {error}")))
}

pub(crate) fn recovery_counts(state_dir: &Path) -> Result<(usize, usize, usize)> {
    Ok((
        completed_issuance_ids(state_dir)?.len(),
        numbered_json_entries(&state_dir.join("serial-reservations"))?.len(),
        numbered_json_entries(&state_dir.join("audit"))?.len(),
    ))
}

pub fn issue(
    loaded: &LoadedAuthority,
    policy: &ServeArgs,
    parsed: &ParsedCsr,
    csr: &[u8],
    idempotency_key: &str,
    source_ip: &str,
) -> Result<Issued> {
    let idempotency_hash = hex(&hash_sha256(idempotency_key.as_bytes())?);
    let csr_hash = hex(&hash_sha256(csr)?);
    let request_hash = hex(&hash_sha256(
        format!(
            "{}:{}:{}",
            loaded.authority.authority_id, csr_hash, "server-auth-v1"
        )
        .as_bytes(),
    )?);
    let mapping_path = loaded
        .state_dir
        .join("idempotency")
        .join(format!("{idempotency_hash}.json"));
    if mapping_path.exists() {
        let mapping: IdempotencyRecord = read_json(&mapping_path, 64 * 1024)?;
        if mapping.request_hash != request_hash {
            return Err(Error::new(ErrorClass::Precondition, "idempotency_conflict"));
        }
        let certificate = read_completed_certificate(
            &loaded.state_dir,
            &mapping.issuance_id,
            &mapping.certificate_sha256,
        )?;
        return Ok(Issued {
            status: 200,
            issuance_id: mapping.issuance_id,
            certificate,
        });
    }
    if let Some(existing) =
        find_issuance_by_idempotency(&loaded.state_dir, &idempotency_hash, &request_hash)?
    {
        recover_issuance_commit(&loaded.state_dir, &existing, &loaded.authority)?;
        let mapping: IdempotencyRecord = read_json(&mapping_path, 64 * 1024)?;
        let certificate = read_completed_certificate(
            &loaded.state_dir,
            &mapping.issuance_id,
            &mapping.certificate_sha256,
        )?;
        return Ok(Issued {
            status: 200,
            issuance_id: mapping.issuance_id,
            certificate,
        });
    }
    let issuance_id = unique_id(&loaded.state_dir.join("issuances"))?;
    let serial = unique_serial(&loaded.state_dir)?;
    let serial_text = serial_hex(&serial);
    let created_at = utc_now()?;
    let issuance_dir = loaded.state_dir.join("issuances").join(&issuance_id);
    create_protected_dir(&issuance_dir)?;
    let now = SystemTime::now();
    let persisted_root_expiry = certificate_not_after(&loaded.root_der)?;
    if persisted_root_expiry != parse_utc(&loaded.authority.not_after)? {
        return Err(Error::new(
            ErrorClass::Validation,
            "persisted root notAfter does not match authority state",
        ));
    }
    let (not_before_system, not_after_system) =
        leaf_validity_interval(now, policy.leaf_valid_hours, persisted_root_expiry)?;
    let root_context = CertContext::create(&loaded.root_der)?;
    let root_ski = root_context.subject_key_identifier()?;
    let backing = CertificateBacking::leaf(
        &parsed.public_blob,
        serial,
        &root_ski,
        not_before_system,
        not_after_system,
        &parsed.dns_sans,
        &parsed.ip_sans,
    )?;
    let intent = IssuanceIntent {
        schema_version: SCHEMA_VERSION,
        issuance_id: issuance_id.clone(),
        authority_id: loaded.authority.authority_id.clone(),
        serial: serial_text.clone(),
        correlation_id: hex(&random::<16>()?),
        idempotency_key_hash: idempotency_hash.clone(),
        request_hash: request_hash.clone(),
        csr_sha256: csr_hash,
        spki_sha256: parsed.spki_sha256.clone(),
        dns_sans: parsed.dns_sans.clone(),
        ip_sans: parsed.ip_sans.iter().map(ToString::to_string).collect(),
        not_before: time_from_system(not_before_system)?,
        not_after: time_from_system(not_after_system)?,
        profile: "server-auth-v1".to_owned(),
        created_at: created_at.clone(),
    };
    let intent_bytes = durable_json(&issuance_dir.join("intent.json"), &intent)?;
    durable_json(
        &loaded
            .state_dir
            .join("serial-reservations")
            .join(format!("{serial_text}.json")),
        &SerialReservation {
            schema_version: SCHEMA_VERSION,
            serial: serial_text.clone(),
            issuance_id: issuance_id.clone(),
            authority_id: loaded.authority.authority_id.clone(),
            created_at: created_at.clone(),
        },
    )?;
    let certificate = backing.sign(&loaded.key)?;
    let leaf_context = CertContext::create(&certificate)?;
    leaf_context.validate_p256_public_blob(&parsed.public_blob)?;
    verify_certificate_signature(&certificate, &root_context)?;
    verify_exclusive_chain(&root_context, &leaf_context, &loaded.root_der, &certificate)?;
    durable_bytes(&issuance_dir.join("certificate.der"), &certificate)?;
    let certificate_hash = hex(&hash_sha256(&certificate)?);
    let record = IssuanceRecord {
        schema_version: SCHEMA_VERSION,
        issuance_id: issuance_id.clone(),
        authority_id: loaded.authority.authority_id.clone(),
        serial: serial_text,
        certificate_sha256: certificate_hash.clone(),
        certificate_size: certificate.len(),
        not_before: intent.not_before.clone(),
        not_after: intent.not_after.clone(),
        status: "issued".to_owned(),
    };
    let record_bytes = durable_json(&issuance_dir.join("record.json"), &record)?;
    let mapping = IdempotencyRecord {
        schema_version: SCHEMA_VERSION,
        key_hash: idempotency_hash,
        request_hash,
        issuance_id: issuance_id.clone(),
        certificate_sha256: certificate_hash.clone(),
        created_at: created_at.clone(),
    };
    durable_json(
        &issuance_dir.join("commit.json"),
        &IssuanceCommit {
            schema_version: SCHEMA_VERSION,
            issuance_id: issuance_id.clone(),
            authority_id: loaded.authority.authority_id.clone(),
            idempotency: mapping,
            source_ip: source_ip.to_owned(),
            created_at,
        },
    )?;
    durable_json(
        &issuance_dir.join("COMPLETE"),
        &CompleteRecord {
            schema_version: SCHEMA_VERSION,
            issuance_id: issuance_id.clone(),
            authority_id: loaded.authority.authority_id.clone(),
            intent_sha256: hex(&hash_sha256(&intent_bytes)?),
            certificate_sha256: certificate_hash,
            record_sha256: hex(&hash_sha256(&record_bytes)?),
        },
    )?;
    recover_issuance_commit(&loaded.state_dir, &issuance_dir, &loaded.authority)?;
    Ok(Issued {
        status: 201,
        issuance_id,
        certificate,
    })
}

pub fn quarantine(state_dir: &Path, issuance_id: &str) -> Result<()> {
    validate_state_format(state_dir)?;
    let _lock = StateLock::acquire(state_dir, false)?;
    let loaded = load(state_dir).or_else(|error| {
        if error.exit_code() == ErrorClass::StateBusy as u8 {
            Err(error)
        } else {
            let authority: Authority = read_json(&state_dir.join("authority.json"), AUTHORITY_CAP)?;
            let root_der = read_bounded(&state_dir.join("root.der"), ROOT_CAP)?;
            let provider = AzihsmProvider::open_named(&authority.provider)?;
            let key = provider.open_key(&authority.key_name).map_err(|status| {
                Error::new(
                    ErrorClass::Provider,
                    format!("authority key unavailable: 0x{:08x}", status as u32),
                )
            })?;
            Ok(LoadedAuthority {
                state_dir: state_dir.to_path_buf(),
                authority,
                root_der,
                key,
            })
        }
    })?;
    let source = state_dir.join("issuances").join(issuance_id);
    if source.join("COMPLETE").exists() {
        return Err(Error::new(
            ErrorClass::Precondition,
            "quarantine requires an incomplete issuance",
        ));
    }
    let intent_path = source.join("intent.json");
    let intent = if intent_path.exists() {
        Some(read_json::<IssuanceIntent>(&intent_path, 64 * 1024)?)
    } else {
        read_pending_publication(&intent_path, 64 * 1024)?
            .filter(|bytes| !bytes.is_empty())
            .and_then(|bytes| parse_exact_json::<IssuanceIntent>(&bytes, "pending intent").ok())
    };
    if let Some(intent) = &intent
        && intent.authority_id != loaded.authority.authority_id
    {
        return Err(Error::new(
            ErrorClass::Precondition,
            "incomplete issuance belongs to a different authority",
        ));
    }
    for mapping in numbered_json_entries(&state_dir.join("idempotency"))? {
        let record: IdempotencyRecord = read_json(&mapping, 64 * 1024)?;
        if record.issuance_id == issuance_id {
            return Err(Error::new(
                ErrorClass::Precondition,
                "idempotency mapping references the incomplete issuance",
            ));
        }
    }
    let mut reservations = Vec::new();
    for path in numbered_json_entries(&state_dir.join("serial-reservations"))? {
        let reservation: SerialReservation = read_json(&path, 64 * 1024)?;
        if reservation.issuance_id == issuance_id {
            reservations.push((path, reservation));
        }
    }
    if reservations.len() > 1 {
        return Err(Error::new(
            ErrorClass::Precondition,
            "multiple serial reservations reference the incomplete issuance",
        ));
    }
    let reservation = reservations.pop();
    if let (Some(intent), Some((_, reservation))) = (&intent, &reservation)
        && (reservation.serial != intent.serial
            || reservation.authority_id != loaded.authority.authority_id)
    {
        return Err(Error::new(
            ErrorClass::Precondition,
            "serial reservation does not match incomplete issuance",
        ));
    }
    let pending_reservations = pending_entries(&state_dir.join("serial-reservations"))?;
    let mut pending_reservation = None;
    for path in &pending_reservations {
        let bytes = read_bounded(path, 64 * 1024)?;
        let belongs = serde_json::from_slice::<SerialReservation>(&bytes)
            .ok()
            .is_some_and(|value| value.issuance_id == issuance_id);
        let intent_serial_match = intent.as_ref().is_some_and(|value| {
            let expected = format!(".{}.json.pending", value.serial);
            path.file_name().and_then(|name| name.to_str()) == Some(expected.as_str())
        });
        if (belongs || intent_serial_match) && pending_reservation.replace(path.clone()).is_some() {
            return Err(Error::new(
                ErrorClass::Precondition,
                "multiple pending reservations reference the incomplete issuance",
            ));
        }
    }
    if pending_reservation.is_none()
        && intent.is_none()
        && reservation.is_none()
        && source.is_dir()
        && pending_reservations.len() == 1
    {
        pending_reservation = pending_reservations.first().cloned();
    }
    if intent.is_none()
        && reservation.is_none()
        && pending_reservation.is_none()
        && !source.is_dir()
    {
        return Err(Error::new(
            ErrorClass::Precondition,
            "no incomplete issuance or orphan reservation evidence exists",
        ));
    }
    if intent.is_none() && source.is_dir() {
        for entry in fs::read_dir(&source).map_err(|error| {
            Error::new(
                ErrorClass::State,
                format!("pre-intent issuance inspection failed: {error}"),
            )
        })? {
            let entry = entry.map_err(|error| {
                Error::new(
                    ErrorClass::State,
                    format!("pre-intent issuance entry failed: {error}"),
                )
            })?;
            let name = entry.file_name();
            let name = name
                .to_str()
                .ok_or_else(|| Error::new(ErrorClass::State, "invalid pre-intent entry name"))?;
            if !name.starts_with('.') || !name.ends_with(".pending") {
                return Err(Error::new(
                    ErrorClass::Precondition,
                    "issuance without a valid intent contains unrecognized artifacts",
                ));
            }
        }
    }
    let serial = intent
        .as_ref()
        .map(|value| value.serial.clone())
        .or_else(|| reservation.as_ref().map(|(_, value)| value.serial.clone()))
        .or_else(|| {
            pending_reservation.as_ref().and_then(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .and_then(|name| name.strip_prefix('.'))
                    .and_then(|name| name.strip_suffix(".json.pending"))
                    .map(str::to_owned)
            })
        });
    let quarantine_id = hex(&random::<16>()?);
    let destination = state_dir
        .join("abandoned-issuances")
        .join(format!("{issuance_id}-{quarantine_id}"));
    create_protected_dir(&destination)?;
    durable_json(
        &destination.join("000000-prepared.json"),
        &serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "phase": "prepared",
            "quarantine_id": quarantine_id,
            "issuance_id": issuance_id,
            "authority_id": loaded.authority.authority_id,
            "serial": serial,
            "utc": utc_now()?
        }),
    )?;
    let original = destination.join("original");
    if source.is_dir() {
        fs::rename(&source, &original).map_err(|error| {
            Error::new(
                ErrorClass::State,
                format!("quarantine move failed: {error}"),
            )
        })?;
    } else {
        create_protected_dir(&original)?;
    }
    if let Some((path, _)) = &reservation {
        durable_bytes(
            &original.join("serial-reservation.json"),
            &read_bounded(path, 64 * 1024)?,
        )?;
    }
    if let Some(pending_reservation) = &pending_reservation {
        durable_bytes(
            &original.join("serial-reservation.pending"),
            &read_bounded(pending_reservation, 64 * 1024)?,
        )?;
        fs::remove_file(pending_reservation).map_err(|error| {
            Error::new(
                ErrorClass::State,
                format!("pending reservation archive cleanup failed: {error}"),
            )
        })?;
    }
    durable_json(
        &destination.join("000001-quarantined.json"),
        &serde_json::json!({
            "schema_version": SCHEMA_VERSION,
            "phase": "quarantined",
            "quarantine_id": quarantine_id,
            "issuance_id": issuance_id,
            "authority_id": loaded.authority.authority_id,
            "utc": utc_now()?
        }),
    )?;
    append_audit(
        state_dir,
        AuditRecord {
            schema_version: SCHEMA_VERSION,
            sequence: 0,
            prior_sha256: None,
            kind: "issuance_quarantined".to_owned(),
            authority_id: Some(loaded.authority.authority_id),
            issuance_id: Some(issuance_id.to_owned()),
            operation_id: None,
            source_ip: None,
            outcome: "accepted".to_owned(),
            detail: "incomplete issuance preserved; serial remains reserved".to_owned(),
            utc: utc_now()?,
        },
    )
}

pub fn certificate_status(state_dir: &Path, issuance_id: &str) -> Result<Option<String>> {
    if !is_lower_hex_32(issuance_id) {
        return Ok(None);
    }
    let directory = state_dir.join("issuances").join(issuance_id);
    if !directory.join("COMPLETE").exists() {
        return Ok(None);
    }
    let record: IssuanceRecord = read_json(&directory.join("record.json"), 64 * 1024)?;
    let authority: Authority = read_json(&state_dir.join("authority.json"), AUTHORITY_CAP)?;
    let state = if parse_utc(&record.not_after)? < time::OffsetDateTime::now_utc() {
        "expired"
    } else {
        "issued"
    };
    let body = serde_json::json!({
        "schema_version": SCHEMA_VERSION,
        "authority_id": authority.authority_id,
        "issuance_id": record.issuance_id,
        "serial": record.serial,
        "certificate_sha256": record.certificate_sha256,
        "not_before": record.not_before,
        "not_after": record.not_after,
        "state": state,
        "revocation_supported": false,
        "assertion": "recorded_as_issued_by_this_authority"
    });
    serde_json::to_string(&body).map(Some).map_err(|error| {
        Error::new(
            ErrorClass::State,
            format!("status encoding failed: {error}"),
        )
    })
}

pub fn certificate_bytes(state_dir: &Path, issuance_id: &str) -> Result<Option<Vec<u8>>> {
    if !is_lower_hex_32(issuance_id) {
        return Ok(None);
    }
    let directory = state_dir.join("issuances").join(issuance_id);
    if !directory.join("COMPLETE").exists() {
        return Ok(None);
    }
    Ok(Some(read_bounded(
        &directory.join("certificate.der"),
        ROOT_CAP,
    )?))
}

fn recover_pending_precommit_publications(state_dir: &Path, authority: &Authority) -> Result<()> {
    for issuance_dir in numbered_json_entries(&state_dir.join("issuances"))? {
        if !issuance_dir.is_dir() {
            continue;
        }
        let issuance_id = issuance_dir
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| Error::new(ErrorClass::State, "invalid issuance directory name"))?;
        let intent_path = issuance_dir.join("intent.json");
        if !intent_path.exists()
            && let Some(bytes) = read_pending_publication(&intent_path, 64 * 1024)?
            && !bytes.is_empty()
        {
            let intent: IssuanceIntent = parse_exact_json(&bytes, "pending issuance intent")?;
            if intent.schema_version == SCHEMA_VERSION
                && intent.issuance_id == issuance_id
                && intent.authority_id == authority.authority_id
            {
                finalize_pending_publication(&intent_path)?;
            }
        }
    }
    for pending in pending_entries(&state_dir.join("serial-reservations"))? {
        let name = pending
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| Error::new(ErrorClass::State, "invalid pending reservation name"))?;
        let Some(serial) = name
            .strip_prefix('.')
            .and_then(|value| value.strip_suffix(".json.pending"))
        else {
            return Err(Error::new(
                ErrorClass::State,
                "unrecognized serial reservation staging artifact",
            ));
        };
        let bytes = read_bounded(&pending, 64 * 1024)?;
        if bytes.is_empty() {
            return Err(Error::new(
                ErrorClass::State,
                "empty serial reservation staging artifact requires quarantine",
            ));
        }
        let reservation: SerialReservation =
            parse_exact_json(&bytes, "pending serial reservation")?;
        let intent_path = state_dir
            .join("issuances")
            .join(&reservation.issuance_id)
            .join("intent.json");
        if reservation.schema_version != SCHEMA_VERSION
            || reservation.authority_id != authority.authority_id
            || reservation.serial != serial
            || !intent_path.exists()
        {
            return Err(Error::new(
                ErrorClass::Validation,
                "pending serial reservation binding mismatch",
            ));
        }
        let intent: IssuanceIntent = read_json(&intent_path, 64 * 1024)?;
        if intent.issuance_id != reservation.issuance_id || intent.serial != reservation.serial {
            return Err(Error::new(
                ErrorClass::Validation,
                "pending serial reservation does not match its intent",
            ));
        }
        finalize_pending_publication(
            &state_dir
                .join("serial-reservations")
                .join(format!("{serial}.json")),
        )?;
    }
    for issuance_dir in numbered_json_entries(&state_dir.join("issuances"))? {
        if issuance_dir.is_dir() && !pending_entries(&issuance_dir)?.is_empty() {
            return Err(Error::new(
                ErrorClass::State,
                "unresolved issuance staging artifact requires quarantine",
            ));
        }
    }
    if !pending_entries(&state_dir.join("serial-reservations"))?.is_empty() {
        return Err(Error::new(
            ErrorClass::State,
            "unresolved serial reservation staging artifact requires quarantine",
        ));
    }
    Ok(())
}

fn parse_exact_json<T>(bytes: &[u8], label: &str) -> Result<T>
where
    T: serde::de::DeserializeOwned + serde::Serialize,
{
    let value: T = serde_json::from_slice(bytes)
        .map_err(|error| Error::new(ErrorClass::State, format!("invalid {label}: {error}")))?;
    let canonical = canonical_json(&value, label)?;
    if canonical != bytes {
        return Err(Error::new(
            ErrorClass::Validation,
            format!("{label} is not the exact deterministic encoding"),
        ));
    }
    Ok(value)
}

fn full_scan(state_dir: &Path, authority: &Authority) -> Result<()> {
    let active = state_dir.join("init-intents").join("active");
    if numbered_json_entries(&active)?
        .iter()
        .any(|entry| entry.is_dir())
    {
        return Err(Error::new(
            ErrorClass::PendingInitialization,
            "active initialization journal blocks readiness",
        ));
    }
    recover_pending_precommit_publications(state_dir, authority)?;
    validate_audit_chain(state_dir)?;
    for entry in numbered_json_entries(&state_dir.join("issuances"))? {
        if !entry.is_dir() || !entry.join("commit.json").exists() {
            return Err(Error::new(
                ErrorClass::State,
                "issuance without a recoverable commit blocks readiness",
            ));
        }

        recover_issuance_commit(state_dir, &entry, authority)?;
        validate_completed_issuance(&entry, authority)?;
    }
    validate_reservations(state_dir, authority)?;
    validate_idempotency_index(state_dir, authority)?;
    validate_audit_chain(state_dir)?;
    for entry in numbered_json_entries(&state_dir.join("abandoned-issuances"))? {
        if !entry.is_dir()
            || !entry.join("original").is_dir()
            || !entry.join("000000-prepared.json").is_file()
            || !entry.join("000001-quarantined.json").is_file()
        {
            return Err(Error::new(
                ErrorClass::State,
                "partial quarantine blocks readiness",
            ));
        }
    }
    Ok(())
}

fn validate_completed_issuance(path: &Path, authority: &Authority) -> Result<()> {
    let intent_bytes = read_bounded(&path.join("intent.json"), 64 * 1024)?;
    let intent: IssuanceIntent = read_json(&path.join("intent.json"), 64 * 1024)?;
    let record_bytes = read_bounded(&path.join("record.json"), 64 * 1024)?;
    let record: IssuanceRecord = read_json(&path.join("record.json"), 64 * 1024)?;
    let complete: CompleteRecord = read_json(&path.join("COMPLETE"), 64 * 1024)?;
    let certificate = read_bounded(&path.join("certificate.der"), ROOT_CAP)?;
    if intent.authority_id != authority.authority_id
        || record.authority_id != authority.authority_id
        || complete.authority_id != authority.authority_id
        || intent.issuance_id != record.issuance_id
        || intent.issuance_id != complete.issuance_id
        || intent.serial != record.serial
        || record.certificate_size != certificate.len()
        || complete.intent_sha256 != hex(&hash_sha256(&intent_bytes)?)
        || hex(&hash_sha256(&certificate)?) != record.certificate_sha256
        || complete.certificate_sha256 != record.certificate_sha256
        || complete.record_sha256 != hex(&hash_sha256(&record_bytes)?)
    {
        return Err(Error::new(
            ErrorClass::Validation,
            "completed issuance consistency check failed",
        ));
    }
    Ok(())
}

fn validate_reservations(state_dir: &Path, authority: &Authority) -> Result<()> {
    let mut reserved_issuances = std::collections::HashSet::new();
    for path in numbered_json_entries(&state_dir.join("serial-reservations"))? {
        let reservation: SerialReservation = read_json(&path, 64 * 1024)?;
        let active_intent = state_dir
            .join("issuances")
            .join(&reservation.issuance_id)
            .join("intent.json");
        let matches = if active_intent.exists() {
            let intent: IssuanceIntent = read_json(&active_intent, 64 * 1024)?;
            reservation.serial == intent.serial && reservation.issuance_id == intent.issuance_id
        } else {
            reservation_matches_quarantine(state_dir, &reservation)?
        };
        if reservation.authority_id != authority.authority_id || !matches {
            return Err(Error::new(
                ErrorClass::Validation,
                "serial reservation does not match an active or quarantined issuance",
            ));
        }

        fn reservation_matches_quarantine(
            state_dir: &Path,
            reservation: &SerialReservation,
        ) -> Result<bool> {
            for quarantine in numbered_json_entries(&state_dir.join("abandoned-issuances"))? {
                let prepared_path = quarantine.join("000000-prepared.json");
                let completed_path = quarantine.join("000001-quarantined.json");
                if !prepared_path.exists() || !completed_path.exists() {
                    continue;
                }
                let prepared: serde_json::Value = read_json(&prepared_path, 64 * 1024)?;
                if prepared.get("issuance_id").and_then(|value| value.as_str())
                    != Some(&reservation.issuance_id)
                    || prepared.get("serial").and_then(|value| value.as_str())
                        != Some(&reservation.serial)
                {
                    continue;
                }
                let copied_path = quarantine.join("original").join("serial-reservation.json");
                if !copied_path.exists() {
                    return Ok(false);
                }
                let copied: SerialReservation = read_json(&copied_path, 64 * 1024)?;
                return Ok(copied == *reservation);
            }
            Ok(false)
        }
        if !reserved_issuances.insert(reservation.issuance_id) {
            return Err(Error::new(
                ErrorClass::Validation,
                "multiple serial reservations reference one issuance",
            ));
        }
    }
    for path in numbered_json_entries(&state_dir.join("issuances"))? {
        let issuance_id = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| Error::new(ErrorClass::Validation, "invalid issuance directory name"))?;
        if !reserved_issuances.contains(issuance_id) {
            return Err(Error::new(
                ErrorClass::Validation,
                "completed issuance has no serial reservation",
            ));
        }
    }
    Ok(())
}

fn validate_idempotency_index(state_dir: &Path, authority: &Authority) -> Result<()> {
    for path in numbered_json_entries(&state_dir.join("idempotency"))? {
        let mapping: IdempotencyRecord = read_json(&path, 64 * 1024)?;
        let commit: IssuanceCommit = read_json(
            &state_dir
                .join("issuances")
                .join(&mapping.issuance_id)
                .join("commit.json"),
            64 * 1024,
        )?;
        if commit.authority_id != authority.authority_id
            || commit.idempotency != mapping
            || path.file_stem().and_then(|name| name.to_str()) != Some(&mapping.key_hash)
        {
            return Err(Error::new(
                ErrorClass::Validation,
                "idempotency index does not match its issuance commit",
            ));
        }
    }
    Ok(())
}

fn validate_audit_chain(state_dir: &Path) -> Result<()> {
    let mut entries = numbered_json_entries(&state_dir.join("audit"))?;
    entries.sort();
    let mut prior = None;
    let mut issuance_ids = std::collections::HashSet::new();
    for (sequence, path) in entries.iter().enumerate() {
        let expected_name = format!("{sequence:020}.json");
        let bytes = read_bounded(path, 64 * 1024)?;
        let record: AuditRecord = serde_json::from_slice(&bytes).map_err(|error| {
            Error::new(
                ErrorClass::State,
                format!("invalid audit record during scan: {error}"),
            )
        })?;
        if record.sequence != sequence as u64
            || record.prior_sha256 != prior
            || path.file_name().and_then(|name| name.to_str()) != Some(expected_name.as_str())
        {
            return Err(Error::new(
                ErrorClass::Validation,
                "audit sequence or hash chain is inconsistent",
            ));
        }
        if record.kind == "certificate_issued" {
            let issuance_id = record.issuance_id.clone().ok_or_else(|| {
                Error::new(
                    ErrorClass::Validation,
                    "certificate audit record has no issuance identifier",
                )
            })?;
            if !issuance_ids.insert(issuance_id) {
                return Err(Error::new(
                    ErrorClass::Validation,
                    "duplicate accepted audit record for issuance",
                ));
            }
        }
        prior = Some(hex(&hash_sha256(&bytes)?));
    }
    Ok(())
}

fn find_issuance_by_idempotency(
    state_dir: &Path,
    key_hash: &str,
    request_hash: &str,
) -> Result<Option<PathBuf>> {
    for entry in numbered_json_entries(&state_dir.join("issuances"))? {
        if !entry.is_dir() || !entry.join("intent.json").exists() {
            continue;
        }
        let intent: IssuanceIntent = read_json(&entry.join("intent.json"), 64 * 1024)?;
        if intent.idempotency_key_hash != key_hash {
            continue;
        }
        if intent.request_hash != request_hash {
            return Err(Error::new(ErrorClass::Precondition, "idempotency_conflict"));
        }
        if !entry.join("commit.json").exists() {
            return Err(Error::new(
                ErrorClass::Issuance,
                "matching issuance transaction is incomplete and requires quarantine",
            ));
        }
        return Ok(Some(entry));
    }
    Ok(None)
}

fn recover_issuance_commit(
    state_dir: &Path,
    issuance_dir: &Path,
    authority: &Authority,
) -> Result<()> {
    let intent_bytes = read_bounded(&issuance_dir.join("intent.json"), 64 * 1024)?;
    let intent: IssuanceIntent = serde_json::from_slice(&intent_bytes).map_err(|error| {
        Error::new(
            ErrorClass::State,
            format!("invalid issuance intent during recovery: {error}"),
        )
    })?;
    let certificate = read_bounded(&issuance_dir.join("certificate.der"), ROOT_CAP)?;
    let record_bytes = read_bounded(&issuance_dir.join("record.json"), 64 * 1024)?;
    let record: IssuanceRecord = serde_json::from_slice(&record_bytes).map_err(|error| {
        Error::new(
            ErrorClass::State,
            format!("invalid issuance record during recovery: {error}"),
        )
    })?;
    let commit: IssuanceCommit = read_json(&issuance_dir.join("commit.json"), 64 * 1024)?;
    if intent.authority_id != authority.authority_id
        || record.authority_id != authority.authority_id
        || commit.authority_id != authority.authority_id
        || commit.issuance_id != intent.issuance_id
        || commit.idempotency.issuance_id != intent.issuance_id
        || commit.idempotency.key_hash != intent.idempotency_key_hash
        || commit.idempotency.request_hash != intent.request_hash
        || hex(&hash_sha256(&certificate)?) != record.certificate_sha256
        || commit.idempotency.certificate_sha256 != record.certificate_sha256
    {
        return Err(Error::new(
            ErrorClass::Validation,
            "issuance recovery transaction is inconsistent",
        ));
    }
    let complete = CompleteRecord {
        schema_version: SCHEMA_VERSION,
        issuance_id: intent.issuance_id.clone(),
        authority_id: authority.authority_id.clone(),
        intent_sha256: hex(&hash_sha256(&intent_bytes)?),
        certificate_sha256: record.certificate_sha256.clone(),
        record_sha256: hex(&hash_sha256(&record_bytes)?),
    };
    let complete_bytes = canonical_json(&complete, "completion")?;
    publish_exact_or_validate(&issuance_dir.join("COMPLETE"), &complete_bytes)?;
    let mapping_path = state_dir
        .join("idempotency")
        .join(format!("{}.json", commit.idempotency.key_hash));
    let mapping_bytes = canonical_json(&commit.idempotency, "idempotency")?;
    publish_exact_or_validate(&mapping_path, &mapping_bytes)?;
    ensure_issuance_audit(state_dir, &commit)?;
    publish_exact_or_validate(
        &issuance_dir.join("AUDIT"),
        format!(
            "schema=1\nissuance_id={}\naudit=accepted\n",
            commit.issuance_id
        )
        .as_bytes(),
    )?;
    Ok(())
}

fn ensure_issuance_audit(state_dir: &Path, commit: &IssuanceCommit) -> Result<()> {
    for path in numbered_json_entries(&state_dir.join("audit"))? {
        let record: AuditRecord = read_json(&path, 64 * 1024)?;
        if record.kind == "certificate_issued"
            && record.issuance_id.as_deref() == Some(&commit.issuance_id)
        {
            if record.authority_id.as_deref() != Some(&commit.authority_id)
                || record.source_ip.as_deref() != Some(&commit.source_ip)
                || record.outcome != "accepted"
                || record.operation_id.is_some()
                || record.detail != "server authentication certificate recorded"
                || record.utc != commit.created_at
            {
                return Err(Error::new(
                    ErrorClass::Validation,
                    "issuance audit record conflicts with commit transaction",
                ));
            }
            return Ok(());
        }
    }
    append_audit(
        state_dir,
        AuditRecord {
            schema_version: SCHEMA_VERSION,
            sequence: 0,
            prior_sha256: None,
            kind: "certificate_issued".to_owned(),
            authority_id: Some(commit.authority_id.clone()),
            issuance_id: Some(commit.issuance_id.clone()),
            operation_id: None,
            source_ip: Some(commit.source_ip.clone()),
            outcome: "accepted".to_owned(),
            detail: "server authentication certificate recorded".to_owned(),
            utc: commit.created_at.clone(),
        },
    )
}

fn completed_issuance_ids(state_dir: &Path) -> Result<Vec<String>> {
    numbered_json_entries(&state_dir.join("issuances")).map(|entries| {
        entries
            .into_iter()
            .filter(|entry| entry.join("COMPLETE").exists())
            .filter_map(|entry| entry.file_name()?.to_str().map(str::to_owned))
            .collect()
    })
}

fn read_completed_certificate(
    state_dir: &Path,
    issuance_id: &str,
    expected_hash: &str,
) -> Result<Vec<u8>> {
    let bytes = read_bounded(
        &state_dir
            .join("issuances")
            .join(issuance_id)
            .join("certificate.der"),
        ROOT_CAP,
    )?;
    if hex(&hash_sha256(&bytes)?) != expected_hash {
        return Err(Error::new(
            ErrorClass::Validation,
            "idempotent certificate hash mismatch",
        ));
    }
    Ok(bytes)
}

fn validate_authority_fields(authority: &Authority) -> Result<()> {
    if authority.schema_version != SCHEMA_VERSION
        || authority.scope != "current_user"
        || authority.algorithm != "ECDSA_P256"
        || authority.signature_oid != "1.2.840.10045.4.3.2"
        || authority.root_subject != "CN=AziHSM Demo Root"
        || authority.root_subject_der_hex.is_empty()
        || !authority.root_subject_der_hex.len().is_multiple_of(2)
        || authority.root_ski_hex.len() != 40
        || !authority
            .root_ski_hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || authority.profile != "azihsm-demo-root-v1"
    {
        return Err(Error::new(
            ErrorClass::Validation,
            "authority schema or profile mismatch",
        ));
    }
    parse_utc(&authority.not_before)?;
    parse_utc(&authority.not_after)?;
    parse_utc(&authority.created_at)?;
    Ok(())
}

fn validate_journal(state_dir: &Path, operation_id: &str) -> Result<Vec<InitGeneration>> {
    let directory = journal_directory(state_dir, operation_id)?;
    for pending in pending_entries(&directory)? {
        let Some(name) = pending.file_name().and_then(|value| value.to_str()) else {
            return Err(Error::new(
                ErrorClass::State,
                "pending journal name is not valid Unicode",
            ));
        };
        let Some(sequence) = name
            .strip_prefix('.')
            .and_then(|value| value.strip_suffix(".json.pending"))
            .filter(|value| value.len() == 6 && value.bytes().all(|byte| byte.is_ascii_digit()))
        else {
            continue;
        };
        let bytes = read_bounded(&pending, JOURNAL_CAP)?;
        if bytes.is_empty() {
            fs::remove_file(&pending).map_err(|error| {
                Error::new(
                    ErrorClass::State,
                    format!("empty pending journal cleanup failed: {error}"),
                )
            })?;
            continue;
        }
        let generation: InitGeneration = serde_json::from_slice(&bytes).map_err(|error| {
            Error::new(
                ErrorClass::State,
                format!("invalid pending journal generation: {error}"),
            )
        })?;
        if generation.operation_id != operation_id
            || generation.sequence
                != sequence
                    .parse::<u32>()
                    .map_err(|_| Error::new(ErrorClass::State, "invalid pending sequence"))?
        {
            return Err(Error::new(
                ErrorClass::State,
                "pending journal generation binding mismatch",
            ));
        }
        finalize_pending_publication(&directory.join(format!("{:06}.json", generation.sequence)))?;
    }
    let mut paths = numbered_json_entries(&directory)?;
    paths.retain(|path| {
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| {
                name.len() == 11
                    && name.ends_with(".json")
                    && name[..6].bytes().all(|byte| byte.is_ascii_digit())
            })
    });
    paths.sort();
    let mut generations: Vec<InitGeneration> = Vec::new();
    let mut prior = None;
    for (index, path) in paths.iter().enumerate() {
        if path.file_name().and_then(|name| name.to_str()) != Some(&format!("{index:06}.json")) {
            return Err(Error::new(
                ErrorClass::State,
                "journal gap or unexpected name",
            ));
        }
        let bytes = read_bounded(path, JOURNAL_CAP)?;
        let generation: InitGeneration = serde_json::from_slice(&bytes)
            .map_err(|error| Error::new(ErrorClass::State, format!("invalid journal: {error}")))?;
        if generation.schema_version != SCHEMA_VERSION
            || generation.operation_id != operation_id
            || generation.sequence as usize != index
            || generation.prior_sha256 != prior
        {
            return Err(Error::new(
                ErrorClass::State,
                "journal identity, sequence, or hash chain mismatch",
            ));
        }
        if let Some(first) = generations.first()
            && (generation.provider != first.provider
                || generation.key_name != first.key_name
                || generation.root_valid_days != first.root_valid_days)
        {
            return Err(Error::new(
                ErrorClass::State,
                "journal immutable parameters changed",
            ));
        }
        prior = Some(hex(&hash_sha256(&bytes)?));
        generations.push(generation);
    }
    validate_transitions(&generations)?;
    Ok(generations)
}

fn validate_transitions(generations: &[InitGeneration]) -> Result<()> {
    if generations.first().map(|value| value.phase) != Some(InitPhase::Prepared) {
        return Err(Error::new(
            ErrorClass::State,
            "journal must begin with prepared",
        ));
    }
    for pair in generations.windows(2) {
        let valid = matches!(
            (pair[0].phase, pair[1].phase),
            (InitPhase::Prepared, InitPhase::FinalizeStarted)
                | (InitPhase::Prepared, InitPhase::AbandonVerified)
                | (InitPhase::FinalizeStarted, InitPhase::FinalizeSucceeded)
                | (InitPhase::FinalizeStarted, InitPhase::FinalizeFailed)
                | (InitPhase::FinalizeStarted, InitPhase::FinalizeUnexpected)
                | (InitPhase::FinalizeStarted, InitPhase::AbandonVerified)
                | (InitPhase::FinalizeSucceeded, InitPhase::KeyValidated)
                | (InitPhase::KeyValidated, InitPhase::RootSigningPrepared)
                | (InitPhase::RootSigningPrepared, InitPhase::RootValidated)
                | (InitPhase::RootValidated, InitPhase::AuthorityPublished)
                | (InitPhase::AuthorityPublished, InitPhase::Completed)
                | (InitPhase::AbandonVerified, InitPhase::Abandoned)
        );
        if !valid {
            return Err(Error::new(ErrorClass::State, "illegal journal transition"));
        }
    }
    Ok(())
}

fn journal_directory(state_dir: &Path, operation_id: &str) -> Result<PathBuf> {
    let active = state_dir
        .join("init-intents")
        .join("active")
        .join(operation_id);
    if active.is_dir() {
        return Ok(active);
    }
    let completed = state_dir
        .join("init-intents")
        .join("archive")
        .join("completed")
        .join(operation_id);
    if completed.is_dir() {
        return Ok(completed);
    }
    Err(Error::new(
        ErrorClass::Precondition,
        "initialization operation was not found in active or completed state",
    ))
}

fn archive_journal(state_dir: &Path, operation_id: &str, class: &str) -> Result<()> {
    let source = state_dir
        .join("init-intents")
        .join("active")
        .join(operation_id);
    let destination = state_dir
        .join("init-intents")
        .join("archive")
        .join(class)
        .join(operation_id);
    if destination.exists() {
        if source.exists() {
            return Err(Error::new(
                ErrorClass::State,
                "journal exists in both active and archived namespaces",
            ));
        }
        return Ok(());
    }
    fs::rename(source, destination)
        .map_err(|error| Error::new(ErrorClass::State, format!("archive move failed: {error}")))
}

fn ensure_initialization_audit(state_dir: &Path, authority: &Authority) -> Result<()> {
    let mut matches = 0;
    for path in numbered_json_entries(&state_dir.join("audit"))? {
        let record: AuditRecord = read_json(&path, 64 * 1024)?;
        if record.kind == "authority_initialized"
            && record.operation_id.as_deref() == Some(&authority.init_operation_id)
        {
            matches += 1;
            if record.authority_id.as_deref() != Some(&authority.authority_id)
                || record.issuance_id.is_some()
                || record.source_ip.is_some()
                || record.outcome != "accepted"
                || record.detail != "persistent named authority published"
                || record.utc != authority.created_at
            {
                return Err(Error::new(
                    ErrorClass::Validation,
                    "initialization audit conflicts with the root transaction",
                ));
            }
        }
    }
    if matches > 1 {
        return Err(Error::new(
            ErrorClass::Validation,
            "duplicate initialization audit records",
        ));
    }
    if matches == 1 {
        return Ok(());
    }
    append_audit(
        state_dir,
        AuditRecord {
            schema_version: SCHEMA_VERSION,
            sequence: 0,
            prior_sha256: None,
            kind: "authority_initialized".to_owned(),
            authority_id: Some(authority.authority_id.clone()),
            issuance_id: None,
            operation_id: Some(authority.init_operation_id.clone()),
            source_ip: None,
            outcome: "accepted".to_owned(),
            detail: "persistent named authority published".to_owned(),
            utc: authority.created_at.clone(),
        },
    )
}

fn assert_empty_product_namespaces(state_dir: &Path) -> Result<()> {
    for name in [
        "issuances",
        "abandoned-issuances",
        "serial-reservations",
        "idempotency",
        "audit",
    ] {
        if numbered_json_entries(&state_dir.join(name))?.is_empty() {
            continue;
        }
        return Err(Error::new(
            ErrorClass::Precondition,
            format!("`{name}` must be empty"),
        ));
    }
    for archive in ["completed", "abandoned"] {
        if !numbered_json_entries(&state_dir.join("init-intents").join("archive").join(archive))?
            .is_empty()
        {
            return Err(Error::new(
                ErrorClass::Precondition,
                "initialization archive must be empty for fresh state",
            ));
        }
    }
    Ok(())
}

fn unique_id(directory: &Path) -> Result<String> {
    for _ in 0..8 {
        let value = hex(&random::<16>()?);
        if !directory.join(&value).exists() {
            return Ok(value);
        }
    }
    Err(Error::new(
        ErrorClass::Issuance,
        "failed to generate a unique issuance identifier",
    ))
}

fn unique_serial(state_dir: &Path) -> Result<[u8; 16]> {
    for _ in 0..8 {
        let value = positive_serial()?;
        let serial = serial_hex(&value);
        if !state_dir
            .join("serial-reservations")
            .join(format!("{serial}.json"))
            .exists()
            && !serial_is_bound_by_intent(state_dir, &serial)?
        {
            return Ok(value);
        }
    }

    fn serial_is_bound_by_intent(state_dir: &Path, serial: &str) -> Result<bool> {
        for path in numbered_json_entries(&state_dir.join("issuances"))? {
            let intent_path = path.join("intent.json");
            if intent_path.exists()
                && read_json::<IssuanceIntent>(&intent_path, 64 * 1024)?.serial == serial
            {
                return Ok(true);
            }
        }
        for quarantine in numbered_json_entries(&state_dir.join("abandoned-issuances"))? {
            let intent_path = quarantine.join("original").join("intent.json");
            if intent_path.exists()
                && read_json::<IssuanceIntent>(&intent_path, 64 * 1024)?.serial == serial
            {
                return Ok(true);
            }
            let prepared_path = quarantine.join("000000-prepared.json");
            if prepared_path.exists() {
                let value: serde_json::Value = read_json(&prepared_path, 64 * 1024)?;
                if value.get("serial").and_then(|value| value.as_str()) == Some(serial) {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }
    Err(Error::new(
        ErrorClass::Issuance,
        "failed to reserve a unique serial",
    ))
}

fn positive_serial() -> Result<[u8; 16]> {
    let mut value = random::<16>()?;
    value[15] &= 0x7f;
    if value.iter().all(|byte| *byte == 0) {
        value[0] = 1;
    }
    Ok(value)
}

fn serial_hex(serial: &[u8; 16]) -> String {
    serial
        .iter()
        .rev()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn time_from_system(value: SystemTime) -> Result<String> {
    let duration = value
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| Error::new(ErrorClass::Validation, "time precedes Unix epoch"))?;
    time::OffsetDateTime::from_unix_timestamp(duration.as_secs() as i64)
        .map_err(|error| Error::new(ErrorClass::Validation, format!("invalid time: {error}")))?
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|error| {
            Error::new(
                ErrorClass::Validation,
                format!("time format failed: {error}"),
            )
        })
}

fn leaf_validity_interval(
    now: SystemTime,
    requested_hours: u16,
    root_expiry: time::OffsetDateTime,
) -> Result<(SystemTime, SystemTime)> {
    let not_before = now
        .checked_sub(Duration::from_secs(CLOCK_SKEW_SECONDS as u64))
        .ok_or_else(|| Error::new(ErrorClass::Validation, "leaf time underflow"))?;
    let requested_not_after = now
        .checked_add(Duration::from_secs(u64::from(requested_hours) * 3_600))
        .ok_or_else(|| Error::new(ErrorClass::Validation, "leaf time overflow"))?;
    let root_seconds = u64::try_from(root_expiry.unix_timestamp())
        .map_err(|_| Error::new(ErrorClass::Validation, "root notAfter precedes Unix epoch"))?;
    let root_not_after = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(root_seconds))
        .ok_or_else(|| Error::new(ErrorClass::Validation, "root notAfter overflow"))?;
    if root_not_after <= now {
        return Err(Error::new(
            ErrorClass::Precondition,
            "root certificate has no remaining leaf validity interval",
        ));
    }
    Ok((not_before, requested_not_after.min(root_not_after)))
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use crate::state::{create_protected_dir, create_state_layout};

    fn test_path(label: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("{label}-{}", std::process::id()))
    }

    fn authority() -> Authority {
        Authority {
            schema_version: SCHEMA_VERSION,
            authority_id: "authority".to_owned(),
            provider: "provider".to_owned(),
            key_name: "key".to_owned(),
            scope: "current_user".to_owned(),
            algorithm: "ECDSA_P256".to_owned(),
            signature_oid: "1.2.840.10045.4.3.2".to_owned(),
            public_key_sha256: "public".to_owned(),
            spki_sha256: "spki".to_owned(),
            root_sha256: "root".to_owned(),
            root_serial: "01".to_owned(),
            root_subject: "CN=AziHSM Demo Root".to_owned(),
            root_subject_der_hex: "subject".to_owned(),
            root_ski_hex: "ski".to_owned(),
            not_before: "2026-01-01T00:00:00Z".to_owned(),
            not_after: "2027-01-01T00:00:00Z".to_owned(),
            profile: "azihsm-demo-root-v1".to_owned(),
            init_operation_id: "operation".to_owned(),
            created_at: "2026-01-01T00:00:00Z".to_owned(),
        }
    }

    #[test]
    fn logging_enrichment_failure_does_not_change_success() {
        let result = finish_initialization(Ok(()), true, true, || {
            Err(Error::new(ErrorClass::State, "injected enrichment failure"))
        });
        assert!(result.is_ok());
    }

    #[test]
    fn disabled_logging_performs_no_enrichment_io() {
        let result = finish_initialization(Ok(()), true, false, || {
            panic!("logging-only enrichment must not run")
        });
        assert!(result.is_ok());
    }

    fn committed_issuance(state_dir: &Path) -> (PathBuf, Authority) {
        create_state_layout(state_dir).unwrap_or_else(|error| panic!("{error}"));
        let authority = authority();
        let issuance_id = "11111111111111111111111111111111";
        let issuance_dir = state_dir.join("issuances").join(issuance_id);
        create_protected_dir(&issuance_dir).unwrap_or_else(|error| panic!("{error}"));
        let certificate = b"certificate";
        let certificate_sha256 =
            hex(&hash_sha256(certificate).unwrap_or_else(|error| panic!("{error}")));
        let intent = IssuanceIntent {
            schema_version: SCHEMA_VERSION,
            issuance_id: issuance_id.to_owned(),
            authority_id: authority.authority_id.clone(),
            serial: "01".to_owned(),
            correlation_id: "correlation".to_owned(),
            idempotency_key_hash: "keyhash".to_owned(),
            request_hash: "requesthash".to_owned(),
            csr_sha256: "csr".to_owned(),
            spki_sha256: "spki".to_owned(),
            dns_sans: vec!["server.example".to_owned()],
            ip_sans: Vec::new(),
            not_before: "2026-01-01T00:00:00Z".to_owned(),
            not_after: "2026-01-02T00:00:00Z".to_owned(),
            profile: "server-auth-v1".to_owned(),
            created_at: "2026-01-01T00:00:00Z".to_owned(),
        };
        let record = IssuanceRecord {
            schema_version: SCHEMA_VERSION,
            issuance_id: issuance_id.to_owned(),
            authority_id: authority.authority_id.clone(),
            serial: "01".to_owned(),
            certificate_sha256: certificate_sha256.clone(),
            certificate_size: certificate.len(),
            not_before: intent.not_before.clone(),
            not_after: intent.not_after.clone(),
            status: "issued".to_owned(),
        };
        let mapping = IdempotencyRecord {
            schema_version: SCHEMA_VERSION,
            key_hash: intent.idempotency_key_hash.clone(),
            request_hash: intent.request_hash.clone(),
            issuance_id: issuance_id.to_owned(),
            certificate_sha256,
            created_at: intent.created_at.clone(),
        };
        durable_json(&issuance_dir.join("intent.json"), &intent)
            .unwrap_or_else(|error| panic!("{error}"));
        durable_bytes(&issuance_dir.join("certificate.der"), certificate)
            .unwrap_or_else(|error| panic!("{error}"));
        durable_json(&issuance_dir.join("record.json"), &record)
            .unwrap_or_else(|error| panic!("{error}"));
        durable_json(
            &issuance_dir.join("commit.json"),
            &IssuanceCommit {
                schema_version: SCHEMA_VERSION,
                issuance_id: issuance_id.to_owned(),
                authority_id: authority.authority_id.clone(),
                idempotency: mapping,
                source_ip: "127.0.0.1".to_owned(),
                created_at: intent.created_at.clone(),
            },
        )
        .unwrap_or_else(|error| panic!("{error}"));
        durable_json(
            &state_dir
                .join("serial-reservations")
                .join(format!("{}.json", intent.serial)),
            &SerialReservation {
                schema_version: SCHEMA_VERSION,
                serial: intent.serial,
                issuance_id: issuance_id.to_owned(),
                authority_id: authority.authority_id.clone(),
                created_at: "2026-01-01T00:00:00Z".to_owned(),
            },
        )
        .unwrap_or_else(|error| panic!("{error}"));
        (issuance_dir, authority)
    }

    #[test]
    fn committed_issuance_recovery_is_idempotent_and_rejects_substitution() {
        let state_dir = test_path("issuance-recovery");
        let _ = fs::remove_dir_all(&state_dir);
        fs::create_dir_all(
            state_dir
                .parent()
                .unwrap_or_else(|| panic!("test path has no parent")),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let (issuance_dir, authority) = committed_issuance(&state_dir);

        recover_issuance_commit(&state_dir, &issuance_dir, &authority)
            .unwrap_or_else(|error| panic!("{error}"));
        let certificate = read_bounded(&issuance_dir.join("certificate.der"), ROOT_CAP)
            .unwrap_or_else(|error| panic!("{error}"));
        recover_issuance_commit(&state_dir, &issuance_dir, &authority)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            read_bounded(&issuance_dir.join("certificate.der"), ROOT_CAP)
                .unwrap_or_else(|error| panic!("{error}")),
            certificate
        );
        assert_eq!(
            numbered_json_entries(&state_dir.join("audit"))
                .unwrap_or_else(|error| panic!("{error}"))
                .len(),
            1
        );

        let mapping_path = state_dir.join("idempotency").join("keyhash.json");
        fs::remove_file(&mapping_path).unwrap_or_else(|error| panic!("{error}"));
        recover_issuance_commit(&state_dir, &issuance_dir, &authority)
            .unwrap_or_else(|error| panic!("{error}"));
        fs::remove_file(&mapping_path).unwrap_or_else(|error| panic!("{error}"));
        durable_bytes(&mapping_path, b"{\"substituted\":true}\n")
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(recover_issuance_commit(&state_dir, &issuance_dir, &authority).is_err());

        fs::remove_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    }

    #[test]
    fn precommit_issuance_fails_closed() {
        let state_dir = test_path("issuance-precommit");
        let _ = fs::remove_dir_all(&state_dir);
        fs::create_dir_all(
            state_dir
                .parent()
                .unwrap_or_else(|| panic!("test path has no parent")),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        create_state_layout(&state_dir).unwrap_or_else(|error| panic!("{error}"));
        create_protected_dir(
            &state_dir
                .join("issuances")
                .join("22222222222222222222222222222222"),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        assert!(full_scan(&state_dir, &authority()).is_err());
        fs::remove_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    }

    #[test]
    fn root_signing_intent_reconstructs_identical_tbs() {
        let mut public_blob = [0_u8; 72];
        public_blob[..4].copy_from_slice(&0x3153_4345_u32.to_le_bytes());
        public_blob[4..8].copy_from_slice(&32_u32.to_le_bytes());
        public_blob[8] = 1;
        public_blob[40] = 2;
        let intent = create_root_signing_intent("operation", "provider", "key", 30, &public_blob)
            .unwrap_or_else(|error| panic!("{error}"));
        let generation = InitGeneration {
            schema_version: SCHEMA_VERSION,
            operation_id: "operation".to_owned(),
            sequence: 0,
            phase: InitPhase::KeyValidated,
            prior_sha256: None,
            provider: "provider".to_owned(),
            key_name: "key".to_owned(),
            root_valid_days: 30,
            utc: intent.created_at.clone(),
            ncrypt_status: None,
            evidence: None,
        };
        let first = root_backing_from_intent(&intent, "operation", &generation, &public_blob)
            .unwrap_or_else(|error| panic!("{error}"))
            .to_be_signed_der()
            .unwrap_or_else(|error| panic!("{error}"));
        let second = root_backing_from_intent(&intent, "operation", &generation, &public_blob)
            .unwrap_or_else(|error| panic!("{error}"))
            .to_be_signed_der()
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(first, second);
        assert_eq!(hex(&first), intent.tbs_der_hex);
    }

    #[test]
    fn leaf_validity_is_capped_by_root_expiry() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let root_expiry = time::OffsetDateTime::from(now + Duration::from_secs(600));
        let (not_before, not_after) =
            leaf_validity_interval(now, 24, root_expiry).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            not_before,
            now - Duration::from_secs(CLOCK_SKEW_SECONDS as u64)
        );
        assert_eq!(not_after, now + Duration::from_secs(600));
    }

    #[test]
    fn leaf_validity_rejects_expired_root() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        let root_expiry = time::OffsetDateTime::from(now - Duration::from_secs(1));
        assert!(leaf_validity_interval(now, 24, root_expiry).is_err());
    }

    #[test]
    fn pending_intent_and_reservation_are_recovered_explicitly() {
        let state_dir = test_path("pending-precommit");
        let _ = fs::remove_dir_all(&state_dir);
        fs::create_dir_all(
            state_dir
                .parent()
                .unwrap_or_else(|| panic!("test path has no parent")),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        create_state_layout(&state_dir).unwrap_or_else(|error| panic!("{error}"));
        let authority = authority();
        let issuance_id = "33333333333333333333333333333333";
        let issuance_dir = state_dir.join("issuances").join(issuance_id);
        create_protected_dir(&issuance_dir).unwrap_or_else(|error| panic!("{error}"));
        let intent = IssuanceIntent {
            schema_version: SCHEMA_VERSION,
            issuance_id: issuance_id.to_owned(),
            authority_id: authority.authority_id.clone(),
            serial: "30".to_owned(),
            correlation_id: "correlation".to_owned(),
            idempotency_key_hash: "key".to_owned(),
            request_hash: "request".to_owned(),
            csr_sha256: "csr".to_owned(),
            spki_sha256: "spki".to_owned(),
            dns_sans: vec!["server.example".to_owned()],
            ip_sans: Vec::new(),
            not_before: "2026-01-01T00:00:00Z".to_owned(),
            not_after: "2026-01-02T00:00:00Z".to_owned(),
            profile: "server-auth-v1".to_owned(),
            created_at: "2026-01-01T00:00:00Z".to_owned(),
        };
        let intent_path = issuance_dir.join("intent.json");
        durable_json(&intent_path, &intent).unwrap_or_else(|error| panic!("{error}"));
        fs::rename(&intent_path, issuance_dir.join(".intent.json.pending"))
            .unwrap_or_else(|error| panic!("{error}"));
        let reservation_path = state_dir.join("serial-reservations").join("30.json");
        durable_json(
            &reservation_path,
            &SerialReservation {
                schema_version: SCHEMA_VERSION,
                serial: "30".to_owned(),
                issuance_id: issuance_id.to_owned(),
                authority_id: authority.authority_id.clone(),
                created_at: intent.created_at,
            },
        )
        .unwrap_or_else(|error| panic!("{error}"));
        fs::rename(
            &reservation_path,
            state_dir
                .join("serial-reservations")
                .join(".30.json.pending"),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        recover_pending_precommit_publications(&state_dir, &authority)
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(intent_path.exists());
        assert!(reservation_path.exists());
        assert!(
            pending_entries(&issuance_dir)
                .unwrap_or_else(|error| panic!("{error}"))
                .is_empty()
        );
        fs::remove_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    }

    #[test]
    fn initialization_audit_is_exactly_once() {
        let state_dir = test_path("init-audit");
        let _ = fs::remove_dir_all(&state_dir);
        fs::create_dir_all(
            state_dir
                .parent()
                .unwrap_or_else(|| panic!("test path has no parent")),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        create_state_layout(&state_dir).unwrap_or_else(|error| panic!("{error}"));
        let authority = authority();
        ensure_initialization_audit(&state_dir, &authority)
            .unwrap_or_else(|error| panic!("{error}"));
        ensure_initialization_audit(&state_dir, &authority)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            numbered_json_entries(&state_dir.join("audit"))
                .unwrap_or_else(|error| panic!("{error}"))
                .len(),
            1
        );
        fs::remove_dir_all(&state_dir).unwrap_or_else(|error| panic!("{error}"));
    }
}

struct JournalWriter {
    directory: PathBuf,
    operation_id: String,
    provider: String,
    key_name: String,
    root_valid_days: u16,
    sequence: u32,
    prior: Option<String>,
}

impl JournalWriter {
    fn new(
        directory: PathBuf,
        operation_id: String,
        provider: String,
        key_name: String,
        root_valid_days: u16,
    ) -> Self {
        Self {
            directory,
            operation_id,
            provider,
            key_name,
            root_valid_days,
            sequence: 0,
            prior: None,
        }
    }

    fn resume(directory: PathBuf, generations: Vec<InitGeneration>) -> Result<Self> {
        let last = generations
            .last()
            .ok_or_else(|| Error::new(ErrorClass::State, "cannot resume an empty journal"))?;
        let bytes = read_bounded(
            &directory.join(format!("{:06}.json", last.sequence)),
            JOURNAL_CAP,
        )?;
        Ok(Self {
            directory,
            operation_id: last.operation_id.clone(),
            provider: last.provider.clone(),
            key_name: last.key_name.clone(),
            root_valid_days: last.root_valid_days,
            sequence: last.sequence + 1,
            prior: Some(hex(&hash_sha256(&bytes)?)),
        })
    }

    fn append(
        &mut self,
        phase: InitPhase,
        status: Option<i32>,
        evidence: Option<String>,
    ) -> Result<()> {
        let generation = InitGeneration {
            schema_version: SCHEMA_VERSION,
            operation_id: self.operation_id.clone(),
            sequence: self.sequence,
            phase,
            prior_sha256: self.prior.clone(),
            provider: self.provider.clone(),
            key_name: self.key_name.clone(),
            root_valid_days: self.root_valid_days,
            utc: utc_now()?,
            ncrypt_status: status,
            evidence,
        };
        let bytes = durable_json(
            &self.directory.join(format!("{:06}.json", self.sequence)),
            &generation,
        )?;
        self.prior = Some(hex(&hash_sha256(&bytes)?));
        self.sequence += 1;
        Ok(())
    }
}
