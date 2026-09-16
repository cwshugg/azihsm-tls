//! Shared artifact, enrollment, retry, display, and deletion operations.

use crate::files;
use crate::http::CaClient;
use crate::model::{
    CHAIN_PEM, CSR_DER, CSR_PEM, DELETION_INTENT, DELETION_RECORD, DeletionIntent, DeletionRecord,
    FINALIZE_FAILED, FINALIZE_STARTED, ISSUANCE_METADATA, IssuanceMetadata, LEAF_DER, LEAF_PEM,
    PUBLIC_DER, PUBLIC_PEM, REQUEST_METADATA, ROOT_DER, ROOT_PEM, RequestMetadata, SCHEMA_VERSION,
    STAGING_METADATA, StagingRecord,
};
use crate::validation::{validate_ca_url, validate_cn, validate_key_name, validate_sans};
use crate::{Error, ErrorClass, Result, csr, transcript, verify};
use azihsm_ncrypt::{AzihsmProvider, PROVIDER_NAME, hash_sha256, random};
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::path::PathBuf;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

const ALGORITHM: &str = "ECDSA_P256_SHA256";
const SCOPE: &str = "current_user";

#[derive(Debug)]
pub struct CreateArgs {
    pub output_dir: PathBuf,
    pub subject_cn: String,
    pub dns: Vec<String>,
    pub ip: Vec<IpAddr>,
    pub ca_url: String,
    pub key_name: Option<String>,
    pub retry_guidance: String,
}

#[derive(Debug)]
pub struct RetryArgs {
    pub output_dir: PathBuf,
    pub retry_guidance: String,
}

#[derive(Debug)]
pub struct OutputArgs {
    pub output_dir: PathBuf,
}

#[derive(Debug)]
pub struct DeleteKeyArgs {
    pub output_dir: PathBuf,
    pub confirm_key_name: String,
}

pub fn create(args: CreateArgs) -> Result<()> {
    tracing::info!(event = "command_started", command = "create");
    validate_sans(&args.dns, &args.ip).map_err(usage)?;
    let staging = prepare_staging(&args)?;
    if args.output_dir.join(FINALIZE_FAILED).exists() {
        return Err(Error::new(
            ErrorClass::Precondition,
            "a prior key finalization failed ambiguously; preserve the directory and use a new key name",
        ));
    }
    let provider = open_provider()?;
    let finalize_marker = args.output_dir.join(FINALIZE_STARTED);
    let key = match provider.open_key(&staging.key_name) {
        Ok(key) if finalize_marker.exists() => {
            tracing::info!(event = "key_recovery_started");
            key
        }
        Ok(_) => {
            return Err(Error::new(
                ErrorClass::Precondition,
                "named key exists without a matching finalize-started recovery marker",
            ));
        }
        Err(_) => {
            provider.require_absent(&staging.key_name)?;
            tracing::info!(event = "key_creation_started");
            let key = provider.create_named_staged(&staging.key_name)?;
            files::publish_json(&finalize_marker, &staging)?;
            let status = key.finalize();
            if status < 0 {
                files::publish_json(&args.output_dir.join(FINALIZE_FAILED), &staging)?;
                return Err(Error::new(
                    ErrorClass::Provider,
                    format!(
                        "named-key finalization failed with status 0x{:08x}",
                        status as u32
                    ),
                ));
            }
            tracing::info!(event = "key_finalized");
            key
        }
    };
    key.kat()?;
    tracing::info!(event = "public_key_export_started");
    let public_blob = key.public_blob()?;
    let spki = csr::spki_der(&public_blob)?;
    tracing::info!(event = "public_key_export_completed");
    publish_public_key(&args.output_dir, &spki)?;
    let csr_der = load_or_create_csr(&args.output_dir, &staging, &key, &public_blob, &spki)?;
    let metadata = RequestMetadata {
        schema_version: SCHEMA_VERSION,
        provider: staging.provider.clone(),
        key_name: staging.key_name.clone(),
        algorithm: staging.algorithm.clone(),
        scope: staging.scope.clone(),
        subject_cn: staging.subject_cn.clone(),
        dns_sans: staging.dns_sans.clone(),
        ip_sans: staging.ip_sans.clone(),
        ca_url: staging.ca_url.clone(),
        idempotency_key: staging.idempotency_key.clone(),
        spki_sha256: hex(&hash_sha256(&spki)?),
        csr_sha256: hex(&hash_sha256(&csr_der)?),
        public_key_der: PUBLIC_DER.to_owned(),
        csr_der: CSR_DER.to_owned(),
    };
    files::publish_json(&args.output_dir.join(REQUEST_METADATA), &metadata)?;
    transcript::local_json("written", REQUEST_METADATA, &metadata)?;
    tracing::info!(event = "artifact_published", artifact = "request_metadata");
    files::remove(&args.output_dir.join(FINALIZE_STARTED))?;
    files::remove(&args.output_dir.join(STAGING_METADATA))?;
    tracing::info!(event = "staging_cleanup_completed");
    enroll_and_publish(
        &args.output_dir,
        &metadata,
        &spki,
        &csr_der,
        &args.retry_guidance,
    )?;
    tracing::info!(event = "command_completed", command = "create");
    Ok(())
}

pub fn retry(args: RetryArgs) -> Result<()> {
    tracing::info!(event = "command_started", command = "retry");
    files::validate_output_dir(&args.output_dir)?;
    let metadata = load_request(&args.output_dir)?;
    for stale in [FINALIZE_STARTED, STAGING_METADATA] {
        let path = args.output_dir.join(stale);
        if path.exists() {
            files::remove(&path)?;
        }
    }
    let provider = open_provider()?;
    tracing::info!(event = "key_open_started");
    let key = provider.open_key(&metadata.key_name).map_err(|status| {
        Error::new(
            ErrorClass::Provider,
            format!("named key could not be opened: 0x{:08x}", status as u32),
        )
    })?;
    key.kat()?;
    tracing::info!(event = "key_open_completed");
    let spki = csr::spki_der(&key.public_blob()?)?;
    if hex(&hash_sha256(&spki)?) != metadata.spki_sha256
        || files::read_bounded(&args.output_dir.join(PUBLIC_DER), 4096)? != spki
    {
        return Err(validation(
            "stored public-key identity does not match the named key",
        ));
    }
    let csr_der = files::read_bounded(&args.output_dir.join(CSR_DER), 16_384)?;
    validate_request_material(&metadata, &spki, &csr_der)?;
    enroll_and_publish(
        &args.output_dir,
        &metadata,
        &spki,
        &csr_der,
        &args.retry_guidance,
    )?;
    tracing::info!(event = "command_completed", command = "retry");
    Ok(())
}

pub fn show(args: OutputArgs) -> Result<()> {
    tracing::info!(event = "command_started", command = "show");
    files::validate_output_dir(&args.output_dir)?;
    let request = load_request(&args.output_dir)?;
    validate_stored_request(&args.output_dir, &request)?;
    println!("Provider: {}", request.provider);
    println!("Key name: {}", request.key_name);
    println!("Scope: {}", request.scope);
    println!("Algorithm: {}", request.algorithm);
    println!("Subject CN: {}", request.subject_cn);
    println!("DNS SANs: {}", request.dns_sans.join(", "));
    println!("IP SANs: {}", request.ip_sans.join(", "));
    println!("SPKI SHA-256: {}", request.spki_sha256);
    println!("CSR SHA-256: {}", request.csr_sha256);
    if args.output_dir.join(ISSUANCE_METADATA).exists() {
        let issuance: IssuanceMetadata =
            files::read_json(&args.output_dir.join(ISSUANCE_METADATA))?;
        println!("Authority ID: {}", issuance.authority_id);
        println!("Issuance ID: {}", issuance.issuance_id);
        println!("Leaf SHA-256: {}", issuance.leaf_sha256);
        println!("Root SHA-256: {}", issuance.root_sha256);
        println!("Verified at: {}", issuance.verified_at);
    } else {
        println!("Issuance: pending");
    }
    println!(
        "Key deletion: {}",
        deletion_status(&args.output_dir, &request)?
    );
    tracing::info!(event = "command_completed", command = "show");
    Ok(())
}

pub fn delete_key(args: DeleteKeyArgs) -> Result<()> {
    tracing::info!(event = "command_started", command = "delete-key");
    files::validate_output_dir(&args.output_dir)?;
    let metadata = load_request(&args.output_dir)?;
    let stored_spki = validate_stored_request(&args.output_dir, &metadata)?;
    if args.confirm_key_name != metadata.key_name {
        return Err(Error::new(
            ErrorClass::Precondition,
            "confirmation does not match the recorded key name",
        ));
    }
    if args.output_dir.join(DELETION_RECORD).exists() {
        let intent = load_deletion_intent(&args.output_dir, &metadata, &args.confirm_key_name)?
            .ok_or_else(|| {
                Error::new(
                    ErrorClass::State,
                    "deletion record exists without its identity-bound intent",
                )
            })?;
        let record: DeletionRecord = files::read_json(&args.output_dir.join(DELETION_RECORD))?;
        validate_deletion_record(&record, &metadata, &intent)?;
        transcript::local_json("read", DELETION_RECORD, &record)?;
        tracing::info!(event = "key_deletion_completed");
        tracing::info!(event = "command_completed", command = "delete-key");
        return Ok(());
    }
    let provider = open_provider()?;
    run_deletion(
        &args.output_dir,
        &metadata,
        &args.confirm_key_name,
        || key_matches(&provider, &metadata, &stored_spki),
        || delete_matching_key(&provider, &metadata, &stored_spki),
        || provider.require_absent(&metadata.key_name),
        None,
    )?;
    tracing::info!(event = "key_deletion_completed");
    tracing::info!(event = "command_completed", command = "delete-key");
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
enum DeletionFault {
    BeforeIntent,
    AfterIntent,
    AfterDelete,
    AfterAbsence,
    AfterFinalStaging,
    AfterFinalPublication,
}

fn run_deletion<Inspect, Delete, Absent>(
    output_dir: &Path,
    metadata: &RequestMetadata,
    confirmation: &str,
    mut inspect: Inspect,
    mut delete: Delete,
    mut require_absent: Absent,
    fault: Option<DeletionFault>,
) -> Result<()>
where
    Inspect: FnMut() -> Result<bool>,
    Delete: FnMut() -> Result<()>,
    Absent: FnMut() -> Result<()>,
{
    let existing_intent = load_deletion_intent(output_dir, metadata, confirmation)?;
    if output_dir.join(DELETION_RECORD).exists() {
        let intent = existing_intent.ok_or_else(|| {
            Error::new(
                ErrorClass::State,
                "deletion record exists without its identity-bound intent",
            )
        })?;
        let record: DeletionRecord = files::read_json(&output_dir.join(DELETION_RECORD))?;
        validate_deletion_record(&record, metadata, &intent)?;
        transcript::local_json("read", DELETION_RECORD, &record)?;
        return Ok(());
    }
    let intent = match existing_intent {
        Some(intent) => intent,
        None => {
            if !inspect()? {
                return Err(Error::new(
                    ErrorClass::Precondition,
                    "named key is absent without a valid deletion intent",
                ));
            }
            fail_deletion(fault, DeletionFault::BeforeIntent)?;
            let intent = DeletionIntent {
                schema_version: SCHEMA_VERSION,
                provider: metadata.provider.clone(),
                key_name: metadata.key_name.clone(),
                spki_sha256: metadata.spki_sha256.clone(),
                confirmation_key_name: confirmation.to_owned(),
                operation_id: hex(&random::<16>()?),
                requested_at: now()?,
            };
            files::publish_json(&output_dir.join(DELETION_INTENT), &intent)?;
            transcript::local_json("written", DELETION_INTENT, &intent)?;
            tracing::info!(event = "deletion_intent_published");
            fail_deletion(fault, DeletionFault::AfterIntent)?;
            intent
        }
    };

    if inspect()? {
        tracing::info!(event = "key_deletion_started");
        delete()?;
        fail_deletion(fault, DeletionFault::AfterDelete)?;
    }
    require_absent()?;
    fail_deletion(fault, DeletionFault::AfterAbsence)?;

    let path = output_dir.join(DELETION_RECORD);
    let pending = output_dir.join(format!(".{DELETION_RECORD}.pending"));
    let record = if pending.exists() {
        let record: DeletionRecord = files::read_json(&pending)?;
        validate_deletion_record(&record, metadata, &intent)?;
        record
    } else {
        DeletionRecord {
            schema_version: SCHEMA_VERSION,
            provider: metadata.provider.clone(),
            key_name: metadata.key_name.clone(),
            spki_sha256: metadata.spki_sha256.clone(),
            operation_id: intent.operation_id.clone(),
            requested_at: intent.requested_at.clone(),
            deleted_at: now()?,
            verified_absent: true,
        }
    };
    files::stage_json(&path, &record)?;
    fail_deletion(fault, DeletionFault::AfterFinalStaging)?;
    files::commit_json(&path, &record)?;
    transcript::local_json("written", DELETION_RECORD, &record)?;
    fail_deletion(fault, DeletionFault::AfterFinalPublication)
}

fn key_matches(
    provider: &AzihsmProvider,
    metadata: &RequestMetadata,
    stored_spki: &[u8],
) -> Result<bool> {
    let key = match provider.open_key(&metadata.key_name) {
        Ok(key) => key,
        Err(_) => {
            provider.require_absent(&metadata.key_name)?;
            return Ok(false);
        }
    };
    let spki = csr::spki_der(&key.public_blob()?)?;
    if spki != stored_spki || hex(&hash_sha256(&spki)?) != metadata.spki_sha256 {
        return Err(validation(
            "refusing to delete a key with a different SPKI identity",
        ));
    }
    Ok(true)
}

fn delete_matching_key(
    provider: &AzihsmProvider,
    metadata: &RequestMetadata,
    stored_spki: &[u8],
) -> Result<()> {
    let key = provider.open_key(&metadata.key_name).map_err(|status| {
        Error::new(
            ErrorClass::Provider,
            format!("named key could not be opened: 0x{:08x}", status as u32),
        )
    })?;
    let spki = csr::spki_der(&key.public_blob()?)?;
    if spki != stored_spki || hex(&hash_sha256(&spki)?) != metadata.spki_sha256 {
        return Err(validation(
            "refusing to delete a key with a different SPKI identity",
        ));
    }
    key.delete()
}

fn load_deletion_intent(
    output_dir: &Path,
    metadata: &RequestMetadata,
    confirmation: &str,
) -> Result<Option<DeletionIntent>> {
    let path = output_dir.join(DELETION_INTENT);
    if !path.exists() {
        return Ok(None);
    }
    let intent: DeletionIntent = files::read_json(&path)?;
    validate_deletion_intent(&intent, metadata, confirmation)?;
    transcript::local_json("read", DELETION_INTENT, &intent)?;
    Ok(Some(intent))
}

fn validate_deletion_intent(
    intent: &DeletionIntent,
    metadata: &RequestMetadata,
    confirmation: &str,
) -> Result<()> {
    if intent.schema_version != SCHEMA_VERSION
        || intent.provider != metadata.provider
        || intent.key_name != metadata.key_name
        || intent.spki_sha256 != metadata.spki_sha256
        || intent.confirmation_key_name != confirmation
        || intent.confirmation_key_name != metadata.key_name
        || !is_lower_hex_32(&intent.operation_id)
        || !is_timestamp(&intent.requested_at)
    {
        return Err(validation("deletion intent identity is invalid"));
    }
    Ok(())
}

fn validate_deletion_record(
    record: &DeletionRecord,
    metadata: &RequestMetadata,
    intent: &DeletionIntent,
) -> Result<()> {
    if record.schema_version != SCHEMA_VERSION
        || record.provider != metadata.provider
        || record.key_name != metadata.key_name
        || record.spki_sha256 != metadata.spki_sha256
        || record.operation_id != intent.operation_id
        || record.requested_at != intent.requested_at
        || !record.verified_absent
        || !is_timestamp(&record.deleted_at)
    {
        return Err(validation("deletion record identity is invalid"));
    }
    Ok(())
}

pub fn deletion_status(output_dir: &Path, metadata: &RequestMetadata) -> Result<&'static str> {
    let intent = load_deletion_intent(output_dir, metadata, &metadata.key_name)?;
    if output_dir.join(DELETION_RECORD).exists() {
        let intent = intent.ok_or_else(|| {
            Error::new(
                ErrorClass::State,
                "deletion record exists without its identity-bound intent",
            )
        })?;
        let record: DeletionRecord = files::read_json(&output_dir.join(DELETION_RECORD))?;
        validate_deletion_record(&record, metadata, &intent)?;
        transcript::local_json("read", DELETION_RECORD, &record)?;
        Ok("completed")
    } else if intent.is_some() {
        Ok("pending recovery")
    } else {
        Ok("not requested")
    }
}

fn fail_deletion(actual: Option<DeletionFault>, expected: DeletionFault) -> Result<()> {
    if actual == Some(expected) {
        Err(Error::new(
            ErrorClass::State,
            "injected deletion recovery fault",
        ))
    } else {
        Ok(())
    }
}

fn prepare_staging(args: &CreateArgs) -> Result<StagingRecord> {
    if args.output_dir.exists() {
        files::validate_output_dir(&args.output_dir)?;
        let staging_path = args.output_dir.join(STAGING_METADATA);
        if !staging_path.exists() {
            if files::is_empty(&args.output_dir)? {
                return publish_new_staging(args);
            }
            return Err(Error::new(
                ErrorClass::State,
                "create requires a fresh output directory",
            ));
        }
        let staging: StagingRecord = files::read_json(&staging_path)?;
        transcript::local_json("read", STAGING_METADATA, &staging)?;
        validate_recovery_entries(&args.output_dir)?;
        let expected_key = args.key_name.as_deref().unwrap_or(&staging.key_name);
        if staging.schema_version != SCHEMA_VERSION
            || staging.provider != PROVIDER_NAME
            || staging.algorithm != ALGORITHM
            || staging.scope != SCOPE
            || staging.subject_cn != args.subject_cn
            || staging.dns_sans != args.dns
            || staging.ip_sans != ip_strings(&args.ip)
            || staging.ca_url != args.ca_url
            || staging.key_name != expected_key
        {
            return Err(Error::new(
                ErrorClass::Precondition,
                "create arguments do not match the recoverable staging record",
            ));
        }
        return Ok(staging);
    }
    files::create_output_dir(&args.output_dir)?;
    publish_new_staging(args)
}

fn publish_new_staging(args: &CreateArgs) -> Result<StagingRecord> {
    let key_name = match &args.key_name {
        Some(value) => value.clone(),
        None => format!("azihsm-tls-{}", hex(&random::<8>()?)),
    };
    let staging = StagingRecord {
        schema_version: SCHEMA_VERSION,
        provider: PROVIDER_NAME.to_owned(),
        key_name,
        algorithm: ALGORITHM.to_owned(),
        scope: SCOPE.to_owned(),
        subject_cn: args.subject_cn.clone(),
        dns_sans: args.dns.clone(),
        ip_sans: ip_strings(&args.ip),
        ca_url: args.ca_url.clone(),
        idempotency_key: hex(&random::<16>()?),
    };
    files::publish_json(&args.output_dir.join(STAGING_METADATA), &staging)?;
    transcript::local_json("written", STAGING_METADATA, &staging)?;
    tracing::info!(event = "staging_record_published");
    Ok(staging)
}

fn load_or_create_csr(
    output_dir: &Path,
    staging: &StagingRecord,
    key: &azihsm_ncrypt::AzihsmKey,
    public_blob: &[u8; 72],
    spki: &[u8],
) -> Result<Vec<u8>> {
    let path = output_dir.join(CSR_DER);
    let ips = parse_ips(&staging.ip_sans)?;
    let csr_der = if path.exists() {
        files::read_bounded(&path, 16_384)?
    } else {
        tracing::info!(event = "csr_generation_started");
        let bytes = csr::build(
            key,
            public_blob,
            &staging.subject_cn,
            &staging.dns_sans,
            &ips,
        )?;
        files::publish(&path, &bytes)?;
        files::publish(
            &output_dir.join(CSR_PEM),
            pem::encode(&pem::Pem::new("CERTIFICATE REQUEST", bytes.clone())).as_bytes(),
        )?;
        tracing::info!(event = "csr_generation_completed");
        bytes
    };
    csr::validate(&csr_der, spki, &staging.subject_cn, &staging.dns_sans, &ips)?;
    Ok(csr_der)
}

fn publish_public_key(output_dir: &Path, spki: &[u8]) -> Result<()> {
    files::publish(&output_dir.join(PUBLIC_DER), spki)?;
    files::publish(
        &output_dir.join(PUBLIC_PEM),
        pem::encode(&pem::Pem::new("PUBLIC KEY", spki)).as_bytes(),
    )?;
    tracing::info!(event = "artifact_published", artifact = "public_key");
    Ok(())
}

fn enroll_and_publish(
    output_dir: &Path,
    metadata: &RequestMetadata,
    spki: &[u8],
    csr_der: &[u8],
    retry_guidance: &str,
) -> Result<()> {
    validate_request_material(metadata, spki, csr_der)?;
    let ips = parse_ips(&metadata.ip_sans)?;
    let client = CaClient::new(&metadata.ca_url);
    client.ready()?;
    let ca = client.metadata()?;
    let root = client.root()?;
    let enrollment = client.enroll(
        csr_der,
        &metadata.idempotency_key,
        &metadata.dns_sans,
        &ips,
        retry_guidance,
    )?;
    verify::verify_chain(&root, &enrollment.leaf_der, spki, &metadata.dns_sans, &ips)?;
    publish_certificate_artifacts(output_dir, &root, &enrollment.leaf_der)?;
    let issuance = IssuanceMetadata {
        schema_version: SCHEMA_VERSION,
        authority_id: ca.authority_id,
        issuance_id: enrollment.issuance_id,
        http_status: enrollment.status,
        root_sha256: hex(&hash_sha256(&root)?),
        leaf_sha256: hex(&hash_sha256(&enrollment.leaf_der)?),
        verified_at: now()?,
        root_der: ROOT_DER.to_owned(),
        leaf_der: LEAF_DER.to_owned(),
        chain_pem: CHAIN_PEM.to_owned(),
    };
    let path = output_dir.join(ISSUANCE_METADATA);
    if path.exists() {
        let existing: IssuanceMetadata = files::read_json(&path)?;
        transcript::local_json("read", ISSUANCE_METADATA, &existing)?;
        if existing.authority_id != issuance.authority_id
            || existing.issuance_id != issuance.issuance_id
            || existing.root_sha256 != issuance.root_sha256
            || existing.leaf_sha256 != issuance.leaf_sha256
        {
            return Err(validation(
                "retry response differs from published issuance metadata",
            ));
        }
    } else {
        files::publish_json(&path, &issuance)?;
        transcript::local_json("written", ISSUANCE_METADATA, &issuance)?;
    }
    tracing::info!(
        event = "issuance_artifacts_published",
        issuance_id = issuance.issuance_id
    );
    Ok(())
}

fn publish_certificate_artifacts(output_dir: &Path, root: &[u8], leaf: &[u8]) -> Result<()> {
    let root_pem = pem::encode(&pem::Pem::new("CERTIFICATE", root));
    let leaf_pem = pem::encode(&pem::Pem::new("CERTIFICATE", leaf));
    files::publish(&output_dir.join(ROOT_DER), root)?;
    files::publish(&output_dir.join(ROOT_PEM), root_pem.as_bytes())?;
    files::publish(&output_dir.join(LEAF_DER), leaf)?;
    files::publish(&output_dir.join(LEAF_PEM), leaf_pem.as_bytes())?;
    files::publish(
        &output_dir.join(CHAIN_PEM),
        format!("{leaf_pem}{root_pem}").as_bytes(),
    )?;
    Ok(())
}

fn validate_request_material(
    metadata: &RequestMetadata,
    spki: &[u8],
    csr_der: &[u8],
) -> Result<()> {
    if metadata.schema_version != SCHEMA_VERSION
        || metadata.provider != PROVIDER_NAME
        || metadata.algorithm != ALGORITHM
        || metadata.scope != SCOPE
        || metadata.public_key_der != PUBLIC_DER
        || metadata.csr_der != CSR_DER
        || metadata.spki_sha256 != hex(&hash_sha256(spki)?)
        || metadata.csr_sha256 != hex(&hash_sha256(csr_der)?)
        || !is_lower_hex_32(&metadata.idempotency_key)
        || validate_key_name(&metadata.key_name).is_err()
        || validate_cn(&metadata.subject_cn).is_err()
        || validate_ca_url(&metadata.ca_url).is_err()
    {
        return Err(validation("request metadata or artifact hash is invalid"));
    }

    let ips = parse_ips(&metadata.ip_sans)?;
    validate_sans(&metadata.dns_sans, &ips).map_err(validation)?;
    csr::validate(
        csr_der,
        spki,
        &metadata.subject_cn,
        &metadata.dns_sans,
        &ips,
    )
}

pub fn validate_stored_request(output_dir: &Path, metadata: &RequestMetadata) -> Result<Vec<u8>> {
    let spki = files::read_bounded(&output_dir.join(PUBLIC_DER), 4096)?;
    let csr_der = files::read_bounded(&output_dir.join(CSR_DER), 16_384)?;
    validate_request_material(metadata, &spki, &csr_der)?;
    Ok(spki)
}

fn validate_recovery_entries(output_dir: &Path) -> Result<()> {
    let allowed = [
        STAGING_METADATA,
        FINALIZE_STARTED,
        FINALIZE_FAILED,
        PUBLIC_DER,
        PUBLIC_PEM,
        CSR_DER,
        CSR_PEM,
    ];
    for entry in fs::read_dir(output_dir)
        .map_err(|error| Error::new(ErrorClass::State, format!("cannot list output: {error}")))?
    {
        let entry = entry.map_err(|error| {
            Error::new(ErrorClass::State, format!("cannot inspect output: {error}"))
        })?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or_else(|| Error::new(ErrorClass::State, "output filename is not Unicode"))?;
        let known_pending = name.starts_with('.') && name.ends_with(".pending");
        if !allowed.contains(&name) && !known_pending {
            return Err(Error::new(
                ErrorClass::State,
                "recoverable create directory contains an unrelated artifact",
            ));
        }
    }
    Ok(())
}

fn is_lower_hex_32(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn load_request(output_dir: &Path) -> Result<RequestMetadata> {
    let metadata = files::read_json(&output_dir.join(REQUEST_METADATA))?;
    transcript::local_json("read", REQUEST_METADATA, &metadata)?;
    Ok(metadata)
}

fn open_provider() -> Result<AzihsmProvider> {
    tracing::info!(event = "provider_open_started");
    let provider = AzihsmProvider::open_named(PROVIDER_NAME)?;
    tracing::info!(event = "provider_open_completed");
    Ok(provider)
}

fn parse_ips(values: &[String]) -> Result<Vec<std::net::IpAddr>> {
    values
        .iter()
        .map(|value| {
            value
                .parse()
                .map_err(|_| validation("stored IP SAN is invalid"))
        })
        .collect()
}

fn ip_strings(values: &[std::net::IpAddr]) -> Vec<String> {
    values.iter().map(ToString::to_string).collect()
}

fn now() -> Result<String> {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|_| Error::new(ErrorClass::State, "cannot format current UTC time"))
}

fn is_timestamp(value: &str) -> bool {
    OffsetDateTime::parse(value, &Rfc3339).is_ok()
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn validation(message: impl Into<String>) -> Error {
    Error::new(ErrorClass::Validation, message)
}

fn usage(message: impl Into<String>) -> Error {
    Error::new(ErrorClass::Usage, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT_DIRECTORY: AtomicUsize = AtomicUsize::new(0);

    #[test]
    fn generated_identifiers_are_lowercase_hex() {
        assert_eq!(hex(&[0, 15, 16, 255]), "000f10ff");
    }

    #[test]
    fn request_metadata_has_no_private_artifact_field() {
        let source = include_str!("model.rs");
        assert!(!source.contains("private_key"));
        assert!(!source.contains("pkcs8"));
    }

    #[test]
    fn staging_recovery_is_immutable() {
        let output_dir = std::env::current_dir()
            .unwrap_or_else(|error| panic!("{error}"))
            .join("target")
            .join(format!("demo-staging-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&output_dir);
        std::fs::create_dir_all(
            output_dir
                .parent()
                .unwrap_or_else(|| panic!("test path has no parent")),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        let args = CreateArgs {
            output_dir: output_dir.clone(),
            subject_cn: "server.test".to_owned(),
            dns: vec!["server.test".to_owned()],
            ip: Vec::new(),
            ca_url: "http://127.0.0.1:8080".to_owned(),
            key_name: Some("azihsm-demo-staging-test".to_owned()),
            retry_guidance: "retry".to_owned(),
        };
        let first = prepare_staging(&args).unwrap_or_else(|error| panic!("{error}"));
        let second = prepare_staging(&args).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(first, second);
        let mut changed = args;
        changed.subject_cn = "different.test".to_owned();
        assert!(prepare_staging(&changed).is_err());
        std::fs::remove_dir_all(output_dir).unwrap_or_else(|error| panic!("{error}"));
    }

    #[test]
    fn deletion_intent_recovers_every_durable_boundary() {
        for fault in [
            DeletionFault::BeforeIntent,
            DeletionFault::AfterIntent,
            DeletionFault::AfterDelete,
            DeletionFault::AfterAbsence,
            DeletionFault::AfterFinalStaging,
            DeletionFault::AfterFinalPublication,
        ] {
            let output_dir = deletion_directory(fault);
            let metadata = deletion_metadata();
            let exists = Cell::new(true);
            let result = run_fake_deletion(&output_dir, &metadata, &exists, Some(fault));
            assert!(result.is_err());
            if fault == DeletionFault::BeforeIntent {
                assert!(!output_dir.join(DELETION_INTENT).exists());
                assert!(exists.get());
                assert_eq!(
                    deletion_status(&output_dir, &metadata)
                        .unwrap_or_else(|error| panic!("{error}")),
                    "not requested"
                );
            } else {
                assert!(output_dir.join(DELETION_INTENT).exists());
                assert_eq!(
                    deletion_status(&output_dir, &metadata)
                        .unwrap_or_else(|error| panic!("{error}")),
                    if output_dir.join(DELETION_RECORD).exists() {
                        "completed"
                    } else {
                        "pending recovery"
                    }
                );
                run_fake_deletion(&output_dir, &metadata, &exists, None)
                    .unwrap_or_else(|error| panic!("{error}"));
                assert!(output_dir.join(DELETION_RECORD).exists());
                assert!(!exists.get());
                assert_eq!(
                    deletion_status(&output_dir, &metadata)
                        .unwrap_or_else(|error| panic!("{error}")),
                    "completed"
                );
                run_fake_deletion(&output_dir, &metadata, &exists, None)
                    .unwrap_or_else(|error| panic!("{error}"));
            }
            std::fs::remove_dir_all(output_dir).unwrap_or_else(|error| panic!("{error}"));
        }
    }

    #[test]
    fn deletion_rejects_absence_or_mismatched_intent_without_evidence() {
        let output_dir = deletion_directory(DeletionFault::BeforeIntent);
        let metadata = deletion_metadata();
        let absent = Cell::new(false);
        assert!(run_fake_deletion(&output_dir, &metadata, &absent, None).is_err());
        assert!(!output_dir.join(DELETION_INTENT).exists());

        let bad = DeletionIntent {
            schema_version: SCHEMA_VERSION,
            provider: metadata.provider.clone(),
            key_name: metadata.key_name.clone(),
            spki_sha256: "ff".repeat(32),
            confirmation_key_name: metadata.key_name.clone(),
            operation_id: "11".repeat(16),
            requested_at: now().unwrap_or_else(|error| panic!("{error}")),
        };
        files::publish_json(&output_dir.join(DELETION_INTENT), &bad)
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(run_fake_deletion(&output_dir, &metadata, &absent, None).is_err());
        std::fs::remove_dir_all(output_dir).unwrap_or_else(|error| panic!("{error}"));
    }

    fn run_fake_deletion(
        output_dir: &Path,
        metadata: &RequestMetadata,
        exists: &Cell<bool>,
        fault: Option<DeletionFault>,
    ) -> Result<()> {
        run_deletion(
            output_dir,
            metadata,
            &metadata.key_name,
            || Ok(exists.get()),
            || {
                if !exists.replace(false) {
                    return Err(Error::new(ErrorClass::State, "fake key was already absent"));
                }
                Ok(())
            },
            || {
                if exists.get() {
                    Err(Error::new(ErrorClass::State, "fake key still exists"))
                } else {
                    Ok(())
                }
            },
            fault,
        )
    }

    fn deletion_directory(fault: DeletionFault) -> std::path::PathBuf {
        let directory = std::env::current_dir()
            .unwrap_or_else(|error| panic!("{error}"))
            .join("target")
            .join(format!(
                "demo-deletion-{}-{:?}-{}",
                std::process::id(),
                fault,
                NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
            ));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(
            directory
                .parent()
                .unwrap_or_else(|| panic!("test path has no parent")),
        )
        .unwrap_or_else(|error| panic!("{error}"));
        files::create_output_dir(&directory).unwrap_or_else(|error| panic!("{error}"));
        directory
    }

    fn deletion_metadata() -> RequestMetadata {
        RequestMetadata {
            schema_version: SCHEMA_VERSION,
            provider: PROVIDER_NAME.to_owned(),
            key_name: "azihsm-delete-recovery-test".to_owned(),
            algorithm: ALGORITHM.to_owned(),
            scope: SCOPE.to_owned(),
            subject_cn: "server.test".to_owned(),
            dns_sans: vec!["server.test".to_owned()],
            ip_sans: Vec::new(),
            ca_url: "http://127.0.0.1:8080".to_owned(),
            idempotency_key: "00".repeat(16),
            spki_sha256: "11".repeat(32),
            csr_sha256: "22".repeat(32),
            public_key_der: PUBLIC_DER.to_owned(),
            csr_der: CSR_DER.to_owned(),
        }
    }
}
