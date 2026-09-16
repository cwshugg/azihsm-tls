//! Shared synchronous identity preparation for the AziHSM TLS server.

use crate::ca_cli::{CreateArgs, DeleteKeyArgs};
use crate::{Error, ErrorClass, Result, workflow};
use azihsm_ca_client::files;
use azihsm_ca_client::model::{
    CSR_DER, ISSUANCE_METADATA, IssuanceMetadata, LEAF_DER, PUBLIC_DER, REQUEST_METADATA, ROOT_DER,
    RequestMetadata, SCHEMA_VERSION,
};
use azihsm_ca_client::{
    CaClient, CaFailure, CaFailureKind, CaOperation, csr, state_lock::StateLock, verify,
};
use azihsm_ncrypt::{AzihsmSession, PROVIDER_NAME, hash_sha256, random};
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};
use x509_parser::prelude::{FromDer, X509Certificate};

const RENEWALS: &str = "renewals";
const INTENT: &str = "intent.json";
const SELECTION: &str = "selection.json";
const MAX_CACHE_AGE: Duration = Duration::days(7);

/// Immutable identity requested by the TLS server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedIdentity {
    pub dns: Vec<String>,
    pub ips: Vec<IpAddr>,
    pub spki_der: Vec<u8>,
}

/// A verified certificate chain with explicit current-time bounds.
#[derive(Debug, Clone)]
pub struct ValidatedServerChain {
    pub not_before: OffsetDateTime,
    pub not_after: OffsetDateTime,
}

/// How startup selected its certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheOutcome {
    Created,
    Renewed,
    Current,
    AvailabilityFallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CacheState {
    MissingOrInvalid,
    Current,
    NearExpiry,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RenewalDecision {
    outcome: CacheOutcome,
    reload: bool,
}

/// Inputs for synchronous key enrollment and cache selection.
#[derive(Debug, Clone)]
pub struct ServerPrepareOptions {
    pub state_dir: PathBuf,
    pub dns: Vec<String>,
    pub ips: Vec<IpAddr>,
    pub ca_url: String,
    pub key_name: Option<String>,
    pub now: OffsetDateTime,
}

/// Complete identity whose lock and provider-backed session outlive serving.
#[derive(Debug)]
pub struct PreparedIdentity {
    pub session: Arc<AzihsmSession>,
    pub key_name: String,
    pub spki_der: Vec<u8>,
    pub chain_der: Vec<Vec<u8>>,
    pub root_der: Vec<u8>,
    pub not_before: OffsetDateTime,
    pub not_after: OffsetDateTime,
    pub issuance_id: String,
    pub cache_outcome: CacheOutcome,
    _state_lock: StateLock,
}

/// Closed preparation failures used by startup policy.
#[derive(Debug)]
pub enum PrepareIdentityError {
    Ca(CaFailure),
    State(Error),
    Provider(Error),
    Validation(Error),
}

impl std::fmt::Display for PrepareIdentityError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ca(failure) => write!(
                formatter,
                "CA {:?} failure during {:?}: {}",
                failure.kind, failure.operation, failure.source
            ),
            Self::State(error) | Self::Provider(error) | Self::Validation(error) => {
                error.fmt(formatter)
            }
        }
    }
}

impl std::error::Error for PrepareIdentityError {}

impl From<CaFailure> for PrepareIdentityError {
    fn from(value: CaFailure) -> Self {
        Self::Ca(value)
    }
}

#[derive(Debug, Clone)]
struct Candidate {
    directory: PathBuf,
    operation_id: String,
    root: Vec<u8>,
    leaf: Vec<u8>,
    issuance: IssuanceMetadata,
    validity: ValidatedServerChain,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RenewalIntent {
    schema_version: u32,
    operation_id: String,
    csr_sha256: String,
    spki_sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectionRecord {
    schema_version: u32,
    operation_id: String,
    issuance_id: String,
}

/// Prepares a persistent identity synchronously before a Tokio runtime exists.
pub fn prepare_server_identity(
    options: ServerPrepareOptions,
) -> std::result::Result<PreparedIdentity, PrepareIdentityError> {
    tracing::info!(
        event = "identity_preparation_started",
        message = "Locking state, opening the AziHSM key, and selecting a verified certificate before Tokio starts."
    );
    let state_lock = StateLock::acquire(&options.state_dir).map_err(classify)?;
    let created = !options.state_dir.join(REQUEST_METADATA).exists();
    if created {
        workflow::create(CreateArgs {
            output_dir: options.state_dir.clone(),
            subject_cn: subject_cn(&options)?,
            dns: options.dns.clone(),
            ip: options.ips.clone(),
            ca_url: options.ca_url.clone(),
            key_name: options.key_name.clone(),
        })
        .map_err(classify)?;
    }

    let request = workflow::load_request(&options.state_dir).map_err(classify)?;
    require_identity_match(&request, &options)?;
    let session =
        Arc::new(AzihsmSession::open(PROVIDER_NAME, &request.key_name).map_err(classify)?);
    session.kat().map_err(classify)?;
    let spki = csr::spki_der(&session.public_blob().map_err(classify)?).map_err(classify)?;
    let stored_spki =
        files::read_bounded(&options.state_dir.join(PUBLIC_DER), 4096).map_err(classify)?;
    if spki != stored_spki || hex(&hash_sha256(&spki).map_err(classify)?) != request.spki_sha256 {
        return Err(PrepareIdentityError::Validation(validation(
            "named key does not match persisted SPKI",
        )));
    }
    let expected = ExpectedIdentity {
        dns: request.dns_sans.clone(),
        ips: parse_ips(&request.ip_sans).map_err(classify)?,
        spki_der: spki.clone(),
    };
    let mut candidates = load_candidates(&options.state_dir, &expected, options.now)?;
    candidates.sort_by(candidate_order);
    let cached = candidates.last().cloned();

    let cache_state = cache_state(cached.as_ref().map(|value| &value.validity), options.now);
    let outcome = if created {
        CacheOutcome::Created
    } else {
        let decision = select_or_renew(cache_state, cached.is_some(), || {
            renew(
                &options.state_dir,
                &request,
                &expected,
                cached.as_ref(),
                options.now,
            )
        })?;
        if decision.reload {
            candidates = load_candidates(&options.state_dir, &expected, options.now)?;
            candidates.sort_by(candidate_order);
        }
        decision.outcome
    };

    let selected = candidates.last().cloned().ok_or_else(|| {
        PrepareIdentityError::Validation(validation("no currently valid certificate generation"))
    })?;
    publish_selection(&selected).map_err(classify)?;
    prune_generations(&options.state_dir, &candidates, &selected);
    let selection_message = match outcome {
        CacheOutcome::Created => "Selected the newly enrolled certificate identity.",
        CacheOutcome::Renewed => "Selected a newly renewed certificate identity.",
        CacheOutcome::Current => {
            "Selected the valid cached certificate because renewal is not yet required."
        }
        CacheOutcome::AvailabilityFallback => {
            "Selected the still-valid cached certificate because the CA was unavailable."
        }
    };
    tracing::info!(
        event = "certificate_generation_selected",
        cache_outcome = ?outcome,
        message = selection_message
    );
    Ok(PreparedIdentity {
        session,
        key_name: request.key_name,
        spki_der: spki,
        chain_der: tls_chain(selected.leaf),
        root_der: selected.root,
        not_before: selected.validity.not_before,
        not_after: selected.validity.not_after,
        issuance_id: selected.issuance.issuance_id,
        cache_outcome: outcome,
        _state_lock: state_lock,
    })
}

/// Prints the existing public identity and certificate summary under lock.
pub fn show_server_identity(state_dir: &Path) -> Result<()> {
    let _lock = StateLock::acquire(state_dir)?;
    let request = workflow::load_request(state_dir)?;
    let spki = workflow::validate_stored_request(state_dir, &request)?;
    let expected = ExpectedIdentity {
        dns: request.dns_sans.clone(),
        ips: parse_ips(&request.ip_sans)?,
        spki_der: spki,
    };
    let mut candidates = load_candidates(state_dir, &expected, OffsetDateTime::now_utc())
        .map_err(|error| state(error.to_string()))?;
    candidates.sort_by(candidate_order);
    let selected = candidates
        .last()
        .ok_or_else(|| validation("no currently valid certificate generation"))?;
    println!("Provider: {}", request.provider);
    println!("Key name: {}", request.key_name);
    println!("Algorithm: {}", request.algorithm);
    println!("DNS SANs: {}", request.dns_sans.join(", "));
    println!("IP SANs: {}", request.ip_sans.join(", "));
    println!("SPKI SHA-256: {}", request.spki_sha256);
    println!("Authority ID: {}", selected.issuance.authority_id);
    println!("Issuance ID: {}", selected.issuance.issuance_id);
    println!("Certificate not before: {}", selected.validity.not_before);
    println!("Certificate not after: {}", selected.validity.not_after);
    println!(
        "Key deletion: {}",
        workflow::deletion_status(state_dir, &request)?
    );
    Ok(())
}

/// Deletes the exact persisted key using the durable deletion-intent protocol.
pub fn delete_server_key(state_dir: &Path, confirmation: String) -> Result<()> {
    let _lock = StateLock::acquire(state_dir)?;
    workflow::delete_key(DeleteKeyArgs {
        output_dir: state_dir.to_owned(),
        confirm_key_name: confirmation,
    })
}

/// Verifies the exact CA profile and explicit caller-supplied current time.
pub fn validate_server_chain(
    root_der: &[u8],
    leaf_der: &[u8],
    expected: &ExpectedIdentity,
    now: OffsetDateTime,
) -> Result<ValidatedServerChain> {
    verify::verify_chain_profile(
        root_der,
        leaf_der,
        &expected.spki_der,
        &expected.dns,
        &expected.ips,
    )?;
    let root = parse_certificate(root_der, "root")?;
    let leaf = parse_certificate(leaf_der, "leaf")?;
    require_valid_at(&root, now, "root")?;
    require_valid_at(&leaf, now, "leaf")?;
    Ok(ValidatedServerChain {
        not_before: timestamp(leaf.validity().not_before.timestamp())?,
        not_after: timestamp(leaf.validity().not_after.timestamp())?,
    })
}

pub(crate) fn log_renewal_started() {
    tracing::info!(
        event = "certificate_renewal_started",
        message = "The certificate is missing, invalid, or within seven days of expiry, so startup is requesting a renewal."
    );
}

fn renew(
    state_dir: &Path,
    request: &RequestMetadata,
    expected: &ExpectedIdentity,
    cached: Option<&Candidate>,
    now: OffsetDateTime,
) -> std::result::Result<(), CaFailure> {
    log_renewal_started();
    let client = CaClient::new(&request.ca_url);
    client.ready_typed()?;
    let metadata = client.metadata_typed()?;
    let root = client.root_typed()?;
    if let Some(cached) = cached {
        let root_hash =
            hex(&hash_sha256(&root)
                .map_err(|source| protocol_failure(CaOperation::Root, source))?);
        if cached.issuance.authority_id != metadata.authority_id
            || cached.issuance.root_sha256 != root_hash
        {
            return Err(protocol_failure(
                CaOperation::Metadata,
                validation("CA authority identity changed"),
            ));
        }
    }
    let csr = files::read_bounded(&state_dir.join(CSR_DER), 16_384)
        .map_err(|source| protocol_failure(CaOperation::Enrollment, source))?;
    let enrollment = client.enroll_typed(
        &csr,
        &request.idempotency_key,
        &request.dns_sans,
        &expected.ips,
        "After restarting or reconfiguring the CA, rerun azihsm-tls-server with the same state \
         directory and identity arguments. The existing AziHSM key, CSR, and idempotency key \
         will be reused.",
    )?;
    let validity = validate_server_chain(&root, &enrollment.leaf_der, expected, now)
        .map_err(|source| protocol_failure(CaOperation::Enrollment, source))?;
    let (operation_id, directory) = match pending_renewal(state_dir, request)
        .map_err(|source| protocol_failure(CaOperation::Enrollment, source))?
    {
        Some(pending) => pending,
        None => {
            let operation_id = hex(&random::<16>()
                .map_err(|source| protocol_failure(CaOperation::Enrollment, source))?);
            let directory = state_dir.join(RENEWALS).join(&operation_id);
            (operation_id, directory)
        }
    };
    ensure_directory(&directory)
        .map_err(|source| protocol_failure(CaOperation::Enrollment, source))?;
    let intent = RenewalIntent {
        schema_version: SCHEMA_VERSION,
        operation_id,
        csr_sha256: request.csr_sha256.clone(),
        spki_sha256: request.spki_sha256.clone(),
    };
    files::publish_json(&directory.join(INTENT), &intent)
        .map_err(|source| protocol_failure(CaOperation::Enrollment, source))?;
    files::publish(&directory.join(ROOT_DER), &root)
        .map_err(|source| protocol_failure(CaOperation::Enrollment, source))?;
    files::publish(&directory.join(LEAF_DER), &enrollment.leaf_der)
        .map_err(|source| protocol_failure(CaOperation::Enrollment, source))?;
    let issuance = IssuanceMetadata {
        schema_version: SCHEMA_VERSION,
        authority_id: metadata.authority_id,
        issuance_id: enrollment.issuance_id,
        http_status: enrollment.status,
        root_sha256: hex(&hash_sha256(&root)
            .map_err(|source| protocol_failure(CaOperation::Enrollment, source))?),
        leaf_sha256: hex(&hash_sha256(&enrollment.leaf_der)
            .map_err(|source| protocol_failure(CaOperation::Enrollment, source))?),
        verified_at: now.format(&Rfc3339).map_err(|_| {
            protocol_failure(
                CaOperation::Enrollment,
                validation("cannot format verification time"),
            )
        })?,
        root_der: ROOT_DER.to_owned(),
        leaf_der: LEAF_DER.to_owned(),
        chain_pem: "chain.pem".to_owned(),
    };
    files::publish_json(&directory.join(ISSUANCE_METADATA), &issuance)
        .map_err(|source| protocol_failure(CaOperation::Enrollment, source))?;
    let reopened_root = files::read_bounded(&directory.join(ROOT_DER), 256 * 1024)
        .map_err(|source| protocol_failure(CaOperation::Enrollment, source))?;
    let reopened_leaf = files::read_bounded(&directory.join(LEAF_DER), 256 * 1024)
        .map_err(|source| protocol_failure(CaOperation::Enrollment, source))?;
    validate_server_chain(&reopened_root, &reopened_leaf, expected, now)
        .map_err(|source| protocol_failure(CaOperation::Enrollment, source))?;
    let _ = validity;
    tracing::info!(
        event = "certificate_renewal_completed",
        message = "Renewal completed and the new certificate generation passed identity and validity checks."
    );
    Ok(())
}

fn load_candidates(
    state_dir: &Path,
    expected: &ExpectedIdentity,
    now: OffsetDateTime,
) -> std::result::Result<Vec<Candidate>, PrepareIdentityError> {
    let mut paths = Vec::new();
    if state_dir.join(ISSUANCE_METADATA).exists() {
        paths.push((
            state_dir.to_owned(),
            "00000000000000000000000000000000".to_owned(),
        ));
    }
    let renewals = state_dir.join(RENEWALS);
    if renewals.exists() {
        let mut incomplete = 0_usize;
        for entry in fs::read_dir(&renewals).map_err(|error| {
            PrepareIdentityError::State(state(format!("cannot list renewals: {error}")))
        })? {
            let entry = entry.map_err(|error| {
                PrepareIdentityError::State(state(format!("cannot inspect renewal: {error}")))
            })?;
            let path = entry.path();
            if path.is_dir() && path.join(ISSUANCE_METADATA).exists() {
                paths.push((path, entry.file_name().to_string_lossy().into_owned()));
            } else if path.is_dir()
                && !entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("quarantine-")
            {
                incomplete += 1;
            }
        }
        if incomplete > 1 {
            return Err(PrepareIdentityError::State(state(
                "multiple incomplete renewal generations require operator review",
            )));
        }
    }
    let mut candidates = Vec::new();
    for (directory, operation_id) in paths {
        match load_candidate(&directory, operation_id.clone(), expected, now) {
            Ok(candidate) => candidates.push(candidate),
            Err(_) => {
                tracing::warn!(
                    event = "certificate_generation_rejected",
                    message = "Rejected a cached certificate generation because it did not pass verification."
                );
                if directory != state_dir {
                    let quarantine = directory.with_file_name(format!("quarantine-{operation_id}"));
                    if !quarantine.exists()
                        && let Err(error) = fs::rename(&directory, quarantine)
                    {
                        tracing::warn!(
                            event = "generation_quarantine_failed",
                            reason = %error,
                            message = "A rejected cached generation could not be quarantined, but it was not selected."
                        );
                    }
                }
            }
        }
    }
    Ok(candidates)
}

fn load_candidate(
    directory: &Path,
    operation_id: String,
    expected: &ExpectedIdentity,
    now: OffsetDateTime,
) -> Result<Candidate> {
    let root = files::read_bounded(&directory.join(ROOT_DER), 256 * 1024)?;
    let leaf = files::read_bounded(&directory.join(LEAF_DER), 256 * 1024)?;
    let issuance: IssuanceMetadata = files::read_json(&directory.join(ISSUANCE_METADATA))?;
    let validity = validate_server_chain(&root, &leaf, expected, now)?;
    if issuance.schema_version != SCHEMA_VERSION
        || issuance.root_sha256 != hex(&hash_sha256(&root)?)
        || issuance.leaf_sha256 != hex(&hash_sha256(&leaf)?)
    {
        return Err(validation("issuance metadata does not match certificates"));
    }
    Ok(Candidate {
        directory: directory.to_owned(),
        operation_id,
        root,
        leaf,
        issuance,
        validity,
    })
}

fn pending_renewal(
    state_dir: &Path,
    request: &RequestMetadata,
) -> Result<Option<(String, PathBuf)>> {
    let renewals = state_dir.join(RENEWALS);
    if !renewals.exists() {
        return Ok(None);
    }
    let mut pending = None;
    for entry in fs::read_dir(renewals)
        .map_err(|error| state(format!("cannot list renewal staging: {error}")))?
    {
        let entry =
            entry.map_err(|error| state(format!("cannot inspect renewal staging: {error}")))?;
        let directory = entry.path();
        let operation_id = entry.file_name().to_string_lossy().into_owned();
        if !directory.is_dir()
            || directory.join(ISSUANCE_METADATA).exists()
            || operation_id.starts_with("quarantine-")
        {
            continue;
        }
        if pending.is_some() {
            return Err(state(
                "multiple incomplete renewal generations require operator review",
            ));
        }
        if operation_id.len() != 32
            || !operation_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(validation("renewal operation identifier is invalid"));
        }
        let intent_path = directory.join(INTENT);
        if intent_path.exists() {
            let intent: RenewalIntent = files::read_json(&intent_path)?;
            if intent.schema_version != SCHEMA_VERSION
                || intent.operation_id != operation_id
                || intent.csr_sha256 != request.csr_sha256
                || intent.spki_sha256 != request.spki_sha256
            {
                return Err(validation("renewal intent identity is invalid"));
            }
        }
        pending = Some((operation_id, directory));
    }
    Ok(pending)
}

fn prune_generations(state_dir: &Path, candidates: &[Candidate], selected: &Candidate) {
    let mut retained = candidates
        .iter()
        .rev()
        .take(3)
        .map(|value| &value.directory);
    let retained: Vec<_> = retained.by_ref().collect();
    for candidate in candidates {
        if candidate.directory == selected.directory || retained.contains(&&candidate.directory) {
            continue;
        }
        let result = if candidate.directory == state_dir {
            [
                ROOT_DER,
                "root.pem",
                LEAF_DER,
                "leaf.pem",
                "chain.pem",
                ISSUANCE_METADATA,
                SELECTION,
            ]
            .into_iter()
            .try_for_each(|name| {
                let path = state_dir.join(name);
                if path.exists() {
                    fs::remove_file(path)
                } else {
                    Ok(())
                }
            })
        } else {
            fs::remove_dir_all(&candidate.directory)
        };
        if let Err(error) = result {
            tracing::warn!(
                event = "generation_prune_failed",
                reason = %error,
                message = "Old-generation cleanup failed without invalidating the selected certificate identity."
            );
        }
    }
}

fn publish_selection(selected: &Candidate) -> Result<()> {
    let record = SelectionRecord {
        schema_version: SCHEMA_VERSION,
        operation_id: selected.operation_id.clone(),
        issuance_id: selected.issuance.issuance_id.clone(),
    };
    files::publish_json(&selected.directory.join(SELECTION), &record)
}

fn candidate_order(left: &Candidate, right: &Candidate) -> std::cmp::Ordering {
    left.validity
        .not_after
        .cmp(&right.validity.not_after)
        .then(left.issuance.verified_at.cmp(&right.issuance.verified_at))
        .then(left.operation_id.cmp(&right.operation_id))
}

fn tls_chain(leaf: Vec<u8>) -> Vec<Vec<u8>> {
    vec![leaf]
}

fn cache_state(validity: Option<&ValidatedServerChain>, now: OffsetDateTime) -> CacheState {
    match validity {
        None => CacheState::MissingOrInvalid,
        Some(value) if value.not_after - now > MAX_CACHE_AGE => CacheState::Current,
        Some(_) => CacheState::NearExpiry,
    }
}

fn select_or_renew(
    cache_state: CacheState,
    cached: bool,
    renew: impl FnOnce() -> std::result::Result<(), CaFailure>,
) -> std::result::Result<RenewalDecision, PrepareIdentityError> {
    if cache_state == CacheState::Current {
        return Ok(RenewalDecision {
            outcome: CacheOutcome::Current,
            reload: false,
        });
    }
    match renew() {
        Ok(()) => Ok(RenewalDecision {
            outcome: CacheOutcome::Renewed,
            reload: true,
        }),
        Err(failure) if failure.kind == CaFailureKind::Availability && cached => {
            tracing::warn!(
                event = "renewal_availability_fallback",
                message = "The CA is unavailable, so startup is using the already verified and still-valid cached certificate."
            );
            Ok(RenewalDecision {
                outcome: CacheOutcome::AvailabilityFallback,
                reload: false,
            })
        }
        Err(failure) => Err(PrepareIdentityError::Ca(failure)),
    }
}

fn require_identity_match(
    request: &RequestMetadata,
    options: &ServerPrepareOptions,
) -> std::result::Result<(), PrepareIdentityError> {
    if request.provider != PROVIDER_NAME
        || request.dns_sans != options.dns
        || request.ip_sans
            != options
                .ips
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        || request.ca_url != options.ca_url
        || options
            .key_name
            .as_ref()
            .is_some_and(|name| name != &request.key_name)
    {
        return Err(PrepareIdentityError::Validation(validation(
            "run arguments do not match the persisted identity",
        )));
    }
    Ok(())
}

fn subject_cn(options: &ServerPrepareOptions) -> std::result::Result<String, PrepareIdentityError> {
    options
        .dns
        .first()
        .cloned()
        .or_else(|| options.ips.first().map(ToString::to_string))
        .ok_or_else(|| PrepareIdentityError::Validation(validation("at least one SAN is required")))
}

fn ensure_directory(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.exists()
    {
        fs::create_dir(parent)
            .map_err(|error| state(format!("cannot create renewals directory: {error}")))?;
    }
    files::create_output_dir(path)
}

fn parse_certificate<'a>(der: &'a [u8], label: &str) -> Result<X509Certificate<'a>> {
    let (remaining, certificate) = X509Certificate::from_der(der)
        .map_err(|_| validation(format!("{label} certificate DER is invalid")))?;
    if !remaining.is_empty() {
        return Err(validation(format!("{label} certificate has trailing DER")));
    }
    Ok(certificate)
}

fn require_valid_at(
    certificate: &X509Certificate<'_>,
    now: OffsetDateTime,
    label: &str,
) -> Result<()> {
    match validity_status(
        certificate.validity().not_before.timestamp(),
        certificate.validity().not_after.timestamp(),
        now.unix_timestamp(),
    ) {
        ValidityStatus::Current => Ok(()),
        ValidityStatus::NotYetValid => {
            Err(validation(format!("{label} certificate is not yet valid")))
        }
        ValidityStatus::Expired => Err(validation(format!("{label} certificate is expired"))),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValidityStatus {
    NotYetValid,
    Current,
    Expired,
}

fn validity_status(not_before: i64, not_after: i64, now: i64) -> ValidityStatus {
    if now < not_before {
        ValidityStatus::NotYetValid
    } else if now > not_after {
        ValidityStatus::Expired
    } else {
        ValidityStatus::Current
    }
}

fn timestamp(value: i64) -> Result<OffsetDateTime> {
    OffsetDateTime::from_unix_timestamp(value)
        .map_err(|_| validation("certificate validity timestamp is out of range"))
}

fn parse_ips(values: &[String]) -> Result<Vec<IpAddr>> {
    values
        .iter()
        .map(|value| {
            value
                .parse()
                .map_err(|_| validation("stored IP SAN is invalid"))
        })
        .collect()
}

fn protocol_failure(operation: CaOperation, source: Error) -> CaFailure {
    CaFailure {
        kind: CaFailureKind::Protocol,
        operation,
        source,
    }
}

fn classify(error: Error) -> PrepareIdentityError {
    match error.class() {
        ErrorClass::Provider | ErrorClass::Issuance => PrepareIdentityError::Provider(error),
        ErrorClass::Validation => PrepareIdentityError::Validation(error),
        _ => PrepareIdentityError::State(error),
    }
}

fn validation(message: impl Into<String>) -> Error {
    Error::new(ErrorClass::Validation, message)
}

fn state(message: impl Into<String>) -> Error {
    Error::new(ErrorClass::State, message)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(value, "{byte:02x}");
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_order_uses_expiry_then_verification_then_operation() {
        assert_eq!(MAX_CACHE_AGE, Duration::days(7));
    }

    #[test]
    fn production_selection_policy_is_exhaustive_and_fail_closed() {
        let failure = |kind| CaFailure {
            kind,
            operation: CaOperation::Readiness,
            source: validation("injected CA outcome"),
        };
        let cases = [
            (
                CacheState::Current,
                false,
                None,
                Some(CacheOutcome::Current),
            ),
            (CacheState::Current, true, None, Some(CacheOutcome::Current)),
            (
                CacheState::NearExpiry,
                true,
                None,
                Some(CacheOutcome::Renewed),
            ),
            (
                CacheState::NearExpiry,
                true,
                Some(CaFailureKind::Availability),
                Some(CacheOutcome::AvailabilityFallback),
            ),
            (
                CacheState::NearExpiry,
                true,
                Some(CaFailureKind::Protocol),
                None,
            ),
            (
                CacheState::MissingOrInvalid,
                false,
                None,
                Some(CacheOutcome::Renewed),
            ),
            (
                CacheState::MissingOrInvalid,
                false,
                Some(CaFailureKind::Availability),
                None,
            ),
            (
                CacheState::MissingOrInvalid,
                false,
                Some(CaFailureKind::Protocol),
                None,
            ),
        ];
        for (state, cached, ca_failure, expected) in cases {
            let result = select_or_renew(state, cached, || {
                ca_failure.map_or(Ok(()), |kind| Err(failure(kind)))
            });
            assert_eq!(result.ok().map(|decision| decision.outcome), expected);
        }
    }

    #[test]
    fn validity_boundaries_are_inclusive_with_zero_skew() {
        assert_eq!(validity_status(10, 20, 9), ValidityStatus::NotYetValid);
        assert_eq!(validity_status(10, 20, 10), ValidityStatus::Current);
        assert_eq!(validity_status(10, 20, 20), ValidityStatus::Current);
        assert_eq!(validity_status(10, 20, 21), ValidityStatus::Expired);
        let now =
            OffsetDateTime::from_unix_timestamp(100).unwrap_or_else(|error| panic!("{error}"));
        let current = ValidatedServerChain {
            not_before: now - Duration::days(1),
            not_after: now + Duration::days(8),
        };
        let near = ValidatedServerChain {
            not_before: now - Duration::days(1),
            not_after: now + Duration::days(7),
        };
        assert_eq!(cache_state(Some(&current), now), CacheState::Current);
        assert_eq!(cache_state(Some(&near), now), CacheState::NearExpiry);
        assert_eq!(cache_state(None, now), CacheState::MissingOrInvalid);
    }

    #[test]
    fn prepared_tls_chain_contains_leaf_without_trust_root() {
        let leaf = vec![1, 2, 3];
        let root = vec![4, 5, 6];
        let chain = tls_chain(leaf.clone());
        assert_eq!(chain, vec![leaf]);
        assert!(!chain.contains(&root));
    }
}
