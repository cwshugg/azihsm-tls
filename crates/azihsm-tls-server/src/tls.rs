//! TLS 1.3 configuration and rustls signing adapter for AziHSM.

use crate::identity::PreparedIdentity;
use azihsm_ncrypt::{AzihsmSession, hash_sha256, p1363_to_der};
use rustls::crypto::KeyProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, SubjectPublicKeyInfoDer};
use rustls::server::{NoServerSessionStorage, ServerConfig};
use rustls::sign::{CertifiedKey, Signer, SigningKey, SingleCertAndKey};
use rustls::{Error, SignatureAlgorithm, SignatureScheme};
use std::sync::Arc;

#[derive(Debug)]
pub struct AzihsmRustlsKey {
    session: Arc<AzihsmSession>,
    spki: Vec<u8>,
}

impl AzihsmRustlsKey {
    pub fn new(session: Arc<AzihsmSession>, spki: Vec<u8>) -> Self {
        Self { session, spki }
    }
}

impl SigningKey for AzihsmRustlsKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .contains(&SignatureScheme::ECDSA_NISTP256_SHA256)
            .then(|| {
                Box::new(AzihsmRustlsSigner {
                    session: Arc::clone(&self.session),
                }) as Box<dyn Signer>
            })
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(SubjectPublicKeyInfoDer::from(self.spki.as_slice()))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

#[derive(Debug)]
struct AzihsmRustlsSigner {
    session: Arc<AzihsmSession>,
}

impl Signer for AzihsmRustlsSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        tokio::task::block_in_place(|| {
            let digest = hash_sha256(message).map_err(tls_error)?;
            let signature = self.session.sign_digest(&digest).map_err(tls_error)?;
            p1363_to_der(&signature).map_err(tls_error)
        })
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ECDSA_NISTP256_SHA256
    }
}

#[derive(Debug)]
struct RejectPrivateKeys;

impl KeyProvider for RejectPrivateKeys {
    fn load_private_key(
        &self,
        _key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn SigningKey>, Error> {
        Err(Error::General(
            "software private keys are disabled".to_owned(),
        ))
    }
}

pub fn build_server_config(identity: &PreparedIdentity) -> Result<Arc<ServerConfig>, Error> {
    build_config(
        identity.chain_der.clone(),
        Arc::new(AzihsmRustlsKey::new(
            Arc::clone(&identity.session),
            identity.spki_der.clone(),
        )),
    )
}

pub fn build_config(
    chain: Vec<Vec<u8>>,
    signing_key: Arc<dyn SigningKey>,
) -> Result<Arc<ServerConfig>, Error> {
    let certificates = chain
        .into_iter()
        .map(CertificateDer::from)
        .collect::<Vec<_>>();
    let certified = CertifiedKey::new(certificates, signing_key);
    certified.keys_match()?;
    let mut provider = rustls::crypto::ring::default_provider();
    provider.key_provider = &RejectPrivateKeys;
    let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SingleCertAndKey::from(certified)));
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    config.max_early_data_size = 0;
    config.send_half_rtt_data = false;
    tracing::info!(event = "rustls_configuration_completed");
    Ok(Arc::new(config))
}

fn tls_error(error: impl std::fmt::Display) -> Error {
    Error::General(format!("AziHSM signing failed: {error}"))
}

const _: fn() = || {
    fn require_send_sync<T: Send + Sync>() {}
    require_send_sync::<AzihsmSession>();
    require_send_sync::<AzihsmRustlsKey>();
    require_send_sync::<AzihsmRustlsSigner>();
};
