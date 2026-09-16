//! Deterministic TLS 1.3 handshake through the production config builder.

use azihsm_tls_server::server::{Admission, ConnectionRuntime, serve_connection};
use azihsm_tls_server::tls::build_config;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType,
};
use rustls::client::Resumption;
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, SubjectPublicKeyInfoDer,
};
use rustls::sign::{Signer, SigningKey};
use rustls::{ClientConfig, RootCertStore, SignatureAlgorithm, SignatureScheme};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, OwnedSemaphorePermit, watch};
use tokio::task::JoinHandle;
use tokio::time::{Instant, timeout};
use tokio_rustls::{TlsAcceptor, TlsConnector};

const MAX_REQUEST: usize = 1_048_576;
const PREFIX: &[u8] = b"azihsm-tls-server: ";

#[derive(Debug)]
struct TestRuntime {
    now: Mutex<Option<Instant>>,
    reached_response: Option<Arc<Notify>>,
    release_response: Option<Arc<Notify>>,
    write_timeout: Duration,
}

impl TestRuntime {
    fn normal() -> Self {
        Self {
            now: Mutex::new(None),
            reached_response: None,
            release_response: None,
            write_timeout: Duration::from_secs(10),
        }
    }

    fn gated(write_timeout: Duration) -> (Arc<Self>, Arc<Notify>, Arc<Notify>) {
        let reached = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        (
            Arc::new(Self {
                now: Mutex::new(None),
                reached_response: Some(Arc::clone(&reached)),
                release_response: Some(Arc::clone(&release)),
                write_timeout,
            }),
            reached,
            release,
        )
    }

    fn set_now(&self, now: Instant) {
        *self.now.lock().unwrap_or_else(|error| panic!("{error}")) = Some(now);
    }
}

impl ConnectionRuntime for TestRuntime {
    fn now(&self) -> Instant {
        self.now
            .lock()
            .unwrap_or_else(|error| panic!("{error}"))
            .unwrap_or_else(Instant::now)
    }

    fn write_timeout(&self) -> Duration {
        self.write_timeout
    }

    fn before_response(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            if let (Some(reached), Some(release)) = (&self.reached_response, &self.release_response)
            {
                reached.notify_one();
                release.notified().await;
            }
        })
    }
}

#[derive(Debug)]
struct CountingKey {
    inner: Arc<dyn SigningKey>,
    count: Arc<AtomicUsize>,
    messages: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl SigningKey for CountingKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        let signer = self.inner.choose_scheme(offered)?;
        Some(Box::new(CountingSigner {
            inner: signer,
            count: Arc::clone(&self.count),
            messages: Arc::clone(&self.messages),
        }))
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        self.inner.public_key()
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        self.inner.algorithm()
    }
}

#[derive(Debug)]
struct CountingSigner {
    inner: Box<dyn Signer>,
    count: Arc<AtomicUsize>,
    messages: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl Signer for CountingSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        self.count.fetch_add(1, Ordering::SeqCst);
        self.messages
            .lock()
            .unwrap_or_else(|error| panic!("{error}"))
            .push(message.to_vec());
        self.inner.sign(message)
    }

    fn scheme(&self) -> SignatureScheme {
        self.inner.scheme()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn trusted_name_tls13_handshake_signs_exactly_once() {
    let (root, leaf, key) = certificates();
    let provider = rustls::crypto::ring::default_provider();
    let inner = provider
        .key_provider
        .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)))
        .unwrap_or_else(|error| panic!("{error}"));
    let count = Arc::new(AtomicUsize::new(0));
    let messages = Arc::new(Mutex::new(Vec::new()));
    let signing = Arc::new(CountingKey {
        inner,
        count: Arc::clone(&count),
        messages: Arc::clone(&messages),
    });
    assert!(
        signing
            .choose_scheme(&[SignatureScheme::RSA_PSS_SHA256])
            .is_none()
    );
    let server =
        build_config(vec![leaf.clone()], signing).unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(server.send_tls13_tickets, 0);
    assert_eq!(server.max_early_data_size, 0);
    assert!(!server.send_half_rtt_data);
    assert!(server.alpn_protocols.is_empty());

    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(root))
        .unwrap_or_else(|error| panic!("{error}"));
    let mut client = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap_or_else(|error| panic!("{error}"))
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.resumption = Resumption::disabled();

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let address = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));
    let server_task = tokio::spawn(async move {
        let (socket, _) = listener
            .accept()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let mut tls = TlsAcceptor::from(server)
            .accept(socket)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        tls.shutdown()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        tls
    });
    let socket = TcpStream::connect(address)
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let name = ServerName::try_from("server.test")
        .unwrap_or_else(|error| panic!("{error}"))
        .to_owned();
    let mut client = TlsConnector::from(Arc::new(client))
        .connect(name, socket)
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let mut eof = Vec::new();
    client
        .read_to_end(&mut eof)
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let server = server_task.await.unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(
        client.get_ref().1.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    assert_eq!(
        server.get_ref().1.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    assert_eq!(count.load(Ordering::SeqCst), 1);
    let captured = messages.lock().unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(captured.len(), 1);
    assert!(!captured[0].is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn production_connection_accepts_zero_then_continues_and_closes_cleanly() {
    let (mut tls, task, admission, _held) = connection(
        Arc::new(TestRuntime::normal()),
        Instant::now() + Duration::from_secs(30),
        0,
    )
    .await;
    assert_eq!(exchange_frame(&mut tls, &[]).await, PREFIX);
    assert_eq!(
        exchange_frame(&mut tls, b"still-open").await,
        [PREFIX, b"still-open"].concat()
    );
    tls.shutdown()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let mut eof = [0_u8; 1];
    assert_eq!(
        tls.read(&mut eof)
            .await
            .unwrap_or_else(|error| panic!("{error}")),
        0
    );
    task.await
        .unwrap_or_else(|error| panic!("{error}"))
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(admission.acquire().is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn production_connection_accepts_exact_maximum_frame() {
    let (mut tls, task, admission, _held) = connection(
        Arc::new(TestRuntime::normal()),
        Instant::now() + Duration::from_secs(30),
        0,
    )
    .await;
    let payload = (0..MAX_REQUEST)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    let response = timeout(Duration::from_secs(5), exchange_frame(&mut tls, &payload))
        .await
        .unwrap_or_else(|_| panic!("maximum frame exchange timed out"));
    assert_eq!(response.len(), PREFIX.len() + MAX_REQUEST);
    assert_eq!(&response[..PREFIX.len()], PREFIX);
    assert_eq!(&response[PREFIX.len()..], payload);
    tls.shutdown()
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    task.await
        .unwrap_or_else(|error| panic!("{error}"))
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(admission.acquire().is_ok());
}

#[tokio::test(flavor = "multi_thread")]
async fn production_connection_rejects_oversize_without_response_and_releases_permit() {
    let (mut tls, task, admission, held) = connection(
        Arc::new(TestRuntime::normal()),
        Instant::now() + Duration::from_secs(30),
        63,
    )
    .await;
    assert!(admission.acquire().is_err());
    tls.write_all(&((MAX_REQUEST + 1) as u32).to_be_bytes())
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let mut byte = [0_u8; 1];
    let read = timeout(Duration::from_secs(2), tls.read(&mut byte))
        .await
        .unwrap_or_else(|_| panic!("oversize rejection timed out"));
    assert!(matches!(read, Ok(0) | Err(_)));
    let error = task
        .await
        .unwrap_or_else(|error| panic!("{error}"))
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    assert!(admission.acquire().is_ok());
    drop(held);
}

#[tokio::test(flavor = "multi_thread")]
async fn production_write_backpressure_times_out_and_releases_permit() {
    let runtime = Arc::new(TestRuntime {
        now: Mutex::new(None),
        reached_response: None,
        release_response: None,
        write_timeout: Duration::from_millis(50),
    });
    let (mut tls, task, admission, held) =
        connection(runtime, Instant::now() + Duration::from_secs(30), 63).await;
    assert!(admission.acquire().is_err());
    let payload = vec![0x5a; MAX_REQUEST];
    tls.write_all(&(MAX_REQUEST as u32).to_be_bytes())
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    tls.write_all(&payload)
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let result = timeout(Duration::from_secs(2), task)
        .await
        .unwrap_or_else(|_| panic!("backpressure timeout was not enforced"))
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
    assert_connection_closes_bounded(&mut tls).await;
    assert!(admission.acquire().is_ok());
    drop(held);
}

#[tokio::test(flavor = "multi_thread")]
async fn production_mid_connection_expiry_sends_no_response_and_releases_permit() {
    let (runtime, reached, release) = TestRuntime::gated(Duration::from_secs(1));
    let expiry = Instant::now() + Duration::from_secs(30);
    let (mut tls, task, admission, held) = connection(runtime.clone(), expiry, 63).await;
    tls.write_all(&4_u32.to_be_bytes())
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    tls.write_all(b"stop")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    timeout(Duration::from_secs(2), reached.notified())
        .await
        .unwrap_or_else(|_| panic!("server did not reach pre-response expiry check"));
    assert!(admission.acquire().is_err());
    runtime.set_now(expiry);
    release.notify_one();
    let mut byte = [0_u8; 1];
    let read = timeout(Duration::from_secs(2), tls.read(&mut byte))
        .await
        .unwrap_or_else(|_| panic!("expired connection did not close"));
    assert!(matches!(read, Ok(0) | Err(_)));
    let error = task
        .await
        .unwrap_or_else(|error| panic!("{error}"))
        .unwrap_err();
    assert_eq!(error.to_string(), "certificate expired before response");
    assert!(admission.acquire().is_ok());
    drop(held);
}

#[tokio::test(flavor = "multi_thread")]
async fn production_connection_rejects_handshake_at_expiry() {
    let (_, leaf, key) = certificates();
    let provider = rustls::crypto::ring::default_provider();
    let signing = provider
        .key_provider
        .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)))
        .unwrap_or_else(|error| panic!("{error}"));
    let server = build_config(vec![leaf], signing).unwrap_or_else(|error| panic!("{error}"));
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let address = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));
    let client = TcpStream::connect(address);
    let accepted = async {
        let (socket, _) = listener
            .accept()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        let (_, shutdown) = watch::channel(None);
        azihsm_tls_server::server::serve_connection(
            1,
            socket,
            TlsAcceptor::from(server),
            Instant::now(),
            shutdown,
            Arc::new(TestRuntime::normal()),
        )
        .await
    };
    let (_, result) = tokio::join!(client, accepted);
    assert_eq!(
        result.unwrap_err().to_string(),
        "certificate expired before handshake"
    );
}

async fn connection(
    runtime: Arc<dyn ConnectionRuntime>,
    expiry: Instant,
    held_permits: usize,
) -> (
    tokio_rustls::client::TlsStream<TcpStream>,
    JoinHandle<std::io::Result<()>>,
    Admission,
    Vec<OwnedSemaphorePermit>,
) {
    let (root, leaf, key) = certificates();
    let (server, client) = configurations(root, leaf, key);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let address = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"));
    let admission = Admission::new();
    let held = (0..held_permits)
        .map(|_| admission.acquire())
        .collect::<Result<Vec<_>, _>>()
        .unwrap_or_else(|error| panic!("{error}"));
    let permit = admission
        .acquire()
        .unwrap_or_else(|error| panic!("{error}"));
    let (shutdown_tx, shutdown) = watch::channel(None);
    let task = tokio::spawn(async move {
        let _shutdown_tx = shutdown_tx;
        let _permit = permit;
        let (socket, _) = listener
            .accept()
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        serve_connection(
            1,
            socket,
            TlsAcceptor::from(server),
            expiry,
            shutdown,
            runtime,
        )
        .await
    });
    let socket = TcpStream::connect(address)
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let name = ServerName::try_from("server.test")
        .unwrap_or_else(|error| panic!("{error}"))
        .to_owned();
    let tls = TlsConnector::from(client)
        .connect(name, socket)
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    (tls, task, admission, held)
}

async fn exchange_frame(
    tls: &mut tokio_rustls::client::TlsStream<TcpStream>,
    payload: &[u8],
) -> Vec<u8> {
    tls.write_all(&(payload.len() as u32).to_be_bytes())
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    tls.write_all(payload)
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let mut header = [0_u8; 4];
    tls.read_exact(&mut header)
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let mut response = vec![0_u8; u32::from_be_bytes(header) as usize];
    tls.read_exact(&mut response)
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    response
}

async fn assert_connection_closes_bounded(tls: &mut tokio_rustls::client::TlsStream<TcpStream>) {
    timeout(Duration::from_secs(2), async {
        let mut total = 0_usize;
        let mut buffer = [0_u8; 8192];
        loop {
            match tls.read(&mut buffer).await {
                Ok(0) | Err(_) => return,
                Ok(count) => {
                    total += count;
                    assert!(total <= MAX_REQUEST + PREFIX.len() + 4);
                }
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("timed-out connection did not close"));
}

fn configurations(
    root: Vec<u8>,
    leaf: Vec<u8>,
    key: Vec<u8>,
) -> (Arc<rustls::ServerConfig>, Arc<ClientConfig>) {
    let provider = rustls::crypto::ring::default_provider();
    let signing = provider
        .key_provider
        .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key)))
        .unwrap_or_else(|error| panic!("{error}"));
    let server = build_config(vec![leaf], signing).unwrap_or_else(|error| panic!("{error}"));
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(root))
        .unwrap_or_else(|error| panic!("{error}"));
    let mut client = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap_or_else(|error| panic!("{error}"))
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.resumption = Resumption::disabled();
    (server, Arc::new(client))
}

fn certificates() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let root_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .unwrap_or_else(|error| panic!("{error}"));
    let mut root_params =
        CertificateParams::new(Vec::<String>::new()).unwrap_or_else(|error| panic!("{error}"));
    root_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    root_params
        .distinguished_name
        .push(DnType::CommonName, "Test Root");
    let root = root_params
        .self_signed(&root_key)
        .unwrap_or_else(|error| panic!("{error}"));

    let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .unwrap_or_else(|error| panic!("{error}"));
    let mut leaf_params =
        CertificateParams::new(Vec::<String>::new()).unwrap_or_else(|error| panic!("{error}"));
    leaf_params.subject_alt_names.push(SanType::DnsName(
        "server.test"
            .try_into()
            .unwrap_or_else(|error| panic!("{error}")),
    ));
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let issuer = Issuer::from_params(&root_params, &root_key);
    let leaf = leaf_params
        .signed_by(&leaf_key, &issuer)
        .unwrap_or_else(|error| panic!("{error}"));
    (
        root.der().to_vec(),
        leaf.der().to_vec(),
        leaf_key.serialize_der(),
    )
}
