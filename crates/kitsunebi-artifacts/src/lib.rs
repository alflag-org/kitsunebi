#![forbid(unsafe_code)]

//! Content-addressed artifacts and side-effect-free provider discovery.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs,
    io::{self, Cursor, Read, Write},
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    path::PathBuf,
    sync::Arc,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use thiserror::Error;

pub const CRATE_NAME: &str = "kitsunebi-artifacts";
pub const MAX_DEFAULT_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_COMPONENT_BYTES: usize = 256;
const MAX_HEADER_BYTES: usize = 8192;
const MAX_URL_BYTES: usize = 8192;
const USER_AGENT: &str = "kitsunebi-artifacts/0.3 (+https://github.com/alflag-org/kitsunebi)";
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Error)]
pub enum ArtifactError {
    #[error("invalid sha256 digest")]
    InvalidDigest,
    #[error("digest mismatch: expected {expected}, got {actual}")]
    DigestMismatch { expected: String, actual: String },
    #[error("artifact exceeds size limit ({limit} bytes)")]
    TooLarge { limit: u64 },
    #[error("unsafe artifact path")]
    UnsafePath,
    #[error("HTTP URLs must use HTTPS")]
    InsecureUrl,
    #[error("HTTP status {status}: {message}")]
    HttpStatus { status: u16, message: String },
    #[error("rate limited by upstream")]
    RateLimited { retry_after: Option<String> },
    #[error("upstream transport error: {0}")]
    Transport(String),
    #[error("declared size does not match downloaded size")]
    SizeMismatch { expected: u64, actual: u64 },
    #[error("invalid provider response: {0}")]
    InvalidResponse(String),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ArtifactMetadata {
    pub kind: String,
    pub name: String,
    pub version: String,
    pub source: String,
    pub source_id: String,
    /// Kitsunebi SHA-256. Empty means discovery supplied only another
    /// provider hash and download must calculate this value.
    pub digest: String,
    pub filename: String,
    pub size: Option<u64>,
    pub compatibility: String,
    pub metadata: String,
}
impl ArtifactMetadata {
    pub fn validate(&self) -> Result<(), ArtifactError> {
        validate_metadata_field(&self.kind, "kind")?;
        validate_metadata_field(&self.name, "name")?;
        validate_metadata_field(&self.version, "version")?;
        validate_metadata_field(&self.source, "source")?;
        validate_metadata_field(&self.source_id, "source_id")?;
        validate_metadata_field(&self.compatibility, "compatibility")?;
        if !self.digest.is_empty() {
            validate_digest(&self.digest)?;
        }
        if self.filename.is_empty()
            || self.filename.len() > MAX_COMPONENT_BYTES
            || self.filename == "."
            || self.filename == ".."
            || self.filename.contains('/')
            || self.filename.contains('\\')
            || self
                .filename
                .chars()
                .any(|character| character.is_control())
        {
            return Err(ArtifactError::UnsafePath);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredArtifact {
    pub digest: String,
    pub size: u64,
}

pub struct ArtifactStore {
    root: PathBuf,
    max_bytes: u64,
}
impl ArtifactStore {
    pub fn new(root: impl Into<PathBuf>, max_bytes: u64) -> Result<Self, ArtifactError> {
        let root = root.into();
        fs::create_dir_all(&root)?;
        Ok(Self {
            root: root.canonicalize()?,
            max_bytes,
        })
    }
    pub fn digest_path(&self, digest: &str) -> Result<PathBuf, ArtifactError> {
        validate_digest(digest)?;
        let dir = self.root.join(&digest[..2]);
        if fs::symlink_metadata(&dir)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
        {
            return Err(ArtifactError::UnsafePath);
        }
        let path = dir.join(digest);
        if fs::symlink_metadata(&path)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
        {
            return Err(ArtifactError::UnsafePath);
        }
        Ok(path)
    }
    pub fn put<R: Read>(
        &self,
        expected: &str,
        mut input: R,
        declared_size: Option<u64>,
    ) -> Result<StoredArtifact, ArtifactError> {
        validate_digest(expected)?;
        if declared_size.is_some_and(|n| n > self.max_bytes) {
            return Err(ArtifactError::TooLarge {
                limit: self.max_bytes,
            });
        }
        let destination = self.digest_path(expected)?;
        if fs::symlink_metadata(&destination)
            .map(|m| m.file_type().is_symlink())
            .unwrap_or(false)
        {
            return Err(ArtifactError::UnsafePath);
        }
        if destination.is_file() {
            let size = fs::metadata(&destination)?.len();
            let actual = hash_reader(fs::File::open(&destination)?)?;
            if actual != expected {
                return Err(ArtifactError::DigestMismatch {
                    expected: expected.into(),
                    actual,
                });
            }
            return Ok(StoredArtifact {
                digest: expected.into(),
                size,
            });
        }
        let dir = destination.parent().ok_or(ArtifactError::UnsafePath)?;
        fs::create_dir_all(dir)?;
        let temporary = dir.join(format!(
            ".{expected}.{}.{}.tmp",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let result = (|| {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)?;
            let mut hash = Sha256::new();
            let mut size = 0u64;
            let mut buf = [0u8; 65536];
            loop {
                let n = input.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                size += n as u64;
                if size > self.max_bytes {
                    return Err(ArtifactError::TooLarge {
                        limit: self.max_bytes,
                    });
                }
                file.write_all(&buf[..n])?;
                hash.update(&buf[..n]);
            }
            file.sync_all()?;
            let actual = hex(&hash.finalize());
            if actual != expected {
                return Err(ArtifactError::DigestMismatch {
                    expected: expected.into(),
                    actual,
                });
            }
            if let Some(expected_size) = declared_size
                && expected_size != size
            {
                return Err(ArtifactError::SizeMismatch {
                    expected: expected_size,
                    actual: size,
                });
            }
            match install_noreplace(&temporary, &destination)? {
                true => Ok(StoredArtifact {
                    digest: expected.into(),
                    size,
                }),
                false => {
                    let size = fs::metadata(&destination)?.len();
                    let actual = hash_reader(fs::File::open(&destination)?)?;
                    if actual != expected {
                        Err(ArtifactError::DigestMismatch {
                            expected: expected.into(),
                            actual,
                        })
                    } else {
                        Ok(StoredArtifact {
                            digest: expected.into(),
                            size,
                        })
                    }
                }
            }
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }
    /// Store an HTTP stream without buffering it in memory. The digest is
    /// computed as bytes are read, then the temporary file is atomically
    /// moved into its digest-addressed CAS path.
    pub fn put_stream<R: Read>(
        &self,
        expected: Option<&str>,
        mut input: R,
        declared_size: Option<u64>,
    ) -> Result<StoredArtifact, ArtifactError> {
        if let Some(expected) = expected {
            validate_digest(expected)?;
        }
        if declared_size.is_some_and(|size| size > self.max_bytes) {
            return Err(ArtifactError::TooLarge {
                limit: self.max_bytes,
            });
        }
        let temporary = self.root.join(format!(
            ".incoming.{}.{}.tmp",
            std::process::id(),
            TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let result = (|| {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)?;
            let mut hash = Sha256::new();
            let mut size = 0u64;
            let mut buffer = [0u8; 65536];
            loop {
                let n = input.read(&mut buffer)?;
                if n == 0 {
                    break;
                }
                size = size.saturating_add(n as u64);
                if size > self.max_bytes {
                    return Err(ArtifactError::TooLarge {
                        limit: self.max_bytes,
                    });
                }
                file.write_all(&buffer[..n])?;
                hash.update(&buffer[..n]);
            }
            if let Some(expected_size) = declared_size
                && expected_size != size
            {
                return Err(ArtifactError::SizeMismatch {
                    expected: expected_size,
                    actual: size,
                });
            }
            file.sync_all()?;
            let actual = hex(&hash.finalize());
            if let Some(expected) = expected
                && expected != actual
            {
                return Err(ArtifactError::DigestMismatch {
                    expected: expected.into(),
                    actual,
                });
            }
            let destination = self.digest_path(&actual)?;
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent)?;
            }
            match install_noreplace(&temporary, &destination)? {
                true => Ok(StoredArtifact {
                    digest: actual,
                    size,
                }),
                false => {
                    let existing_size = fs::metadata(&destination)?.len();
                    let existing_digest = hash_reader(fs::File::open(&destination)?)?;
                    if existing_digest != actual {
                        return Err(ArtifactError::DigestMismatch {
                            expected: actual,
                            actual: existing_digest,
                        });
                    }
                    Ok(StoredArtifact {
                        digest: existing_digest,
                        size: existing_size,
                    })
                }
            }
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }
    pub fn read(&self, digest: &str) -> Result<Vec<u8>, ArtifactError> {
        Ok(fs::read(self.digest_path(digest)?)?)
    }
    pub fn open(&self, digest: &str) -> Result<fs::File, ArtifactError> {
        Ok(fs::File::open(self.digest_path(digest)?)?)
    }
    pub fn metadata(&self, digest: &str) -> Result<fs::Metadata, ArtifactError> {
        Ok(fs::metadata(self.digest_path(digest)?)?)
    }
}
fn validate_digest(d: &str) -> Result<(), ArtifactError> {
    if d.len() == 64
        && d.bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(ArtifactError::InvalidDigest)
    }
}
fn validate_metadata_field(value: &str, label: &str) -> Result<(), ArtifactError> {
    if value.len() > MAX_HEADER_BYTES || value.chars().any(|character| character.is_control()) {
        return Err(ArtifactError::InvalidResponse(format!(
            "invalid artifact {label}"
        )));
    }
    Ok(())
}
/// Link the completed temporary file into the CAS without replacing an
/// existing object. Both paths are inside the store, so the hard link is on
/// one filesystem and gives us an atomic create-if-absent operation.
fn install_noreplace(temporary: &PathBuf, destination: &PathBuf) -> Result<bool, io::Error> {
    match fs::hard_link(temporary, destination) {
        Ok(()) => {
            fs::remove_file(temporary)?;
            Ok(true)
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let _ = fs::remove_file(temporary);
            Ok(false)
        }
        Err(error) => Err(error),
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn hash_reader<R: Read>(mut reader: R) -> Result<String, ArtifactError> {
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    Ok(hex(&hash.finalize()))
}
fn sha512_reader<R: Read>(mut reader: R) -> Result<String, ArtifactError> {
    let mut hash = sha2::Sha512::new();
    let mut buffer = [0u8; 65536];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    Ok(hex(&hash.finalize()))
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}
pub trait HttpTransport: Send + Sync {
    /// Whether this transport is an explicitly test-scoped localhost transport.
    fn allows_localhost(&self) -> bool {
        false
    }
    fn send(
        &self,
        request: HttpRequest,
        timeout: Duration,
        max_bytes: u64,
    ) -> Result<HttpResponse, ArtifactError>;
    fn send_stream(
        &self,
        request: HttpRequest,
        timeout: Duration,
        max_bytes: u64,
    ) -> Result<StreamResponse, ArtifactError> {
        let response = self.send(request, timeout, max_bytes)?;
        Ok(StreamResponse {
            status: response.status,
            headers: response.headers,
            body: Box::new(Cursor::new(response.body)),
        })
    }
}

/// DNS resolution is kept behind a small port so production requests can pin
/// the socket address that was checked and tests can exercise address policy
/// without depending on the host resolver.
pub trait DnsResolver: Send + Sync {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, ArtifactError>;
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemDnsResolver;

impl DnsResolver for SystemDnsResolver {
    fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, ArtifactError> {
        let addresses = (host, port)
            .to_socket_addrs()
            .map_err(|_| ArtifactError::Transport("DNS resolution failed".into()))?
            .collect::<Vec<_>>();
        validate_resolved_addresses(&addresses)?;
        Ok(addresses)
    }
}

fn validate_resolved_addresses(addresses: &[SocketAddr]) -> Result<(), ArtifactError> {
    if addresses.is_empty()
        || addresses
            .iter()
            .any(|address| !is_global_public(address.ip()))
    {
        return Err(ArtifactError::InsecureUrl);
    }
    Ok(())
}

fn is_global_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            let [a, b, c, _] = octets;
            !(ip.is_loopback()
                || a == 0 // "this network" / special-purpose addresses
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_multicast()
                || a >= 240 // reserved, including limited broadcast
                || (a == 100 && (64..=127).contains(&b)) // CGNAT
                || (a == 192 && b == 0 && c == 2) // TEST-NET-1
                || (a == 198 && b == 51 && c == 100) // TEST-NET-2
                || (a == 203 && b == 0 && c == 113) // TEST-NET-3
                || (a == 192 && b == 0 && c == 0) // IETF protocol assignments
                || (a == 198 && (18..=19).contains(&b))) // benchmarking
        }
        IpAddr::V6(ip) => {
            let segments = ip.segments();
            let is_ipv4_mapped =
                segments[..5].iter().all(|&segment| segment == 0) && segments[5] == 0xffff;
            if is_ipv4_mapped {
                return ip
                    .to_ipv4()
                    .is_some_and(|ipv4| is_global_public(IpAddr::V4(ipv4)));
            }
            let is_ipv4_compatible = segments[..6].iter().all(|&segment| segment == 0);
            !(ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || is_ipv4_compatible
                || (segments[0] & 0xfe00) == 0xfc00 // unique local
                || (segments[0] & 0xffc0) == 0xfe80 // link local
                || (segments[0] & 0xffc0) == 0xfec0 // deprecated site local
                || (segments[0] == 0x2001 && segments[1] == 0x0db8) // documentation
                || (segments[0] == 0x2001 && segments[1] == 0x0000) // teredo
                || (segments[0] == 0x2001 && segments[1] == 0x0002) // benchmarking
                || (segments[0] == 0x2001 && segments[1] == 0x0010) // orchid
                || (segments[0] == 0x2001 && segments[1] == 0x0020)) // documentation
        }
    }
}
pub struct StreamResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Box<dyn Read + Send>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportConfig {
    pub timeout: Duration,
    pub max_response_bytes: u64,
    pub allow_localhost: bool,
    pub allowed_hosts: Vec<String>,
}
impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            max_response_bytes: MAX_DEFAULT_BYTES,
            allow_localhost: false,
            allowed_hosts: vec![
                "api.modrinth.com".into(),
                "cdn.modrinth.com".into(),
                "fill.papermc.io".into(),
                "fill-data.papermc.io".into(),
                "hangar.papermc.io".into(),
                "api.hangar.papermc.io".into(),
                "hangarcdn.papermc.io".into(),
                "api.github.com".into(),
                "github.com".into(),
                "objects.githubusercontent.com".into(),
                "release-assets.githubusercontent.com".into(),
            ],
        }
    }
}

fn is_local_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "::1"
}

fn validate_allowlist_host(host: &str, allow_localhost: bool) -> Result<(), ArtifactError> {
    if host.is_empty()
        || host.len() > MAX_COMPONENT_BYTES
        || host.chars().any(|character| character.is_control())
        || (host.contains(['/', '\\', '?', '#', ':', '@'])
            && !(allow_localhost && is_local_host(host)))
        || host.chars().any(char::is_whitespace)
        || (host.parse::<IpAddr>().is_ok() && !(allow_localhost && is_local_host(host)))
    {
        return Err(ArtifactError::InvalidResponse(
            "host allowlist must contain bare DNS names".into(),
        ));
    }
    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(ArtifactError::InvalidResponse(
                "host allowlist must contain bare DNS names".into(),
            ));
        }
    }
    Ok(())
}

fn same_origin(left: &reqwest::Url, right: &reqwest::Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

fn sensitive_redirect_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "authorization" | "cookie" | "proxy-authorization" | "proxy-authenticate" | "x-api-key"
    )
}

fn redirect_headers_safe(headers: &[(String, String)], cross_origin: bool) -> bool {
    !cross_origin
        || !headers
            .iter()
            .any(|(name, _)| sensitive_redirect_header(name))
}

/// Blocking reqwest transport with rustls, bounded response reads, and at most
/// one manually revalidated redirect. Blocking is intentional: provider
/// interfaces are synchronous, while reads still stream in bounded chunks.
#[derive(Clone)]
pub struct ReqwestTransport {
    max_response_bytes: u64,
    timeout: Duration,
    allow_localhost: bool,
    allowed_hosts: Vec<String>,
    resolver: Arc<dyn DnsResolver>,
}
impl std::fmt::Debug for ReqwestTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReqwestTransport")
            .field("max_response_bytes", &self.max_response_bytes)
            .field("timeout", &self.timeout)
            .field("allow_localhost", &self.allow_localhost)
            .field("allowed_hosts", &self.allowed_hosts)
            .finish()
    }
}
impl ReqwestTransport {
    pub fn new(config: TransportConfig) -> Result<Self, ArtifactError> {
        let mut config = config;
        config.allow_localhost = false;
        Self::build(config, Arc::new(SystemDnsResolver))
    }
    pub fn localhost_test(mut config: TransportConfig) -> Result<Self, ArtifactError> {
        config.allow_localhost = true;
        Self::build(config, Arc::new(SystemDnsResolver))
    }
    pub fn with_allowed_hosts(
        config: TransportConfig,
        hosts: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self, ArtifactError> {
        let mut config = config;
        config.allow_localhost = false;
        config.allowed_hosts = hosts.into_iter().map(Into::into).collect();
        Self::build(config, Arc::new(SystemDnsResolver))
    }
    pub fn with_resolver(
        mut config: TransportConfig,
        resolver: Arc<dyn DnsResolver>,
    ) -> Result<Self, ArtifactError> {
        config.allow_localhost = false;
        Self::build(config, resolver)
    }
    fn build(
        config: TransportConfig,
        resolver: Arc<dyn DnsResolver>,
    ) -> Result<Self, ArtifactError> {
        let mut config = config;
        config.allowed_hosts = config
            .allowed_hosts
            .into_iter()
            .map(|host| host.to_ascii_lowercase())
            .collect();
        if config.max_response_bytes == 0 {
            return Err(ArtifactError::InvalidResponse(
                "max response bytes must be positive".into(),
            ));
        }
        if config.timeout.is_zero()
            || config.allowed_hosts.is_empty()
            || config
                .allowed_hosts
                .iter()
                .any(|host| validate_allowlist_host(host, config.allow_localhost).is_err())
        {
            return Err(ArtifactError::InvalidResponse(
                "bounded timeout and non-empty host allowlist are required".into(),
            ));
        }
        Ok(Self {
            max_response_bytes: config.max_response_bytes,
            timeout: config.timeout,
            allow_localhost: config.allow_localhost,
            allowed_hosts: config.allowed_hosts,
            resolver,
        })
    }
    fn validate_url(&self, raw: &str) -> Result<reqwest::Url, ArtifactError> {
        if raw.len() > MAX_URL_BYTES {
            return Err(ArtifactError::InsecureUrl);
        }
        let url = reqwest::Url::parse(raw).map_err(|_| ArtifactError::InsecureUrl)?;
        self.validate_parsed_url(url, false)
    }
    fn validate_parsed_url(
        &self,
        url: reqwest::Url,
        allow_query: bool,
    ) -> Result<reqwest::Url, ArtifactError> {
        if url.as_str().len() > MAX_URL_BYTES {
            return Err(ArtifactError::InsecureUrl);
        }
        if url.username() != "" || url.password().is_some() || url.host_str().is_none() {
            return Err(ArtifactError::InsecureUrl);
        }
        let local = is_local_host(url.host_str().unwrap_or_default());
        if local && !self.allow_localhost {
            return Err(ArtifactError::InvalidResponse(
                "localhost requires explicit test transport".into(),
            ));
        }
        if (!allow_query && url.query().is_some()) || url.fragment().is_some() {
            return Err(ArtifactError::InsecureUrl);
        }
        if url.scheme() != "https" && !(self.allow_localhost && local && url.scheme() == "http") {
            return Err(ArtifactError::InsecureUrl);
        }
        if url.scheme() == "https" && url.port_or_known_default() != Some(443) {
            return Err(ArtifactError::InsecureUrl);
        }
        if !local
            && !self.allowed_hosts.is_empty()
            && !self
                .allowed_hosts
                .iter()
                .any(|host| host.eq_ignore_ascii_case(url.host_str().unwrap_or_default()))
        {
            return Err(ArtifactError::InvalidResponse(
                "request host is not allowlisted".into(),
            ));
        }
        Ok(url)
    }

    fn resolve_for_request(&self, url: &reqwest::Url) -> Result<SocketAddr, ArtifactError> {
        if self.allow_localhost && is_local_host(url.host_str().unwrap_or_default()) {
            return url
                .socket_addrs(|| None)
                .map_err(|_| ArtifactError::Transport("localhost resolution failed".into()))?
                .into_iter()
                .next()
                .ok_or_else(|| ArtifactError::Transport("localhost resolution failed".into()));
        }
        let host = url.host_str().ok_or(ArtifactError::InsecureUrl)?;
        let port = url
            .port_or_known_default()
            .ok_or(ArtifactError::InsecureUrl)?;
        let addresses = self.resolver.resolve(host, port)?;
        validate_resolved_addresses(&addresses)?;
        addresses
            .into_iter()
            .next()
            .ok_or_else(|| ArtifactError::Transport("DNS resolution failed".into()))
    }
}
impl HttpTransport for ReqwestTransport {
    fn allows_localhost(&self) -> bool {
        self.allow_localhost
    }

    fn send(
        &self,
        request: HttpRequest,
        timeout: Duration,
        max_bytes: u64,
    ) -> Result<HttpResponse, ArtifactError> {
        let max_bytes = max_bytes.min(self.max_response_bytes);
        let mut stream = self.send_stream(request, timeout, max_bytes)?;
        let mut body = Vec::new();
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let n = stream.body.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            if body.len().saturating_add(n) as u64 > max_bytes {
                return Err(ArtifactError::TooLarge { limit: max_bytes });
            }
            body.extend_from_slice(&buffer[..n]);
        }
        Ok(HttpResponse {
            status: stream.status,
            headers: stream.headers,
            body,
        })
    }
    fn send_stream(
        &self,
        request: HttpRequest,
        timeout: Duration,
        max_bytes: u64,
    ) -> Result<StreamResponse, ArtifactError> {
        let mut url = self.validate_url(&request.url)?;
        let max_bytes = max_bytes.min(self.max_response_bytes);
        let mut method = reqwest::Method::from_bytes(request.method.as_bytes())
            .map_err(|error| ArtifactError::InvalidResponse(error.to_string()))?;
        if timeout.is_zero() {
            return Err(ArtifactError::InvalidResponse(
                "request timeout must be positive".into(),
            ));
        }
        for redirect_count in 0..=1 {
            let address = self.resolve_for_request(&url)?;
            let host = url.host_str().ok_or(ArtifactError::InsecureUrl)?;
            let client = reqwest::blocking::Client::builder()
                .timeout(self.timeout)
                .redirect(reqwest::redirect::Policy::none())
                .resolve(host, address)
                .build()
                .map_err(|error| ArtifactError::Transport(error.to_string()))?;
            let mut builder = client
                .request(method.clone(), url.clone())
                .timeout(timeout.min(self.timeout))
                .header("Accept", "application/json");
            for (name, value) in &request.headers {
                builder = builder.header(name, value);
            }
            let response = builder.send().map_err(|error| {
                if error.is_timeout() {
                    ArtifactError::Transport("request timed out".into())
                } else {
                    ArtifactError::Transport("upstream transport failed".into())
                }
            })?;
            if response.status().is_redirection() && redirect_count == 0 {
                if method != reqwest::Method::GET {
                    return Err(ArtifactError::InsecureUrl);
                }
                let location = response
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|value| value.to_str().ok())
                    .ok_or_else(|| {
                        ArtifactError::InvalidResponse("redirect location is invalid".into())
                    })?;
                let next_url = self.validate_parsed_url(
                    url.join(location).map_err(|_| ArtifactError::InsecureUrl)?,
                    true,
                )?;
                let cross_origin = !same_origin(&url, &next_url);
                if !redirect_headers_safe(&request.headers, cross_origin) {
                    return Err(ArtifactError::InsecureUrl);
                }
                url = next_url;
                method = reqwest::Method::GET;
                continue;
            }
            if response
                .content_length()
                .is_some_and(|size| size > max_bytes)
            {
                return Err(ArtifactError::TooLarge { limit: max_bytes });
            }
            let status = response.status().as_u16();
            let headers = response
                .headers()
                .iter()
                .filter_map(|(name, value)| {
                    value
                        .to_str()
                        .ok()
                        .map(|value| (name.to_string(), value.to_owned()))
                })
                .collect();
            return Ok(StreamResponse {
                status,
                headers,
                body: Box::new(response),
            });
        }
        Err(ArtifactError::InvalidResponse(
            "redirect limit exceeded".into(),
        ))
    }
}
pub fn checked_request(
    method: &str,
    url: &str,
    headers: Vec<(String, String)>,
) -> Result<HttpRequest, ArtifactError> {
    checked_request_inner(method, url, headers, false)
}

fn checked_request_for_transport(
    method: &str,
    url: &str,
    headers: Vec<(String, String)>,
    transport: &dyn HttpTransport,
) -> Result<HttpRequest, ArtifactError> {
    checked_request_inner(method, url, headers, transport.allows_localhost())
}

fn checked_request_inner(
    method: &str,
    url: &str,
    headers: Vec<(String, String)>,
    allow_localhost: bool,
) -> Result<HttpRequest, ArtifactError> {
    if url.len() > MAX_URL_BYTES {
        return Err(ArtifactError::InsecureUrl);
    }
    let parsed = reqwest::Url::parse(url).map_err(|_| ArtifactError::InsecureUrl)?;
    let local = matches!(parsed.host_str(), Some("localhost" | "127.0.0.1" | "::1"));
    if parsed.username() != ""
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || parsed.host_str().is_none()
        || (parsed.scheme() != "https" && !(allow_localhost && local && parsed.scheme() == "http"))
    {
        return Err(ArtifactError::InsecureUrl);
    }
    if parsed.scheme() == "https" && parsed.port_or_known_default() != Some(443) {
        return Err(ArtifactError::InsecureUrl);
    }
    if method.is_empty()
        || method.len() > MAX_COMPONENT_BYTES
        || !method.bytes().all(is_header_name_byte)
    {
        return Err(ArtifactError::InvalidResponse("invalid HTTP method".into()));
    }
    for (name, value) in &headers {
        if name.is_empty()
            || name.len() > MAX_COMPONENT_BYTES
            || !name.bytes().all(is_header_name_byte)
        {
            return Err(ArtifactError::InvalidResponse(
                "invalid request header".into(),
            ));
        }
        validate_header_value(value)?;
    }
    Ok(HttpRequest {
        method: method.into(),
        url: url.into(),
        headers,
    })
}
pub fn check_response(r: HttpResponse, max: u64) -> Result<HttpResponse, ArtifactError> {
    if r.status == 429 {
        return Err(ArtifactError::RateLimited {
            retry_after: r
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("retry-after"))
                .map(|(_, value)| value.clone()),
        });
    }
    if !(200..300).contains(&r.status) {
        return Err(ArtifactError::HttpStatus {
            status: r.status,
            message: "upstream request failed".into(),
        });
    }
    if r.body.len() as u64 > max {
        return Err(ArtifactError::TooLarge { limit: max });
    }
    Ok(r)
}
fn check_stream_response(r: &StreamResponse, max: u64) -> Result<(), ArtifactError> {
    if r.status == 429 {
        return Err(ArtifactError::RateLimited {
            retry_after: r
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("retry-after"))
                .map(|(_, value)| value.clone()),
        });
    }
    if !(200..300).contains(&r.status) {
        return Err(ArtifactError::HttpStatus {
            status: r.status,
            message: "upstream request failed".into(),
        });
    }
    if let Some(size) = content_length(&r.headers)?
        && size > max
    {
        return Err(ArtifactError::TooLarge { limit: max });
    }
    Ok(())
}

fn content_length(headers: &[(String, String)]) -> Result<Option<u64>, ArtifactError> {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| {
            value
                .parse::<u64>()
                .map(Some)
                .map_err(|_| ArtifactError::InvalidResponse("invalid Content-Length".into()))
        })
        .transpose()
        .map(|value| value.flatten())
}

fn is_header_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

fn validate_header_value(value: &str) -> Result<(), ArtifactError> {
    if value.is_empty()
        || value.len() > MAX_HEADER_BYTES
        || value.chars().any(|character| character.is_control())
    {
        return Err(ArtifactError::InvalidResponse(
            "invalid request header".into(),
        ));
    }
    Ok(())
}

pub trait ArtifactProvider {
    fn discover(&self, t: &dyn HttpTransport) -> Result<Vec<ArtifactMetadata>, ArtifactError>;
    fn download(
        &self,
        a: &ArtifactMetadata,
        t: &dyn HttpTransport,
        s: &ArtifactStore,
    ) -> Result<StoredArtifact, ArtifactError>;
}
/// A user-supplied HTTPS URL. It performs no network request during discovery.
pub struct DirectUrl {
    pub url: String,
    pub filename: String,
    pub digest: String,
    pub size: Option<u64>,
}
impl ArtifactProvider for DirectUrl {
    fn discover(&self, _t: &dyn HttpTransport) -> Result<Vec<ArtifactMetadata>, ArtifactError> {
        checked_request_for_transport("GET", &self.url, Vec::new(), _t)?;
        validate_digest(&self.digest)?;
        let m = ArtifactMetadata {
            kind: "binary".into(),
            name: self.filename.clone(),
            version: String::new(),
            source: "direct-url".into(),
            source_id: self.url.clone(),
            digest: self.digest.clone(),
            filename: self.filename.clone(),
            size: self.size,
            compatibility: String::new(),
            metadata: serde_json::json!({"url": self.url}).to_string(),
        };
        m.validate()?;
        Ok(vec![m])
    }
    fn download(
        &self,
        a: &ArtifactMetadata,
        t: &dyn HttpTransport,
        s: &ArtifactStore,
    ) -> Result<StoredArtifact, ArtifactError> {
        a.validate()?;
        let metadata: Value = serde_json::from_str(&a.metadata)?;
        let metadata_url = strv(&metadata, "url")
            .ok_or_else(|| ArtifactError::InvalidResponse("missing download URL".into()))?;
        if metadata_url != self.url {
            return Err(ArtifactError::InvalidResponse(
                "direct URL changed after discovery".into(),
            ));
        }
        download(a, t, s)
    }
}
/// Manual uploads are already local bytes and therefore bypass HTTP entirely.
pub fn manual_upload<R: Read>(
    store: &ArtifactStore,
    digest: &str,
    input: R,
    size: Option<u64>,
) -> Result<StoredArtifact, ArtifactError> {
    store.put(digest, input, size)
}
fn strv(v: &Value, k: &str) -> Option<String> {
    v.get(k).and_then(Value::as_str).map(Into::into)
}
fn validate_component(value: &str, label: &str) -> Result<(), ArtifactError> {
    if value.trim().is_empty()
        || value.len() > MAX_COMPONENT_BYTES
        || value
            .chars()
            .any(|character| matches!(character, '\\' | '?' | '#'))
        || value.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
        || value
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(ArtifactError::InvalidResponse(format!("invalid {label}")));
    }
    Ok(())
}
fn parse_items(
    body: &[u8],
    source: &str,
    source_id: &str,
    kind: &str,
) -> Result<Vec<ArtifactMetadata>, ArtifactError> {
    let v: Value = serde_json::from_slice(body)?;
    let xs = v
        .as_array()
        .ok_or_else(|| ArtifactError::InvalidResponse("expected array".into()))?;
    xs.iter()
        .map(|x| {
            let url = strv(x, "url")
                .or_else(|| strv(x, "browser_download_url"))
                .ok_or_else(|| ArtifactError::InvalidResponse("missing download URL".into()))?;
            checked_request("GET", &url, Vec::new())?;
            let digest = strv(x, "digest")
                .unwrap_or_default()
                .trim_start_matches("sha256:")
                .to_owned();
            let filename = strv(x, "filename")
                .or_else(|| strv(x, "name"))
                .ok_or_else(|| ArtifactError::InvalidResponse("missing filename".into()))?;
            let m = ArtifactMetadata {
                kind: kind.into(),
                name: strv(x, "name").unwrap_or_else(|| filename.clone()),
                version: strv(x, "version").unwrap_or_default(),
                source: source.into(),
                source_id: source_id.into(),
                digest,
                filename,
                size: x.get("size").and_then(Value::as_u64),
                compatibility: String::new(),
                metadata: x.to_string(),
            };
            m.validate()?;
            Ok(m)
        })
        .collect()
}
fn download(
    a: &ArtifactMetadata,
    t: &dyn HttpTransport,
    s: &ArtifactStore,
) -> Result<StoredArtifact, ArtifactError> {
    a.validate()?;
    let v: Value = serde_json::from_str(&a.metadata)?;
    let url = strv(&v, "url")
        .or_else(|| strv(&v, "browser_download_url"))
        .ok_or_else(|| ArtifactError::InvalidResponse("missing download URL".into()))?;
    let request = checked_request_for_transport(
        "GET",
        &url,
        vec![("User-Agent".into(), USER_AGENT.into())],
        t,
    )?;
    let stream = t.send_stream(request, Duration::from_secs(60), s.max_bytes)?;
    check_stream_response(&stream, s.max_bytes)?;
    let response_size = content_length(&stream.headers)?;
    if let (Some(expected), Some(actual)) = (a.size, response_size)
        && expected != actual
    {
        return Err(ArtifactError::SizeMismatch { expected, actual });
    }
    let expected = (!a.digest.is_empty()).then_some(a.digest.as_str());
    let stored = s.put_stream(expected, stream.body, a.size.or(response_size))?;
    let metadata: Value = serde_json::from_str(&a.metadata)?;
    if let Some(expected_sha512) = metadata
        .get("hashes")
        .and_then(|hashes| strv(hashes, "sha512"))
    {
        let actual_sha512 = sha512_reader(s.open(&stored.digest)?)?;
        if expected_sha512 != actual_sha512 {
            return Err(ArtifactError::DigestMismatch {
                expected: expected_sha512,
                actual: actual_sha512,
            });
        }
    }
    Ok(stored)
}

#[derive(Debug, Deserialize)]
struct ModrinthVersion {
    id: String,
    version_number: String,
    files: Vec<ModrinthFile>,
}
#[derive(Debug, Serialize, Deserialize)]
struct ModrinthFile {
    hashes: ModrinthHashes,
    url: String,
    filename: String,
    size: u64,
}
#[derive(Debug, Serialize, Deserialize)]
struct ModrinthHashes {
    sha1: String,
    sha512: String,
}
/// Modrinth v2 version endpoint (official docs: https://docs.modrinth.com/api/operations/getversion/).
pub struct Modrinth {
    pub project_id: String,
}
impl ArtifactProvider for Modrinth {
    fn discover(&self, t: &dyn HttpTransport) -> Result<Vec<ArtifactMetadata>, ArtifactError> {
        validate_component(&self.project_id, "Modrinth project ID")?;
        let u = format!(
            "https://api.modrinth.com/v2/project/{}/version",
            self.project_id
        );
        let r = t.send(
            checked_request("GET", &u, vec![("User-Agent".into(), USER_AGENT.into())])?,
            Duration::from_secs(20),
            MAX_DEFAULT_BYTES,
        )?;
        let versions: Vec<ModrinthVersion> =
            serde_json::from_slice(&check_response(r, MAX_DEFAULT_BYTES)?.body)?;
        let mut files = Vec::new();
        for version in versions {
            for file in version.files {
                let filename = file.filename.clone();
                let value = serde_json::json!({
                    "version": version.version_number.clone(),
                    "version_id": version.id.clone(),
                    "name": filename.clone(),
                    "filename": filename,
                    "url": file.url,
                    "size": file.size,
                    "hashes": file.hashes,
                });
                files.push(value);
            }
        }
        parse_items(
            &serde_json::to_vec(&files)?,
            "modrinth",
            &self.project_id,
            "mod",
        )
    }
    fn download(
        &self,
        a: &ArtifactMetadata,
        t: &dyn HttpTransport,
        s: &ArtifactStore,
    ) -> Result<StoredArtifact, ArtifactError> {
        download(a, t, s)
    }
}
/// GitHub latest release API (official docs: https://docs.github.com/en/rest/releases).
#[derive(Debug, Deserialize)]
struct GitHubReleaseResponse {
    tag_name: String,
    assets: Vec<GitHubAsset>,
}
#[derive(Debug, Serialize, Deserialize)]
struct GitHubAsset {
    name: String,
    size: u64,
    browser_download_url: String,
    #[serde(default)]
    digest: Option<String>,
}
pub struct GitHubRelease {
    pub owner: String,
    pub repo: String,
}
impl ArtifactProvider for GitHubRelease {
    fn discover(&self, t: &dyn HttpTransport) -> Result<Vec<ArtifactMetadata>, ArtifactError> {
        validate_component(&self.owner, "GitHub owner")?;
        validate_component(&self.repo, "GitHub repository")?;
        let u = format!(
            "https://api.github.com/repos/{}/{}/releases/latest",
            self.owner, self.repo
        );
        let r = t.send(
            checked_request(
                "GET",
                &u,
                vec![
                    ("Accept".into(), "application/vnd.github+json".into()),
                    ("X-GitHub-Api-Version".into(), "2022-11-28".into()),
                    ("User-Agent".into(), USER_AGENT.into()),
                ],
            )?,
            Duration::from_secs(20),
            MAX_DEFAULT_BYTES,
        )?;
        let release: GitHubReleaseResponse =
            serde_json::from_slice(&check_response(r, MAX_DEFAULT_BYTES)?.body)?;
        let assets: Vec<Value> = release
            .assets
            .into_iter()
            .map(|asset| {
                serde_json::json!({
                    "name": asset.name.clone(),
                    "filename": asset.name,
                    "size": asset.size,
                    "browser_download_url": asset.browser_download_url,
                    "digest": asset.digest,
                    "version": release.tag_name.clone(),
                })
            })
            .collect();
        parse_items(
            &serde_json::to_vec(&assets)?,
            "github",
            &format!("{}/{}", self.owner, self.repo),
            "release",
        )
    }
    fn download(
        &self,
        a: &ArtifactMetadata,
        t: &dyn HttpTransport,
        s: &ArtifactStore,
    ) -> Result<StoredArtifact, ArtifactError> {
        download(a, t, s)
    }
}
/// PaperMC Fill v3 builds API. Fill requires a User-Agent; only stable builds are accepted by callers.
#[derive(Debug, Deserialize)]
struct PaperBuild {
    channel: String,
    downloads: HashMap<String, PaperDownload>,
}
#[derive(Debug, Deserialize)]
struct PaperDownload {
    name: String,
    checksums: PaperChecksums,
    size: u64,
    url: String,
}
#[derive(Debug, Deserialize)]
struct PaperChecksums {
    sha256: String,
}
pub struct PaperFill {
    pub minecraft_version: String,
}
impl ArtifactProvider for PaperFill {
    fn discover(&self, t: &dyn HttpTransport) -> Result<Vec<ArtifactMetadata>, ArtifactError> {
        validate_component(&self.minecraft_version, "Minecraft version")?;
        let u = format!(
            "https://fill.papermc.io/v3/projects/paper/versions/{}/builds",
            self.minecraft_version
        );
        let r = t.send(
            checked_request("GET", &u, vec![("User-Agent".into(), USER_AGENT.into())])?,
            Duration::from_secs(20),
            MAX_DEFAULT_BYTES,
        )?;
        let builds: Vec<PaperBuild> =
            serde_json::from_slice(&check_response(r, MAX_DEFAULT_BYTES)?.body)?;
        let mut items = Vec::new();
        for build in builds {
            if !build.channel.eq_ignore_ascii_case("STABLE") {
                continue;
            }
            let file = build.downloads.get("server:default").ok_or_else(|| {
                ArtifactError::InvalidResponse("missing Paper server:default download".into())
            })?;
            items.push(serde_json::json!({
                "version": self.minecraft_version.clone(),
                "name": file.name.clone(),
                "filename": file.name.clone(),
                "url": file.url.clone(),
                "size": file.size,
                "digest": file.checksums.sha256.clone(),
            }));
        }
        parse_items(
            &serde_json::to_vec(&items)?,
            "papermc-fill-v3",
            &self.minecraft_version,
            "server",
        )
    }
    fn download(
        &self,
        a: &ArtifactMetadata,
        t: &dyn HttpTransport,
        s: &ArtifactStore,
    ) -> Result<StoredArtifact, ArtifactError> {
        download(a, t, s)
    }
}
/// Hangar v1 project versions API (official docs: https://hangar.papermc.io/api-docs/).
#[derive(Debug, Serialize, Deserialize)]
struct HangarPage {
    #[serde(rename = "pagination")]
    _pagination: HangarPagination,
    result: Vec<HangarVersion>,
}
#[derive(Debug, Serialize, Deserialize)]
#[allow(dead_code)]
struct HangarPagination {
    count: u64,
    limit: u64,
    offset: u64,
}
#[derive(Debug, Serialize, Deserialize)]
struct HangarVersion {
    name: String,
    downloads: HashMap<String, HangarDownload>,
}
#[derive(Debug, Serialize, Deserialize)]
struct HangarDownload {
    #[serde(rename = "fileInfo")]
    file_info: HangarFileInfo,
    #[serde(rename = "downloadUrl")]
    download_url: String,
}
#[derive(Debug, Serialize, Deserialize)]
struct HangarFileInfo {
    name: String,
    #[serde(rename = "sizeBytes")]
    size_bytes: u64,
    #[serde(rename = "sha256Hash")]
    sha256_hash: String,
}
pub struct Hangar {
    pub project: String,
}
impl ArtifactProvider for Hangar {
    fn discover(&self, t: &dyn HttpTransport) -> Result<Vec<ArtifactMetadata>, ArtifactError> {
        validate_component(&self.project, "Hangar project")?;
        let u = format!(
            "https://hangar.papermc.io/api/v1/projects/{}/versions",
            self.project
        );
        let r = t.send(
            checked_request("GET", &u, vec![("User-Agent".into(), USER_AGENT.into())])?,
            Duration::from_secs(20),
            MAX_DEFAULT_BYTES,
        )?;
        let page: HangarPage = serde_json::from_slice(&check_response(r, MAX_DEFAULT_BYTES)?.body)?;
        let mut items = Vec::new();
        for version in page.result {
            for (platform, download) in version.downloads {
                let metadata = serde_json::to_string(&download)?;
                checked_request("GET", &download.download_url, Vec::new())?;
                let m = ArtifactMetadata {
                    kind: "plugin".into(), name: self.project.clone(), version: version.name.clone(),
                    source: "hangar".into(), source_id: self.project.clone(), digest: download.file_info.sha256_hash.clone(),
                    filename: download.file_info.name.clone(), size: Some(download.file_info.size_bytes), compatibility: platform,
                    metadata: serde_json::json!({"url": download.download_url, "sha256": download.file_info.sha256_hash, "source": metadata}).to_string(),
                };
                m.validate()?;
                items.push(m);
            }
        }
        Ok(items)
    }
    fn download(
        &self,
        a: &ArtifactMetadata,
        t: &dyn HttpTransport,
        s: &ArtifactStore,
    ) -> Result<StoredArtifact, ArtifactError> {
        download(a, t, s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    struct MockTransport {
        requests: Mutex<Vec<HttpRequest>>,
        responses: Mutex<VecDeque<HttpResponse>>,
    }
    impl MockTransport {
        fn new(body: &str) -> Self {
            Self {
                requests: Mutex::new(Vec::new()),
                responses: Mutex::new(VecDeque::from([HttpResponse {
                    status: 200,
                    headers: vec![],
                    body: body.as_bytes().to_vec(),
                }])),
            }
        }
        fn requests(&self) -> Vec<HttpRequest> {
            self.requests.lock().unwrap().clone()
        }
    }
    impl HttpTransport for MockTransport {
        fn send(
            &self,
            request: HttpRequest,
            _timeout: Duration,
            _max_bytes: u64,
        ) -> Result<HttpResponse, ArtifactError> {
            self.requests.lock().unwrap().push(request);
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| ArtifactError::Transport("mock response exhausted".into()))
        }
    }

    fn digest(bytes: &[u8]) -> String {
        hex(&Sha256::digest(bytes))
    }

    #[test]
    fn cas_verifies_deduplicates_and_limits() {
        let root =
            std::env::temp_dir().join(format!("kitsunebi-artifacts-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let store = ArtifactStore::new(&root, 32).unwrap();
        let bytes = b"artifact";
        let d = digest(bytes);
        assert_eq!(store.put(&d, &bytes[..], Some(8)).unwrap().size, 8);
        assert_eq!(store.put(&d, &bytes[..], Some(8)).unwrap().size, 8);
        assert!(matches!(
            store.put(&digest(b"expected"), &b"wrong"[..], None),
            Err(ArtifactError::DigestMismatch { .. })
        ));
        let large = b"012345678901234567890123456789012345";
        assert!(matches!(
            store.put(&digest(large), &large[..], None),
            Err(ArtifactError::TooLarge { .. })
        ));
        assert_eq!(store.read(&d).unwrap(), bytes);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn url_policy_rejects_traversal_and_plain_http() {
        assert!(matches!(
            checked_request("GET", "http://example.test/a", vec![]),
            Err(ArtifactError::InsecureUrl)
        ));
        assert!(matches!(
            checked_request("GET", "https://example.test/a?token=secret", vec![]),
            Err(ArtifactError::InsecureUrl)
        ));
        assert!(matches!(
            checked_request("GET", "https://example.test/a#fragment", vec![]),
            Err(ArtifactError::InsecureUrl)
        ));
        assert!(
            checked_request(
                "GET",
                "https://example.test/a",
                vec![("X-Test".into(), "ok\nno".into())]
            )
            .is_err()
        );
        let m = ArtifactMetadata {
            kind: "x".into(),
            name: "x".into(),
            version: "x".into(),
            source: "x".into(),
            source_id: "x".into(),
            digest: "0".repeat(64),
            filename: "../escape.jar".into(),
            size: None,
            compatibility: "".into(),
            metadata: "{}".into(),
        };
        assert!(matches!(m.validate(), Err(ArtifactError::UnsafePath)));

        let config = TransportConfig {
            allow_localhost: true,
            ..TransportConfig::default()
        };
        let transport = ReqwestTransport::new(config).unwrap();
        assert!(
            transport
                .send(
                    HttpRequest {
                        method: "GET".into(),
                        url: "http://127.0.0.1:1/artifact".into(),
                        headers: vec![],
                    },
                    Duration::from_secs(1),
                    32,
                )
                .is_err()
        );
        let localhost = ReqwestTransport::localhost_test(TransportConfig::default()).unwrap();
        assert!(
            localhost
                .validate_parsed_url(
                    reqwest::Url::parse("http://127.0.0.1:1/artifact?signature=fixture").unwrap(),
                    true,
                )
                .is_ok()
        );
        let production = ReqwestTransport::new(TransportConfig::default()).unwrap();
        assert!(
            production
                .validate_parsed_url(
                    reqwest::Url::parse("https://evil.example/artifact").unwrap(),
                    true,
                )
                .is_err()
        );
        assert!(
            production
                .validate_parsed_url(
                    reqwest::Url::parse("https://user:password@api.github.com/artifact").unwrap(),
                    true,
                )
                .is_err()
        );
        assert!(
            production
                .validate_parsed_url(
                    reqwest::Url::parse("https://evil.example/artifact?signature=fixture").unwrap(),
                    true,
                )
                .is_err()
        );
        assert!(
            ReqwestTransport::with_allowed_hosts(TransportConfig::default(), ["127.0.0.1"])
                .is_err()
        );
        assert!(
            ReqwestTransport::localhost_test(TransportConfig {
                allowed_hosts: vec!["127.0.0.1".into()],
                ..TransportConfig::default()
            })
            .is_ok()
        );
        assert!(redirect_headers_safe(
            &[("User-Agent".into(), USER_AGENT.into())],
            true
        ));
        assert!(!redirect_headers_safe(
            &[("Authorization".into(), "fixture-secret".into())],
            true
        ));
        assert!(redirect_headers_safe(
            &[("Authorization".into(), "fixture-secret".into())],
            false
        ));
    }

    #[test]
    fn modrinth_fixture_keeps_upstream_hashes_and_exact_path() {
        let mock = MockTransport::new(include_str!(
            "../../../tests/contract/artifacts/modrinth_versions.json"
        ));
        let items = Modrinth {
            project_id: "project01".into(),
        }
        .discover(&mock)
        .unwrap();
        assert_eq!(items.len(), 1);
        assert!(
            items[0].digest.is_empty(),
            "Modrinth does not publish SHA-256"
        );
        assert!(items[0].metadata.contains("sha512"));
        assert_eq!(
            mock.requests()[0].url,
            "https://api.modrinth.com/v2/project/project01/version"
        );
        assert_eq!(
            mock.requests()[0].headers,
            vec![("User-Agent".into(), USER_AGENT.into())]
        );
    }

    #[test]
    fn paper_fixture_uses_fill_v3_server_default() {
        let mock = MockTransport::new(include_str!(
            "../../../tests/contract/artifacts/paper_builds.json"
        ));
        let items = PaperFill {
            minecraft_version: "1.21.4".into(),
        }
        .discover(&mock)
        .unwrap();
        assert_eq!(items[0].filename, "paper-1.21.4-232.jar");
        assert_eq!(
            items[0].digest,
            "5ee4f542f628a14c644410b08c94ea42e772ef4d29fe92973636b6813d4eaffc"
        );
        assert_eq!(
            mock.requests()[0].url,
            "https://fill.papermc.io/v3/projects/paper/versions/1.21.4/builds"
        );
    }

    #[test]
    fn hangar_fixture_parses_pagination_result_and_sha256() {
        let mock = MockTransport::new(include_str!(
            "../../../tests/contract/artifacts/hangar_versions.json"
        ));
        let items = Hangar {
            project: "HelpChat/PlaceholderAPI".into(),
        }
        .discover(&mock)
        .unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].size, Some(1160690));
        assert_eq!(items[0].compatibility, "PAPER");
        assert_eq!(
            mock.requests()[0].url,
            "https://hangar.papermc.io/api/v1/projects/HelpChat/PlaceholderAPI/versions"
        );
    }

    #[test]
    fn github_fixture_parses_sha256_digest_and_asset_url() {
        let mock = MockTransport::new(include_str!(
            "../../../tests/contract/artifacts/github_release.json"
        ));
        let items = GitHubRelease {
            owner: "example".into(),
            repo: "example".into(),
        }
        .discover(&mock)
        .unwrap();
        assert_eq!(
            items[0].digest,
            "c7c5c1d70c5dec4416ab6158afd0b223ef40c29b1dc1f97ed9428b94d4cadb1c"
        );
        assert_eq!(
            mock.requests()[0].url,
            "https://api.github.com/repos/example/example/releases/latest"
        );
    }

    #[test]
    fn provider_schema_regressions_are_rejected() {
        let modrinth = MockTransport::new(
            r#"[{"id":"v1","version_number":"1.0.0","files":[{"hashes":{"sha1":"x"},"url":"https://cdn.modrinth.com/x","filename":"x.jar","size":1}]}]"#,
        );
        assert!(matches!(
            (Modrinth {
                project_id: "project".into()
            })
            .discover(&modrinth),
            Err(ArtifactError::Json(_))
        ));

        let paper = MockTransport::new(
            r#"[{"channel":"STABLE","downloads":{"server:jar":{"name":"paper.jar","checksums":{"sha256":"0000000000000000000000000000000000000000000000000000000000000000"},"size":1,"url":"https://fill-data.papermc.io/x"}}}]"#,
        );
        assert!(matches!(
            (PaperFill {
                minecraft_version: "1.21.4".into()
            })
            .discover(&paper),
            Err(ArtifactError::InvalidResponse(_))
        ));

        let hangar = MockTransport::new("[]");
        assert!(matches!(
            (Hangar {
                project: "owner/project".into()
            })
            .discover(&hangar),
            Err(ArtifactError::Json(_))
        ));

        let github = MockTransport::new(r#"{"assets":[]}"#);
        assert!(matches!(
            (GitHubRelease {
                owner: "owner".into(),
                repo: "repo".into()
            })
            .discover(&github),
            Err(ArtifactError::Json(_))
        ));

        let query_url = MockTransport::new(
            r#"[{"id":"v1","version_number":"1.0.0","files":[{"hashes":{"sha1":"x","sha512":"x"},"url":"https://cdn.modrinth.com/x?signature=fixture","filename":"x.jar","size":1}]}]"#,
        );
        assert!(matches!(
            (Modrinth {
                project_id: "project".into()
            })
            .discover(&query_url),
            Err(ArtifactError::InsecureUrl)
        ));
    }

    #[test]
    fn download_computes_sha256_and_writes_cas() {
        let mock = MockTransport::new("artifact");
        let root = std::env::temp_dir().join(format!(
            "kitsunebi-artifacts-download-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let store = ArtifactStore::new(&root, 32).unwrap();
        let provider = DirectUrl {
            url: "https://example.test/artifact.jar".into(),
            filename: "artifact.jar".into(),
            digest: digest(b"artifact"),
            size: Some(8),
        };
        mock.responses.lock().unwrap().push_back(HttpResponse {
            status: 200,
            headers: vec![],
            body: b"artifact".to_vec(),
        });
        let artifact = provider.discover(&mock).unwrap().remove(0);
        let stored = provider.download(&artifact, &mock, &store).unwrap();
        assert_eq!(stored.digest, digest(b"artifact"));
        assert_eq!(mock.requests()[0].url, "https://example.test/artifact.jar");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn direct_url_cannot_change_after_discovery() {
        let mock = MockTransport::new("artifact");
        let root = std::env::temp_dir().join(format!(
            "kitsunebi-artifacts-direct-url-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let store = ArtifactStore::new(&root, 32).unwrap();
        let provider = DirectUrl {
            url: "https://example.test/artifact.jar".into(),
            filename: "artifact.jar".into(),
            digest: digest(b"artifact"),
            size: Some(8),
        };
        let mut artifact = provider.discover(&mock).unwrap().remove(0);
        artifact.metadata = serde_json::json!({
            "url": "https://other.example.test/artifact.jar"
        })
        .to_string();
        assert!(matches!(
            provider.download(&artifact, &mock, &store),
            Err(ArtifactError::InvalidResponse(_))
        ));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn official_provider_candidates_download_and_verify() {
        let root = std::env::temp_dir().join(format!(
            "kitsunebi-artifacts-provider-download-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let store = ArtifactStore::new(&root, 32).unwrap();

        let modrinth = MockTransport::new(include_str!(
            "../../../tests/contract/artifacts/modrinth_versions.json"
        ));
        modrinth.responses.lock().unwrap().push_back(HttpResponse {
            status: 200,
            headers: vec![("Content-Length".into(), "8".into())],
            body: b"artifact".to_vec(),
        });
        let modrinth_artifact = Modrinth {
            project_id: "project01".into(),
        }
        .discover(&modrinth)
        .unwrap()
        .remove(0);
        let stored = Modrinth {
            project_id: "project01".into(),
        }
        .download(&modrinth_artifact, &modrinth, &store)
        .unwrap();
        assert_eq!(stored.digest, digest(b"artifact"));

        let github = MockTransport::new(include_str!(
            "../../../tests/contract/artifacts/github_release.json"
        ));
        github.responses.lock().unwrap().push_back(HttpResponse {
            status: 200,
            headers: vec![("Content-Length".into(), "8".into())],
            body: b"artifact".to_vec(),
        });
        let github_provider = GitHubRelease {
            owner: "example".into(),
            repo: "example".into(),
        };
        let github_artifact = github_provider.discover(&github).unwrap().remove(0);
        assert_eq!(
            github_provider
                .download(&github_artifact, &github, &store)
                .unwrap()
                .digest,
            digest(b"artifact")
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn rate_limit_keeps_retry_after() {
        let response = HttpResponse {
            status: 429,
            headers: vec![("Retry-After".into(), "12".into())],
            body: vec![],
        };
        assert!(
            matches!(check_response(response, 32), Err(ArtifactError::RateLimited { retry_after: Some(value) }) if value == "12")
        );
    }

    #[test]
    fn stream_content_length_is_bounded_and_validated() {
        let too_large = StreamResponse {
            status: 200,
            headers: vec![("Content-Length".into(), "33".into())],
            body: Box::new(Cursor::new(Vec::new())),
        };
        assert!(matches!(
            check_stream_response(&too_large, 32),
            Err(ArtifactError::TooLarge { limit: 32 })
        ));

        let malformed = StreamResponse {
            status: 200,
            headers: vec![("Content-Length".into(), "unknown".into())],
            body: Box::new(Cursor::new(Vec::new())),
        };
        assert!(matches!(
            check_stream_response(&malformed, 32),
            Err(ArtifactError::InvalidResponse(_))
        ));
    }

    struct SequenceResolver {
        answers: Mutex<VecDeque<Vec<SocketAddr>>>,
    }

    impl DnsResolver for SequenceResolver {
        fn resolve(&self, _host: &str, _port: u16) -> Result<Vec<SocketAddr>, ArtifactError> {
            self.answers
                .lock()
                .unwrap()
                .pop_front()
                .ok_or_else(|| ArtifactError::Transport("resolver exhausted".into()))
        }
    }

    fn address(value: &str) -> SocketAddr {
        value.parse().unwrap()
    }

    #[test]
    fn resolved_address_policy_rejects_non_global_and_mixed_answers() {
        assert!(validate_resolved_addresses(&[address("1.1.1.1:443")]).is_ok());
        for value in [
            "127.0.0.1:443",
            "10.0.0.1:443",
            "169.254.1.1:443",
            "100.64.0.1:443",
            "192.0.2.1:443",
            "240.0.0.1:443",
            "[::1]:443",
            "[::ffff:127.0.0.1]:443",
            "[::1.1.1.1]:443",
            "0.1.2.3:443",
            "[fc00::1]:443",
            "[fe80::1]:443",
            "[fec0::1]:443",
            "[2001:db8::1]:443",
        ] {
            assert!(
                validate_resolved_addresses(&[address(value)]).is_err(),
                "{value}"
            );
        }
        assert!(validate_resolved_addresses(&[address("[::ffff:1.1.1.1]:443")]).is_ok());
        assert!(validate_resolved_addresses(&[]).is_err());
        assert!(
            validate_resolved_addresses(&[address("1.1.1.1:443"), address("10.0.0.1:443")])
                .is_err()
        );
    }

    #[test]
    fn https_port_is_exactly_443() {
        let transport = ReqwestTransport::new(TransportConfig::default()).unwrap();
        assert!(
            transport
                .validate_parsed_url(
                    reqwest::Url::parse("https://api.github.com/file").unwrap(),
                    true
                )
                .is_ok()
        );
        assert!(
            transport
                .validate_parsed_url(
                    reqwest::Url::parse("https://api.github.com:444/file").unwrap(),
                    true
                )
                .is_err()
        );
        assert!(
            transport
                .validate_parsed_url(
                    reqwest::Url::parse("https://api.github.com:443/file").unwrap(),
                    true
                )
                .is_ok()
        );
    }

    #[test]
    fn resolver_is_rechecked_for_each_request_and_rebinding_fails_closed() {
        let resolver = Arc::new(SequenceResolver {
            answers: Mutex::new(VecDeque::from([
                vec![address("1.1.1.1:443")],
                vec![address("127.0.0.1:443")],
            ])),
        });
        let transport =
            ReqwestTransport::with_resolver(TransportConfig::default(), resolver).unwrap();
        let url = reqwest::Url::parse("https://api.github.com/file").unwrap();
        assert_eq!(
            transport.resolve_for_request(&url).unwrap(),
            address("1.1.1.1:443")
        );
        assert!(transport.resolve_for_request(&url).is_err());
    }
}
