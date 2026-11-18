#![forbid(unsafe_code)]
//! Typed TCPShield backend-set adapter.
//!
//! Endpoint/payload names follow the vendor OpenAPI 1.0 document, checked
//! 2026-08-31. TCPShield documents X-API-Key authentication for Pro+ plans.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, fmt, future::Future, pin::Pin, sync::Arc, time::Duration};
use tokio::sync::Mutex;
pub const CRATE_NAME: &str = "kitsunebi-tcpshield";
pub const API_BASE_URL: &str = "https://api.tcpshield.com";
pub const API_SPEC_URL: &str =
    "https://raw.githubusercontent.com/TCPShield/api-docs/development/tcpshield-api.yaml";
pub const API_SPEC_VERSION: &str = "1.0";
pub const API_SPEC_CHECKED: &str = "2026-08-31";
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);
impl Secret {
    pub fn new(v: impl Into<String>) -> Self {
        Self(v.into())
    }
    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.trim().is_empty()
    }
}
impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([REDACTED])")
    }
}
impl fmt::Display for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientConfig {
    pub timeout: Duration,
    pub max_response_bytes: u64,
}
impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(15),
            max_response_bytes: 1024 * 1024,
        }
    }
}
#[derive(Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}
impl fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let headers: Vec<_> = self
            .headers
            .iter()
            .map(|(name, value)| {
                (
                    name,
                    if name.eq_ignore_ascii_case("x-api-key") {
                        "[REDACTED]"
                    } else {
                        value.as_str()
                    },
                )
            })
            .collect();
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("path", &self.path)
            .field("headers", &headers)
            .field("body", &self.body)
            .finish()
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    Timeout,
    Unavailable,
    Other(String),
    BodyTooLarge { limit: u64 },
}
pub trait HttpTransport: Send + Sync {
    fn send(
        &self,
        r: HttpRequest,
    ) -> Pin<Box<dyn Future<Output = Result<HttpResponse, TransportError>> + Send + '_>>;
}

/// Configuration for the concrete HTTPS transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportConfig {
    pub timeout: Duration,
    pub max_response_bytes: u64,
    /// Permit `http://localhost`, `127.0.0.1`, and `[::1]` only for tests.
    pub allow_localhost: bool,
}
impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(15),
            max_response_bytes: 1024 * 1024,
            allow_localhost: false,
        }
    }
}

/// Production HTTP transport. Redirects are deliberately disabled so an API
/// key cannot be forwarded to an unexpected host.
#[derive(Clone)]
pub struct ReqwestTransport {
    base_url: reqwest::Url,
    client: reqwest::Client,
    max_response_bytes: u64,
    allow_localhost: bool,
}
impl fmt::Debug for ReqwestTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReqwestTransport")
            .field("base_url", &self.base_url)
            .field("max_response_bytes", &self.max_response_bytes)
            .field("allow_localhost", &self.allow_localhost)
            .finish()
    }
}
impl ReqwestTransport {
    pub fn new(base_url: impl AsRef<str>, config: TransportConfig) -> Result<Self, Error> {
        Self::build(base_url.as_ref(), config)
    }
    pub fn localhost_test(
        base_url: impl AsRef<str>,
        mut config: TransportConfig,
    ) -> Result<Self, Error> {
        config.allow_localhost = true;
        Self::build(base_url.as_ref(), config)
    }
    fn build(base_url: &str, config: TransportConfig) -> Result<Self, Error> {
        let mut parsed = reqwest::Url::parse(base_url)
            .map_err(|e| Error::InvalidInput(format!("invalid TCPShield base URL: {e}")))?;
        if parsed.username() != ""
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(Error::InvalidInput(
                "base URL must not contain credentials, query, or fragment".into(),
            ));
        }
        if !allowed_url(&parsed, config.allow_localhost) {
            return Err(Error::InvalidInput(
                "TCPShield transport requires HTTPS (or explicit localhost test mode)".into(),
            ));
        }
        if parsed.host_str().is_none() {
            return Err(Error::InvalidInput(
                "TCPShield base URL must include a host".into(),
            ));
        }
        if config.max_response_bytes == 0 {
            return Err(Error::InvalidInput(
                "TCPShield max response bytes must be positive".into(),
            ));
        }
        if config.timeout.is_zero() {
            return Err(Error::InvalidInput(
                "TCPShield timeout must be positive".into(),
            ));
        }
        if !parsed.path().ends_with('/') {
            parsed.set_path(&format!("{}/", parsed.path()));
        }
        let client = reqwest::Client::builder()
            .timeout(config.timeout)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| Error::InvalidInput(format!("cannot build HTTPS client: {e}")))?;
        Ok(Self {
            base_url: parsed,
            client,
            max_response_bytes: config.max_response_bytes,
            allow_localhost: config.allow_localhost,
        })
    }
    fn endpoint(&self, path: &str) -> Result<reqwest::Url, TransportError> {
        let path = path.strip_prefix('/').unwrap_or(path);
        let url = self
            .base_url
            .join(path)
            .map_err(|e| TransportError::Other(format!("invalid endpoint path: {e}")))?;
        if !allowed_url(&url, self.allow_localhost)
            || url.host() != self.base_url.host()
            || url.port() != self.base_url.port()
        {
            return Err(TransportError::Other(
                "endpoint host policy rejected URL".into(),
            ));
        }
        Ok(url)
    }
}
fn allowed_url(url: &reqwest::Url, allow_localhost: bool) -> bool {
    let local = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1"));
    if local && !allow_localhost {
        return false;
    }
    if url.scheme() == "https" {
        return true;
    }
    allow_localhost
        && url.scheme() == "http"
        && matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1"))
}
impl HttpTransport for ReqwestTransport {
    fn send(
        &self,
        request: HttpRequest,
    ) -> Pin<Box<dyn Future<Output = Result<HttpResponse, TransportError>> + Send + '_>> {
        let transport = self.clone();
        Box::pin(async move {
            let url = transport.endpoint(&request.path)?;
            let method = reqwest::Method::from_bytes(request.method.as_bytes())
                .map_err(|e| TransportError::Other(format!("invalid HTTP method: {e}")))?;
            let mut builder = transport.client.request(method, url).body(request.body);
            for (name, value) in request.headers {
                builder = builder.header(name, value);
            }
            let response = builder.send().await.map_err(|error| {
                if error.is_timeout() {
                    TransportError::Timeout
                } else if error.is_connect() {
                    TransportError::Unavailable
                } else {
                    TransportError::Other(error.to_string())
                }
            })?;
            let status = response.status().as_u16();
            if let Some(value) = response.headers().get(reqwest::header::CONTENT_LENGTH) {
                let length = value
                    .to_str()
                    .ok()
                    .and_then(|value| value.parse::<u64>().ok())
                    .ok_or_else(|| TransportError::Other("invalid content length".into()))?;
                if length > transport.max_response_bytes {
                    return Err(TransportError::BodyTooLarge {
                        limit: transport.max_response_bytes,
                    });
                }
            }
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
            let mut body = Vec::new();
            let mut stream = response.bytes_stream();
            use futures_util::StreamExt;
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|error| TransportError::Other(error.to_string()))?;
                if body.len().saturating_add(chunk.len()) as u64 > transport.max_response_bytes {
                    return Err(TransportError::BodyTooLarge {
                        limit: transport.max_response_bytes,
                    });
                }
                body.extend_from_slice(&chunk);
            }
            Ok(HttpResponse {
                status,
                headers,
                body,
            })
        })
    }
}
#[derive(Clone, PartialEq, Eq)]
pub enum Error {
    Transport(TransportError),
    Timeout,
    RateLimited {
        retry_after: Option<String>,
    },
    Unauthorized,
    Forbidden,
    NotFound,
    Http {
        status: u16,
        body: String,
    },
    Decode(String),
    /// The API response did not include the fields required for a safe
    /// backend-set hash. Treating an omitted `backends` field as an empty set
    /// would turn an unknown state into a false drift/verification result.
    IncompleteResponse(String),
    InvalidInput(String),
    ExternalDrift {
        expected: String,
        observed: String,
    },
    VerificationFailed {
        expected: String,
        observed: String,
    },
    RollbackConflict {
        expected: String,
        observed: String,
    },
    Ambiguous {
        expected: String,
        original: String,
        observed: Option<String>,
    },
    BodyTooLarge {
        limit: u64,
    },
    DrainUnknown,
    ConnectionsActive {
        count: u64,
    },
}
impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(error) => f.debug_tuple("Transport").field(error).finish(),
            Self::Timeout => f.write_str("Timeout"),
            Self::RateLimited { retry_after } => f
                .debug_struct("RateLimited")
                .field("retry_after", retry_after)
                .finish(),
            Self::Unauthorized => f.write_str("Unauthorized"),
            Self::Forbidden => f.write_str("Forbidden"),
            Self::NotFound => f.write_str("NotFound"),
            // Keep provider-controlled response bodies out of diagnostics.
            Self::Http { status, .. } => f
                .debug_struct("Http")
                .field("status", status)
                .field("body", &"[REDACTED]")
                .finish(),
            Self::Decode(error) => f.debug_tuple("Decode").field(error).finish(),
            Self::IncompleteResponse(error) => {
                f.debug_tuple("IncompleteResponse").field(error).finish()
            }
            Self::InvalidInput(error) => f.debug_tuple("InvalidInput").field(error).finish(),
            Self::ExternalDrift { expected, observed } => f
                .debug_struct("ExternalDrift")
                .field("expected", expected)
                .field("observed", observed)
                .finish(),
            Self::VerificationFailed { expected, observed } => f
                .debug_struct("VerificationFailed")
                .field("expected", expected)
                .field("observed", observed)
                .finish(),
            Self::RollbackConflict { expected, observed } => f
                .debug_struct("RollbackConflict")
                .field("expected", expected)
                .field("observed", observed)
                .finish(),
            Self::Ambiguous {
                expected,
                original,
                observed,
            } => f
                .debug_struct("Ambiguous")
                .field("expected", expected)
                .field("original", original)
                .field("observed", observed)
                .finish(),
            Self::BodyTooLarge { limit } => f
                .debug_struct("BodyTooLarge")
                .field("limit", limit)
                .finish(),
            Self::DrainUnknown => f.write_str("DrainUnknown"),
            Self::ConnectionsActive { count } => f
                .debug_struct("ConnectionsActive")
                .field("count", count)
                .finish(),
        }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendSet {
    pub id: u64,
    pub name: String,
    #[serde(default)]
    pub backends: Vec<String>,
    #[serde(default)]
    pub proxy_protocol: bool,
    #[serde(default)]
    pub vulcan_ac_enabled: bool,
    #[serde(default)]
    pub load_balancing_mode: i64,
}
impl BackendSet {
    pub fn normalized(&self) -> Self {
        let mut x = self.clone();
        x.name = x.name.trim().into();
        x.backends = normalized_backends(&x.backends);
        x
    }
    pub fn hash(&self) -> String {
        normalized_hash(self)
    }
    pub fn add(&self, b: impl Into<String>) -> Result<Self, Error> {
        let b: String = b.into().trim().to_owned();
        validate_backend(&b)?;
        let mut x = self.clone();
        x.backends.push(b);
        Ok(x.normalized())
    }
    pub fn remove(&self, b: &str) -> Self {
        let mut x = self.clone();
        x.backends.retain(|v| v != b);
        x.normalized()
    }
}
fn decode_backend_set(value: serde_json::Value) -> Result<BackendSet, Error> {
    if !value
        .as_object()
        .is_some_and(|object| object.contains_key("backends"))
    {
        return Err(Error::IncompleteResponse(
            "backend-set response omitted backends".into(),
        ));
    }
    let set: BackendSet =
        serde_json::from_value(value).map_err(|error| Error::Decode(error.to_string()))?;
    validate_backend_set(&set)?;
    Ok(set)
}

const MAX_BACKEND_LENGTH: usize = 512;

fn validate_backend(value: &str) -> Result<(), Error> {
    if value.is_empty() {
        return Err(Error::InvalidInput("backend must not be empty".into()));
    }
    if value.len() > MAX_BACKEND_LENGTH || value.chars().any(char::is_control) {
        return Err(Error::InvalidInput("backend is malformed".into()));
    }
    Ok(())
}

fn validate_backend_set(set: &BackendSet) -> Result<(), Error> {
    if set.name.trim().is_empty() || set.name.chars().any(char::is_control) {
        return Err(Error::InvalidInput("backend-set name is malformed".into()));
    }
    for backend in &set.backends {
        validate_backend(backend)?;
    }
    Ok(())
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendSetPlan {
    pub before: BackendSet,
    pub desired: BackendSet,
    pub rollback: BackendSet,
    pub before_hash: String,
    pub desired_hash: String,
}
impl BackendSetPlan {
    pub fn new(a: BackendSet, b: BackendSet) -> Self {
        let (a, b) = (a.normalized(), b.normalized());
        Self {
            before_hash: a.hash(),
            desired_hash: b.hash(),
            rollback: a.clone(),
            before: a,
            desired: b,
        }
    }
}
/// Evidence supplied by a connection-aware caller. TCPShield's API has no
/// endpoint that can prove draining or that existing connections are gone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionEvidence {
    pub count: u64,
    pub observed_at: Option<u64>,
    pub source: String,
}
pub trait ConnectionObserver: Send + Sync {
    fn observe(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<ConnectionEvidence, Error>> + Send + '_>>;
}
pub async fn require_drained(
    observer: &dyn ConnectionObserver,
) -> Result<ConnectionEvidence, Error> {
    let evidence = observer.observe().await?;
    if evidence.count != 0 {
        return Err(Error::ConnectionsActive {
            count: evidence.count,
        });
    }
    if evidence.observed_at.is_none() || evidence.source.trim().is_empty() {
        return Err(Error::DrainUnknown);
    }
    Ok(evidence)
}
pub struct Client<T> {
    base_url: String,
    api_key: Secret,
    pub config: ClientConfig,
    transport: T,
    set_locks: BackendSetLocks,
}
type BackendSetLocks = Mutex<HashMap<(u64, u64), Arc<Mutex<()>>>>;
impl<T: HttpTransport> Client<T> {
    pub fn new(base: impl Into<String>, key: Secret, t: T) -> Result<Self, Error> {
        Self::new_with_policy(base.into(), key, t, false)
    }
    fn localhost(base: impl Into<String>, key: Secret, t: T) -> Result<Self, Error> {
        Self::new_with_policy(base.into(), key, t, true)
    }
    fn new_with_policy(
        base: String,
        key: Secret,
        t: T,
        allow_localhost: bool,
    ) -> Result<Self, Error> {
        let base: String = base.trim_end_matches('/').to_owned();
        let parsed = reqwest::Url::parse(&base)
            .map_err(|e| Error::InvalidInput(format!("invalid TCPShield base URL: {e}")))?;
        if parsed.username() != ""
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(Error::InvalidInput(
                "base URL must not contain credentials, query, or fragment".into(),
            ));
        }
        if parsed.host_str().is_none() || !allowed_url(&parsed, allow_localhost) {
            return Err(Error::InvalidInput(
                "TCPShield base URL requires HTTPS (or explicit localhost test mode)".into(),
            ));
        }
        if key.is_empty() {
            return Err(Error::InvalidInput(
                "TCPShield API key must not be empty".into(),
            ));
        }
        Ok(Self {
            base_url: base,
            api_key: key,
            config: Default::default(),
            transport: t,
            set_locks: Mutex::new(HashMap::new()),
        })
    }
    pub fn with_config(mut self, c: ClientConfig) -> Self {
        self.config = c;
        self
    }
    pub fn base_url(&self) -> &str {
        &self.base_url
    }
    async fn lock_for(&self, network: u64, set: u64) -> Arc<Mutex<()>> {
        let mut locks = self.set_locks.lock().await;
        locks
            .entry((network, set))
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }
    async fn request(&self, m: &str, p: String, b: Vec<u8>) -> Result<HttpResponse, Error> {
        let r = HttpRequest {
            method: m.into(),
            path: p,
            headers: vec![
                ("X-API-Key".into(), self.api_key.expose().into()),
                ("Content-Type".into(), "application/json".into()),
            ],
            body: b,
        };
        let x = self.transport.send(r).await.map_err(|e| match e {
            TransportError::Timeout => Error::Timeout,
            TransportError::BodyTooLarge { limit } => Error::BodyTooLarge { limit },
            e => Error::Transport(e),
        })?;
        if (200..300).contains(&x.status) {
            return Ok(x);
        }
        Err(match x.status {
            401 => Error::Unauthorized,
            403 => Error::Forbidden,
            404 => Error::NotFound,
            408 => Error::Timeout,
            429 => Error::RateLimited {
                retry_after: x
                    .headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("retry-after"))
                    .map(|(_, v)| v.clone()),
            },
            // Provider error bodies are not a stable contract and may contain
            // tenant data or credentials. Keep only the status code.
            s => Error::Http {
                status: s,
                body: String::new(),
            },
        })
    }
    fn path(n: u64, s: u64) -> Result<String, Error> {
        if n == 0 || s == 0 {
            return Err(Error::InvalidInput(
                "network and set IDs must be positive".into(),
            ));
        }
        Ok(format!("/networks/{n}/backendSets/{s}"))
    }
    fn network_path(n: u64) -> Result<String, Error> {
        if n == 0 {
            return Err(Error::InvalidInput("network ID must be positive".into()));
        }
        Ok(format!("/networks/{n}/backendSets"))
    }
    pub async fn list(&self, n: u64) -> Result<Vec<BackendSet>, Error> {
        let x = self.request("GET", Self::network_path(n)?, vec![]).await?;
        let values: Vec<serde_json::Value> =
            serde_json::from_slice(&x.body).map_err(|e| Error::Decode(e.to_string()))?;
        let sets = values
            .into_iter()
            .map(decode_backend_set)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(sets.into_iter().map(|set| set.normalized()).collect())
    }
    pub async fn observe(&self, n: u64, s: u64) -> Result<BackendSet, Error> {
        let x = self.request("GET", Self::path(n, s)?, vec![]).await?;
        let value: serde_json::Value =
            serde_json::from_slice(&x.body).map_err(|e| Error::Decode(e.to_string()))?;
        decode_backend_set(value).map(|v| v.normalized())
    }
    pub fn plan(&self, a: BackendSet, b: BackendSet) -> BackendSetPlan {
        BackendSetPlan::new(a, b)
    }
    pub async fn apply(&self, n: u64, s: u64, p: &BackendSetPlan) -> Result<BackendSet, Error> {
        validate_backend_set(&p.desired)?;
        let set_lock = self.lock_for(n, s).await;
        let _g = set_lock.clone().lock_owned().await;
        let c = self.observe(n, s).await?;
        if c.hash() != p.before_hash {
            return Err(Error::ExternalDrift {
                expected: p.before_hash.clone(),
                observed: c.hash(),
            });
        }
        let body = serde_json::to_vec(&Update {
            name: p.desired.name.clone(),
            backends: p.desired.backends.clone(),
        })
        .map_err(|e| Error::Decode(e.to_string()))?;
        if let Err(e) = self.request("PATCH", Self::path(n, s)?, body).await {
            let o = self.observe(n, s).await.ok().map(|v| v.hash());
            return Err(Error::Ambiguous {
                expected: p.desired_hash.clone(),
                original: e.to_string(),
                observed: o,
            });
        }
        let o = self.observe(n, s).await?;
        if o.hash() != p.desired_hash {
            return Err(Error::VerificationFailed {
                expected: p.desired_hash.clone(),
                observed: o.hash(),
            });
        }
        Ok(o)
    }
    pub async fn rollback(&self, n: u64, s: u64, p: &BackendSetPlan) -> Result<BackendSet, Error> {
        validate_backend_set(&p.rollback)?;
        let set_lock = self.lock_for(n, s).await;
        let _g = set_lock.clone().lock_owned().await;
        let c = self.observe(n, s).await?;
        if c.hash() != p.desired_hash {
            return Err(Error::RollbackConflict {
                expected: p.desired_hash.clone(),
                observed: c.hash(),
            });
        }
        let body = serde_json::to_vec(&Update {
            name: p.rollback.name.clone(),
            backends: p.rollback.backends.clone(),
        })
        .map_err(|e| Error::Decode(e.to_string()))?;
        if let Err(error) = self.request("PATCH", Self::path(n, s)?, body).await {
            let observed = self.observe(n, s).await.ok().map(|set| set.hash());
            return Err(Error::Ambiguous {
                expected: p.before_hash.clone(),
                original: error.to_string(),
                observed,
            });
        }
        let o = self.observe(n, s).await?;
        if o.hash() != p.before_hash {
            return Err(Error::VerificationFailed {
                expected: p.before_hash.clone(),
                observed: o.hash(),
            });
        }
        Ok(o)
    }
}
impl Client<ReqwestTransport> {
    /// Construct the production rustls-backed client. The default transport
    /// accepts HTTPS only and never follows redirects.
    pub fn production(
        base: impl AsRef<str>,
        key: Secret,
        config: ClientConfig,
    ) -> Result<Self, Error> {
        let transport = ReqwestTransport::new(
            base.as_ref(),
            TransportConfig {
                timeout: config.timeout,
                max_response_bytes: config.max_response_bytes,
                allow_localhost: false,
            },
        )?;
        Client::new(base.as_ref(), key, transport).map(|client| client.with_config(config))
    }
    /// Test-only network constructor. It permits HTTP only for localhost hosts.
    pub fn localhost_test(
        base: impl AsRef<str>,
        key: Secret,
        config: ClientConfig,
    ) -> Result<Self, Error> {
        let transport = ReqwestTransport::localhost_test(
            base.as_ref(),
            TransportConfig {
                timeout: config.timeout,
                max_response_bytes: config.max_response_bytes,
                allow_localhost: true,
            },
        )?;
        Client::localhost(base.as_ref(), key, transport).map(|client| client.with_config(config))
    }
}
#[derive(Serialize)]
struct Update {
    name: String,
    backends: Vec<String>,
}
pub fn normalized_backends(v: &[String]) -> Vec<String> {
    let mut x: Vec<_> = v
        .iter()
        .map(|s| s.trim().into())
        .filter(|s: &String| !s.is_empty())
        .collect();
    x.sort();
    x.dedup();
    x
}
pub fn normalized_hash(v: &BackendSet) -> String {
    let b = serde_json::to_vec(&v.normalized()).expect("serializable");
    let mut h = Sha256::new();
    h.update(b);
    format!("{:x}", h.finalize())
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
        fn new(responses: Vec<HttpResponse>) -> Self {
            Self {
                requests: Mutex::new(Vec::new()),
                responses: Mutex::new(responses.into()),
            }
        }
    }
    impl HttpTransport for MockTransport {
        fn send(
            &self,
            request: HttpRequest,
        ) -> Pin<Box<dyn Future<Output = Result<HttpResponse, TransportError>> + Send + '_>>
        {
            self.requests.lock().unwrap().push(request);
            let response = self.responses.lock().unwrap().pop_front().unwrap();
            Box::pin(async move { Ok(response) })
        }
    }
    fn s(v: &[&str]) -> BackendSet {
        BackendSet {
            id: 1,
            name: "prod".into(),
            backends: v.iter().map(|x| (*x).into()).collect(),
            proxy_protocol: false,
            vulcan_ac_enabled: false,
            load_balancing_mode: 0,
        }
    }
    #[test]
    fn hash_normalizes() {
        assert_eq!(s(&[" b ", "a"]).hash(), s(&["a", "b"]).hash())
    }
    #[test]
    fn redacts() {
        assert!(!format!("{:?}", Secret::new("key")).contains("key"));
        assert!(!format!("{}", Secret::new("key")).contains("key"))
    }

    #[test]
    fn provider_error_body_is_redacted_even_when_constructed_directly() {
        let error = Error::Http {
            status: 500,
            body: "provider-secret".into(),
        };
        assert!(!format!("{error:?}").contains("provider-secret"));
        assert!(!error.to_string().contains("provider-secret"));
    }
    #[test]
    fn request_debug_redacts_api_key() {
        let request = HttpRequest {
            method: "GET".into(),
            path: "/networks".into(),
            headers: vec![("X-API-Key".into(), "key".into())],
            body: vec![],
        };
        assert!(!format!("{request:?}").contains("key"));
    }
    #[test]
    fn pure_ops() {
        let x = s(&["a"]);
        assert_eq!(x.add(" b ").unwrap().backends, vec!["a", "b"]);
        assert_eq!(x.remove("a").backends, Vec::<String>::new())
    }

    #[test]
    fn client_url_policy_is_https_and_rejects_url_metadata() {
        let transport = MockTransport::new(vec![]);
        assert!(Client::new("http://provider.example", Secret::new("key"), transport).is_err());
        let transport = MockTransport::new(vec![]);
        assert!(
            Client::new(
                "https://provider.example/?tenant=one",
                Secret::new("key"),
                transport
            )
            .is_err()
        );
        let transport = MockTransport::new(vec![]);
        assert!(
            Client::new(
                "https://user:password@provider.example",
                Secret::new("key"),
                transport
            )
            .is_err()
        );
        let transport = MockTransport::new(vec![]);
        assert!(Client::localhost("http://127.0.0.1:8080", Secret::new("key"), transport).is_ok());
    }

    fn fixture_set() -> BackendSet {
        serde_json::from_str(include_str!(
            "../../../tests/contract/tcpshield/backend_set.json"
        ))
        .unwrap()
    }

    #[tokio::test]
    async fn patch_contract_sends_exact_path_payload_and_verifies() {
        let before = fixture_set();
        let desired = before.add("203.0.113.12:25565").unwrap();
        let mock = MockTransport::new(vec![
            HttpResponse {
                status: 200,
                headers: vec![],
                body: serde_json::to_vec(&before).unwrap(),
            },
            HttpResponse {
                status: 200,
                headers: vec![],
                body: vec![],
            },
            HttpResponse {
                status: 200,
                headers: vec![],
                body: serde_json::to_vec(&desired).unwrap(),
            },
        ]);
        let client = Client::new(
            "https://api.tcpshield.com",
            Secret::new("test-secret"),
            mock,
        )
        .unwrap();
        let plan = client.plan(before, desired.clone());
        assert_eq!(client.apply(7, 42, &plan).await.unwrap(), desired);
        let requests = client.transport.requests.lock().unwrap();
        assert_eq!(requests[0].path, "/networks/7/backendSets/42");
        assert_eq!(requests[1].method, "PATCH");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&requests[1].body).unwrap(),
            serde_json::json!({"name":"Production","backends":["203.0.113.10:25565","203.0.113.11:25565","203.0.113.12:25565"]})
        );
        assert_eq!(
            requests[1]
                .headers
                .iter()
                .find(|(name, _)| name == "X-API-Key")
                .unwrap()
                .1,
            "test-secret"
        );
    }

    #[tokio::test]
    async fn pre_apply_drift_is_rejected_without_patch() {
        let before = fixture_set();
        let drift = before.add("203.0.113.99:25565").unwrap();
        let mock = MockTransport::new(vec![HttpResponse {
            status: 200,
            headers: vec![],
            body: serde_json::to_vec(&drift).unwrap(),
        }]);
        let client = Client::new("https://api.tcpshield.com", Secret::new("key"), mock).unwrap();
        let plan = client.plan(before, drift.clone());
        assert!(matches!(
            client.apply(7, 42, &plan).await,
            Err(Error::ExternalDrift { .. })
        ));
        assert_eq!(client.transport.requests.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn observe_rejects_official_response_without_backends() {
        // The published BackendSetResponse schema omits `backends`. It is
        // unsafe to deserialize that omission as an empty set because the
        // hash would not represent the state being changed.
        let mock = MockTransport::new(vec![HttpResponse {
            status: 200,
            headers: vec![],
            body: serde_json::json!({"id": 42, "name": "Production"})
                .to_string()
                .into_bytes(),
        }]);
        let client = Client::new("https://api.tcpshield.com", Secret::new("key"), mock).unwrap();
        assert!(matches!(
            client.observe(7, 42).await,
            Err(Error::IncompleteResponse(_))
        ));
    }

    #[tokio::test]
    async fn list_rejects_any_entry_without_backends() {
        let mock = MockTransport::new(vec![HttpResponse {
            status: 200,
            headers: vec![],
            body: serde_json::json!([{"id": 42, "name": "Production"}])
                .to_string()
                .into_bytes(),
        }]);
        let client = Client::new("https://api.tcpshield.com", Secret::new("key"), mock).unwrap();
        assert!(matches!(
            client.list(7).await,
            Err(Error::IncompleteResponse(_))
        ));
    }

    #[tokio::test]
    async fn malformed_observed_backend_is_rejected() {
        let mock = MockTransport::new(vec![HttpResponse {
            status: 200,
            headers: vec![],
            body: serde_json::json!({
                "id": 42,
                "name": "Production",
                "backends": ["203.0.113.11:25565\n"]
            })
            .to_string()
            .into_bytes(),
        }]);
        let client = Client::new("https://api.tcpshield.com", Secret::new("key"), mock).unwrap();
        assert!(matches!(
            client.observe(7, 42).await,
            Err(Error::InvalidInput(_))
        ));
    }

    #[tokio::test]
    async fn ambiguous_patch_reobserves_and_rollback_conflict_is_typed() {
        let before = fixture_set();
        let desired = before.add("203.0.113.12:25565").unwrap();
        let failure = HttpResponse {
            status: 503,
            headers: vec![],
            body: b"unavailable".to_vec(),
        };
        let mock = MockTransport::new(vec![
            HttpResponse {
                status: 200,
                headers: vec![],
                body: serde_json::to_vec(&before).unwrap(),
            },
            failure,
            HttpResponse {
                status: 200,
                headers: vec![],
                body: serde_json::to_vec(&desired).unwrap(),
            },
        ]);
        let client = Client::new("https://api.tcpshield.com", Secret::new("key"), mock).unwrap();
        let plan = client.plan(before, desired);
        assert!(matches!(
            client.apply(7, 42, &plan).await,
            Err(Error::Ambiguous {
                observed: Some(_),
                ..
            })
        ));
        let current = fixture_set().add("203.0.113.99:25565").unwrap();
        let rollback_mock = MockTransport::new(vec![HttpResponse {
            status: 200,
            headers: vec![],
            body: serde_json::to_vec(&current).unwrap(),
        }]);
        let rollback_client = Client::new(
            "https://api.tcpshield.com",
            Secret::new("key"),
            rollback_mock,
        )
        .unwrap();
        assert!(matches!(
            rollback_client.rollback(7, 42, &plan).await,
            Err(Error::RollbackConflict { .. })
        ));
    }

    #[tokio::test]
    async fn error_redacts_api_key_and_drain_requires_evidence() {
        let mock = MockTransport::new(vec![HttpResponse {
            status: 500,
            headers: vec![],
            body: b"provider-secret leaked".to_vec(),
        }]);
        let client =
            Client::new("https://api.tcpshield.com", Secret::new("secret-key"), mock).unwrap();
        let error = client.observe(7, 42).await.unwrap_err();
        assert!(!error.to_string().contains("secret-key"));
        assert!(!error.to_string().contains("provider-secret"));
        struct Unknown;
        impl ConnectionObserver for Unknown {
            fn observe(
                &self,
            ) -> Pin<Box<dyn Future<Output = Result<ConnectionEvidence, Error>> + Send + '_>>
            {
                Box::pin(async {
                    Ok(ConnectionEvidence {
                        count: 0,
                        observed_at: None,
                        source: String::new(),
                    })
                })
            }
        }
        assert!(matches!(
            require_drained(&Unknown).await,
            Err(Error::DrainUnknown)
        ));
    }
}
