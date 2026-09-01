#![forbid(unsafe_code)]

//! GameAP v4.4.2 execution adapter.
//!
//! This crate is the anti-corruption boundary around GameAP.  The domain only sees the
//! operation types below; it never receives a GameAP PAT.  The generic transport is useful
//! for contract tests, while [`ReqwestTransport`] and [`GameApWebSocketTransport`] are the
//! production transports.

use std::net::IpAddr;
use std::{
    fmt,
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use futures_util::{SinkExt, Stream, StreamExt, stream};
use reqwest::{Method, header, redirect::Policy};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::Notify;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use url::Url;

pub const CRATE_NAME: &str = "kitsunebi-gameap";
pub const SUPPORTED_VERSION: &str = "4.4.2";
pub const OFFICIAL_SCHEMA_SHA256: &str =
    "e4225e17edba528a07cb808422af832bf89410fc8f88d2759b199ac92862363e";
pub const PROCESS_MANAGER_PLUGIN_ID: &str = "pmobserve2j7d";

/// A PAT or short-lived token.  It has deliberately no serde implementation and redacts in
/// every standard formatting mode.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);
impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }
    pub fn expose(&self) -> &str {
        &self.0
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
    pub max_upload_bytes: u64,
    pub max_download_bytes: u64,
}
impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            max_response_bytes: 8 * 1024 * 1024,
            max_upload_bytes: 512 * 1024 * 1024,
            max_download_bytes: 512 * 1024 * 1024,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub authorization: String,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}
impl fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("path", &redact_request_path(&self.path))
            .field("authorization", &"Bearer [REDACTED]")
            .field("content_type", &self.content_type)
            .field("body_bytes", &self.body.len())
            .finish()
    }
}
#[derive(Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
    pub request_id: Option<String>,
}
impl fmt::Debug for HttpResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("body_bytes", &self.body.len())
            .field("request_id", &self.request_id)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum TransportError {
    Timeout,
    Unavailable,
    BodyTooLarge,
    Other(String),
}
impl fmt::Debug for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => f.write_str("Timeout"),
            Self::Unavailable => f.write_str("Unavailable"),
            Self::BodyTooLarge => f.write_str("BodyTooLarge"),
            Self::Other(error) => f
                .debug_tuple("Other")
                .field(&redact_sensitive(error))
                .finish(),
        }
    }
}
pub trait HttpTransport: Send + Sync {
    fn send(
        &self,
        request: HttpRequest,
    ) -> Pin<Box<dyn Future<Output = Result<HttpResponse, TransportError>> + Send + '_>>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpErrorKind {
    Unauthorized,
    Forbidden,
    NotFound,
    Conflict,
    RateLimited,
    Server,
    BadRequest,
    Other,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GameApError {
    Transport(TransportError),
    Http {
        status: u16,
        kind: HttpErrorKind,
        body: String,
        request_id: Option<String>,
    },
    InvalidPath,
    TransferTooLarge,
    Unsupported(Capability),
    Decode(String),
    Cancelled,
}
impl fmt::Display for GameApError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Http { status, kind, .. } => write!(f, "GameAP HTTP {status} ({kind:?})"),
            Self::Transport(error) => write!(f, "GameAP transport error: {error:?}"),
            Self::InvalidPath => f.write_str("invalid relative GameAP file path"),
            Self::TransferTooLarge => f.write_str("GameAP transfer exceeds configured limit"),
            Self::Unsupported(capability) => {
                write!(f, "GameAP capability is unavailable: {capability:?}")
            }
            Self::Decode(error) => write!(f, "GameAP response decode failed: {error}"),
            Self::Cancelled => f.write_str("GameAP operation cancelled"),
        }
    }
}
impl std::error::Error for GameApError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    ExecutionCreate,
    PlacementMutation,
    ExecutionDelete,
    Lifecycle,
    StatusRead,
    NodeStatusRead,
    ResourceStatusRead,
    Console,
    FileList,
    FileRead,
    FileWrite,
    FileUpload,
    FileDownload,
    FileMove,
    FileDelete,
    FileMetadata,
    FileQuarantine,
    ShortLivedToken,
    ProcessManager,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityState {
    Supported,
    Unknown,
    Unsupported,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CapabilityDiagnostic {
    pub capability: Capability,
    pub state: CapabilityState,
    pub code: String,
    pub reason: String,
    pub endpoint: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Capabilities {
    /// `None` is intentional: the public v4 API has no explicit version operation.
    pub version: Option<String>,
    pub diagnostics: Vec<CapabilityDiagnostic>,
}
/// Evidence that the pinned GameAP lifecycle endpoints were exercised against
/// a disposable server and restored to its original state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleContractAttestation {
    NotRun,
    Verified,
}
impl Capabilities {
    pub fn conservative() -> Self {
        let unknown = [
            (Capability::ExecutionCreate, "creation_not_probed"),
            (Capability::PlacementMutation, "placement_not_public"),
            (Capability::ExecutionDelete, "deletion_not_probed"),
            (Capability::Lifecycle, "lifecycle_not_probed"),
            (Capability::ProcessManager, "process_manager_not_public"),
        ];
        Self {
            version: None,
            diagnostics: unknown
                .into_iter()
                .map(|(capability, code)| CapabilityDiagnostic {
                    capability,
                    state: CapabilityState::Unknown,
                    code: code.into(),
                    reason: if capability == Capability::ProcessManager {
                        "the public Node schema does not expose process_manager".into()
                    } else {
                        "the public API does not provide a safe non-mutating capability probe"
                            .into()
                    },
                    endpoint: None,
                })
                .collect(),
        }
    }
    pub fn state(&self, capability: Capability) -> CapabilityState {
        self.diagnostics
            .iter()
            .find(|diagnostic| diagnostic.capability == capability)
            .map_or_else(
                || match capability {
                    // A caller must opt in with a probe result or a trusted assertion before
                    // any operation that changes an execution can run.
                    Capability::ExecutionCreate
                    | Capability::PlacementMutation
                    | Capability::ExecutionDelete
                    | Capability::Lifecycle
                    | Capability::ProcessManager => CapabilityState::Unknown,
                    // Read-only operations are part of the stable public subset. Discovery can
                    // still downgrade them to Unknown when an endpoint probe fails.
                    _ => CapabilityState::Supported,
                },
                |diagnostic| diagnostic.state,
            )
    }
    pub fn allows_mutation(&self, capability: Capability) -> bool {
        self.state(capability) == CapabilityState::Supported
    }
    /// Apply the operator's deployment assertion to the conservative baseline.
    ///
    /// GameAP 4.4.2 does not expose a version endpoint.  Consequently an
    /// operator assertion is the only source for the deployment version, and
    /// lifecycle mutation additionally requires the pinned public schema
    /// digest and an explicitly enabled real-contract check.  A missing or
    /// out-of-range value leaves the capability unknown (fail closed).
    pub fn with_operator_lifecycle_attestation(
        assertion: TrustedDeploymentAssertion,
        schema_sha256: &str,
        lifecycle_attestation: LifecycleContractAttestation,
    ) -> Self {
        let mut capabilities = Self::conservative();
        let version_ok = assertion.api_version == SUPPORTED_VERSION;
        let schema_ok = schema_sha256.eq_ignore_ascii_case(OFFICIAL_SCHEMA_SHA256);
        if version_ok && schema_ok {
            capabilities.version = Some(assertion.api_version);
        }
        if assertion.allow_creation && version_ok && schema_ok {
            set_diagnostic(
                &mut capabilities,
                Capability::ExecutionCreate,
                CapabilityState::Supported,
                "trusted_deployment_assertion",
                "creation enabled by an operator-supplied version and schema assertion",
                Some("/api/servers"),
            );
        }
        let (lifecycle_state, lifecycle_code, lifecycle_reason) = if !version_ok {
            (
                CapabilityState::Unknown,
                "lifecycle_assertion_out_of_range",
                "lifecycle requires an exact supported GameAP version assertion",
            )
        } else if !schema_ok {
            (
                CapabilityState::Unknown,
                "lifecycle_schema_assertion_invalid",
                "lifecycle requires the pinned public GameAP schema digest",
            )
        } else if lifecycle_attestation != LifecycleContractAttestation::Verified {
            (
                CapabilityState::Unknown,
                "lifecycle_attestation_required",
                "lifecycle requires a successful real v4.4.2 disposable-server attestation",
            )
        } else {
            (
                CapabilityState::Supported,
                "lifecycle_attestation_ok",
                "lifecycle enabled by exact version, pinned schema, and restored real contract attestation",
            )
        };
        set_diagnostic(
            &mut capabilities,
            Capability::Lifecycle,
            lifecycle_state,
            lifecycle_code,
            lifecycle_reason,
            Some("/api/servers/{server}/{start|stop|restart}"),
        );
        if assertion.allow_placement
            && version_ok
            && schema_ok
            && lifecycle_attestation == LifecycleContractAttestation::Verified
        {
            set_diagnostic(
                &mut capabilities,
                Capability::PlacementMutation,
                CapabilityState::Supported,
                "placement_contract_test_ok",
                "placement enabled by an operator-supplied contract assertion",
                None,
            );
        }
        // The assertion can never manufacture the absent process_manager field.
        capabilities
    }
}

fn set_diagnostic(
    capabilities: &mut Capabilities,
    capability: Capability,
    state: CapabilityState,
    code: &str,
    reason: &str,
    endpoint: Option<&str>,
) {
    capabilities
        .diagnostics
        .retain(|diagnostic| diagnostic.capability != capability);
    capabilities.diagnostics.push(CapabilityDiagnostic {
        capability,
        state,
        code: code.into(),
        reason: reason.into(),
        endpoint: endpoint.map(str::to_owned),
    });
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedDeploymentAssertion {
    pub api_version: String,
    pub allow_creation: bool,
    pub allow_placement: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateExecutionRequest {
    pub name: String,
    pub ds_id: serde_json::Value,
    pub game_id: String,
    pub game_mod_id: serde_json::Value,
    pub server_ip: String,
    pub server_port: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query_port: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rcon_port: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rcon: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dir: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub su_user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub install: Option<serde_json::Value>,
}
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct CreateExecutionResponse {
    pub message: String,
    pub result: CreateExecutionResult,
}
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct CreateExecutionResult {
    #[serde(rename = "taskId")]
    pub task_id: u64,
    #[serde(rename = "serverId")]
    pub server_id: u64,
}
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct TaskResponse {
    #[serde(alias = "taskId")]
    pub task_id: Option<u64>,
}
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct ServerStatusResponse {
    #[serde(rename = "processActive")]
    pub process_active: bool,
}
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct NodeDaemonStatusResponse {
    pub id: u64,
    pub name: String,
    pub connection_type: String,
    pub version: Option<NodeVersion>,
}

/// The closed process-manager set returned by the optional WASI observation
/// plugin. `Unknown` is an observation result, never a mutation capability.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProcessManager {
    Systemd,
    Docker,
    Podman,
    Unknown,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ProcessManagerObservationResponse {
    node_id: u64,
    process_manager: ProcessManager,
    evidence_hash: String,
    version: String,
    timestamp: u64,
}

/// Typed evidence returned by the optional process-manager plugin. The plugin
/// id is bound to the authenticated route used for the observation rather than
/// accepted from the response body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProcessManagerObservation {
    pub plugin_id: String,
    pub node_id: u64,
    pub process_manager: ProcessManager,
    pub evidence_hash: String,
    pub version: String,
    pub timestamp: u64,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct NodeObservationRequest {
    node_id: u64,
}
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct NodeVersion {
    pub version: String,
    pub compile_date: String,
}
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct FileContentResponse {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub content: Option<String>,
    #[serde(default)]
    pub items: Vec<FileEntry>,
}
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct FileEntry {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub modified: Option<String>,
}
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct SuccessResponse {
    pub status: Option<String>,
    pub message: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileMetadata {
    pub path: String,
    pub size: u64,
    pub modified: Option<String>,
    pub is_directory: bool,
    pub hash: Option<String>,
}

/// A point-in-time observation of a provider file path.
///
/// A missing path is represented by `digest == None` and
/// `is_directory == false`.  Directory observations intentionally do not
/// have a digest because the public GameAP file API does not provide a stable
/// directory content hash.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct FileObservation {
    pub path: String,
    pub size: Option<u64>,
    pub is_directory: bool,
    pub digest: Option<String>,
}

/// The provider evidence returned after a compare-and-set file move.
///
/// `source_before` and `destination_before` are the observations used for the
/// CAS.  `source` and `destination` are observations taken after the move.  A
/// successful move has an absent source and a destination whose digest equals
/// `moved_digest`.  Keeping both paths and both observations in the result
/// makes the evidence suitable for durable operation records and for a later
/// reverse move.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct FileMoveObservation {
    pub source_before: FileObservation,
    pub destination_before: FileObservation,
    pub source: FileObservation,
    pub destination: FileObservation,
    pub moved_digest: String,
}
#[derive(Clone, PartialEq, Eq)]
pub struct ShortLivedToken {
    secret: Secret,
    pub expires_in: u64,
}
impl ShortLivedToken {
    pub fn secret(&self) -> &Secret {
        &self.secret
    }
}
impl fmt::Debug for ShortLivedToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ShortLivedToken")
            .field("secret", &self.secret)
            .field("expires_in", &self.expires_in)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lifecycle {
    Start,
    Stop,
    Restart,
}
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct ConsoleMessage {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub payload: serde_json::Value,
    pub ts: Option<i64>,
}
pub trait ConsoleSocket: Send {
    fn send_command(
        &mut self,
        command: String,
    ) -> Pin<Box<dyn Future<Output = Result<(), GameApError>> + Send + '_>>;
    fn next(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<ConsoleMessage>, GameApError>> + Send + '_>>;
}
pub trait WebSocketTransport: Send + Sync {
    fn connect(&self, url: String, token: Secret) -> WebSocketFuture<'_>;
}
pub type WebSocketFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Box<dyn ConsoleSocket>, TransportError>> + Send + 'a>>;

/// A reqwest/rustls HTTP implementation. Redirects are rejected so a PAT cannot follow to an
/// unexpected origin; all response bodies are bounded before being returned.
pub struct ReqwestTransport {
    base_url: Url,
    client: reqwest::Client,
    config: ClientConfig,
}
impl fmt::Debug for ReqwestTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReqwestTransport")
            .field("base_url", &self.base_url)
            .field("config", &self.config)
            .finish()
    }
}
impl ReqwestTransport {
    pub fn new(base_url: impl AsRef<str>, config: ClientConfig) -> Result<Self, GameApError> {
        if config.timeout.is_zero()
            || config.max_response_bytes == 0
            || config.max_upload_bytes == 0
            || config.max_download_bytes == 0
        {
            return Err(GameApError::Decode(
                "HTTP limits and timeout must be non-zero".into(),
            ));
        }
        let base_url = parse_http_url(base_url.as_ref())?;
        let client = reqwest::Client::builder()
            .timeout(config.timeout)
            .redirect(Policy::none())
            .use_rustls_tls()
            .build()
            .map_err(|error| GameApError::Decode(error.to_string()))?;
        Ok(Self {
            base_url,
            client,
            config,
        })
    }
    pub fn base_url(&self) -> &Url {
        &self.base_url
    }
    fn url(&self, path: &str) -> Result<Url, TransportError> {
        self.base_url
            .join(path.trim_start_matches('/'))
            .map_err(|error| TransportError::Other(format!("invalid request URL: {error}")))
    }
    async fn execute(
        &self,
        request: HttpRequest,
        body: reqwest::Body,
    ) -> Result<HttpResponse, TransportError> {
        let method = Method::from_bytes(request.method.as_bytes())
            .map_err(|error| TransportError::Other(error.to_string()))?;
        let url = self.url(&request.path)?;
        let mut builder = self.client.request(method, url).body(body);
        if !request.authorization.is_empty() {
            builder = builder.header(header::AUTHORIZATION, request.authorization);
        }
        if let Some(content_type) = request.content_type {
            builder = builder.header(header::CONTENT_TYPE, content_type);
        }
        let response = builder.send().await.map_err(map_reqwest_error)?;
        let status = response.status().as_u16();
        let request_id = response
            .headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let body = collect_bounded(response.bytes_stream(), self.config.max_response_bytes).await?;
        Ok(HttpResponse {
            status,
            body,
            request_id,
        })
    }
    pub async fn send_stream<S>(
        &self,
        mut request: HttpRequest,
        body: S,
    ) -> Result<HttpResponse, TransportError>
    where
        S: Stream<Item = Result<Bytes, io::Error>> + Send + Unpin + 'static,
    {
        request.body.clear();
        let body = Box::pin(guarded_upload(body, self.config.max_upload_bytes));
        self.execute(request, reqwest::Body::wrap_stream(body))
            .await
    }
    pub async fn download_stream(
        &self,
        mut request: HttpRequest,
    ) -> Result<ByteStream, GameApError> {
        request.body.clear();
        let method = Method::from_bytes(request.method.as_bytes())
            .map_err(|error| GameApError::Decode(error.to_string()))?;
        let url = self.url(&request.path).map_err(map_transport_error)?;
        let mut builder = self.client.request(method, url);
        if !request.authorization.is_empty() {
            builder = builder.header(header::AUTHORIZATION, request.authorization);
        }
        let response = builder
            .send()
            .await
            .map_err(|error| GameApError::Transport(map_reqwest_error(error)))?;
        if !(200..300).contains(&response.status().as_u16()) {
            let status = response.status().as_u16();
            let request_id = response
                .headers()
                .get("x-request-id")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            let body = collect_bounded(response.bytes_stream(), self.config.max_response_bytes)
                .await
                .map_err(map_transport_error)?;
            return Err(http_error(status, body, request_id));
        }
        let max = self.config.max_download_bytes;
        let stream = response.bytes_stream();
        Ok(Box::pin(stream::unfold(
            Some((stream, 0_u64)),
            move |state| async move {
                let (mut stream, total) = state?;
                match stream.next().await {
                    None => None,
                    Some(Ok(bytes)) => {
                        let next = total.saturating_add(bytes.len() as u64);
                        if next > max {
                            Some((Err(GameApError::TransferTooLarge), None))
                        } else {
                            Some((Ok(bytes.to_vec()), Some((stream, next))))
                        }
                    }
                    Some(Err(error)) => {
                        Some((Err(GameApError::Transport(map_reqwest_error(error))), None))
                    }
                }
            },
        )))
    }
    pub async fn download_to<W: AsyncWrite + Unpin>(
        &self,
        request: HttpRequest,
        writer: &mut W,
    ) -> Result<String, GameApError> {
        let mut stream = self.download_stream(request).await?;
        let mut hasher = Sha256::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            hasher.update(&chunk);
            writer.write_all(&chunk).await.map_err(|error| {
                GameApError::Transport(TransportError::Other(error.to_string()))
            })?;
        }
        Ok(hex_digest(hasher.finalize()))
    }
}
impl HttpTransport for ReqwestTransport {
    fn send(
        &self,
        request: HttpRequest,
    ) -> Pin<Box<dyn Future<Output = Result<HttpResponse, TransportError>> + Send + '_>> {
        if request.body.len() as u64 > self.config.max_upload_bytes {
            return Box::pin(async { Err(TransportError::BodyTooLarge) });
        }
        Box::pin(self.execute(request.clone(), reqwest::Body::from(request.body.clone())))
    }
}

pub type ByteStream = Pin<Box<dyn Stream<Item = Result<Vec<u8>, GameApError>> + Send>>;

fn guarded_upload<S>(
    stream: S,
    max: u64,
) -> impl Stream<Item = Result<Bytes, io::Error>> + Send + 'static
where
    S: Stream<Item = Result<Bytes, io::Error>> + Send + Unpin + 'static,
{
    stream::unfold(Some((stream, 0_u64)), move |state| async move {
        let (mut stream, total) = state?;
        match stream.next().await {
            None => None,
            Some(Err(error)) => Some((Err(error), None)),
            Some(Ok(bytes)) => {
                let next = total.saturating_add(bytes.len() as u64);
                if next > max {
                    Some((Err(io::Error::other("upload exceeds limit")), None))
                } else {
                    Some((Ok(bytes), Some((stream, next))))
                }
            }
        }
    })
}
fn limit_download_stream(stream: ByteStream, max: u64) -> ByteStream {
    Box::pin(stream::unfold(
        Some((stream, 0_u64)),
        move |state| async move {
            let (mut stream, total) = state?;
            match stream.next().await {
                None => None,
                Some(Ok(chunk)) => {
                    let next = total.saturating_add(chunk.len() as u64);
                    if next > max {
                        Some((Err(GameApError::TransferTooLarge), None))
                    } else {
                        Some((Ok(chunk), Some((stream, next))))
                    }
                }
                Some(Err(error)) => Some((Err(error), None)),
            }
        },
    ))
}
async fn collect_bounded<S>(mut stream: S, max: u64) -> Result<Vec<u8>, TransportError>
where
    S: Stream<Item = Result<Bytes, reqwest::Error>> + Unpin,
{
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(map_reqwest_error)?;
        if body.len() as u64 + chunk.len() as u64 > max {
            return Err(TransportError::BodyTooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}
fn map_reqwest_error(error: reqwest::Error) -> TransportError {
    if error.is_timeout() {
        TransportError::Timeout
    } else if error.is_connect() || error.is_request() {
        TransportError::Unavailable
    } else {
        TransportError::Other(redact_sensitive(&error.to_string()))
    }
}

/// Concrete tokio-tungstenite WebSocket transport.  The only credential accepted here is a
/// freshly minted `glst_` token in the query string required by GameAP's browser-compatible API.
#[derive(Debug, Clone, Copy)]
pub struct GameApWebSocketTransport {
    pub timeout: Duration,
}
impl Default for GameApWebSocketTransport {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
        }
    }
}
impl WebSocketTransport for GameApWebSocketTransport {
    fn connect(&self, mut url: String, token: Secret) -> WebSocketFuture<'_> {
        Box::pin(async move {
            if !token.expose().starts_with("glst_") {
                return Err(TransportError::Other(
                    "WebSocket requires a glst_ token".into(),
                ));
            }
            let mut parsed =
                Url::parse(&url).map_err(|error| TransportError::Other(error.to_string()))?;
            let local = parsed
                .host_str()
                .is_some_and(|host| host.eq_ignore_ascii_case("localhost"))
                || parsed
                    .host_str()
                    .and_then(|host| host.parse::<IpAddr>().ok())
                    .is_some_and(|address| address.is_loopback());
            if !matches!(parsed.scheme(), "wss" | "ws")
                || (parsed.scheme() == "ws" && !local)
                || parsed.host_str().is_none()
                || !parsed.username().is_empty()
                || parsed.password().is_some()
                || parsed.fragment().is_some()
                || parsed
                    .query_pairs()
                    .any(|(name, _)| name.eq_ignore_ascii_case("token"))
            {
                return Err(TransportError::Other(
                    "WebSocket URL must be secure and must not contain credentials".into(),
                ));
            }
            parsed
                .query_pairs_mut()
                .append_pair("token", token.expose());
            url = parsed.to_string();
            let (stream, _) = tokio::time::timeout(self.timeout, connect_async(url))
                .await
                .map_err(|_| TransportError::Timeout)?
                .map_err(|_error| TransportError::Unavailable)?;
            Ok(Box::new(TungsteniteConsoleSocket { stream }) as Box<dyn ConsoleSocket>)
        })
    }
}
type TungsteniteStream =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;
struct TungsteniteConsoleSocket {
    stream: TungsteniteStream,
}
impl ConsoleSocket for TungsteniteConsoleSocket {
    fn send_command(
        &mut self,
        command: String,
    ) -> Pin<Box<dyn Future<Output = Result<(), GameApError>> + Send + '_>> {
        Box::pin(async move {
            let payload =
                serde_json::json!({ "type": "console.command", "payload": { "command": command } });
            self.stream
                .send(Message::Text(payload.to_string().into()))
                .await
                .map_err(|error| GameApError::Transport(TransportError::Other(error.to_string())))
        })
    }
    fn next(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<ConsoleMessage>, GameApError>> + Send + '_>>
    {
        Box::pin(async move {
            loop {
                match self.stream.next().await {
                    None | Some(Ok(Message::Close(_))) => return Ok(None),
                    Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => continue,
                    Some(Ok(Message::Text(text))) => {
                        return serde_json::from_str(&text)
                            .map(Some)
                            .map_err(|error| GameApError::Decode(error.to_string()));
                    }
                    Some(Ok(Message::Binary(bytes))) => {
                        return serde_json::from_slice(&bytes)
                            .map(Some)
                            .map_err(|error| GameApError::Decode(error.to_string()));
                    }
                    Some(Err(error)) => {
                        return Err(GameApError::Transport(TransportError::Other(
                            error.to_string(),
                        )));
                    }
                    Some(Ok(Message::Frame(_))) => continue,
                }
            }
        })
    }
}

pub struct Client<T> {
    base_url: Url,
    pat: Secret,
    config: ClientConfig,
    transport: T,
    capabilities: Capabilities,
}
impl<T: HttpTransport> Client<T> {
    pub fn new(base_url: impl AsRef<str>, pat: Secret, transport: T) -> Result<Self, GameApError> {
        Ok(Self {
            base_url: parse_http_url(base_url.as_ref())?,
            pat,
            config: Default::default(),
            transport,
            capabilities: Capabilities::conservative(),
        })
    }
    pub fn with_config(mut self, config: ClientConfig) -> Self {
        self.config = config;
        self
    }
    pub fn with_capabilities(mut self, capabilities: Capabilities) -> Self {
        self.capabilities = capabilities;
        self
    }
    pub fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }
    pub fn base_url(&self) -> &Url {
        &self.base_url
    }
    fn request(
        &self,
        method: &str,
        path: String,
        body: Vec<u8>,
        content_type: Option<&str>,
        auth: &Secret,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, GameApError>> + Send + '_>> {
        self.request_with_limit(
            method,
            path,
            body,
            content_type,
            auth,
            self.config.max_response_bytes,
        )
    }
    fn request_with_limit(
        &self,
        method: &str,
        path: String,
        body: Vec<u8>,
        content_type: Option<&str>,
        auth: &Secret,
        max_response_bytes: u64,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, GameApError>> + Send + '_>> {
        let request = HttpRequest {
            method: method.into(),
            path,
            authorization: if auth.expose().is_empty() {
                String::new()
            } else {
                format!("Bearer {}", auth.expose())
            },
            content_type: content_type.map(str::to_owned),
            body,
        };
        Box::pin(async move {
            let response = self
                .transport
                .send(request)
                .await
                .map_err(map_transport_error)?;
            if response.body.len() as u64 > max_response_bytes {
                return Err(GameApError::TransferTooLarge);
            }
            if !(200..300).contains(&response.status) {
                return Err(http_error(
                    response.status,
                    response.body,
                    response.request_id,
                ));
            }
            Ok(response.body)
        })
    }
    async fn json_request<R: DeserializeOwned>(
        &self,
        method: &str,
        path: String,
        body: impl Serialize,
        auth: &Secret,
    ) -> Result<R, GameApError> {
        let body =
            serde_json::to_vec(&body).map_err(|error| GameApError::Decode(error.to_string()))?;
        let bytes = self
            .request(method, path, body, Some("application/json"), auth)
            .await?;
        serde_json::from_slice(&bytes).map_err(|error| GameApError::Decode(error.to_string()))
    }
    async fn empty_request(&self, method: &str, path: String) -> Result<Vec<u8>, GameApError> {
        self.request(method, path, Vec::new(), None, &self.pat)
            .await
    }
    pub async fn create_execution(
        &self,
        input: &CreateExecutionRequest,
    ) -> Result<CreateExecutionResponse, GameApError> {
        if !self
            .capabilities
            .allows_mutation(Capability::ExecutionCreate)
        {
            return Err(GameApError::Unsupported(Capability::ExecutionCreate));
        }
        self.json_request("POST", "/api/servers".into(), input, &self.pat)
            .await
    }
    pub async fn delete_execution(&self, server: &str) -> Result<(), GameApError> {
        if !self
            .capabilities
            .allows_mutation(Capability::ExecutionDelete)
        {
            return Err(GameApError::Unsupported(Capability::ExecutionDelete));
        }
        self.empty_request("DELETE", format!("/api/servers/{}", id_segment(server)?))
            .await
            .map(|_| ())
    }
    pub async fn lifecycle(
        &self,
        server: &str,
        action: Lifecycle,
    ) -> Result<TaskResponse, GameApError> {
        if !self.capabilities.allows_mutation(Capability::Lifecycle) {
            return Err(GameApError::Unsupported(Capability::Lifecycle));
        }
        let action = match action {
            Lifecycle::Start => "start",
            Lifecycle::Stop => "stop",
            Lifecycle::Restart => "restart",
        };
        let bytes = self
            .request(
                "POST",
                format!("/api/servers/{}/{action}", id_segment(server)?),
                Vec::new(),
                None,
                &self.pat,
            )
            .await?;
        serde_json::from_slice(&bytes).map_err(|error| GameApError::Decode(error.to_string()))
    }
    pub async fn status(&self, server: &str) -> Result<ServerStatusResponse, GameApError> {
        self.empty_json_request(
            "GET",
            format!("/api/servers/{}/status", id_segment(server)?),
        )
        .await
    }
    pub async fn node_status(&self, node: &str) -> Result<NodeDaemonStatusResponse, GameApError> {
        self.empty_json_request("GET", format!("/api/nodes/{}/daemon", id_segment(node)?))
            .await
    }
    /// Observe the daemon process manager through the authenticated optional
    /// WASI plugin. The route identity supplies the plugin id; no plugin or
    /// node data is trusted from an untyped response.
    pub async fn observe_process_manager(
        &self,
        plugin_id: &str,
        node_id: u64,
    ) -> Result<ProcessManagerObservation, GameApError> {
        if !is_secure_or_localhost(&self.base_url) {
            return Err(GameApError::Decode(
                "plugin observation requires HTTPS outside localhost".into(),
            ));
        }
        let plugin_id = plugin_id_segment(plugin_id)?;
        if node_id == 0 {
            return Err(GameApError::InvalidPath);
        }
        let request = NodeObservationRequest { node_id };
        let response: ProcessManagerObservationResponse = self
            .json_request(
                "POST",
                format!("/api/plugins/{plugin_id}/observe"),
                request,
                &self.pat,
            )
            .await?;
        if response.node_id != node_id
            || response.version != "1"
            || response.timestamp == 0
            || !is_sha256_digest(&response.evidence_hash)
        {
            return Err(GameApError::Decode(
                "invalid process-manager observation response".into(),
            ));
        }
        Ok(ProcessManagerObservation {
            plugin_id,
            node_id: response.node_id,
            process_manager: response.process_manager,
            evidence_hash: response.evidence_hash,
            version: response.version,
            timestamp: response.timestamp,
        })
    }
    /// Resource metrics are a WebSocket operation in the public API, not an HTTP `/metrics` route.
    pub async fn resource_status<W: WebSocketTransport>(
        &self,
        ws: &W,
        server: &str,
    ) -> Result<Box<dyn ConsoleSocket>, GameApError> {
        self.connect_metrics(ws, server).await
    }
    pub async fn short_lived_token(&self) -> Result<ShortLivedToken, GameApError> {
        let response: ShortLivedTokenResponse = self
            .empty_json_request("POST", "/api/auth/short-lived-token".into())
            .await?;
        if !response.token.starts_with("glst_")
            || response.expires_in == 0
            || response.expires_in > 10
        {
            return Err(GameApError::Decode(
                "invalid GameAP short-lived token response".into(),
            ));
        }
        Ok(ShortLivedToken {
            secret: Secret::new(response.token),
            expires_in: response.expires_in,
        })
    }
    pub async fn list_files(
        &self,
        server: &str,
        path: &str,
    ) -> Result<FileContentResponse, GameApError> {
        self.file_json("GET", server, "/content", path, ()).await
    }
    pub async fn read_file(&self, server: &str, path: &str) -> Result<String, GameApError> {
        let result = self.list_files(server, path).await?;
        if result.kind != "file" {
            return Err(GameApError::Decode("GameAP path is not a file".into()));
        }
        result
            .content
            .ok_or_else(|| GameApError::Decode("GameAP file response omitted content".into()))
    }
    pub async fn write_file(
        &self,
        server: &str,
        path: &str,
        content: &str,
    ) -> Result<SuccessResponse, GameApError> {
        validate_relative_path(path)?;
        self.file_json(
            "POST",
            server,
            "/update-file",
            "",
            UpdateFileRequest { path, content },
        )
        .await
    }
    pub async fn upload_file(
        &self,
        server: &str,
        path: &str,
        bytes: &[u8],
    ) -> Result<SuccessResponse, GameApError> {
        validate_relative_path(path)?;
        if bytes.len() as u64 > self.config.max_upload_bytes {
            return Err(GameApError::TransferTooLarge);
        }
        let body = multipart_body(path, bytes);
        if body.len() as u64 > self.config.max_upload_bytes {
            return Err(GameApError::TransferTooLarge);
        }
        self.request_json_response(
            "POST",
            format!("/api/file-manager/{}/upload", id_segment(server)?),
            body,
            Some("multipart/form-data; boundary=kitsunebi-gameap"),
        )
        .await
    }
    pub async fn download_file(&self, server: &str, path: &str) -> Result<Vec<u8>, GameApError> {
        let server = id_segment(server)?;
        let encoded = encoded_path(path)?;
        let token = self.short_lived_token().await?;
        let bytes = self
            .request_with_limit(
                "GET",
                format!(
                    "/api/file-manager/{}/download?path={encoded}&token={}",
                    server,
                    url::form_urlencoded::byte_serialize(token.secret().expose().as_bytes())
                        .collect::<String>()
                ),
                Vec::new(),
                None,
                &Secret::new(""),
                self.config.max_download_bytes,
            )
            .await?;
        if bytes.len() as u64 > self.config.max_download_bytes {
            return Err(GameApError::TransferTooLarge);
        }
        Ok(bytes)
    }
    pub async fn move_file(
        &self,
        server: &str,
        from: &str,
        to: &str,
        kind: &str,
    ) -> Result<SuccessResponse, GameApError> {
        validate_relative_path(from)?;
        validate_relative_path(to)?;
        let provider_kind = provider_rename_kind(kind)?;
        self.file_json(
            "POST",
            server,
            "/rename",
            "",
            RenameRequest {
                disk: "server",
                old_name: from,
                new_name: to,
                kind: provider_kind,
            },
        )
        .await
    }
    pub async fn delete_file(
        &self,
        server: &str,
        path: &str,
    ) -> Result<SuccessResponse, GameApError> {
        validate_relative_path(path)?;
        self.file_json(
            "POST",
            server,
            "/delete",
            "",
            DeleteRequest { items: vec![path] },
        )
        .await
    }
    /// Delete a regular file only when its current SHA-256 digest still
    /// matches the caller's durable inverse evidence. The delete endpoint is
    /// public GameAP file-manager API; no provider-internal operation is used.
    pub async fn delete_file_checked(
        &self,
        server: &str,
        path: &str,
        expected_digest: &str,
    ) -> Result<FileObservation, GameApError> {
        validate_relative_path(path)?;
        validate_digest(expected_digest)?;
        let before = self.observe_file(server, path).await?;
        if before.is_directory || !digest_matches(before.digest.as_deref(), expected_digest) {
            return Err(compare_and_set_error(path));
        }
        self.delete_file(server, path).await?;
        let after = self.observe_file_optional(server, path).await?;
        if after.is_directory || after.digest.is_some() {
            return Err(GameApError::Decode(
                "GameAP file delete postcondition did not match absence".into(),
            ));
        }
        Ok(after)
    }
    /// Move a file into the controller-owned deterministic quarantine path.
    ///
    /// GameAP exposes a generic file-manager rename operation, not a
    /// quarantine operation.  The adapter therefore uses that public
    /// operation with the provider's ordinary `file` kind and verifies the
    /// result with a digest CAS.  The word `quarantine` is an application
    /// operation label only; it is never sent as a GameAP type.
    pub async fn quarantine_file(
        &self,
        server: &str,
        path: &str,
    ) -> Result<FileMoveObservation, GameApError> {
        self.quarantine_file_checked(server, path).await
    }

    /// Observe a file or directory through the public GameAP file-manager
    /// operations.  This method returns the provider error for a missing
    /// path; the checked move methods use the same observation shape with a
    /// missing path represented by `digest == None`.
    pub async fn observe_file(
        &self,
        server: &str,
        path: &str,
    ) -> Result<FileObservation, GameApError> {
        validate_relative_path(path)?;
        let metadata = self.file_metadata(server, path).await?;
        Ok(file_observation(path, metadata))
    }

    /// Move a file only when the source digest and destination state still
    /// match the caller's observation, then re-observe both paths.
    ///
    /// A destination digest of `None` means that the destination must be
    /// absent.  This makes the default safe for quarantine and rollback and
    /// prevents an unnoticed overwrite.  The expected source digest is
    /// mandatory: a path-only rename is not a safe mutation primitive.
    pub async fn move_file_checked(
        &self,
        server: &str,
        from: &str,
        to: &str,
        expected_source_digest: &str,
        expected_destination_digest: Option<&str>,
    ) -> Result<FileMoveObservation, GameApError> {
        validate_relative_path(from)?;
        validate_relative_path(to)?;
        if from == to {
            return Err(GameApError::InvalidPath);
        }
        validate_digest(expected_source_digest)?;
        if let Some(expected) = expected_destination_digest {
            validate_digest(expected)?;
        }

        let source_before = self.observe_file(server, from).await?;
        if source_before.is_directory
            || !digest_matches(source_before.digest.as_deref(), expected_source_digest)
        {
            return Err(compare_and_set_error(from));
        }

        let destination_before = self.observe_file_optional(server, to).await?;
        match expected_destination_digest {
            Some(expected)
                if !destination_before.is_directory
                    && digest_matches(destination_before.digest.as_deref(), expected) => {}
            Some(_) => return Err(compare_and_set_error(to)),
            None if destination_before.digest.is_none() && !destination_before.is_directory => {}
            None => return Err(compare_and_set_error(to)),
        }

        // `quarantine` and `quarantine-restore` are accepted by this adapter
        // only as internal operation labels from the controller.  The public
        // GameAP request below always carries the official `file` kind.
        self.move_file(server, from, to, "file").await?;

        let source_after = self.observe_file_optional(server, from).await?;
        let destination_after = self.observe_file_optional(server, to).await?;
        if source_after.digest.is_some()
            || source_after.is_directory
            || destination_after.is_directory
            || !digest_matches(destination_after.digest.as_deref(), expected_source_digest)
        {
            return Err(GameApError::Decode(
                "GameAP file move postcondition did not match the expected digest".into(),
            ));
        }

        Ok(FileMoveObservation {
            source_before,
            destination_before,
            source: source_after,
            destination: destination_after,
            moved_digest: expected_source_digest.to_ascii_lowercase(),
        })
    }

    /// Reverse a previously verified file move using the same digest CAS.
    /// `from` is the current (quarantine) path and `to` is the original path.
    pub async fn reverse_move_file_checked(
        &self,
        server: &str,
        from: &str,
        to: &str,
        expected_digest: &str,
    ) -> Result<FileMoveObservation, GameApError> {
        self.move_file_checked(server, from, to, expected_digest, None)
            .await
    }

    /// Return the deterministic controller-owned quarantine path for a
    /// relative GameAP file path.
    pub fn quarantine_path(path: &str) -> Result<String, GameApError> {
        validate_relative_path(path)?;
        Ok(format!(
            ".kitsunebi-quarantine/{}",
            sha256_hex(path.as_bytes())
        ))
    }

    /// Quarantine a file with a verified source digest and return provider
    /// observations proving the move.
    pub async fn quarantine_file_checked(
        &self,
        server: &str,
        path: &str,
    ) -> Result<FileMoveObservation, GameApError> {
        let source = self.observe_file(server, path).await?;
        let digest = source.digest.as_deref().ok_or_else(|| {
            GameApError::Decode("GameAP quarantine requires a regular file".into())
        })?;
        let quarantine = Self::quarantine_path(path)?;
        self.move_file_checked(server, path, &quarantine, digest, None)
            .await
    }

    /// Restore a quarantined file to its original path with a digest CAS.
    pub async fn restore_quarantined_file_checked(
        &self,
        server: &str,
        path: &str,
        expected_digest: &str,
    ) -> Result<FileMoveObservation, GameApError> {
        let quarantine = Self::quarantine_path(path)?;
        self.reverse_move_file_checked(server, &quarantine, path, expected_digest)
            .await
    }
    pub async fn file_metadata(
        &self,
        server: &str,
        path: &str,
    ) -> Result<FileMetadata, GameApError> {
        let content = self.list_files(server, path).await?;
        if content.kind == "directory" {
            return Ok(FileMetadata {
                path: path.into(),
                size: 0,
                modified: None,
                is_directory: true,
                hash: None,
            });
        }
        let bytes = self.download_file(server, path).await?;
        Ok(FileMetadata {
            path: path.into(),
            size: bytes.len() as u64,
            modified: None,
            is_directory: false,
            hash: Some(sha256_hex(&bytes)),
        })
    }
    async fn observe_file_optional(
        &self,
        server: &str,
        path: &str,
    ) -> Result<FileObservation, GameApError> {
        match self.observe_file(server, path).await {
            Ok(observation) => Ok(observation),
            Err(GameApError::Http {
                kind: HttpErrorKind::NotFound,
                ..
            }) => Ok(FileObservation {
                path: path.into(),
                size: None,
                is_directory: false,
                digest: None,
            }),
            Err(error) => Err(error),
        }
    }
    pub async fn connect_console<W: WebSocketTransport>(
        &self,
        ws: &W,
        server: &str,
    ) -> Result<Box<dyn ConsoleSocket>, GameApError> {
        id_segment(server)?;
        let token = self.short_lived_token().await?;
        self.connect_ws(ws, server, "console", token).await
    }
    pub async fn connect_metrics<W: WebSocketTransport>(
        &self,
        ws: &W,
        server: &str,
    ) -> Result<Box<dyn ConsoleSocket>, GameApError> {
        id_segment(server)?;
        let token = self.short_lived_token().await?;
        self.connect_ws(ws, server, "metrics", token).await
    }
    async fn connect_ws<W: WebSocketTransport>(
        &self,
        ws: &W,
        server: &str,
        channel: &str,
        token: ShortLivedToken,
    ) -> Result<Box<dyn ConsoleSocket>, GameApError> {
        let path = format!("/api/ws/servers/{}/{channel}", id_segment(server)?);
        let url = ws_url(&self.base_url, &path)?;
        ws.connect(url, token.secret)
            .await
            .map_err(GameApError::Transport)
    }
    async fn file_json<R: DeserializeOwned, B: Serialize>(
        &self,
        method: &str,
        server: &str,
        suffix: &str,
        query_path: &str,
        body: B,
    ) -> Result<R, GameApError> {
        let path = format!(
            "/api/file-manager/{}/{}",
            id_segment(server)?,
            suffix.trim_start_matches('/')
        );
        let path = if query_path.is_empty() {
            path
        } else {
            format!("{path}?path={}", encoded_path(query_path)?)
        };
        if method == "GET" {
            self.empty_json_request(method, path).await
        } else {
            self.json_request(method, path, body, &self.pat).await
        }
    }
    async fn empty_json_request<R: DeserializeOwned>(
        &self,
        method: &str,
        path: String,
    ) -> Result<R, GameApError> {
        let bytes = self
            .request(method, path, Vec::new(), None, &self.pat)
            .await?;
        serde_json::from_slice(&bytes).map_err(|error| GameApError::Decode(error.to_string()))
    }
    async fn request_json_response<R: DeserializeOwned, B: AsRef<[u8]>>(
        &self,
        method: &str,
        path: String,
        body: B,
        content_type: Option<&str>,
    ) -> Result<R, GameApError> {
        let bytes = self
            .request(
                method,
                path,
                body.as_ref().to_vec(),
                content_type,
                &self.pat,
            )
            .await?;
        serde_json::from_slice(&bytes).map_err(|error| GameApError::Decode(error.to_string()))
    }
    pub async fn discover_capabilities(
        &self,
        server: &str,
        node: &str,
    ) -> Result<Capabilities, GameApError> {
        let server_id = id_segment(server)?;
        let node_id = id_segment(node)?;
        let node_number = node_id
            .parse::<u64>()
            .map_err(|_| GameApError::InvalidPath)?;
        let mut capabilities = Capabilities::conservative();
        let status = self
            .request(
                "GET",
                format!("/api/servers/{server_id}/status"),
                Vec::new(),
                None,
                &self.pat,
            )
            .await;
        add_probe(
            &mut capabilities,
            Capability::StatusRead,
            "/api/servers/{server}/status",
            status.is_ok(),
        );
        let daemon = self
            .request(
                "GET",
                format!("/api/nodes/{node_id}/daemon"),
                Vec::new(),
                None,
                &self.pat,
            )
            .await;
        add_probe(
            &mut capabilities,
            Capability::NodeStatusRead,
            "/api/nodes/{id}/daemon",
            daemon.is_ok(),
        );
        let files = self
            .request(
                "GET",
                format!("/api/file-manager/{server_id}/initialize"),
                Vec::new(),
                None,
                &self.pat,
            )
            .await;
        add_probe(
            &mut capabilities,
            Capability::FileList,
            "/api/file-manager/{server}/content",
            files.is_ok(),
        );
        let plugin = self
            .observe_process_manager(PROCESS_MANAGER_PLUGIN_ID, node_number)
            .await;
        let plugin_supported = plugin
            .as_ref()
            .is_ok_and(|observation| observation.process_manager != ProcessManager::Unknown);
        let plugin_unknown = plugin
            .as_ref()
            .is_ok_and(|observation| observation.process_manager == ProcessManager::Unknown);
        set_diagnostic(
            &mut capabilities,
            Capability::ProcessManager,
            if plugin_supported {
                CapabilityState::Supported
            } else {
                CapabilityState::Unknown
            },
            if plugin_supported {
                "process_manager_plugin_ok"
            } else if plugin_unknown {
                "process_manager_unknown"
            } else {
                "process_manager_plugin_unavailable"
            },
            if plugin_supported {
                "optional authenticated process-manager plugin observation succeeded"
            } else if plugin_unknown {
                "plugin returned an unknown process manager; mutation remains disabled"
            } else {
                "optional process-manager plugin observation failed; fail closed"
            },
            Some("/api/plugins/{plugin_id}/observe"),
        );
        Ok(capabilities)
    }
}
impl Client<ReqwestTransport> {
    /// Stream an upload through reqwest without buffering the file in memory.
    pub async fn upload_file_stream<S>(
        &self,
        server: &str,
        path: &str,
        chunks: S,
    ) -> Result<SuccessResponse, GameApError>
    where
        S: Stream<Item = Result<Bytes, io::Error>> + Send + Unpin + 'static,
    {
        validate_relative_path(path)?;
        let server = id_segment(server)?;
        let request = HttpRequest {
            method: "POST".into(),
            path: format!("/api/file-manager/{server}/upload"),
            authorization: format!("Bearer {}", self.pat.expose()),
            content_type: Some("multipart/form-data; boundary=kitsunebi-gameap".into()),
            body: Vec::new(),
        };
        let prefix = multipart_prefix();
        let suffix = multipart_suffix(path);
        let body = stream::iter(vec![Ok(Bytes::from(prefix))])
            .chain(chunks)
            .chain(stream::iter(vec![Ok(Bytes::from(suffix))]));
        let body = Box::pin(guarded_upload(body, self.config.max_upload_bytes));
        let response = self
            .transport
            .send_stream(request, body)
            .await
            .map_err(map_transport_error)?;
        if !(200..300).contains(&response.status) {
            return Err(http_error(
                response.status,
                response.body,
                response.request_id,
            ));
        }
        serde_json::from_slice(&response.body)
            .map_err(|error| GameApError::Decode(error.to_string()))
    }
    /// Stream a download directly from the official file-manager download operation.
    pub async fn download_file_stream(
        &self,
        server: &str,
        path: &str,
    ) -> Result<ByteStream, GameApError> {
        let server = id_segment(server)?;
        let encoded = encoded_path(path)?;
        let token = self.short_lived_token().await?;
        let request = HttpRequest {
            method: "GET".into(),
            path: format!(
                "/api/file-manager/{}/download?path={}&token={}",
                server,
                encoded,
                url::form_urlencoded::byte_serialize(token.secret().expose().as_bytes())
                    .collect::<String>()
            ),
            authorization: String::new(),
            content_type: None,
            body: Vec::new(),
        };
        let stream = self.transport.download_stream(request).await?;
        Ok(limit_download_stream(
            stream,
            self.config.max_download_bytes,
        ))
    }
    pub async fn download_file_to<W: AsyncWrite + Unpin>(
        &self,
        server: &str,
        path: &str,
        writer: &mut W,
    ) -> Result<String, GameApError> {
        let server = id_segment(server)?;
        let encoded = encoded_path(path)?;
        let token = self.short_lived_token().await?;
        let request = HttpRequest {
            method: "GET".into(),
            path: format!(
                "/api/file-manager/{}/download?path={}&token={}",
                server,
                encoded,
                url::form_urlencoded::byte_serialize(token.secret().expose().as_bytes())
                    .collect::<String>()
            ),
            authorization: String::new(),
            content_type: None,
            body: Vec::new(),
        };
        let mut stream = self.transport.download_stream(request).await?;
        let mut total = 0_u64;
        let mut hasher = Sha256::new();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            total = total.saturating_add(chunk.len() as u64);
            if total > self.config.max_download_bytes {
                return Err(GameApError::TransferTooLarge);
            }
            hasher.update(&chunk);
            writer.write_all(&chunk).await.map_err(|error| {
                GameApError::Transport(TransportError::Other(error.to_string()))
            })?;
        }
        Ok(hex_digest(hasher.finalize()))
    }
}

#[derive(Debug, Serialize)]
struct UpdateFileRequest<'a> {
    path: &'a str,
    content: &'a str,
}
#[derive(Debug, Serialize)]
struct RenameRequest<'a> {
    disk: &'a str,
    #[serde(rename = "oldName")]
    old_name: &'a str,
    #[serde(rename = "newName")]
    new_name: &'a str,
    #[serde(rename = "type")]
    kind: &'a str,
}
fn provider_rename_kind(kind: &str) -> Result<&'static str, GameApError> {
    match kind {
        // The controller uses these labels to describe a reversible move in
        // its operation log.  GameAP's public rename endpoint accepts only
        // the ordinary file kind, so never forward either label to the
        // provider.
        "file" | "quarantine" | "quarantine-restore" => Ok("file"),
        "dir" => Ok("dir"),
        _ => Err(GameApError::Decode(
            "GameAP rename type must be file or dir".into(),
        )),
    }
}
#[derive(Debug, Serialize)]
struct DeleteRequest<'a> {
    items: Vec<&'a str>,
}
#[derive(Debug, Deserialize)]
struct ShortLivedTokenResponse {
    token: String,
    expires_in: u64,
}

pub trait ShortLivedTokenProvider: Send + Sync {
    fn issue(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<ShortLivedToken, GameApError>> + Send + '_>>;
}
impl<T: HttpTransport> ShortLivedTokenProvider for Client<T> {
    fn issue(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<ShortLivedToken, GameApError>> + Send + '_>> {
        Box::pin(self.short_lived_token())
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetricsReconnectPolicy {
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
    pub max_attempts: usize,
}
impl Default for MetricsReconnectPolicy {
    fn default() -> Self {
        Self {
            initial_backoff: Duration::from_millis(100),
            max_backoff: Duration::from_secs(5),
            max_attempts: 5,
        }
    }
}
struct CancellationState {
    cancelled: AtomicBool,
    notify: Notify,
}
#[derive(Clone)]
pub struct Cancellation(Arc<CancellationState>);
impl Default for Cancellation {
    fn default() -> Self {
        Self(Arc::new(CancellationState {
            cancelled: AtomicBool::new(false),
            notify: Notify::new(),
        }))
    }
}
impl Cancellation {
    pub fn cancel(&self) {
        self.0.cancelled.store(true, Ordering::Release);
        self.0.notify.notify_waiters();
    }
    pub fn is_cancelled(&self) -> bool {
        self.0.cancelled.load(Ordering::Acquire)
    }
}
pub async fn reconnect_metrics<W, P>(
    ws: &W,
    base_url: &Url,
    server: &str,
    provider: &P,
    policy: MetricsReconnectPolicy,
    cancellation: &Cancellation,
) -> Result<Box<dyn ConsoleSocket>, GameApError>
where
    W: WebSocketTransport,
    P: ShortLivedTokenProvider,
{
    let mut delay = policy.initial_backoff;
    let mut attempt = 0;
    loop {
        if cancellation.is_cancelled() {
            return Err(GameApError::Cancelled);
        }
        let token = provider.issue().await?;
        let path = format!("/api/ws/servers/{}/metrics", id_segment(server)?);
        match ws.connect(ws_url(base_url, &path)?, token.secret).await {
            Ok(socket) => return Ok(socket),
            Err(error) => {
                attempt += 1;
                if attempt >= policy.max_attempts {
                    return Err(GameApError::Transport(error));
                }
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {}
                    _ = cancellation.0.notify.notified() => return Err(GameApError::Cancelled),
                }
                delay = (delay.saturating_mul(2)).min(policy.max_backoff);
            }
        }
    }
}

fn parse_http_url(value: &str) -> Result<Url, GameApError> {
    let mut url =
        Url::parse(value.trim()).map_err(|error| GameApError::Decode(error.to_string()))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(GameApError::Decode(
            "base URL must be an http(s) URL without userinfo, query, or fragment".into(),
        ));
    }
    // `Url::join` treats a base path without a trailing slash as a file.  Keep the
    // deployment prefix as a directory so `https://panel.example/gameap/` routes to
    // `https://panel.example/gameap/api/...` in both HTTP and WebSocket clients.
    let mut path = url.path().to_owned();
    if !path.ends_with('/') {
        path.push('/');
        url.set_path(&path);
    }
    Ok(url)
}
fn is_secure_or_localhost(url: &Url) -> bool {
    if url.scheme() == "https" {
        return true;
    }
    let Some(host) = url.host_str() else {
        return false;
    };
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}
fn plugin_id_segment(value: &str) -> Result<String, GameApError> {
    let value = safe_segment(value)?;
    if value.len() > 128 || value.trim() != value || !value.is_ascii() {
        return Err(GameApError::InvalidPath);
    }
    Ok(value)
}
fn ws_url(base: &Url, path: &str) -> Result<String, GameApError> {
    let mut url = base
        .join(path.trim_start_matches('/'))
        .map_err(|error| GameApError::Decode(error.to_string()))?;
    let scheme = match url.scheme() {
        "https" => "wss",
        "http" => "ws",
        _ => return Err(GameApError::Decode("invalid WebSocket base URL".into())),
    };
    url.set_scheme(scheme)
        .map_err(|_| GameApError::Decode("could not set WebSocket URL scheme".into()))?;
    Ok(url.to_string())
}
fn id_segment(value: &str) -> Result<String, GameApError> {
    let value = safe_segment(value)?;
    if value.parse::<u64>().is_err() {
        return Err(GameApError::InvalidPath);
    }
    Ok(value)
}
pub fn safe_segment(value: &str) -> Result<String, GameApError> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || value.contains('/')
        || value.contains('\\')
        || value.contains('\0')
        || value.bytes().any(|byte| byte < 0x20)
    {
        Err(GameApError::InvalidPath)
    } else {
        Ok(value.into())
    }
}
pub fn validate_relative_path(value: &str) -> Result<(), GameApError> {
    if value.is_empty()
        || value.starts_with('/')
        || value.starts_with('\\')
        || value.contains('\\')
        || value.contains('\0')
        || value.contains('%')
        || value.bytes().any(|byte| byte < 0x20 || byte == 0x7f)
        || value.split('/').any(|segment| {
            segment.is_empty() || segment == "." || segment == ".." || segment.contains(':')
        })
    {
        Err(GameApError::InvalidPath)
    } else {
        Ok(())
    }
}
fn encoded_path(value: &str) -> Result<String, GameApError> {
    validate_relative_path(value)?;
    Ok(url::form_urlencoded::byte_serialize(value.as_bytes()).collect())
}
fn multipart_body(path: &str, bytes: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&multipart_prefix());
    body.extend_from_slice(bytes);
    body.extend_from_slice(&multipart_suffix(path));
    body
}
fn multipart_prefix() -> Vec<u8> {
    b"--kitsunebi-gameap\r\nContent-Disposition: form-data; name=\"file\"; filename=\"upload.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n".to_vec()
}
fn multipart_suffix(path: &str) -> Vec<u8> {
    format!("\r\n--kitsunebi-gameap\r\nContent-Disposition: form-data; name=\"path\"\r\n\r\n{path}\r\n--kitsunebi-gameap--\r\n").into_bytes()
}
fn map_transport_error(error: TransportError) -> GameApError {
    match error {
        TransportError::BodyTooLarge => GameApError::TransferTooLarge,
        other => GameApError::Transport(other),
    }
}
fn http_error(status: u16, body: Vec<u8>, request_id: Option<String>) -> GameApError {
    let kind = match status {
        400 => HttpErrorKind::BadRequest,
        401 => HttpErrorKind::Unauthorized,
        403 => HttpErrorKind::Forbidden,
        404 => HttpErrorKind::NotFound,
        409 => HttpErrorKind::Conflict,
        429 => HttpErrorKind::RateLimited,
        500..=599 => HttpErrorKind::Server,
        _ => HttpErrorKind::Other,
    };
    GameApError::Http {
        status,
        kind,
        body: redact_sensitive(&String::from_utf8_lossy(&body)),
        request_id,
    }
}
fn redact_sensitive(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(index) = rest.find("glst_") {
        output.push_str(&rest[..index]);
        output.push_str("[REDACTED-TOKEN]");
        let token_end = rest[index..]
            .char_indices()
            .find(|(_, character)| {
                !character.is_ascii_alphanumeric()
                    && *character != '_'
                    && *character != '-'
                    && *character != '.'
            })
            .map_or(rest.len(), |(offset, _)| index + offset);
        rest = &rest[token_end..];
    }
    output.push_str(rest);
    output
}
fn redact_request_path(path: &str) -> String {
    let Some((prefix, query)) = path.split_once('?') else {
        return redact_sensitive(path);
    };

    let mut output = String::with_capacity(path.len());
    output.push_str(prefix);
    output.push('?');
    for (index, pair) in query.split('&').enumerate() {
        if index > 0 {
            output.push('&');
        }
        let Some((name, _value)) = pair.split_once('=') else {
            output.push_str(&redact_sensitive(pair));
            continue;
        };
        if matches!(
            name.to_ascii_lowercase().as_str(),
            "token" | "authorization"
        ) {
            output.push_str(name);
            output.push_str("=[REDACTED]");
        } else {
            output.push_str(&redact_sensitive(pair));
        }
    }
    output
}
fn add_probe(
    capabilities: &mut Capabilities,
    capability: Capability,
    endpoint: &str,
    supported: bool,
) {
    capabilities
        .diagnostics
        .retain(|diagnostic| diagnostic.capability != capability);
    capabilities.diagnostics.push(CapabilityDiagnostic {
        capability,
        state: if supported {
            CapabilityState::Supported
        } else {
            CapabilityState::Unknown
        },
        code: if supported {
            "endpoint_probe_ok"
        } else {
            "endpoint_probe_failed"
        }
        .into(),
        reason: if supported {
            "public endpoint probe succeeded"
        } else {
            "public endpoint probe did not succeed; fail closed"
        }
        .into(),
        endpoint: Some(endpoint.into()),
    });
}
fn is_sha256_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
fn validate_digest(value: &str) -> Result<(), GameApError> {
    if is_sha256_digest(value) {
        Ok(())
    } else {
        Err(GameApError::Decode(
            "expected file digest must be a SHA-256 hexadecimal value".into(),
        ))
    }
}
fn digest_matches(observed: Option<&str>, expected: &str) -> bool {
    observed.is_some_and(|value| value.eq_ignore_ascii_case(expected))
}
fn compare_and_set_error(path: &str) -> GameApError {
    GameApError::Decode(format!(
        "GameAP file compare-and-set failed for path {path}"
    ))
}
fn file_observation(path: &str, metadata: FileMetadata) -> FileObservation {
    FileObservation {
        path: path.into(),
        size: Some(metadata.size),
        is_directory: metadata.is_directory,
        digest: metadata.hash,
    }
}
pub fn sha256_hex(input: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hex_digest(hasher.finalize())
}
fn hex_digest(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn secret_is_redacted() {
        assert!(!format!("{:?}", Secret::new("pat_secret")).contains("pat_secret"));
    }
    #[test]
    fn request_debug_redacts_credentials_in_path_and_header() {
        let request = HttpRequest {
            method: "GET".into(),
            path: "/download?path=mods/a.jar&token=glst_short_lived_secret".into(),
            authorization: "Bearer pat_secret".into(),
            content_type: None,
            body: Vec::new(),
        };
        let debug = format!("{request:?}");
        assert!(!debug.contains("glst_short_lived_secret"));
        assert!(!debug.contains("pat_secret"));
        assert!(debug.contains("token=[REDACTED]"));
    }
    #[test]
    fn paths_reject_traversal_and_encoding() {
        for path in [
            "../x",
            "a/../../x",
            "a/%2e%2e/x",
            "/etc/passwd",
            "a\\b",
            "a\0b",
        ] {
            assert!(validate_relative_path(path).is_err(), "{path:?}");
        }
    }
    #[test]
    fn digest_is_sha256() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
    #[test]
    fn public_capabilities_fail_closed() {
        assert_eq!(
            Capabilities::conservative().state(Capability::ProcessManager),
            CapabilityState::Unknown
        );
        assert!(!Capabilities::conservative().allows_mutation(Capability::ExecutionCreate));
        assert!(
            !Capabilities {
                version: Some(SUPPORTED_VERSION.into()),
                diagnostics: Vec::new(),
            }
            .allows_mutation(Capability::Lifecycle)
        );
    }
    #[test]
    fn lifecycle_requires_exact_version_schema_and_real_contract_test() {
        let assertion = TrustedDeploymentAssertion {
            api_version: SUPPORTED_VERSION.into(),
            allow_creation: false,
            allow_placement: false,
        };
        let missing_contract = Capabilities::with_operator_lifecycle_attestation(
            assertion.clone(),
            OFFICIAL_SCHEMA_SHA256,
            LifecycleContractAttestation::NotRun,
        );
        assert_eq!(
            missing_contract.state(Capability::Lifecycle),
            CapabilityState::Unknown
        );
        assert_eq!(
            missing_contract
                .diagnostics
                .iter()
                .find(|diagnostic| diagnostic.capability == Capability::Lifecycle)
                .map(|diagnostic| diagnostic.code.as_str()),
            Some("lifecycle_attestation_required")
        );

        let wrong_schema = Capabilities::with_operator_lifecycle_attestation(
            assertion.clone(),
            "bad",
            LifecycleContractAttestation::Verified,
        );
        assert_eq!(
            wrong_schema.state(Capability::Lifecycle),
            CapabilityState::Unknown
        );
        let wrong_version = Capabilities::with_operator_lifecycle_attestation(
            TrustedDeploymentAssertion {
                api_version: "4.4.1".into(),
                ..assertion.clone()
            },
            OFFICIAL_SCHEMA_SHA256,
            LifecycleContractAttestation::Verified,
        );
        assert_eq!(
            wrong_version.state(Capability::Lifecycle),
            CapabilityState::Unknown
        );

        let enabled = Capabilities::with_operator_lifecycle_attestation(
            assertion,
            OFFICIAL_SCHEMA_SHA256,
            LifecycleContractAttestation::Verified,
        );
        assert_eq!(
            enabled.state(Capability::Lifecycle),
            CapabilityState::Supported
        );
        assert_eq!(enabled.version.as_deref(), Some(SUPPORTED_VERSION));
        let enum_enabled = Capabilities::with_operator_lifecycle_attestation(
            TrustedDeploymentAssertion {
                api_version: SUPPORTED_VERSION.into(),
                allow_creation: false,
                allow_placement: false,
            },
            OFFICIAL_SCHEMA_SHA256,
            LifecycleContractAttestation::Verified,
        );
        assert_eq!(
            enum_enabled
                .diagnostics
                .iter()
                .find(|diagnostic| diagnostic.capability == Capability::Lifecycle)
                .map(|diagnostic| diagnostic.code.as_str()),
            Some("lifecycle_attestation_ok")
        );
    }
    #[test]
    fn base_url_preserves_deployment_prefix() {
        let url = parse_http_url("https://panel.example/gameap").expect("base URL");
        assert_eq!(url.as_str(), "https://panel.example/gameap/");
        assert!(parse_http_url("https://panel.example/gameap?x=1").is_err());
    }
    #[test]
    fn multipart_has_official_fields() {
        let body = multipart_body("mods/a.jar", b"x");
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains("name=\"file\""));
        assert!(text.contains("name=\"path\""));
    }
    #[test]
    fn error_body_redacts_entire_short_lived_token() {
        let error = http_error(401, b"token=glst_secret_value".to_vec(), None);
        let GameApError::Http { body, .. } = error else {
            panic!("not an HTTP error")
        };
        assert!(!body.contains("glst_secret_value"));
        assert!(!body.contains("secret_value"));
    }

    #[tokio::test]
    async fn websocket_transport_rejects_remote_insecure_urls() {
        let result = GameApWebSocketTransport::default()
            .connect(
                "ws://panel.example.test/api/ws".into(),
                Secret::new("glst_token"),
            )
            .await;
        assert!(matches!(result, Err(TransportError::Other(_))));
    }
}
