//! Application-owned ports consumed by the HTTP transport.
pub use crate::dto::OperationEvent;
use crate::{
    auth::VerifiedClaims,
    dto::{
        ArtifactCandidateDto, ArtifactDiscoverPayload, ChangeApprovalDto, ChangeBeginPayload,
        ChangePlanResultDto, ChangeSessionDto, FileClassification, FileDiffDto, FileEntryDto,
        FileReadDto, MutationRequest, OperationDto, ResourceDto, SftpEndpointDto, SftpScanDto,
        SftpScanPayload, StagedContentDto,
    },
    error::ApiError,
};
use async_trait::async_trait;
pub use kitsunebi_domain::{Permission, Role};
use std::collections::BTreeSet;

/// Distinguishes browser requests from non-browser service automation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ActorKind {
    Browser,
    Service,
}
/// Internal authorization result. Service scopes are resolved by the application.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authorization {
    pub role: Role,
    pub permissions: BTreeSet<Permission>,
    pub service_scopes: BTreeSet<String>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedActor {
    pub subject: String,
    pub email: Option<String>,
    pub common_name: Option<String>,
    pub kind: ActorKind,
    pub authorization: Authorization,
}
/// Result of object-level access resolution. The caller cannot supply the service id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessDecision {
    pub service_key: Option<String>,
}
/// Request metadata that must travel with every state-changing command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MutationContext {
    pub actor: VerifiedActor,
    pub idempotency_key: String,
    pub if_match: String,
    /// Parsed session version for plan/approve CAS. Other commands leave it
    /// unset and continue to use their plan hash token.
    pub session_version: Option<u64>,
    /// SHA-256 binding of the exact typed request payload. The persisted plan
    /// hash is carried by the plan/approval payload and `If-Match` instead.
    pub request_hash: String,
    pub expires_at: u64,
    pub request_id: String,
}
/// Typed request for staging bytes in an actor-owned change session.
///
/// The HTTP transport derives `request_hash` from the exact uploaded bytes;
/// callers cannot provide a provider-specific command or identifier here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StageContentRequest {
    pub session_id: String,
    pub bytes: Vec<u8>,
    pub classification: FileClassification,
    pub session_version: u64,
    pub idempotency_key: String,
    pub request_hash: String,
}

impl StageContentRequest {
    pub fn validate(&self) -> Result<(), ApiError> {
        if self.session_id.trim().is_empty()
            || self.idempotency_key.trim().is_empty()
            || self.session_version == 0
        {
            return Err(ApiError::InvalidRequest("staged content request"));
        }
        if !matches!(
            self.classification,
            FileClassification::Managed
                | FileClassification::MutableConfig
                | FileClassification::Artifact
                | FileClassification::Generated
        ) {
            return Err(ApiError::InvalidRequest("staged content classification"));
        }
        if self.request_hash.len() != 64
            || !self
                .request_hash
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(ApiError::InvalidRequest("staged content request hash"));
        }
        crate::validate_upload_size(self.bytes.len())?;
        Ok(())
    }
}
/// A verified identity mapper backed by the application's access-policy store.
#[async_trait]
pub trait IdentityMapper: Send + Sync {
    async fn map(&self, claims: &VerifiedClaims) -> Result<VerifiedActor, ApiError>;
}
/// Frames exchanged with an execution backend. No backend credential is representable here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConsoleFrame {
    Text(String),
    Binary(Vec<u8>),
}
/// Direction recorded by a console audit policy without retaining frame content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsoleDirection {
    ClientToBackend,
    BackendToClient,
}
/// Redacted console audit event. The digest permits correlation without storing secrets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsoleAuditEvent {
    pub direction: ConsoleDirection,
    pub size: usize,
    pub digest: String,
}
/// Authenticated console relay session.
#[async_trait]
pub trait ConsoleSession: Send {
    async fn receive(&mut self) -> Result<Option<ConsoleFrame>, ApiError>;
    async fn send(&mut self, frame: ConsoleFrame) -> Result<(), ApiError>;
    async fn record(&mut self, event: ConsoleAuditEvent) -> Result<(), ApiError>;
    async fn close(&mut self);
}
/// Authenticated, operation-specific progress stream.
#[async_trait]
pub trait OperationStreamPort: Send {
    async fn next(&mut self) -> Result<Option<OperationEvent>, ApiError>;
}
/// File API port. Implementations own path resolution; Unknown, State, and
/// Secret classifications are metadata-only and must never expose contents.
#[async_trait]
pub trait FilePort: Send + Sync {
    async fn browse(
        &self,
        actor: &VerifiedActor,
        unit_id: &str,
        path: &str,
    ) -> Result<Vec<FileEntryDto>, ApiError>;
    async fn read(
        &self,
        actor: &VerifiedActor,
        unit_id: &str,
        path: &str,
    ) -> Result<FileReadDto, ApiError>;
    async fn download(
        &self,
        actor: &VerifiedActor,
        unit_id: &str,
        path: &str,
    ) -> Result<FileReadDto, ApiError>;
    async fn diff(
        &self,
        actor: &VerifiedActor,
        unit_id: &str,
        path: &str,
    ) -> Result<FileDiffDto, ApiError>;
}
/// Application facade used by all resource and mutation routes.
#[async_trait]
pub trait ManagementApi: Send + Sync + 'static {
    async fn list(
        &self,
        resource: &str,
        actor: &VerifiedActor,
    ) -> Result<Vec<ResourceDto>, ApiError>;
    async fn get(
        &self,
        resource: &str,
        id: &str,
        actor: &VerifiedActor,
    ) -> Result<ResourceDto, ApiError>;
    async fn authorize(
        &self,
        actor: &VerifiedActor,
        resource: &str,
        id: Option<&str>,
        permission: Permission,
    ) -> Result<AccessDecision, ApiError>;
    async fn mutate(
        &self,
        resource: &str,
        id: Option<&str>,
        request: MutationRequest,
        context: MutationContext,
    ) -> Result<OperationDto, ApiError>;
    async fn plan_change(
        &self,
        actor: &VerifiedActor,
        resource: &str,
        id: &str,
        request: MutationRequest,
        context: MutationContext,
    ) -> Result<ChangePlanResultDto, ApiError>;
    async fn approve_change(
        &self,
        actor: &VerifiedActor,
        resource: &str,
        id: &str,
        request: MutationRequest,
        context: MutationContext,
    ) -> Result<ChangeApprovalDto, ApiError>;
    /// Store opaque bytes in the session-owned CAS and return only its digest
    /// and size. The HTTP route authenticates and binds the session before
    /// delegating here.
    async fn stage_content(
        &self,
        actor: &VerifiedActor,
        request: StageContentRequest,
    ) -> Result<StagedContentDto, ApiError>;
    async fn discover_artifacts(
        &self,
        actor: &VerifiedActor,
        payload: ArtifactDiscoverPayload,
    ) -> Result<Vec<ArtifactCandidateDto>, ApiError>;
    async fn list_sftp_endpoints(
        &self,
        actor: &VerifiedActor,
    ) -> Result<Vec<SftpEndpointDto>, ApiError>;
    async fn get_sftp_endpoint(
        &self,
        actor: &VerifiedActor,
        id: &str,
    ) -> Result<SftpEndpointDto, ApiError>;
    async fn scan_sftp(
        &self,
        actor: &VerifiedActor,
        endpoint_id: &str,
        payload: SftpScanPayload,
        context: MutationContext,
    ) -> Result<SftpScanDto, ApiError>;
    async fn begin_change_session(
        &self,
        actor: &VerifiedActor,
        payload: ChangeBeginPayload,
        idempotency_key: &str,
        request_id: &str,
    ) -> Result<ChangeSessionDto, ApiError>;
    async fn open_console(
        &self,
        actor: &VerifiedActor,
        unit_id: &str,
    ) -> Result<Box<dyn ConsoleSession>, ApiError>;
    async fn open_operation_stream(
        &self,
        actor: &VerifiedActor,
        operation_id: &str,
    ) -> Result<Box<dyn OperationStreamPort>, ApiError>;
    async fn health(&self) -> Result<serde_json::Value, ApiError>;
    /// Return the shallow readiness signal used by load balancers. Providers
    /// may be degraded while the controller database is still able to accept
    /// authenticated requests, so implementations should avoid deep checks.
    /// The default preserves the port contract for small test adapters until
    /// they provide a dedicated readiness probe.
    async fn ready(&self) -> Result<serde_json::Value, ApiError> {
        let checks = self.health().await?;
        Ok(serde_json::json!({"status": "ready", "checks": checks}))
    }
    /// Return detailed dependency health to an authenticated operator. This
    /// must never be used by the public liveness/readiness probes.
    async fn provider_health(&self, _actor: &VerifiedActor) -> Result<serde_json::Value, ApiError> {
        self.health().await
    }
    fn files(&self) -> &dyn FilePort;
}
