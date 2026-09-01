#![forbid(unsafe_code)]
#![recursion_limit = "512"]

//! HTTP boundary for the Kitsunebi management plane.
//!
//! This crate contains no GameAP client and no domain mutation logic. The controller
//! supplies implementations of the application ports declared in [`ports`].
pub mod auth;
pub mod dto;
pub mod error;
pub mod openapi;
pub mod ports;
pub mod routes;
pub mod security;
pub mod testing;

#[cfg(test)]
mod tests;

pub use auth::{
    AccessClaims, AccessConfig, Authenticator, JwksProvider, RemoteJwks, StaticJwks, VerifiedClaims,
};
pub use dto::{
    AccessPolicyUpdateStep, ArtifactActivateStep, ArtifactCandidateDto, ArtifactDiscoverPayload,
    ArtifactProvider, ArtifactProviderQuery, ArtifactRegisterStep, ArtifactStageStep,
    BackupCreateStep, BackupKind, BackupRestoreStep, BackupTarget, ChangeAcceptPayload,
    ChangeApplyPayload, ChangeApprovalDto, ChangeApprovePayload, ChangeBeginPayload,
    ChangePlanPayload, ChangePlanResultDto, ChangeRollbackPayload, ChangeSessionDto,
    ChangeVerifyPayload, ClusterRevisionCreateStep, EndpointRolloutStep, ExecutionDeleteStep,
    ExecutionLifecycleAction, ExecutionLifecycleStep, ExecutionProvisionStep, FileBatchStep,
    FileBatchStepOperation, FileClassification, FileDiffDto, FileEntryDto, FileMoveStep,
    FileQuarantineStep, FileReadDto, FileWriteStep, MutationAction, MutationCommand,
    MutationPayload, MutationRequest, OperationDto, PlanStepAction, PlanStepDto, PlanTarget,
    PolicyGrantPayload, PolicyPermission, PolicyRole, ProxyRolloutStep, ProxyState, ResourceDto,
    ResourceKind, RoutePolicyUpdateStep, ServiceArchiveStep, ServiceLifecycleTransitionStep,
    ServicePurgeStep, SessionDto, SftpChangeKind, SftpChangedPathDto, SftpEndpointDto, SftpScanDto,
    SftpScanPayload, SftpScanSource, StagedContentDto, WorldWriterCutoverStep,
};
pub use error::ApiError;
pub use openapi::openapi_document;
pub use ports::{
    AccessDecision, ActorKind, Authorization, ConsoleAuditEvent, ConsoleDirection, ConsoleFrame,
    ConsoleSession, FilePort, IdentityMapper, ManagementApi, MutationContext, OperationEvent,
    OperationStreamPort, Permission, Role, StageContentRequest, VerifiedActor,
};
pub use routes::{ApiState, RequestId, router};
pub use security::{
    CsrfTokenProvider, HmacCsrfValidator, LocalAuthConfig, RuntimeEnvironment, SecurityConfig,
    StaticCsrfValidator,
};
pub use security::{check_origin, validate_archive_entries, validate_content_type};

/// Versioned API prefix.
pub const API_PREFIX: &str = "/api/v1";
/// Maximum JSON request body accepted by the API.
pub const JSON_BODY_LIMIT: usize = 1_048_576;
/// Maximum file upload accepted by the API.
pub const UPLOAD_LIMIT: usize = 50 * 1024 * 1024;

/// Validate an upload length before buffering it.
pub fn validate_upload_size(size: usize) -> Result<(), ApiError> {
    if size > UPLOAD_LIMIT {
        Err(ApiError::PayloadTooLarge)
    } else {
        Ok(())
    }
}
/// Hash a redacted, canonical plan representation.
pub fn plan_hash(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}
/// Normalize and validate a GameAP-relative path.
pub fn validate_file_path(path: &str) -> Result<String, ApiError> {
    security::validate_relative_path(path)
}
