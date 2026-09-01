#![forbid(unsafe_code)]

//! Kitsunebi's composition root.
//!
//! The controller owns wiring only.  Domain transitions, durable plans and
//! operation leases are delegated to `kitsunebi-application`; external calls
//! are made by the concrete bridges in this module.

use async_trait::async_trait;
use kitsunebi_api::dto::{
    ArtifactCandidateDto, ArtifactDiscoverPayload, ArtifactProviderQuery, ChangeApprovalDto,
    ChangeBeginPayload, ChangePlanResultDto, ChangeSessionDto, FileDiffDto, FileEntryDto,
    FileReadDto, PlanTarget as ApiPlanTarget, SftpChangedPathDto, SftpEndpointDto, SftpScanDto,
    SftpScanPayload,
};
use kitsunebi_api::{
    AccessConfig, AccessDecision, ApiError, Authenticator, ConsoleAuditEvent, ConsoleDirection,
    ConsoleFrame, ConsoleSession, FilePort, IdentityMapper, ManagementApi, MutationAction,
    MutationCommand, MutationContext, MutationPayload, MutationRequest, OperationDto,
    OperationEvent, OperationStreamPort, Permission as ApiPermission, ResourceDto, Role as ApiRole,
    SecurityConfig, StageContentRequest, VerifiedActor,
};
use kitsunebi_application as application;
use kitsunebi_application::{
    ApplicationError, ApplicationService, ArtifactCandidate,
    ArtifactProvider as AppArtifactProvider, ArtifactStore as AppArtifactStore, AuditSink,
    Authorizer, BackupComponent, BackupProvider, BackupRestoreInvocation, ChangeRequest,
    ConnectionEvidence, ConnectionObserver, DnsResolver, DomainRepository, DurableStepPort,
    ExecutionBackend, ExecutionStatus, FileChange, FileEntry, FileRestoreSnapshot, HealthVerifier,
    OperationRequest, OperationStep, OperationStore, ProxyEdge, ProxyEdgeBinding,
    ProxyEdgeObservation, ProxyEdgeResolver, RollbackStepPort, SftpScanRequest, StepApplyResult,
    StepEvidence, StepExecutionEvidence, StepObservation, WorldStorage,
};
use kitsunebi_artifacts::{
    ArtifactMetadata, ArtifactProvider as ArtifactProviderPort, ArtifactStore as CasStore,
    DirectUrl, GitHubRelease, Hangar, Modrinth, PaperFill,
    ReqwestTransport as ArtifactHttpTransport, StoredArtifact,
    TransportConfig as ArtifactTransportConfig,
};
use kitsunebi_backup::BackupHttpProvider;
use kitsunebi_domain::{
    AccessPolicy, ActorId, Artifact, BindingId, ChangeSessionId, ChangeSessionState, ClusterId,
    FileBatchOperation, FileClassification, GameAPBinding, Operation, OperationState,
    Permission as DomainPermission, PlanStep, ServiceId, SftpChangeKind as DomainSftpChangeKind,
    SftpChangedPath as DomainSftpChangedPath, SftpScanSource as DomainSftpScanSource,
    StagedContentOwnership, StagedContentRef,
};
use kitsunebi_gameap::{
    Capabilities, Client as GameApClient, ClientConfig as GameApClientConfig, ConsoleMessage,
    ConsoleSocket, CreateExecutionRequest, GameApError, GameApWebSocketTransport, Lifecycle,
    LifecycleContractAttestation, ReqwestTransport as GameApHttpTransport, Secret as GameApSecret,
    TrustedDeploymentAssertion,
};
use kitsunebi_monitoring::MonitoringHttpObserver;
use kitsunebi_storage::{MySqlStorage, ResourceKind};
use kitsunebi_tcpshield::{
    BackendSet, Client as TcpShieldClient, ClientConfig as TcpShieldClientConfig,
    ReqwestTransport as TcpShieldHttpTransport, Secret as TcpShieldSecret,
    TransportConfig as TcpShieldTransportConfig,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fmt,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::sleep;
use uuid::Uuid;

#[cfg(test)]
use kitsunebi_domain::GameAPBindingTarget;

const DEFAULT_BODY_LIMIT: usize = 1_048_576;
const DEFAULT_UPLOAD_LIMIT: usize = 50 * 1024 * 1024;
const DEFAULT_GAMEAP_RESPONSE_LIMIT: u64 = 64 * 1024 * 1024;

/// Process configuration.  Secret values are intentionally not exposed by a
/// `Debug` implementation or by any startup log.
#[derive(Clone)]
pub struct Config {
    pub listen_addr: String,
    pub database_url: String,
    pub gameap_base_url: String,
    pub gameap_pat: String,
    pub gameap_allow_creation: bool,
    pub tcpshield_base_url: Option<String>,
    pub tcpshield_api_key: Option<String>,
    pub tcpshield_network_id: Option<u64>,
    pub artifact_root: PathBuf,
    pub web_static_root: PathBuf,
    pub access: AccessConfig,
    pub allowed_origins: BTreeSet<String>,
    pub csrf_token: Option<String>,
    pub csrf_secret: Option<String>,
    pub mode: RuntimeMode,
    pub local_auth: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RuntimeMode {
    Local,
    Production,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("listen_addr", &self.listen_addr)
            .field("database_url", &"[REDACTED]")
            .field("gameap_base_url", &redacted_endpoint(&self.gameap_base_url))
            .field("gameap_pat", &"[REDACTED]")
            .field(
                "tcpshield_base_url",
                &self.tcpshield_base_url.as_deref().map(redacted_endpoint),
            )
            .field("tcpshield_api_key", &"[REDACTED]")
            .field("tcpshield_network_id", &self.tcpshield_network_id)
            .field("artifact_root", &self.artifact_root)
            .field("web_static_root", &self.web_static_root)
            .field("access", &"configured")
            .field("allowed_origins", &self.allowed_origins)
            .field("csrf_token", &"[REDACTED]")
            .field("csrf_secret", &"[REDACTED]")
            .field("mode", &self.mode)
            .field("local_auth", &self.local_auth)
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigError {
    Missing(&'static str),
    Invalid(&'static str),
    Security,
}
impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(name) => write!(f, "required configuration is missing: {name}"),
            Self::Invalid(name) => write!(f, "configuration is invalid: {name}"),
            Self::Security => f.write_str("security configuration is invalid"),
        }
    }
}
impl std::error::Error for ConfigError {}

fn redacted_endpoint(value: &str) -> String {
    let Some((scheme, rest)) = value.split_once("://") else {
        return "[REDACTED]".into();
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let suffix = rest[authority_end..]
        .split(['?', '#'])
        .next()
        .unwrap_or_default();
    format!("{scheme}://{host}{suffix}")
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        let get = |name: &'static str| env::var(name).map_err(|_| ConfigError::Missing(name));
        let mode = match env::var("KITSUNEBI_MODE")
            .unwrap_or_else(|_| "production".into())
            .as_str()
        {
            "local" => RuntimeMode::Local,
            "production" => RuntimeMode::Production,
            _ => return Err(ConfigError::Invalid("KITSUNEBI_MODE")),
        };
        let bool_env = |name: &'static str, default: bool| -> Result<bool, ConfigError> {
            match env::var(name) {
                Ok(value) => match value.as_str() {
                    "1" | "true" | "yes" => Ok(true),
                    "0" | "false" | "no" => Ok(false),
                    _ => Err(ConfigError::Invalid(name)),
                },
                Err(_) => Ok(default),
            }
        };
        let team_domain = env::var("CLOUDFLARE_ACCESS_ISSUER").unwrap_or_default();
        let audience = env::var("CLOUDFLARE_ACCESS_AUDIENCE").unwrap_or_default();
        let jwks_url = env::var("CLOUDFLARE_ACCESS_JWKS_URL").unwrap_or_default();
        let access = AccessConfig {
            issuer: team_domain,
            audience,
            jwks_url,
            clock_skew: Duration::from_secs(60),
            cache_ttl: Duration::from_secs(3600),
            request_timeout: Duration::from_secs(5),
            max_jwks_bytes: 256 * 1024,
        };
        let origins = get("KITSUNEBI_ALLOWED_ORIGINS")?
            .split(',')
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .collect();
        let local_auth = bool_env("KITSUNEBI_LOCAL_AUTH", false)?;
        let config = Self {
            listen_addr: get("KITSUNEBI_LISTEN_ADDR")?,
            database_url: get("DATABASE_URL")?,
            gameap_base_url: get("GAMEAP_BASE_URL")?,
            gameap_pat: get("GAMEAP_PAT")?,
            gameap_allow_creation: bool_env("GAMEAP_ALLOW_CREATION", false)?,
            tcpshield_base_url: env::var("TCPSHIELD_BASE_URL").ok(),
            tcpshield_api_key: env::var("TCPSHIELD_API_KEY").ok(),
            tcpshield_network_id: env::var("TCPSHIELD_NETWORK_ID")
                .ok()
                .map(|value| value.parse::<u64>())
                .transpose()
                .map_err(|_| ConfigError::Invalid("TCPSHIELD_NETWORK_ID"))?,
            artifact_root: PathBuf::from(get("KITSUNEBI_ARTIFACT_ROOT")?),
            web_static_root: PathBuf::from(get("KITSUNEBI_WEB_STATIC_ROOT")?),
            access,
            allowed_origins: origins,
            csrf_token: env::var("KITSUNEBI_CSRF_TOKEN").ok(),
            csrf_secret: env::var("KITSUNEBI_CSRF_SECRET").ok(),
            mode,
            local_auth,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.listen_addr.parse::<SocketAddr>().is_err() {
            return Err(ConfigError::Invalid("KITSUNEBI_LISTEN_ADDR"));
        }
        for (value, name) in [
            (&self.database_url, "DATABASE_URL"),
            (&self.gameap_base_url, "GAMEAP_BASE_URL"),
            (&self.gameap_pat, "GAMEAP_PAT"),
        ] {
            if value.trim().is_empty() {
                return Err(ConfigError::Missing(name));
            }
        }
        if self.gameap_pat.len() > 4096
            || self
                .gameap_pat
                .chars()
                .any(|character| character.is_control() || character.is_whitespace())
        {
            return Err(ConfigError::Invalid("GAMEAP_PAT"));
        }
        let gameap_transport =
            GameApHttpTransport::new(&self.gameap_base_url, GameApClientConfig::default())
                .map_err(|_| ConfigError::Invalid("GAMEAP_BASE_URL"))?;
        if self.mode == RuntimeMode::Production && gameap_transport.base_url().scheme() != "https" {
            return Err(ConfigError::Security);
        }
        if self.artifact_root.as_os_str().is_empty() {
            return Err(ConfigError::Missing("KITSUNEBI_ARTIFACT_ROOT"));
        }
        if self.web_static_root.as_os_str().is_empty() {
            return Err(ConfigError::Missing("KITSUNEBI_WEB_STATIC_ROOT"));
        }
        if self.mode == RuntimeMode::Production
            && (!self.artifact_root.is_absolute() || !self.web_static_root.is_absolute())
        {
            return Err(ConfigError::Security);
        }
        if self.allowed_origins.is_empty() {
            return Err(ConfigError::Missing("KITSUNEBI_ALLOWED_ORIGINS"));
        }
        if self.tcpshield_base_url.is_some() != self.tcpshield_api_key.is_some() {
            return Err(ConfigError::Invalid("TCPShield configuration"));
        }
        if self.tcpshield_base_url.is_some()
            && self
                .tcpshield_network_id
                .is_none_or(|network_id| network_id == 0)
        {
            return Err(ConfigError::Missing("TCPSHIELD_NETWORK_ID"));
        }
        if self.tcpshield_base_url.is_none() && self.tcpshield_network_id.is_some() {
            return Err(ConfigError::Invalid("TCPShield configuration"));
        }
        if let (Some(base), Some(_key)) = (
            self.tcpshield_base_url.as_deref(),
            self.tcpshield_api_key.as_deref(),
        ) {
            TcpShieldHttpTransport::new(
                base,
                TcpShieldTransportConfig {
                    timeout: Duration::from_secs(15),
                    max_response_bytes: 1024 * 1024,
                    allow_localhost: self.mode == RuntimeMode::Local,
                },
            )
            .map_err(|_| ConfigError::Invalid("TCPShield configuration"))?;
        }
        if self.tcpshield_api_key.as_deref().is_some_and(|key| {
            key.is_empty()
                || key.len() > 4096
                || key
                    .chars()
                    .any(|character| character.is_control() || character.is_whitespace())
        }) {
            return Err(ConfigError::Invalid("TCPShield configuration"));
        }
        if self.mode == RuntimeMode::Production {
            self.access.validate().map_err(|_| ConfigError::Security)?;
        }
        match (self.mode, self.local_auth) {
            (RuntimeMode::Production, true) => return Err(ConfigError::Security),
            (RuntimeMode::Local, false) => return Err(ConfigError::Security),
            (RuntimeMode::Local, true) => {
                #[cfg(not(feature = "local-auth"))]
                return Err(ConfigError::Security);
            }
            (RuntimeMode::Production, false) => {}
        }
        match self.mode {
            RuntimeMode::Local => {
                let Some(token) = self.csrf_token.as_deref() else {
                    return Err(ConfigError::Missing("KITSUNEBI_CSRF_TOKEN"));
                };
                if token.is_empty() || token.len() > 4096 || token.chars().any(char::is_control) {
                    return Err(ConfigError::Invalid("KITSUNEBI_CSRF_TOKEN"));
                }
                if self.csrf_secret.is_some() {
                    return Err(ConfigError::Invalid("KITSUNEBI_CSRF_SECRET"));
                }
            }
            RuntimeMode::Production => {
                let Some(secret) = self.csrf_secret.as_deref() else {
                    return Err(ConfigError::Missing("KITSUNEBI_CSRF_SECRET"));
                };
                if secret.len() < 32
                    || secret.len() > 4096
                    || secret
                        .chars()
                        .any(|character| character.is_control() || character.is_whitespace())
                {
                    return Err(ConfigError::Invalid("KITSUNEBI_CSRF_SECRET"));
                }
                if self.csrf_token.is_some() {
                    return Err(ConfigError::Invalid("KITSUNEBI_CSRF_TOKEN"));
                }
            }
        }
        configured_backup_provider(self.mode)?;
        configured_monitoring(self.mode)?;
        Ok(())
    }

    pub fn redacted_database_url(&self) -> String {
        let Some((prefix, rest)) = self.database_url.split_once("://") else {
            return "[REDACTED]".into();
        };
        let Some((_, host)) = rest.rsplit_once('@') else {
            return "[REDACTED]".into();
        };
        let host = host.split(['?', '#']).next().unwrap_or(host);
        format!("{prefix}://[REDACTED]@{host}")
    }

    pub fn security(&self) -> Result<SecurityConfig, ConfigError> {
        let csrf: Arc<dyn kitsunebi_api::security::CsrfTokenProvider> = match self.mode {
            RuntimeMode::Local => {
                #[cfg(feature = "local-auth")]
                {
                    let token = self
                        .csrf_token
                        .as_deref()
                        .ok_or(ConfigError::Missing("KITSUNEBI_CSRF_TOKEN"))?;
                    Arc::new(kitsunebi_api::security::StaticCsrfValidator::new(token))
                }
                #[cfg(not(feature = "local-auth"))]
                {
                    return Err(ConfigError::Security);
                }
            }
            RuntimeMode::Production => {
                let secret = self
                    .csrf_secret
                    .as_deref()
                    .ok_or(ConfigError::Missing("KITSUNEBI_CSRF_SECRET"))?;
                Arc::new(
                    kitsunebi_api::security::HmacCsrfValidator::new(
                        secret.as_bytes(),
                        Duration::from_secs(15 * 60),
                    )
                    .map_err(|_| ConfigError::Security)?,
                )
            }
        };
        let environment = match self.mode {
            RuntimeMode::Local => kitsunebi_api::RuntimeEnvironment::Development,
            RuntimeMode::Production => kitsunebi_api::RuntimeEnvironment::Production,
        };
        let security = SecurityConfig {
            allowed_origins: self.allowed_origins.clone(),
            csrf,
            body_limit: DEFAULT_BODY_LIMIT,
            upload_limit: DEFAULT_UPLOAD_LIMIT,
            dangerous_rate_limit: 30,
            dangerous_rate_window: Duration::from_secs(60),
            environment,
            local_auth: kitsunebi_api::LocalAuthConfig {
                enabled: self.local_auth,
            },
        };
        security.validate().map_err(|_| ConfigError::Security)?;
        Ok(security)
    }
}

fn configured_backup_provider(mode: RuntimeMode) -> Result<ConfiguredBackupProvider, ConfigError> {
    let endpoint = env::var("KITSUNEBI_BACKUP_BASE_URL").ok();
    let bearer = env::var("KITSUNEBI_BACKUP_TOKEN").ok();
    match (endpoint, bearer) {
        (None, None) => Ok(ConfiguredBackupProvider::Disabled),
        (Some(endpoint), Some(bearer)) => {
            let provider = if mode == RuntimeMode::Local {
                BackupHttpProvider::new_localhost_for_tests(&endpoint, bearer)
            } else {
                BackupHttpProvider::new(&endpoint, bearer)
            }
            .map_err(|_| ConfigError::Security)?;
            Ok(ConfiguredBackupProvider::Http(provider))
        }
        _ => Err(ConfigError::Invalid("KITSUNEBI_BACKUP provider")),
    }
}

fn configured_monitoring(mode: RuntimeMode) -> Result<Option<MonitoringHttpObserver>, ConfigError> {
    let endpoint = env::var("KITSUNEBI_MONITORING_BASE_URL").ok();
    let bearer = env::var("KITSUNEBI_MONITORING_TOKEN").ok();
    match (endpoint, bearer) {
        (None, None) => Ok(None),
        (Some(endpoint), Some(bearer)) => {
            let observer = if mode == RuntimeMode::Local {
                MonitoringHttpObserver::new_localhost_for_tests(
                    &endpoint,
                    bearer,
                    Duration::from_secs(1),
                    Duration::from_secs(30),
                )
            } else {
                MonitoringHttpObserver::new(
                    &endpoint,
                    bearer,
                    Duration::from_secs(1),
                    Duration::from_secs(30),
                )
            }
            .map_err(|_| ConfigError::Security)?;
            Ok(Some(observer))
        }
        _ => Err(ConfigError::Invalid("KITSUNEBI_MONITORING provider")),
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn gameap_lifecycle_attestation(
    value: Option<&str>,
) -> Result<LifecycleContractAttestation, &'static str> {
    match value {
        Some("1") => Ok(LifecycleContractAttestation::Verified),
        None | Some("") => Ok(LifecycleContractAttestation::NotRun),
        Some(_) => Err("KITSUNEBI_GAMEAP_LIFECYCLE_ATTESTED must be 1"),
    }
}
fn actor_id(actor: &VerifiedActor) -> Result<ActorId, ApiError> {
    Uuid::parse_str(&actor.subject)
        .map(ActorId::from_uuid)
        .map_err(|_| ApiError::Forbidden)
}
fn actor_identity_matches_service(
    kind: kitsunebi_storage::ActorKind,
    identity_service: Option<ServiceId>,
    service: ServiceId,
) -> bool {
    match kind {
        kitsunebi_storage::ActorKind::Browser => identity_service.is_none(),
        kitsunebi_storage::ActorKind::Service => identity_service == Some(service),
    }
}
fn application_error(error: ApplicationError) -> ApiError {
    match error {
        ApplicationError::NotFound(_) => ApiError::NotFound,
        ApplicationError::Forbidden => ApiError::Forbidden,
        ApplicationError::Conflict(_)
        | ApplicationError::RollbackConflict(_)
        | ApplicationError::StalePlan
        | ApplicationError::Replay
        | ApplicationError::VerificationFailed(_) => ApiError::Conflict,
        ApplicationError::ExpiredPlan => ApiError::InvalidRequest("plan has expired"),
        ApplicationError::BackupUnavailable | ApplicationError::Port(_) => ApiError::Backend,
    }
}
fn domain_permission(permission: ApiPermission) -> DomainPermission {
    match permission {
        ApiPermission::ServiceRead => DomainPermission::ServiceRead,
        ApiPermission::LifecycleStart => DomainPermission::LifecycleStart,
        ApiPermission::LifecycleStop => DomainPermission::LifecycleStop,
        ApiPermission::LifecycleRestart => DomainPermission::LifecycleRestart,
        ApiPermission::ServiceLifecycle => DomainPermission::ServiceLifecycle,
        ApiPermission::ConsoleRead => DomainPermission::ConsoleRead,
        ApiPermission::ConsoleSend => DomainPermission::ConsoleSend,
        ApiPermission::FilesRead => DomainPermission::FilesRead,
        ApiPermission::FilesWrite => DomainPermission::FilesWrite,
        ApiPermission::FilesBatch => DomainPermission::FilesBatch,
        ApiPermission::ArtifactDiscover => DomainPermission::ArtifactDiscover,
        ApiPermission::ArtifactStage => DomainPermission::ArtifactStage,
        ApiPermission::ArtifactActivate => DomainPermission::ArtifactActivate,
        ApiPermission::ProxyRollout => DomainPermission::ProxyRollout,
        ApiPermission::BackupCreate => DomainPermission::BackupCreate,
        ApiPermission::BackupRestore => DomainPermission::BackupRestore,
        ApiPermission::WorldRead => DomainPermission::WorldRead,
        ApiPermission::WorldWrite => DomainPermission::WorldWrite,
        ApiPermission::EndpointRead => DomainPermission::EndpointRead,
        ApiPermission::EndpointWrite => DomainPermission::EndpointWrite,
        ApiPermission::ServiceArchive => DomainPermission::ServiceArchive,
        ApiPermission::ServicePurge => DomainPermission::ServicePurge,
        ApiPermission::ChangePlan => DomainPermission::ChangePlan,
        ApiPermission::ChangeApprove => DomainPermission::ChangeApprove,
        ApiPermission::ChangeApply => DomainPermission::ChangeApply,
        ApiPermission::ChangeVerify => DomainPermission::ChangeVerify,
        ApiPermission::ChangeAccept => DomainPermission::ChangeAccept,
        ApiPermission::ChangeRollback => DomainPermission::ChangeRollback,
        ApiPermission::AuditRead => DomainPermission::AuditRead,
        ApiPermission::AccessRead => DomainPermission::AccessRead,
        ApiPermission::AccessManage => DomainPermission::AccessManage,
        ApiPermission::OperationRead => DomainPermission::OperationRead,
    }
}

fn mutation_permission(
    resource: &str,
    action: MutationAction,
    command: MutationCommand,
) -> ApiPermission {
    match action {
        MutationAction::Change => match resource {
            "worlds" => ApiPermission::WorldWrite,
            "endpoints" => ApiPermission::EndpointWrite,
            "access-policies" => ApiPermission::AccessManage,
            _ => match command {
                MutationCommand::Plan => ApiPermission::ChangePlan,
                MutationCommand::Approve => ApiPermission::ChangeApprove,
                MutationCommand::Apply => ApiPermission::ChangeApply,
                MutationCommand::Verify => ApiPermission::ChangeVerify,
                MutationCommand::Accept => ApiPermission::ChangeAccept,
                MutationCommand::Rollback => ApiPermission::ChangeRollback,
            },
        },
    }
}
fn api_permission_for_domain(permission: &DomainPermission) -> Vec<ApiPermission> {
    match permission {
        DomainPermission::ServiceRead => vec![ApiPermission::ServiceRead],
        DomainPermission::LifecycleStart => vec![ApiPermission::LifecycleStart],
        DomainPermission::LifecycleStop => vec![ApiPermission::LifecycleStop],
        DomainPermission::LifecycleRestart => vec![ApiPermission::LifecycleRestart],
        DomainPermission::ServiceLifecycle => vec![ApiPermission::ServiceLifecycle],
        DomainPermission::ConsoleRead => vec![ApiPermission::ConsoleRead],
        DomainPermission::ConsoleSend => vec![ApiPermission::ConsoleSend],
        DomainPermission::FilesRead => vec![ApiPermission::FilesRead],
        DomainPermission::FilesWrite => vec![ApiPermission::FilesWrite],
        DomainPermission::FilesBatch => vec![ApiPermission::FilesBatch],
        DomainPermission::ArtifactDiscover => vec![ApiPermission::ArtifactDiscover],
        DomainPermission::ArtifactStage => vec![ApiPermission::ArtifactStage],
        DomainPermission::ArtifactActivate => vec![ApiPermission::ArtifactActivate],
        DomainPermission::ProxyRollout => vec![ApiPermission::ProxyRollout],
        DomainPermission::BackupCreate => vec![ApiPermission::BackupCreate],
        DomainPermission::BackupRestore => vec![ApiPermission::BackupRestore],
        DomainPermission::WorldRead => vec![ApiPermission::WorldRead],
        DomainPermission::WorldWrite => vec![ApiPermission::WorldWrite],
        DomainPermission::EndpointRead => vec![ApiPermission::EndpointRead],
        DomainPermission::EndpointWrite => vec![ApiPermission::EndpointWrite],
        DomainPermission::ServiceArchive => vec![ApiPermission::ServiceArchive],
        DomainPermission::ServicePurge => vec![ApiPermission::ServicePurge],
        DomainPermission::ChangePlan => vec![ApiPermission::ChangePlan],
        DomainPermission::ChangeApprove => vec![ApiPermission::ChangeApprove],
        DomainPermission::ChangeApply => vec![ApiPermission::ChangeApply],
        DomainPermission::ChangeVerify => vec![ApiPermission::ChangeVerify],
        DomainPermission::ChangeAccept => vec![ApiPermission::ChangeAccept],
        DomainPermission::ChangeRollback => vec![ApiPermission::ChangeRollback],
        DomainPermission::AuditRead => vec![ApiPermission::AuditRead],
        DomainPermission::AccessRead => vec![ApiPermission::AccessRead],
        DomainPermission::AccessManage => vec![ApiPermission::AccessManage],
        DomainPermission::OperationRead => vec![ApiPermission::OperationRead],
    }
}

/// Object authorization backed by access-policy rows.  No JWT role or scope
/// is consulted here; the verified subject is resolved to a database actor.
#[derive(Clone)]
pub struct AccessChecker {
    storage: MySqlStorage,
}
impl AccessChecker {
    pub fn new(storage: MySqlStorage) -> Self {
        Self { storage }
    }
    async fn policies(&self) -> Result<Vec<AccessPolicy>, ApiError> {
        self.storage
            .list_access_policies()
            .await
            .map_err(|_| ApiError::Backend)
    }
    async fn allows(
        &self,
        actor: ActorId,
        service: ServiceId,
        permission: DomainPermission,
    ) -> Result<bool, ApiError> {
        let identity = self
            .storage
            .actor_identity(actor)
            .await
            .map_err(|_| ApiError::Backend)?;
        let identity_matches_service = identity.is_some_and(|identity| {
            actor_identity_matches_service(identity.kind, identity.service_id, service)
        });
        if !identity_matches_service {
            return Ok(false);
        }
        let candidates = api_permission_for_domain(&permission);
        Ok(self.policies().await?.into_iter().any(|policy| {
            candidates
                .iter()
                .copied()
                .map(domain_permission)
                .any(|candidate| policy.allows(actor, service, candidate))
        }))
    }
    async fn service_ids(
        &self,
        actor: ActorId,
        permission: DomainPermission,
    ) -> Result<Vec<ServiceId>, ApiError> {
        let mut services = BTreeSet::new();
        for candidate in api_permission_for_domain(&permission) {
            services.extend(
                self.storage
                    .service_ids_for_actor(actor, &domain_permission(candidate))
                    .await
                    .map_err(|_| ApiError::Backend)?,
            );
        }
        Ok(services.into_iter().collect())
    }
    async fn resource_services(
        &self,
        resource: &str,
        id: Option<&str>,
        actor: ActorId,
        permission: DomainPermission,
    ) -> Result<Vec<ServiceId>, ApiError> {
        let Some(id) = id else {
            return self.service_ids(actor, permission).await;
        };
        let uuid = if resource == "execution-units" {
            self.execution_binding_id(id)
                .await?
                .ok_or(ApiError::NotFound)?
        } else {
            Uuid::parse_str(id).map_err(|_| ApiError::NotFound)?
        };
        let kind = Self::resource_kind(resource).ok_or(ApiError::NotFound)?;
        self.storage
            .resource_service_scope(kind, uuid)
            .await
            .map_err(|_| ApiError::NotFound)
    }
    fn resource_kind(resource: &str) -> Option<ResourceKind> {
        Some(match resource {
            "networks" => ResourceKind::Network,
            "services" => ResourceKind::Service,
            "clusters" => ResourceKind::Cluster,
            "cluster-revisions" => ResourceKind::Revision,
            "worlds" => ResourceKind::World,
            "proxy-pools" => ResourceKind::ProxyPool,
            "proxy-instances" => ResourceKind::ProxyInstance,
            "runtime-profiles" => ResourceKind::RuntimeProfile,
            "artifacts" => ResourceKind::Artifact,
            "config" => ResourceKind::ConfigBaseline,
            "endpoints" => ResourceKind::Endpoint,
            "access-policies" => ResourceKind::AccessPolicy,
            "change-sessions" => ResourceKind::ChangeSession,
            "operations" => ResourceKind::Operation,
            "backups" => ResourceKind::BackupReference,
            "audit-events" => ResourceKind::AuditEvent,
            "execution-units" => ResourceKind::GameAPBinding,
            _ => return None,
        })
    }
    async fn execution_binding_id(&self, unit: &str) -> Result<Option<Uuid>, ApiError> {
        let row = sqlx::query("SELECT id FROM gameap_bindings WHERE execution_unit_ref = ?")
            .bind(unit)
            .fetch_optional(self.storage.pool())
            .await
            .map_err(|_| ApiError::Backend)?;
        row.map(|row| {
            let value: String = sqlx::Row::try_get(&row, "id").map_err(|_| ApiError::Backend)?;
            Uuid::parse_str(&value).map_err(|_| ApiError::Backend)
        })
        .transpose()
    }

    pub async fn authorize(
        &self,
        actor: &VerifiedActor,
        resource: &str,
        id: Option<&str>,
        permission: ApiPermission,
    ) -> Result<AccessDecision, ApiError> {
        let actor_id = actor_id(actor)?;
        let domain = domain_permission(permission);
        let service_ids = self
            .resource_services(resource, id, actor_id, domain)
            .await?;
        let authorized = self
            .authorized_service_ids_for(actor_id, &service_ids, domain)
            .await?;
        if authorized.is_empty() {
            return Err(ApiError::NotFound);
        }
        let service_key = self
            .storage
            .get_service(authorized[0])
            .await
            .map_err(|_| ApiError::Backend)?
            .map(|service| service.key);
        Ok(AccessDecision { service_key })
    }

    /// Resolve only the service ids that both own the object and grant the
    /// requested permission.  Mutation code uses this result directly; it
    /// never parses a presentation key back into an id.
    pub async fn authorized_service_ids(
        &self,
        actor: &VerifiedActor,
        resource: &str,
        id: Option<&str>,
        permission: ApiPermission,
    ) -> Result<Vec<ServiceId>, ApiError> {
        let actor_id = actor_id(actor)?;
        let domain = domain_permission(permission);
        let services = self
            .resource_services(resource, id, actor_id, domain)
            .await?;
        self.authorized_service_ids_for(actor_id, &services, domain)
            .await
    }

    async fn authorized_service_ids_for(
        &self,
        actor: ActorId,
        services: &[ServiceId],
        permission: DomainPermission,
    ) -> Result<Vec<ServiceId>, ApiError> {
        let mut authorized = Vec::new();
        for service in services {
            if self.allows(actor, *service, permission).await? {
                authorized.push(*service);
            }
        }
        Ok(authorized)
    }
}

/// Maps cryptographically verified Access subjects to the database policy.
/// Claims never carry role or service scopes.
pub struct MysqlIdentityMapper {
    checker: AccessChecker,
}
impl MysqlIdentityMapper {
    pub fn new(storage: MySqlStorage) -> Self {
        Self {
            checker: AccessChecker::new(storage),
        }
    }
}
#[async_trait]
impl IdentityMapper for MysqlIdentityMapper {
    async fn map(&self, claims: &kitsunebi_api::VerifiedClaims) -> Result<VerifiedActor, ApiError> {
        let actor = Uuid::parse_str(&claims.subject).map_err(|_| ApiError::Unauthorized)?;
        let actor = ActorId::from_uuid(actor);
        let identity = self
            .checker
            .storage
            .actor_identity(actor)
            .await
            .map_err(|_| ApiError::Backend)?
            .ok_or(ApiError::Unauthorized)?;
        if identity.subject != claims.subject {
            return Err(ApiError::Unauthorized);
        }
        match identity.kind {
            kitsunebi_storage::ActorKind::Browser if identity.service_id.is_some() => {
                return Err(ApiError::Unauthorized);
            }
            kitsunebi_storage::ActorKind::Service if identity.service_id.is_none() => {
                return Err(ApiError::Unauthorized);
            }
            _ => {}
        }
        let kind = match identity.kind.as_str() {
            "browser" => kitsunebi_api::ActorKind::Browser,
            "service" => kitsunebi_api::ActorKind::Service,
            _ => return Err(ApiError::Unauthorized),
        };
        let policies = self.checker.policies().await?;
        let mut role = ApiRole::Auditor;
        let mut permissions = BTreeSet::new();
        let mut service_scopes = BTreeSet::new();
        for policy in policies {
            for grant in policy.grants {
                if grant.actor != actor {
                    continue;
                }
                if identity.kind == kitsunebi_storage::ActorKind::Service
                    && grant.service_scope != identity.service_id
                {
                    return Err(ApiError::Unauthorized);
                }
                let platform_admin = matches!(grant.role, kitsunebi_domain::Role::PlatformAdmin);
                role = match (role, grant.role) {
                    (_, kitsunebi_domain::Role::PlatformAdmin) => ApiRole::PlatformAdmin,
                    (ApiRole::PlatformAdmin, _) => ApiRole::PlatformAdmin,
                    (_, kitsunebi_domain::Role::Operator) => ApiRole::Operator,
                    (ApiRole::Operator, _) => ApiRole::Operator,
                    (_, kitsunebi_domain::Role::ServiceMaintainer) => ApiRole::ServiceMaintainer,
                    _ => ApiRole::Auditor,
                };
                if platform_admin {
                    service_scopes.insert("*".into());
                } else if let Some(service) = grant.service_scope {
                    service_scopes.insert(service.as_uuid().to_string());
                }
                for domain_permission in grant.permissions {
                    permissions.extend(api_permission_for_domain(&domain_permission));
                }
            }
        }
        if permissions.is_empty() || service_scopes.is_empty() {
            return Err(ApiError::Forbidden);
        }
        Ok(VerifiedActor {
            subject: claims.subject.clone(),
            email: claims.email.clone(),
            common_name: claims.common_name.clone(),
            kind,
            authorization: kitsunebi_api::Authorization {
                role,
                permissions,
                service_scopes,
            },
        })
    }
}

#[derive(Clone)]
pub struct MysqlAuthorizer {
    checker: AccessChecker,
}
impl MysqlAuthorizer {
    pub fn new(storage: MySqlStorage) -> Self {
        Self {
            checker: AccessChecker::new(storage),
        }
    }
}
#[async_trait]
impl Authorizer for MysqlAuthorizer {
    async fn authorize(
        &self,
        request: &application::Authorization,
    ) -> Result<(), ApplicationError> {
        self.checker
            .allows(request.actor, request.service, request.permission)
            .await
            .map_err(|_| ApplicationError::Port("authorization backend unavailable".into()))?
            .then_some(())
            .ok_or(ApplicationError::Forbidden)
    }
}

#[derive(Clone)]
pub struct MysqlAudit {
    storage: MySqlStorage,
}
impl MysqlAudit {
    pub fn new(storage: MySqlStorage) -> Self {
        Self { storage }
    }
}
#[async_trait]
impl AuditSink for MysqlAudit {
    async fn record(&self, event: kitsunebi_domain::AuditEvent) -> Result<(), ApplicationError> {
        self.storage
            .append_audit_event(&event)
            .await
            .map(|_| ())
            .map_err(|_| ApplicationError::Port("audit persistence failed".into()))
    }
}

/// TCPShield's public API only exposes backend-set state. This bridge keeps
/// provider identifiers and state hashes behind application-owned proxy
/// bindings; removing an old backend disables new edge assignments, while a
/// separate connection observer proves existing connections have drained.
#[derive(Clone)]
pub struct TcpShieldBridge {
    pub client: Arc<TcpShieldClient<TcpShieldHttpTransport>>,
    pub network_id: u64,
}
impl TcpShieldBridge {
    pub fn new(
        client: Arc<TcpShieldClient<TcpShieldHttpTransport>>,
        network_id: u64,
    ) -> Result<Self, ApplicationError> {
        if network_id == 0 {
            return Err(ApplicationError::Port(
                "TCPShield network id must be positive".into(),
            ));
        }
        Ok(Self { client, network_id })
    }
    fn provider_ids(&self, binding: &ProxyEdgeBinding) -> Result<(u64, u64), ApplicationError> {
        let set = binding
            .backend_set_id
            .parse::<u64>()
            .map_err(|_| ApplicationError::Conflict("proxy backend set id is not numeric"))?;
        if set == 0 {
            return Err(ApplicationError::Conflict(
                "proxy backend set id must be positive",
            ));
        }
        Ok((self.network_id, set))
    }
    async fn observe_set(
        &self,
        binding: &ProxyEdgeBinding,
    ) -> Result<BackendSet, ApplicationError> {
        binding.validate()?;
        let (network, set) = self.provider_ids(binding)?;
        self.client
            .observe(network, set)
            .await
            .map_err(Self::map_error)
    }
    fn map_error(error: kitsunebi_tcpshield::Error) -> ApplicationError {
        match error {
            kitsunebi_tcpshield::Error::ExternalDrift { .. } => ApplicationError::StalePlan,
            kitsunebi_tcpshield::Error::VerificationFailed { .. }
            | kitsunebi_tcpshield::Error::RollbackConflict { .. } => {
                ApplicationError::Conflict("TCPShield postcondition did not match")
            }
            kitsunebi_tcpshield::Error::Ambiguous { .. } => {
                ApplicationError::Conflict("TCPShield mutation outcome is ambiguous")
            }
            kitsunebi_tcpshield::Error::InvalidInput(_)
            | kitsunebi_tcpshield::Error::IncompleteResponse(_)
            | kitsunebi_tcpshield::Error::Decode(_)
            | kitsunebi_tcpshield::Error::BodyTooLarge { .. }
            | kitsunebi_tcpshield::Error::DrainUnknown
            | kitsunebi_tcpshield::Error::ConnectionsActive { .. } => {
                ApplicationError::Port("TCPShield response was not usable".into())
            }
            kitsunebi_tcpshield::Error::Transport(_)
            | kitsunebi_tcpshield::Error::Timeout
            | kitsunebi_tcpshield::Error::RateLimited { .. }
            | kitsunebi_tcpshield::Error::Unauthorized
            | kitsunebi_tcpshield::Error::Forbidden
            | kitsunebi_tcpshield::Error::NotFound
            | kitsunebi_tcpshield::Error::Http { .. } => {
                ApplicationError::Port("TCPShield request failed".into())
            }
        }
    }
    async fn apply_address(
        &self,
        binding: &ProxyEdgeBinding,
        add: bool,
    ) -> Result<(), ApplicationError> {
        let current = self.observe_set(binding).await?;
        if current.hash() != binding.observed_hash {
            return Err(ApplicationError::StalePlan);
        }
        let desired = if add {
            current
                .add(binding.backend_address.clone())
                .map_err(|_| ApplicationError::Conflict("invalid proxy backend"))?
        } else {
            current.remove(&binding.backend_address)
        };
        if desired == current {
            return Err(ApplicationError::Conflict(if add {
                "proxy backend already exists"
            } else {
                "proxy backend does not exist"
            }));
        }
        let plan = self.client.plan(current, desired);
        let (network, set) = self.provider_ids(binding)?;
        self.client
            .apply(network, set, &plan)
            .await
            .map(|_| ())
            .map_err(Self::map_error)
    }
}
#[async_trait]
impl ProxyEdge for TcpShieldBridge {
    async fn prepare(&self, binding: &ProxyEdgeBinding) -> Result<(), ApplicationError> {
        let current = self.observe_set(binding).await?;
        if current.hash() != binding.observed_hash {
            return Err(ApplicationError::StalePlan);
        }
        Ok(())
    }
    async fn configure(&self, binding: &ProxyEdgeBinding) -> Result<(), ApplicationError> {
        // Configuration is an observation gate. The actual provider mutation
        // is performed by `add`, so a retry cannot silently succeed twice.
        let current = self.observe_set(binding).await?;
        if current.hash() != binding.observed_hash {
            return Err(ApplicationError::StalePlan);
        }
        if current.backends.contains(&binding.backend_address) {
            return Err(ApplicationError::Conflict("proxy backend already exists"));
        }
        Ok(())
    }
    async fn add(&self, binding: &ProxyEdgeBinding) -> Result<(), ApplicationError> {
        self.apply_address(binding, true).await
    }
    async fn remove(&self, binding: &ProxyEdgeBinding) -> Result<(), ApplicationError> {
        self.apply_address(binding, false).await
    }
    async fn drain(&self, _binding: &ProxyEdgeBinding) -> Result<(), ApplicationError> {
        self.apply_address(_binding, false).await
    }
    async fn real_connect(
        &self,
        binding: &ProxyEdgeBinding,
    ) -> Result<ConnectionEvidence, ApplicationError> {
        let mut addresses = tokio::net::lookup_host(&binding.backend_address)
            .await
            .map_err(|_| ApplicationError::Port("proxy backend DNS lookup failed".into()))?;
        let address = addresses.next().ok_or(ApplicationError::Port(
            "proxy backend did not resolve".into(),
        ))?;
        tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::TcpStream::connect(address),
        )
        .await
        .map_err(|_| ApplicationError::Port("proxy backend connection timed out".into()))?
        .map_err(|_| ApplicationError::Port("proxy backend connection failed".into()))?;
        Ok(ConnectionEvidence {
            active: 1,
            observed: true,
            hash: kitsunebi_gameap::sha256_hex(binding.backend_address.as_bytes()),
        })
    }
    async fn stop(&self, binding: &ProxyEdgeBinding) -> Result<(), ApplicationError> {
        let current = self.observe_set(binding).await?;
        if current.hash() != binding.observed_hash {
            return Err(ApplicationError::StalePlan);
        }
        if current.backends.contains(&binding.backend_address) {
            return Err(ApplicationError::Conflict(
                "proxy backend remains after removal",
            ));
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProxyEdgePhase {
    Prior,
    PostAdd,
    Final,
}

#[async_trait]
trait ProxyEdgeState: ProxyEdge {
    async fn observe_backend_set(
        &self,
        binding: &ProxyEdgeBinding,
    ) -> Result<BackendSet, ApplicationError>;
}

#[async_trait]
impl ProxyEdgeState for TcpShieldBridge {
    async fn observe_backend_set(
        &self,
        binding: &ProxyEdgeBinding,
    ) -> Result<BackendSet, ApplicationError> {
        self.observe_set(binding).await
    }
}

#[async_trait]
impl ProxyEdgeResolver for TcpShieldBridge {
    async fn resolve(
        &self,
        binding: &ProxyEdgeBinding,
    ) -> Result<ProxyEdgeObservation, ApplicationError> {
        let observed = self.observe_set(binding).await?;
        Ok(ProxyEdgeObservation {
            instance_id: binding.instance_id,
            provider_network_id: binding.provider_network_id,
            domain_network_id: binding.domain_network_id,
            backend_set_id: binding.backend_set_id.clone(),
            backend_address: binding.backend_address.clone(),
            revision: binding.revision,
            evidence_hash: observed.hash(),
        })
    }
}

/// TCPShield cannot report active connections. Keeping this explicit observer
/// in the composition prevents a rollout from claiming that removal completed
/// the connection drain without monitoring evidence.
#[derive(Clone, Copy, Debug, Default)]
pub struct TcpShieldConnectionObserver;
#[async_trait]
impl application::ConnectionObserver for TcpShieldConnectionObserver {
    async fn observe(&self, _target: &str) -> Result<ConnectionEvidence, ApplicationError> {
        Err(ApplicationError::Port(
            "TCPShield connection/drain evidence is not available".into(),
        ))
    }
}

/// Runtime-selected provider adapters. Configuration is deliberately
/// fail-closed: an absent provider remains disabled, while a partially
/// configured pair is rejected before the controller starts.
#[derive(Clone)]
pub enum ConfiguredBackupProvider {
    Disabled,
    Http(BackupHttpProvider),
}

impl fmt::Debug for ConfiguredBackupProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => formatter.write_str("Disabled"),
            Self::Http(provider) => provider.fmt(formatter),
        }
    }
}

#[async_trait]
impl BackupProvider for ConfiguredBackupProvider {
    async fn create(
        &self,
        request: &application::BackupRequest,
    ) -> Result<kitsunebi_domain::BackupReference, ApplicationError> {
        match self {
            Self::Disabled => Err(ApplicationError::BackupUnavailable),
            Self::Http(provider) => provider.create(request).await,
        }
    }

    async fn verify(
        &self,
        reference: &kitsunebi_domain::BackupReference,
    ) -> Result<kitsunebi_domain::BackupObservation, ApplicationError> {
        match self {
            Self::Disabled => Err(ApplicationError::BackupUnavailable),
            Self::Http(provider) => provider.verify(reference).await,
        }
    }

    async fn restore(
        &self,
        request: &application::BackupRestoreRequest,
    ) -> Result<application::BackupRestoreInvocation, ApplicationError> {
        match self {
            Self::Disabled => Err(ApplicationError::BackupUnavailable),
            Self::Http(provider) => provider.restore(request).await,
        }
    }

    async fn verify_restore(
        &self,
        invocation: &application::BackupRestoreInvocation,
    ) -> Result<kitsunebi_domain::BackupObservation, ApplicationError> {
        match self {
            Self::Disabled => Err(ApplicationError::BackupUnavailable),
            Self::Http(provider) => provider.verify_restore(invocation).await,
        }
    }
}

#[derive(Clone)]
pub enum ConfiguredConnectionObserver {
    Unavailable,
    Http(MonitoringHttpObserver),
}

#[async_trait]
impl ConnectionObserver for ConfiguredConnectionObserver {
    async fn observe(&self, target: &str) -> Result<ConnectionEvidence, ApplicationError> {
        match self {
            Self::Unavailable => Err(ApplicationError::Port(
                "monitoring observer is not configured".into(),
            )),
            Self::Http(observer) => observer.observe(target).await,
        }
    }
}

#[derive(Clone)]
pub enum ConfiguredHealth {
    Tcp,
    Monitoring(ConfiguredConnectionObserver),
}

#[async_trait]
impl HealthVerifier for ConfiguredHealth {
    async fn verify(&self, target: &str) -> Result<(), ApplicationError> {
        match self {
            Self::Tcp => TcpShieldHealth.verify(target).await,
            Self::Monitoring(observer) => {
                let evidence = observer.observe(target).await?;
                if evidence.observed {
                    Ok(())
                } else {
                    Err(ApplicationError::Conflict(
                        "monitoring target is not healthy",
                    ))
                }
            }
        }
    }
}

/// Read-only DNS bridge used by endpoint health checks. It deliberately has
/// no write or reconciliation operation; resolution is performed by the host
/// resolver configured for the controller process.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemDnsResolver;
#[async_trait]
impl application::DnsResolver for SystemDnsResolver {
    async fn resolve(&self, hostname: &str, port: u16) -> Result<Vec<String>, ApplicationError> {
        if hostname.trim().is_empty()
            || hostname.chars().any(|character| character.is_control())
            || port == 0
        {
            return Err(ApplicationError::Conflict("invalid DNS query"));
        }
        let addresses = tokio::net::lookup_host((hostname, port))
            .await
            .map_err(|_| ApplicationError::Port("DNS resolution failed".into()))?;
        let addresses = addresses
            .map(|address| address.to_string())
            .collect::<Vec<_>>();
        if addresses.is_empty() {
            return Err(ApplicationError::NotFound("DNS address"));
        }
        Ok(addresses)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct TcpShieldHealth;
#[async_trait]
impl HealthVerifier for TcpShieldHealth {
    async fn verify(&self, target: &str) -> Result<(), ApplicationError> {
        let mut addresses = tokio::net::lookup_host(target)
            .await
            .map_err(|_| ApplicationError::Port("proxy health DNS lookup failed".into()))?;
        let address = addresses.next().ok_or(ApplicationError::Port(
            "proxy health target did not resolve".into(),
        ))?;
        tokio::time::timeout(
            Duration::from_secs(5),
            tokio::net::TcpStream::connect(address),
        )
        .await
        .map_err(|_| ApplicationError::Port("proxy health check timed out".into()))?
        .map_err(|_| ApplicationError::Port("proxy health check failed".into()))?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct TcpShieldComposition {
    pub edge: Arc<TcpShieldBridge>,
    pub observer: Arc<ConfiguredConnectionObserver>,
    pub health: Arc<ConfiguredHealth>,
}
impl TcpShieldComposition {
    pub fn new(
        client: Arc<TcpShieldClient<TcpShieldHttpTransport>>,
        network_id: u64,
    ) -> Result<Self, ApplicationError> {
        Self::new_with_monitoring(client, network_id, None)
    }
    pub fn new_with_monitoring(
        client: Arc<TcpShieldClient<TcpShieldHttpTransport>>,
        network_id: u64,
        monitoring: Option<MonitoringHttpObserver>,
    ) -> Result<Self, ApplicationError> {
        let (observer, health) = match monitoring {
            Some(observer) => {
                let observer = ConfiguredConnectionObserver::Http(observer);
                (observer.clone(), ConfiguredHealth::Monitoring(observer))
            }
            None => (
                ConfiguredConnectionObserver::Unavailable,
                ConfiguredHealth::Tcp,
            ),
        };
        Ok(Self {
            edge: Arc::new(TcpShieldBridge::new(client, network_id)?),
            observer: Arc::new(observer),
            health: Arc::new(health),
        })
    }
    pub async fn rollout(
        &self,
        rollout: application::ProxyRollout,
        actor: ActorId,
        service: ServiceId,
        authorizer: MysqlAuthorizer,
        audit: MysqlAudit,
    ) -> Result<(), ApplicationError> {
        let edge = (*self.edge).clone();
        let resolver = edge.clone();
        let observer = (*self.observer).clone();
        let proxy = application::ProxyService {
            edge,
            health: (*self.health).clone(),
            authorizer: authorizer.clone(),
            audit,
        };
        proxy
            .roll(rollout, &resolver, &observer, actor, service)
            .await
    }
}

/// Concrete GameAP HTTP/WS bridge. Process-manager capability checks remain
/// observation-gated; file quarantine is represented as a deterministic,
/// reversible GameAP move below.
#[derive(Clone)]
pub struct GameApExecutionBackend {
    pub client: Arc<GameApClient<GameApHttpTransport>>,
    pub websocket: GameApWebSocketTransport,
    capability_store: Option<MySqlStorage>,
    snapshots: Arc<std::sync::Mutex<BTreeMap<(String, String), FileSnapshot>>>,
}
#[derive(Clone)]
struct FileSnapshot {
    bytes: Vec<u8>,
    post_write_observation_pending: bool,
}
impl GameApExecutionBackend {
    pub fn new(client: Arc<GameApClient<GameApHttpTransport>>) -> Self {
        Self {
            client,
            websocket: GameApWebSocketTransport::default(),
            capability_store: None,
            snapshots: Arc::new(std::sync::Mutex::new(BTreeMap::new())),
        }
    }
    pub fn with_capability_store(
        client: Arc<GameApClient<GameApHttpTransport>>,
        capability_store: MySqlStorage,
    ) -> Self {
        Self {
            client,
            websocket: GameApWebSocketTransport::default(),
            capability_store: Some(capability_store),
            snapshots: Arc::new(std::sync::Mutex::new(BTreeMap::new())),
        }
    }
    fn binding_id(binding: &GameAPBinding) -> &str {
        &binding.execution_unit_id
    }
    fn quarantine_path(path: &str) -> String {
        format!(
            ".kitsunebi-quarantine/{}",
            kitsunebi_gameap::sha256_hex(path.as_bytes())
        )
    }
    fn require_capability(
        &self,
        capability: kitsunebi_gameap::Capability,
    ) -> Result<(), ApplicationError> {
        if self.client.capabilities().allows_mutation(capability) {
            Ok(())
        } else {
            Err(ApplicationError::Port(
                "GameAP capability is unavailable".into(),
            ))
        }
    }
    fn map_error(_error: GameApError) -> ApplicationError {
        ApplicationError::Port("GameAP request failed".into())
    }
    fn map_status_error(error: GameApError) -> ApplicationError {
        match error {
            GameApError::Http {
                kind: kitsunebi_gameap::HttpErrorKind::NotFound,
                ..
            } => ApplicationError::NotFound("GameAP execution"),
            other => Self::map_error(other),
        }
    }
    async fn require_node_observation(
        &self,
        binding: &GameAPBinding,
    ) -> Result<(), ApplicationError> {
        let node_id = binding
            .node_id
            .parse::<u64>()
            .map_err(|_| ApplicationError::Conflict("node capability observation is unknown"))?;
        let observation = self
            .client
            .observe_process_manager(kitsunebi_gameap::PROCESS_MANAGER_PLUGIN_ID, node_id)
            .await
            .map_err(|_| ApplicationError::Conflict("node capability observation unavailable"))?;
        if matches!(
            observation.process_manager,
            kitsunebi_gameap::ProcessManager::Unknown
        ) {
            return Err(ApplicationError::Conflict(
                "node capability observation is unknown",
            ));
        }
        if let Some(storage) = &self.capability_store {
            let process_manager = match observation.process_manager {
                kitsunebi_gameap::ProcessManager::Systemd => {
                    kitsunebi_domain::ProcessManager::Systemd
                }
                kitsunebi_gameap::ProcessManager::Docker => {
                    kitsunebi_domain::ProcessManager::Docker
                }
                kitsunebi_gameap::ProcessManager::Podman => {
                    kitsunebi_domain::ProcessManager::Podman
                }
                kitsunebi_gameap::ProcessManager::Unknown => {
                    kitsunebi_domain::ProcessManager::Unknown
                }
            };
            let record = kitsunebi_domain::NodeCapabilityObservation::new(
                &node_id.to_string(),
                process_manager,
                Some(observation.version),
                vec!["process_manager".into()],
                &observation.evidence_hash,
                observation.timestamp,
            )
            .map_err(|_| ApplicationError::Conflict("node capability observation invalid"))?;
            application::NodeCapabilityRepository::record_node_capability(storage, record).await?;
        }
        Ok(())
    }
    pub async fn observe_node_capability(
        &self,
        binding: &GameAPBinding,
    ) -> Result<(), ApplicationError> {
        self.require_node_observation(binding).await
    }
    fn remember_snapshot(&self, binding: &GameAPBinding, path: &str, bytes: &[u8]) {
        let key = (Self::binding_id(binding).to_owned(), path.to_owned());
        let Ok(mut snapshots) = self.snapshots.lock() else {
            return;
        };
        match snapshots.get_mut(&key) {
            Some(snapshot) if snapshot.post_write_observation_pending => {
                // The application reads once after a successful mutation to
                // verify its postcondition. Keep the original bytes until a
                // later mutation starts or the compensator consumes them.
                snapshot.post_write_observation_pending = false;
            }
            Some(snapshot) if snapshot.bytes == bytes => {}
            Some(snapshot) => {
                // A later operation starts with a fresh observation after the
                // previous operation has finished. Its current bytes become
                // the new rollback baseline.
                snapshot.bytes = bytes.to_vec();
            }
            None => {
                snapshots.insert(
                    key,
                    FileSnapshot {
                        bytes: bytes.to_vec(),
                        post_write_observation_pending: false,
                    },
                );
            }
        }
    }
    fn mark_snapshot_post_write(&self, binding: &GameAPBinding, path: &str) {
        if let Ok(mut snapshots) = self.snapshots.lock()
            && let Some(snapshot) =
                snapshots.get_mut(&(Self::binding_id(binding).to_owned(), path.to_owned()))
        {
            snapshot.post_write_observation_pending = true;
        }
    }
    fn take_snapshot(&self, binding: &GameAPBinding, path: &str) -> Option<Vec<u8>> {
        self.snapshots
            .lock()
            .ok()?
            .remove(&(Self::binding_id(binding).to_owned(), path.to_owned()))
            .map(|snapshot| snapshot.bytes)
    }
}
#[async_trait]
impl ExecutionBackend for GameApExecutionBackend {
    async fn create(&self, binding: &GameAPBinding) -> Result<(), ApplicationError> {
        self.require_capability(kitsunebi_gameap::Capability::ExecutionCreate)?;
        self.require_node_observation(binding).await?;
        let request = CreateExecutionRequest {
            name: binding.execution_unit_id.clone(),
            ds_id: serde_json::Value::Null,
            game_id: "kitsunebi".into(),
            game_mod_id: serde_json::Value::Null,
            server_ip: binding.node_id.clone(),
            server_port: serde_json::Value::Null,
            query_port: None,
            rcon_port: None,
            rcon: None,
            dir: None,
            start_command: None,
            su_user: None,
            install: None,
        };
        self.client
            .create_execution(&request)
            .await
            .map(|_| ())
            .map_err(Self::map_error)
    }
    async fn delete(&self, binding: &GameAPBinding) -> Result<(), ApplicationError> {
        self.require_capability(kitsunebi_gameap::Capability::ExecutionDelete)?;
        self.require_node_observation(binding).await?;
        self.client
            .delete_execution(Self::binding_id(binding))
            .await
            .map_err(Self::map_error)
    }
    async fn start(&self, binding: &GameAPBinding) -> Result<(), ApplicationError> {
        self.require_capability(kitsunebi_gameap::Capability::Lifecycle)?;
        self.require_node_observation(binding).await?;
        self.client
            .lifecycle(Self::binding_id(binding), Lifecycle::Start)
            .await
            .map(|_| ())
            .map_err(Self::map_error)
    }
    async fn stop(&self, binding: &GameAPBinding) -> Result<(), ApplicationError> {
        self.require_capability(kitsunebi_gameap::Capability::Lifecycle)?;
        self.require_node_observation(binding).await?;
        self.client
            .lifecycle(Self::binding_id(binding), Lifecycle::Stop)
            .await
            .map(|_| ())
            .map_err(Self::map_error)
    }
    async fn restart(&self, binding: &GameAPBinding) -> Result<(), ApplicationError> {
        self.require_capability(kitsunebi_gameap::Capability::Lifecycle)?;
        self.require_node_observation(binding).await?;
        self.client
            .lifecycle(Self::binding_id(binding), Lifecycle::Restart)
            .await
            .map(|_| ())
            .map_err(Self::map_error)
    }
    async fn status(&self, binding: &GameAPBinding) -> Result<ExecutionStatus, ApplicationError> {
        let status = self
            .client
            .status(Self::binding_id(binding))
            .await
            .map_err(Self::map_status_error)?;
        Ok(ExecutionStatus {
            running: status.process_active,
            state_hash: kitsunebi_gameap::sha256_hex(status.process_active.to_string().as_bytes()),
            node: binding.node_id.clone(),
        })
    }
    async fn files(
        &self,
        binding: &GameAPBinding,
        path: &str,
    ) -> Result<Vec<FileEntry>, ApplicationError> {
        let content = self
            .client
            .list_files(
                Self::binding_id(binding),
                if path == "." { "" } else { path },
            )
            .await
            .map_err(Self::map_error)?;
        let prefix = if path.is_empty() || path == "." {
            String::new()
        } else {
            format!("{path}/")
        };
        let mut entries = Vec::with_capacity(content.items.len());
        for entry in content.items {
            let entry_path = format!("{prefix}{}", entry.name);
            if entry.kind == "directory" {
                entries.push(FileEntry {
                    path: entry_path,
                    classification: FileClassification::Unknown,
                    digest: String::new(),
                    size: 0,
                });
                continue;
            }
            let bytes = self
                .client
                .download_file(Self::binding_id(binding), &entry_path)
                .await
                .map_err(Self::map_error)?;
            entries.push(FileEntry {
                path: entry_path,
                classification: FileClassification::Unknown,
                digest: kitsunebi_gameap::sha256_hex(&bytes),
                size: bytes.len() as u64,
            });
        }
        // A file request may return its content directly rather than an item
        // list. Preserve that shape so callers still receive a digestable
        // snapshot for a nested path.
        if entries.is_empty()
            && content.kind == "file"
            && let Some(value) = content.content
        {
            let bytes = value.into_bytes();
            entries.push(FileEntry {
                path: path.into(),
                classification: FileClassification::Unknown,
                digest: kitsunebi_gameap::sha256_hex(&bytes),
                size: bytes.len() as u64,
            });
        }
        Ok(entries)
    }
    async fn read_file(
        &self,
        binding: &GameAPBinding,
        path: &str,
    ) -> Result<Vec<u8>, ApplicationError> {
        // The public content endpoint is text-oriented. Binary mutations use
        // the official download operation instead; trying the text endpoint
        // first preserves the cheaper path for ordinary configuration files.
        let bytes = match self.client.read_file(Self::binding_id(binding), path).await {
            Ok(value) => value.into_bytes(),
            Err(_) => self
                .client
                .download_file(Self::binding_id(binding), path)
                .await
                .map_err(Self::map_error)?,
        };
        self.remember_snapshot(binding, path, &bytes);
        Ok(bytes)
    }
    async fn write_file(
        &self,
        binding: &GameAPBinding,
        change: &FileChange,
        bytes: &[u8],
    ) -> Result<(), ApplicationError> {
        self.require_node_observation(binding).await?;
        let content = std::str::from_utf8(bytes)
            .map_err(|_| ApplicationError::VerificationFailed("text file is not UTF-8".into()))?;
        self.client
            .write_file(Self::binding_id(binding), &change.path, content)
            .await
            .map(|_| ())
            .map_err(Self::map_error)?;
        self.mark_snapshot_post_write(binding, &change.path);
        Ok(())
    }
    async fn upload(
        &self,
        binding: &GameAPBinding,
        change: &FileChange,
        bytes: &[u8],
    ) -> Result<(), ApplicationError> {
        self.require_node_observation(binding).await?;
        self.client
            .upload_file(Self::binding_id(binding), &change.path, bytes)
            .await
            .map(|_| ())
            .map_err(Self::map_error)?;
        self.mark_snapshot_post_write(binding, &change.path);
        Ok(())
    }
    async fn download(
        &self,
        binding: &GameAPBinding,
        path: &str,
    ) -> Result<Vec<u8>, ApplicationError> {
        self.client
            .download_file(Self::binding_id(binding), path)
            .await
            .map_err(Self::map_error)
    }
    async fn move_file(
        &self,
        binding: &GameAPBinding,
        from: &str,
        to: &str,
    ) -> Result<(), ApplicationError> {
        self.require_capability(kitsunebi_gameap::Capability::FileMove)?;
        self.require_node_observation(binding).await?;
        self.client
            .move_file(Self::binding_id(binding), from, to, "file")
            .await
            .map(|_| ())
            .map_err(Self::map_error)
    }
    async fn move_file_checked(
        &self,
        binding: &GameAPBinding,
        from: &str,
        to: &str,
        expected_source_digest: &str,
        expected_destination_digest: Option<&str>,
    ) -> Result<(), ApplicationError> {
        self.require_capability(kitsunebi_gameap::Capability::FileMove)?;
        self.require_node_observation(binding).await?;
        self.client
            .move_file_checked(
                Self::binding_id(binding),
                from,
                to,
                expected_source_digest,
                expected_destination_digest,
            )
            .await
            .map(|_| ())
            .map_err(Self::map_error)
    }
    async fn quarantine(
        &self,
        binding: &GameAPBinding,
        path: &str,
    ) -> Result<(), ApplicationError> {
        self.require_capability(kitsunebi_gameap::Capability::FileMove)?;
        self.require_node_observation(binding).await?;
        self.client
            .quarantine_file_checked(Self::binding_id(binding), path)
            .await
            .map(|_| ())
            .map_err(Self::map_error)
    }
    async fn restore_quarantined_file_checked(
        &self,
        binding: &GameAPBinding,
        path: &str,
        expected_digest: &str,
    ) -> Result<(), ApplicationError> {
        self.require_capability(kitsunebi_gameap::Capability::FileMove)?;
        self.require_node_observation(binding).await?;
        self.client
            .restore_quarantined_file_checked(Self::binding_id(binding), path, expected_digest)
            .await
            .map(|_| ())
            .map_err(Self::map_error)
    }
    async fn delete_file_checked(
        &self,
        binding: &GameAPBinding,
        path: &str,
        expected_digest: &str,
    ) -> Result<(), ApplicationError> {
        self.require_capability(kitsunebi_gameap::Capability::FileDelete)?;
        self.require_node_observation(binding).await?;
        self.client
            .delete_file_checked(Self::binding_id(binding), path, expected_digest)
            .await
            .map(|_| ())
            .map_err(Self::map_error)
    }
    async fn observe_file_optional(
        &self,
        binding: &GameAPBinding,
        path: &str,
    ) -> Result<Option<(String, u64)>, ApplicationError> {
        match self
            .client
            .observe_file(Self::binding_id(binding), path)
            .await
        {
            Ok(observation) if observation.is_directory => {
                Err(ApplicationError::Conflict("path is a directory"))
            }
            Ok(observation) => observation
                .digest
                .map(|digest| Some((digest, observation.size.unwrap_or_default())))
                .ok_or(ApplicationError::Conflict(
                    "regular file digest unavailable",
                )),
            Err(GameApError::Http {
                kind: kitsunebi_gameap::HttpErrorKind::NotFound,
                ..
            }) => Ok(None),
            Err(error) => Err(Self::map_error(error)),
        }
    }
    async fn restore_file(
        &self,
        binding: &GameAPBinding,
        change: &FileChange,
    ) -> Result<(), ApplicationError> {
        self.require_node_observation(binding).await?;
        let bytes = self
            .take_snapshot(binding, &change.path)
            .ok_or(ApplicationError::Conflict(
                "file rollback snapshot unavailable",
            ))?;
        // Quarantine is a reversible move. Restore the original provider
        // object first, retaining the snapshot as a byte-level postcondition
        // check; ordinary writes fall through to the existing CAS-safe write.
        if self
            .client
            .move_file(
                Self::binding_id(binding),
                &Self::quarantine_path(&change.path),
                &change.path,
                "quarantine-restore",
            )
            .await
            .is_ok()
        {
            let observed = self
                .client
                .download_file(Self::binding_id(binding), &change.path)
                .await
                .map_err(Self::map_error)?;
            if observed != bytes {
                return Err(ApplicationError::VerificationFailed(
                    "quarantine rollback postcondition mismatch".into(),
                ));
            }
            return Ok(());
        }
        if !matches!(change.classification, FileClassification::Artifact) {
            let content = std::str::from_utf8(&bytes).map_err(|_| {
                ApplicationError::VerificationFailed("text file rollback is not UTF-8".into())
            })?;
            self.client
                .write_file(Self::binding_id(binding), &change.path, content)
                .await
                .map_err(Self::map_error)?;
            let observed = self
                .client
                .read_file(Self::binding_id(binding), &change.path)
                .await
                .map_err(Self::map_error)?
                .into_bytes();
            if observed != bytes {
                return Err(ApplicationError::VerificationFailed(
                    "text file rollback postcondition mismatch".into(),
                ));
            }
        } else {
            self.client
                .upload_file(Self::binding_id(binding), &change.path, &bytes)
                .await
                .map_err(Self::map_error)?;
            let observed = self
                .client
                .download_file(Self::binding_id(binding), &change.path)
                .await
                .map_err(Self::map_error)?;
            if observed != bytes {
                return Err(ApplicationError::VerificationFailed(
                    "binary file rollback postcondition mismatch".into(),
                ));
            }
        }
        Ok(())
    }
    async fn restore_file_snapshot(
        &self,
        binding: &GameAPBinding,
        snapshot: &FileRestoreSnapshot,
    ) -> Result<(), ApplicationError> {
        if snapshot.path.trim().is_empty()
            || kitsunebi_gameap::validate_relative_path(&snapshot.path).is_err()
        {
            return Err(ApplicationError::Conflict("invalid file rollback path"));
        }
        let expected = kitsunebi_gameap::sha256_hex(&snapshot.bytes);
        if expected != snapshot.digest {
            return Err(ApplicationError::VerificationFailed(
                "file rollback snapshot digest mismatch".into(),
            ));
        }
        if !matches!(snapshot.classification, FileClassification::Artifact) {
            let content = std::str::from_utf8(&snapshot.bytes).map_err(|_| {
                ApplicationError::VerificationFailed("text file rollback is not UTF-8".into())
            })?;
            self.client
                .write_file(Self::binding_id(binding), &snapshot.path, content)
                .await
                .map_err(Self::map_error)?;
            let observed = self
                .client
                .read_file(Self::binding_id(binding), &snapshot.path)
                .await
                .map_err(Self::map_error)?
                .into_bytes();
            if observed != snapshot.bytes {
                return Err(ApplicationError::VerificationFailed(
                    "text file rollback postcondition mismatch".into(),
                ));
            }
        } else {
            self.client
                .upload_file(Self::binding_id(binding), &snapshot.path, &snapshot.bytes)
                .await
                .map_err(Self::map_error)?;
            let observed = self
                .client
                .download_file(Self::binding_id(binding), &snapshot.path)
                .await
                .map_err(Self::map_error)?;
            if observed != snapshot.bytes {
                return Err(ApplicationError::VerificationFailed(
                    "binary file rollback postcondition mismatch".into(),
                ));
            }
        }
        Ok(())
    }
    async fn command(
        &self,
        binding: &GameAPBinding,
        masked_command: &str,
    ) -> Result<(), ApplicationError> {
        let mut socket = self
            .client
            .connect_console(&self.websocket, Self::binding_id(binding))
            .await
            .map_err(Self::map_error)?;
        // GameAP's public WS protocol accepts a command message; the socket is
        // closed immediately after the one-shot application command.
        socket
            .send_command(masked_command.to_owned())
            .await
            .map_err(Self::map_error)
    }
    async fn open_console(
        &self,
        binding: &GameAPBinding,
    ) -> Result<Box<dyn application::ExecutionConsole>, ApplicationError> {
        let socket = self
            .client
            .connect_console(&self.websocket, Self::binding_id(binding))
            .await
            .map_err(Self::map_error)?;
        Ok(Box::new(GameApExecutionConsole { socket }))
    }
}

struct GameApExecutionConsole {
    socket: Box<dyn ConsoleSocket>,
}

#[cfg(test)]
fn gameap_api_error(error: GameApError) -> ApiError {
    match error {
        GameApError::InvalidPath => ApiError::InvalidRequest("invalid file path"),
        GameApError::TransferTooLarge => ApiError::PayloadTooLarge,
        GameApError::Http { kind, .. } => match kind {
            kitsunebi_gameap::HttpErrorKind::Unauthorized => ApiError::Unauthorized,
            kitsunebi_gameap::HttpErrorKind::Forbidden => ApiError::Forbidden,
            kitsunebi_gameap::HttpErrorKind::NotFound => ApiError::NotFound,
            kitsunebi_gameap::HttpErrorKind::BadRequest => {
                ApiError::InvalidRequest("GameAP rejected the request")
            }
            kitsunebi_gameap::HttpErrorKind::Conflict => ApiError::Conflict,
            _ => ApiError::Backend,
        },
        GameApError::Unsupported(_) => ApiError::Unsupported,
        GameApError::Transport(_) | GameApError::Decode(_) | GameApError::Cancelled => {
            ApiError::Backend
        }
    }
}
#[async_trait]
impl application::ExecutionConsole for GameApExecutionConsole {
    async fn send(&mut self, command: &str) -> Result<(), ApplicationError> {
        self.socket
            .send_command(command.to_owned())
            .await
            .map_err(GameApExecutionBackend::map_error)
    }
    async fn receive(&mut self) -> Result<Option<Vec<u8>>, ApplicationError> {
        self.socket
            .next()
            .await
            .map(|message| {
                message.map(|message| match console_message(message) {
                    ConsoleFrame::Text(text) => text.into_bytes(),
                    ConsoleFrame::Binary(bytes) => bytes,
                })
            })
            .map_err(GameApExecutionBackend::map_error)
    }
    async fn close(&mut self) -> Result<(), ApplicationError> {
        Ok(())
    }
}

/// Production durable-step dispatcher.  Plans contain only domain IDs; this
/// port resolves those IDs against MySQL and then calls the typed provider
/// ports.  It is intentionally separate from the small GameAP-only fixture
/// bridge above so tests cannot accidentally construct a dispatcher without
/// the persistence and provider dependencies required for mutation.
#[derive(Clone)]
pub struct ControllerStepPort {
    pub execution: Arc<GameApExecutionBackend>,
    pub artifacts: Arc<ArtifactBridge>,
    pub storage: MySqlStorage,
    pub authorizer: MysqlAuthorizer,
    pub audit: MysqlAudit,
    pub backup: ConfiguredBackupProvider,
    pub tcp_shield: Option<Arc<TcpShieldComposition>>,
}

impl ControllerStepPort {
    fn hash(bytes: &[u8]) -> String {
        kitsunebi_gameap::sha256_hex(bytes)
    }

    fn endpoint_binding_pair_matches(
        expected: &kitsunebi_domain::EndpointBinding,
        target: &kitsunebi_domain::EndpointBinding,
        cluster: ClusterId,
        expected_revision: kitsunebi_domain::RevisionId,
        target_revision: kitsunebi_domain::RevisionId,
        expected_id: BindingId,
        target_id: BindingId,
    ) -> bool {
        expected.id == expected_id
            && target.id == target_id
            && expected.cluster_id == cluster
            && target.cluster_id == cluster
            && expected.revision_id == expected_revision
            && target.revision_id == target_revision
            && expected.binding_key == target.binding_key
    }

    fn endpoint_reconnect_complete(
        current_revision: Option<kitsunebi_domain::RevisionId>,
        target_revision: kitsunebi_domain::RevisionId,
        runtime_complete: bool,
        endpoint_healthy: bool,
    ) -> bool {
        current_revision == Some(target_revision) && runtime_complete && endpoint_healthy
    }

    fn endpoint_compensation_error(
        original: ApplicationError,
        compensation: Result<(), ApplicationError>,
    ) -> ApplicationError {
        match compensation {
            Ok(()) => original,
            Err(error) => ApplicationError::RollbackConflict(format!(
                "endpoint reconnect compensation failed after {original}: {error}"
            )),
        }
    }

    #[cfg(test)]
    fn proxy_applied_state_matches(
        state_hash: &str,
        expected_hash: &str,
        target_is_member: bool,
    ) -> bool {
        state_hash == expected_hash && target_is_member
    }

    fn policy_has_exclusive_owner(owners: &[ServiceId], target: ServiceId) -> bool {
        owners == [target]
    }

    fn grants_are_service_scoped(
        grants: &[kitsunebi_domain::AccessGrant],
        service: ServiceId,
    ) -> bool {
        grants
            .iter()
            .all(|grant| grant.service_scope == Some(service))
    }

    async fn grant_identities_are_bound_to_service(
        &self,
        grants: &[kitsunebi_domain::AccessGrant],
        service: ServiceId,
    ) -> Result<bool, ApplicationError> {
        let mut actors = BTreeSet::new();
        for grant in grants {
            if !actors.insert(grant.actor) {
                continue;
            }
            let identity = self
                .storage
                .actor_identity(grant.actor)
                .await
                .map_err(|_| {
                    ApplicationError::Port("access policy actor identity unavailable".into())
                })?
                .ok_or(ApplicationError::Forbidden)?;
            let identity_valid =
                actor_identity_matches_service(identity.kind, identity.service_id, service);
            if !identity_valid
                || grants
                    .iter()
                    .filter(|candidate| candidate.actor == grant.actor)
                    .any(|candidate| candidate.service_scope != Some(service))
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn proxy_binding_with_hash(
        binding: &ProxyEdgeBinding,
        observed_hash: &str,
    ) -> ProxyEdgeBinding {
        let mut binding = binding.clone();
        binding.observed_hash = observed_hash.to_owned();
        binding
    }

    fn proxy_edge_phase(
        state: &BackendSet,
        old: &ProxyEdgeBinding,
        new: &ProxyEdgeBinding,
        prior_hash: &str,
        post_add_hash: &str,
        final_hash: &str,
    ) -> Option<ProxyEdgePhase> {
        let old_present = state.backends.contains(&old.backend_address);
        let new_present = state.backends.contains(&new.backend_address);
        match (state.hash().as_str(), old_present, new_present) {
            (hash, true, false) if hash == prior_hash => Some(ProxyEdgePhase::Prior),
            (hash, true, true) if hash == post_add_hash => Some(ProxyEdgePhase::PostAdd),
            (hash, false, true) if hash == final_hash => Some(ProxyEdgePhase::Final),
            _ => None,
        }
    }

    fn proxy_edge_state_evidence(
        state: &BackendSet,
        old: &ProxyEdgeBinding,
        new: &ProxyEdgeBinding,
    ) -> String {
        format!(
            "observed_hash={};old_present={};new_present={}",
            state.hash(),
            state.backends.contains(&old.backend_address),
            state.backends.contains(&new.backend_address),
        )
    }

    fn file_read_payload(
        classification: FileClassification,
        content: Vec<u8>,
    ) -> (String, Vec<u8>) {
        if matches!(
            classification,
            FileClassification::Secret | FileClassification::State | FileClassification::Unknown
        ) {
            let digest = kitsunebi_gameap::sha256_hex(&content);
            (
                "application/vnd.kitsunebi.file-metadata".into(),
                format!("digest={digest}\nbytes={}\n", content.len()).into_bytes(),
            )
        } else {
            ("application/octet-stream".into(), content)
        }
    }

    fn service_state_hash(service: &kitsunebi_domain::Service) -> String {
        Self::hash(format!("{service:?}").as_bytes())
    }
    async fn validate_access_policy_update(
        &self,
        policy_id: kitsunebi_domain::PolicyId,
        service_id: ServiceId,
        desired_grants: &[kitsunebi_domain::AccessGrant],
    ) -> Result<(), ApplicationError> {
        let owners = self
            .storage
            .resource_service_scope(ResourceKind::AccessPolicy, policy_id.as_uuid())
            .await
            .map_err(|_| ApplicationError::Port("access policy ownership unavailable".into()))?;
        if !Self::policy_has_exclusive_owner(&owners, service_id) {
            return Err(ApplicationError::Conflict(
                "access policy must belong exclusively to target service",
            ));
        }
        if !Self::grants_are_service_scoped(desired_grants, service_id) {
            return Err(ApplicationError::Conflict(
                "access policy grants must be scoped to target service",
            ));
        }
        if !self
            .grant_identities_are_bound_to_service(desired_grants, service_id)
            .await?
        {
            return Err(ApplicationError::Conflict(
                "access policy actors are not bound to target service",
            ));
        }
        Ok(())
    }
    async fn artifact(
        &self,
        id: kitsunebi_domain::ArtifactId,
    ) -> Result<Artifact, ApplicationError> {
        self.storage
            .get_artifact(id)
            .await
            .map_err(|_| ApplicationError::NotFound("artifact"))?
            .ok_or(ApplicationError::NotFound("artifact"))
    }
    async fn file_bytes(&self, digest: &str) -> Result<Vec<u8>, ApplicationError> {
        let bytes = self.artifacts.read(digest).await?;
        if Self::hash(&bytes) != digest {
            return Err(ApplicationError::VerificationFailed(
                "staged content digest mismatch".into(),
            ));
        }
        Ok(bytes)
    }
    async fn binding_id_for(&self, binding: &GameAPBinding) -> Result<BindingId, ApplicationError> {
        let rows =
            sqlx::query("SELECT id FROM gameap_bindings WHERE execution_unit_ref = ? ORDER BY id")
                .bind(&binding.execution_unit_id)
                .fetch_all(self.storage.pool())
                .await
                .map_err(|_| ApplicationError::NotFound("gameap binding"))?;
        if rows.len() != 1 {
            return Err(ApplicationError::Conflict(
                "gameap binding identifier is ambiguous",
            ));
        }
        let value: String = sqlx::Row::try_get(&rows[0], "id")
            .map_err(|_| ApplicationError::NotFound("gameap binding"))?;
        Uuid::parse_str(&value)
            .map(BindingId::from_uuid)
            .map_err(|_| ApplicationError::NotFound("gameap binding"))
    }
    async fn validate_declared_file(
        &self,
        binding: &GameAPBinding,
        path: &str,
        claimed: &FileClassification,
    ) -> Result<(), ApplicationError> {
        kitsunebi_gameap::validate_relative_path(path)
            .map_err(|_| ApplicationError::Conflict("invalid file path"))?;
        if matches!(
            claimed,
            FileClassification::Secret | FileClassification::State | FileClassification::Unknown
        ) {
            return Err(ApplicationError::Conflict(
                "file classification is not writable",
            ));
        }
        let binding_id = self.binding_id_for(binding).await?;
        let baseline = self
            .storage
            .get_config_baseline_for_binding(binding_id)
            .await
            .map_err(|_| ApplicationError::Conflict("config baseline unavailable"))?
            .ok_or(ApplicationError::Conflict("config baseline unavailable"))?;
        Self::validate_baseline_entry(&baseline, path, claimed)
    }
    async fn validate_declared_file_revision(
        &self,
        revision_id: kitsunebi_domain::RevisionId,
        path: &str,
        claimed: &FileClassification,
    ) -> Result<(), ApplicationError> {
        kitsunebi_gameap::validate_relative_path(path)
            .map_err(|_| ApplicationError::Conflict("invalid file path"))?;
        if matches!(
            claimed,
            FileClassification::Secret | FileClassification::State | FileClassification::Unknown
        ) {
            return Err(ApplicationError::Conflict(
                "file classification is not writable",
            ));
        }
        let revision = self
            .storage
            .get_revision(revision_id)
            .await
            .map_err(|_| ApplicationError::NotFound("cluster revision"))?
            .ok_or(ApplicationError::NotFound("cluster revision"))?;
        let baseline = self
            .storage
            .get_config_baseline(revision.config_baseline)
            .await
            .map_err(|_| ApplicationError::Conflict("config baseline unavailable"))?
            .ok_or(ApplicationError::Conflict("config baseline unavailable"))?;
        Self::validate_baseline_entry(&baseline, path, claimed)
    }
    fn validate_baseline_entry(
        baseline: &kitsunebi_domain::ConfigBaseline,
        path: &str,
        claimed: &FileClassification,
    ) -> Result<(), ApplicationError> {
        let entry = baseline
            .files
            .iter()
            .find(|entry| entry.path == path)
            .ok_or(ApplicationError::Conflict(
                "file is not declared in baseline",
            ))?;
        if &entry.classification != claimed {
            return Err(ApplicationError::Conflict(
                "file classification does not match baseline",
            ));
        }
        Ok(())
    }
    async fn capture_file_inverse(
        &self,
        binding: &GameAPBinding,
        path: &str,
        target_path: Option<&str>,
    ) -> Result<application::FileInverse, ApplicationError> {
        let (prior_exists, prior_digest, prior_size) =
            self.capture_file_state(binding, path).await?;
        let (target_digest, target_size) = if let Some(target) = target_path {
            let (exists, digest, size) = self.capture_file_state(binding, target).await?;
            if exists { (digest, size) } else { (None, None) }
        } else {
            (None, None)
        };
        Ok(application::FileInverse {
            binding_id: self.binding_id_for(binding).await?,
            path: path.to_owned(),
            prior_digest,
            prior_size,
            prior_exists,
            target_path: target_path.map(str::to_owned),
            target_digest,
            target_size,
        })
    }
    async fn capture_file_state(
        &self,
        binding: &GameAPBinding,
        path: &str,
    ) -> Result<(bool, Option<String>, Option<u64>), ApplicationError> {
        let Some((digest, size)) = self.execution.observe_file_optional(binding, path).await?
        else {
            return Ok((false, None, None));
        };
        let bytes = self.execution.read_file(binding, path).await?;
        if Self::hash(&bytes) != digest || bytes.len() as u64 != size {
            return Err(ApplicationError::VerificationFailed(
                "file observation changed during capture".into(),
            ));
        }
        self.artifacts.put(&digest, &bytes).await?;
        Ok((true, Some(digest), Some(size)))
    }
    async fn world_version(
        &self,
        world: kitsunebi_domain::WorldId,
    ) -> Result<u64, ApplicationError> {
        sqlx::query_scalar("SELECT version FROM worlds WHERE id = ?")
            .bind(world.as_uuid().to_string())
            .fetch_optional(self.storage.pool())
            .await
            .map_err(|_| ApplicationError::NotFound("world"))?
            .ok_or(ApplicationError::NotFound("world"))
    }
    async fn route_version(
        &self,
        route: kitsunebi_domain::RouteId,
    ) -> Result<u64, ApplicationError> {
        sqlx::query_scalar("SELECT version FROM routes WHERE id = ?")
            .bind(route.as_uuid().to_string())
            .fetch_optional(self.storage.pool())
            .await
            .map_err(|_| ApplicationError::NotFound("route"))?
            .ok_or(ApplicationError::NotFound("route"))
    }
    async fn restore_inverse(
        &self,
        binding: &GameAPBinding,
        inverse: &application::FileInverse,
        classification: FileClassification,
        expected_current_digest: &str,
    ) -> Result<(), ApplicationError> {
        if !inverse.prior_exists {
            self.execution
                .delete_file_checked(binding, &inverse.path, expected_current_digest)
                .await
                .map_err(|_| {
                    ApplicationError::RollbackConflict("file changed before rollback".into())
                })?;
            return Ok(());
        }
        let current = self.execution.read_file(binding, &inverse.path).await?;
        if Self::hash(&current) != expected_current_digest {
            return Err(ApplicationError::RollbackConflict(
                "file changed before rollback".into(),
            ));
        }
        let digest = inverse
            .prior_digest
            .as_deref()
            .ok_or(ApplicationError::RollbackConflict(
                "file inverse has no prior bytes".into(),
            ))?;
        let bytes = self.file_bytes(digest).await?;
        if Some(bytes.len() as u64) != inverse.prior_size {
            return Err(ApplicationError::VerificationFailed(
                "file inverse size mismatch".into(),
            ));
        }
        self.execution
            .restore_file_snapshot(
                binding,
                &FileRestoreSnapshot {
                    path: inverse.path.clone(),
                    bytes,
                    digest: digest.to_owned(),
                    classification,
                },
            )
            .await
    }
    async fn restore_inverse_bytes(
        &self,
        binding: &GameAPBinding,
        path: &str,
        digest: &str,
        size: Option<u64>,
        classification: FileClassification,
    ) -> Result<(), ApplicationError> {
        let bytes = self.file_bytes(digest).await?;
        if Some(bytes.len() as u64) != size {
            return Err(ApplicationError::VerificationFailed(
                "file inverse size mismatch".into(),
            ));
        }
        self.execution
            .restore_file_snapshot(
                binding,
                &FileRestoreSnapshot {
                    path: path.to_owned(),
                    bytes,
                    digest: digest.to_owned(),
                    classification,
                },
            )
            .await
    }
    async fn restore_inverse_bytes_checked(
        &self,
        binding: &GameAPBinding,
        path: &str,
        digest: &str,
        size: Option<u64>,
        classification: FileClassification,
        expected_current_digest: &str,
    ) -> Result<(), ApplicationError> {
        let current = self.execution.read_file(binding, path).await?;
        if Self::hash(&current) != expected_current_digest {
            return Err(ApplicationError::RollbackConflict(
                "file changed before rollback".into(),
            ));
        }
        self.restore_inverse_bytes(binding, path, digest, size, classification)
            .await
    }
    async fn observe_file(
        &self,
        binding: &GameAPBinding,
        path: &str,
    ) -> Result<String, ApplicationError> {
        Ok(Self::hash(&self.execution.read_file(binding, path).await?))
    }
    async fn ensure_placement(&self, binding: &GameAPBinding) -> Result<(), ApplicationError> {
        self.execution.observe_node_capability(binding).await?;
        let matches = self
            .storage
            .list_gameap_bindings()
            .await
            .map_err(|_| ApplicationError::NotFound("gameap binding"))?
            .into_iter()
            .filter(|candidate| candidate.fingerprint() == binding.fingerprint())
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(ApplicationError::Conflict(
                "gameap binding fingerprint is ambiguous",
            ));
        }
        let row =
            sqlx::query("SELECT id FROM gameap_bindings WHERE execution_unit_ref = ? ORDER BY id")
                .bind(&binding.execution_unit_id)
                .fetch_all(self.storage.pool())
                .await
                .map_err(|_| ApplicationError::NotFound("gameap binding"))?;
        if row.len() != 1 {
            return Err(ApplicationError::Conflict(
                "gameap binding identifier is ambiguous",
            ));
        }
        let binding_id: String = sqlx::Row::try_get(&row[0], "id")
            .map_err(|_| ApplicationError::NotFound("gameap binding"))?;
        let binding_id = Uuid::parse_str(&binding_id)
            .map(BindingId::from_uuid)
            .map_err(|_| ApplicationError::NotFound("gameap binding"))?;
        let cluster = self
            .storage
            .resolve_gameap_binding_cluster(binding_id.as_uuid())
            .await
            .map_err(|_| ApplicationError::NotFound("binding cluster"))?
            .ok_or(ApplicationError::Conflict("binding cluster is unknown"))?;
        let cluster = self
            .storage
            .get_cluster(cluster)
            .await
            .map_err(|_| ApplicationError::NotFound("cluster"))?
            .ok_or(ApplicationError::NotFound("cluster"))?;
        let revision_id = cluster
            .current_revision
            .ok_or(ApplicationError::Conflict("cluster placement is unknown"))?;
        let revision = self
            .storage
            .get_revision(revision_id)
            .await
            .map_err(|_| ApplicationError::NotFound("cluster revision"))?
            .ok_or(ApplicationError::NotFound("cluster revision"))?;
        let requirements = revision
            .typed_placement_requirements()
            .map_err(|_| ApplicationError::Conflict("invalid placement requirements"))?;
        let observation = self
            .storage
            .latest_node_capability(&binding.node_id)
            .await
            .map_err(|_| ApplicationError::Conflict("node capability observation unavailable"))?
            .ok_or(ApplicationError::Conflict(
                "node capability observation unknown",
            ))?;
        application::validate_placement(&requirements, &observation)
    }
    async fn world_binding(
        &self,
        world: kitsunebi_domain::WorldId,
        binding_id: kitsunebi_domain::BindingId,
        expected_cluster: Option<kitsunebi_domain::ClusterId>,
    ) -> Result<GameAPBinding, ApplicationError> {
        let binding = self
            .storage
            .get_gameap_binding(binding_id.as_uuid())
            .await
            .map_err(|_| ApplicationError::NotFound("world GameAP binding"))?
            .ok_or(ApplicationError::NotFound("world GameAP binding"))?;
        if !matches!(binding.target, kitsunebi_domain::GameAPBindingTarget::World(id) if id == world)
        {
            return Err(ApplicationError::Conflict("world binding target mismatch"));
        }
        let cluster = self
            .storage
            .resolve_gameap_binding_cluster(binding_id.as_uuid())
            .await
            .map_err(|_| ApplicationError::NotFound("world binding cluster"))?
            .ok_or(ApplicationError::Conflict("world binding cluster unknown"))?;
        if expected_cluster.is_some_and(|expected| expected != cluster) {
            return Err(ApplicationError::StalePlan);
        }
        Ok(binding)
    }
    async fn apply_file_write(
        &self,
        binding: &GameAPBinding,
        change: &FileChange,
        content: &StagedContentRef,
        expected_before: &Option<String>,
    ) -> Result<StepObservation, ApplicationError> {
        self.validate_declared_file(binding, &change.path, &change.classification)
            .await?;
        let before = self.observe_file(binding, &change.path).await?;
        if expected_before
            .as_deref()
            .is_some_and(|expected| expected != before)
        {
            return Err(ApplicationError::StalePlan);
        }
        let bytes = self.file_bytes(&content.digest).await?;
        if bytes.len() as u64 != content.size || Self::hash(&bytes) != change.content_digest {
            return Err(ApplicationError::VerificationFailed(
                "staged content does not match step".into(),
            ));
        }
        if matches!(change.classification, FileClassification::Artifact) {
            self.execution.upload(binding, change, &bytes).await?;
        } else {
            let text = std::str::from_utf8(&bytes).map_err(|_| {
                ApplicationError::VerificationFailed("text content is not UTF-8".into())
            })?;
            self.execution
                .write_file(binding, change, text.as_bytes())
                .await?;
        }
        let after = self.observe_file(binding, &change.path).await?;
        if after != change.content_digest {
            return Err(ApplicationError::VerificationFailed(
                "file postcondition mismatch".into(),
            ));
        }
        Ok(StepObservation {
            state_hash: after,
            completed: true,
            unambiguous: true,
        })
    }
    async fn proxy_bindings(
        &self,
        expected_instance: kitsunebi_domain::ProxyInstanceId,
        target_instance: kitsunebi_domain::ProxyInstanceId,
        pool: kitsunebi_domain::ProxyPoolId,
        binding: &GameAPBinding,
        target_binding_id: kitsunebi_domain::BindingId,
    ) -> Result<
        (
            ProxyEdgeBinding,
            ProxyEdgeBinding,
            ServiceId,
            GameAPBinding,
            GameAPBinding,
        ),
        ApplicationError,
    > {
        let edge_set = self
            .storage
            .get_tcp_shield_backend_set(pool)
            .await
            .map_err(|_| ApplicationError::NotFound("TCPShield backend set"))?
            .ok_or(ApplicationError::NotFound("TCPShield backend set"))?;
        let new_row = self
            .storage
            .get_proxy_instance_binding(target_instance)
            .await
            .map_err(|_| ApplicationError::NotFound("proxy instance binding"))?
            .ok_or(ApplicationError::NotFound("proxy instance binding"))?;
        let old = self
            .storage
            .get_proxy_instance(expected_instance)
            .await
            .map_err(|_| ApplicationError::NotFound("proxy instance"))?
            .ok_or(ApplicationError::NotFound("proxy instance"))?;
        let target = self
            .storage
            .get_proxy_instance(target_instance)
            .await
            .map_err(|_| ApplicationError::NotFound("proxy instance"))?
            .ok_or(ApplicationError::NotFound("proxy instance"))?;
        if old.pool_id != pool || target.pool_id != pool || target_instance == expected_instance {
            return Err(ApplicationError::Conflict("proxy instance scope mismatch"));
        }
        let old_row = self
            .storage
            .get_proxy_instance_binding(old.id)
            .await
            .map_err(|_| ApplicationError::NotFound("proxy instance binding"))?
            .ok_or(ApplicationError::NotFound("proxy instance binding"))?;
        if new_row.gameap_binding_id != target_binding_id {
            return Err(ApplicationError::Conflict(
                "proxy target binding does not belong to target instance",
            ));
        }
        let services = self
            .storage
            .resource_service_scope(ResourceKind::ProxyPool, pool.as_uuid())
            .await
            .map_err(|_| ApplicationError::NotFound("proxy pool scope"))?;
        if services.len() != 1 {
            return Err(ApplicationError::Conflict(
                "proxy pool ownership is ambiguous",
            ));
        }
        let service = services[0];
        let persisted_binding = self
            .storage
            .get_gameap_binding(target_binding_id.as_uuid())
            .await
            .map_err(|_| ApplicationError::NotFound("proxy target binding"))?
            .ok_or(ApplicationError::NotFound("proxy target binding"))?;
        if persisted_binding.fingerprint() != binding.fingerprint()
            || !matches!(binding.target, kitsunebi_domain::GameAPBindingTarget::ProxyInstance(id) if id == target_instance)
        {
            return Err(ApplicationError::Conflict("proxy binding target mismatch"));
        }
        let target_execution = persisted_binding;
        let old_execution = self
            .storage
            .get_gameap_binding(old_row.gameap_binding_id.as_uuid())
            .await
            .map_err(|_| ApplicationError::NotFound("proxy old GameAP binding"))?
            .ok_or(ApplicationError::NotFound("proxy old GameAP binding"))?;
        if !matches!(
            old_execution.target,
            kitsunebi_domain::GameAPBindingTarget::ProxyInstance(id) if id == old.id
        ) {
            return Err(ApplicationError::Conflict(
                "proxy old binding target mismatch",
            ));
        }
        let tcp_shield = self
            .tcp_shield
            .as_ref()
            .ok_or(ApplicationError::Port("TCPShield is unavailable".into()))?;
        let backend_set_id = edge_set
            .backend_set_id
            .parse::<u64>()
            .map_err(|_| ApplicationError::Conflict("proxy backend set id is not numeric"))?;
        let observed_hash = tcp_shield
            .edge
            .client
            .observe(tcp_shield.edge.network_id, backend_set_id)
            .await
            .map_err(TcpShieldBridge::map_error)?
            .hash();
        let target_cluster = self
            .storage
            .resolve_gameap_binding_cluster(target_binding_id.as_uuid())
            .await
            .map_err(|_| ApplicationError::NotFound("proxy target cluster"))?
            .ok_or(ApplicationError::NotFound("proxy target cluster"))?;
        let revision = self
            .storage
            .get_cluster(target_cluster)
            .await
            .map_err(|_| ApplicationError::NotFound("proxy target cluster"))?
            .and_then(|cluster| cluster.current_revision)
            .ok_or(ApplicationError::Conflict(
                "proxy target revision is unknown",
            ))?;
        let make = |instance_id, address, observed_hash| ProxyEdgeBinding {
            instance_id,
            provider_network_id: edge_set.provider_network_id,
            domain_network_id: edge_set.domain_network_id,
            backend_set_id: edge_set.backend_set_id.clone(),
            backend_address: address,
            revision,
            observed_hash,
        };
        Ok((
            make(
                target_instance,
                new_row.backend_address,
                observed_hash.clone(),
            ),
            make(old.id, old_row.backend_address, observed_hash),
            service,
            target_execution,
            old_execution,
        ))
    }
}

impl ControllerStepPort {
    async fn proxy_execution_status(
        &self,
        binding: &GameAPBinding,
    ) -> Result<Option<ExecutionStatus>, ApplicationError> {
        match self.execution.status(binding).await {
            Ok(status) => Ok(Some(status)),
            Err(ApplicationError::NotFound(_)) => Ok(None),
            Err(error) => Err(error),
        }
    }

    async fn observe(
        &self,
        step: &OperationStep,
        evidence: Option<&StepEvidence>,
    ) -> Result<StepObservation, ApplicationError> {
        let needs_inverse = !matches!(
            step,
            OperationStep::ClusterRevisionCreate { .. }
                | OperationStep::ArtifactStage { .. }
                | OperationStep::ArtifactRegister { .. }
                | OperationStep::BackupCreate { .. }
                | OperationStep::BackupRestore { .. }
                | OperationStep::ServicePurge { .. }
        );
        if needs_inverse
            && evidence
                .and_then(|value| value.execution.as_ref())
                .is_none()
        {
            return Ok(StepObservation {
                state_hash: Self::hash(format!("{step:?}").as_bytes()),
                completed: false,
                unambiguous: true,
            });
        }
        match step {
            OperationStep::ExecutionProvision { binding } => {
                let status = self.execution.status(binding).await?;
                Ok(StepObservation {
                    state_hash: status.state_hash,
                    completed: true,
                    unambiguous: true,
                })
            }
            OperationStep::ServiceLifecycleTransition {
                service_id,
                next_state,
                ..
            } => {
                let service = self
                    .storage
                    .get_service(*service_id)
                    .await
                    .map_err(|_| ApplicationError::NotFound("service"))?
                    .ok_or(ApplicationError::NotFound("service"))?;
                let state_hash = Self::service_state_hash(&service);
                Ok(StepObservation {
                    completed: service.lifecycle == *next_state,
                    state_hash,
                    unambiguous: true,
                })
            }
            OperationStep::ClusterRevisionCreate {
                cluster, revision, ..
            } => {
                self.storage
                    .get_cluster(*cluster)
                    .await
                    .map_err(|_| ApplicationError::NotFound("cluster"))?
                    .ok_or(ApplicationError::NotFound("cluster"))?;
                let current = self
                    .storage
                    .get_revision(revision.id)
                    .await
                    .map_err(|_| ApplicationError::NotFound("cluster revision"))?;
                let state_hash = Self::hash(revision.id.as_uuid().as_bytes());
                Ok(StepObservation {
                    completed: current.is_some(),
                    state_hash,
                    unambiguous: true,
                })
            }
            OperationStep::ExecutionDelete {
                expected_state_hash,
                ..
            } => Ok(StepObservation {
                state_hash: expected_state_hash.clone(),
                completed: false,
                unambiguous: true,
            }),
            OperationStep::ExecutionStart { binding } => {
                let status = self.execution.status(binding).await?;
                Ok(StepObservation {
                    state_hash: status.state_hash,
                    completed: status.running,
                    unambiguous: true,
                })
            }
            OperationStep::ExecutionStop { binding } => {
                let status = self.execution.status(binding).await?;
                Ok(StepObservation {
                    state_hash: status.state_hash,
                    completed: !status.running,
                    unambiguous: true,
                })
            }
            OperationStep::ExecutionRestart { binding } => {
                let status = self.execution.status(binding).await?;
                Ok(StepObservation {
                    state_hash: status.state_hash,
                    completed: false,
                    unambiguous: true,
                })
            }
            OperationStep::FileWrite {
                binding,
                change,
                content,
                ..
            } => {
                let digest = self.observe_file(binding, &change.path).await?;
                Ok(StepObservation {
                    completed: digest == content.digest,
                    state_hash: digest,
                    unambiguous: true,
                })
            }
            OperationStep::FileMove {
                binding,
                to,
                expected_target_digest,
                ..
            } => {
                let digest = self.observe_file(binding, to).await?;
                Ok(StepObservation {
                    completed: expected_target_digest
                        .as_deref()
                        .is_some_and(|v| v == digest),
                    state_hash: digest,
                    unambiguous: true,
                })
            }
            OperationStep::FileQuarantine { binding, path, .. } => {
                let (state_hash, completed) = match self.observe_file(binding, path).await {
                    Ok(digest) => (digest, false),
                    Err(_) => (Self::hash(path.as_bytes()), true),
                };
                Ok(StepObservation {
                    state_hash,
                    completed,
                    unambiguous: true,
                })
            }
            OperationStep::FileBatch {
                binding,
                operations,
                ..
            } => {
                let mut hashes = Vec::with_capacity(operations.len());
                let mut complete = true;
                for operation in operations {
                    match operation {
                        FileBatchOperation::Write { path, content, .. } => {
                            let digest = self.observe_file(binding, path).await?;
                            complete &= digest == content.digest;
                            hashes.push(digest);
                        }
                        FileBatchOperation::Move {
                            to,
                            expected_target_digest,
                            ..
                        } => {
                            let digest = self.observe_file(binding, to).await?;
                            complete &= expected_target_digest
                                .as_deref()
                                .is_some_and(|v| v == digest);
                            hashes.push(digest);
                        }
                        FileBatchOperation::Quarantine { path, .. } => {
                            match self.observe_file(binding, path).await {
                                Ok(digest) => {
                                    complete = false;
                                    hashes.push(digest);
                                }
                                Err(_) => hashes.push(Self::hash(path.as_bytes())),
                            }
                        }
                    }
                }
                Ok(StepObservation {
                    state_hash: kitsunebi_api::plan_hash(hashes.join("|").as_bytes()),
                    completed: complete,
                    unambiguous: true,
                })
            }
            OperationStep::ArtifactStage {
                expected_digest, ..
            } => Ok(StepObservation {
                state_hash: expected_digest.clone(),
                completed: self.artifacts.has_digest(expected_digest).await?,
                unambiguous: true,
            }),
            OperationStep::ArtifactRegister {
                artifact, content, ..
            } => {
                let existing = self
                    .storage
                    .get_artifact(artifact.id)
                    .await
                    .map_err(|_| ApplicationError::NotFound("artifact"))?;
                let staged = self.artifacts.has_digest(&content.digest).await?;
                Ok(StepObservation {
                    completed: existing.as_ref().is_some_and(|value| {
                        value.digest == artifact.digest && value.id == artifact.id
                    }) && staged,
                    state_hash: Self::hash(
                        format!("{}:{}", artifact.id.as_uuid(), artifact.digest).as_bytes(),
                    ),
                    unambiguous: true,
                })
            }
            OperationStep::ArtifactActivate {
                binding,
                cluster,
                destination_path,
                target_revision,
                expected_digest,
                ..
            } => {
                let current = self
                    .storage
                    .get_cluster(*cluster)
                    .await
                    .map_err(|_| ApplicationError::NotFound("cluster"))?
                    .ok_or(ApplicationError::NotFound("cluster"))?;
                let file_digest = self.observe_file(binding, destination_path).await?;
                let hash = current
                    .current_revision
                    .map(|id| id.as_uuid().to_string())
                    .unwrap_or_default();
                Ok(StepObservation {
                    completed: current.current_revision == Some(*target_revision)
                        && file_digest == *expected_digest,
                    state_hash: Self::hash(format!("{hash}:{file_digest}").as_bytes()),
                    unambiguous: true,
                })
            }
            OperationStep::ProxyRollout {
                expected_instance,
                target_instance,
                pool,
                binding,
                target_binding_id,
                desired_state,
                configuration,
                ..
            } => {
                let edge = self
                    .tcp_shield
                    .as_ref()
                    .ok_or(ApplicationError::Port("TCPShield is unavailable".into()))?;
                let (new, old, _, target_execution, old_execution) = self
                    .proxy_bindings(
                        *expected_instance,
                        *target_instance,
                        *pool,
                        binding,
                        *target_binding_id,
                    )
                    .await?;
                let expected_final_hash = match evidence.and_then(|item| item.execution.as_ref()) {
                    Some(StepExecutionEvidence::Proxy {
                        final_edge_hash, ..
                    }) => Some(final_edge_hash),
                    Some(_) => return Err(ApplicationError::StalePlan),
                    None => None,
                };
                let state = edge.edge.observe_set(&new).await?;
                let edge_hash = state.hash();
                let target_status = self.proxy_execution_status(&target_execution).await?;
                let old_status = self.proxy_execution_status(&old_execution).await?;
                let mut configuration_hashes = Vec::with_capacity(configuration.len());
                let mut configuration_complete = true;
                for operation in configuration {
                    let FileBatchOperation::Write { path, content, .. } = operation else {
                        return Err(ApplicationError::StalePlan);
                    };
                    let observed = self
                        .execution
                        .observe_file_optional(&target_execution, path)
                        .await?;
                    match observed {
                        Some((digest, _)) => {
                            configuration_complete &= digest == content.digest;
                            configuration_hashes.push(digest);
                        }
                        None => {
                            configuration_complete = false;
                            configuration_hashes.push("absent".into());
                        }
                    }
                }
                let target_running = target_status.as_ref().is_some_and(|status| status.running);
                let old_running = old_status.as_ref().is_some_and(|status| status.running);
                let target_state_hash = target_status
                    .as_ref()
                    .map(|status| status.state_hash.as_str())
                    .unwrap_or("absent");
                let old_state_hash = old_status
                    .as_ref()
                    .map(|status| status.state_hash.as_str())
                    .unwrap_or("absent");
                let state_material = format!(
                    "edge={edge_hash}:target={target_state_hash}:{target_running}:old={old_state_hash}:{old_running}:config={}",
                    configuration_hashes.join(",")
                );
                let state_hash = Self::hash(state_material.as_bytes());
                let completed = state.backends.contains(&new.backend_address)
                    && !state.backends.contains(&old.backend_address)
                    && expected_final_hash.is_none_or(|expected| edge_hash == *expected)
                    && target_status.as_ref().is_some_and(|status| status.running)
                    && old_status.as_ref().is_some_and(|status| !status.running)
                    && configuration_complete
                    && self
                        .storage
                        .get_proxy_instance(*target_instance)
                        .await
                        .map_err(|_| ApplicationError::NotFound("proxy instance"))?
                        .is_some_and(|row| row.state == *desired_state)
                    && self
                        .storage
                        .get_proxy_instance(*expected_instance)
                        .await
                        .map_err(|_| ApplicationError::NotFound("proxy instance"))?
                        .is_some_and(|row| row.state == kitsunebi_domain::ProxyState::Stopped);
                Ok(StepObservation {
                    state_hash: Self::hash(
                        format!("{}:{}", state_hash, target_binding_id.as_uuid()).as_bytes(),
                    ),
                    completed,
                    unambiguous: true,
                })
            }
            OperationStep::WorldWriterCutover {
                world: world_id,
                to,
                target_writer_binding_id,
                ..
            } => {
                let world = self
                    .storage
                    .get_world(*world_id)
                    .await
                    .map_err(|_| ApplicationError::NotFound("world"))?
                    .ok_or(ApplicationError::NotFound("world"))?;
                let digest = Self::hash(
                    serde_json::to_string(&world.current_writers)
                        .unwrap_or_default()
                        .as_bytes(),
                );
                let target_running = match self
                    .world_binding(*world_id, *target_writer_binding_id, Some(*to))
                    .await
                {
                    Ok(binding) => self.execution.status(&binding).await?.running,
                    Err(_) => false,
                };
                Ok(StepObservation {
                    completed: world.current_writers == vec![*to] && target_running,
                    state_hash: Self::hash(format!("{}:{}", digest, target_running).as_bytes()),
                    unambiguous: true,
                })
            }
            OperationStep::EndpointReconnect {
                expected_binding_id,
                target_binding_id,
                cluster,
                expected_revision,
                target_revision,
                runtime_binding_ids,
                ..
            } => {
                let Some(StepExecutionEvidence::Endpoint {
                    expected_binding_id: evidence_expected,
                    target_binding_id: evidence_target,
                    prior_binding,
                    target_binding,
                    runtime,
                    ..
                }) = evidence.and_then(|item| item.execution.as_ref())
                else {
                    return Ok(StepObservation {
                        state_hash: Self::hash(format!("{step:?}").as_bytes()),
                        completed: false,
                        unambiguous: true,
                    });
                };
                if evidence_expected != expected_binding_id
                    || evidence_target != target_binding_id
                    || runtime.len() != runtime_binding_ids.len()
                    || !Self::endpoint_binding_pair_matches(
                        prior_binding,
                        target_binding,
                        *cluster,
                        *expected_revision,
                        *target_revision,
                        *expected_binding_id,
                        *target_binding_id,
                    )
                {
                    return Err(ApplicationError::StalePlan);
                }
                let current = self
                    .storage
                    .get_cluster(*cluster)
                    .await
                    .map_err(|_| ApplicationError::NotFound("endpoint cluster"))?
                    .ok_or(ApplicationError::NotFound("endpoint cluster"))?;
                let endpoint = self
                    .storage
                    .list_endpoints()
                    .await
                    .map_err(|_| ApplicationError::NotFound("external endpoint"))?
                    .into_iter()
                    .find(|item| item.id == target_binding.endpoint_id)
                    .ok_or(ApplicationError::NotFound("target external endpoint"))?;
                let mut addresses = SystemDnsResolver
                    .resolve(&endpoint.logical_hostname, endpoint.port)
                    .await?;
                addresses.sort();
                addresses.dedup();
                TcpShieldHealth
                    .verify(&format!("{}:{}", endpoint.logical_hostname, endpoint.port))
                    .await?;
                let mut runtime_state = Vec::with_capacity(runtime.len());
                let mut runtime_complete = true;
                for observation in runtime {
                    if !runtime_binding_ids.contains(&observation.binding_id) {
                        return Err(ApplicationError::StalePlan);
                    }
                    let binding = self
                        .storage
                        .get_gameap_binding(observation.binding_id.as_uuid())
                        .await
                        .map_err(|_| ApplicationError::NotFound("endpoint runtime binding"))?
                        .ok_or(ApplicationError::NotFound("endpoint runtime binding"))?;
                    let resolved_cluster = self
                        .storage
                        .resolve_gameap_binding_cluster(observation.binding_id.as_uuid())
                        .await
                        .map_err(|_| ApplicationError::NotFound("endpoint runtime cluster"))?
                        .ok_or(ApplicationError::Conflict(
                            "endpoint runtime binding cluster unknown",
                        ))?;
                    if resolved_cluster != *cluster {
                        return Err(ApplicationError::Conflict(
                            "endpoint runtime binding is outside endpoint cluster",
                        ));
                    }
                    let status = self.execution.status(&binding).await?;
                    runtime_complete &= status.running == observation.prior_running;
                    runtime_state.push(format!(
                        "{}:{}:{}",
                        observation.binding_id.as_uuid(),
                        status.running,
                        status.state_hash
                    ));
                }
                runtime_state.sort();
                let state_hash = Self::hash(
                    format!(
                        "{}:{}:{}:{}",
                        current
                            .current_revision
                            .map(|revision| revision.as_uuid().to_string())
                            .unwrap_or_default(),
                        target_binding.id.as_uuid(),
                        addresses.join(","),
                        runtime_state.join("|")
                    )
                    .as_bytes(),
                );
                Ok(StepObservation {
                    completed: Self::endpoint_reconnect_complete(
                        current.current_revision,
                        *target_revision,
                        runtime_complete,
                        true,
                    ),
                    state_hash,
                    unambiguous: true,
                })
            }
            OperationStep::AccessPolicyUpdate {
                policy_id,
                desired_policy_hash,
                ..
            } => {
                let policy = self
                    .storage
                    .get_access_policy(*policy_id)
                    .await
                    .map_err(|_| ApplicationError::NotFound("access policy"))?
                    .ok_or(ApplicationError::NotFound("access policy"))?;
                let hash = Self::hash(&serde_json::to_vec(&policy.grants).unwrap_or_default());
                Ok(StepObservation {
                    completed: hash == *desired_policy_hash,
                    state_hash: hash,
                    unambiguous: true,
                })
            }
            OperationStep::RoutePolicyUpdate {
                route_id,
                target_cluster,
                target_priority,
                disabled,
                ..
            } => {
                let route = self
                    .storage
                    .get_route(*route_id)
                    .await
                    .map_err(|_| ApplicationError::NotFound("route"))?
                    .ok_or(ApplicationError::NotFound("route"))?;
                let state_hash = Self::hash(
                    format!(
                        "{}:{}:{}",
                        route.target_cluster.as_uuid(),
                        route.priority,
                        route.disabled
                    )
                    .as_bytes(),
                );
                Ok(StepObservation {
                    completed: route.target_cluster == *target_cluster
                        && route.priority == *target_priority
                        && route.disabled == *disabled,
                    state_hash,
                    unambiguous: true,
                })
            }
            OperationStep::ServiceArchive { service_id, .. } => {
                let service = self
                    .storage
                    .get_service(*service_id)
                    .await
                    .map_err(|_| ApplicationError::NotFound("service"))?
                    .ok_or(ApplicationError::NotFound("service"))?;
                let state = format!("{service:?}");
                Ok(StepObservation {
                    completed: service.lifecycle == kitsunebi_domain::ServiceLifecycle::Archived,
                    state_hash: Self::hash(state.as_bytes()),
                    unambiguous: true,
                })
            }
            OperationStep::ServicePurge { service_id, .. } => {
                let service = self
                    .storage
                    .get_service(*service_id)
                    .await
                    .map_err(|_| ApplicationError::NotFound("service"))?
                    .ok_or(ApplicationError::NotFound("service"))?;
                let purged = service.lifecycle == kitsunebi_domain::ServiceLifecycle::Archived
                    && serde_json::from_str::<serde_json::Value>(&service.metadata)
                        .ok()
                        .and_then(|value| value.get("purged").and_then(|value| value.as_bool()))
                        == Some(true);
                Ok(StepObservation {
                    state_hash: Self::service_state_hash(&service),
                    completed: purged,
                    unambiguous: true,
                })
            }
            OperationStep::BackupCreate { request_hash, .. } => Ok(StepObservation {
                state_hash: request_hash.clone(),
                completed: false,
                unambiguous: true,
            }),
            OperationStep::BackupRestore { .. } => self.observe_restore(step, None).await,
        }
    }

    async fn observe_backup(
        &self,
        step: &OperationStep,
        evidence: Option<&StepEvidence>,
    ) -> Result<StepObservation, ApplicationError> {
        let OperationStep::BackupCreate { kind, target, .. } = step else {
            return self.observe(step, evidence).await;
        };
        let Some(reference) = evidence.and_then(|item| match item.execution.as_ref() {
            Some(StepExecutionEvidence::BackupCreate(reference)) => Some(reference),
            _ => None,
        }) else {
            return Ok(StepObservation {
                state_hash: Self::hash(format!("{kind:?}:{target:?}").as_bytes()),
                completed: false,
                unambiguous: true,
            });
        };
        if reference.kind != *kind || reference.target != *target {
            return Err(ApplicationError::StalePlan);
        }
        let observation = self.backup.verify(reference).await?;
        Ok(StepObservation {
            state_hash: observation.manifest_digest,
            completed: true,
            unambiguous: true,
        })
    }

    async fn observe_restore(
        &self,
        step: &OperationStep,
        evidence: Option<&StepEvidence>,
    ) -> Result<StepObservation, ApplicationError> {
        let OperationStep::BackupRestore {
            expected_manifest_digest,
            ..
        } = step
        else {
            return Err(ApplicationError::Conflict(
                "restore observation requires a restore step",
            ));
        };
        let Some(invocation) = evidence.and_then(|item| match item.execution.as_ref() {
            Some(StepExecutionEvidence::BackupRestore(invocation)) => Some(invocation),
            None
            | Some(
                StepExecutionEvidence::BackupCreate(_)
                | StepExecutionEvidence::File { .. }
                | StepExecutionEvidence::FileBatch { .. }
                | StepExecutionEvidence::Execution { .. }
                | StepExecutionEvidence::Lifecycle { .. }
                | StepExecutionEvidence::Artifact { .. }
                | StepExecutionEvidence::Proxy { .. }
                | StepExecutionEvidence::World { .. }
                | StepExecutionEvidence::Endpoint { .. }
                | StepExecutionEvidence::Access { .. }
                | StepExecutionEvidence::Route { .. }
                | StepExecutionEvidence::Noop,
            ) => None,
        }) else {
            return Ok(StepObservation {
                state_hash: expected_manifest_digest.clone(),
                completed: false,
                unambiguous: true,
            });
        };
        if invocation.expected_manifest_digest != *expected_manifest_digest {
            return Err(ApplicationError::Conflict(
                "restore evidence digest mismatch",
            ));
        }
        let observation = self.backup.verify_restore(invocation).await?;
        if observation.manifest_digest != *expected_manifest_digest {
            return Err(ApplicationError::VerificationFailed(
                "restore manifest digest mismatch".into(),
            ));
        }
        Ok(StepObservation {
            state_hash: observation.manifest_digest,
            completed: true,
            unambiguous: true,
        })
    }

    async fn prepare(
        &self,
        step: &OperationStep,
    ) -> Result<Option<StepExecutionEvidence>, ApplicationError> {
        match step {
            OperationStep::ExecutionProvision { binding }
            | OperationStep::ExecutionStart { binding }
            | OperationStep::ExecutionStop { binding }
            | OperationStep::ExecutionRestart { binding } => {
                self.ensure_placement(binding).await?;
                let binding_id = self.binding_id_for(binding).await?;
                let (prior_state_hash, prior_running, prior_exists) =
                    match self.execution.status(binding).await {
                        Ok(status) => (status.state_hash, status.running, true),
                        Err(_) => (Self::hash(b"absent"), false, false),
                    };
                Ok(Some(StepExecutionEvidence::Execution {
                    binding_id,
                    prior_state_hash,
                    prior_running,
                    prior_exists,
                    prior_binding: Some(binding.clone()),
                    created_provider_unit: Some(binding.execution_unit_id.clone()),
                    provider_idempotency_key: Self::hash(binding.fingerprint().as_bytes()),
                }))
            }
            OperationStep::ExecutionDelete {
                binding,
                expected_state_hash,
                ..
            } => {
                self.ensure_placement(binding).await?;
                let binding_id = self.binding_id_for(binding).await?;
                let status = self.execution.status(binding).await?;
                if status.state_hash != *expected_state_hash {
                    return Err(ApplicationError::StalePlan);
                }
                Ok(Some(StepExecutionEvidence::Execution {
                    binding_id,
                    prior_state_hash: status.state_hash,
                    prior_running: status.running,
                    prior_exists: true,
                    prior_binding: Some(binding.clone()),
                    created_provider_unit: Some(binding.execution_unit_id.clone()),
                    provider_idempotency_key: Self::hash(binding.fingerprint().as_bytes()),
                }))
            }
            OperationStep::ServiceLifecycleTransition { service_id, .. }
            | OperationStep::ServiceArchive { service_id, .. } => {
                let service = self
                    .storage
                    .get_service(*service_id)
                    .await
                    .map_err(|_| ApplicationError::NotFound("service"))?
                    .ok_or(ApplicationError::NotFound("service"))?;
                Ok(Some(StepExecutionEvidence::Lifecycle {
                    service_id: *service_id,
                    prior_state: service.lifecycle,
                }))
            }
            OperationStep::FileWrite {
                binding, change, ..
            } => {
                self.ensure_placement(binding).await?;
                self.validate_declared_file(binding, &change.path, &change.classification)
                    .await?;
                Ok(Some(StepExecutionEvidence::File {
                    inverse: self
                        .capture_file_inverse(binding, &change.path, None)
                        .await?,
                }))
            }
            OperationStep::FileMove {
                binding,
                from,
                to,
                classification,
                ..
            } => {
                self.ensure_placement(binding).await?;
                self.validate_declared_file(binding, from, classification)
                    .await?;
                self.validate_declared_file(binding, to, classification)
                    .await?;
                Ok(Some(StepExecutionEvidence::File {
                    inverse: self.capture_file_inverse(binding, from, Some(to)).await?,
                }))
            }
            OperationStep::FileQuarantine {
                binding,
                path,
                classification,
                ..
            } => {
                self.ensure_placement(binding).await?;
                self.validate_declared_file(binding, path, classification)
                    .await?;
                let target = GameApExecutionBackend::quarantine_path(path);
                Ok(Some(StepExecutionEvidence::File {
                    inverse: self
                        .capture_file_inverse(binding, path, Some(&target))
                        .await?,
                }))
            }
            OperationStep::FileBatch {
                binding,
                operations,
                ..
            } => {
                self.ensure_placement(binding).await?;
                let mut entries = Vec::with_capacity(operations.len());
                for operation in operations {
                    let inverse = match operation {
                        FileBatchOperation::Write {
                            path,
                            classification,
                            ..
                        } => {
                            self.validate_declared_file(binding, path, classification)
                                .await?;
                            self.capture_file_inverse(binding, path, None).await?
                        }
                        FileBatchOperation::Move {
                            from,
                            to,
                            classification,
                            ..
                        } => {
                            self.validate_declared_file(binding, from, classification)
                                .await?;
                            self.validate_declared_file(binding, to, classification)
                                .await?;
                            self.capture_file_inverse(binding, from, Some(to)).await?
                        }
                        FileBatchOperation::Quarantine {
                            path,
                            classification,
                            ..
                        } => {
                            self.validate_declared_file(binding, path, classification)
                                .await?;
                            let target = GameApExecutionBackend::quarantine_path(path);
                            self.capture_file_inverse(binding, path, Some(&target))
                                .await?
                        }
                    };
                    entries.push(inverse);
                }
                Ok(Some(StepExecutionEvidence::FileBatch { entries }))
            }
            OperationStep::ArtifactActivate {
                binding_id,
                binding,
                cluster,
                destination_path,
                ..
            } => {
                self.ensure_placement(binding).await?;
                if self.binding_id_for(binding).await? != *binding_id {
                    return Err(ApplicationError::Conflict(
                        "artifact binding identity does not match persisted binding",
                    ));
                }
                let (prior_exists, prior_digest, prior_size) =
                    self.capture_file_state(binding, destination_path).await?;
                let cluster_row = self
                    .storage
                    .get_cluster(*cluster)
                    .await
                    .map_err(|_| ApplicationError::NotFound("cluster"))?
                    .ok_or(ApplicationError::NotFound("cluster"))?;
                Ok(Some(StepExecutionEvidence::Artifact {
                    binding_id: *binding_id,
                    cluster_id: *cluster,
                    prior_revision: cluster_row.current_revision,
                    destination_path: destination_path.clone(),
                    prior_digest,
                    prior_size,
                    prior_exists,
                }))
            }
            OperationStep::ProxyRollout {
                expected_instance,
                target_instance,
                pool,
                binding,
                target_binding_id,
                expected_instance_version,
                target_instance_version,
                expected_instance_state,
                target_instance_state,
                configuration,
                ..
            } => {
                self.ensure_placement(binding).await?;
                let edge = self
                    .tcp_shield
                    .as_ref()
                    .ok_or(ApplicationError::Port("TCPShield is unavailable".into()))?;
                let (new, old, _, target_execution, old_execution) = self
                    .proxy_bindings(
                        *expected_instance,
                        *target_instance,
                        *pool,
                        binding,
                        *target_binding_id,
                    )
                    .await?;
                let set = edge.edge.observe_set(&new).await?;
                let new_row = self
                    .storage
                    .get_proxy_instance(*target_instance)
                    .await
                    .map_err(|_| ApplicationError::NotFound("proxy instance"))?
                    .ok_or(ApplicationError::NotFound("proxy instance"))?;
                let old_id = old.instance_id;
                let old_row = self
                    .storage
                    .get_proxy_instance(old_id)
                    .await
                    .map_err(|_| ApplicationError::NotFound("proxy instance"))?
                    .ok_or(ApplicationError::NotFound("proxy instance"))?;
                if new_row.state != *target_instance_state
                    || old_row.state != *expected_instance_state
                {
                    return Err(ApplicationError::StalePlan);
                }
                let new_version: u64 =
                    sqlx::query_scalar("SELECT version FROM proxy_instances WHERE id = ?")
                        .bind(target_instance.as_uuid().to_string())
                        .fetch_one(self.storage.pool())
                        .await
                        .map_err(|_| ApplicationError::NotFound("proxy instance"))?;
                let old_version: u64 =
                    sqlx::query_scalar("SELECT version FROM proxy_instances WHERE id = ?")
                        .bind(old_id.as_uuid().to_string())
                        .fetch_one(self.storage.pool())
                        .await
                        .map_err(|_| ApplicationError::NotFound("proxy instance"))?;
                if new_version != *target_instance_version
                    || old_version != *expected_instance_version
                {
                    return Err(ApplicationError::StalePlan);
                }
                let target_status = self.proxy_execution_status(&target_execution).await?;
                let old_status = self.proxy_execution_status(&old_execution).await?;
                if old_status.is_none() {
                    return Err(ApplicationError::NotFound("proxy old GameAP execution"));
                }
                let target_execution_existed = target_status.is_some();
                if !target_execution_existed
                    && *target_instance_state != kitsunebi_domain::ProxyState::Preparing
                {
                    return Err(ApplicationError::StalePlan);
                }
                let target_execution_was_running =
                    target_status.as_ref().is_some_and(|status| status.running);
                if target_execution_was_running {
                    return Err(ApplicationError::StalePlan);
                }
                let target_execution_created = !target_execution_existed;
                let target_execution_started = !target_execution_was_running;
                let old_execution_was_running =
                    old_status.as_ref().is_some_and(|status| status.running);
                let mut configuration_inverse = Vec::with_capacity(configuration.len());
                for operation in configuration {
                    let FileBatchOperation::Write {
                        path,
                        classification,
                        ..
                    } = operation
                    else {
                        return Err(ApplicationError::Conflict(
                            "proxy configuration must contain writes",
                        ));
                    };
                    if *classification != FileClassification::MutableConfig {
                        return Err(ApplicationError::Conflict(
                            "proxy configuration must be mutable config",
                        ));
                    }
                    self.validate_declared_file(&target_execution, path, classification)
                        .await?;
                    configuration_inverse.push(
                        self.capture_file_inverse(&target_execution, path, None)
                            .await?,
                    );
                }
                if new.backend_address == old.backend_address
                    || !set.backends.contains(&old.backend_address)
                    || set.backends.contains(&new.backend_address)
                {
                    return Err(ApplicationError::StalePlan);
                }
                let prior_edge_hash = set.hash();
                let post_add_set = set
                    .add(&new.backend_address)
                    .map_err(|_| ApplicationError::Conflict("invalid proxy backend"))?;
                let post_add_edge_hash = post_add_set.hash();
                let final_edge_hash = post_add_set.remove(&old.backend_address).hash();
                Ok(Some(StepExecutionEvidence::Proxy {
                    expected_instance_id: *expected_instance,
                    target_instance_id: *target_instance,
                    prior_expected_state: old_row.state.clone(),
                    prior_expected_version: old_version,
                    prior_target_state: new_row.state,
                    prior_target_version: new_version,
                    prior_edge_hash,
                    prior_target_member: false,
                    new_state: kitsunebi_domain::ProxyState::Accepting,
                    new_version,
                    post_add_edge_hash,
                    final_edge_hash,
                    target_execution_existed,
                    target_execution_was_running,
                    target_execution_created,
                    target_execution_started,
                    old_execution_was_running,
                    configuration_inverse,
                }))
            }
            OperationStep::WorldWriterCutover {
                world,
                from,
                to,
                expected_writer_binding_id,
                target_writer_binding_id,
                expected_writer_binding_hash,
                target_writer_binding_hash,
                ..
            } => {
                let writers = self
                    .storage
                    .list_world_writers(*world)
                    .await
                    .map_err(|_| ApplicationError::NotFound("world writer"))?;
                let prior_writer = match from {
                    Some(cluster) if writers.as_slice() == [*cluster] => Some(*cluster),
                    None if writers.is_empty() => None,
                    _ => return Err(ApplicationError::StalePlan),
                };
                if let Some(binding_id) = expected_writer_binding_id {
                    let source = self.world_binding(*world, *binding_id, *from).await?;
                    if expected_writer_binding_hash.as_deref()
                        != Some(source.fingerprint().as_str())
                    {
                        return Err(ApplicationError::StalePlan);
                    }
                } else {
                    return Err(ApplicationError::Conflict(
                        "world source binding is required for a reversible cutover",
                    ));
                }
                let target = self
                    .world_binding(*world, *target_writer_binding_id, Some(*to))
                    .await?;
                if target.fingerprint() != *target_writer_binding_hash {
                    return Err(ApplicationError::StalePlan);
                }
                Ok(Some(StepExecutionEvidence::World {
                    world_id: *world,
                    prior_writer,
                    prior_version: self.world_version(*world).await?,
                    expected_writer_binding_id: *expected_writer_binding_id,
                    target_writer_binding_id: *target_writer_binding_id,
                    prior_writer_binding_hash: expected_writer_binding_hash.clone(),
                    target_writer_binding_hash: target_writer_binding_hash.clone(),
                }))
            }
            OperationStep::EndpointReconnect {
                expected_binding_id,
                target_binding_id,
                cluster,
                runtime_binding_ids,
                runtime_binding_hashes,
                ..
            } => {
                if runtime_binding_ids.len() != runtime_binding_hashes.len() {
                    return Err(ApplicationError::Conflict(
                        "endpoint runtime expectation cardinality mismatch",
                    ));
                }
                let prior_binding = self
                    .storage
                    .get_endpoint_binding(*expected_binding_id)
                    .await
                    .map_err(|_| ApplicationError::NotFound("endpoint binding"))?
                    .ok_or(ApplicationError::NotFound("endpoint binding"))?;
                Ok(Some(StepExecutionEvidence::Endpoint {
                    expected_binding_id: *expected_binding_id,
                    target_binding_id: *target_binding_id,
                    prior_revision: prior_binding.revision_id,
                    prior_binding,
                    target_binding: self
                        .storage
                        .get_endpoint_binding(*target_binding_id)
                        .await
                        .map_err(|_| ApplicationError::NotFound("target endpoint binding"))?
                        .ok_or(ApplicationError::NotFound("target endpoint binding"))?,
                    runtime: {
                        let mut observations = Vec::with_capacity(runtime_binding_ids.len());
                        for (binding_id, expected_hash) in
                            runtime_binding_ids.iter().zip(runtime_binding_hashes)
                        {
                            let binding = self
                                .storage
                                .get_gameap_binding(binding_id.as_uuid())
                                .await
                                .map_err(|_| {
                                    ApplicationError::NotFound("endpoint runtime binding")
                                })?
                                .ok_or(ApplicationError::NotFound("endpoint runtime binding"))?;
                            let resolved_cluster = self
                                .storage
                                .resolve_gameap_binding_cluster(binding_id.as_uuid())
                                .await
                                .map_err(|_| {
                                    ApplicationError::NotFound("endpoint runtime cluster")
                                })?
                                .ok_or(ApplicationError::Conflict(
                                    "endpoint runtime binding cluster unknown",
                                ))?;
                            if resolved_cluster != *cluster {
                                return Err(ApplicationError::Conflict(
                                    "endpoint runtime binding is outside endpoint cluster",
                                ));
                            }
                            let status = self.execution.status(&binding).await?;
                            if status.state_hash != *expected_hash {
                                return Err(ApplicationError::StalePlan);
                            }
                            observations.push(application::EndpointRuntimeObservation {
                                binding_id: *binding_id,
                                prior_running: status.running,
                                prior_state_hash: status.state_hash,
                            });
                        }
                        observations
                    },
                }))
            }
            OperationStep::AccessPolicyUpdate {
                policy_id,
                service_id,
                desired_grants,
                ..
            } => {
                self.validate_access_policy_update(*policy_id, *service_id, desired_grants)
                    .await?;
                let policy = self
                    .storage
                    .get_access_policy(*policy_id)
                    .await
                    .map_err(|_| ApplicationError::NotFound("access policy"))?
                    .ok_or(ApplicationError::NotFound("access policy"))?;
                Ok(Some(StepExecutionEvidence::Access {
                    policy_id: *policy_id,
                    prior_policy_hash: Self::hash(
                        &serde_json::to_vec(&policy.grants).unwrap_or_default(),
                    ),
                    prior_grants: policy.grants,
                }))
            }
            OperationStep::RoutePolicyUpdate { route_id, .. } => {
                let route = self
                    .storage
                    .get_route(*route_id)
                    .await
                    .map_err(|_| ApplicationError::NotFound("route"))?
                    .ok_or(ApplicationError::NotFound("route"))?;
                Ok(Some(StepExecutionEvidence::Route {
                    route_id: *route_id,
                    prior_cluster: route.target_cluster,
                    prior_priority: route.priority,
                    prior_disabled: route.disabled,
                    prior_version: self.route_version(*route_id).await?,
                }))
            }
            // These operations either have their own durable provider result or
            // are immutable registrations. They must not manufacture an
            // inverse that could later be mistaken for a rollback snapshot.
            OperationStep::ClusterRevisionCreate { .. }
            | OperationStep::ArtifactStage { .. }
            | OperationStep::ArtifactRegister { .. }
            | OperationStep::BackupCreate { .. }
            | OperationStep::BackupRestore { .. }
            | OperationStep::ServicePurge { .. } => Ok(None),
        }
    }

    async fn apply_restore(
        &self,
        step: &OperationStep,
    ) -> Result<BackupRestoreInvocation, ApplicationError> {
        let OperationStep::BackupRestore {
            session_id,
            plan_id,
            plan_expiry,
            idempotency_key,
            reference,
            target,
            expected_manifest_digest,
            rollback_reference,
            expected_rollback_manifest_digest,
            ..
        } = step
        else {
            return Err(ApplicationError::Conflict("restore step required"));
        };
        let backup = self
            .storage
            .get_backup_reference(*reference)
            .await
            .map_err(|_| ApplicationError::NotFound("backup reference"))?
            .ok_or(ApplicationError::NotFound("backup reference"))?;
        if backup.session_id != *session_id
            || backup.target != *target
            || backup.manifest_digest != *expected_manifest_digest
            || backup.verified_at.is_none()
        {
            return Err(ApplicationError::Conflict("backup restore scope mismatch"));
        }
        let rollback = self
            .storage
            .get_backup_reference(*rollback_reference)
            .await
            .map_err(|_| ApplicationError::NotFound("rollback backup reference"))?
            .ok_or(ApplicationError::NotFound("rollback backup reference"))?;
        if rollback.session_id != *session_id
            || rollback.target != *target
            || rollback.manifest_digest != *expected_rollback_manifest_digest
            || rollback.verified_at.is_none()
        {
            return Err(ApplicationError::Conflict("rollback backup scope mismatch"));
        }
        let invocation = self
            .backup
            .restore(&application::BackupRestoreRequest {
                session_id: *session_id,
                plan_id: *plan_id,
                plan_expiry: *plan_expiry,
                idempotency_key: idempotency_key.clone(),
                reference: backup,
                rollback_reference: rollback,
                target: *target,
            })
            .await?;
        if invocation.plan_id != *plan_id
            || invocation.reference_id != *reference
            || invocation.target != *target
            || invocation.expected_manifest_digest != *expected_manifest_digest
            || invocation.rollback_reference_id != *rollback_reference
            || invocation.expected_rollback_manifest_digest != *expected_rollback_manifest_digest
            || invocation.provider_invocation.trim().is_empty()
        {
            return Err(ApplicationError::Conflict(
                "backup provider invocation scope mismatch",
            ));
        }
        Ok(invocation)
    }

    async fn apply_backup(
        &self,
        step: &OperationStep,
    ) -> Result<kitsunebi_domain::BackupReference, ApplicationError> {
        let OperationStep::BackupCreate {
            session_id,
            kind,
            target,
            idempotency_key,
            request_hash,
            ..
        } = step
        else {
            return Err(ApplicationError::Conflict("backup create step required"));
        };
        let components = if *kind == kitsunebi_domain::BackupKind::ServiceConsistent {
            self.service_consistent_components(*session_id, *target)
                .await?
        } else {
            Vec::new()
        };
        let request = application::BackupRequest {
            session_id: *session_id,
            kind: *kind,
            target: *target,
            idempotency_key: idempotency_key.clone(),
            request_hash: request_hash.clone(),
            components,
        };
        request.validate()?;
        let reference = self.backup.create(&request).await?;
        if reference.session_id != *session_id
            || reference.kind != *kind
            || reference.target != *target
        {
            return Err(ApplicationError::Conflict(
                "backup provider reference scope mismatch",
            ));
        }
        reference
            .validate_unverified()
            .map_err(|_| ApplicationError::Conflict("invalid backup provider reference"))?;
        let observation = self.backup.verify(&reference).await?;
        if observation.manifest_digest != reference.manifest_digest {
            return Err(ApplicationError::VerificationFailed(
                "backup manifest changed during verification".into(),
            ));
        }
        let mut verified = reference;
        verified.verified_at = Some(observation.observed_at);
        verified
            .validate()
            .map_err(|_| ApplicationError::Conflict("invalid verified backup reference"))?;
        self.storage
            .create_backup_reference(&verified)
            .await
            .map_err(|_| ApplicationError::Conflict("backup reference persistence failed"))?;
        Ok(verified)
    }

    async fn service_consistent_components(
        &self,
        session_id: kitsunebi_domain::ChangeSessionId,
        target: kitsunebi_domain::BackupTarget,
    ) -> Result<Vec<BackupComponent>, ApplicationError> {
        let service_id = match target {
            kitsunebi_domain::BackupTarget::Service(service_id) => service_id,
            _ => return Err(ApplicationError::Conflict("service backup target")),
        };
        let references = self
            .storage
            .list_backup_references()
            .await
            .map_err(|_| ApplicationError::BackupUnavailable)?;
        let mut components = references
            .into_iter()
            .filter(|reference| {
                reference.session_id == session_id
                    && reference.verified_at.is_some()
                    && matches!(
                        reference.kind,
                        kitsunebi_domain::BackupKind::World
                            | kitsunebi_domain::BackupKind::ExternalDatabaseReference
                    )
            })
            .collect::<Vec<_>>();
        components.sort_by_key(|reference| reference.id);
        let worlds = components
            .iter()
            .filter(|reference| reference.kind == kitsunebi_domain::BackupKind::World)
            .count();
        let databases = components
            .iter()
            .filter(|reference| {
                reference.kind == kitsunebi_domain::BackupKind::ExternalDatabaseReference
            })
            .count();
        if worlds == 0 || databases != 1 {
            return Err(ApplicationError::Conflict(
                "service-consistent backup components are incomplete",
            ));
        }
        let service = self
            .storage
            .get_service(service_id)
            .await
            .map_err(|_| ApplicationError::NotFound("service"))?
            .ok_or(ApplicationError::NotFound("service"))?;
        let cluster = service
            .current_cluster
            .ok_or(ApplicationError::Conflict("service cluster is unavailable"))?;
        let current_revision = self
            .storage
            .get_cluster(cluster)
            .await
            .map_err(|_| ApplicationError::NotFound("cluster"))?
            .and_then(|cluster| cluster.current_revision);
        let known_worlds: std::collections::BTreeSet<kitsunebi_domain::WorldId> =
            match current_revision {
                Some(revision_id) => self
                    .storage
                    .list_all_revisions()
                    .await
                    .map_err(|_| ApplicationError::NotFound("cluster revision"))?
                    .into_iter()
                    .find(|revision| revision.id == revision_id)
                    .map(|revision| revision.world_bindings.into_iter().collect())
                    .unwrap_or_default(),
                None => self
                    .storage
                    .list_all_worlds()
                    .await
                    .map_err(|_| ApplicationError::NotFound("world"))?
                    .into_iter()
                    .filter(|world| world.current_writers.contains(&cluster))
                    .map(|world| world.id)
                    .collect(),
            };
        if !known_worlds.is_empty() {
            let component_worlds = components
                .iter()
                .filter_map(|reference| match reference.target {
                    kitsunebi_domain::BackupTarget::World(world) => Some(world),
                    _ => None,
                })
                .collect::<std::collections::BTreeSet<_>>();
            if component_worlds != known_worlds {
                return Err(ApplicationError::Conflict(
                    "service-consistent backup does not cover every service world",
                ));
            }
        }
        components
            .into_iter()
            .map(|reference| {
                reference
                    .validate()
                    .map_err(|_| ApplicationError::Conflict("invalid backup component"))?;
                Ok(BackupComponent {
                    reference_id: reference.id,
                    kind: reference.kind,
                    target: reference.target,
                    provider_reference: reference.provider_reference,
                    manifest_digest: reference.manifest_digest,
                })
            })
            .collect()
    }
    async fn reobserve_verified_backup(
        &self,
        reference_id: kitsunebi_domain::BackupReferenceId,
        kind: kitsunebi_domain::BackupKind,
        target: kitsunebi_domain::BackupTarget,
    ) -> Result<(), ApplicationError> {
        let reference = self
            .storage
            .get_backup_reference(reference_id)
            .await
            .map_err(|_| ApplicationError::NotFound("backup reference"))?
            .ok_or(ApplicationError::NotFound("backup reference"))?;
        if reference.kind != kind || reference.target != target || reference.verified_at.is_none() {
            return Err(ApplicationError::Conflict(
                "destructive step requires a verified scoped backup",
            ));
        }
        let observation = self.backup.verify(&reference).await?;
        if observation.manifest_digest != reference.manifest_digest {
            return Err(ApplicationError::VerificationFailed(
                "backup manifest changed before destructive step".into(),
            ));
        }
        Ok(())
    }

    async fn require_verified_session_backup(
        &self,
        session_id: kitsunebi_domain::ChangeSessionId,
        kind: kitsunebi_domain::BackupKind,
        target: kitsunebi_domain::BackupTarget,
    ) -> Result<(), ApplicationError> {
        let references = self
            .storage
            .list_backup_references()
            .await
            .map_err(|_| ApplicationError::BackupUnavailable)?;
        let matching = references
            .into_iter()
            .filter(|reference| {
                reference.session_id == session_id
                    && reference.kind == kind
                    && reference.target == target
                    && reference.verified_at.is_some()
            })
            .collect::<Vec<_>>();
        if matching.len() != 1 {
            return Err(ApplicationError::Conflict(
                "destructive step requires a verified scoped backup",
            ));
        }
        let reference = matching.into_iter().next().expect("one matching backup");
        let observation = self.backup.verify(&reference).await?;
        if observation.manifest_digest != reference.manifest_digest {
            return Err(ApplicationError::VerificationFailed(
                "backup manifest changed before destructive step".into(),
            ));
        }
        Ok(())
    }

    async fn apply_endpoint_reconnect(
        &self,
        step: &OperationStep,
        prepared: Option<&StepExecutionEvidence>,
    ) -> Result<StepApplyResult, ApplicationError> {
        let OperationStep::EndpointReconnect {
            expected_binding_id,
            target_binding_id,
            cluster,
            expected_version,
            expected_revision,
            target_revision,
            runtime_binding_ids,
            ..
        } = step
        else {
            return Err(ApplicationError::Conflict(
                "endpoint reconnect step required",
            ));
        };
        let Some(StepExecutionEvidence::Endpoint {
            expected_binding_id: evidence_expected,
            target_binding_id: evidence_target,
            prior_binding,
            target_binding,
            runtime,
            ..
        }) = prepared
        else {
            return Err(ApplicationError::Conflict(
                "endpoint reconnect requires prepared runtime evidence",
            ));
        };
        if evidence_expected != expected_binding_id
            || evidence_target != target_binding_id
            || runtime.len() != runtime_binding_ids.len()
        {
            return Err(ApplicationError::Conflict(
                "endpoint reconnect evidence does not match step",
            ));
        }
        let endpoints = self
            .storage
            .list_endpoints()
            .await
            .map_err(|_| ApplicationError::NotFound("external endpoint"))?;
        let endpoint = endpoints
            .iter()
            .find(|endpoint| endpoint.id == target_binding.endpoint_id)
            .ok_or(ApplicationError::NotFound("external endpoint"))?;
        let mut addresses = SystemDnsResolver
            .resolve(&endpoint.logical_hostname, endpoint.port)
            .await?;
        addresses.sort();
        addresses.dedup();
        if addresses.is_empty() {
            return Err(ApplicationError::VerificationFailed(
                "endpoint did not resolve".into(),
            ));
        }
        TcpShieldHealth
            .verify(&format!("{}:{}", endpoint.logical_hostname, endpoint.port))
            .await?;
        if !Self::endpoint_binding_pair_matches(
            prior_binding,
            target_binding,
            *cluster,
            *expected_revision,
            *target_revision,
            *expected_binding_id,
            *target_binding_id,
        ) {
            return Err(ApplicationError::StalePlan);
        }
        self.storage
            .activate_endpoint_bindings_at_version(prior_binding, target_binding, *expected_version)
            .await
            .map_err(|_| ApplicationError::Conflict("endpoint binding pair changed"))?;
        for observation in runtime {
            if !observation.prior_running {
                continue;
            }
            let binding = self
                .storage
                .get_gameap_binding(observation.binding_id.as_uuid())
                .await
                .map_err(|_| ApplicationError::NotFound("endpoint runtime binding"))?
                .ok_or(ApplicationError::NotFound("endpoint runtime binding"))?;
            if let Err(error) = self.execution.restart(&binding).await {
                return Err(self
                    .compensate_endpoint_activation(
                        *cluster,
                        *expected_binding_id,
                        *target_binding_id,
                        *expected_version,
                        error,
                    )
                    .await);
            }
            let status = match self.execution.status(&binding).await {
                Ok(status) => status,
                Err(error) => {
                    return Err(self
                        .compensate_endpoint_activation(
                            *cluster,
                            *expected_binding_id,
                            *target_binding_id,
                            *expected_version,
                            error,
                        )
                        .await);
                }
            };
            if !status.running {
                return Err(self
                    .compensate_endpoint_activation(
                        *cluster,
                        *expected_binding_id,
                        *target_binding_id,
                        *expected_version,
                        ApplicationError::VerificationFailed(
                            "endpoint runtime did not reconnect".into(),
                        ),
                    )
                    .await);
            }
        }
        let evidence = StepEvidence {
            sequence: 0,
            state_hash: String::new(),
            result: "applied".into(),
            execution: prepared.cloned(),
        };
        match self.observe(step, Some(&evidence)).await {
            Ok(observation) if observation.completed => Ok(StepApplyResult {
                observation,
                evidence: prepared.cloned(),
            }),
            Ok(_) => Err(self
                .compensate_endpoint_activation(
                    *cluster,
                    *expected_binding_id,
                    *target_binding_id,
                    *expected_version,
                    ApplicationError::VerificationFailed(
                        "endpoint reconnect postcondition did not hold".into(),
                    ),
                )
                .await),
            Err(error) => Err(self
                .compensate_endpoint_activation(
                    *cluster,
                    *expected_binding_id,
                    *target_binding_id,
                    *expected_version,
                    error,
                )
                .await),
        }
    }

    async fn compensate_endpoint_activation(
        &self,
        cluster: ClusterId,
        expected_binding_id: BindingId,
        target_binding_id: BindingId,
        expected_version: u64,
        original: ApplicationError,
    ) -> ApplicationError {
        Self::endpoint_compensation_error(
            original,
            self.storage
                .rollback_endpoint_bindings_at_version(
                    cluster,
                    expected_binding_id,
                    target_binding_id,
                    expected_version.saturating_add(1),
                )
                .await
                .map_err(|error| ApplicationError::RollbackConflict(error.to_string())),
        )
    }

    async fn compensate_endpoint_rollback_runtime(
        &self,
        cluster: ClusterId,
        prior_binding: &kitsunebi_domain::EndpointBinding,
        target_binding: &kitsunebi_domain::EndpointBinding,
        expected_version: u64,
        runtime: &[application::EndpointRuntimeObservation],
        original: ApplicationError,
    ) -> ApplicationError {
        let reactivation = self
            .storage
            .activate_endpoint_bindings_at_version(
                prior_binding,
                target_binding,
                expected_version.saturating_add(2),
            )
            .await
            .map_err(|error| ApplicationError::RollbackConflict(error.to_string()));
        match reactivation {
            Ok(()) => {
                let mut reconnect_errors = Vec::new();
                for observation in runtime {
                    if !observation.prior_running {
                        continue;
                    }
                    let binding = match self
                        .storage
                        .get_gameap_binding(observation.binding_id.as_uuid())
                        .await
                    {
                        Ok(Some(binding)) => binding,
                        Ok(None) => {
                            reconnect_errors.push(format!(
                                "runtime {} is missing",
                                observation.binding_id.as_uuid()
                            ));
                            continue;
                        }
                        Err(error) => {
                            reconnect_errors.push(format!(
                                "runtime {} lookup failed: {error}",
                                observation.binding_id.as_uuid()
                            ));
                            continue;
                        }
                    };
                    if let Err(error) = self.execution.restart(&binding).await {
                        reconnect_errors.push(format!(
                            "runtime {} reactivation reconnect failed: {error}",
                            observation.binding_id.as_uuid()
                        ));
                        continue;
                    }
                    match self.execution.status(&binding).await {
                        Ok(status) if status.running => {}
                        Ok(_) => reconnect_errors.push(format!(
                            "runtime {} reactivation did not become running",
                            observation.binding_id.as_uuid()
                        )),
                        Err(error) => reconnect_errors.push(format!(
                            "runtime {} reactivation status failed: {error}",
                            observation.binding_id.as_uuid()
                        )),
                    }
                }
                if reconnect_errors.is_empty() {
                    ApplicationError::RollbackConflict(format!(
                        "endpoint rollback runtime failed after {original}; target revision was reactivated and all prior runtimes reconnected for cluster {cluster:?}"
                    ))
                } else {
                    ApplicationError::RollbackConflict(format!(
                        "endpoint rollback runtime failed after {original}; target revision was reactivated but runtime reactivation failed: {reconnect_errors:?}"
                    ))
                }
            }
            Err(error) => ApplicationError::RollbackConflict(format!(
                "endpoint rollback runtime failed after {original}; target revision reactivation failed: {error}"
            )),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn preserve_proxy_final_after_old_add<E: ProxyEdgeState + ?Sized>(
        edge: &E,
        final_new: &ProxyEdgeBinding,
        post_add_old: &ProxyEdgeBinding,
        prior_hash: &str,
        post_add_hash: &str,
        final_hash: &str,
        original: &ApplicationError,
        stage: &str,
        failure: &ApplicationError,
    ) -> ApplicationError {
        let observed = match edge.observe_backend_set(final_new).await {
            Ok(state) => state,
            Err(error) => {
                return ApplicationError::RollbackConflict(format!(
                    "proxy edge handoff compensation could not observe phase after {original}: stage={stage}; failure={failure}; expected_final={final_hash}; observation={error}"
                ));
            }
        };
        let state_evidence = Self::proxy_edge_state_evidence(&observed, post_add_old, final_new);
        match Self::proxy_edge_phase(
            &observed,
            post_add_old,
            final_new,
            prior_hash,
            post_add_hash,
            final_hash,
        ) {
            Some(ProxyEdgePhase::Final) => ApplicationError::RollbackConflict(format!(
                "proxy edge handoff stopped before old backend became ready: stage={stage}; failure={failure}; original={original}; {state_evidence}"
            )),
            Some(ProxyEdgePhase::PostAdd) => {
                let remove_old = edge.remove(post_add_old).await;
                if let Err(error) = remove_old {
                    return ApplicationError::RollbackConflict(format!(
                        "proxy edge handoff compensation failed to remove old backend: stage={stage}; failure={failure}; original={original}; {state_evidence}; remove_old={error}"
                    ));
                }
                let restored = match edge.observe_backend_set(final_new).await {
                    Ok(state) => state,
                    Err(error) => {
                        return ApplicationError::RollbackConflict(format!(
                            "proxy edge handoff compensation could not verify final state: stage={stage}; failure={failure}; original={original}; remove_old=ok; observation={error}"
                        ));
                    }
                };
                if !matches!(
                    Self::proxy_edge_phase(
                        &restored,
                        post_add_old,
                        final_new,
                        prior_hash,
                        post_add_hash,
                        final_hash,
                    ),
                    Some(ProxyEdgePhase::Final)
                ) {
                    return ApplicationError::RollbackConflict(format!(
                        "proxy edge handoff compensation did not restore final state: stage={stage}; failure={failure}; original={original}; observed={}; old_present={}; new_present={}",
                        restored.hash(),
                        restored.backends.contains(&post_add_old.backend_address),
                        restored.backends.contains(&final_new.backend_address),
                    ));
                }
                ApplicationError::RollbackConflict(format!(
                    "proxy edge handoff stopped before old backend became ready and restored final state: stage={stage}; failure={failure}; original={original}; observed_hash={}",
                    restored.hash(),
                ))
            }
            Some(ProxyEdgePhase::Prior) => ApplicationError::RollbackConflict(format!(
                "proxy edge handoff compensation observed prior state instead of final: stage={stage}; failure={failure}; original={original}; {state_evidence}"
            )),
            None => ApplicationError::RollbackConflict(format!(
                "proxy edge handoff compensation found external drift: stage={stage}; failure={failure}; original={original}; expected_hashes=prior:{prior_hash},post_add:{post_add_hash},final:{final_hash}; {state_evidence}"
            )),
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn restore_proxy_edge<E, H>(
        edge: &E,
        health: &H,
        new: &ProxyEdgeBinding,
        old: &ProxyEdgeBinding,
        prior_hash: &str,
        post_add_hash: &str,
        final_hash: &str,
        original: &ApplicationError,
    ) -> Result<(), ApplicationError>
    where
        E: ProxyEdgeState + ?Sized,
        H: HealthVerifier + ?Sized,
    {
        let final_new = Self::proxy_binding_with_hash(new, final_hash);
        let final_old = Self::proxy_binding_with_hash(old, final_hash);
        let post_add_new = Self::proxy_binding_with_hash(new, post_add_hash);
        let post_add_old = Self::proxy_binding_with_hash(old, post_add_hash);
        let prior_new = Self::proxy_binding_with_hash(new, prior_hash);
        let current = edge
            .observe_backend_set(&final_new)
            .await
            .map_err(|error| {
                ApplicationError::RollbackConflict(format!(
                    "proxy edge handoff could not observe current phase: original={original}; expected_hashes=prior:{prior_hash},post_add:{post_add_hash},final:{final_hash}; observation={error}"
                ))
            })?;
        let phase = Self::proxy_edge_phase(
            &current,
            &final_old,
            &final_new,
            prior_hash,
            post_add_hash,
            final_hash,
        )
        .ok_or_else(|| {
            ApplicationError::RollbackConflict(format!(
                "proxy edge handoff found external drift: original={original}; expected_hashes=prior:{prior_hash},post_add:{post_add_hash},final:{final_hash}; {}",
                Self::proxy_edge_state_evidence(&current, &final_old, &final_new),
            ))
        })?;
        if phase == ProxyEdgePhase::Prior {
            edge.stop(&prior_new).await.map_err(|error| {
                ApplicationError::RollbackConflict(format!(
                    "proxy edge handoff prior-state postcondition failed: original={original}; expected_hash={prior_hash}; error={error}"
                ))
            })?;
            return Ok(());
        }

        if let Err(error) = health.verify(&old.backend_address).await {
            let compensation = if phase == ProxyEdgePhase::PostAdd {
                Self::preserve_proxy_final_after_old_add(
                    edge,
                    &final_new,
                    &post_add_old,
                    prior_hash,
                    post_add_hash,
                    final_hash,
                    original,
                    "old-health",
                    &error,
                )
                .await
            } else {
                ApplicationError::RollbackConflict(format!(
                    "proxy edge handoff could not verify old backend health: stage=old-health; failure={error}; original={original}; expected_hash={final_hash}; {}",
                    Self::proxy_edge_state_evidence(&current, &final_old, &final_new),
                ))
            };
            return Err(compensation);
        }

        if phase == ProxyEdgePhase::Final {
            if let Err(error) = edge.add(&final_old).await {
                return Err(Self::preserve_proxy_final_after_old_add(
                    edge,
                    &final_new,
                    &post_add_old,
                    prior_hash,
                    post_add_hash,
                    final_hash,
                    original,
                    "old-add",
                    &error,
                )
                .await);
            }
            let post_add = match edge.observe_backend_set(&post_add_new).await {
                Ok(state) => state,
                Err(error) => {
                    return Err(Self::preserve_proxy_final_after_old_add(
                        edge,
                        &final_new,
                        &post_add_old,
                        prior_hash,
                        post_add_hash,
                        final_hash,
                        original,
                        "old-add-verify",
                        &error,
                    )
                    .await);
                }
            };
            if !matches!(
                Self::proxy_edge_phase(
                    &post_add,
                    &post_add_old,
                    &post_add_new,
                    prior_hash,
                    post_add_hash,
                    final_hash,
                ),
                Some(ProxyEdgePhase::PostAdd)
            ) {
                let error = ApplicationError::RollbackConflict(format!(
                    "old edge add postcondition mismatch: observed_hash={}; old_present={}; new_present={}",
                    post_add.hash(),
                    post_add.backends.contains(&post_add_old.backend_address),
                    post_add.backends.contains(&post_add_new.backend_address),
                ));
                return Err(Self::preserve_proxy_final_after_old_add(
                    edge,
                    &final_new,
                    &post_add_old,
                    prior_hash,
                    post_add_hash,
                    final_hash,
                    original,
                    "old-add-verify",
                    &error,
                )
                .await);
            }
        }

        let connect = match edge.real_connect(&post_add_old).await {
            Ok(evidence) => evidence,
            Err(error) => {
                return Err(Self::preserve_proxy_final_after_old_add(
                    edge,
                    &final_new,
                    &post_add_old,
                    prior_hash,
                    post_add_hash,
                    final_hash,
                    original,
                    "old-connect",
                    &error,
                )
                .await);
            }
        };
        if !connect.observed || connect.active == 0 || connect.hash.trim().is_empty() {
            let error = ApplicationError::VerificationFailed(format!(
                "old backend real connection evidence invalid: observed={};active={};hash_present={}",
                connect.observed,
                connect.active,
                !connect.hash.trim().is_empty(),
            ));
            return Err(Self::preserve_proxy_final_after_old_add(
                edge,
                &final_new,
                &post_add_old,
                prior_hash,
                post_add_hash,
                final_hash,
                original,
                "old-connect",
                &error,
            )
            .await);
        }

        if let Err(error) = edge.remove(&post_add_new).await {
            return Err(Self::preserve_proxy_final_after_old_add(
                edge,
                &final_new,
                &post_add_old,
                prior_hash,
                post_add_hash,
                final_hash,
                original,
                "new-remove",
                &error,
            )
            .await);
        }
        let restored = edge
            .observe_backend_set(&prior_new)
            .await
            .map_err(|error| {
                ApplicationError::RollbackConflict(format!(
                    "proxy edge handoff could not verify prior state: original={original}; expected_hash={prior_hash}; error={error}"
                ))
            })?;
        if !matches!(
            Self::proxy_edge_phase(
                &restored,
                &final_old,
                &final_new,
                prior_hash,
                post_add_hash,
                final_hash,
            ),
            Some(ProxyEdgePhase::Prior)
        ) {
            return Err(ApplicationError::RollbackConflict(format!(
                "proxy edge handoff prior-state postcondition failed: original={original}; expected_hash={prior_hash}; {}",
                Self::proxy_edge_state_evidence(&restored, &final_old, &final_new),
            )));
        }
        edge.stop(&prior_new).await.map_err(|error| {
            ApplicationError::RollbackConflict(format!(
                "proxy edge handoff stop postcondition failed: original={original}; expected_hash={prior_hash}; error={error}"
            ))
        })?;
        Ok(())
    }

    async fn compensate_proxy_configuration(
        &self,
        target: &GameAPBinding,
        configuration: &[FileBatchOperation],
        inverses: &[application::FileInverse],
        target_existed: bool,
    ) -> Result<(), ApplicationError> {
        if !target_existed {
            // A newly created target is removed by execution compensation;
            // its configuration disappears with that provider unit.
            return Ok(());
        }
        if configuration.len() != inverses.len() {
            return Err(ApplicationError::RollbackConflict(
                "proxy configuration inverse count mismatch".into(),
            ));
        }
        for (operation, inverse) in configuration.iter().zip(inverses) {
            let FileBatchOperation::Write {
                path,
                content,
                classification,
                ..
            } = operation
            else {
                return Err(ApplicationError::RollbackConflict(
                    "proxy configuration inverse action mismatch".into(),
                ));
            };
            if *classification != FileClassification::MutableConfig
                || inverse.path != *path
                || inverse.target_path.is_some()
            {
                return Err(ApplicationError::RollbackConflict(
                    "proxy configuration inverse metadata mismatch".into(),
                ));
            }
            self.validate_declared_file(target, path, classification)
                .await
                .map_err(|error| {
                    ApplicationError::RollbackConflict(format!(
                        "proxy configuration rollback validation failed: {error}"
                    ))
                })?;
            let current = self
                .execution
                .observe_file_optional(target, path)
                .await
                .map_err(|error| {
                    ApplicationError::RollbackConflict(format!(
                        "proxy configuration rollback observation failed: {error}"
                    ))
                })?;
            let already_restored = match current.as_ref() {
                Some((digest, _)) => {
                    inverse.prior_exists && inverse.prior_digest.as_deref() == Some(digest)
                }
                None => !inverse.prior_exists,
            };
            if already_restored {
                continue;
            }
            let Some((current_digest, _)) = current else {
                return Err(ApplicationError::RollbackConflict(
                    "proxy configuration file disappeared before rollback".into(),
                ));
            };
            if current_digest != content.digest {
                return Err(ApplicationError::RollbackConflict(
                    "proxy configuration file changed outside rollout".into(),
                ));
            }
            self.restore_inverse(target, inverse, classification.clone(), &content.digest)
                .await
                .map_err(|error| {
                    ApplicationError::RollbackConflict(format!(
                        "proxy configuration rollback failed: {error}"
                    ))
                })?;
            let restored = self
                .execution
                .observe_file_optional(target, path)
                .await
                .map_err(|error| {
                    ApplicationError::RollbackConflict(format!(
                        "proxy configuration rollback verification failed: {error}"
                    ))
                })?;
            let restored_ok = match restored {
                Some((digest, _)) => {
                    inverse.prior_exists && inverse.prior_digest.as_deref() == Some(digest.as_str())
                }
                None => !inverse.prior_exists,
            };
            if !restored_ok {
                return Err(ApplicationError::RollbackConflict(
                    "proxy configuration rollback postcondition did not hold".into(),
                ));
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn compensate_proxy_rollout(
        &self,
        edge: &TcpShieldComposition,
        new: &ProxyEdgeBinding,
        old: &ProxyEdgeBinding,
        prior_hash: &str,
        post_add_hash: &str,
        final_hash: &str,
        target_execution: &GameAPBinding,
        old_execution: &GameAPBinding,
        target_execution_existed: bool,
        target_create_attempted: bool,
        target_execution_was_running: bool,
        target_execution_started: bool,
        old_execution_was_running: bool,
        old_stop_attempted: bool,
        configuration: &[FileBatchOperation],
        configuration_inverse: &[application::FileInverse],
        original: ApplicationError,
    ) -> ApplicationError {
        // The old execution must be healthy before traffic is moved back to
        // it.  If this check fails, leave the provider and target runtime in
        // their observable state and surface a conflict for reconciliation.
        if let Err(error) = self
            .restore_proxy_old_execution(
                old_execution,
                old_execution_was_running,
                old_stop_attempted,
            )
            .await
        {
            return ApplicationError::RollbackConflict(format!(
                "proxy rollout compensation could not restore old execution after {original}: {error}"
            ));
        }
        if let Err(error) = Self::restore_proxy_edge(
            edge.edge.as_ref(),
            edge.health.as_ref(),
            new,
            old,
            prior_hash,
            post_add_hash,
            final_hash,
            &original,
        )
        .await
        {
            return error;
        }
        let mut runtime_errors = Vec::new();
        let target_created = !target_execution_existed && target_create_attempted;
        match self.proxy_execution_status(target_execution).await {
            Ok(None) if !target_execution_existed => {}
            Ok(None) => runtime_errors.push("target execution disappeared".to_owned()),
            Ok(Some(status)) => {
                if target_created {
                    if status.running {
                        if let Err(error) = self.execution.stop(target_execution).await {
                            runtime_errors.push(format!("stop created target: {error}"));
                        } else if let Ok(Some(status)) =
                            self.proxy_execution_status(target_execution).await
                            && status.running
                        {
                            runtime_errors.push("created target remained running".into());
                        }
                    }
                    if runtime_errors.is_empty() {
                        if let Err(error) = self.execution.delete(target_execution).await {
                            runtime_errors.push(format!("delete created target: {error}"));
                        } else if !matches!(
                            self.proxy_execution_status(target_execution).await,
                            Ok(None)
                        ) {
                            runtime_errors.push("created target remained after delete".into());
                        }
                    }
                } else if !target_execution_existed {
                    runtime_errors.push("target execution appeared without create".into());
                } else if target_execution_started {
                    if status.running {
                        if let Err(error) = self.execution.stop(target_execution).await {
                            runtime_errors.push(format!("stop started target: {error}"));
                        } else if matches!(
                            self.proxy_execution_status(target_execution).await,
                            Ok(Some(status)) if status.running
                        ) {
                            runtime_errors.push("started target remained running".into());
                        }
                    }
                } else if status.running != target_execution_was_running {
                    runtime_errors.push("target execution state changed".into());
                }
            }
            Err(error) => runtime_errors.push(format!("observe target execution: {error}")),
        }
        if target_execution_existed
            && runtime_errors.is_empty()
            && let Err(error) = self
                .compensate_proxy_configuration(
                    target_execution,
                    configuration,
                    configuration_inverse,
                    true,
                )
                .await
        {
            runtime_errors.push(error.to_string());
        }
        if runtime_errors.is_empty() {
            original
        } else {
            ApplicationError::RollbackConflict(format!(
                "proxy rollout compensation failed after {original}: edge=restored; runtime={runtime_errors:?}"
            ))
        }
    }

    async fn restore_proxy_old_execution(
        &self,
        old: &GameAPBinding,
        old_was_running: bool,
        old_stop_attempted: bool,
    ) -> Result<(), ApplicationError> {
        let old_status = self
            .proxy_execution_status(old)
            .await
            .map_err(|error| ApplicationError::RollbackConflict(error.to_string()))?;
        let Some(old_status) = old_status else {
            return Err(ApplicationError::RollbackConflict(
                "old execution disappeared".into(),
            ));
        };
        if old_was_running {
            if !old_status.running {
                if !old_stop_attempted {
                    return Err(ApplicationError::RollbackConflict(
                        "old execution stopped outside rollout".into(),
                    ));
                }
                self.execution.start(old).await.map_err(|error| {
                    ApplicationError::RollbackConflict(format!("restart old execution: {error}"))
                })?;
            }
            if !self
                .proxy_execution_status(old)
                .await
                .map_err(|error| ApplicationError::RollbackConflict(error.to_string()))?
                .is_some_and(|status| status.running)
            {
                return Err(ApplicationError::RollbackConflict(
                    "old execution did not restart".into(),
                ));
            }
        } else if old_status.running {
            return Err(ApplicationError::RollbackConflict(
                "old execution became running outside rollout".into(),
            ));
        }
        Ok(())
    }

    async fn rollback_proxy_target_execution(
        &self,
        target: &GameAPBinding,
        target_existed: bool,
        target_was_running: bool,
        target_created: bool,
        target_started: bool,
    ) -> Result<(), ApplicationError> {
        if target_created == target_existed {
            return Err(ApplicationError::RollbackConflict(
                "proxy execution inverse flags are inconsistent".into(),
            ));
        }
        let target_status = self
            .proxy_execution_status(target)
            .await
            .map_err(|error| ApplicationError::RollbackConflict(error.to_string()))?;
        if target_created {
            if let Some(status) = target_status {
                if status.running {
                    self.execution.stop(target).await.map_err(|error| {
                        ApplicationError::RollbackConflict(format!("stop created target: {error}"))
                    })?;
                }
                let status = self
                    .proxy_execution_status(target)
                    .await
                    .map_err(|error| ApplicationError::RollbackConflict(error.to_string()))?;
                if status.is_some_and(|status| status.running) {
                    return Err(ApplicationError::RollbackConflict(
                        "created target remained running".into(),
                    ));
                }
                self.execution.delete(target).await.map_err(|error| {
                    ApplicationError::RollbackConflict(format!("delete created target: {error}"))
                })?;
                if self
                    .proxy_execution_status(target)
                    .await
                    .map_err(|error| ApplicationError::RollbackConflict(error.to_string()))?
                    .is_some()
                {
                    return Err(ApplicationError::RollbackConflict(
                        "created target remained after delete".into(),
                    ));
                }
            }
        } else {
            let Some(status) = target_status else {
                return Err(ApplicationError::RollbackConflict(
                    "target execution disappeared".into(),
                ));
            };
            if target_started {
                if status.running {
                    self.execution.stop(target).await.map_err(|error| {
                        ApplicationError::RollbackConflict(format!("stop started target: {error}"))
                    })?;
                }
                if self
                    .proxy_execution_status(target)
                    .await
                    .map_err(|error| ApplicationError::RollbackConflict(error.to_string()))?
                    .is_some_and(|status| status.running)
                {
                    return Err(ApplicationError::RollbackConflict(
                        "started target remained running".into(),
                    ));
                }
            } else if status.running != target_was_running {
                return Err(ApplicationError::RollbackConflict(
                    "target execution state changed outside rollout".into(),
                ));
            }
        }
        Ok(())
    }

    async fn apply(
        &self,
        step: &OperationStep,
        prepared: Option<&StepExecutionEvidence>,
    ) -> Result<StepApplyResult, ApplicationError> {
        if let Some(evidence) = prepared {
            evidence.validate_for(step)?;
        }
        if matches!(step, OperationStep::BackupCreate { .. }) {
            if prepared.is_some() {
                return Err(ApplicationError::Conflict(
                    "backup create cannot reuse prepared evidence",
                ));
            }
            let reference = self.apply_backup(step).await?;
            return Ok(StepApplyResult {
                observation: StepObservation {
                    state_hash: reference.manifest_digest.clone(),
                    completed: true,
                    unambiguous: true,
                },
                evidence: Some(StepExecutionEvidence::BackupCreate(reference)),
            });
        }
        if matches!(step, OperationStep::EndpointReconnect { .. }) {
            return self.apply_endpoint_reconnect(step, prepared).await;
        }
        if matches!(step, OperationStep::BackupRestore { .. }) {
            let invocation = match prepared {
                Some(StepExecutionEvidence::BackupRestore(invocation)) => invocation.clone(),
                Some(_) => {
                    return Err(ApplicationError::Conflict(
                        "backup restore evidence has the wrong type",
                    ));
                }
                None => self.apply_restore(step).await?,
            };
            return Ok(StepApplyResult {
                observation: StepObservation {
                    state_hash: invocation.expected_manifest_digest.clone(),
                    completed: true,
                    // Restore verification is deliberately a separate durable
                    // ChangeSession verify observation.
                    unambiguous: false,
                },
                evidence: Some(StepExecutionEvidence::BackupRestore(invocation)),
            });
        }
        let observation = if let Some(execution) = prepared {
            let provisional = self.apply_observation(step, prepared).await?;
            self.observe(
                step,
                Some(&StepEvidence {
                    sequence: 0,
                    state_hash: provisional.state_hash,
                    result: "applied".into(),
                    execution: Some(execution.clone()),
                }),
            )
            .await?
        } else {
            self.apply_observation(step, None).await?
        };
        Ok(StepApplyResult {
            observation,
            evidence: prepared.cloned(),
        })
    }

    async fn apply_observation(
        &self,
        step: &OperationStep,
        prepared: Option<&StepExecutionEvidence>,
    ) -> Result<StepObservation, ApplicationError> {
        match step {
            OperationStep::ExecutionProvision { binding } => {
                self.execution.create(binding).await?;
                Ok(StepObservation {
                    state_hash: binding.fingerprint(),
                    completed: true,
                    unambiguous: true,
                })
            }
            OperationStep::ServiceLifecycleTransition {
                service_id,
                expected_state,
                next_state,
                expected_version,
                ..
            } => {
                let mut service = self
                    .storage
                    .get_service(*service_id)
                    .await
                    .map_err(|_| ApplicationError::NotFound("service"))?
                    .ok_or(ApplicationError::NotFound("service"))?;
                if service.lifecycle != *expected_state {
                    return Err(ApplicationError::StalePlan);
                }
                service.transition(next_state.clone()).map_err(|_| {
                    ApplicationError::Conflict("invalid service lifecycle transition")
                })?;
                self.storage
                    .update_service(&service, *expected_version)
                    .await
                    .map_err(|_| ApplicationError::Conflict("service changed"))?;
                self.observe(step, None).await
            }
            OperationStep::ClusterRevisionCreate {
                cluster,
                revision,
                new_endpoint_bindings,
                expected_current_number,
            } => {
                let cluster_row = self
                    .storage
                    .get_cluster(*cluster)
                    .await
                    .map_err(|_| ApplicationError::NotFound("cluster"))?
                    .ok_or(ApplicationError::NotFound("cluster"))?;
                let current_number = match cluster_row.current_revision {
                    Some(id) => self
                        .storage
                        .get_revision(id)
                        .await
                        .map_err(|_| ApplicationError::NotFound("cluster revision"))?
                        .map(|value| value.number),
                    None => None,
                };
                if current_number != *expected_current_number {
                    return Err(ApplicationError::StalePlan);
                }
                let endpoints = self
                    .storage
                    .list_endpoints()
                    .await
                    .map_err(|_| ApplicationError::NotFound("external endpoint"))?;
                if new_endpoint_bindings.iter().any(|binding| {
                    binding.cluster_id != *cluster
                        || binding.revision_id != revision.id
                        || !endpoints
                            .iter()
                            .any(|endpoint| endpoint.id == binding.endpoint_id)
                }) {
                    return Err(ApplicationError::Conflict(
                        "revision endpoint binding is not compatible with its external endpoint",
                    ));
                }
                self.storage
                    .create_revision_with_bindings(*cluster, revision, new_endpoint_bindings)
                    .await
                    .map_err(|_| ApplicationError::Conflict("cluster revision already exists"))?;
                self.observe(step, None).await
            }
            OperationStep::ExecutionDelete {
                binding,
                expected_state_hash,
                expected_version,
                session_id,
            } => {
                let binding_id = self.binding_id_for(binding).await?;
                self.require_verified_session_backup(
                    *session_id,
                    kitsunebi_domain::BackupKind::ChangeSnapshot,
                    kitsunebi_domain::BackupTarget::ExecutionUnit(binding_id),
                )
                .await?;
                let status = self.execution.status(binding).await?;
                if status.state_hash != *expected_state_hash {
                    return Err(ApplicationError::StalePlan);
                }
                let persisted_version: u64 =
                    sqlx::query_scalar("SELECT version FROM gameap_bindings WHERE id = ?")
                        .bind(binding_id.as_uuid().to_string())
                        .fetch_one(self.storage.pool())
                        .await
                        .map_err(|_| ApplicationError::NotFound("GameAP binding"))?;
                if persisted_version != *expected_version {
                    return Err(ApplicationError::StalePlan);
                }
                self.execution.delete(binding).await?;
                Ok(StepObservation {
                    state_hash: expected_state_hash.clone(),
                    completed: true,
                    unambiguous: true,
                })
            }
            OperationStep::ExecutionStart { binding } => {
                self.ensure_placement(binding).await?;
                self.execution.start(binding).await?;
                self.observe(step, None).await
            }
            OperationStep::ArtifactRegister {
                artifact, content, ..
            } => {
                let bytes = self.file_bytes(&content.digest).await?;
                if bytes.len() as u64 != content.size || Self::hash(&bytes) != artifact.digest {
                    return Err(ApplicationError::VerificationFailed(
                        "registered artifact content mismatch".into(),
                    ));
                }
                self.artifacts.put(&content.digest, &bytes).await?;
                if self
                    .storage
                    .get_artifact(artifact.id)
                    .await
                    .map_err(|_| ApplicationError::NotFound("artifact"))?
                    .is_some()
                {
                    return Err(ApplicationError::Conflict("artifact already exists"));
                }
                self.storage
                    .create_artifact(artifact)
                    .await
                    .map_err(|_| ApplicationError::Conflict("artifact already exists"))?;
                self.observe(step, None).await
            }
            OperationStep::ExecutionStop { binding } => {
                self.ensure_placement(binding).await?;
                self.execution.stop(binding).await?;
                self.observe(step, None).await
            }
            OperationStep::ExecutionRestart { binding } => {
                self.ensure_placement(binding).await?;
                self.execution.restart(binding).await?;
                let status = self.execution.status(binding).await?;
                Ok(StepObservation {
                    state_hash: status.state_hash,
                    completed: status.running,
                    unambiguous: false,
                })
            }
            OperationStep::FileWrite {
                binding,
                change,
                content,
                expected_before_digest,
                ..
            } => {
                self.ensure_placement(binding).await?;
                self.apply_file_write(binding, change, content, expected_before_digest)
                    .await
            }
            OperationStep::FileMove {
                binding,
                from,
                to,
                classification,
                expected_before_digest,
                expected_target_digest,
                ..
            } => {
                self.ensure_placement(binding).await?;
                self.validate_declared_file(binding, from, classification)
                    .await?;
                self.validate_declared_file(binding, to, classification)
                    .await?;
                let expected_before =
                    expected_before_digest
                        .as_deref()
                        .ok_or(ApplicationError::Conflict(
                            "file move requires source digest",
                        ))?;
                self.execution
                    .move_file_checked(
                        binding,
                        from,
                        to,
                        expected_before,
                        expected_target_digest.as_deref(),
                    )
                    .await?;
                self.observe(step, None).await
            }
            OperationStep::FileQuarantine {
                binding,
                path,
                classification,
                ..
            } => {
                self.ensure_placement(binding).await?;
                self.validate_declared_file(binding, path, classification)
                    .await?;
                self.execution.quarantine(binding, path).await?;
                Ok(StepObservation {
                    state_hash: Self::hash(path.as_bytes()),
                    completed: true,
                    unambiguous: true,
                })
            }
            OperationStep::FileBatch {
                binding,
                operations,
                ..
            } => {
                self.ensure_placement(binding).await?;
                for operation in operations {
                    match operation {
                        FileBatchOperation::Write {
                            path,
                            content,
                            classification,
                            expected_before_digest,
                        } => {
                            self.validate_declared_file(binding, path, classification)
                                .await?;
                            self.apply_file_write(
                                binding,
                                &FileChange {
                                    path: path.clone(),
                                    content_digest: content.digest.clone(),
                                    classification: classification.clone(),
                                },
                                content,
                                expected_before_digest,
                            )
                            .await?;
                        }
                        FileBatchOperation::Move {
                            from,
                            to,
                            classification,
                            expected_before_digest,
                            expected_target_digest,
                        } => {
                            self.validate_declared_file(binding, from, classification)
                                .await?;
                            self.validate_declared_file(binding, to, classification)
                                .await?;
                            let expected_before = expected_before_digest.as_deref().ok_or(
                                ApplicationError::Conflict("file move requires source digest"),
                            )?;
                            self.execution
                                .move_file_checked(
                                    binding,
                                    from,
                                    to,
                                    expected_before,
                                    expected_target_digest.as_deref(),
                                )
                                .await?
                        }
                        FileBatchOperation::Quarantine {
                            path,
                            classification,
                            ..
                        } => {
                            self.validate_declared_file(binding, path, classification)
                                .await?;
                            self.execution.quarantine(binding, path).await?
                        }
                    }
                }
                self.observe(step, None).await
            }
            OperationStep::ArtifactStage {
                artifact,
                expected_digest,
                ..
            } => {
                let value = self.artifact(*artifact).await?;
                if value.digest != *expected_digest {
                    return Err(ApplicationError::StalePlan);
                }
                self.artifacts.stage_artifact(&value).await?;
                self.observe(step, None).await
            }
            OperationStep::ProxyRollout {
                expected_instance,
                target_instance,
                pool,
                binding,
                expected_instance_version,
                target_instance_version,
                expected_instance_state,
                target_instance_state,
                target_binding_id,
                desired_state,
                configuration,
                ..
            } => {
                self.ensure_placement(binding).await?;
                let edge = self
                    .tcp_shield
                    .as_ref()
                    .ok_or(ApplicationError::Port("TCPShield is unavailable".into()))?;
                let Some(StepExecutionEvidence::Proxy {
                    expected_instance_id: evidence_expected_instance,
                    target_instance_id: evidence_target_instance,
                    prior_expected_state: evidence_prior_expected_state,
                    prior_expected_version: evidence_prior_expected_version,
                    prior_target_state: evidence_prior_target_state,
                    prior_target_version: evidence_prior_target_version,
                    prior_edge_hash,
                    prior_target_member,
                    new_state: evidence_new_state,
                    new_version: evidence_new_version,
                    post_add_edge_hash,
                    final_edge_hash,
                    target_execution_existed,
                    target_execution_was_running,
                    target_execution_created,
                    target_execution_started,
                    old_execution_was_running,
                    configuration_inverse,
                }) = prepared
                else {
                    return Err(ApplicationError::Conflict(
                        "proxy rollout requires prepared edge evidence",
                    ));
                };
                if evidence_expected_instance != expected_instance
                    || evidence_target_instance != target_instance
                    || evidence_prior_expected_state != expected_instance_state
                    || evidence_prior_expected_version != expected_instance_version
                    || evidence_prior_target_state != target_instance_state
                    || evidence_prior_target_version != target_instance_version
                    || evidence_new_state != desired_state
                    || evidence_new_version != target_instance_version
                    || *prior_target_member
                {
                    return Err(ApplicationError::StalePlan);
                }
                let (new, old, _service, target_execution, old_execution) = self
                    .proxy_bindings(
                        *expected_instance,
                        *target_instance,
                        *pool,
                        binding,
                        *target_binding_id,
                    )
                    .await?;
                let current = edge.edge.observe_set(&new).await?;
                if current.hash() != *prior_edge_hash
                    || !current.backends.contains(&old.backend_address)
                    || current.backends.contains(&new.backend_address)
                {
                    return Err(ApplicationError::StalePlan);
                }
                let post_add_new = Self::proxy_binding_with_hash(&new, post_add_edge_hash);
                let post_add_old = Self::proxy_binding_with_hash(&old, post_add_edge_hash);
                let final_old = Self::proxy_binding_with_hash(&old, final_edge_hash);
                if !matches!(desired_state, kitsunebi_domain::ProxyState::Accepting) {
                    return Err(ApplicationError::Conflict(
                        "proxy rollout target must be accepting",
                    ));
                }
                let target_before = self.proxy_execution_status(&target_execution).await?;
                if target_before.is_some() != *target_execution_existed
                    || target_before
                        .as_ref()
                        .is_some_and(|status| status.running != *target_execution_was_running)
                {
                    return Err(ApplicationError::StalePlan);
                }
                let mut target_create_attempted = false;
                let mut target_started = false;
                let mut old_stop_attempted = false;
                macro_rules! compensate {
                    ($error:expr) => {
                        return Err(self
                            .compensate_proxy_rollout(
                                edge,
                                &post_add_new,
                                &final_old,
                                prior_edge_hash,
                                post_add_edge_hash,
                                final_edge_hash,
                                &target_execution,
                                &old_execution,
                                *target_execution_existed,
                                target_create_attempted,
                                *target_execution_was_running,
                                target_started,
                                *old_execution_was_running,
                                old_stop_attempted,
                                configuration,
                                configuration_inverse,
                                $error,
                            )
                            .await)
                    };
                }
                if *target_execution_created {
                    target_create_attempted = true;
                    if let Err(error) = self.execution.create(&target_execution).await {
                        compensate!(error);
                    }
                }
                for operation in configuration {
                    let FileBatchOperation::Write {
                        path,
                        content,
                        classification,
                        expected_before_digest,
                    } = operation
                    else {
                        compensate!(ApplicationError::Conflict(
                            "proxy configuration must contain writes",
                        ));
                    };
                    if *classification != FileClassification::MutableConfig {
                        compensate!(ApplicationError::Conflict(
                            "proxy configuration must be mutable config",
                        ));
                    }
                    if let Err(error) = self
                        .apply_file_write(
                            &target_execution,
                            &FileChange {
                                path: path.clone(),
                                content_digest: content.digest.clone(),
                                classification: classification.clone(),
                            },
                            content,
                            expected_before_digest,
                        )
                        .await
                    {
                        compensate!(error);
                    }
                }
                if *target_execution_started {
                    target_started = true;
                    if let Err(error) = self.execution.start(&target_execution).await {
                        compensate!(error);
                    }
                }
                let target_after = match self.proxy_execution_status(&target_execution).await {
                    Ok(status) => status,
                    Err(error) => compensate!(error),
                };
                if !target_after.is_some_and(|status| status.running) {
                    compensate!(ApplicationError::VerificationFailed(
                        "proxy target execution did not start".into()
                    ));
                }
                if let Err(error) = edge.edge.prepare(&new).await {
                    compensate!(error);
                }
                if let Err(error) = edge.edge.configure(&new).await {
                    compensate!(error);
                }
                if let Err(error) = edge.health.verify(&new.backend_address).await {
                    compensate!(error);
                }
                if let Err(error) = edge.edge.add(&new).await {
                    compensate!(error);
                }
                macro_rules! after_add {
                    ($result:expr) => {
                        match $result {
                            Ok(value) => value,
                            Err(error) => {
                                compensate!(error);
                            }
                        }
                    };
                }
                let connection = after_add!(edge.edge.real_connect(&new).await);
                if !connection.observed || connection.active == 0 {
                    compensate!(ApplicationError::VerificationFailed(
                        "proxy real connection failed".into()
                    ));
                }
                // TCPShield has no connection-drain endpoint. Removing the
                // old backend disables new edge assignments; monitoring then
                // proves existing connections have reached zero.
                after_add!(edge.edge.drain(&post_add_old).await);
                let drained = after_add!(edge.observer.observe(&old.backend_address).await);
                if drained.active != 0 {
                    compensate!(ApplicationError::Conflict(
                        "proxy connections remain during drain"
                    ));
                }
                after_add!(edge.edge.stop(&final_old).await);
                if *old_execution_was_running {
                    old_stop_attempted = true;
                    if let Err(error) = self.execution.stop(&old_execution).await {
                        compensate!(error);
                    }
                }
                let old_after = match self.proxy_execution_status(&old_execution).await {
                    Ok(status) => status,
                    Err(error) => compensate!(error),
                };
                if old_after.is_none_or(|status| status.running) {
                    compensate!(ApplicationError::VerificationFailed(
                        "proxy old execution did not stop".into()
                    ));
                }
                let mut new_instance = after_add!(
                    async {
                        self.storage
                            .get_proxy_instance(*target_instance)
                            .await
                            .map_err(|_| ApplicationError::NotFound("proxy instance"))?
                            .ok_or(ApplicationError::NotFound("proxy instance"))
                    }
                    .await
                );
                let mut new_version = *target_instance_version;
                if new_instance.state != *target_instance_state {
                    compensate!(ApplicationError::StalePlan);
                }
                if new_instance.state == kitsunebi_domain::ProxyState::Preparing {
                    after_add!(
                        new_instance
                            .transition(kitsunebi_domain::ProxyState::Ready)
                            .map_err(|_| ApplicationError::Conflict("proxy state transition"))
                    );
                    after_add!(
                        self.storage
                            .update_proxy_instance(&new_instance, new_version)
                            .await
                            .map_err(|_| ApplicationError::Conflict("proxy instance changed"))
                    );
                    new_version = new_version.saturating_add(1);
                }
                if new_instance.state == kitsunebi_domain::ProxyState::Ready {
                    after_add!(
                        new_instance
                            .transition(kitsunebi_domain::ProxyState::Accepting)
                            .map_err(|_| ApplicationError::Conflict("proxy state transition"))
                    );
                    after_add!(
                        self.storage
                            .update_proxy_instance(&new_instance, new_version)
                            .await
                            .map_err(|_| ApplicationError::Conflict("proxy instance changed"))
                    );
                }
                let mut old_instance = after_add!(
                    async {
                        self.storage
                            .get_proxy_instance(old.instance_id)
                            .await
                            .map_err(|_| ApplicationError::NotFound("proxy instance"))?
                            .ok_or(ApplicationError::NotFound("proxy instance"))
                    }
                    .await
                );
                let old_version = *expected_instance_version;
                if old_instance.state != *expected_instance_state {
                    compensate!(ApplicationError::StalePlan);
                }
                if old_instance.state == kitsunebi_domain::ProxyState::Accepting {
                    after_add!(
                        old_instance
                            .transition(kitsunebi_domain::ProxyState::Draining)
                            .map_err(|_| ApplicationError::Conflict("proxy state transition"))
                    );
                    after_add!(
                        self.storage
                            .update_proxy_instance(&old_instance, old_version)
                            .await
                            .map_err(|_| ApplicationError::Conflict("proxy instance changed"))
                    );
                    after_add!(
                        old_instance
                            .transition(kitsunebi_domain::ProxyState::Stopped)
                            .map_err(|_| ApplicationError::Conflict("proxy state transition"))
                    );
                    after_add!(
                        self.storage
                            .update_proxy_instance(&old_instance, old_version.saturating_add(1))
                            .await
                            .map_err(|_| ApplicationError::Conflict("proxy instance changed"))
                    );
                }
                let observation = after_add!(
                    self.observe(
                        step,
                        Some(&StepEvidence {
                            sequence: 0,
                            state_hash: final_edge_hash.clone(),
                            result: "applied".into(),
                            execution: prepared.cloned(),
                        }),
                    )
                    .await
                );
                if !observation.completed {
                    compensate!(ApplicationError::VerificationFailed(
                        "proxy rollout postcondition did not hold".into()
                    ));
                }
                Ok(observation)
            }
            OperationStep::WorldWriterCutover {
                world,
                from,
                to,
                expected_version,
                expected_writer_binding_id,
                target_writer_binding_id,
                expected_writer_binding_hash,
                target_writer_binding_hash,
                domain_revision,
                session_id,
            } => {
                let _ = domain_revision;
                self.require_verified_session_backup(
                    *session_id,
                    kitsunebi_domain::BackupKind::World,
                    kitsunebi_domain::BackupTarget::World(*world),
                )
                .await?;
                if from.is_none() || expected_writer_binding_id.is_none() {
                    return Err(ApplicationError::Conflict(
                        "world writer CAS contract cannot compensate an unowned source",
                    ));
                }
                let source = match expected_writer_binding_id {
                    Some(binding_id) => Some(self.world_binding(*world, *binding_id, *from).await?),
                    None => None,
                };
                let target = self
                    .world_binding(*world, *target_writer_binding_id, Some(*to))
                    .await?;
                if target.fingerprint() != *target_writer_binding_hash {
                    return Err(ApplicationError::StalePlan);
                }
                if let Some(source) = &source {
                    if expected_writer_binding_hash.as_deref()
                        != Some(source.fingerprint().as_str())
                    {
                        return Err(ApplicationError::StalePlan);
                    }
                    let status = self.execution.status(source).await?;
                    if status.running {
                        return Err(ApplicationError::StalePlan);
                    }
                }
                let current = self
                    .storage
                    .get_world(*world)
                    .await
                    .map_err(|_| ApplicationError::NotFound("world"))?
                    .ok_or(ApplicationError::NotFound("world"))?;
                if current.current_writers != from.iter().copied().collect::<Vec<_>>() {
                    return Err(ApplicationError::StalePlan);
                }
                self.storage
                    .compare_and_swap_writer(*world, *expected_version, *from, *to)
                    .await?;
                let start_result = async {
                    self.execution.start(&target).await?;
                    let status = self.execution.status(&target).await?;
                    if !status.running {
                        return Err(ApplicationError::VerificationFailed(
                            "world target did not start".into(),
                        ));
                    }
                    Ok::<(), ApplicationError>(())
                }
                .await;
                if let Err(error) = start_result {
                    if let Err(compensation_error) = self.execution.stop(&target).await {
                        return Err(ApplicationError::RollbackConflict(format!(
                            "world target compensation failed after start error: {compensation_error}"
                        )));
                    }
                    if let Err(compensation_error) = self
                        .storage
                        .compare_and_swap_writer(
                            *world,
                            expected_version.saturating_add(1),
                            Some(*to),
                            from.unwrap_or(*to),
                        )
                        .await
                    {
                        return Err(ApplicationError::RollbackConflict(format!(
                            "world writer compensation failed after start error: {compensation_error}"
                        )));
                    }
                    return Err(error);
                }
                self.observe(step, None).await
            }
            OperationStep::EndpointReconnect { .. } => Err(ApplicationError::Port(
                "endpoint reconnect requires prepared runtime evidence".into(),
            )),
            OperationStep::AccessPolicyUpdate {
                policy_id,
                service_id,
                expected_version,
                desired_grants,
                ..
            } => {
                self.validate_access_policy_update(*policy_id, *service_id, desired_grants)
                    .await?;
                self.storage
                    .update_access_policy(
                        &AccessPolicy {
                            id: *policy_id,
                            grants: desired_grants.clone(),
                        },
                        *expected_version,
                    )
                    .await
                    .map_err(|_| ApplicationError::Conflict("access policy changed"))?;
                self.observe(step, None).await
            }
            OperationStep::RoutePolicyUpdate {
                route_id,
                expected_cluster,
                target_cluster,
                expected_priority,
                target_priority,
                expected_version,
                disabled,
                ..
            } => {
                let mut route = self
                    .storage
                    .get_route(*route_id)
                    .await
                    .map_err(|_| ApplicationError::NotFound("route"))?
                    .ok_or(ApplicationError::NotFound("route"))?;
                if route.target_cluster != *expected_cluster || route.priority != *expected_priority
                {
                    return Err(ApplicationError::StalePlan);
                }
                route.target_cluster = *target_cluster;
                route.priority = *target_priority;
                route.disabled = *disabled;
                self.storage
                    .update_route(&route, *expected_version)
                    .await
                    .map_err(|_| ApplicationError::Conflict("route changed"))?;
                self.observe(step, None).await
            }
            OperationStep::ServiceArchive {
                service_id,
                expected_version,
                sunsetting_evidence_hash,
                session_id,
            } => {
                let mut service = self
                    .storage
                    .get_service(*service_id)
                    .await
                    .map_err(|_| ApplicationError::NotFound("service"))?
                    .ok_or(ApplicationError::NotFound("service"))?;
                if service.lifecycle != kitsunebi_domain::ServiceLifecycle::Sunsetting {
                    return Err(ApplicationError::Conflict(
                        "service must be sunsetting before archive",
                    ));
                }
                if Self::service_state_hash(&service) != *sunsetting_evidence_hash {
                    return Err(ApplicationError::StalePlan);
                }
                let retirement = self
                    .storage
                    .retirement_safety(*service_id)
                    .await
                    .map_err(|_| ApplicationError::Conflict("retirement state unavailable"))?;
                if retirement.active_routes
                    || retirement.active_world_writers
                    || retirement.active_execution_bindings
                    || !retirement.effective_access_grants.is_empty()
                {
                    return Err(ApplicationError::Conflict(
                        "service retirement blockers remain",
                    ));
                }
                self.require_verified_session_backup(
                    *session_id,
                    kitsunebi_domain::BackupKind::ServiceConsistent,
                    kitsunebi_domain::BackupTarget::Service(*service_id),
                )
                .await?;
                service.lifecycle = kitsunebi_domain::ServiceLifecycle::Archived;
                self.storage
                    .update_service(&service, *expected_version)
                    .await
                    .map_err(|_| ApplicationError::Conflict("service changed"))?;
                self.observe(step, None).await
            }
            OperationStep::ArtifactActivate {
                binding_id,
                binding,
                artifact,
                artifact_set,
                cluster,
                expected_revision,
                target_revision,
                expected_digest,
                destination_path,
                expected_before_digest,
                ..
            } => {
                let current = self
                    .storage
                    .get_cluster(*cluster)
                    .await
                    .map_err(|_| ApplicationError::NotFound("cluster"))?
                    .ok_or(ApplicationError::NotFound("cluster"))?;
                if current.current_revision != Some(*expected_revision) {
                    return Err(ApplicationError::StalePlan);
                }
                let revision = self
                    .storage
                    .get_revision(*target_revision)
                    .await
                    .map_err(|_| ApplicationError::NotFound("cluster revision"))?
                    .ok_or(ApplicationError::NotFound("cluster revision"))?;
                if revision.artifact_set != *artifact_set {
                    return Err(ApplicationError::StalePlan);
                }
                let set = self
                    .storage
                    .get_artifact_set(*artifact_set)
                    .await
                    .map_err(|_| ApplicationError::NotFound("artifact set"))?
                    .ok_or(ApplicationError::NotFound("artifact set"))?;
                if !set.artifacts.contains(artifact) {
                    return Err(ApplicationError::StalePlan);
                }
                let selected = self.artifact(*artifact).await?;
                if selected.digest != *expected_digest {
                    return Err(ApplicationError::StalePlan);
                }
                self.validate_declared_file_revision(
                    *target_revision,
                    destination_path,
                    &FileClassification::Artifact,
                )
                .await?;
                self.ensure_placement(binding).await?;
                if self.binding_id_for(binding).await? != *binding_id {
                    return Err(ApplicationError::Conflict(
                        "artifact binding identity does not match persisted binding",
                    ));
                }
                let before = self.observe_file(binding, destination_path).await?;
                if expected_before_digest
                    .as_deref()
                    .is_some_and(|expected| expected != before)
                {
                    return Err(ApplicationError::StalePlan);
                }
                let bytes = self.file_bytes(expected_digest).await?;
                self.execution
                    .upload(
                        binding,
                        &FileChange {
                            path: destination_path.clone(),
                            content_digest: expected_digest.clone(),
                            classification: FileClassification::Artifact,
                        },
                        &bytes,
                    )
                    .await?;
                let after = self.observe_file(binding, destination_path).await?;
                if after != *expected_digest {
                    return Err(ApplicationError::VerificationFailed(
                        "artifact activation digest mismatch".into(),
                    ));
                }
                self.storage
                    .activate_cluster_revision(*cluster, Some(*expected_revision), *target_revision)
                    .await
                    .map_err(|_| ApplicationError::Conflict("cluster revision changed"))?;
                self.observe(step, None).await
            }
            OperationStep::BackupRestore {
                expected_manifest_digest,
                ..
            } => {
                let _ = self.apply_restore(step).await?;
                Ok(StepObservation {
                    state_hash: expected_manifest_digest.clone(),
                    completed: true,
                    unambiguous: true,
                })
            }
            OperationStep::BackupCreate { .. } => Err(ApplicationError::Conflict(
                "backup create requires a session-bound request",
            )),
            OperationStep::ServicePurge {
                service_id,
                expected_version,
                archive_evidence_hash,
                archived_at,
                verified_backup_id,
                session_id,
            } => {
                let service = self
                    .storage
                    .get_service(*service_id)
                    .await
                    .map_err(|_| ApplicationError::NotFound("service"))?
                    .ok_or(ApplicationError::NotFound("service"))?;
                if service.lifecycle != kitsunebi_domain::ServiceLifecycle::Archived
                    || Self::service_state_hash(&service) != *archive_evidence_hash
                {
                    return Err(ApplicationError::StalePlan);
                }
                let retirement = self
                    .storage
                    .retirement_safety(*service_id)
                    .await
                    .map_err(|_| ApplicationError::Conflict("retirement state unavailable"))?;
                if retirement.active_routes
                    || retirement.active_world_writers
                    || retirement.active_execution_bindings
                    || !retirement.effective_access_grants.is_empty()
                {
                    return Err(ApplicationError::Conflict("service purge blockers remain"));
                }
                let backup = self
                    .storage
                    .get_backup_reference(*verified_backup_id)
                    .await
                    .map_err(|_| ApplicationError::NotFound("backup reference"))?
                    .ok_or(ApplicationError::NotFound("backup reference"))?;
                if backup.session_id != *session_id {
                    return Err(ApplicationError::Conflict(
                        "service purge backup is outside the change session",
                    ));
                }
                self.reobserve_verified_backup(
                    *verified_backup_id,
                    kitsunebi_domain::BackupKind::ServiceConsistent,
                    kitsunebi_domain::BackupTarget::Service(*service_id),
                )
                .await?;
                self.storage
                    .purge_archived_service(*service_id, *expected_version, *archived_at)
                    .await
                    .map_err(|_| ApplicationError::Conflict("archived service changed"))?;
                self.observe(step, None).await
            }
        }
    }
}

#[async_trait]
impl DurableStepPort for ControllerStepPort {
    async fn observe(
        &self,
        step: &OperationStep,
        evidence: Option<&StepEvidence>,
    ) -> Result<StepObservation, ApplicationError> {
        ControllerStepPort::observe(self, step, evidence).await
    }

    async fn observe_restore(
        &self,
        step: &OperationStep,
        evidence: Option<&StepEvidence>,
    ) -> Result<StepObservation, ApplicationError> {
        ControllerStepPort::observe_restore(self, step, evidence).await
    }

    async fn observe_backup(
        &self,
        step: &OperationStep,
        evidence: Option<&StepEvidence>,
    ) -> Result<StepObservation, ApplicationError> {
        ControllerStepPort::observe_backup(self, step, evidence).await
    }

    async fn prepare(
        &self,
        step: &OperationStep,
    ) -> Result<Option<StepExecutionEvidence>, ApplicationError> {
        ControllerStepPort::prepare(self, step).await
    }

    async fn apply(
        &self,
        step: &OperationStep,
        prepared: Option<&StepExecutionEvidence>,
    ) -> Result<StepApplyResult, ApplicationError> {
        ControllerStepPort::apply(self, step, prepared).await
    }

    async fn apply_backup(
        &self,
        step: &OperationStep,
    ) -> Result<kitsunebi_domain::BackupReference, ApplicationError> {
        ControllerStepPort::apply_backup(self, step).await
    }

    async fn apply_restore(
        &self,
        step: &OperationStep,
    ) -> Result<BackupRestoreInvocation, ApplicationError> {
        ControllerStepPort::apply_restore(self, step).await
    }
}

#[async_trait]
impl RollbackStepPort for ControllerStepPort {
    async fn rollback(
        &self,
        step: &OperationStep,
        evidence: Option<&StepEvidence>,
    ) -> Result<StepObservation, ApplicationError> {
        let reversible = !matches!(
            step,
            OperationStep::ClusterRevisionCreate { .. }
                | OperationStep::ArtifactStage { .. }
                | OperationStep::ArtifactRegister { .. }
                | OperationStep::BackupCreate { .. }
                | OperationStep::BackupRestore { .. }
                | OperationStep::ServicePurge { .. }
        );
        if reversible {
            let Some(inverse) = evidence.and_then(|item| item.execution.as_ref()) else {
                return Err(ApplicationError::RollbackConflict(
                    "step inverse evidence is unavailable".into(),
                ));
            };
            inverse.validate_for(step).map_err(|_| {
                ApplicationError::RollbackConflict(
                    "step inverse evidence does not match action".into(),
                )
            })?;
        }
        match step {
            OperationStep::ExecutionProvision { binding } => {
                let Some(StepExecutionEvidence::Execution {
                    binding_id,
                    created_provider_unit: Some(_),
                    ..
                }) = evidence.and_then(|item| item.execution.as_ref())
                else {
                    return Err(ApplicationError::RollbackConflict(
                        "execution provision identity is unavailable".into(),
                    ));
                };
                if *binding_id != self.binding_id_for(binding).await? {
                    return Err(ApplicationError::RollbackConflict(
                        "execution provision identity mismatch".into(),
                    ));
                }
                self.execution.delete(binding).await?;
                Ok(StepObservation {
                    state_hash: Self::hash(b"absent"),
                    completed: true,
                    unambiguous: true,
                })
            }
            OperationStep::ExecutionDelete { binding, .. } => {
                let Some(StepExecutionEvidence::Execution {
                    binding_id,
                    prior_binding: Some(prior_binding),
                    ..
                }) = evidence.and_then(|item| item.execution.as_ref())
                else {
                    return Err(ApplicationError::RollbackConflict(
                        "execution deletion snapshot is unavailable".into(),
                    ));
                };
                if *binding_id != self.binding_id_for(binding).await? || prior_binding != binding {
                    return Err(ApplicationError::RollbackConflict(
                        "execution deletion snapshot mismatch".into(),
                    ));
                }
                self.execution.create(prior_binding).await?;
                self.observe(step, None).await
            }
            OperationStep::ServiceLifecycleTransition {
                service_id,
                expected_state,
                next_state,
                expected_version,
                ..
            } => {
                let mut service = self
                    .storage
                    .get_service(*service_id)
                    .await
                    .map_err(|_| ApplicationError::NotFound("service"))?
                    .ok_or(ApplicationError::NotFound("service"))?;
                if service.lifecycle != *next_state {
                    return Err(ApplicationError::RollbackConflict(
                        "service lifecycle changed before rollback".into(),
                    ));
                }
                let Some(StepExecutionEvidence::Lifecycle {
                    service_id: evidence_service,
                    prior_state,
                }) = evidence.and_then(|value| value.execution.as_ref())
                else {
                    return Err(ApplicationError::RollbackConflict(
                        "lifecycle inverse unavailable".into(),
                    ));
                };
                if evidence_service != service_id || prior_state != expected_state {
                    return Err(ApplicationError::RollbackConflict(
                        "lifecycle inverse does not match plan".into(),
                    ));
                }
                service.lifecycle = prior_state.clone();
                self.storage
                    .update_service(&service, expected_version.saturating_add(1))
                    .await
                    .map_err(|_| {
                        ApplicationError::RollbackConflict(
                            "service lifecycle version changed before rollback".into(),
                        )
                    })?;
                self.observe(step, None).await
            }
            OperationStep::ClusterRevisionCreate { .. } => Err(ApplicationError::RollbackConflict(
                "cluster revision creation has no reversible delete operation".into(),
            )),
            OperationStep::ExecutionStart { binding } => {
                self.ensure_placement(binding).await?;
                self.execution.stop(binding).await?;
                self.observe(step, None).await
            }
            OperationStep::ExecutionStop { binding } => {
                self.ensure_placement(binding).await?;
                let prior_running = match evidence.and_then(|item| item.execution.as_ref()) {
                    Some(StepExecutionEvidence::Execution { prior_running, .. }) => *prior_running,
                    _ => {
                        return Err(ApplicationError::RollbackConflict(
                            "execution stop prior state is unavailable".into(),
                        ));
                    }
                };
                if prior_running {
                    self.execution.start(binding).await?;
                }
                self.observe(step, None).await
            }
            OperationStep::FileMove {
                binding,
                classification,
                ..
            } => {
                let Some(StepExecutionEvidence::File { inverse }) =
                    evidence.and_then(|value| value.execution.as_ref())
                else {
                    return Err(ApplicationError::RollbackConflict(
                        "file inverse unavailable".into(),
                    ));
                };
                self.ensure_placement(binding).await?;
                let moved_digest =
                    inverse
                        .prior_digest
                        .as_deref()
                        .ok_or(ApplicationError::RollbackConflict(
                            "file move source digest unavailable".into(),
                        ))?;
                if !inverse.prior_exists {
                    return Err(ApplicationError::RollbackConflict(
                        "file move source was absent before apply".into(),
                    ));
                }
                // The source must still be absent and the destination must
                // still contain the moved digest before restoring either side.
                if !self
                    .execution
                    .files(binding, &inverse.path)
                    .await?
                    .is_empty()
                {
                    return Err(ApplicationError::RollbackConflict(
                        "file move source changed before rollback".into(),
                    ));
                }
                let target =
                    inverse
                        .target_path
                        .as_deref()
                        .ok_or(ApplicationError::RollbackConflict(
                            "file move destination unavailable".into(),
                        ))?;
                if let Some(digest) = inverse.target_digest.as_deref() {
                    self.restore_inverse_bytes_checked(
                        binding,
                        target,
                        digest,
                        inverse.target_size,
                        classification.clone(),
                        moved_digest,
                    )
                    .await?;
                } else {
                    self.execution
                        .delete_file_checked(binding, target, moved_digest)
                        .await
                        .map_err(|_| {
                            ApplicationError::RollbackConflict(
                                "file move destination changed before rollback".into(),
                            )
                        })?;
                }
                self.restore_inverse_bytes(
                    binding,
                    &inverse.path,
                    moved_digest,
                    inverse.prior_size,
                    classification.clone(),
                )
                .await?;
                Ok(StepObservation {
                    state_hash: inverse.prior_digest.clone().unwrap_or_default(),
                    completed: true,
                    unambiguous: true,
                })
            }
            OperationStep::FileWrite {
                binding, change, ..
            } => {
                let Some(StepExecutionEvidence::File { inverse }) =
                    evidence.and_then(|value| value.execution.as_ref())
                else {
                    return Err(ApplicationError::RollbackConflict(
                        "file inverse unavailable".into(),
                    ));
                };
                self.ensure_placement(binding).await?;
                self.restore_inverse(
                    binding,
                    inverse,
                    change.classification.clone(),
                    &change.content_digest,
                )
                .await?;
                let restored = self.execution.read_file(binding, &change.path).await?;
                Ok(StepObservation {
                    state_hash: Self::hash(&restored),
                    completed: true,
                    unambiguous: true,
                })
            }
            OperationStep::FileQuarantine {
                binding,
                path,
                classification: _classification,
                ..
            } => {
                let Some(StepExecutionEvidence::File { inverse }) =
                    evidence.and_then(|value| value.execution.as_ref())
                else {
                    return Err(ApplicationError::RollbackConflict(
                        "quarantine inverse unavailable".into(),
                    ));
                };
                self.ensure_placement(binding).await?;
                if inverse.path != *path {
                    return Err(ApplicationError::RollbackConflict(
                        "quarantine path mismatch".into(),
                    ));
                }
                let prior_digest =
                    inverse
                        .prior_digest
                        .as_deref()
                        .ok_or(ApplicationError::RollbackConflict(
                            "quarantine inverse has no prior bytes".into(),
                        ))?;
                self.execution
                    .restore_quarantined_file_checked(binding, path, prior_digest)
                    .await?;
                let restored = self.execution.read_file(binding, path).await?;
                if Self::hash(&restored) != prior_digest
                    || Some(restored.len() as u64) != inverse.prior_size
                {
                    return Err(ApplicationError::VerificationFailed(
                        "quarantine rollback postcondition mismatch".into(),
                    ));
                }
                Ok(StepObservation {
                    state_hash: Self::hash(&restored),
                    completed: true,
                    unambiguous: true,
                })
            }
            OperationStep::FileBatch {
                binding,
                operations,
                ..
            } => {
                let Some(StepExecutionEvidence::FileBatch { entries }) =
                    evidence.and_then(|value| value.execution.as_ref())
                else {
                    return Err(ApplicationError::RollbackConflict(
                        "file batch inverse unavailable".into(),
                    ));
                };
                if entries.len() != operations.len() {
                    return Err(ApplicationError::RollbackConflict(
                        "file batch inverse cardinality mismatch".into(),
                    ));
                }
                self.ensure_placement(binding).await?;
                let mut restored_hashes = Vec::with_capacity(operations.len());
                for (index, operation) in operations.iter().enumerate().rev() {
                    let inverse = &entries[index];
                    match operation {
                        FileBatchOperation::Write {
                            path,
                            classification,
                            content,
                            ..
                        } => {
                            if inverse.path != *path {
                                return Err(ApplicationError::RollbackConflict(
                                    "file batch path mismatch".into(),
                                ));
                            }
                            self.restore_inverse(
                                binding,
                                inverse,
                                classification.clone(),
                                &content.digest,
                            )
                            .await?;
                            restored_hashes
                                .push(Self::hash(&self.execution.read_file(binding, path).await?));
                        }
                        FileBatchOperation::Move {
                            from,
                            to,
                            classification,
                            ..
                        } => {
                            if inverse.path != *from || inverse.target_path.as_deref() != Some(to) {
                                return Err(ApplicationError::RollbackConflict(
                                    "file batch move mismatch".into(),
                                ));
                            }
                            let moved_digest = inverse.prior_digest.as_deref().ok_or(
                                ApplicationError::RollbackConflict(
                                    "file batch source snapshot unavailable".into(),
                                ),
                            )?;
                            if !inverse.prior_exists
                                || !self.execution.files(binding, from).await?.is_empty()
                            {
                                return Err(ApplicationError::RollbackConflict(
                                    "file batch move source changed before rollback".into(),
                                ));
                            }
                            if let Some(digest) = inverse.target_digest.as_deref() {
                                self.restore_inverse_bytes_checked(
                                    binding,
                                    to,
                                    digest,
                                    inverse.target_size,
                                    classification.clone(),
                                    moved_digest,
                                )
                                .await?;
                            } else {
                                self.execution
                                    .delete_file_checked(binding, to, moved_digest)
                                    .await
                                    .map_err(|_| {
                                        ApplicationError::RollbackConflict(
                                            "file batch move destination changed before rollback"
                                                .into(),
                                        )
                                    })?;
                            }
                            self.restore_inverse_bytes(
                                binding,
                                from,
                                moved_digest,
                                inverse.prior_size,
                                classification.clone(),
                            )
                            .await?;
                            restored_hashes
                                .push(Self::hash(&self.execution.read_file(binding, from).await?));
                        }
                        FileBatchOperation::Quarantine {
                            path,
                            classification: _classification,
                            ..
                        } => {
                            if inverse.path != *path {
                                return Err(ApplicationError::RollbackConflict(
                                    "quarantine path mismatch".into(),
                                ));
                            }
                            let prior_digest = inverse.prior_digest.as_deref().ok_or(
                                ApplicationError::RollbackConflict(
                                    "quarantine snapshot unavailable".into(),
                                ),
                            )?;
                            self.execution
                                .restore_quarantined_file_checked(binding, path, prior_digest)
                                .await?;
                            let restored = self.execution.read_file(binding, path).await?;
                            if Self::hash(&restored) != prior_digest
                                || Some(restored.len() as u64) != inverse.prior_size
                            {
                                return Err(ApplicationError::VerificationFailed(
                                    "quarantine rollback postcondition mismatch".into(),
                                ));
                            }
                            restored_hashes
                                .push(Self::hash(&self.execution.read_file(binding, path).await?));
                        }
                    }
                }
                Ok(StepObservation {
                    state_hash: kitsunebi_api::plan_hash(restored_hashes.join("|").as_bytes()),
                    completed: true,
                    unambiguous: true,
                })
            }
            OperationStep::ExecutionRestart { binding } => {
                self.ensure_placement(binding).await?;
                self.execution.restart(binding).await?;
                self.observe(step, None).await
            }
            OperationStep::ArtifactActivate {
                binding,
                cluster,
                target_revision,
                destination_path,
                expected_digest,
                ..
            } => {
                let Some(StepExecutionEvidence::Artifact {
                    binding_id,
                    cluster_id,
                    prior_revision: Some(prior_revision),
                    destination_path: evidence_path,
                    prior_digest,
                    prior_size,
                    prior_exists,
                    ..
                }) = evidence.and_then(|value| value.execution.as_ref())
                else {
                    return Err(ApplicationError::RollbackConflict(
                        "artifact inverse is unavailable".into(),
                    ));
                };
                if *cluster_id != *cluster
                    || evidence_path != destination_path
                    || *binding_id != self.binding_id_for(binding).await?
                {
                    return Err(ApplicationError::RollbackConflict(
                        "artifact inverse does not match plan".into(),
                    ));
                }
                self.ensure_placement(binding).await?;
                if *prior_exists {
                    let prior_digest =
                        prior_digest
                            .as_deref()
                            .ok_or(ApplicationError::RollbackConflict(
                                "artifact prior digest unavailable".into(),
                            ))?;
                    self.restore_inverse_bytes_checked(
                        binding,
                        destination_path,
                        prior_digest,
                        *prior_size,
                        FileClassification::Artifact,
                        expected_digest,
                    )
                    .await?;
                } else {
                    self.execution
                        .delete_file_checked(binding, destination_path, expected_digest)
                        .await
                        .map_err(|_| {
                            ApplicationError::RollbackConflict(
                                "artifact destination changed before rollback".into(),
                            )
                        })?;
                }
                self.storage
                    .activate_cluster_revision(*cluster, Some(*target_revision), *prior_revision)
                    .await
                    .map_err(|_| {
                        ApplicationError::RollbackConflict(
                            "cluster revision changed before artifact rollback".into(),
                        )
                    })?;
                self.observe(step, None).await
            }
            OperationStep::ServiceArchive {
                service_id,
                expected_version,
                ..
            } => {
                let Some(StepExecutionEvidence::Lifecycle {
                    service_id: evidence_service,
                    prior_state,
                }) = evidence.and_then(|value| value.execution.as_ref())
                else {
                    return Err(ApplicationError::RollbackConflict(
                        "archive inverse unavailable".into(),
                    ));
                };
                if evidence_service != service_id {
                    return Err(ApplicationError::RollbackConflict(
                        "archive inverse mismatch".into(),
                    ));
                }
                let mut service = self
                    .storage
                    .get_service(*service_id)
                    .await
                    .map_err(|_| ApplicationError::NotFound("service"))?
                    .ok_or(ApplicationError::NotFound("service"))?;
                if service.lifecycle != kitsunebi_domain::ServiceLifecycle::Archived {
                    return Err(ApplicationError::RollbackConflict(
                        "service archive changed".into(),
                    ));
                }
                service.lifecycle = prior_state.clone();
                self.storage
                    .update_service(&service, expected_version.saturating_add(1))
                    .await
                    .map_err(|_| {
                        ApplicationError::RollbackConflict("service archive version changed".into())
                    })?;
                Ok(StepObservation {
                    state_hash: Self::service_state_hash(&service),
                    completed: true,
                    unambiguous: true,
                })
            }
            OperationStep::ServicePurge { .. } => Err(ApplicationError::RollbackConflict(
                "purging an archived service is irreversible".into(),
            )),
            // A backup reference is an immutable record. It has no inverse
            // call, but it must not prevent compensation of the surrounding
            // maintenance window.
            OperationStep::BackupCreate { request_hash, .. } => Ok(StepObservation {
                state_hash: request_hash.clone(),
                completed: true,
                unambiguous: true,
            }),
            OperationStep::BackupRestore {
                session_id,
                plan_id,
                plan_expiry,
                idempotency_key,
                target,
                rollback_reference,
                expected_rollback_manifest_digest,
                ..
            } => {
                let Some(StepExecutionEvidence::BackupRestore(invocation)) =
                    evidence.and_then(|value| value.execution.as_ref())
                else {
                    return Err(ApplicationError::RollbackConflict(
                        "backup restore invocation evidence is unavailable".into(),
                    ));
                };
                if invocation.rollback_reference_id != *rollback_reference
                    || invocation.expected_rollback_manifest_digest
                        != *expected_rollback_manifest_digest
                {
                    return Err(ApplicationError::RollbackConflict(
                        "backup restore rollback reference mismatch".into(),
                    ));
                }
                let rollback = self
                    .storage
                    .get_backup_reference(*rollback_reference)
                    .await
                    .map_err(|_| ApplicationError::NotFound("rollback backup reference"))?
                    .ok_or(ApplicationError::NotFound("rollback backup reference"))?;
                if rollback.session_id != *session_id
                    || rollback.target != *target
                    || rollback.manifest_digest != *expected_rollback_manifest_digest
                    || rollback.verified_at.is_none()
                {
                    return Err(ApplicationError::RollbackConflict(
                        "rollback backup reference is not verified".into(),
                    ));
                }
                let restored = self
                    .backup
                    .restore(&application::BackupRestoreRequest {
                        session_id: *session_id,
                        plan_id: *plan_id,
                        plan_expiry: *plan_expiry,
                        idempotency_key: format!("{idempotency_key}:rollback"),
                        reference: rollback.clone(),
                        rollback_reference: rollback,
                        target: *target,
                    })
                    .await
                    .map_err(|error| ApplicationError::RollbackConflict(error.to_string()))?;
                if restored.reference_id != *rollback_reference
                    || restored.expected_manifest_digest != *expected_rollback_manifest_digest
                    || restored.target != *target
                {
                    return Err(ApplicationError::RollbackConflict(
                        "provider rollback invocation mismatch".into(),
                    ));
                }
                let observation = self.backup.verify_restore(&restored).await?;
                if observation.manifest_digest != *expected_rollback_manifest_digest {
                    return Err(ApplicationError::RollbackConflict(
                        "provider rollback verification mismatch".into(),
                    ));
                }
                Ok(StepObservation {
                    state_hash: observation.manifest_digest,
                    completed: true,
                    unambiguous: true,
                })
            }
            OperationStep::ArtifactStage {
                expected_digest, ..
            } => Ok(StepObservation {
                state_hash: expected_digest.clone(),
                completed: true,
                unambiguous: true,
            }),
            OperationStep::ArtifactRegister { .. } => Err(ApplicationError::RollbackConflict(
                "registered artifact deletion is not available in the storage contract".into(),
            )),
            OperationStep::ProxyRollout {
                expected_instance,
                target_instance,
                pool,
                binding,
                target_binding_id,
                configuration,
                ..
            } => {
                let Some(StepExecutionEvidence::Proxy {
                    expected_instance_id,
                    target_instance_id,
                    prior_expected_state,
                    prior_target_state,
                    prior_edge_hash,
                    prior_target_member,
                    post_add_edge_hash,
                    final_edge_hash,
                    target_execution_existed,
                    target_execution_was_running,
                    target_execution_created,
                    target_execution_started,
                    old_execution_was_running,
                    configuration_inverse,
                    ..
                }) = evidence.and_then(|value| value.execution.as_ref())
                else {
                    return Err(ApplicationError::RollbackConflict(
                        "proxy inverse evidence is unavailable".into(),
                    ));
                };
                if expected_instance_id != expected_instance
                    || target_instance_id != target_instance
                {
                    return Err(ApplicationError::RollbackConflict(
                        "proxy inverse instance mismatch".into(),
                    ));
                }
                let edge = self
                    .tcp_shield
                    .as_ref()
                    .ok_or(ApplicationError::Port("TCPShield is unavailable".into()))?;
                let (new, old, _, target_execution, old_execution) = self
                    .proxy_bindings(
                        *expected_instance,
                        *target_instance,
                        *pool,
                        binding,
                        *target_binding_id,
                    )
                    .await?;
                let state = edge.edge.observe_set(&new).await?;
                if state.hash() != *final_edge_hash
                    || !state.backends.contains(&new.backend_address)
                    || state.backends.contains(&old.backend_address)
                {
                    return Err(ApplicationError::RollbackConflict(
                        "proxy provider state no longer matches final rollout".into(),
                    ));
                }
                if *prior_target_member {
                    return Err(ApplicationError::RollbackConflict(
                        "proxy target was already a member; exact edge inverse unavailable".into(),
                    ));
                }
                let prior_new = Self::proxy_binding_with_hash(&new, prior_edge_hash);
                self.restore_proxy_old_execution(
                    &old_execution,
                    *old_execution_was_running,
                    *old_execution_was_running,
                )
                .await?;
                let rollback_context = ApplicationError::RollbackConflict(
                    "explicit proxy rollback edge handoff".into(),
                );
                Self::restore_proxy_edge(
                    edge.edge.as_ref(),
                    edge.health.as_ref(),
                    &new,
                    &old,
                    prior_edge_hash,
                    post_add_edge_hash,
                    final_edge_hash,
                    &rollback_context,
                )
                .await?;
                self.rollback_proxy_target_execution(
                    &target_execution,
                    *target_execution_existed,
                    *target_execution_was_running,
                    *target_execution_created,
                    *target_execution_started,
                )
                .await?;
                self.compensate_proxy_configuration(
                    &target_execution,
                    configuration,
                    configuration_inverse,
                    *target_execution_existed,
                )
                .await?;
                let mut new_instance = self
                    .storage
                    .get_proxy_instance(*target_instance)
                    .await
                    .map_err(|_| ApplicationError::NotFound("proxy instance"))?
                    .ok_or(ApplicationError::NotFound("proxy instance"))?;
                let mut old_instance = self
                    .storage
                    .get_proxy_instance(old.instance_id)
                    .await
                    .map_err(|_| ApplicationError::NotFound("proxy instance"))?
                    .ok_or(ApplicationError::NotFound("proxy instance"))?;
                let new_version: u64 =
                    sqlx::query_scalar("SELECT version FROM proxy_instances WHERE id = ?")
                        .bind(target_instance.as_uuid().to_string())
                        .fetch_one(self.storage.pool())
                        .await
                        .map_err(|_| ApplicationError::NotFound("proxy instance"))?;
                let old_version: u64 =
                    sqlx::query_scalar("SELECT version FROM proxy_instances WHERE id = ?")
                        .bind(old.instance_id.as_uuid().to_string())
                        .fetch_one(self.storage.pool())
                        .await
                        .map_err(|_| ApplicationError::NotFound("proxy instance"))?;
                new_instance.state = prior_target_state.clone();
                old_instance.state = prior_expected_state.clone();
                self.storage
                    .update_proxy_instance(&new_instance, new_version)
                    .await
                    .map_err(|_| {
                        ApplicationError::RollbackConflict("proxy instance changed".into())
                    })?;
                self.storage
                    .update_proxy_instance(&old_instance, old_version)
                    .await
                    .map_err(|_| {
                        ApplicationError::RollbackConflict("proxy instance changed".into())
                    })?;
                let restored = edge.edge.observe_set(&prior_new).await.map_err(|error| {
                    ApplicationError::RollbackConflict(format!(
                        "proxy inverse verification failed: {error}"
                    ))
                })?;
                if restored.hash() != *prior_edge_hash
                    || !restored.backends.contains(&old.backend_address)
                    || restored.backends.contains(&new.backend_address)
                {
                    return Err(ApplicationError::RollbackConflict(
                        "proxy inverse provider postcondition did not hold".into(),
                    ));
                }
                Ok(StepObservation {
                    state_hash: Self::hash(
                        format!("{}:{}", restored.hash(), target_binding_id.as_uuid()).as_bytes(),
                    ),
                    completed: new_instance.state == *prior_target_state
                        && old_instance.state == *prior_expected_state,
                    unambiguous: true,
                })
            }
            OperationStep::WorldWriterCutover {
                world,
                to,
                expected_writer_binding_id,
                target_writer_binding_id,
                expected_writer_binding_hash,
                target_writer_binding_hash,
                ..
            } => {
                let Some(StepExecutionEvidence::World {
                    world_id,
                    prior_writer,
                    prior_version,
                    expected_writer_binding_id: evidence_expected_binding_id,
                    target_writer_binding_id: evidence_target_binding_id,
                    prior_writer_binding_hash: evidence_prior_binding_hash,
                    target_writer_binding_hash: evidence_target_binding_hash,
                }) = evidence.and_then(|value| value.execution.as_ref())
                else {
                    return Err(ApplicationError::RollbackConflict(
                        "world inverse is unavailable".into(),
                    ));
                };
                if world_id != world
                    || evidence_expected_binding_id != expected_writer_binding_id
                    || evidence_target_binding_id != target_writer_binding_id
                    || evidence_prior_binding_hash.as_deref()
                        != expected_writer_binding_hash.as_deref()
                    || evidence_target_binding_hash != target_writer_binding_hash
                {
                    return Err(ApplicationError::RollbackConflict(
                        "world inverse mismatch".into(),
                    ));
                }
                let Some(prior_writer) = prior_writer else {
                    return Err(ApplicationError::RollbackConflict(
                        "world rollback cannot represent an unowned writer in provider contract"
                            .into(),
                    ));
                };
                let target_binding = self
                    .world_binding(*world, *target_writer_binding_id, Some(*to))
                    .await
                    .map_err(|_| {
                        ApplicationError::RollbackConflict("world target binding changed".into())
                    })?;
                let status = self.execution.status(&target_binding).await?;
                if !status.running {
                    return Err(ApplicationError::RollbackConflict(
                        "world target is no longer in the applied state".into(),
                    ));
                }
                self.execution.stop(&target_binding).await?;
                if let Err(error) = self
                    .storage
                    .compare_and_swap_writer(
                        *world,
                        prior_version.saturating_add(1),
                        Some(*to),
                        *prior_writer,
                    )
                    .await
                {
                    let _ = self.execution.start(&target_binding).await;
                    return Err(ApplicationError::RollbackConflict(error.to_string()));
                }
                Ok(StepObservation {
                    state_hash: Self::hash(
                        serde_json::to_string(&Some(*prior_writer))
                            .unwrap_or_default()
                            .as_bytes(),
                    ),
                    completed: true,
                    unambiguous: true,
                })
            }
            OperationStep::EndpointReconnect {
                expected_binding_id,
                target_binding_id,
                cluster,
                expected_version,
                expected_revision,
                target_revision,
                ..
            } => {
                let Some(StepExecutionEvidence::Endpoint {
                    expected_binding_id: evidence_expected,
                    target_binding_id: evidence_target,
                    prior_revision,
                    prior_binding,
                    target_binding,
                    runtime,
                }) = evidence.and_then(|value| value.execution.as_ref())
                else {
                    return Err(ApplicationError::RollbackConflict(
                        "endpoint inverse is unavailable".into(),
                    ));
                };
                if evidence_expected != expected_binding_id
                    || evidence_target != target_binding_id
                    || prior_revision != expected_revision
                {
                    return Err(ApplicationError::RollbackConflict(
                        "endpoint inverse does not match plan".into(),
                    ));
                }
                let current = self
                    .storage
                    .get_endpoint_binding(*target_binding_id)
                    .await
                    .map_err(|_| ApplicationError::NotFound("endpoint binding"))?
                    .ok_or(ApplicationError::NotFound("endpoint binding"))?;
                if current.cluster_id != *cluster
                    || current.revision_id != *target_revision
                    || prior_binding.cluster_id != *cluster
                    || target_binding.cluster_id != *cluster
                    || target_binding.revision_id != *target_revision
                {
                    return Err(ApplicationError::RollbackConflict(
                        "endpoint changed before rollback".into(),
                    ));
                }
                let endpoint = self
                    .storage
                    .list_endpoints()
                    .await
                    .map_err(|_| ApplicationError::RollbackConflict("endpoint unavailable".into()))?
                    .into_iter()
                    .find(|endpoint| endpoint.id == prior_binding.endpoint_id)
                    .ok_or(ApplicationError::RollbackConflict(
                        "endpoint unavailable".into(),
                    ))?;
                let addresses = SystemDnsResolver
                    .resolve(&endpoint.logical_hostname, endpoint.port)
                    .await
                    .map_err(|error| ApplicationError::RollbackConflict(error.to_string()))?;
                if addresses.is_empty() {
                    return Err(ApplicationError::RollbackConflict(
                        "endpoint did not resolve during rollback".into(),
                    ));
                }
                TcpShieldHealth
                    .verify(&format!("{}:{}", endpoint.logical_hostname, endpoint.port))
                    .await
                    .map_err(|error| ApplicationError::RollbackConflict(error.to_string()))?;
                for observation in runtime {
                    let binding = self
                        .storage
                        .get_gameap_binding(observation.binding_id.as_uuid())
                        .await
                        .map_err(|_| ApplicationError::NotFound("endpoint runtime binding"))?
                        .ok_or(ApplicationError::NotFound("endpoint runtime binding"))?;
                    let status = self.execution.status(&binding).await?;
                    if status.running != observation.prior_running {
                        return Err(ApplicationError::RollbackConflict(
                            "endpoint runtime changed before rollback".into(),
                        ));
                    }
                }
                self.storage
                    .rollback_endpoint_bindings_at_version(
                        *cluster,
                        *expected_binding_id,
                        *target_binding_id,
                        expected_version.saturating_add(1),
                    )
                    .await
                    .map_err(|_| {
                        ApplicationError::RollbackConflict(
                            "endpoint revision changed before rollback".into(),
                        )
                    })?;
                macro_rules! compensate_runtime_failure {
                    ($error:expr) => {
                        return Err(self
                            .compensate_endpoint_rollback_runtime(
                                *cluster,
                                prior_binding,
                                target_binding,
                                *expected_version,
                                runtime,
                                $error,
                            )
                            .await)
                    };
                }
                for observation in runtime {
                    if !observation.prior_running {
                        continue;
                    }
                    let binding = self
                        .storage
                        .get_gameap_binding(observation.binding_id.as_uuid())
                        .await
                        .map_err(|_| ApplicationError::NotFound("endpoint runtime binding"))?
                        .ok_or(ApplicationError::NotFound("endpoint runtime binding"))?;
                    if let Err(error) = self.execution.restart(&binding).await {
                        compensate_runtime_failure!(error);
                    }
                    let status = match self.execution.status(&binding).await {
                        Ok(status) => status,
                        Err(error) => compensate_runtime_failure!(error),
                    };
                    if !status.running {
                        compensate_runtime_failure!(ApplicationError::VerificationFailed(
                            "endpoint runtime did not reconnect during rollback".into(),
                        ));
                    }
                }
                let current = match self.storage.get_cluster(*cluster).await {
                    Ok(Some(current)) => current,
                    Ok(None) => {
                        compensate_runtime_failure!(ApplicationError::NotFound("endpoint cluster"))
                    }
                    Err(error) => compensate_runtime_failure!(ApplicationError::Port(format!(
                        "endpoint rollback observation failed: {error}"
                    ))),
                };
                if current.current_revision != Some(*expected_revision) {
                    compensate_runtime_failure!(ApplicationError::RollbackConflict(
                        "endpoint rollback revision postcondition did not hold".into()
                    ));
                }
                let mut post_addresses = match SystemDnsResolver
                    .resolve(&endpoint.logical_hostname, endpoint.port)
                    .await
                {
                    Ok(addresses) => addresses,
                    Err(error) => compensate_runtime_failure!(error),
                };
                post_addresses.sort();
                post_addresses.dedup();
                if post_addresses.is_empty() {
                    compensate_runtime_failure!(ApplicationError::VerificationFailed(
                        "endpoint did not resolve during rollback verification".into()
                    ));
                }
                if let Err(error) = TcpShieldHealth
                    .verify(&format!("{}:{}", endpoint.logical_hostname, endpoint.port))
                    .await
                {
                    compensate_runtime_failure!(error);
                }
                let mut runtime_state = Vec::with_capacity(runtime.len());
                for observation in runtime {
                    let binding = match self
                        .storage
                        .get_gameap_binding(observation.binding_id.as_uuid())
                        .await
                    {
                        Ok(Some(binding)) => binding,
                        Ok(None) => compensate_runtime_failure!(ApplicationError::NotFound(
                            "endpoint runtime binding"
                        )),
                        Err(error) => compensate_runtime_failure!(ApplicationError::Port(format!(
                            "endpoint runtime observation failed: {error}"
                        ))),
                    };
                    let status = match self.execution.status(&binding).await {
                        Ok(status) => status,
                        Err(error) => compensate_runtime_failure!(error),
                    };
                    if status.running != observation.prior_running {
                        compensate_runtime_failure!(ApplicationError::VerificationFailed(
                            "endpoint runtime rollback postcondition did not hold".into()
                        ));
                    }
                    runtime_state.push(format!(
                        "{}:{}:{}",
                        observation.binding_id.as_uuid(),
                        status.running,
                        status.state_hash
                    ));
                }
                runtime_state.sort();
                let state_hash = Self::hash(
                    format!(
                        "{}:{}:{}:{}",
                        current
                            .current_revision
                            .map(|revision| revision.as_uuid().to_string())
                            .unwrap_or_default(),
                        prior_binding.id.as_uuid(),
                        post_addresses.join(","),
                        runtime_state.join("|")
                    )
                    .as_bytes(),
                );
                Ok(StepObservation {
                    state_hash,
                    completed: true,
                    unambiguous: true,
                })
            }
            OperationStep::AccessPolicyUpdate {
                policy_id,
                expected_version,
                ..
            } => {
                let Some(StepExecutionEvidence::Access {
                    policy_id: evidence_policy,
                    prior_grants,
                    ..
                }) = evidence.and_then(|value| value.execution.as_ref())
                else {
                    return Err(ApplicationError::RollbackConflict(
                        "access inverse unavailable".into(),
                    ));
                };
                if evidence_policy != policy_id {
                    return Err(ApplicationError::RollbackConflict(
                        "access inverse mismatch".into(),
                    ));
                }
                self.storage
                    .update_access_policy(
                        &AccessPolicy {
                            id: *policy_id,
                            grants: prior_grants.clone(),
                        },
                        expected_version.saturating_add(1),
                    )
                    .await
                    .map_err(|_| {
                        ApplicationError::RollbackConflict(
                            "access policy changed before rollback".into(),
                        )
                    })?;
                Ok(StepObservation {
                    state_hash: Self::hash(&serde_json::to_vec(prior_grants).unwrap_or_default()),
                    completed: true,
                    unambiguous: true,
                })
            }
            OperationStep::RoutePolicyUpdate {
                route_id,
                expected_cluster,
                target_cluster,
                expected_priority,
                target_priority,
                expected_version,
                disabled,
                ..
            } => {
                let Some(StepExecutionEvidence::Route {
                    route_id: prior_id,
                    prior_cluster,
                    prior_priority,
                    prior_disabled,
                    prior_version,
                }) = evidence.and_then(|value| value.execution.as_ref())
                else {
                    return Err(ApplicationError::RollbackConflict(
                        "route inverse evidence is unavailable".into(),
                    ));
                };
                if prior_id != route_id
                    || *prior_cluster != *expected_cluster
                    || *prior_priority != *expected_priority
                    || *prior_version != *expected_version
                {
                    return Err(ApplicationError::RollbackConflict(
                        "route inverse evidence does not match plan".into(),
                    ));
                }
                let mut route = self
                    .storage
                    .get_route(*route_id)
                    .await
                    .map_err(|_| ApplicationError::NotFound("route"))?
                    .ok_or(ApplicationError::NotFound("route"))?;
                if route.target_cluster != *target_cluster
                    || route.priority != *target_priority
                    || route.disabled != *disabled
                {
                    return Err(ApplicationError::RollbackConflict(
                        "route changed before rollback".into(),
                    ));
                }
                route.target_cluster = *expected_cluster;
                route.priority = *expected_priority;
                route.disabled = *prior_disabled;
                self.storage
                    .update_route(&route, prior_version.saturating_add(1))
                    .await
                    .map_err(|_| {
                        ApplicationError::RollbackConflict(
                            "route version changed before rollback".into(),
                        )
                    })?;
                self.observe(step, None).await
            }
        }
    }
}

/// Content-addressed artifact bridge. Discovery/staging uses the concrete
/// HTTPS provider; activation is owned by the application artifact service.
#[derive(Clone)]
pub struct ArtifactBridge {
    pub cas: Arc<CasStore>,
    pub transport: Arc<ArtifactHttpTransport>,
}
impl ArtifactBridge {
    pub fn new(root: PathBuf) -> Result<Self, ApiError> {
        let cas = CasStore::new(root, kitsunebi_artifacts::MAX_DEFAULT_BYTES)
            .map_err(|_| ApiError::SecurityMisconfigured)?;
        // The artifact crate intentionally uses reqwest's blocking client because its
        // provider port is synchronous. Construct it off the Tokio runtime: reqwest's
        // blocking builder creates a private runtime and panics when entered from an
        // asynchronous context.
        let transport =
            std::thread::spawn(|| ArtifactHttpTransport::new(ArtifactTransportConfig::default()))
                .join()
                .map_err(|_| ApiError::SecurityMisconfigured)?
                .map_err(|_| ApiError::SecurityMisconfigured)?;
        Ok(Self {
            cas: Arc::new(cas),
            transport: Arc::new(transport),
        })
    }
    async fn has_digest(&self, digest: &str) -> Result<bool, ApplicationError> {
        let cas = self.cas.clone();
        let digest = digest.to_owned();
        tokio::task::spawn_blocking(move || cas.metadata(&digest).is_ok())
            .await
            .map_err(|_| ApplicationError::Port("artifact CAS observation failed".into()))
    }
    async fn stage_artifact(&self, artifact: &Artifact) -> Result<(), ApplicationError> {
        let bytes = self.download_artifact(artifact).await?;
        self.put(&artifact.digest, &bytes).await
    }
    async fn download_artifact(&self, artifact: &Artifact) -> Result<Vec<u8>, ApplicationError> {
        let transport = self.transport.clone();
        let cas = self.cas.clone();
        let artifact = artifact.clone();
        tokio::task::spawn_blocking(move || {
            if artifact.source == "manual" {
                return cas
                    .read(&artifact.digest)
                    .map_err(|_| ApplicationError::NotFound("artifact"));
            }

            fn select<'a>(
                items: &'a [ArtifactMetadata],
                artifact: &Artifact,
            ) -> Option<&'a ArtifactMetadata> {
                items.iter().find(|item| {
                    let digest_matches = !item.digest.is_empty() && item.digest == artifact.digest;
                    let identity_matches = item.filename == artifact.filename
                        && (artifact.version.is_empty() || item.version == artifact.version);
                    digest_matches || identity_matches
                })
            }

            fn download<P: ArtifactProviderPort>(
                provider: P,
                artifact: &Artifact,
                transport: &ArtifactHttpTransport,
                cas: &CasStore,
            ) -> Result<Vec<u8>, ApplicationError> {
                let items = provider
                    .discover(transport)
                    .map_err(|_| ApplicationError::Port("artifact discovery failed".into()))?;
                let metadata = select(&items, artifact)
                    .ok_or(ApplicationError::NotFound("artifact candidate"))?;
                let stored = provider
                    .download(metadata, transport, cas)
                    .map_err(|_| ApplicationError::Port("artifact download failed".into()))?;
                cas.read(&stored.digest)
                    .map_err(|_| ApplicationError::Port("artifact read failed".into()))
            }

            match artifact.source.as_str() {
                "direct-url" => download(
                    DirectUrl {
                        url: artifact.source_id.clone(),
                        filename: artifact.filename.clone(),
                        digest: artifact.digest.clone(),
                        size: artifact_size(&artifact),
                    },
                    &artifact,
                    transport.as_ref(),
                    cas.as_ref(),
                ),
                "modrinth" => download(
                    Modrinth {
                        project_id: artifact.source_id.clone(),
                    },
                    &artifact,
                    transport.as_ref(),
                    cas.as_ref(),
                ),
                "github" => {
                    let (owner, repo) = artifact
                        .source_id
                        .split_once('/')
                        .ok_or(ApplicationError::NotFound("artifact provider"))?;
                    download(
                        GitHubRelease {
                            owner: owner.into(),
                            repo: repo.into(),
                        },
                        &artifact,
                        transport.as_ref(),
                        cas.as_ref(),
                    )
                }
                "papermc-fill-v3" => download(
                    PaperFill {
                        minecraft_version: artifact.source_id.clone(),
                    },
                    &artifact,
                    transport.as_ref(),
                    cas.as_ref(),
                ),
                "hangar" => download(
                    Hangar {
                        project: artifact.source_id.clone(),
                    },
                    &artifact,
                    transport.as_ref(),
                    cas.as_ref(),
                ),
                _ => Err(ApplicationError::NotFound("artifact provider")),
            }
        })
        .await
        .map_err(|_| ApplicationError::Port("artifact download task failed".into()))?
    }
}
#[async_trait]
impl AppArtifactProvider for ArtifactBridge {
    async fn discover(&self, query: &str) -> Result<Vec<ArtifactCandidate>, ApplicationError> {
        let query: ArtifactDiscoverPayload = serde_json::from_str(query)
            .map_err(|_| ApplicationError::Port("invalid typed artifact query".into()))?;
        query
            .validate()
            .map_err(|_| ApplicationError::Port("invalid typed artifact query".into()))?;
        let transport = self.transport.clone();
        tokio::task::spawn_blocking(move || {
            let items = match query.query {
                ArtifactProviderQuery::Manual(query) => {
                    let item = ArtifactMetadata {
                        kind: query.kind,
                        name: query.name,
                        version: query.version,
                        source: query.source,
                        source_id: query.source_id,
                        digest: query.digest,
                        filename: query.filename,
                        size: Some(query.size),
                        compatibility: query.compatibility,
                        metadata: serde_json::json!({
                            "size": query.size,
                            "metadata": query.metadata,
                        })
                        .to_string(),
                    };
                    item.validate()
                        .map(|()| vec![item])
                        .map_err(|_| ApplicationError::Port("invalid manual artifact".into()))
                }
                ArtifactProviderQuery::DirectUrl(query) => DirectUrl {
                    url: query.url,
                    filename: query.filename,
                    digest: query.digest,
                    size: query.size,
                }
                .discover(transport.as_ref())
                .map_err(|_| ApplicationError::Port("artifact discovery failed".into())),
                ArtifactProviderQuery::Modrinth(query) => Modrinth {
                    project_id: query.project,
                }
                .discover(transport.as_ref())
                .map_err(|_| ApplicationError::Port("artifact discovery failed".into())),
                ArtifactProviderQuery::GithubRelease(query) => {
                    let (owner, repo) = query.project.split_once('/').ok_or_else(|| {
                        ApplicationError::Port("GitHub project must be owner/repository".into())
                    })?;
                    GitHubRelease {
                        owner: owner.into(),
                        repo: repo.into(),
                    }
                    .discover(transport.as_ref())
                    .map_err(|_| ApplicationError::Port("artifact discovery failed".into()))
                }
                ArtifactProviderQuery::Paper(query) => PaperFill {
                    minecraft_version: query.version.unwrap_or(query.project),
                }
                .discover(transport.as_ref())
                .map_err(|_| ApplicationError::Port("artifact discovery failed".into())),
                ArtifactProviderQuery::Hangar(query) => Hangar {
                    project: query.project,
                }
                .discover(transport.as_ref())
                .map_err(|_| ApplicationError::Port("artifact discovery failed".into())),
            }?;
            items
                .into_iter()
                .map(|item| ArtifactCandidate {
                    artifact: Artifact {
                        id: kitsunebi_domain::ArtifactId::new(),
                        kind: item.kind,
                        name: item.name,
                        version: item.version,
                        source: item.source,
                        digest: item.digest,
                        filename: item.filename,
                        compatibility: item.compatibility,
                        metadata: item.metadata,
                        source_id: item.source_id,
                    },
                })
                .map(Ok)
                .collect()
        })
        .await
        .map_err(|_| ApplicationError::Port("artifact discovery task failed".into()))?
    }
    async fn download(&self, candidate: &ArtifactCandidate) -> Result<Vec<u8>, ApplicationError> {
        self.download_artifact(&candidate.artifact).await
    }
}

fn artifact_size(artifact: &Artifact) -> Option<u64> {
    serde_json::from_str::<Value>(&artifact.metadata)
        .ok()
        .and_then(|metadata| metadata.get("size").and_then(Value::as_u64))
}
#[async_trait]
impl AppArtifactStore for ArtifactBridge {
    async fn has(&self, digest: &str) -> Result<bool, ApplicationError> {
        self.has_digest(digest).await
    }
    async fn put(&self, digest: &str, bytes: &[u8]) -> Result<(), ApplicationError> {
        let cas = self.cas.clone();
        let digest = digest.to_owned();
        let bytes = bytes.to_owned();
        tokio::task::spawn_blocking(move || {
            cas.put(
                &digest,
                std::io::Cursor::new(bytes.as_slice()),
                Some(bytes.len() as u64),
            )
            .map(|_: StoredArtifact| ())
            .map_err(|_| ApplicationError::Port("artifact CAS write failed".into()))
        })
        .await
        .map_err(|_| ApplicationError::Port("artifact CAS write task failed".into()))?
    }
    async fn read(&self, digest: &str) -> Result<Vec<u8>, ApplicationError> {
        let cas = self.cas.clone();
        let digest = digest.to_owned();
        tokio::task::spawn_blocking(move || {
            cas.read(&digest)
                .map_err(|_| ApplicationError::NotFound("artifact"))
        })
        .await
        .map_err(|_| ApplicationError::Port("artifact CAS read task failed".into()))?
    }
}

/// API file bridge.  Every method repeats the object authorization check so a
/// caller holding the port cannot bypass the route-level check.
#[derive(Clone)]
struct ResolvedExecution {
    binding: GameAPBinding,
    service: ServiceId,
    cluster: ClusterId,
}

pub struct GameApFiles {
    pub change: Arc<ConcreteChangeCoordinator>,
    pub execution: Arc<GameApExecutionBackend>,
    pub execution_service: Arc<ConcreteExecutionService>,
    pub checker: Arc<AccessChecker>,
    pub storage: MySqlStorage,
    pub audit: MysqlAudit,
    pub upload_limit: usize,
}
impl GameApFiles {
    async fn authorize(
        &self,
        actor: &VerifiedActor,
        unit: &str,
        permission: ApiPermission,
    ) -> Result<(), ApiError> {
        self.checker
            .authorize(actor, "execution-units", Some(unit), permission)
            .await
            .map(|_| ())
    }
    fn path(path: &str) -> Result<String, ApiError> {
        kitsunebi_api::validate_file_path(path)
    }
    fn browse_path(path: &str) -> Result<String, ApiError> {
        if path == "." {
            Ok(String::from("."))
        } else {
            Self::path(path)
        }
    }
    async fn execution_binding_id(&self, unit: &str) -> Result<Option<Uuid>, ApiError> {
        let row = sqlx::query("SELECT id FROM gameap_bindings WHERE execution_unit_ref = ?")
            .bind(unit)
            .fetch_optional(self.storage.pool())
            .await
            .map_err(|_| ApiError::Backend)?;
        row.map(|row| {
            let value: String = sqlx::Row::try_get(&row, "id").map_err(|_| ApiError::Backend)?;
            Uuid::parse_str(&value).map_err(|_| ApiError::Backend)
        })
        .transpose()
    }

    async fn resolve_execution(
        &self,
        actor: &VerifiedActor,
        unit: &str,
        permission: ApiPermission,
    ) -> Result<ResolvedExecution, ApiError> {
        self.authorize(actor, unit, permission).await?;
        let binding_uuid = self
            .execution_binding_id(unit)
            .await?
            .ok_or(ApiError::NotFound)?;
        let cluster = self
            .storage
            .resolve_gameap_binding_cluster(binding_uuid)
            .await
            .map_err(|_| ApiError::NotFound)?
            .ok_or(ApiError::NotFound)?;
        let cluster_record = self
            .storage
            .get_cluster(cluster)
            .await
            .map_err(|_| ApiError::NotFound)?
            .ok_or(ApiError::NotFound)?;
        let service = cluster_record.service_id;
        let authorized = self
            .checker
            .authorized_service_ids(actor, "execution-units", Some(unit), permission)
            .await?;
        if !authorized.contains(&service) {
            return Err(ApiError::NotFound);
        }
        let binding = self
            .storage
            .get_gameap_binding_for_scope(binding_uuid, service, cluster)
            .await
            .map_err(|_| ApiError::NotFound)?
            .ok_or(ApiError::NotFound)?;
        if binding.execution_unit_id != unit || binding.fingerprint().is_empty() {
            return Err(ApiError::Conflict);
        }
        Ok(ResolvedExecution {
            binding,
            service,
            cluster,
        })
    }

    async fn current_baseline(
        &self,
        resolved: &ResolvedExecution,
    ) -> Result<Option<kitsunebi_domain::ConfigBaseline>, ApiError> {
        let cluster = self
            .storage
            .get_cluster(resolved.cluster)
            .await
            .map_err(|_| ApiError::Backend)?
            .ok_or(ApiError::NotFound)?;
        let Some(revision_id) = cluster.current_revision else {
            return Ok(None);
        };
        let revision = self
            .storage
            .get_revision(revision_id)
            .await
            .map_err(|_| ApiError::Backend)?
            .ok_or(ApiError::NotFound)?;
        let baseline = self
            .storage
            .get_config_baseline(revision.config_baseline)
            .await
            .map_err(|_| ApiError::Backend)?;
        if let Some(baseline) = &baseline {
            baseline.validate().map_err(|_| ApiError::Conflict)?;
        }
        Ok(baseline)
    }

    async fn classification(
        &self,
        resolved: &ResolvedExecution,
        path: &str,
    ) -> Result<FileClassification, ApiError> {
        Ok(self
            .current_baseline(resolved)
            .await?
            .and_then(|baseline| {
                baseline
                    .files
                    .into_iter()
                    .find(|entry| entry.path == path)
                    .map(|entry| entry.classification)
            })
            .unwrap_or(FileClassification::Unknown))
    }
}
#[async_trait]
impl FilePort for GameApFiles {
    async fn browse(
        &self,
        actor: &VerifiedActor,
        unit_id: &str,
        path: &str,
    ) -> Result<Vec<FileEntryDto>, ApiError> {
        let resolved = self
            .resolve_execution(actor, unit_id, ApiPermission::FilesRead)
            .await?;
        let path = Self::browse_path(path)?;
        let provider_path = if path == "." { "" } else { path.as_str() };
        let actor_id = actor_id(actor)?;
        let entries = self
            .execution_service
            .files(&resolved.binding, provider_path, actor_id, resolved.service)
            .await
            .map_err(application_error)?;
        let baseline = self.current_baseline(&resolved).await?;
        entries
            .into_iter()
            .map(|entry| {
                let classification = baseline
                    .as_ref()
                    .and_then(|baseline| {
                        baseline
                            .files
                            .iter()
                            .find(|candidate| candidate.path == entry.path)
                            .map(|candidate| candidate.classification.clone())
                    })
                    .unwrap_or(FileClassification::Unknown);
                Ok(FileEntryDto {
                    path: entry.path,
                    size: entry.size,
                    digest: entry.digest,
                    classification: classification.as_str().into(),
                })
            })
            .collect()
    }
    async fn read(
        &self,
        actor: &VerifiedActor,
        unit_id: &str,
        path: &str,
    ) -> Result<FileReadDto, ApiError> {
        let resolved = self
            .resolve_execution(actor, unit_id, ApiPermission::FilesRead)
            .await?;
        let path = Self::path(path)?;
        let actor_id = actor_id(actor)?;
        let classification = self.classification(&resolved, &path).await?;
        let content = self
            .execution_service
            .read_file(&resolved.binding, &path, actor_id, resolved.service)
            .await
            .map_err(application_error)?;
        let (content_type, content) =
            ControllerStepPort::file_read_payload(classification, content);
        Ok(FileReadDto {
            path,
            content_type,
            content,
        })
    }
    async fn download(
        &self,
        actor: &VerifiedActor,
        unit_id: &str,
        path: &str,
    ) -> Result<FileReadDto, ApiError> {
        let resolved = self
            .resolve_execution(actor, unit_id, ApiPermission::FilesRead)
            .await?;
        let path = Self::path(path)?;
        let actor_id = actor_id(actor)?;
        let content = self
            .execution_service
            .download(&resolved.binding, &path, actor_id, resolved.service)
            .await
            .map_err(application_error)?;
        if content.len() > self.upload_limit {
            return Err(ApiError::PayloadTooLarge);
        }
        let classification = self.classification(&resolved, &path).await?;
        let (content_type, content) =
            ControllerStepPort::file_read_payload(classification, content);
        Ok(FileReadDto {
            path,
            content_type,
            content,
        })
    }
    async fn diff(
        &self,
        actor: &VerifiedActor,
        unit_id: &str,
        path: &str,
    ) -> Result<FileDiffDto, ApiError> {
        let resolved = self
            .resolve_execution(actor, unit_id, ApiPermission::FilesRead)
            .await?;
        let path = Self::path(path)?;
        let actor_id = actor_id(actor)?;
        let before_digest = self
            .current_baseline(&resolved)
            .await?
            .and_then(|baseline| {
                baseline
                    .files
                    .into_iter()
                    .find(|entry| entry.path == path)
                    .map(|entry| entry.digest)
            });
        let after = self
            .execution_service
            .download(&resolved.binding, &path, actor_id, resolved.service)
            .await
            .map_err(application_error)?;
        let after_digest = kitsunebi_gameap::sha256_hex(&after);
        Ok(FileDiffDto {
            path,
            changed: before_digest.as_deref() != Some(after_digest.as_str()),
            before_digest,
            after_digest: Some(after_digest),
        })
    }
}

pub struct GameApConsoleSession {
    console: Box<dyn application::ExecutionConsole>,
    can_command: bool,
    execution_service: Arc<ConcreteExecutionService>,
    audit: MysqlAudit,
    binding: GameAPBinding,
    actor: ActorId,
    service: ServiceId,
}

fn console_audit_event(
    actor: ActorId,
    service: ServiceId,
    binding: &GameAPBinding,
    event: ConsoleAuditEvent,
) -> Result<kitsunebi_domain::AuditEvent, ApiError> {
    let action = match event.direction {
        ConsoleDirection::ClientToBackend => "console.send",
        ConsoleDirection::BackendToClient => "console.receive",
    };
    let scope = kitsunebi_domain::AuditScope::for_execution_unit(
        service,
        binding.execution_unit_id.clone(),
    )
    .map_err(|_| ApiError::Backend)?;
    Ok(kitsunebi_domain::AuditEvent {
        actor,
        action: action.into(),
        target: binding.execution_unit_id.clone(),
        classification: FileClassification::Secret,
        scope,
        source: kitsunebi_domain::AuditSource::Api,
        result: kitsunebi_domain::AuditResult::Success,
        before_revision: None,
        after_revision: None,
        plan_hash: None,
        request_id: None,
        evidence: vec![
            format!("digest={}", event.digest),
            format!("bytes={}", event.size),
        ],
    })
}

fn console_can_command(authorized_services: &[ServiceId], service: ServiceId) -> bool {
    authorized_services.contains(&service)
}

fn rollback_state_pair_is_valid(operation: OperationState, session: ChangeSessionState) -> bool {
    matches!(
        (operation, session),
        (OperationState::Applying, ChangeSessionState::Applying)
            | (OperationState::Verifying, ChangeSessionState::Verifying)
            | (OperationState::Verified, ChangeSessionState::Verifying)
            | (OperationState::Failed, ChangeSessionState::Aborted)
    )
}

async fn persist_console_audit<S: AuditSink + ?Sized>(
    audit: &S,
    event: kitsunebi_domain::AuditEvent,
) -> Result<(), ApiError> {
    audit.record(event).await.map_err(application_error)
}

#[async_trait]
impl ConsoleSession for GameApConsoleSession {
    async fn receive(&mut self) -> Result<Option<ConsoleFrame>, ApiError> {
        self.execution_service
            .console_receive(self.console.as_mut(), self.actor, self.service)
            .await
            .map_err(application_error)
            .map(|frame| frame.map(ConsoleFrame::Binary))
    }
    async fn send(&mut self, frame: ConsoleFrame) -> Result<(), ApiError> {
        if !self.can_command {
            return Err(ApiError::Forbidden);
        }
        match frame {
            ConsoleFrame::Text(text) => self
                .execution_service
                .console_send(self.console.as_mut(), &text, self.actor, self.service)
                .await
                .map_err(application_error),
            ConsoleFrame::Binary(_) => Err(ApiError::InvalidRequest(
                "GameAP console accepts text commands only",
            )),
        }
    }
    async fn record(&mut self, event: ConsoleAuditEvent) -> Result<(), ApiError> {
        persist_console_audit(
            &self.audit,
            console_audit_event(self.actor, self.service, &self.binding, event)?,
        )
        .await
    }
    async fn close(&mut self) {
        let _ = self
            .execution_service
            .close_console(
                self.console.as_mut(),
                &self.binding,
                self.actor,
                self.service,
            )
            .await;
    }
}
fn console_message(message: ConsoleMessage) -> ConsoleFrame {
    ConsoleFrame::Text(serde_json::to_string(&message.payload).unwrap_or_else(|_| "{}".into()))
}

pub struct MysqlOperationStream {
    storage: MySqlStorage,
    checker: AccessChecker,
    actor: VerifiedActor,
    operation: kitsunebi_domain::OperationId,
    emitted: bool,
    terminal: bool,
    next_sequence: u64,
}
#[async_trait]
impl OperationStreamPort for MysqlOperationStream {
    async fn next(&mut self) -> Result<Option<OperationEvent>, ApiError> {
        let operation_id = self.operation.as_uuid().to_string();
        self.checker
            .authorize(
                &self.actor,
                "operations",
                Some(&operation_id),
                ApiPermission::OperationRead,
            )
            .await?;
        if self.terminal {
            return Ok(None);
        }
        if self.emitted {
            sleep(Duration::from_millis(250)).await;
        }
        let operation = self
            .storage
            .get_operation(self.operation)
            .await
            .map_err(|_| ApiError::Backend)?
            .ok_or(ApiError::NotFound)?;
        let status = format!("{:?}", operation.state).to_lowercase();
        self.emitted = true;
        self.terminal = matches!(
            operation.state,
            OperationState::Accepted | OperationState::RolledBack | OperationState::Failed
        );
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        Ok(Some(OperationEvent {
            operation_id: operation.id.as_uuid().to_string(),
            sequence,
            status,
            message: None,
            progress: None,
        }))
    }
}

pub type ConcreteApplication =
    ApplicationService<MySqlStorage, MySqlStorage, ControllerStepPort, MysqlAuthorizer, MysqlAudit>;
pub type ConcreteChangeCoordinator =
    application::ChangeCoordinator<MySqlStorage, MysqlAuthorizer, MysqlAudit>;
pub type ConcreteExecutionService =
    application::ExecutionService<GameApExecutionBackend, MysqlAuthorizer, MysqlAudit>;
pub type ConcreteArtifactService =
    application::ArtifactService<ArtifactBridge, ArtifactBridge, MysqlAuthorizer, MysqlAudit>;
pub type ConcreteBackupService =
    application::BackupService<ConfiguredBackupProvider, MysqlAuthorizer>;

pub struct ManagementComponents {
    pub app: Arc<ConcreteApplication>,
    pub checker: Arc<AccessChecker>,
    pub execution: Arc<GameApExecutionBackend>,
    pub files: Arc<GameApFiles>,
    pub audit: MysqlAudit,
    pub execution_service: Arc<ConcreteExecutionService>,
    pub artifact_service: Arc<ConcreteArtifactService>,
    pub staging: Arc<ArtifactBridge>,
    pub backup_service: Arc<ConcreteBackupService>,
    pub tcp_shield: Option<Arc<TcpShieldComposition>>,
}

pub struct MysqlManagement {
    pub storage: MySqlStorage,
    pub app: Arc<ConcreteApplication>,
    pub checker: Arc<AccessChecker>,
    pub execution: Arc<GameApExecutionBackend>,
    pub files: Arc<GameApFiles>,
    pub audit: MysqlAudit,
    pub execution_service: Arc<ConcreteExecutionService>,
    pub artifact_service: Arc<ConcreteArtifactService>,
    pub staging: Arc<ArtifactBridge>,
    pub backup_service: Arc<ConcreteBackupService>,
    pub tcp_shield: Option<Arc<TcpShieldComposition>>,
}

#[derive(Default)]
struct GameApHealthObservation {
    binding_count: usize,
    bindings_query_failed: bool,
    panel_successes: usize,
    panel_failures: usize,
    daemon_successes: usize,
    daemon_failures: usize,
    runtime_running: usize,
    runtime_stopped: usize,
    runtime_unknown: usize,
}

fn gameap_component_status(
    observations: usize,
    failures: usize,
    bindings_query_failed: bool,
) -> &'static str {
    if bindings_query_failed || observations == 0 {
        "unknown"
    } else if failures == 0 {
        "ready"
    } else if failures == observations {
        "unavailable"
    } else {
        "degraded"
    }
}

fn gameap_runtime_status(observation: &GameApHealthObservation) -> &'static str {
    if observation.bindings_query_failed
        || observation.binding_count == 0
        || observation.runtime_unknown > 0
    {
        "unknown"
    } else if observation.runtime_running > 0 && observation.runtime_stopped > 0 {
        "mixed"
    } else if observation.runtime_running > 0 {
        "running"
    } else {
        "stopped"
    }
}

fn gameap_health_payload(observation: GameApHealthObservation) -> Value {
    let status = if observation.bindings_query_failed {
        "unavailable"
    } else if observation.binding_count == 0
        || observation.panel_failures > 0
        || observation.daemon_failures > 0
    {
        "degraded"
    } else {
        "healthy"
    };
    json!({
        "status": status,
        "bindings": {
            "status": if observation.bindings_query_failed { "unavailable" } else { "ready" },
            "observed": observation.binding_count,
        },
        "panel": {
            "status": gameap_component_status(
                observation.binding_count,
                observation.panel_failures,
                observation.bindings_query_failed,
            ),
            "observed": observation.panel_successes,
            "failures": observation.panel_failures,
        },
        "daemon": {
            "status": gameap_component_status(
                observation.binding_count,
                observation.daemon_failures,
                observation.bindings_query_failed,
            ),
            "observed": observation.daemon_successes,
            "failures": observation.daemon_failures,
        },
        "runtime": {
            "status": gameap_runtime_status(&observation),
            "running": observation.runtime_running,
            "stopped": observation.runtime_stopped,
            "unknown": observation.runtime_unknown,
        },
    })
}

impl MysqlManagement {
    pub fn new(storage: MySqlStorage, components: ManagementComponents) -> Self {
        Self {
            storage,
            app: components.app,
            checker: components.checker,
            execution: components.execution,
            files: components.files,
            audit: components.audit,
            execution_service: components.execution_service,
            artifact_service: components.artifact_service,
            staging: components.staging,
            backup_service: components.backup_service,
            tcp_shield: components.tcp_shield,
        }
    }
    fn read_permission(resource: &str) -> ApiPermission {
        match resource {
            "artifacts" => ApiPermission::ArtifactDiscover,
            "worlds" => ApiPermission::WorldRead,
            "endpoints" => ApiPermission::EndpointRead,
            "access-policies" => ApiPermission::AccessRead,
            "sftp-scans" => ApiPermission::FilesRead,
            "audit-events" => ApiPermission::AuditRead,
            "operations" => ApiPermission::OperationRead,
            _ => ApiPermission::ServiceRead,
        }
    }
    async fn scoped<T: Serialize + Clone>(
        &self,
        actor: &VerifiedActor,
        resource: &str,
        kind: ResourceKind,
        values: Vec<T>,
        id_of: impl Fn(&T) -> Uuid,
    ) -> Result<Vec<ResourceDto>, ApiError> {
        let mut result = Vec::new();
        let permission = Self::read_permission(resource);
        for value in values {
            let id = id_of(&value);
            if self
                .checker
                .authorize(actor, resource, Some(&id.to_string()), permission)
                .await
                .is_ok()
            {
                result.push(ResourceDto {
                    id: id.to_string(),
                    fields: serde_json::to_value(value).map_err(|_| ApiError::Backend)?,
                });
            }
        }
        let _ = kind;
        Ok(result)
    }
    fn uuid(value: &str, field: &'static str) -> Result<Uuid, ApiError> {
        Uuid::parse_str(value).map_err(|_| ApiError::InvalidRequest(field))
    }
    fn session_id(value: &str) -> Result<ChangeSessionId, ApiError> {
        Self::uuid(value, "session_id").map(ChangeSessionId::from_uuid)
    }
    fn plan_id(value: &str) -> Result<kitsunebi_domain::PlanId, ApiError> {
        Self::uuid(value, "plan_id").map(kitsunebi_domain::PlanId::from_uuid)
    }
    fn operation_id(value: &str) -> Result<kitsunebi_domain::OperationId, ApiError> {
        Self::uuid(value, "operation_id").map(kitsunebi_domain::OperationId::from_uuid)
    }
    fn service_id(value: &str) -> Result<ServiceId, ApiError> {
        Self::uuid(value, "service_id").map(ServiceId::from_uuid)
    }
    fn cluster_id(value: &str) -> Result<ClusterId, ApiError> {
        Self::uuid(value, "cluster_id").map(ClusterId::from_uuid)
    }
    fn plan_target(target: &ApiPlanTarget) -> Result<kitsunebi_domain::PlanTarget, ApiError> {
        let id =
            |value: &str| Uuid::parse_str(value).map_err(|_| ApiError::InvalidRequest("target"));
        Ok(match target {
            ApiPlanTarget::Service(value) => {
                kitsunebi_domain::PlanTarget::Service(ServiceId::from_uuid(id(value)?))
            }
            ApiPlanTarget::Cluster(value) => {
                kitsunebi_domain::PlanTarget::Cluster(ClusterId::from_uuid(id(value)?))
            }
            ApiPlanTarget::World(value) => kitsunebi_domain::PlanTarget::World(
                kitsunebi_domain::WorldId::from_uuid(id(value)?),
            ),
            ApiPlanTarget::ProxyPool(value) => kitsunebi_domain::PlanTarget::ProxyPool(
                kitsunebi_domain::ProxyPoolId::from_uuid(id(value)?),
            ),
            ApiPlanTarget::ProxyInstance(value) => kitsunebi_domain::PlanTarget::ProxyInstance(
                kitsunebi_domain::ProxyInstanceId::from_uuid(id(value)?),
            ),
            ApiPlanTarget::Artifact(value) => kitsunebi_domain::PlanTarget::Artifact(
                kitsunebi_domain::ArtifactId::from_uuid(id(value)?),
            ),
            ApiPlanTarget::ArtifactSet(value) => kitsunebi_domain::PlanTarget::ArtifactSet(
                kitsunebi_domain::ArtifactSetId::from_uuid(id(value)?),
            ),
            ApiPlanTarget::Endpoint(value) => kitsunebi_domain::PlanTarget::Endpoint(
                kitsunebi_domain::EndpointId::from_uuid(id(value)?),
            ),
            ApiPlanTarget::EndpointBinding(value) => {
                kitsunebi_domain::PlanTarget::EndpointBinding(BindingId::from_uuid(id(value)?))
            }
            ApiPlanTarget::AccessPolicy(value) => kitsunebi_domain::PlanTarget::AccessPolicy(
                kitsunebi_domain::PolicyId::from_uuid(id(value)?),
            ),
            ApiPlanTarget::Backup(value) => kitsunebi_domain::PlanTarget::Backup(
                kitsunebi_domain::BackupReferenceId::from_uuid(id(value)?),
            ),
            ApiPlanTarget::ExecutionUnit(value) => {
                kitsunebi_domain::PlanTarget::ExecutionUnit(BindingId::from_uuid(id(value)?))
            }
        })
    }
    fn request_hash(
        request: &MutationRequest,
        context: &MutationContext,
    ) -> Result<String, ApiError> {
        let identity = json!({
            "actor": context.actor.subject,
            "payload": request.payload,
            "request_hash": request.request_hash,
            "expires_at": request.expires_at,
            "if_match": context.if_match,
            "command": request.command.as_str(),
            "action": request.action.as_str(),
        });
        Ok(kitsunebi_api::plan_hash(
            &serde_json::to_vec(&identity)
                .map_err(|_| ApiError::InvalidRequest("invalid payload"))?,
        ))
    }
    fn if_match_matches(value: &str, expected: &str) -> bool {
        let value = value.trim();
        let value = value
            .strip_prefix('"')
            .and_then(|value| value.strip_suffix('"'))
            .unwrap_or(value);
        value == expected
    }
    fn coordinator(
        &self,
    ) -> application::ChangeCoordinator<MySqlStorage, MysqlAuthorizer, MysqlAudit> {
        application::ChangeCoordinator {
            repository: self.app.repository.clone(),
            authorizer: self.app.authorizer.clone(),
            audit: self.app.audit.clone(),
        }
    }
    fn execution_workflow(
        &self,
    ) -> application::ChangeExecutionWorkflow<
        MySqlStorage,
        MySqlStorage,
        ControllerStepPort,
        ControllerStepPort,
        MysqlAudit,
    > {
        application::ChangeExecutionWorkflow {
            repository: self.app.repository.clone(),
            operations: self.app.operations.clone(),
            verification: self.app.steps.clone(),
            rollback: self.app.steps.clone(),
            audit: self.app.audit.clone(),
        }
    }
    async fn session(
        &self,
        id: ChangeSessionId,
    ) -> Result<kitsunebi_domain::ChangeSession, ApiError> {
        self.app
            .repository
            .sessions()
            .await
            .map_err(application_error)?
            .into_iter()
            .find(|session| session.id == id)
            .ok_or(ApiError::NotFound)
    }
    async fn plan_for_session(
        &self,
        session_id: ChangeSessionId,
        plan_id: kitsunebi_domain::PlanId,
    ) -> Result<kitsunebi_domain::PlanDescriptor, ApiError> {
        self.storage
            .list_plans(session_id)
            .await
            .map_err(|_| ApiError::Backend)?
            .into_iter()
            .find(|plan| plan.id == plan_id)
            .ok_or(ApiError::NotFound)
    }
    async fn session_service(
        &self,
        session: &kitsunebi_domain::ChangeSession,
    ) -> Result<ServiceId, ApiError> {
        Ok(self
            .app
            .repository
            .cluster(session.target_cluster)
            .await
            .map_err(application_error)?
            .service_id)
    }
    async fn create_change_plan(
        &self,
        actor: &VerifiedActor,
        session_path_id: &str,
        request: MutationRequest,
        context: MutationContext,
    ) -> Result<ChangePlanResultDto, ApiError> {
        let MutationPayload::ChangePlan(payload) = request.payload.clone() else {
            return Err(ApiError::InvalidRequest("change plan payload is required"));
        };
        if context.actor.subject != actor.subject
            || context.request_hash != request.request_hash
            || context.expires_at != request.expires_at
            || payload.expires_at != request.expires_at
        {
            return Err(ApiError::Conflict);
        }
        let session_id = Self::session_id(session_path_id)?;
        if session_id != Self::session_id(&payload.session_id)? {
            return Err(ApiError::Conflict);
        }
        let service_id = Self::service_id(&payload.service_id)?;
        let target = Self::plan_target(&payload.target)?;
        let cluster_id = self
            .app
            .repository
            .cluster_for_plan_target(target, service_id)
            .await
            .map_err(application_error)?;
        let authorized = self
            .checker
            .authorized_service_ids(
                actor,
                "change-sessions",
                Some(session_path_id),
                ApiPermission::ChangePlan,
            )
            .await?;
        if !authorized.contains(&service_id) {
            return Err(ApiError::NotFound);
        }
        let cluster = self
            .app
            .repository
            .cluster(cluster_id)
            .await
            .map_err(application_error)?;
        if cluster.service_id != service_id {
            return Err(ApiError::Conflict);
        }
        let session = self.session(session_id).await?;
        if session.target_cluster != cluster_id
            || !matches!(session.state, ChangeSessionState::Editing)
        {
            return Err(ApiError::Conflict);
        }
        if context.session_version != Some(session.version) {
            return Err(ApiError::Conflict);
        }
        // The API and domain both expose the same closed, typed plan-step
        // algebra.  Decode it through serde only to translate the transport
        // enum; no free-form command or provider identifier can enter a plan.
        let steps = payload
            .steps
            .into_iter()
            .map(|step| {
                let encoded = serde_json::to_value(step.action)
                    .map_err(|_| ApiError::InvalidRequest("invalid plan step"))?;
                let kind = encoded
                    .get("kind")
                    .and_then(Value::as_str)
                    .ok_or(ApiError::InvalidRequest("invalid plan step"))?;
                let variant = kind
                    .split('_')
                    .map(|part| {
                        let mut chars = part.chars();
                        chars
                            .next()
                            .map(|first| first.to_uppercase().collect::<String>() + chars.as_str())
                            .unwrap_or_default()
                    })
                    .collect::<String>();
                let action = serde_json::from_value::<kitsunebi_domain::PlanStepAction>(
                    json!({ variant: encoded.get("value") }),
                )
                .map_err(|_| ApiError::InvalidRequest("invalid plan step"))?;
                PlanStep::new(action).map_err(|_| ApiError::InvalidRequest("invalid plan step"))
            })
            .collect::<Result<Vec<_>, ApiError>>()?;
        let change = ChangeRequest {
            actor: actor_id(actor)?,
            service: service_id,
            cluster: cluster_id,
            domain_revision: payload.domain_revision,
            idempotency_key: context.idempotency_key.clone(),
            steps,
            observed_state_hashes: payload.observed_state_hashes.clone(),
            expiry: context.expires_at,
        };
        let mut plan = self
            .coordinator()
            .plan(&change)
            .await
            .map_err(application_error)?;
        plan.target = target;
        plan.observed_state_hashes = payload.observed_state_hashes;
        plan.expected_file_hashes = payload.expected_file_hashes;
        plan.expected_artifact_hashes = payload.expected_artifact_hashes;
        plan.backup_requirements.required = payload.backup_required;
        plan.backup_requirements.references = payload
            .backup_references
            .into_iter()
            .map(|value| {
                Uuid::parse_str(&value)
                    .map(kitsunebi_domain::BackupReferenceId::from_uuid)
                    .map_err(|_| ApiError::InvalidRequest("backup_references"))
            })
            .collect::<Result<_, _>>()?;
        plan.rollback_instructions = payload.rollback_instructions;
        plan.expiry = payload.expires_at;
        plan.plan_hash = plan.compute_hash();
        // Persist the complete typed descriptor in one transaction; planning
        // never allocates an execution operation.
        let audit = kitsunebi_domain::AuditEvent {
            actor: change.actor,
            action: "change.plan".into(),
            target: plan.target.stable_string(),
            classification: FileClassification::Managed,
            scope: kitsunebi_domain::AuditScope::for_cluster(service_id, cluster_id),
            source: kitsunebi_domain::AuditSource::Api,
            result: kitsunebi_domain::AuditResult::Accepted,
            before_revision: None,
            after_revision: Some(payload.domain_revision),
            plan_hash: Some(plan.plan_hash.clone()),
            request_id: Some(context.request_id.clone()),
            evidence: vec![plan.plan_hash.clone()],
        };
        let mut tx = self
            .storage
            .transaction()
            .await
            .map_err(|_| ApiError::Backend)?;
        let existing = tx
            .save_plan_idempotent(
                plan.clone(),
                session_id,
                &context.idempotency_key,
                &context.request_hash,
                audit,
            )
            .await
            .map_err(application_error)?;
        tx.commit().await.map_err(application_error)?;
        let plan = existing.unwrap_or(plan);
        Ok(ChangePlanResultDto {
            plan_id: plan.id.as_uuid().to_string(),
            plan_hash: plan.plan_hash,
            session_id: session_id.as_uuid().to_string(),
            state: "planned".into(),
        })
    }
    async fn operation_dto(
        &self,
        operation: Operation,
        request_id: &str,
    ) -> Result<OperationDto, ApiError> {
        let plan = self
            .plan_for_session(operation.session_id, operation.plan_id)
            .await?;
        Ok(OperationDto {
            id: operation.id.as_uuid().to_string(),
            status: format!("{:?}", operation.state).to_lowercase(),
            plan_hash: plan.plan_hash,
            request_id: request_id.into(),
        })
    }

    fn sftp_scan_dto(scan: kitsunebi_domain::SftpScan) -> SftpScanDto {
        SftpScanDto {
            id: scan.id.as_uuid().to_string(),
            endpoint_id: scan.endpoint_id.as_uuid().to_string(),
            service_id: scan.service_id.as_uuid().to_string(),
            execution_binding_id: scan.execution_binding_id.as_uuid().to_string(),
            session_id: scan.session_id.as_uuid().to_string(),
            before_manifest_hash: scan.before_manifest_hash,
            after_manifest_hash: scan.after_manifest_hash,
            changed_paths: scan
                .changed_paths
                .into_iter()
                .map(|path| SftpChangedPathDto {
                    path: path.path,
                    kind: match path.kind {
                        DomainSftpChangeKind::Added => kitsunebi_api::dto::SftpChangeKind::Added,
                        DomainSftpChangeKind::Modified => {
                            kitsunebi_api::dto::SftpChangeKind::Modified
                        }
                        DomainSftpChangeKind::Removed => {
                            kitsunebi_api::dto::SftpChangeKind::Removed
                        }
                    },
                    before_digest: path.before_digest,
                    after_digest: path.after_digest,
                    classification: match path.classification {
                        FileClassification::Managed => {
                            kitsunebi_api::dto::FileClassification::Managed
                        }
                        FileClassification::MutableConfig => {
                            kitsunebi_api::dto::FileClassification::MutableConfig
                        }
                        FileClassification::Artifact => {
                            kitsunebi_api::dto::FileClassification::Artifact
                        }
                        FileClassification::Generated => {
                            kitsunebi_api::dto::FileClassification::Generated
                        }
                        FileClassification::State => kitsunebi_api::dto::FileClassification::State,
                        FileClassification::Secret => {
                            kitsunebi_api::dto::FileClassification::Secret
                        }
                        FileClassification::Unknown => {
                            kitsunebi_api::dto::FileClassification::Unknown
                        }
                    },
                })
                .collect(),
            observed_at: scan.observed_at,
            source: match scan.source {
                DomainSftpScanSource::OutOfBand => kitsunebi_api::dto::SftpScanSource::OutOfBand,
                DomainSftpScanSource::Provisioning => {
                    kitsunebi_api::dto::SftpScanSource::Provisioning
                }
                DomainSftpScanSource::Operator => kitsunebi_api::dto::SftpScanSource::Operator,
            },
            request_hash: scan.request_hash,
        }
    }
}

#[async_trait]
impl ManagementApi for MysqlManagement {
    async fn list(
        &self,
        resource: &str,
        actor: &VerifiedActor,
    ) -> Result<Vec<ResourceDto>, ApiError> {
        self.checker
            .authorize(actor, resource, None, Self::read_permission(resource))
            .await?;
        match resource {
            "networks" => {
                self.scoped(
                    actor,
                    resource,
                    ResourceKind::Network,
                    self.storage
                        .list_networks()
                        .await
                        .map_err(|_| ApiError::Backend)?,
                    |v| v.id.as_uuid(),
                )
                .await
            }
            "services" => {
                self.scoped(
                    actor,
                    resource,
                    ResourceKind::Service,
                    self.app
                        .repository
                        .services()
                        .await
                        .map_err(application_error)?,
                    |v| v.id.as_uuid(),
                )
                .await
            }
            "clusters" => {
                self.scoped(
                    actor,
                    resource,
                    ResourceKind::Cluster,
                    self.app
                        .repository
                        .clusters()
                        .await
                        .map_err(application_error)?,
                    |v| v.id.as_uuid(),
                )
                .await
            }
            "cluster-revisions" => {
                self.scoped(
                    actor,
                    resource,
                    ResourceKind::Revision,
                    self.app
                        .repository
                        .revisions()
                        .await
                        .map_err(application_error)?,
                    |v| v.id.as_uuid(),
                )
                .await
            }
            "worlds" => {
                self.scoped(
                    actor,
                    resource,
                    ResourceKind::World,
                    self.app
                        .repository
                        .worlds()
                        .await
                        .map_err(application_error)?,
                    |v| v.id.as_uuid(),
                )
                .await
            }
            "proxy-pools" => {
                self.scoped(
                    actor,
                    resource,
                    ResourceKind::ProxyPool,
                    self.storage
                        .list_proxy_pools()
                        .await
                        .map_err(|_| ApiError::Backend)?,
                    |v| v.id.as_uuid(),
                )
                .await
            }
            "proxy-instances" => {
                self.scoped(
                    actor,
                    resource,
                    ResourceKind::ProxyInstance,
                    self.app
                        .repository
                        .proxies()
                        .await
                        .map_err(application_error)?,
                    |v| v.id.as_uuid(),
                )
                .await
            }
            "execution-units" => {
                let mut result = Vec::new();
                for binding in self
                    .storage
                    .list_gameap_bindings()
                    .await
                    .map_err(|_| ApiError::Backend)?
                {
                    if self
                        .checker
                        .authorize(
                            actor,
                            resource,
                            Some(&binding.execution_unit_id),
                            ApiPermission::ServiceRead,
                        )
                        .await
                        .is_ok()
                    {
                        let binding_id = sqlx::query(
                            "SELECT id FROM gameap_bindings WHERE execution_unit_ref = ?",
                        )
                        .bind(&binding.execution_unit_id)
                        .fetch_optional(self.storage.pool())
                        .await
                        .map_err(|_| ApiError::Backend)?
                        .and_then(|row| sqlx::Row::try_get::<String, _>(&row, "id").ok());
                        let mut fields =
                            serde_json::to_value(&binding).map_err(|_| ApiError::Backend)?;
                        if let Some(object) = fields.as_object_mut()
                            && let Some(binding_id) = binding_id
                        {
                            object.insert("binding_id".into(), Value::String(binding_id));
                        }
                        result.push(ResourceDto {
                            id: binding.execution_unit_id.clone(),
                            fields,
                        });
                    }
                }
                Ok(result)
            }
            "runtime-profiles" => {
                self.scoped(
                    actor,
                    resource,
                    ResourceKind::RuntimeProfile,
                    self.storage
                        .list_runtime_profiles()
                        .await
                        .map_err(|_| ApiError::Backend)?,
                    |v| v.id.as_uuid(),
                )
                .await
            }
            "artifacts" => {
                self.scoped(
                    actor,
                    resource,
                    ResourceKind::Artifact,
                    self.app
                        .repository
                        .artifacts()
                        .await
                        .map_err(application_error)?,
                    |v| v.id.as_uuid(),
                )
                .await
            }
            "config" => {
                self.scoped(
                    actor,
                    resource,
                    ResourceKind::ConfigBaseline,
                    self.storage
                        .list_config_baselines()
                        .await
                        .map_err(|_| ApiError::Backend)?,
                    |v| v.id.as_uuid(),
                )
                .await
            }
            "endpoints" => {
                self.scoped(
                    actor,
                    resource,
                    ResourceKind::Endpoint,
                    self.app
                        .repository
                        .endpoints()
                        .await
                        .map_err(application_error)?,
                    |v| v.id.as_uuid(),
                )
                .await
            }
            "access-policies" => {
                self.scoped(
                    actor,
                    resource,
                    ResourceKind::AccessPolicy,
                    self.storage
                        .list_access_policies()
                        .await
                        .map_err(|_| ApiError::Backend)?,
                    |v| v.id.as_uuid(),
                )
                .await
            }
            "change-sessions" => {
                self.scoped(
                    actor,
                    resource,
                    ResourceKind::ChangeSession,
                    self.app
                        .repository
                        .sessions()
                        .await
                        .map_err(application_error)?,
                    |v| v.id.as_uuid(),
                )
                .await
            }
            "operations" => {
                self.scoped(
                    actor,
                    resource,
                    ResourceKind::Operation,
                    self.app
                        .repository
                        .operations()
                        .await
                        .map_err(application_error)?,
                    |v| v.id.as_uuid(),
                )
                .await
            }
            "backups" => {
                self.scoped(
                    actor,
                    resource,
                    ResourceKind::BackupReference,
                    self.app
                        .repository
                        .backups()
                        .await
                        .map_err(application_error)?,
                    |v| v.id.as_uuid(),
                )
                .await
            }
            "sftp-scans" => {
                let authorized_services = self
                    .checker
                    .authorized_service_ids(actor, resource, None, ApiPermission::FilesRead)
                    .await?;
                let sessions = self
                    .app
                    .repository
                    .sessions()
                    .await
                    .map_err(application_error)?;
                let mut result = Vec::new();
                for session in sessions {
                    if !authorized_services.contains(&self.session_service(&session).await?) {
                        continue;
                    }
                    for scan in self
                        .storage
                        .list_sftp_scans(session.id)
                        .await
                        .map_err(|_| ApiError::Backend)?
                    {
                        result.push(ResourceDto {
                            id: scan.id.as_uuid().to_string(),
                            fields: serde_json::to_value(Self::sftp_scan_dto(scan))
                                .map_err(|_| ApiError::Backend)?,
                        });
                    }
                }
                Ok(result)
            }
            "audit-events" => {
                let records = self
                    .storage
                    .read_audit_events(100)
                    .await
                    .map_err(|_| ApiError::Backend)?;
                let mut result = Vec::new();
                for record in records {
                    if self
                        .checker
                        .authorize(
                            actor,
                            resource,
                            Some(&record.event_id.to_string()),
                            ApiPermission::AuditRead,
                        )
                        .await
                        .is_ok()
                    {
                        result.push(ResourceDto {
                            id: record.event_id.to_string(),
                            fields: json!({
                                "occurred_at": record.occurred_at,
                                "actor": record.event.actor.as_uuid().to_string(),
                                "action": record.event.action,
                                "target": record.event.target,
                                "classification": format!("{:?}", record.event.classification).to_lowercase(),
                                "source": record.event.source.as_str(),
                                "result": record.event.result.as_str(),
                                "service_id": record.event.scope.service_id.as_uuid().to_string(),
                                "cluster_id": record.event.scope.cluster_id.map(|id| id.as_uuid().to_string()),
                                "world_id": record.event.scope.world_id.map(|id| id.as_uuid().to_string()),
                                "execution_unit_ref": record.event.scope.execution_unit_ref,
                                "operation_id": record.event.scope.operation_id.map(|id| id.as_uuid().to_string()),
                                "before_revision": record.event.before_revision,
                                "after_revision": record.event.after_revision,
                                "plan_hash": record.event.plan_hash,
                                "request_id": record.event.request_id,
                                "evidence": record.event.evidence,
                            }),
                        });
                    }
                }
                Ok(result)
            }
            _ => Err(ApiError::NotFound),
        }
    }
    async fn get(
        &self,
        resource: &str,
        id: &str,
        actor: &VerifiedActor,
    ) -> Result<ResourceDto, ApiError> {
        self.checker
            .authorize(actor, resource, Some(id), Self::read_permission(resource))
            .await?;
        if resource == "execution-units" {
            let binding_id = self
                .checker
                .execution_binding_id(id)
                .await?
                .ok_or(ApiError::NotFound)?;
            let binding = self
                .storage
                .get_gameap_binding(binding_id)
                .await
                .map_err(|_| ApiError::Backend)?
                .ok_or(ApiError::NotFound)?;
            let mut fields = serde_json::to_value(&binding).map_err(|_| ApiError::Backend)?;
            if let Some(object) = fields.as_object_mut() {
                object.insert("binding_id".into(), Value::String(binding_id.to_string()));
            }
            return Ok(ResourceDto {
                id: binding.execution_unit_id.clone(),
                fields,
            });
        }
        if resource == "audit-events" {
            let event_id = Uuid::parse_str(id).map_err(|_| ApiError::NotFound)?;
            let record = self
                .storage
                .read_audit_events(1000)
                .await
                .map_err(|_| ApiError::Backend)?
                .into_iter()
                .find(|record| record.event_id == event_id)
                .ok_or(ApiError::NotFound)?;
            return Ok(ResourceDto {
                id: record.event_id.to_string(),
                fields: json!({
                    "occurred_at": record.occurred_at,
                    "actor": record.event.actor.as_uuid().to_string(),
                    "action": record.event.action,
                    "target": record.event.target,
                    "classification": format!("{:?}", record.event.classification).to_lowercase(),
                    "source": record.event.source.as_str(),
                    "result": record.event.result.as_str(),
                    "service_id": record.event.scope.service_id.as_uuid().to_string(),
                    "cluster_id": record.event.scope.cluster_id.map(|id| id.as_uuid().to_string()),
                    "world_id": record.event.scope.world_id.map(|id| id.as_uuid().to_string()),
                    "execution_unit_ref": record.event.scope.execution_unit_ref,
                    "operation_id": record.event.scope.operation_id.map(|id| id.as_uuid().to_string()),
                    "before_revision": record.event.before_revision,
                    "after_revision": record.event.after_revision,
                    "plan_hash": record.event.plan_hash,
                    "request_id": record.event.request_id,
                    "evidence": record.event.evidence,
                }),
            });
        }
        let id_uuid = Uuid::parse_str(id).map_err(|_| ApiError::NotFound)?;
        macro_rules! get {
            ($call:ident, $ty:path) => {
                self.storage
                    .$call(<$ty>::from_uuid(id_uuid))
                    .await
                    .map_err(|_| ApiError::NotFound)?
                    .map(|value| ResourceDto {
                        id: id.into(),
                        fields: serde_json::to_value(value).unwrap_or_else(|_| json!({})),
                    })
                    .ok_or(ApiError::NotFound)
            };
        }
        match resource {
            "networks" => get!(get_network, kitsunebi_domain::NetworkId),
            "services" => get!(get_service, kitsunebi_domain::ServiceId),
            "clusters" => get!(get_cluster, kitsunebi_domain::ClusterId),
            "cluster-revisions" => get!(get_revision, kitsunebi_domain::RevisionId),
            "worlds" => get!(get_world, kitsunebi_domain::WorldId),
            "proxy-pools" => get!(get_proxy_pool, kitsunebi_domain::ProxyPoolId),
            "proxy-instances" => get!(get_proxy_instance, kitsunebi_domain::ProxyInstanceId),
            "runtime-profiles" => get!(get_runtime_profile, kitsunebi_domain::RuntimeProfileId),
            "artifacts" => get!(get_artifact, kitsunebi_domain::ArtifactId),
            "config" => get!(get_config_baseline, kitsunebi_domain::ConfigBaselineId),
            "endpoints" => get!(get_endpoint, kitsunebi_domain::EndpointId),
            "access-policies" => get!(get_access_policy, kitsunebi_domain::PolicyId),
            "change-sessions" => get!(get_change_session, kitsunebi_domain::ChangeSessionId),
            "operations" => get!(get_operation, kitsunebi_domain::OperationId),
            "backups" => get!(get_backup_reference, kitsunebi_domain::BackupReferenceId),
            "sftp-scans" => {
                let scan_id = kitsunebi_domain::SftpScanId::from_uuid(id_uuid);
                let scan = self
                    .storage
                    .get_sftp_scan(scan_id)
                    .await
                    .map_err(|_| ApiError::NotFound)?
                    .ok_or(ApiError::NotFound)?;
                self.checker
                    .authorize(actor, resource, Some(id), ApiPermission::FilesRead)
                    .await?;
                Ok(ResourceDto {
                    id: id.into(),
                    fields: serde_json::to_value(Self::sftp_scan_dto(scan))
                        .map_err(|_| ApiError::Backend)?,
                })
            }
            _ => Err(ApiError::NotFound),
        }
    }
    async fn authorize(
        &self,
        actor: &VerifiedActor,
        resource: &str,
        id: Option<&str>,
        permission: ApiPermission,
    ) -> Result<AccessDecision, ApiError> {
        self.checker
            .authorize(actor, resource, id, permission)
            .await
    }
    async fn plan_change(
        &self,
        actor: &VerifiedActor,
        resource: &str,
        id: &str,
        request: MutationRequest,
        context: MutationContext,
    ) -> Result<ChangePlanResultDto, ApiError> {
        if resource != "change-sessions" {
            return Err(ApiError::NotFound);
        }
        self.create_change_plan(actor, id, request, context).await
    }
    async fn approve_change(
        &self,
        actor: &VerifiedActor,
        resource: &str,
        id: &str,
        request: MutationRequest,
        context: MutationContext,
    ) -> Result<ChangeApprovalDto, ApiError> {
        if resource != "change-sessions" {
            return Err(ApiError::NotFound);
        }
        request.validate_for(resource, MutationCommand::Approve, MutationAction::Change)?;
        let MutationPayload::ChangeApprove(payload) = request.payload.clone() else {
            return Err(ApiError::InvalidRequest(
                "change approval payload is required",
            ));
        };
        if context.actor.subject != actor.subject
            || context.request_hash != request.request_hash
            || context.idempotency_key.trim().is_empty()
            || context.request_id.trim().is_empty()
            || context.if_match.trim().is_empty()
            || context.expires_at != request.expires_at
        {
            return Err(ApiError::Conflict);
        }
        let session_id = Self::session_id(id)?;
        if session_id != Self::session_id(&payload.session_id)? {
            return Err(ApiError::Conflict);
        }
        let actor_id = actor_id(actor)?;
        let session = self.session(session_id).await?;
        let service_id = self.session_service(&session).await?;
        let authorized = self
            .checker
            .authorized_service_ids(actor, resource, Some(id), ApiPermission::ChangeApprove)
            .await?;
        if !authorized.contains(&service_id) {
            return Err(ApiError::NotFound);
        }
        if self
            .storage
            .get_change_session_for_actor(session_id, actor_id)
            .await
            .map_err(|_| ApiError::Backend)?
            .is_none()
        {
            return Err(ApiError::NotFound);
        }
        let plan = self
            .plan_for_session(session_id, Self::plan_id(&payload.plan_id)?)
            .await?;
        if plan.actor != actor_id {
            return Err(ApiError::Forbidden);
        }
        if plan.is_expired(now())
            || plan.plan_hash != payload.plan_hash
            || !Self::if_match_matches(&context.if_match, &plan.plan_hash)
        {
            return Err(ApiError::Conflict);
        }
        if session.state == ChangeSessionState::Editing {
            self.coordinator()
                .ready(session_id, actor_id, service_id)
                .await
                .map_err(application_error)?;
        } else if session.state != ChangeSessionState::Ready {
            return Err(ApiError::Conflict);
        }
        Ok(ChangeApprovalDto {
            plan_id: plan.id.as_uuid().to_string(),
            plan_hash: plan.plan_hash,
            session_id: session_id.as_uuid().to_string(),
            state: "ready".into(),
        })
    }
    async fn stage_content(
        &self,
        actor: &VerifiedActor,
        request: StageContentRequest,
    ) -> Result<kitsunebi_api::dto::StagedContentDto, ApiError> {
        request.validate()?;
        let StageContentRequest {
            session_id: session_id_value,
            bytes,
            classification,
            session_version,
            idempotency_key,
            request_hash,
        } = request;
        let session_id = Self::session_id(&session_id_value)?;
        let actor_id = actor_id(actor)?;
        let session = self
            .storage
            .get_change_session_for_actor(session_id, actor_id)
            .await
            .map_err(|_| ApiError::Backend)?
            .ok_or(ApiError::NotFound)?;
        if !session.is_active() {
            return Err(ApiError::Conflict);
        }
        if session.version != session_version {
            return Err(ApiError::Conflict);
        }
        let classification = match classification {
            kitsunebi_api::dto::FileClassification::Managed => FileClassification::Managed,
            kitsunebi_api::dto::FileClassification::MutableConfig => {
                FileClassification::MutableConfig
            }
            kitsunebi_api::dto::FileClassification::Artifact => FileClassification::Artifact,
            kitsunebi_api::dto::FileClassification::Generated => FileClassification::Generated,
            kitsunebi_api::dto::FileClassification::State
            | kitsunebi_api::dto::FileClassification::Secret
            | kitsunebi_api::dto::FileClassification::Unknown => {
                return Err(ApiError::InvalidRequest("staged content classification"));
            }
        };
        let digest = kitsunebi_gameap::sha256_hex(&bytes);
        if let Some(existing) = self
            .storage
            .get_staged_content_by_idempotency(session_id, actor_id, &idempotency_key)
            .await
            .map_err(|_| ApiError::Backend)?
        {
            if existing.content.digest != digest
                || existing.content.size != bytes.len() as u64
                || existing.classification != classification
                || existing.request_hash != request_hash
            {
                return Err(ApiError::Conflict);
            }
            return Ok(kitsunebi_api::dto::StagedContentDto {
                digest: existing.content.digest,
                size: existing.content.size,
            });
        }
        self.staging
            .put(&digest, &bytes)
            .await
            .map_err(application_error)?;
        let ownership = StagedContentOwnership {
            id: kitsunebi_domain::StagedContentId::new(),
            session_id,
            actor: actor_id,
            content: StagedContentRef::new(&digest, bytes.len() as u64)
                .map_err(|_| ApiError::InvalidRequest("staged content"))?,
            classification,
            idempotency_key,
            request_hash,
            expires_at: now().saturating_add(24 * 60 * 60),
        };
        let ownership = self
            .storage
            .create_staged_content_ownership(&ownership, session_version)
            .await
            .map_err(|error| match error {
                kitsunebi_storage::StorageError::Conflict { .. }
                | kitsunebi_storage::StorageError::StagedContentConflict => ApiError::Conflict,
                _ => ApiError::Backend,
            })?;
        Ok(kitsunebi_api::dto::StagedContentDto {
            digest: ownership.content.digest,
            size: ownership.content.size,
        })
    }
    async fn discover_artifacts(
        &self,
        actor: &VerifiedActor,
        payload: ArtifactDiscoverPayload,
    ) -> Result<Vec<ArtifactCandidateDto>, ApiError> {
        payload.validate()?;
        let service_id = *self
            .checker
            .authorized_service_ids(actor, "artifacts", None, ApiPermission::ArtifactDiscover)
            .await?
            .first()
            .ok_or(ApiError::NotFound)?;
        let query = serde_json::to_string(&payload).map_err(|_| ApiError::Backend)?;
        let candidates = self
            .artifact_service
            .discover(&query, actor_id(actor)?, service_id)
            .await
            .map_err(application_error)?;
        Ok(candidates
            .into_iter()
            .map(|candidate| {
                let artifact = candidate.artifact;
                let size = artifact_size(&artifact).unwrap_or_default();
                ArtifactCandidateDto {
                    id: artifact.id.as_uuid().to_string(),
                    provider: payload.provider,
                    kind: artifact.kind,
                    name: artifact.name,
                    version: artifact.version,
                    source: artifact.source,
                    source_id: artifact.source_id,
                    digest: artifact.digest,
                    filename: artifact.filename,
                    compatibility: artifact.compatibility,
                    metadata: artifact.metadata,
                    size,
                }
            })
            .collect())
    }

    async fn list_sftp_endpoints(
        &self,
        actor: &VerifiedActor,
    ) -> Result<Vec<SftpEndpointDto>, ApiError> {
        let services = self
            .checker
            .authorized_service_ids(actor, "sftp-endpoints", None, ApiPermission::FilesRead)
            .await?;
        let mut endpoints = Vec::new();
        for service in services {
            for endpoint in self
                .storage
                .list_sftp_endpoints(service)
                .await
                .map_err(|_| ApiError::Backend)?
            {
                endpoints.push(SftpEndpointDto {
                    id: endpoint.id.as_uuid().to_string(),
                    service_id: endpoint.service_id.as_uuid().to_string(),
                    execution_binding_id: endpoint.execution_binding_id.as_uuid().to_string(),
                    host: endpoint.host,
                    port: endpoint.port,
                    root: endpoint.root,
                    provisioning_owned: endpoint.provisioning_owned,
                });
            }
        }
        Ok(endpoints)
    }

    async fn get_sftp_endpoint(
        &self,
        actor: &VerifiedActor,
        id: &str,
    ) -> Result<SftpEndpointDto, ApiError> {
        let endpoint_id = Uuid::parse_str(id)
            .map(kitsunebi_domain::SftpEndpointId::from_uuid)
            .map_err(|_| ApiError::NotFound)?;
        let endpoint = self
            .storage
            .get_sftp_endpoint(endpoint_id)
            .await
            .map_err(|_| ApiError::Backend)?
            .ok_or(ApiError::NotFound)?;
        self.checker
            .authorize(actor, "sftp-endpoints", Some(id), ApiPermission::FilesRead)
            .await?;
        Ok(SftpEndpointDto {
            id: endpoint.id.as_uuid().to_string(),
            service_id: endpoint.service_id.as_uuid().to_string(),
            execution_binding_id: endpoint.execution_binding_id.as_uuid().to_string(),
            host: endpoint.host,
            port: endpoint.port,
            root: endpoint.root,
            provisioning_owned: endpoint.provisioning_owned,
        })
    }

    async fn scan_sftp(
        &self,
        actor: &VerifiedActor,
        endpoint_id: &str,
        payload: SftpScanPayload,
        context: MutationContext,
    ) -> Result<SftpScanDto, ApiError> {
        let endpoint = Uuid::parse_str(endpoint_id)
            .map(kitsunebi_domain::SftpEndpointId::from_uuid)
            .map_err(|_| ApiError::NotFound)?;
        let service = Self::service_id(&payload.service_id)?;
        let binding = Uuid::parse_str(&payload.execution_binding_id)
            .map(BindingId::from_uuid)
            .map_err(|_| ApiError::InvalidRequest("execution_binding_id"))?;
        let session = Self::session_id(&payload.change_session_id)?;
        let session_record = self
            .storage
            .get_change_session_for_actor(session, actor_id(actor)?)
            .await
            .map_err(|_| ApiError::Backend)?
            .ok_or(ApiError::NotFound)?;
        let cluster = session_record.target_cluster;
        let binding_record = self
            .app
            .repository
            .gameap_binding(binding, service, cluster)
            .await
            .map_err(application_error)?;
        // SFTP is an out-of-band observation path.  For paths that still
        // exist, capture the provider hash through GameAP before persisting
        // the metadata scan; the API never claims realtime SFTP auditing.
        for changed in &payload.changed_paths {
            if !matches!(changed.kind, kitsunebi_api::dto::SftpChangeKind::Removed) {
                let observed = self
                    .execution
                    .download(&binding_record, &changed.path)
                    .await
                    .map_err(application_error)?;
                if changed.after_digest.as_deref()
                    != Some(kitsunebi_gameap::sha256_hex(&observed).as_str())
                {
                    return Err(ApiError::Conflict);
                }
            }
        }
        let changed_paths = payload
            .changed_paths
            .into_iter()
            .map(|path| {
                let kind = match path.kind {
                    kitsunebi_api::dto::SftpChangeKind::Added => DomainSftpChangeKind::Added,
                    kitsunebi_api::dto::SftpChangeKind::Modified => DomainSftpChangeKind::Modified,
                    kitsunebi_api::dto::SftpChangeKind::Removed => DomainSftpChangeKind::Removed,
                };
                DomainSftpChangedPath::new(
                    &path.path,
                    kind,
                    path.before_digest.as_deref(),
                    path.after_digest.as_deref(),
                    match path.classification {
                        kitsunebi_api::dto::FileClassification::Managed => {
                            FileClassification::Managed
                        }
                        kitsunebi_api::dto::FileClassification::MutableConfig => {
                            FileClassification::MutableConfig
                        }
                        kitsunebi_api::dto::FileClassification::Artifact => {
                            FileClassification::Artifact
                        }
                        kitsunebi_api::dto::FileClassification::Generated => {
                            FileClassification::Generated
                        }
                        kitsunebi_api::dto::FileClassification::State => FileClassification::State,
                        kitsunebi_api::dto::FileClassification::Secret => {
                            FileClassification::Secret
                        }
                        kitsunebi_api::dto::FileClassification::Unknown => {
                            FileClassification::Unknown
                        }
                    },
                )
                .map_err(|_| ApiError::InvalidRequest("changed_paths"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let source = match payload.source {
            kitsunebi_api::dto::SftpScanSource::OutOfBand => DomainSftpScanSource::OutOfBand,
            kitsunebi_api::dto::SftpScanSource::Provisioning => DomainSftpScanSource::Provisioning,
            kitsunebi_api::dto::SftpScanSource::Operator => DomainSftpScanSource::Operator,
        };
        let mut request = SftpScanRequest {
            actor: actor_id(actor)?,
            service,
            endpoint,
            binding,
            session,
            before_manifest_hash: payload.before_manifest_hash,
            after_manifest_hash: payload.after_manifest_hash,
            changed_paths,
            observed_at: payload.observed_at,
            source,
            idempotency_key: context.idempotency_key,
            request_hash: String::new(),
        };
        request.request_hash = request.computed_request_hash().map_err(application_error)?;
        let scan = application::SftpScanService {
            repository: self.storage.clone(),
            authorizer: self.app.authorizer.clone(),
            audit: self.app.audit.clone(),
        }
        .record_scan(&request)
        .await
        .map_err(application_error)?;
        let changed_paths = scan
            .changed_paths
            .iter()
            .map(|path| SftpChangedPathDto {
                path: path.path.clone(),
                kind: match path.kind {
                    DomainSftpChangeKind::Added => kitsunebi_api::dto::SftpChangeKind::Added,
                    DomainSftpChangeKind::Modified => kitsunebi_api::dto::SftpChangeKind::Modified,
                    DomainSftpChangeKind::Removed => kitsunebi_api::dto::SftpChangeKind::Removed,
                },
                before_digest: path.before_digest.clone(),
                after_digest: path.after_digest.clone(),
                classification: match path.classification {
                    FileClassification::Managed => kitsunebi_api::dto::FileClassification::Managed,
                    FileClassification::MutableConfig => {
                        kitsunebi_api::dto::FileClassification::MutableConfig
                    }
                    FileClassification::Artifact => {
                        kitsunebi_api::dto::FileClassification::Artifact
                    }
                    FileClassification::Generated => {
                        kitsunebi_api::dto::FileClassification::Generated
                    }
                    FileClassification::State => kitsunebi_api::dto::FileClassification::State,
                    FileClassification::Secret => kitsunebi_api::dto::FileClassification::Secret,
                    FileClassification::Unknown => kitsunebi_api::dto::FileClassification::Unknown,
                },
            })
            .collect();
        Ok(SftpScanDto {
            id: scan.id.as_uuid().to_string(),
            endpoint_id: scan.endpoint_id.as_uuid().to_string(),
            service_id: scan.service_id.as_uuid().to_string(),
            execution_binding_id: scan.execution_binding_id.as_uuid().to_string(),
            session_id: scan.session_id.as_uuid().to_string(),
            before_manifest_hash: scan.before_manifest_hash,
            after_manifest_hash: scan.after_manifest_hash,
            changed_paths,
            observed_at: scan.observed_at,
            source: match scan.source {
                DomainSftpScanSource::OutOfBand => kitsunebi_api::dto::SftpScanSource::OutOfBand,
                DomainSftpScanSource::Provisioning => {
                    kitsunebi_api::dto::SftpScanSource::Provisioning
                }
                DomainSftpScanSource::Operator => kitsunebi_api::dto::SftpScanSource::Operator,
            },
            request_hash: scan.request_hash,
        })
    }
    async fn begin_change_session(
        &self,
        actor: &VerifiedActor,
        payload: ChangeBeginPayload,
        idempotency_key: &str,
        request_id: &str,
    ) -> Result<ChangeSessionDto, ApiError> {
        if idempotency_key.trim().is_empty() || request_id.trim().is_empty() {
            return Err(ApiError::InvalidRequest("mutation identity is required"));
        }
        let service_id = Self::service_id(&payload.service_id)?;
        let cluster_id = Self::cluster_id(&payload.cluster_id)?;
        // Resolve the owner from the persisted cluster before accepting the
        // client-supplied service id. JWT role/scope claims are not consulted.
        self.checker
            .authorize(
                actor,
                "clusters",
                Some(&payload.cluster_id),
                ApiPermission::ChangePlan,
            )
            .await?;
        let cluster = self
            .app
            .repository
            .cluster(cluster_id)
            .await
            .map_err(application_error)?;
        if cluster.service_id != service_id {
            return Err(ApiError::Conflict);
        }
        let session = self
            .coordinator()
            .begin(&ChangeRequest {
                actor: actor_id(actor)?,
                service: service_id,
                cluster: cluster_id,
                domain_revision: 0,
                idempotency_key: idempotency_key.to_owned(),
                steps: Vec::new(),
                observed_state_hashes: Vec::new(),
                expiry: now().saturating_add(24 * 60 * 60),
            })
            .await
            .map_err(application_error)?;
        Ok(ChangeSessionDto {
            id: session.id.as_uuid().to_string(),
            service_id: service_id.as_uuid().to_string(),
            cluster_id: session.target_cluster.as_uuid().to_string(),
            version: session.version,
            state: match session.state {
                ChangeSessionState::Open => "open",
                ChangeSessionState::Editing => "editing",
                ChangeSessionState::Ready => "ready",
                ChangeSessionState::Applying => "applying",
                ChangeSessionState::Verifying => "verifying",
                ChangeSessionState::Accepted => "accepted",
                ChangeSessionState::RolledBack => "rolled_back",
                ChangeSessionState::Aborted => "aborted",
                ChangeSessionState::Conflicted => "conflicted",
            }
            .into(),
        })
    }
    async fn mutate(
        &self,
        resource: &str,
        id: Option<&str>,
        request: MutationRequest,
        context: MutationContext,
    ) -> Result<OperationDto, ApiError> {
        request.validate_for(resource, request.command, request.action)?;
        // High-impact work is executable only through a persisted typed plan.
        // Resource action routes are deliberately not a second operation
        // engine: callers must use the change-session plan/apply/verify/
        // accept/rollback protocol.  This also prevents a synthetic session
        // or caller-selected provider operation from being manufactured here.
        if !matches!(
            request.action,
            MutationAction::Change
                if matches!(
                    request.command,
                    MutationCommand::Apply
                        | MutationCommand::Verify
                        | MutationCommand::Accept
                        | MutationCommand::Rollback
                )
        ) {
            return Err(ApiError::InvalidRequest(
                "high-impact mutations require a persisted change plan",
            ));
        }
        if context.request_hash != request.request_hash || context.expires_at != request.expires_at
        {
            return Err(ApiError::Conflict);
        }
        if context.idempotency_key.trim().is_empty()
            || context.request_id.trim().is_empty()
            || context.if_match.trim().is_empty()
            || context.expires_at <= now()
        {
            return Err(ApiError::InvalidRequest("mutation context is invalid"));
        }
        let actor = actor_id(&context.actor)?;
        let permission = mutation_permission(resource, request.action, request.command);
        let authorized = self
            .checker
            .authorized_service_ids(&context.actor, resource, id, permission)
            .await?;
        if authorized.is_empty() {
            return Err(ApiError::NotFound);
        }
        let request_hash = Self::request_hash(&request, &context)?;
        let payload = request.payload.clone();
        let operation = match payload {
            MutationPayload::ChangePlan(_) => {
                // The dedicated plan route returns ChangePlanResultDto. Keeping
                // this generic mutation path closed prevents a plan from being
                // misrepresented as a durable execution operation.
                return Err(ApiError::InvalidRequest(
                    "change plans must use /change-sessions/{id}/plan",
                ));
            }
            MutationPayload::ChangeApprove(payload) => {
                let session_id = Self::session_id(&payload.session_id)?;
                let session = self.session(session_id).await?;
                let service_id = self.session_service(&session).await?;
                if !authorized.contains(&service_id) {
                    return Err(ApiError::NotFound);
                }
                let plan = self
                    .plan_for_session(session_id, Self::plan_id(&payload.plan_id)?)
                    .await?;
                if plan.actor != actor {
                    return Err(ApiError::Forbidden);
                }
                if plan.is_expired(now()) {
                    return Err(ApiError::InvalidRequest("plan has expired"));
                }
                if plan.plan_hash != payload.plan_hash
                    || !Self::if_match_matches(&context.if_match, &plan.plan_hash)
                {
                    return Err(ApiError::Conflict);
                }
                if !matches!(session.state, ChangeSessionState::Ready) {
                    self.coordinator()
                        .ready(session_id, actor, service_id)
                        .await
                        .map_err(application_error)?;
                }
                Operation {
                    id: kitsunebi_domain::OperationId::from_uuid(plan.id.as_uuid()),
                    plan_id: plan.id,
                    session_id,
                    state: OperationState::Planned,
                }
            }
            MutationPayload::ChangeApply(payload) => {
                let session_id = Self::session_id(&payload.session_id)?;
                let session = self.session(session_id).await?;
                let service_id = self.session_service(&session).await?;
                if !authorized.contains(&service_id) {
                    return Err(ApiError::NotFound);
                }
                let plan_id = Self::plan_id(&payload.plan_id)?;
                let plan = self.plan_for_session(session_id, plan_id).await?;
                if !Self::if_match_matches(&context.if_match, &plan.plan_hash) {
                    return Err(ApiError::Conflict);
                }
                if !matches!(
                    session.state,
                    ChangeSessionState::Ready | ChangeSessionState::Applying
                ) {
                    return Err(ApiError::Conflict);
                }
                let operation_request = OperationRequest {
                    key: context.idempotency_key.clone(),
                    actor,
                    service: service_id,
                    session_id,
                    target: plan.target.stable_string(),
                    request_hash,
                };
                if let Some(existing) = self
                    .app
                    .operations
                    .find_idempotent(&operation_request)
                    .await
                    .map_err(application_error)?
                {
                    existing
                } else {
                    if matches!(session.state, ChangeSessionState::Ready) {
                        self.coordinator()
                            .mark_applying(session_id, actor, service_id)
                            .await
                            .map_err(application_error)?;
                    }
                    self.app
                        .execute_plan(&operation_request, plan_id, now(), &context.request_id)
                        .await
                        .map_err(application_error)?
                }
            }
            MutationPayload::ChangeVerify(payload) => {
                let session_id = Self::session_id(&payload.session_id)?;
                let session = self.session(session_id).await?;
                let service_id = self.session_service(&session).await?;
                if !authorized.contains(&service_id) {
                    return Err(ApiError::NotFound);
                }
                let operation_id = Self::operation_id(&payload.operation_id)?;
                let operation = self
                    .app
                    .operations
                    .operation(operation_id)
                    .await
                    .map_err(application_error)?;
                if operation.session_id != session_id
                    || operation.state != OperationState::Verifying
                {
                    return Err(ApiError::Conflict);
                }
                if session.state != ChangeSessionState::Verifying {
                    return Err(ApiError::Conflict);
                }
                // The client-provided evidence hash is an assertion about the
                // request, never proof of the provider state. Verification
                // reobserves every typed plan step through the application
                // workflow and compares it with durable apply evidence.
                // Operations are allocated independently from plans. Resolve
                // the plan through the persisted operation association; using
                // the operation UUID as a plan UUID silently verified the
                // wrong object whenever the IDs differed.
                let plan = self.plan_for_session(session_id, operation.plan_id).await?;
                self.execution_workflow()
                    .verify(
                        operation_id,
                        session_id,
                        &plan,
                        service_id,
                        now(),
                        &context.request_id,
                    )
                    .await
                    .map_err(application_error)?
            }
            MutationPayload::ChangeAccept(payload) => {
                let session_id = Self::session_id(&payload.session_id)?;
                let session = self.session(session_id).await?;
                let service_id = self.session_service(&session).await?;
                if !authorized.contains(&service_id) {
                    return Err(ApiError::NotFound);
                }
                let operation_id = Self::operation_id(&payload.operation_id)?;
                let operation = self
                    .app
                    .operations
                    .operation(operation_id)
                    .await
                    .map_err(application_error)?;
                if operation.state == OperationState::Accepted
                    && session.state == ChangeSessionState::Accepted
                {
                    return self.operation_dto(operation, &context.request_id).await;
                }
                if operation.session_id != session_id || operation.state != OperationState::Verified
                {
                    return Err(ApiError::Conflict);
                }
                if session.state != ChangeSessionState::Verifying {
                    return Err(ApiError::Conflict);
                }
                self.execution_workflow()
                    .accept(operation_id, session_id, now(), &context.request_id)
                    .await
                    .map_err(application_error)?
            }
            MutationPayload::ChangeRollback(payload) => {
                let session_id = Self::session_id(&payload.session_id)?;
                let session = self.session(session_id).await?;
                let service_id = self.session_service(&session).await?;
                if !authorized.contains(&service_id) {
                    return Err(ApiError::NotFound);
                }
                let operation_id = Self::operation_id(&payload.operation_id)?;
                let operation = self
                    .app
                    .operations
                    .operation(operation_id)
                    .await
                    .map_err(application_error)?;
                if operation.state == OperationState::RolledBack
                    && session.state == ChangeSessionState::RolledBack
                {
                    return self.operation_dto(operation, &context.request_id).await;
                }
                if operation.session_id != session_id
                    || !matches!(
                        operation.state,
                        OperationState::Applying
                            | OperationState::Verifying
                            | OperationState::Verified
                            | OperationState::Failed
                    )
                {
                    return Err(ApiError::Conflict);
                }
                if !rollback_state_pair_is_valid(operation.state, session.state) {
                    return Err(ApiError::Conflict);
                }
                let plan = self.plan_for_session(session_id, operation.plan_id).await?;
                let _ = payload.reason;
                self.execution_workflow()
                    .rollback(
                        operation_id,
                        session_id,
                        &plan,
                        service_id,
                        now(),
                        &context.request_id,
                    )
                    .await
                    .map_err(application_error)?
            }
        };
        self.operation_dto(operation, &context.request_id).await
    }
    async fn open_console(
        &self,
        actor: &VerifiedActor,
        unit_id: &str,
    ) -> Result<Box<dyn ConsoleSession>, ApiError> {
        self.checker
            .authorize(
                actor,
                "execution-units",
                Some(unit_id),
                ApiPermission::ConsoleRead,
            )
            .await?;
        let binding_uuid = self
            .checker
            .execution_binding_id(unit_id)
            .await?
            .ok_or(ApiError::NotFound)?;
        let target_cluster = self
            .storage
            .resolve_gameap_binding_cluster(binding_uuid)
            .await
            .map_err(|_| ApiError::Backend)?
            .ok_or(ApiError::NotFound)?;
        let service = self
            .app
            .repository
            .cluster(target_cluster)
            .await
            .map_err(application_error)?
            .service_id;
        let authorized_services = self
            .checker
            .authorized_service_ids(
                actor,
                "execution-units",
                Some(unit_id),
                ApiPermission::ConsoleRead,
            )
            .await?;
        if !authorized_services.contains(&service) {
            return Err(ApiError::NotFound);
        }
        // Read and command are independent capabilities. Keep a read-only
        // stream available while enabling command input only for an explicitly
        // scoped ConsoleSend grant.
        let command_services = self
            .checker
            .authorized_service_ids(
                actor,
                "execution-units",
                Some(unit_id),
                ApiPermission::ConsoleSend,
            )
            .await?;
        let can_command = console_can_command(&command_services, service);
        let binding = self
            .storage
            .get_gameap_binding_for_scope(binding_uuid, service, target_cluster)
            .await
            .map_err(|_| ApiError::Backend)?
            .ok_or(ApiError::NotFound)?;
        let actor_id = actor_id(actor)?;
        let console = self
            .execution_service
            .open_console(&binding, actor_id, service)
            .await
            .map_err(application_error)?;
        Ok(Box::new(GameApConsoleSession {
            console,
            can_command,
            execution_service: self.execution_service.clone(),
            audit: self.audit.clone(),
            binding,
            actor: actor_id,
            service,
        }))
    }
    async fn open_operation_stream(
        &self,
        actor: &VerifiedActor,
        operation_id: &str,
    ) -> Result<Box<dyn OperationStreamPort>, ApiError> {
        self.checker
            .authorize(
                actor,
                "operations",
                Some(operation_id),
                ApiPermission::OperationRead,
            )
            .await?;
        let id = Uuid::parse_str(operation_id)
            .map(kitsunebi_domain::OperationId::from_uuid)
            .map_err(|_| ApiError::NotFound)?;
        Ok(Box::new(MysqlOperationStream {
            storage: self.storage.clone(),
            checker: self.checker.as_ref().clone(),
            actor: actor.clone(),
            operation: id,
            emitted: false,
            terminal: false,
            next_sequence: 0,
        }))
    }
    async fn health(&self) -> Result<Value, ApiError> {
        let database_ready = self.storage.ping().await.is_ok();
        Ok(json!({
            "status": if database_ready { "healthy" } else { "unhealthy" },
            "controller": {"status": "up"},
            "controller_database": {
                "status": if database_ready { "ready" } else { "unhealthy" },
                "migrations": if database_ready { "applied" } else { "unknown" },
            },
        }))
    }

    async fn provider_health(&self, _actor: &VerifiedActor) -> Result<Value, ApiError> {
        Ok(MysqlManagement::provider_health(self).await)
    }

    async fn ready(&self) -> Result<Value, ApiError> {
        let database_ready = self.storage.ping().await.is_ok();
        Ok(json!({
            "status": if database_ready { "ready" } else { "unready" },
            "controller": {"status": "up"},
            "controller_database": {
                "status": if database_ready { "ready" } else { "unhealthy" },
                "migrations": if database_ready { "applied" } else { "unknown" },
            },
        }))
    }

    fn files(&self) -> &dyn FilePort {
        self.files.as_ref()
    }
}

impl MysqlManagement {
    /// Reachability is an observation, not a startup capability diagnostic.
    /// Probe the public server-status and node-daemon endpoints for every
    /// current binding so panel, daemon, and runtime failures remain distinct.
    pub async fn provider_health(&self) -> Value {
        let bindings = match self.storage.list_gameap_bindings().await {
            Ok(bindings) => bindings,
            Err(_) => {
                return gameap_health_payload(GameApHealthObservation {
                    bindings_query_failed: true,
                    ..Default::default()
                });
            }
        };
        let mut observation = GameApHealthObservation {
            binding_count: bindings.len(),
            ..Default::default()
        };
        for binding in bindings {
            match self
                .execution
                .client
                .status(&binding.execution_unit_id)
                .await
            {
                Ok(status) => {
                    observation.panel_successes += 1;
                    if status.process_active {
                        observation.runtime_running += 1;
                    } else {
                        observation.runtime_stopped += 1;
                    }
                }
                Err(_) => {
                    observation.panel_failures += 1;
                    observation.runtime_unknown += 1;
                }
            }
            if self
                .execution
                .client
                .node_status(&binding.node_id)
                .await
                .is_ok()
            {
                observation.daemon_successes += 1;
            } else {
                observation.daemon_failures += 1;
            }
        }
        gameap_health_payload(observation)
    }

    /// Readiness is limited to the controller's own durable store. Provider
    /// degradation is reported by `health`, but does not make the process
    /// unready while its database remains usable.
    pub async fn controller_database_ready(&self) -> Result<(), ApiError> {
        self.storage.ping().await.map_err(|_| ApiError::Backend)
    }
}

pub struct Controller {
    pub config: Config,
    pub storage: MySqlStorage,
    pub management: Arc<MysqlManagement>,
    pub authenticator: Arc<Authenticator>,
    pub security: Arc<SecurityConfig>,
}
impl Controller {
    pub async fn build(config: Config) -> Result<Self, Box<dyn std::error::Error>> {
        config.validate()?;
        let security = Arc::new(config.security()?);
        let storage = MySqlStorage::connect(&config.database_url)
            .await
            .map_err(|_| std::io::Error::other("database connection failed"))?;
        storage
            .migrate()
            .await
            .map_err(|_| std::io::Error::other("database migration failed"))?;
        let checker = Arc::new(AccessChecker::new(storage.clone()));
        let mapper: Arc<dyn IdentityMapper> = Arc::new(MysqlIdentityMapper::new(storage.clone()));
        let authenticator = if config.mode == RuntimeMode::Local {
            #[cfg(feature = "local-auth")]
            {
                Arc::new(Authenticator::local(mapper))
            }
            #[cfg(not(feature = "local-auth"))]
            {
                return Err(Box::new(ConfigError::Security));
            }
        } else {
            let jwks: Arc<dyn kitsunebi_api::JwksProvider> =
                Arc::new(kitsunebi_api::RemoteJwks::new(&config.access)?);
            Arc::new(Authenticator::new(config.access.clone(), jwks, mapper)?)
        };
        let gameap_config = GameApClientConfig {
            timeout: Duration::from_secs(10),
            max_response_bytes: DEFAULT_GAMEAP_RESPONSE_LIMIT,
            max_upload_bytes: DEFAULT_UPLOAD_LIMIT as u64,
            max_download_bytes: DEFAULT_UPLOAD_LIMIT as u64,
        };
        let gameap_transport = GameApHttpTransport::new(&config.gameap_base_url, gameap_config)?;
        let gameap_assertion = TrustedDeploymentAssertion {
            api_version: env::var("GAMEAP_API_VERSION").unwrap_or_default(),
            allow_creation: config.gameap_allow_creation,
            allow_placement: false,
        };
        let schema_hash = env::var("GAMEAP_SCHEMA_SHA256")
            .or_else(|_| env::var("GAMEAP_API_SCHEMA_SHA256"))
            .unwrap_or_default();
        // The real contract suite is deliberately opt-in.  Merely knowing the
        // version is not enough to enable lifecycle mutation; operators must
        // run the external contract test against their panel and assert its
        // result through this gate.
        let lifecycle_attestation = gameap_lifecycle_attestation(
            env::var("KITSUNEBI_GAMEAP_LIFECYCLE_ATTESTED")
                .ok()
                .as_deref(),
        )
        .map_err(std::io::Error::other)?;
        let gameap_client = GameApClient::new(
            &config.gameap_base_url,
            GameApSecret::new(config.gameap_pat.clone()),
            gameap_transport,
        )?
        .with_config(gameap_config);
        let mut gameap_capabilities = Capabilities::with_operator_lifecycle_attestation(
            gameap_assertion,
            &schema_hash,
            lifecycle_attestation,
        );
        // Status, daemon and file-list reads are non-destructive.  Probe them
        // at startup when an operator supplies concrete IDs; failed probes
        // remain diagnostics and never widen mutation capabilities.
        let probe_server = env::var("GAMEAP_PROBE_SERVER_ID")
            .or_else(|_| env::var("GAMEAP_CAPABILITY_SERVER_ID"))
            .ok();
        let probe_node = env::var("GAMEAP_PROBE_NODE_ID")
            .or_else(|_| env::var("GAMEAP_CAPABILITY_NODE_ID"))
            .ok();
        if let (Some(server), Some(node)) = (probe_server, probe_node)
            && !server.trim().is_empty()
            && !node.trim().is_empty()
            && let Ok(probed) = gameap_client.discover_capabilities(&server, &node).await
        {
            for diagnostic in probed.diagnostics {
                if !matches!(
                    diagnostic.capability,
                    kitsunebi_gameap::Capability::StatusRead
                        | kitsunebi_gameap::Capability::NodeStatusRead
                        | kitsunebi_gameap::Capability::FileList
                ) {
                    continue;
                }
                gameap_capabilities
                    .diagnostics
                    .retain(|item| item.capability != diagnostic.capability);
                gameap_capabilities.diagnostics.push(diagnostic);
            }
        }
        // Persist the provider-neutral node observation returned by the
        // official process-manager plugin.  Placement decisions consume this
        // durable evidence; an absent or unknown observation is never turned
        // into an optimistic default.
        if let Some(node) = env::var("GAMEAP_PROBE_NODE_ID")
            .or_else(|_| env::var("GAMEAP_CAPABILITY_NODE_ID"))
            .ok()
            && let Ok(node_id) = node.parse::<u64>()
            && let Ok(process) = gameap_client
                .observe_process_manager(kitsunebi_gameap::PROCESS_MANAGER_PLUGIN_ID, node_id)
                .await
        {
            let manager = match process.process_manager {
                kitsunebi_gameap::ProcessManager::Systemd => {
                    kitsunebi_domain::ProcessManager::Systemd
                }
                kitsunebi_gameap::ProcessManager::Docker => {
                    kitsunebi_domain::ProcessManager::Docker
                }
                kitsunebi_gameap::ProcessManager::Podman => {
                    kitsunebi_domain::ProcessManager::Podman
                }
                kitsunebi_gameap::ProcessManager::Unknown => {
                    kitsunebi_domain::ProcessManager::Unknown
                }
            };
            if let Ok(observation) = kitsunebi_domain::NodeCapabilityObservation::new(
                &node,
                manager,
                Some(process.version),
                vec!["process_manager".into()],
                &process.evidence_hash,
                process.timestamp,
            ) {
                storage
                    .record_node_capability(&observation)
                    .await
                    .map_err(|_| std::io::Error::other("node capability persistence failed"))?;
            }
        }
        let gameap = Arc::new(gameap_client.with_capabilities(gameap_capabilities));
        let execution = Arc::new(GameApExecutionBackend::with_capability_store(
            gameap,
            storage.clone(),
        ));
        let artifacts = Arc::new(ArtifactBridge::new(config.artifact_root.clone())?);
        let backup_provider = configured_backup_provider(config.mode)?;
        let monitoring = configured_monitoring(config.mode)?;
        let authorizer = MysqlAuthorizer::new(storage.clone());
        let audit = MysqlAudit::new(storage.clone());
        let execution_service = Arc::new(application::ExecutionService {
            backend: (*execution).clone(),
            authorizer: authorizer.clone(),
            audit: audit.clone(),
        });
        let artifact_service = Arc::new(application::ArtifactService {
            provider: (*artifacts).clone(),
            store: (*artifacts).clone(),
            authorizer: authorizer.clone(),
            audit: audit.clone(),
        });
        let backup_service = Arc::new(application::BackupService {
            provider: backup_provider.clone(),
            authorizer: authorizer.clone(),
        });
        let tcp_shield = match (
            config.tcpshield_base_url.as_deref(),
            config.tcpshield_api_key.as_deref(),
            config.tcpshield_network_id,
        ) {
            (Some(base), Some(key), Some(network_id)) => {
                let client_config = TcpShieldClientConfig {
                    timeout: Duration::from_secs(15),
                    max_response_bytes: 1024 * 1024,
                };
                let client = if config.mode == RuntimeMode::Local {
                    TcpShieldClient::localhost_test(
                        base,
                        TcpShieldSecret::new(key.to_owned()),
                        client_config,
                    )?
                } else {
                    TcpShieldClient::production(
                        base,
                        TcpShieldSecret::new(key.to_owned()),
                        client_config,
                    )?
                };
                Some(Arc::new(TcpShieldComposition::new_with_monitoring(
                    Arc::new(client),
                    network_id,
                    monitoring,
                )?))
            }
            (None, None, None) => None,
            _ => return Err("invalid TCPShield configuration".into()),
        };
        let app = Arc::new(ApplicationService {
            repository: storage.clone(),
            operations: storage.clone(),
            steps: ControllerStepPort {
                execution: execution.clone(),
                artifacts: artifacts.clone(),
                storage: storage.clone(),
                authorizer: authorizer.clone(),
                audit: audit.clone(),
                backup: backup_provider,
                tcp_shield: tcp_shield.clone(),
            },
            authorizer: authorizer.clone(),
            audit: audit.clone(),
        });
        let change = Arc::new(application::ChangeCoordinator {
            repository: storage.clone(),
            authorizer: authorizer.clone(),
            audit: audit.clone(),
        });
        let files = Arc::new(GameApFiles {
            change,
            execution: execution.clone(),
            execution_service: execution_service.clone(),
            checker: checker.clone(),
            storage: storage.clone(),
            audit: audit.clone(),
            upload_limit: security.upload_limit,
        });
        let management = Arc::new(MysqlManagement::new(
            storage.clone(),
            ManagementComponents {
                app,
                checker,
                execution,
                files,
                audit,
                execution_service,
                artifact_service,
                staging: artifacts.clone(),
                backup_service,
                tcp_shield,
            },
        ));
        Ok(Self {
            config,
            storage,
            management,
            authenticator,
            security,
        })
    }
}

pub async fn open_storage(
    config: &Config,
) -> Result<MySqlStorage, kitsunebi_storage::StorageError> {
    let storage = MySqlStorage::connect(&config.database_url).await?;
    storage.migrate().await?;
    Ok(storage)
}
pub async fn shutdown_signal() {
    #[cfg(unix)]
    {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {},
                    _ = terminate.recv() => {},
                }
            }
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct RecordingAudit {
        events: std::sync::Mutex<Vec<kitsunebi_domain::AuditEvent>>,
        fail: bool,
    }

    #[async_trait::async_trait]
    impl AuditSink for RecordingAudit {
        async fn record(
            &self,
            event: kitsunebi_domain::AuditEvent,
        ) -> Result<(), ApplicationError> {
            if self.fail {
                return Err(ApplicationError::Port("test audit failure".into()));
            }
            self.events.lock().unwrap().push(event);
            Ok(())
        }
    }

    fn config() -> Config {
        Config {
            listen_addr: "127.0.0.1:8080".into(),
            database_url: "mysql://operator:db-secret@db.example/kitsunebi".into(),
            gameap_base_url: "https://gameap.example".into(),
            gameap_pat: "gameap-secret".into(),
            gameap_allow_creation: false,
            tcpshield_base_url: None,
            tcpshield_api_key: None,
            tcpshield_network_id: None,
            artifact_root: "/var/lib/kitsunebi/artifacts".into(),
            web_static_root: "/var/lib/kitsunebi/web".into(),
            access: AccessConfig {
                issuer: "https://team.example".into(),
                audience: "console".into(),
                jwks_url: "https://team.example/cdn-cgi/access/certs".into(),
                clock_skew: Duration::from_secs(60),
                cache_ttl: Duration::from_secs(3600),
                request_timeout: Duration::from_secs(5),
                max_jwks_bytes: 256 * 1024,
            },
            allowed_origins: BTreeSet::from(["https://console.example".into()]),
            csrf_token: None,
            csrf_secret: Some("0123456789abcdef0123456789abcdef".into()),
            mode: RuntimeMode::Production,
            local_auth: false,
        }
    }

    #[test]
    fn production_config_validates_and_redacts_credentials() {
        let config = config();
        config.validate().unwrap();
        let debug = format!("{config:?}");
        assert!(!debug.contains("db-secret"));
        assert!(!debug.contains("gameap-secret"));
        assert!(!debug.contains("0123456789abcdef0123456789abcdef"));
        assert_eq!(
            config.redacted_database_url(),
            "mysql://[REDACTED]@db.example/kitsunebi"
        );
    }

    #[test]
    fn database_url_query_is_redacted_too() {
        let mut config = config();
        config.database_url =
            "mysql://operator:db-secret@db.example/kitsunebi?password=query-secret".into();
        let redacted = config.redacted_database_url();
        assert!(!redacted.contains("db-secret"));
        assert!(!redacted.contains("query-secret"));
        assert_eq!(redacted, "mysql://[REDACTED]@db.example/kitsunebi");
    }

    #[test]
    fn endpoint_debug_redacts_userinfo_and_query() {
        let mut config = config();
        config.gameap_base_url =
            "https://operator:gameap-secret@gameap.example/panel?token=query-secret".into();
        config.tcpshield_base_url =
            Some("https://operator:shield-secret@shield.example?key=query-secret".into());
        let debug = format!("{config:?}");
        assert!(!debug.contains("gameap-secret"));
        assert!(!debug.contains("shield-secret"));
        assert!(!debug.contains("query-secret"));
        assert!(debug.contains("https://gameap.example/panel"));
    }

    #[test]
    fn provider_errors_are_mapped_without_response_body() {
        let gameap = GameApExecutionBackend::map_error(GameApError::Http {
            status: 401,
            kind: kitsunebi_gameap::HttpErrorKind::Unauthorized,
            body: "glst_secret-pat".into(),
            request_id: None,
        });
        assert!(!format!("{gameap:?}").contains("glst_secret-pat"));

        let tcpshield = TcpShieldBridge::map_error(kitsunebi_tcpshield::Error::Http {
            status: 500,
            body: "api-key=secret".into(),
        });
        assert!(!format!("{tcpshield:?}").contains("api-key=secret"));

        assert_eq!(
            gameap_api_error(GameApError::Unsupported(
                kitsunebi_gameap::Capability::FileQuarantine,
            )),
            ApiError::Unsupported
        );
    }

    #[test]
    fn production_local_auth_is_rejected() {
        let mut config = config();
        config.local_auth = true;
        assert_eq!(config.validate(), Err(ConfigError::Security));
        assert!(matches!(config.security(), Err(ConfigError::Security)));
    }

    #[test]
    fn production_requires_a_valid_csrf_secret() {
        let mut missing = config();
        missing.csrf_secret = None;
        assert_eq!(
            missing.validate(),
            Err(ConfigError::Missing("KITSUNEBI_CSRF_SECRET"))
        );
        assert!(matches!(
            missing.security(),
            Err(ConfigError::Missing("KITSUNEBI_CSRF_SECRET"))
        ));

        let mut short = config();
        short.csrf_secret = Some("too-short".into());
        assert_eq!(
            short.validate(),
            Err(ConfigError::Invalid("KITSUNEBI_CSRF_SECRET"))
        );
        assert!(matches!(short.security(), Err(ConfigError::Security)));
    }

    #[test]
    fn lifecycle_attestation_requires_the_single_explicit_gate() {
        assert_eq!(
            gameap_lifecycle_attestation(Some("1")),
            Ok(LifecycleContractAttestation::Verified)
        );
        assert_eq!(
            gameap_lifecycle_attestation(None),
            Ok(LifecycleContractAttestation::NotRun)
        );
        assert!(gameap_lifecycle_attestation(Some("true")).is_err());
    }

    #[test]
    fn console_command_capability_is_independent_from_read_access() {
        let service = ServiceId::from_uuid(Uuid::new_v4());
        let other_service = ServiceId::from_uuid(Uuid::new_v4());
        assert!(console_can_command(&[service], service));
        assert!(!console_can_command(&[], service));
        assert!(!console_can_command(&[other_service], service));
    }

    #[test]
    fn gameap_health_reports_provider_parts_and_runtime_state_separately() {
        let healthy = gameap_health_payload(GameApHealthObservation {
            binding_count: 2,
            panel_successes: 2,
            daemon_successes: 2,
            runtime_running: 1,
            runtime_stopped: 1,
            ..Default::default()
        });
        assert_eq!(healthy["status"], "healthy");
        assert_eq!(healthy["panel"]["status"], "ready");
        assert_eq!(healthy["daemon"]["status"], "ready");
        assert_eq!(healthy["runtime"]["status"], "mixed");

        let degraded = gameap_health_payload(GameApHealthObservation {
            binding_count: 2,
            panel_successes: 1,
            panel_failures: 1,
            daemon_successes: 2,
            runtime_running: 1,
            runtime_unknown: 1,
            ..Default::default()
        });
        assert_eq!(degraded["status"], "degraded");
        assert_eq!(degraded["panel"]["status"], "degraded");
        assert_eq!(degraded["daemon"]["status"], "ready");
        assert_eq!(degraded["runtime"]["status"], "unknown");

        let no_bindings = gameap_health_payload(GameApHealthObservation::default());
        assert_eq!(no_bindings["status"], "degraded");
        assert_eq!(no_bindings["panel"]["status"], "unknown");
        assert_eq!(no_bindings["daemon"]["status"], "unknown");
        assert_eq!(no_bindings["runtime"]["status"], "unknown");

        let unavailable = gameap_health_payload(GameApHealthObservation {
            bindings_query_failed: true,
            ..Default::default()
        });
        assert_eq!(unavailable["status"], "unavailable");
        assert_eq!(unavailable["panel"]["status"], "unknown");
    }

    #[test]
    fn console_audit_is_scoped_and_content_free() {
        let actor = ActorId::from_uuid(Uuid::new_v4());
        let service = ServiceId::from_uuid(Uuid::new_v4());
        let binding = GameAPBinding {
            execution_unit_id: "provider-unit-opaque".into(),
            node_id: "provider-node-opaque".into(),
            target: GameAPBindingTarget::ExecutionUnit("provider-unit-opaque".into()),
        };
        let event = console_audit_event(
            actor,
            service,
            &binding,
            ConsoleAuditEvent {
                direction: ConsoleDirection::ClientToBackend,
                size: 12,
                digest: "digest-value".into(),
            },
        )
        .expect("valid execution-unit scope");
        assert_eq!(event.action, "console.send");
        assert_eq!(event.target, "provider-unit-opaque");
        assert_eq!(event.scope.service_id, service);
        assert_eq!(
            event.scope.execution_unit_ref.as_deref(),
            Some("provider-unit-opaque")
        );
        assert_eq!(event.evidence, vec!["digest=digest-value", "bytes=12"]);
        assert!(!event.evidence.iter().any(|value| value.contains("secret")));
    }

    #[tokio::test]
    async fn console_audit_persistence_is_required() {
        let actor = ActorId::from_uuid(Uuid::new_v4());
        let service = ServiceId::from_uuid(Uuid::new_v4());
        let binding = GameAPBinding {
            execution_unit_id: "unit-1".into(),
            node_id: "node-1".into(),
            target: GameAPBindingTarget::ExecutionUnit("unit-1".into()),
        };
        let event = console_audit_event(
            actor,
            service,
            &binding,
            ConsoleAuditEvent {
                direction: ConsoleDirection::BackendToClient,
                size: 4,
                digest: "digest".into(),
            },
        )
        .unwrap();
        let sink = RecordingAudit {
            events: std::sync::Mutex::new(Vec::new()),
            fail: false,
        };
        persist_console_audit(&sink, event).await.unwrap();
        assert_eq!(sink.events.lock().unwrap().len(), 1);

        let failing_sink = RecordingAudit {
            events: std::sync::Mutex::new(Vec::new()),
            fail: true,
        };
        assert_eq!(
            persist_console_audit(
                &failing_sink,
                console_audit_event(
                    actor,
                    service,
                    &binding,
                    ConsoleAuditEvent {
                        direction: ConsoleDirection::ClientToBackend,
                        size: 1,
                        digest: "digest".into(),
                    },
                )
                .unwrap(),
            )
            .await,
            Err(ApiError::Backend)
        );
    }

    #[test]
    fn invalid_tcp_shield_configuration_fails_closed() {
        let mut config = config();
        config.tcpshield_base_url = Some("https://api.tcpshield.example".into());
        assert_eq!(
            config.validate(),
            Err(ConfigError::Invalid("TCPShield configuration"))
        );
    }

    #[test]
    fn production_rejects_insecure_gameap_transport() {
        let mut config = config();
        config.gameap_base_url = "http://gameap.example".into();
        assert_eq!(config.validate(), Err(ConfigError::Security));
    }

    #[test]
    fn provider_tokens_reject_header_injection() {
        let mut pat_config = config();
        pat_config.gameap_pat = "pat\nsecret".into();
        assert_eq!(
            pat_config.validate(),
            Err(ConfigError::Invalid("GAMEAP_PAT"))
        );

        let mut tcp_config = config();
        tcp_config.tcpshield_base_url = Some("https://api.tcpshield.example".into());
        tcp_config.tcpshield_api_key = Some("key\rsecret".into());
        tcp_config.tcpshield_network_id = Some(1);
        assert_eq!(
            tcp_config.validate(),
            Err(ConfigError::Invalid("TCPShield configuration"))
        );
    }

    #[test]
    fn mutation_permissions_follow_action_level_api_contract() {
        assert_eq!(
            mutation_permission("worlds", MutationAction::Change, MutationCommand::Apply),
            ApiPermission::WorldWrite
        );
        assert_eq!(
            mutation_permission("endpoints", MutationAction::Change, MutationCommand::Apply),
            ApiPermission::EndpointWrite
        );
        assert_eq!(
            mutation_permission(
                "access-policies",
                MutationAction::Change,
                MutationCommand::Apply
            ),
            ApiPermission::AccessManage
        );
    }

    #[test]
    fn failed_operation_can_roll_back_only_from_aborted_session() {
        assert!(rollback_state_pair_is_valid(
            OperationState::Failed,
            ChangeSessionState::Aborted,
        ));
        for session in [
            ChangeSessionState::Applying,
            ChangeSessionState::Verifying,
            ChangeSessionState::Ready,
            ChangeSessionState::RolledBack,
        ] {
            assert!(!rollback_state_pair_is_valid(
                OperationState::Failed,
                session
            ));
        }
        for operation in [
            OperationState::Applying,
            OperationState::Verifying,
            OperationState::Verified,
        ] {
            assert!(!rollback_state_pair_is_valid(
                operation,
                ChangeSessionState::Aborted,
            ));
        }
    }

    #[test]
    fn endpoint_reconnect_requires_live_postconditions() {
        let cluster = ClusterId::from_uuid(Uuid::new_v4());
        let expected_revision = kitsunebi_domain::RevisionId::from_uuid(Uuid::new_v4());
        let target_revision = kitsunebi_domain::RevisionId::from_uuid(Uuid::new_v4());
        let expected = kitsunebi_domain::EndpointBinding::new(
            kitsunebi_domain::EndpointId::from_uuid(Uuid::new_v4()),
            cluster,
            expected_revision,
            "database",
        )
        .unwrap();
        let target = kitsunebi_domain::EndpointBinding::new(
            kitsunebi_domain::EndpointId::from_uuid(Uuid::new_v4()),
            cluster,
            target_revision,
            "database",
        )
        .unwrap();

        // Different endpoint records are valid during a reconnect, while the
        // logical binding key and cluster remain the same.
        assert!(ControllerStepPort::endpoint_binding_pair_matches(
            &expected,
            &target,
            cluster,
            expected_revision,
            target_revision,
            expected.id,
            target.id,
        ));
        let wrong_cluster = ClusterId::from_uuid(Uuid::new_v4());
        assert!(!ControllerStepPort::endpoint_binding_pair_matches(
            &expected,
            &target,
            wrong_cluster,
            expected_revision,
            target_revision,
            expected.id,
            target.id,
        ));
        let mut wrong_key = target.clone();
        wrong_key.binding_key = "other".into();
        assert!(!ControllerStepPort::endpoint_binding_pair_matches(
            &expected,
            &wrong_key,
            cluster,
            expected_revision,
            target_revision,
            expected.id,
            target.id,
        ));
        assert!(!ControllerStepPort::endpoint_reconnect_complete(
            Some(expected_revision),
            target_revision,
            true,
            true,
        ));
        assert!(!ControllerStepPort::endpoint_reconnect_complete(
            Some(target_revision),
            target_revision,
            false,
            true,
        ));
        assert!(!ControllerStepPort::endpoint_reconnect_complete(
            Some(target_revision),
            target_revision,
            true,
            false,
        ));
        assert!(ControllerStepPort::endpoint_reconnect_complete(
            Some(target_revision),
            target_revision,
            true,
            true,
        ));
    }

    #[test]
    fn endpoint_compensation_failure_is_not_swallowed() {
        let original = ApplicationError::VerificationFailed("postcondition".into());
        let error = ControllerStepPort::endpoint_compensation_error(
            original,
            Err(ApplicationError::Conflict("concurrent update")),
        );
        assert!(matches!(error, ApplicationError::RollbackConflict(_)));
        assert!(format!("{error}").contains("concurrent update"));
    }

    #[test]
    fn access_policy_update_rejects_shared_or_cross_scope_grants() {
        let service = ServiceId::from_uuid(Uuid::new_v4());
        let other = ServiceId::from_uuid(Uuid::new_v4());
        let actor = ActorId::from_uuid(Uuid::new_v4());
        let grant = |scope| {
            kitsunebi_domain::AccessGrant::for_actor(
                actor,
                kitsunebi_domain::Role::Operator,
                scope,
                [kitsunebi_domain::Permission::ServiceRead],
            )
        };
        assert!(ControllerStepPort::policy_has_exclusive_owner(
            &[service],
            service
        ));
        assert!(!ControllerStepPort::policy_has_exclusive_owner(
            &[service, other],
            service
        ));
        assert!(ControllerStepPort::grants_are_service_scoped(
            &[grant(Some(service))],
            service,
        ));
        assert!(!ControllerStepPort::grants_are_service_scoped(
            &[grant(Some(other))],
            service,
        ));
    }

    #[test]
    fn persisted_identity_kind_is_bound_to_the_authorized_service() {
        let service = ServiceId::from_uuid(Uuid::new_v4());
        let other = ServiceId::from_uuid(Uuid::new_v4());
        assert!(actor_identity_matches_service(
            kitsunebi_storage::ActorKind::Browser,
            None,
            service,
        ));
        assert!(!actor_identity_matches_service(
            kitsunebi_storage::ActorKind::Browser,
            Some(service),
            service,
        ));
        assert!(actor_identity_matches_service(
            kitsunebi_storage::ActorKind::Service,
            Some(service),
            service,
        ));
        assert!(!actor_identity_matches_service(
            kitsunebi_storage::ActorKind::Service,
            Some(other),
            service,
        ));
    }

    #[test]
    fn proxy_rollback_requires_exact_applied_state_and_membership() {
        assert!(ControllerStepPort::proxy_applied_state_matches(
            "applied", "applied", true,
        ));
        assert!(!ControllerStepPort::proxy_applied_state_matches(
            "prior", "applied", true,
        ));
        assert!(!ControllerStepPort::proxy_applied_state_matches(
            "applied", "applied", false,
        ));
    }

    #[test]
    fn protected_file_classes_return_metadata_only() {
        let content = b"private-state".to_vec();
        for classification in [
            FileClassification::Unknown,
            FileClassification::State,
            FileClassification::Secret,
        ] {
            let (content_type, response) =
                ControllerStepPort::file_read_payload(classification, content.clone());
            assert_eq!(content_type, "application/vnd.kitsunebi.file-metadata");
            assert!(
                !response
                    .windows(content.len())
                    .any(|window| window == content)
            );
            assert!(String::from_utf8(response).unwrap().contains("bytes=13"));
        }
        let (content_type, response) =
            ControllerStepPort::file_read_payload(FileClassification::Managed, content.clone());
        assert_eq!(content_type, "application/octet-stream");
        assert_eq!(response, content);
    }

    struct RecordingProxyEdge {
        state: std::sync::Mutex<BackendSet>,
        events: Arc<std::sync::Mutex<Vec<String>>>,
        connect_failure: bool,
    }

    impl RecordingProxyEdge {
        fn record(&self, event: String) {
            self.events.lock().unwrap().push(event);
        }

        fn state(&self) -> BackendSet {
            self.state.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl ProxyEdge for RecordingProxyEdge {
        async fn prepare(&self, _binding: &ProxyEdgeBinding) -> Result<(), ApplicationError> {
            self.record("prepare".into());
            Ok(())
        }

        async fn configure(&self, _binding: &ProxyEdgeBinding) -> Result<(), ApplicationError> {
            self.record("configure".into());
            Ok(())
        }

        async fn add(&self, binding: &ProxyEdgeBinding) -> Result<(), ApplicationError> {
            self.record(format!(
                "add:{}:{}",
                binding.backend_address, binding.observed_hash
            ));
            let mut state = self
                .state
                .lock()
                .map_err(|_| ApplicationError::Port("test edge lock poisoned".into()))?;
            if state.hash() != binding.observed_hash {
                return Err(ApplicationError::StalePlan);
            }
            if state.backends.contains(&binding.backend_address) {
                return Err(ApplicationError::Conflict("proxy backend already exists"));
            }
            *state = state
                .add(binding.backend_address.clone())
                .map_err(|_| ApplicationError::Conflict("invalid proxy backend"))?;
            Ok(())
        }

        async fn remove(&self, binding: &ProxyEdgeBinding) -> Result<(), ApplicationError> {
            self.record(format!(
                "remove:{}:{}",
                binding.backend_address, binding.observed_hash
            ));
            let mut state = self
                .state
                .lock()
                .map_err(|_| ApplicationError::Port("test edge lock poisoned".into()))?;
            if state.hash() != binding.observed_hash {
                return Err(ApplicationError::StalePlan);
            }
            if !state.backends.contains(&binding.backend_address) {
                return Err(ApplicationError::Conflict("proxy backend does not exist"));
            }
            *state = state.remove(&binding.backend_address);
            Ok(())
        }

        async fn drain(&self, binding: &ProxyEdgeBinding) -> Result<(), ApplicationError> {
            self.record("drain".into());
            self.remove(binding).await
        }

        async fn real_connect(
            &self,
            binding: &ProxyEdgeBinding,
        ) -> Result<ConnectionEvidence, ApplicationError> {
            self.record(format!(
                "connect:{}:{}",
                binding.backend_address, binding.observed_hash
            ));
            if self.connect_failure {
                return Err(ApplicationError::Port("test old connection failed".into()));
            }
            Ok(ConnectionEvidence {
                active: 1,
                observed: true,
                hash: "c".repeat(64),
            })
        }

        async fn stop(&self, binding: &ProxyEdgeBinding) -> Result<(), ApplicationError> {
            self.record(format!(
                "stop:{}:{}",
                binding.backend_address, binding.observed_hash
            ));
            let state = self
                .state
                .lock()
                .map_err(|_| ApplicationError::Port("test edge lock poisoned".into()))?;
            if state.hash() != binding.observed_hash
                || state.backends.contains(&binding.backend_address)
            {
                return Err(ApplicationError::StalePlan);
            }
            Ok(())
        }
    }

    #[async_trait]
    impl ProxyEdgeState for RecordingProxyEdge {
        async fn observe_backend_set(
            &self,
            _binding: &ProxyEdgeBinding,
        ) -> Result<BackendSet, ApplicationError> {
            let state = self
                .state
                .lock()
                .map_err(|_| ApplicationError::Port("test edge lock poisoned".into()))?
                .clone();
            self.record(format!("observe:{}", state.hash()));
            Ok(state)
        }
    }

    struct RecordingHealth {
        events: Arc<std::sync::Mutex<Vec<String>>>,
        failure: bool,
    }

    #[async_trait]
    impl HealthVerifier for RecordingHealth {
        async fn verify(&self, target: &str) -> Result<(), ApplicationError> {
            self.events.lock().unwrap().push(format!("health:{target}"));
            if self.failure {
                Err(ApplicationError::Port("test old health failed".into()))
            } else {
                Ok(())
            }
        }
    }

    fn proxy_edge_restore_fixture(
        connect_failure: bool,
        health_failure: bool,
    ) -> (
        RecordingProxyEdge,
        RecordingHealth,
        ProxyEdgeBinding,
        ProxyEdgeBinding,
        String,
        String,
        String,
    ) {
        let old_address = "old.example:25565".to_owned();
        let new_address = "new.example:25565".to_owned();
        let prior = BackendSet {
            id: 1,
            name: "proxy".into(),
            backends: vec![old_address.clone()],
            proxy_protocol: false,
            vulcan_ac_enabled: false,
            load_balancing_mode: 0,
        };
        let post_add = prior.add(new_address.clone()).unwrap();
        let final_state = post_add.remove(&old_address);
        let prior_hash = prior.hash();
        let post_add_hash = post_add.hash();
        let final_hash = final_state.hash();
        let revision = kitsunebi_domain::RevisionId::from_uuid(Uuid::new_v4());
        let new = ProxyEdgeBinding {
            instance_id: kitsunebi_domain::ProxyInstanceId::from_uuid(Uuid::new_v4()),
            provider_network_id: 1,
            domain_network_id: None,
            backend_set_id: "1".into(),
            backend_address: new_address,
            revision,
            observed_hash: final_hash.clone(),
        };
        let old = ProxyEdgeBinding {
            backend_address: old_address,
            observed_hash: final_hash.clone(),
            ..new.clone()
        };
        let events = Arc::new(std::sync::Mutex::new(Vec::new()));
        (
            RecordingProxyEdge {
                state: std::sync::Mutex::new(final_state),
                events: events.clone(),
                connect_failure,
            },
            RecordingHealth {
                events,
                failure: health_failure,
            },
            new,
            old,
            prior_hash,
            post_add_hash,
            final_hash,
        )
    }

    #[tokio::test]
    async fn proxy_edge_restore_checks_old_health_and_connect_before_new_remove() {
        let (edge, health, new, old, prior_hash, post_add_hash, final_hash) =
            proxy_edge_restore_fixture(false, false);
        ControllerStepPort::restore_proxy_edge(
            &edge,
            &health,
            &new,
            &old,
            &prior_hash,
            &post_add_hash,
            &final_hash,
            &ApplicationError::Conflict("handoff failed"),
        )
        .await
        .unwrap();
        assert_eq!(edge.state().hash(), prior_hash);
        let events = edge.events.lock().unwrap().clone();
        let health = events
            .iter()
            .position(|event| event.starts_with("health:old.example"))
            .unwrap();
        let add = events
            .iter()
            .position(|event| event.starts_with("add:old.example"))
            .unwrap();
        let connect = events
            .iter()
            .position(|event| event.starts_with("connect:old.example"))
            .unwrap();
        let remove = events
            .iter()
            .position(|event| event.starts_with("remove:new.example"))
            .unwrap();
        assert!(health < add && add < connect && connect < remove);
        assert!(
            events
                .iter()
                .any(|event| event == &format!("add:old.example:25565:{final_hash}"))
        );
        assert!(
            events
                .iter()
                .any(|event| event == &format!("remove:new.example:25565:{post_add_hash}"))
        );
    }

    #[tokio::test]
    async fn proxy_edge_restore_connect_failure_removes_old_and_preserves_final() {
        let (edge, health, new, old, prior_hash, post_add_hash, final_hash) =
            proxy_edge_restore_fixture(true, false);
        let error = ControllerStepPort::restore_proxy_edge(
            &edge,
            &health,
            &new,
            &old,
            &prior_hash,
            &post_add_hash,
            &final_hash,
            &ApplicationError::Conflict("handoff failed"),
        )
        .await
        .unwrap_err();
        assert!(matches!(error, ApplicationError::RollbackConflict(_)));
        assert!(format!("{error}").contains("old-connect"));
        assert_eq!(edge.state().hash(), final_hash);
        let events = edge.events.lock().unwrap().clone();
        let connect = events
            .iter()
            .position(|event| event.starts_with("connect:old.example"))
            .unwrap();
        let remove_old = events
            .iter()
            .position(|event| event.starts_with("remove:old.example"))
            .unwrap();
        assert!(connect < remove_old);
        assert_eq!(
            events
                .iter()
                .filter(|event| event.starts_with("remove:new.example"))
                .count(),
            0
        );
        assert!(
            events
                .iter()
                .any(|event| event == &format!("remove:old.example:25565:{post_add_hash}"))
        );
    }

    #[tokio::test]
    async fn tcpshield_drain_is_rejected_before_provider_mutation() {
        let client = TcpShieldClient::localhost_test(
            "http://127.0.0.1:1",
            TcpShieldSecret::new("test-key"),
            TcpShieldClientConfig::default(),
        )
        .unwrap();
        let bridge = TcpShieldBridge::new(Arc::new(client), 1).unwrap();
        let binding = ProxyEdgeBinding {
            instance_id: kitsunebi_domain::ProxyInstanceId::from_uuid(Uuid::new_v4()),
            provider_network_id: 1,
            domain_network_id: None,
            backend_set_id: "1".into(),
            backend_address: "127.0.0.1:25565".into(),
            revision: kitsunebi_domain::RevisionId::from_uuid(Uuid::new_v4()),
            observed_hash: "0".repeat(64),
        };
        let result = bridge.drain(&binding).await;
        assert!(matches!(result, Err(ApplicationError::Port(_))));
    }

    #[tokio::test]
    async fn unknown_gameap_lifecycle_never_becomes_observed_success() {
        let transport =
            GameApHttpTransport::new("https://gameap.example", GameApClientConfig::default())
                .expect("valid GameAP transport");
        let client = GameApClient::new(
            "https://gameap.example",
            GameApSecret::new("test-pat"),
            transport,
        )
        .expect("valid GameAP client");
        let execution = Arc::new(GameApExecutionBackend::new(Arc::new(client)));
        let result = execution
            .start(&GameAPBinding {
                execution_unit_id: "1".into(),
                node_id: "1".into(),
                target: GameAPBindingTarget::ExecutionUnit("1".into()),
            })
            .await;
        assert!(matches!(result, Err(ApplicationError::Port(_))));
    }
}
