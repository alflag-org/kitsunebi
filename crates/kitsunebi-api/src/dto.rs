//! Stable transport DTOs used at the HTTP/application boundary.

use crate::error::ApiError;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

/// A resource collection exposed by the management API.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "kebab-case")]
pub enum ResourceKind {
    Networks,
    Services,
    Clusters,
    ClusterRevisions,
    Worlds,
    ProxyPools,
    ProxyInstances,
    ExecutionUnits,
    RuntimeProfiles,
    Artifacts,
    Config,
    Endpoints,
    AccessPolicies,
    ChangeSessions,
    Operations,
    Backups,
    SftpEndpoints,
    SftpScans,
    AuditEvents,
}

impl ResourceKind {
    pub const ALL: [Self; 19] = [
        Self::Networks,
        Self::Services,
        Self::Clusters,
        Self::ClusterRevisions,
        Self::Worlds,
        Self::ProxyPools,
        Self::ProxyInstances,
        Self::ExecutionUnits,
        Self::RuntimeProfiles,
        Self::Artifacts,
        Self::Config,
        Self::Endpoints,
        Self::AccessPolicies,
        Self::ChangeSessions,
        Self::Operations,
        Self::Backups,
        Self::SftpEndpoints,
        Self::SftpScans,
        Self::AuditEvents,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Networks => "networks",
            Self::Services => "services",
            Self::Clusters => "clusters",
            Self::ClusterRevisions => "cluster-revisions",
            Self::Worlds => "worlds",
            Self::ProxyPools => "proxy-pools",
            Self::ProxyInstances => "proxy-instances",
            Self::ExecutionUnits => "execution-units",
            Self::RuntimeProfiles => "runtime-profiles",
            Self::Artifacts => "artifacts",
            Self::Config => "config",
            Self::Endpoints => "endpoints",
            Self::AccessPolicies => "access-policies",
            Self::ChangeSessions => "change-sessions",
            Self::Operations => "operations",
            Self::Backups => "backups",
            Self::SftpEndpoints => "sftp-endpoints",
            Self::SftpScans => "sftp-scans",
            Self::AuditEvents => "audit-events",
        }
    }

    pub fn parse(value: &str) -> Result<Self, ApiError> {
        Self::ALL
            .into_iter()
            .find(|resource| resource.as_str() == value)
            .ok_or(ApiError::NotFound)
    }
}

/// Generic object representation. Domain-specific serialization remains in the
/// application layer and is not exposed through this crate's ports.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct ResourceDto {
    pub id: String,
    #[serde(flatten)]
    pub fields: Value,
}

/// Browser session material returned after authentication. The token is
/// intentionally not persisted and no service actor can request this DTO.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SessionDto {
    pub csrf_token: String,
}

/// A state-changing command carried by a mutation envelope.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MutationCommand {
    Plan,
    Approve,
    Apply,
    Verify,
    Accept,
    Rollback,
}

impl MutationCommand {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Plan => "plan",
            Self::Approve => "approve",
            Self::Apply => "apply",
            Self::Verify => "verify",
            Self::Accept => "accept",
            Self::Rollback => "rollback",
        }
    }
}

/// Identifies the typed operation requested by an action route.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum MutationAction {
    Change,
}

impl MutationAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Change => "change",
        }
    }

    pub fn parse(value: &str) -> Result<Self, ApiError> {
        match value {
            "change" => Ok(Self::Change),
            _ => Err(ApiError::NotFound),
        }
    }
}

/// Domain-owned backup target. Provider references returned by a backup
/// adapter are intentionally not representable in a persisted plan.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum BackupTarget {
    Service(String),
    Cluster(String),
    World(String),
    ExecutionUnit(String),
}

/// Closed set of Kitsunebi domain targets accepted by a persisted plan.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum PlanTarget {
    Service(String),
    Cluster(String),
    World(String),
    ProxyPool(String),
    ProxyInstance(String),
    Artifact(String),
    ArtifactSet(String),
    Endpoint(String),
    EndpointBinding(String),
    AccessPolicy(String),
    Backup(String),
    ExecutionUnit(String),
}

impl PlanTarget {
    fn validate(&self) -> Result<(), ApiError> {
        let id = match self {
            Self::Service(id)
            | Self::Cluster(id)
            | Self::World(id)
            | Self::ProxyPool(id)
            | Self::ProxyInstance(id)
            | Self::Artifact(id)
            | Self::ArtifactSet(id)
            | Self::Endpoint(id)
            | Self::EndpointBinding(id)
            | Self::AccessPolicy(id)
            | Self::Backup(id)
            | Self::ExecutionUnit(id) => id,
        };
        validate_uuid_id(id, "target")
    }
}

impl BackupTarget {
    fn validate(&self, field: &'static str) -> Result<(), ApiError> {
        let id = match self {
            Self::Service(id) | Self::Cluster(id) | Self::World(id) | Self::ExecutionUnit(id) => id,
        };
        validate_uuid_id(id, field)
    }
}

/// The closed set of actions which can be persisted in a change plan.
///
/// Every variant carries the compare-and-set material required to re-observe
/// the target immediately before apply. There is intentionally no generic
/// JSON command or provider identifier in this type.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum PlanStepAction {
    ExecutionProvision(ExecutionProvisionStep),
    ExecutionDelete(ExecutionDeleteStep),
    ServiceLifecycleTransition(ServiceLifecycleTransitionStep),
    ClusterRevisionCreate(ClusterRevisionCreateStep),
    ExecutionLifecycle(ExecutionLifecycleStep),
    FileWrite(FileWriteStep),
    FileMove(FileMoveStep),
    FileQuarantine(FileQuarantineStep),
    FileBatch(FileBatchStep),
    ArtifactStage(ArtifactStageStep),
    ArtifactRegister(ArtifactRegisterStep),
    ArtifactActivate(ArtifactActivateStep),
    ProxyRollout(ProxyRolloutStep),
    WorldWriterCutover(WorldWriterCutoverStep),
    EndpointRollout(EndpointRolloutStep),
    AccessPolicyUpdate(AccessPolicyUpdateStep),
    RoutePolicyUpdate(RoutePolicyUpdateStep),
    BackupCreate(BackupCreateStep),
    BackupRestore(BackupRestoreStep),
    ServiceArchive(ServiceArchiveStep),
    ServicePurge(ServicePurgeStep),
}

impl PlanStepAction {
    pub fn validate(&self) -> Result<(), ApiError> {
        let id = |value: &str, field: &'static str| validate_uuid_id(value, field);
        let hash = |value: &str, field: &'static str| validate_hash(value, field);
        let optional_hash = |value: &Option<String>, field: &'static str| {
            value.as_deref().map(|value| hash(value, field)).transpose()
        };
        let staged = |value: &StagedContentDto| {
            hash(&value.digest, "step.content.digest")?;
            if value.size > crate::UPLOAD_LIMIT as u64 {
                return Err(ApiError::InvalidRequest("step.content.size"));
            }
            Ok(())
        };
        let writable = |value: FileClassification| match value {
            FileClassification::Unknown
            | FileClassification::State
            | FileClassification::Secret => Err(ApiError::InvalidRequest("step.classification")),
            _ => Ok(()),
        };
        match self {
            Self::ExecutionProvision(step) => {
                id(&step.binding_id, "step.binding_id")?;
                hash(&step.expected_binding_hash, "step.expected_binding_hash")?;
            }
            Self::ExecutionDelete(step) => {
                id(&step.binding_id, "step.binding_id")?;
                hash(&step.expected_binding_hash, "step.expected_binding_hash")?;
                hash(&step.expected_state_hash, "step.expected_state_hash")?;
            }
            Self::ServiceLifecycleTransition(step) => {
                id(&step.service_id, "step.service_id")?;
                if step.reason.trim().is_empty() || step.reason.len() > 1024 {
                    return Err(ApiError::InvalidRequest("step.reason"));
                }
            }
            Self::ClusterRevisionCreate(step) => {
                id(&step.cluster_id, "step.cluster_id")?;
                id(&step.revision.id.as_uuid().to_string(), "step.revision.id")?;
                id(
                    &step.revision.runtime_profile.as_uuid().to_string(),
                    "step.revision.runtime_profile",
                )?;
                id(
                    &step.revision.artifact_set.as_uuid().to_string(),
                    "step.revision.artifact_set",
                )?;
                id(
                    &step.revision.config_baseline.as_uuid().to_string(),
                    "step.revision.config_baseline",
                )?;
                for world in &step.revision.world_bindings {
                    id(&world.as_uuid().to_string(), "step.revision.world_bindings")?;
                }
                for endpoint in &step.revision.endpoint_bindings {
                    id(
                        &endpoint.as_uuid().to_string(),
                        "step.revision.endpoint_bindings",
                    )?;
                }
                let mut binding_ids = std::collections::BTreeSet::new();
                let mut binding_keys = std::collections::BTreeSet::new();
                for binding in &step.new_endpoint_bindings {
                    binding
                        .validate()
                        .map_err(|_| ApiError::InvalidRequest("step.new_endpoint_bindings"))?;
                    if binding.cluster_id.as_uuid().to_string() != step.cluster_id
                        || binding.revision_id != step.revision.id
                        || !binding_ids.insert(binding.id)
                        || !binding_keys.insert(&binding.binding_key)
                    {
                        return Err(ApiError::InvalidRequest(
                            "step.new_endpoint_bindings does not match revision",
                        ));
                    }
                }
                let revision_binding_ids = step
                    .revision
                    .endpoint_bindings
                    .iter()
                    .copied()
                    .collect::<std::collections::BTreeSet<_>>();
                if revision_binding_ids != binding_ids {
                    return Err(ApiError::InvalidRequest(
                        "step.new_endpoint_bindings does not match revision",
                    ));
                }
            }
            Self::ExecutionLifecycle(step) => {
                id(&step.binding_id, "step.binding_id")?;
                hash(&step.expected_binding_hash, "step.expected_binding_hash")?;
                hash(&step.expected_state_hash, "step.expected_state_hash")?;
            }
            Self::FileWrite(step) => {
                id(&step.binding_id, "step.binding_id")?;
                crate::security::validate_relative_path(&step.path)?;
                hash(&step.expected_binding_hash, "step.expected_binding_hash")?;
                optional_hash(&step.expected_before_digest, "step.expected_before_digest")?;
                staged(&step.content)?;
                writable(step.classification)?;
            }
            Self::FileMove(step) => {
                id(&step.binding_id, "step.binding_id")?;
                crate::security::validate_relative_path(&step.from)?;
                crate::security::validate_relative_path(&step.to)?;
                hash(&step.expected_binding_hash, "step.expected_binding_hash")?;
                optional_hash(&step.expected_before_digest, "step.expected_before_digest")?;
                optional_hash(&step.expected_target_digest, "step.expected_target_digest")?;
                writable(step.classification)?;
            }
            Self::FileQuarantine(step) => {
                id(&step.binding_id, "step.binding_id")?;
                crate::security::validate_relative_path(&step.path)?;
                hash(&step.expected_binding_hash, "step.expected_binding_hash")?;
                optional_hash(&step.expected_before_digest, "step.expected_before_digest")?;
                writable(step.classification)?;
            }
            Self::FileBatch(step) => {
                id(&step.binding_id, "step.binding_id")?;
                hash(&step.expected_binding_hash, "step.expected_binding_hash")?;
                if step.operations.is_empty() || step.operations.len() > 1024 {
                    return Err(ApiError::InvalidRequest(
                        "step.operations must contain 1..1024 items",
                    ));
                }
                for operation in &step.operations {
                    match operation {
                        FileBatchStepOperation::Write {
                            path,
                            expected_before_digest,
                            content,
                            classification,
                        } => {
                            crate::security::validate_relative_path(path)?;
                            optional_hash(expected_before_digest, "step.expected_before_digest")?;
                            staged(content)?;
                            writable(*classification)?;
                        }
                        FileBatchStepOperation::Move {
                            from,
                            to,
                            expected_before_digest,
                            expected_target_digest,
                            classification,
                        } => {
                            crate::security::validate_relative_path(from)?;
                            crate::security::validate_relative_path(to)?;
                            optional_hash(expected_before_digest, "step.expected_before_digest")?;
                            optional_hash(expected_target_digest, "step.expected_target_digest")?;
                            writable(*classification)?;
                        }
                        FileBatchStepOperation::Quarantine {
                            path,
                            expected_before_digest,
                            classification,
                        } => {
                            crate::security::validate_relative_path(path)?;
                            optional_hash(expected_before_digest, "step.expected_before_digest")?;
                            writable(*classification)?;
                        }
                    }
                }
            }
            Self::ArtifactStage(step) => {
                id(&step.artifact_id, "step.artifact_id")?;
                hash(&step.expected_digest, "step.expected_digest")?;
            }
            Self::ArtifactRegister(step) => {
                id(&step.artifact.id.as_uuid().to_string(), "step.artifact.id")?;
                hash(&step.artifact.digest, "step.artifact.digest")?;
                staged(&step.content)?;
                if !step
                    .artifact
                    .digest
                    .eq_ignore_ascii_case(&step.content.digest)
                {
                    return Err(ApiError::InvalidRequest(
                        "step.content.digest does not match artifact",
                    ));
                }
            }
            Self::ArtifactActivate(step) => {
                id(&step.artifact_id, "step.artifact_id")?;
                id(&step.artifact_set_id, "step.artifact_set_id")?;
                id(&step.cluster_id, "step.cluster_id")?;
                id(&step.expected_revision, "step.expected_revision")?;
                id(&step.target_revision, "step.target_revision")?;
                hash(&step.expected_digest, "step.expected_digest")?;
                id(&step.binding_id, "step.binding_id")?;
                hash(&step.expected_binding_hash, "step.expected_binding_hash")?;
                crate::security::validate_relative_path(&step.destination_path)?;
                optional_hash(&step.expected_before_digest, "step.expected_before_digest")?;
            }
            Self::ProxyRollout(step) => {
                id(&step.pool_id, "step.pool_id")?;
                id(&step.expected_instance_id, "step.expected_instance_id")?;
                id(&step.target_instance_id, "step.target_instance_id")?;
                id(&step.target_binding_id, "step.target_binding_id")?;
                hash(&step.target_binding_hash, "step.target_binding_hash")?;
                if step.expected_instance_id == step.target_instance_id
                    || step.expected_instance_version == 0
                    || step.target_instance_version == 0
                    || step.expected_instance_state != ProxyState::Accepting
                    || !matches!(
                        step.target_instance_state,
                        ProxyState::Preparing | ProxyState::Ready
                    )
                    || step.desired_state != ProxyState::Accepting
                    || step.domain_revision == 0
                {
                    return Err(ApiError::InvalidRequest("step.proxy rollout state"));
                }
                if step.configuration.is_empty() || step.configuration.len() > 1024 {
                    return Err(ApiError::InvalidRequest(
                        "step.configuration must contain 1..1024 writes",
                    ));
                }
                let mut paths = std::collections::BTreeSet::new();
                for operation in &step.configuration {
                    let FileBatchStepOperation::Write {
                        path,
                        expected_before_digest,
                        content,
                        classification,
                    } = operation
                    else {
                        return Err(ApiError::InvalidRequest(
                            "step.configuration must contain writes",
                        ));
                    };
                    crate::security::validate_relative_path(path)?;
                    if !paths.insert(path) || *classification != FileClassification::MutableConfig {
                        return Err(ApiError::InvalidRequest("step.configuration"));
                    }
                    optional_hash(expected_before_digest, "step.expected_before_digest")?;
                    staged(content)?;
                }
            }
            Self::WorldWriterCutover(step) => {
                id(&step.world_id, "step.world_id")?;
                if let Some(writer) = &step.expected_writer {
                    id(writer, "step.expected_writer")?;
                }
                id(&step.next_writer, "step.next_writer")?;
                if let Some(binding) = &step.expected_writer_binding_id {
                    id(binding, "step.expected_writer_binding_id")?;
                }
                id(
                    &step.target_writer_binding_id,
                    "step.target_writer_binding_id",
                )?;
                if step.expected_writer.is_some() != step.expected_writer_binding_id.is_some()
                    || step.expected_writer.is_some() != step.expected_writer_binding_hash.is_some()
                    || step.expected_writer == Some(step.next_writer.clone())
                    || step.expected_version == 0
                    || step.domain_revision == 0
                {
                    return Err(ApiError::InvalidRequest("step.world writer"));
                }
                if let Some(hash_value) = &step.expected_writer_binding_hash {
                    hash(hash_value, "step.expected_writer_binding_hash")?;
                }
                hash(
                    &step.target_writer_binding_hash,
                    "step.target_writer_binding_hash",
                )?;
            }
            Self::EndpointRollout(step) => {
                id(&step.expected_binding_id, "step.expected_binding_id")?;
                id(&step.target_binding_id, "step.target_binding_id")?;
                id(&step.cluster_id, "step.cluster_id")?;
                id(&step.expected_revision, "step.expected_revision")?;
                id(&step.target_revision, "step.target_revision")?;
                if step.expected_binding_id == step.target_binding_id
                    || step.expected_revision == step.target_revision
                    || step.expected_version == 0
                    || step.runtime_binding_ids.is_empty()
                    || step.runtime_binding_ids.len() > 128
                    || step.runtime_binding_ids.len() != step.runtime_binding_hashes.len()
                {
                    return Err(ApiError::InvalidRequest("step.endpoint rollout bindings"));
                }
                let mut runtime_ids = std::collections::BTreeSet::new();
                for (binding_id, binding_hash) in step
                    .runtime_binding_ids
                    .iter()
                    .zip(&step.runtime_binding_hashes)
                {
                    id(binding_id, "step.runtime_binding_ids")?;
                    hash(binding_hash, "step.runtime_binding_hashes")?;
                    if !runtime_ids.insert(binding_id) {
                        return Err(ApiError::InvalidRequest(
                            "step.runtime_binding_ids contains duplicates",
                        ));
                    }
                }
            }
            Self::AccessPolicyUpdate(step) => {
                id(&step.policy_id, "step.policy_id")?;
                id(&step.service_id, "step.service_id")?;
                hash(&step.desired_policy_hash, "step.desired_policy_hash")?;
                if step.desired_grants.len() > 1024 {
                    return Err(ApiError::InvalidRequest(
                        "step.desired_grants must contain 1..1024 items",
                    ));
                }
                for grant in &step.desired_grants {
                    id(&grant.actor_id, "step.desired_grants.actor_id")?;
                    let Some(scope) = grant.service_scope.as_deref() else {
                        return Err(ApiError::InvalidRequest(
                            "step.desired_grants.service_scope must target service_id",
                        ));
                    };
                    if scope != step.service_id {
                        return Err(ApiError::InvalidRequest(
                            "step.desired_grants.service_scope must target service_id",
                        ));
                    }
                    id(scope, "step.desired_grants.service_scope")?;
                    if grant.permissions.is_empty() {
                        return Err(ApiError::InvalidRequest(
                            "step.desired_grants.permissions must not be empty",
                        ));
                    }
                }
            }
            Self::RoutePolicyUpdate(step) => {
                id(&step.route_id, "step.route_id")?;
                id(&step.pool_id, "step.pool_id")?;
                id(&step.service_id, "step.service_id")?;
                id(&step.expected_cluster, "step.expected_cluster")?;
                id(&step.target_cluster, "step.target_cluster")?;
            }
            Self::BackupCreate(step) => {
                step.target.validate("step.target")?;
                hash(&step.request_hash, "step.request_hash")?;
            }
            Self::BackupRestore(step) => {
                id(&step.reference_id, "step.reference_id")?;
                id(&step.rollback_reference_id, "step.rollback_reference_id")?;
                step.target.validate("step.target")?;
                hash(
                    &step.expected_manifest_digest,
                    "step.expected_manifest_digest",
                )?;
                hash(
                    &step.expected_rollback_manifest_digest,
                    "step.expected_rollback_manifest_digest",
                )?;
                if step.reference_id == step.rollback_reference_id || step.expected_version == 0 {
                    return Err(ApiError::InvalidRequest("step.backup restore references"));
                }
            }
            Self::ServiceArchive(step) => {
                id(&step.service_id, "step.service_id")?;
                hash(
                    &step.sunsetting_evidence_hash,
                    "step.sunsetting_evidence_hash",
                )?;
            }
            Self::ServicePurge(step) => {
                id(&step.service_id, "step.service_id")?;
                hash(&step.archive_evidence_hash, "step.archive_evidence_hash")?;
                id(&step.verified_backup_id, "step.verified_backup_id")?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PlanStepDto {
    pub action: PlanStepAction,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionProvisionStep {
    pub binding_id: String,
    pub expected_binding_hash: String,
    pub domain_revision: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionDeleteStep {
    pub binding_id: String,
    pub expected_binding_hash: String,
    pub expected_state_hash: String,
    pub domain_revision: u64,
    pub expected_version: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServiceLifecycleTransitionStep {
    pub service_id: String,
    pub expected_state: kitsunebi_domain::ServiceLifecycle,
    pub next_state: kitsunebi_domain::ServiceLifecycle,
    pub expected_version: u64,
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClusterRevisionCreateStep {
    pub cluster_id: String,
    pub revision: kitsunebi_domain::ClusterRevision,
    pub new_endpoint_bindings: Vec<kitsunebi_domain::EndpointBinding>,
    pub expected_current_number: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionLifecycleStep {
    pub binding_id: String,
    pub action: ExecutionLifecycleAction,
    pub expected_binding_hash: String,
    pub expected_state_hash: String,
    pub domain_revision: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StagedContentDto {
    pub digest: String,
    pub size: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileWriteStep {
    pub binding_id: String,
    pub path: String,
    pub expected_binding_hash: String,
    pub domain_revision: u64,
    pub expected_before_digest: Option<String>,
    pub content: StagedContentDto,
    pub classification: FileClassification,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileMoveStep {
    pub binding_id: String,
    pub from: String,
    pub to: String,
    pub expected_binding_hash: String,
    pub domain_revision: u64,
    pub expected_before_digest: Option<String>,
    pub expected_target_digest: Option<String>,
    pub classification: FileClassification,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileQuarantineStep {
    pub binding_id: String,
    pub path: String,
    pub expected_binding_hash: String,
    pub domain_revision: u64,
    pub expected_before_digest: Option<String>,
    pub classification: FileClassification,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FileBatchStep {
    pub binding_id: String,
    pub expected_binding_hash: String,
    pub domain_revision: u64,
    pub operations: Vec<FileBatchStepOperation>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum FileBatchStepOperation {
    Write {
        path: String,
        expected_before_digest: Option<String>,
        content: StagedContentDto,
        classification: FileClassification,
    },
    Move {
        from: String,
        to: String,
        expected_before_digest: Option<String>,
        expected_target_digest: Option<String>,
        classification: FileClassification,
    },
    Quarantine {
        path: String,
        expected_before_digest: Option<String>,
        classification: FileClassification,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactStageStep {
    pub artifact_id: String,
    pub expected_digest: String,
    pub expected_version: u64,
    pub domain_revision: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRegisterStep {
    pub artifact: kitsunebi_domain::Artifact,
    pub content: StagedContentDto,
    pub expected_version: u64,
    pub domain_revision: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactActivateStep {
    pub artifact_id: String,
    pub artifact_set_id: String,
    pub cluster_id: String,
    pub expected_revision: String,
    pub target_revision: String,
    pub expected_digest: String,
    pub expected_version: u64,
    pub binding_id: String,
    pub expected_binding_hash: String,
    pub destination_path: String,
    pub expected_before_digest: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProxyRolloutStep {
    pub pool_id: String,
    pub expected_instance_id: String,
    pub target_instance_id: String,
    pub expected_instance_version: u64,
    pub target_instance_version: u64,
    pub expected_instance_state: ProxyState,
    pub target_instance_state: ProxyState,
    pub target_binding_id: String,
    pub target_binding_hash: String,
    pub domain_revision: u64,
    pub desired_state: ProxyState,
    pub configuration: Vec<FileBatchStepOperation>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorldWriterCutoverStep {
    pub world_id: String,
    pub expected_version: u64,
    pub expected_writer: Option<String>,
    pub next_writer: String,
    pub expected_writer_binding_id: Option<String>,
    pub target_writer_binding_id: String,
    pub expected_writer_binding_hash: Option<String>,
    pub target_writer_binding_hash: String,
    pub domain_revision: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EndpointRolloutStep {
    pub expected_binding_id: String,
    pub target_binding_id: String,
    pub cluster_id: String,
    pub expected_revision: String,
    pub target_revision: String,
    pub expected_version: u64,
    pub runtime_binding_ids: Vec<String>,
    pub runtime_binding_hashes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AccessPolicyUpdateStep {
    pub policy_id: String,
    pub service_id: String,
    pub expected_version: u64,
    pub desired_grants: Vec<PolicyGrantPayload>,
    pub desired_policy_hash: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RoutePolicyUpdateStep {
    pub route_id: String,
    pub pool_id: String,
    pub service_id: String,
    pub expected_cluster: String,
    pub target_cluster: String,
    pub expected_priority: u32,
    pub target_priority: u32,
    pub expected_version: u64,
    pub disabled: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BackupCreateStep {
    pub kind: BackupKind,
    pub target: BackupTarget,
    pub request_hash: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BackupRestoreStep {
    pub reference_id: String,
    pub target: BackupTarget,
    pub expected_manifest_digest: String,
    pub rollback_reference_id: String,
    pub expected_rollback_manifest_digest: String,
    pub expected_version: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServiceArchiveStep {
    pub service_id: String,
    pub expected_version: u64,
    pub sunsetting_evidence_hash: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServicePurgeStep {
    pub service_id: String,
    pub expected_version: u64,
    pub archive_evidence_hash: String,
    pub verified_backup_id: String,
    pub archived_at: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChangeBeginPayload {
    pub service_id: String,
    pub cluster_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChangeSessionDto {
    pub id: String,
    pub service_id: String,
    pub cluster_id: String,
    pub state: String,
    pub version: u64,
}

/// Result returned when a change plan is persisted. Planning does not create
/// an execution operation; that identity is allocated only by apply.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ChangePlanResultDto {
    pub plan_id: String,
    pub plan_hash: String,
    pub session_id: String,
    pub state: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ChangeApprovalDto {
    pub plan_id: String,
    pub plan_hash: String,
    pub session_id: String,
    pub state: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionLifecycleAction {
    Start,
    Stop,
    Restart,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChangePlanPayload {
    pub session_id: String,
    pub service_id: String,
    pub target: PlanTarget,
    pub domain_revision: u64,
    pub observed_state_hashes: Vec<String>,
    #[serde(default)]
    pub expected_file_hashes: Vec<String>,
    #[serde(default)]
    pub expected_artifact_hashes: Vec<String>,
    pub steps: Vec<PlanStepDto>,
    #[serde(default)]
    pub backup_required: bool,
    #[serde(default)]
    pub backup_references: Vec<String>,
    #[serde(default)]
    pub rollback_instructions: Vec<String>,
    pub expires_at: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChangeApprovePayload {
    pub session_id: String,
    pub plan_id: String,
    pub plan_hash: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChangeApplyPayload {
    pub session_id: String,
    pub plan_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChangeVerifyPayload {
    pub session_id: String,
    pub operation_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChangeAcceptPayload {
    pub session_id: String,
    pub operation_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChangeRollbackPayload {
    pub session_id: String,
    pub operation_id: String,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyRole {
    PlatformAdmin,
    Operator,
    ServiceMaintainer,
    Auditor,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyPermission {
    ServiceRead,
    LifecycleStart,
    LifecycleStop,
    LifecycleRestart,
    ServiceLifecycle,
    ConsoleRead,
    ConsoleSend,
    FilesRead,
    FilesWrite,
    FilesBatch,
    ArtifactDiscover,
    ArtifactStage,
    ArtifactActivate,
    ProxyRollout,
    BackupCreate,
    BackupRestore,
    WorldRead,
    WorldWrite,
    EndpointRead,
    EndpointWrite,
    ServiceArchive,
    ServicePurge,
    ChangePlan,
    ChangeApprove,
    ChangeApply,
    ChangeVerify,
    ChangeAccept,
    ChangeRollback,
    AuditRead,
    AccessRead,
    AccessManage,
    OperationRead,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolicyGrantPayload {
    pub actor_id: String,
    pub role: PolicyRole,
    pub service_scope: Option<String>,
    pub permissions: Vec<PolicyPermission>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactProvider {
    Manual,
    DirectUrl,
    Modrinth,
    GithubRelease,
    Paper,
    Hangar,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManualArtifactQuery {
    pub kind: String,
    pub name: String,
    pub version: String,
    pub source: String,
    pub source_id: String,
    pub digest: String,
    pub filename: String,
    pub compatibility: String,
    pub metadata: String,
    pub size: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DirectUrlArtifactQuery {
    pub url: String,
    pub filename: String,
    pub digest: String,
    pub size: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RepositoryArtifactQuery {
    pub project: String,
    pub version: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "value", rename_all = "kebab-case")]
pub enum ArtifactProviderQuery {
    Manual(ManualArtifactQuery),
    DirectUrl(DirectUrlArtifactQuery),
    Modrinth(RepositoryArtifactQuery),
    GithubRelease(RepositoryArtifactQuery),
    Paper(RepositoryArtifactQuery),
    Hangar(RepositoryArtifactQuery),
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactDiscoverPayload {
    pub provider: ArtifactProvider,
    pub query: ArtifactProviderQuery,
}
impl ArtifactDiscoverPayload {
    pub fn validate(&self) -> Result<(), ApiError> {
        let matches = matches!(
            (&self.provider, &self.query),
            (ArtifactProvider::Manual, ArtifactProviderQuery::Manual(_))
                | (
                    ArtifactProvider::DirectUrl,
                    ArtifactProviderQuery::DirectUrl(_)
                )
                | (
                    ArtifactProvider::Modrinth,
                    ArtifactProviderQuery::Modrinth(_)
                )
                | (
                    ArtifactProvider::GithubRelease,
                    ArtifactProviderQuery::GithubRelease(_)
                )
                | (ArtifactProvider::Paper, ArtifactProviderQuery::Paper(_))
                | (ArtifactProvider::Hangar, ArtifactProviderQuery::Hangar(_))
        );
        if !matches {
            return Err(ApiError::InvalidRequest("provider/query mismatch"));
        }
        match &self.query {
            ArtifactProviderQuery::Manual(query) => {
                for (value, field, limit) in [
                    (&query.kind, "query.kind", 64),
                    (&query.name, "query.name", 256),
                    (&query.version, "query.version", 256),
                    (&query.source, "query.source", 256),
                    (&query.source_id, "query.source_id", 512),
                    (&query.filename, "query.filename", 512),
                    (&query.compatibility, "query.compatibility", 256),
                    (&query.metadata, "query.metadata", 4096),
                ] {
                    validate_text(value, field, limit)?;
                }
                validate_hash(&query.digest, "query.digest")?;
            }
            ArtifactProviderQuery::DirectUrl(query) => {
                validate_text(&query.url, "query.url", 2048)?;
                if !query.url.starts_with("https://")
                    || query.url[8..].split('/').next().is_none_or(str::is_empty)
                {
                    return Err(ApiError::InvalidRequest("query.url"));
                }
                validate_text(&query.filename, "query.filename", 512)?;
                validate_hash(&query.digest, "query.digest")?;
            }
            ArtifactProviderQuery::Modrinth(query)
            | ArtifactProviderQuery::GithubRelease(query)
            | ArtifactProviderQuery::Paper(query)
            | ArtifactProviderQuery::Hangar(query) => {
                validate_text(&query.project, "query.project", 512)?;
                if let Some(version) = query.version.as_deref() {
                    validate_text(version, "query.version", 256)?;
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactCandidateDto {
    pub id: String,
    pub provider: ArtifactProvider,
    pub kind: String,
    pub name: String,
    pub version: String,
    pub source: String,
    pub source_id: String,
    pub digest: String,
    pub filename: String,
    pub compatibility: String,
    pub metadata: String,
    pub size: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum BackupKind {
    ChangeSnapshot,
    World,
    ServiceConsistent,
    #[serde(rename = "external-database-reference")]
    ExternalDatabaseReference,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SftpChangedPathDto {
    pub path: String,
    pub kind: SftpChangeKind,
    pub before_digest: Option<String>,
    pub after_digest: Option<String>,
    pub classification: FileClassification,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SftpChangeKind {
    Added,
    Modified,
    Removed,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FileClassification {
    Managed,
    MutableConfig,
    Artifact,
    Generated,
    State,
    Secret,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProxyState {
    Preparing,
    Ready,
    Accepting,
    Draining,
    Stopped,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SftpScanSource {
    OutOfBand,
    Provisioning,
    Operator,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SftpScanPayload {
    pub change_session_id: String,
    pub service_id: String,
    pub endpoint_id: String,
    pub execution_binding_id: String,
    pub before_manifest_hash: String,
    pub after_manifest_hash: String,
    pub changed_paths: Vec<SftpChangedPathDto>,
    pub observed_at: u64,
    pub source: SftpScanSource,
}

impl SftpScanPayload {
    pub fn validate(&self) -> Result<(), ApiError> {
        validate_uuid_id(&self.change_session_id, "change_session_id")?;
        validate_uuid_id(&self.service_id, "service_id")?;
        validate_uuid_id(&self.endpoint_id, "endpoint_id")?;
        validate_uuid_id(&self.execution_binding_id, "execution_binding_id")?;
        validate_hash(&self.before_manifest_hash, "before_manifest_hash")?;
        validate_hash(&self.after_manifest_hash, "after_manifest_hash")?;
        if self.changed_paths.len() > 4096 {
            return Err(ApiError::InvalidRequest("changed_paths"));
        }
        for changed in &self.changed_paths {
            crate::security::validate_relative_path(&changed.path)?;
            if let Some(digest) = &changed.before_digest {
                validate_hash(digest, "before_digest")?;
            }
            if let Some(digest) = &changed.after_digest {
                validate_hash(digest, "after_digest")?;
            }
        }
        if self.observed_at == 0 {
            return Err(ApiError::InvalidRequest("observed_at"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SftpEndpointDto {
    pub id: String,
    pub service_id: String,
    pub execution_binding_id: String,
    pub host: String,
    pub port: u16,
    pub root: String,
    pub provisioning_owned: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SftpScanDto {
    pub id: String,
    pub endpoint_id: String,
    pub service_id: String,
    pub execution_binding_id: String,
    pub session_id: String,
    pub before_manifest_hash: String,
    pub after_manifest_hash: String,
    pub changed_paths: Vec<SftpChangedPathDto>,
    pub observed_at: u64,
    pub source: SftpScanSource,
    pub request_hash: String,
}

/// Every mutation variant has a closed JSON shape. A controller receives this
/// enum, never an unvalidated arbitrary JSON value.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", content = "value", rename_all = "kebab-case")]
pub enum MutationPayload {
    ChangePlan(ChangePlanPayload),
    ChangeApprove(ChangeApprovePayload),
    ChangeApply(ChangeApplyPayload),
    ChangeVerify(ChangeVerifyPayload),
    ChangeAccept(ChangeAcceptPayload),
    ChangeRollback(ChangeRollbackPayload),
}

impl MutationPayload {
    pub const fn action(&self) -> MutationAction {
        MutationAction::Change
    }

    pub const fn command(&self) -> MutationCommand {
        match self {
            Self::ChangePlan(_) => MutationCommand::Plan,
            Self::ChangeApprove(_) => MutationCommand::Approve,
            Self::ChangeApply(_) => MutationCommand::Apply,
            Self::ChangeVerify(_) => MutationCommand::Verify,
            Self::ChangeAccept(_) => MutationCommand::Accept,
            Self::ChangeRollback(_) => MutationCommand::Rollback,
        }
    }

    pub fn validate(&self) -> Result<(), ApiError> {
        match self {
            Self::ChangePlan(payload) => {
                validate_uuid_id(&payload.session_id, "session_id")?;
                validate_uuid_id(&payload.service_id, "service_id")?;
                payload.target.validate()?;
                if payload.observed_state_hashes.len() != payload.steps.len() {
                    return Err(ApiError::InvalidRequest(
                        "observed_state_hashes must match steps",
                    ));
                }
                for hash_value in &payload.observed_state_hashes {
                    validate_hash(hash_value, "observed_state_hashes")?;
                }
                for digest in &payload.expected_file_hashes {
                    validate_hash(digest, "expected_file_hashes")?;
                }
                for digest in &payload.expected_artifact_hashes {
                    validate_hash(digest, "expected_artifact_hashes")?;
                }
                if payload.steps.is_empty() || payload.steps.len() > 1024 {
                    return Err(ApiError::InvalidRequest("steps must contain 1..1024 items"));
                }
                for step in &payload.steps {
                    step.action.validate()?;
                }
                if payload.backup_references.len() > 1024 {
                    return Err(ApiError::InvalidRequest("backup_references exceeds limit"));
                }
                for reference in &payload.backup_references {
                    validate_uuid_id(reference, "backup_references")?;
                }
                if payload.rollback_instructions.len() > 1024 {
                    return Err(ApiError::InvalidRequest(
                        "rollback_instructions exceeds limit",
                    ));
                }
                for instruction in &payload.rollback_instructions {
                    validate_text(instruction, "rollback_instructions", 4096)?;
                }
                if payload.expires_at == 0 {
                    return Err(ApiError::InvalidRequest("expires_at"));
                }
            }
            Self::ChangeApprove(payload) => {
                validate_uuid_id(&payload.session_id, "session_id")?;
                validate_uuid_id(&payload.plan_id, "plan_id")?;
                validate_hash(&payload.plan_hash, "plan_hash")?;
            }
            Self::ChangeApply(payload) => {
                validate_uuid_id(&payload.session_id, "session_id")?;
                validate_uuid_id(&payload.plan_id, "plan_id")?;
            }
            Self::ChangeVerify(payload) => {
                validate_uuid_id(&payload.session_id, "session_id")?;
                validate_uuid_id(&payload.operation_id, "operation_id")?;
            }
            Self::ChangeAccept(payload) => {
                validate_uuid_id(&payload.session_id, "session_id")?;
                validate_uuid_id(&payload.operation_id, "operation_id")?;
            }
            Self::ChangeRollback(payload) => {
                validate_uuid_id(&payload.session_id, "session_id")?;
                validate_uuid_id(&payload.operation_id, "operation_id")?;
                validate_text(&payload.reason, "reason", 1024)?;
            }
        }
        Ok(())
    }
}

/// Mutation envelope. `payload` is a tagged, command-specific DTO rather than
/// arbitrary JSON. The route and payload command/action must agree.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MutationRequest {
    pub command: MutationCommand,
    pub action: MutationAction,
    pub request_hash: String,
    pub expires_at: u64,
    pub target_revision: Option<String>,
    pub payload: MutationPayload,
}

impl MutationRequest {
    pub fn validate_for(
        &self,
        resource: &str,
        route_command: MutationCommand,
        route_action: MutationAction,
    ) -> Result<(), ApiError> {
        if self.command != route_command {
            return Err(ApiError::InvalidRequest("command does not match route"));
        }
        if self.action != route_action || self.payload.action() != self.action {
            return Err(ApiError::InvalidRequest("action does not match route"));
        }
        if self.payload.command() != self.command {
            return Err(ApiError::InvalidRequest("payload does not match command"));
        }
        validate_hash(&self.request_hash, "request_hash")?;
        if let Some(revision) = self.target_revision.as_deref() {
            validate_uuid_id(revision, "target_revision")?;
        }
        self.payload.validate()?;
        let encoded = serde_json::to_vec(&self.payload)
            .map_err(|_| ApiError::InvalidRequest("invalid payload"))?;
        if crate::plan_hash(&encoded) != self.request_hash {
            return Err(ApiError::Conflict);
        }
        match (route_action, resource) {
            (MutationAction::Change, "change-sessions") => Ok(()),
            _ if ResourceKind::parse(resource).is_ok() => Err(ApiError::Unsupported),
            _ => Err(ApiError::NotFound),
        }
    }
}

fn validate_text(value: &str, field: &'static str, max: usize) -> Result<(), ApiError> {
    if value.trim().is_empty()
        || value.len() > max
        || value.chars().any(|character| character.is_control())
    {
        Err(ApiError::InvalidRequest(field))
    } else {
        Ok(())
    }
}

fn validate_id(value: &str, field: &'static str) -> Result<(), ApiError> {
    validate_text(value, field, 256)?;
    if value.contains('/')
        || value.contains('\\')
        || value.contains('%')
        || value.chars().any(|character| character.is_whitespace())
    {
        return Err(ApiError::InvalidRequest(field));
    }
    Ok(())
}

fn validate_uuid_id(value: &str, field: &'static str) -> Result<(), ApiError> {
    validate_id(value, field)?;
    Uuid::parse_str(value).map_err(|_| ApiError::InvalidRequest(field))?;
    Ok(())
}

fn validate_hash(value: &str, field: &'static str) -> Result<(), ApiError> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Err(ApiError::InvalidRequest(field))
    } else {
        Ok(())
    }
}

/// Operation returned for a mutation.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct OperationDto {
    pub id: String,
    pub status: String,
    pub plan_hash: String,
    pub request_id: String,
}

/// File metadata returned by browse and diff operations.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct FileEntryDto {
    pub path: String,
    pub size: u64,
    pub digest: String,
    pub classification: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct FileReadDto {
    pub path: String,
    pub content_type: String,
    pub content: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct FileDiffDto {
    pub path: String,
    pub before_digest: Option<String>,
    pub after_digest: Option<String>,
    pub changed: bool,
}

/// A single operation-progress event used by SSE.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct OperationEvent {
    pub operation_id: String,
    pub sequence: u64,
    pub status: String,
    pub message: Option<String>,
    pub progress: Option<u8>,
}

/// Safe download filename. It prevents header injection and path disclosure.
pub fn safe_content_disposition(filename: &str) -> Result<String, ApiError> {
    let name = filename.rsplit(['/', '\\']).next().unwrap_or("");
    if name.is_empty()
        || name.len() > 255
        || name.contains('\0')
        || name.contains('\r')
        || name.contains('\n')
        || name == "."
        || name == ".."
    {
        return Err(ApiError::InvalidRequest("unsafe filename"));
    }
    let clean = name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-') {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    Ok(format!("attachment; filename=\"{clean}\""))
}
