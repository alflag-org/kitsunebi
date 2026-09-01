use crate::{MySqlStorage, StorageError};
use kitsunebi_application::{
    OperationLease as ApplicationOperationLease, RetirementSafety, StepEvidence,
};
use kitsunebi_domain::{
    AccessGrant, AccessPolicy, AccessPrincipal, Artifact, ArtifactSet, AuditEvent, AuditResult,
    AuditScope, AuditSource, Availability, BackupKind, BackupReference, BackupTarget,
    ChangeSession, ChangeSessionState, ClusterRevision, ConfigBaseline, ConfigBaselineEntry,
    EndpointBinding, ExternalEndpoint, FileClassification, GameAPBinding, GameAPBindingTarget,
    GameCluster, LifecycleDecision, MCPlayNetwork, NodeCapabilityObservation, Operation,
    OperationState, Ownership, Permission, PlanDescriptor, PlanTarget, ProcessManager,
    ProxyInstance, ProxyInstanceBinding, ProxyPool, ProxyState, Route, RuntimeProfile, Service,
    ServiceLifecycle, ServiceTombstone, SftpEndpointMetadata, SftpScan, SftpScanSource,
    StagedContentOwnership, StagedContentRef, TcpShieldBackendSet, TrustProfile, World,
    WorldExecutionModel, WorldWriteMode,
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sqlx::{Row, mysql::MySqlRow};
use uuid::Uuid;

fn is_duplicate_key(error: &sqlx::Error) -> bool {
    matches!(
        error,
        sqlx::Error::Database(database) if database.code().as_deref() == Some("1062")
    )
}

pub struct AuditEventRecord {
    pub event_id: Uuid,
    pub occurred_at: String,
    pub event: AuditEvent,
}

pub struct LifecycleDecisionRecord {
    pub id: Uuid,
    pub service_id: kitsunebi_domain::ServiceId,
    pub from_state: String,
    pub to_state: String,
    pub actor: String,
    pub reason: String,
}

pub struct OperationLease {
    pub owner: String,
    pub attempt: u64,
    pub operation: Operation,
}

/// Persisted origin of an actor id.  Actor ids are intentionally opaque to
/// the domain, while storage keeps the trust boundary explicit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActorKind {
    Browser,
    Service,
}

impl ActorKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Browser => "browser",
            Self::Service => "service",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActorIdentity {
    pub actor_id: kitsunebi_domain::ActorId,
    pub kind: ActorKind,
    pub subject: String,
    pub service_id: Option<kitsunebi_domain::ServiceId>,
}

/// Domain resources for which service ownership can be resolved. Resources
/// with more than one route or binding may return more than one service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceKind {
    Network,
    Service,
    Cluster,
    Revision,
    World,
    WorldWriter,
    RuntimeProfile,
    ProxyPool,
    ProxyInstance,
    Route,
    Artifact,
    ArtifactSet,
    ConfigBaseline,
    Endpoint,
    EndpointBinding,
    AccessPolicy,
    AccessPolicyBinding,
    ChangeSession,
    Plan,
    Operation,
    BackupReference,
    LifecycleDecision,
    GameAPBinding,
    AuditEvent,
    SftpEndpoint,
    SftpScan,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
}

fn db(error: sqlx::Error) -> StorageError {
    match &error {
        sqlx::Error::Database(database) => match database.code().as_deref() {
            Some("1062") => StorageError::Conflict {
                entity: "unique constraint",
            },
            Some("1451" | "1452" | "3819") => {
                StorageError::InvalidData("database constraint rejected the value".into())
            }
            _ => StorageError::Database(error),
        },
        _ => StorageError::Database(error),
    }
}

fn invalid(error: impl Into<String>) -> StorageError {
    StorageError::InvalidData(error.into())
}

pub(crate) fn policy_grant_identity_matches(
    kind: &str,
    identity_service: Option<&str>,
    grant_scope: Option<kitsunebi_domain::ServiceId>,
    target_service: kitsunebi_domain::ServiceId,
) -> bool {
    if grant_scope != Some(target_service) {
        return false;
    }
    match kind {
        "browser" => identity_service.is_none(),
        "service" => identity_service == Some(text(target_service.as_uuid()).as_str()),
        _ => false,
    }
}

fn text(id: Uuid) -> String {
    id.hyphenated().to_string()
}

fn uuid(row: &MySqlRow, column: &str) -> Result<Uuid, StorageError> {
    let value: String = row.try_get(column).map_err(db)?;
    Uuid::parse_str(&value).map_err(|error| invalid(format!("{column}: {error}")))
}

fn uuid_opt(row: &MySqlRow, column: &str) -> Result<Option<Uuid>, StorageError> {
    let value: Option<String> = row.try_get(column).map_err(db)?;
    value
        .map(|v| Uuid::parse_str(&v).map_err(|error| invalid(format!("{column}: {error}"))))
        .transpose()
}

fn to_json<T: Serialize>(value: &T) -> Result<Value, StorageError> {
    serde_json::to_value(value).map_err(|error| invalid(error.to_string()))
}

fn json_col<T: DeserializeOwned>(row: &MySqlRow, column: &str) -> Result<T, StorageError> {
    let value: Value = row.try_get(column).map_err(db)?;
    serde_json::from_value(value).map_err(|error| invalid(format!("{column}: {error}")))
}

fn json_string(row: &MySqlRow, column: &str) -> Result<String, StorageError> {
    let value: Value = row.try_get(column).map_err(db)?;
    match value {
        Value::String(value) => Ok(value),
        value => serde_json::to_string(&value).map_err(|error| invalid(error.to_string())),
    }
}

fn id_vec(ids: impl IntoIterator<Item = Uuid>) -> Value {
    Value::Array(ids.into_iter().map(|id| Value::String(text(id))).collect())
}

fn parse_id_vec(value: Value, column: &str) -> Result<Vec<Uuid>, StorageError> {
    let values: Vec<String> =
        serde_json::from_value(value).map_err(|error| invalid(format!("{column}: {error}")))?;
    values
        .into_iter()
        .map(|value| Uuid::parse_str(&value).map_err(|error| invalid(format!("{column}: {error}"))))
        .collect()
}

fn ownership(value: &Ownership) -> &'static str {
    match value {
        Ownership::FirstParty => "first_party",
        Ownership::Hosted => "hosted",
    }
}
fn parse_ownership(value: &str) -> Result<Ownership, StorageError> {
    match value {
        "first_party" => Ok(Ownership::FirstParty),
        "hosted" => Ok(Ownership::Hosted),
        _ => Err(invalid(format!("ownership: {value}"))),
    }
}
fn audience(value: &kitsunebi_domain::Audience) -> &'static str {
    match value {
        kitsunebi_domain::Audience::Public => "public",
        kitsunebi_domain::Audience::Allowlist => "allowlist",
        kitsunebi_domain::Audience::OperatorOnly => "operator_only",
    }
}
fn parse_audience(value: &str) -> Result<kitsunebi_domain::Audience, StorageError> {
    match value {
        "public" => Ok(kitsunebi_domain::Audience::Public),
        "allowlist" => Ok(kitsunebi_domain::Audience::Allowlist),
        "operator_only" => Ok(kitsunebi_domain::Audience::OperatorOnly),
        _ => Err(invalid(format!("audience: {value}"))),
    }
}
fn operator_model(value: &kitsunebi_domain::OperatorModel) -> &'static str {
    match value {
        kitsunebi_domain::OperatorModel::Central => "central",
        kitsunebi_domain::OperatorModel::Delegated => "delegated",
    }
}
fn parse_operator_model(value: &str) -> Result<kitsunebi_domain::OperatorModel, StorageError> {
    match value {
        "central" => Ok(kitsunebi_domain::OperatorModel::Central),
        "delegated" => Ok(kitsunebi_domain::OperatorModel::Delegated),
        _ => Err(invalid(format!("operator_model: {value}"))),
    }
}
fn trust_profile(value: &TrustProfile) -> &'static str {
    match value {
        TrustProfile::Trusted => "trusted",
        TrustProfile::Constrained => "constrained",
        TrustProfile::Untrusted => "untrusted",
    }
}
fn parse_trust_profile(value: &str) -> Result<TrustProfile, StorageError> {
    match value {
        "trusted" => Ok(TrustProfile::Trusted),
        "constrained" => Ok(TrustProfile::Constrained),
        "untrusted" => Ok(TrustProfile::Untrusted),
        _ => Err(invalid(format!("trust_profile: {value}"))),
    }
}
fn lifecycle(value: &ServiceLifecycle) -> &'static str {
    match value {
        ServiceLifecycle::Planned => "planned",
        ServiceLifecycle::Testing => "testing",
        ServiceLifecycle::Active => "active",
        ServiceLifecycle::Maintenance => "maintenance",
        ServiceLifecycle::Sunsetting => "sunsetting",
        ServiceLifecycle::Archived => "archived",
    }
}
fn parse_lifecycle(value: &str) -> Result<ServiceLifecycle, StorageError> {
    match value {
        "planned" => Ok(ServiceLifecycle::Planned),
        "testing" => Ok(ServiceLifecycle::Testing),
        "active" => Ok(ServiceLifecycle::Active),
        "maintenance" => Ok(ServiceLifecycle::Maintenance),
        "sunsetting" => Ok(ServiceLifecycle::Sunsetting),
        "archived" => Ok(ServiceLifecycle::Archived),
        _ => Err(invalid(format!("lifecycle: {value}"))),
    }
}
fn availability(value: &Availability) -> &'static str {
    match value {
        Availability::AlwaysOn => "always_on",
        Availability::Scheduled => "scheduled",
        Availability::OnDemand => "on_demand",
        Availability::Disabled => "disabled",
    }
}
fn parse_availability(value: &str) -> Result<Availability, StorageError> {
    match value {
        "always_on" => Ok(Availability::AlwaysOn),
        "scheduled" => Ok(Availability::Scheduled),
        "on_demand" => Ok(Availability::OnDemand),
        "disabled" => Ok(Availability::Disabled),
        _ => Err(invalid(format!("availability: {value}"))),
    }
}
fn world_mode(value: &WorldWriteMode) -> &'static str {
    match value {
        WorldWriteMode::SingleWriter => "single_writer",
        WorldWriteMode::ExternallyCoordinated => "externally_coordinated",
    }
}
fn parse_world_mode(value: &str) -> Result<WorldWriteMode, StorageError> {
    match value {
        "single_writer" => Ok(WorldWriteMode::SingleWriter),
        "externally_coordinated" => Ok(WorldWriteMode::ExternallyCoordinated),
        _ => Err(invalid(format!("write_mode: {value}"))),
    }
}
fn execution_model(value: &WorldExecutionModel) -> &'static str {
    match value {
        WorldExecutionModel::SingleProcess => "single_process",
        WorldExecutionModel::RegionParallel => "region_parallel",
        WorldExecutionModel::PartitionedWorld => "partitioned_world",
        WorldExecutionModel::ExternallyDistributed => "externally_distributed",
    }
}
fn parse_execution_model(value: &str) -> Result<WorldExecutionModel, StorageError> {
    match value {
        "single_process" => Ok(WorldExecutionModel::SingleProcess),
        "region_parallel" => Ok(WorldExecutionModel::RegionParallel),
        "partitioned_world" => Ok(WorldExecutionModel::PartitionedWorld),
        "externally_distributed" => Ok(WorldExecutionModel::ExternallyDistributed),
        _ => Err(invalid(format!("execution_model: {value}"))),
    }
}

fn backup_kind(value: BackupKind) -> &'static str {
    value.as_str()
}

fn parse_backup_kind(value: &str) -> Result<BackupKind, StorageError> {
    BackupKind::parse(value).map_err(StorageError::Domain)
}

fn process_manager(value: &ProcessManager) -> &'static str {
    value.as_str()
}

fn parse_process_manager(value: &str) -> Result<ProcessManager, StorageError> {
    ProcessManager::parse(value).map_err(StorageError::Domain)
}

fn sftp_source(value: SftpScanSource) -> &'static str {
    value.as_str()
}

fn parse_sftp_source(value: &str) -> Result<SftpScanSource, StorageError> {
    match value {
        "out_of_band" => Ok(SftpScanSource::OutOfBand),
        "provisioning" => Ok(SftpScanSource::Provisioning),
        "operator" => Ok(SftpScanSource::Operator),
        _ => Err(invalid(format!("sftp scan source: {value}"))),
    }
}
fn proxy_state(value: &ProxyState) -> &'static str {
    match value {
        ProxyState::Preparing => "preparing",
        ProxyState::Ready => "ready",
        ProxyState::Accepting => "accepting",
        ProxyState::Draining => "draining",
        ProxyState::Stopped => "stopped",
        ProxyState::Failed => "failed",
    }
}
fn parse_proxy_state(value: &str) -> Result<ProxyState, StorageError> {
    match value {
        "preparing" => Ok(ProxyState::Preparing),
        "ready" => Ok(ProxyState::Ready),
        "accepting" => Ok(ProxyState::Accepting),
        "draining" => Ok(ProxyState::Draining),
        "stopped" => Ok(ProxyState::Stopped),
        "failed" => Ok(ProxyState::Failed),
        _ => Err(invalid(format!("proxy state: {value}"))),
    }
}
fn change_state(value: &ChangeSessionState) -> &'static str {
    match value {
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
}
fn parse_change_state(value: &str) -> Result<ChangeSessionState, StorageError> {
    match value {
        "open" => Ok(ChangeSessionState::Open),
        "editing" => Ok(ChangeSessionState::Editing),
        "ready" => Ok(ChangeSessionState::Ready),
        "applying" => Ok(ChangeSessionState::Applying),
        "verifying" => Ok(ChangeSessionState::Verifying),
        "accepted" => Ok(ChangeSessionState::Accepted),
        "rolled_back" => Ok(ChangeSessionState::RolledBack),
        "aborted" => Ok(ChangeSessionState::Aborted),
        "conflicted" => Ok(ChangeSessionState::Conflicted),
        _ => Err(invalid(format!("change state: {value}"))),
    }
}
fn operation_state(value: &OperationState) -> &'static str {
    match value {
        OperationState::Planned => "planned",
        OperationState::Applying => "applying",
        OperationState::Verifying => "verifying",
        OperationState::Verified => "verified",
        OperationState::Accepted => "accepted",
        OperationState::RolledBack => "rolled_back",
        OperationState::Failed => "failed",
    }
}

fn operation_payload_with_plan(mut payload: Value, plan: kitsunebi_domain::PlanId) -> Value {
    if let Value::Object(fields) = &mut payload {
        fields.insert("plan_id".into(), Value::String(text(plan.as_uuid())));
    }
    payload
}

fn parse_operation_state(value: &str) -> Result<OperationState, StorageError> {
    match value {
        "planned" => Ok(OperationState::Planned),
        "applying" => Ok(OperationState::Applying),
        "verifying" => Ok(OperationState::Verifying),
        "verified" => Ok(OperationState::Verified),
        "accepted" => Ok(OperationState::Accepted),
        "rolled_back" => Ok(OperationState::RolledBack),
        "failed" => Ok(OperationState::Failed),
        _ => Err(invalid(format!("operation state: {value}"))),
    }
}

fn session_state_for_operation(state: &OperationState) -> Option<&'static str> {
    match state {
        OperationState::Planned => None,
        OperationState::Applying => Some("applying"),
        OperationState::Verifying => Some("verifying"),
        // Verification is an operation-only state. The owning session remains
        // in `verifying` until the separate acceptance transition.
        OperationState::Verified => None,
        OperationState::Accepted => Some("accepted"),
        OperationState::RolledBack => Some("rolled_back"),
        OperationState::Failed => Some("aborted"),
    }
}

async fn sync_session_state(
    tx: &mut sqlx::Transaction<'static, sqlx::MySql>,
    session_id: &str,
    operation_state: &OperationState,
) -> Result<(), StorageError> {
    let Some(state) = session_state_for_operation(operation_state) else {
        return Ok(());
    };
    let expected = match operation_state {
        OperationState::Applying => ["ready", "ready"],
        OperationState::Verifying => ["applying", "applying"],
        OperationState::Verified => ["verifying", "verifying"],
        OperationState::Accepted => ["verifying", "verifying"],
        OperationState::RolledBack => ["applying", "verifying"],
        OperationState::Failed => ["applying", "verifying"],
        OperationState::Planned => unreachable!("planned state is not synchronized"),
    };
    let result = sqlx::query(
        "UPDATE change_sessions SET state = ?, version = version + 1, updated_at = CURRENT_TIMESTAMP(6) WHERE id = ? AND state IN (?, ?)",
    )
    .bind(state)
    .bind(session_id)
    .bind(expected[0])
    .bind(expected[1])
    .execute(&mut **tx)
    .await
    .map_err(db)?;
    if result.rows_affected() == 0 {
        return Err(StorageError::Conflict {
            entity: "change session state",
        });
    }
    Ok(())
}

fn row_network(row: &MySqlRow) -> Result<MCPlayNetwork, StorageError> {
    Ok(MCPlayNetwork {
        id: kitsunebi_domain::NetworkId::from_uuid(uuid(row, "id")?),
        key: row.try_get("key").map_err(db)?,
        display_name: row.try_get("display_name").map_err(db)?,
        metadata: json_string(row, "metadata")?,
    })
}

fn row_service(row: &MySqlRow) -> Result<Service, StorageError> {
    Ok(Service {
        id: kitsunebi_domain::ServiceId::from_uuid(uuid(row, "id")?),
        key: row.try_get("key").map_err(db)?,
        display_name: row.try_get("display_name").map_err(db)?,
        ownership: parse_ownership(&row.try_get::<String, _>("ownership").map_err(db)?)?,
        audience: parse_audience(&row.try_get::<String, _>("audience").map_err(db)?)?,
        operator_model: parse_operator_model(
            &row.try_get::<String, _>("operator_model").map_err(db)?,
        )?,
        trust_profile: parse_trust_profile(
            &row.try_get::<String, _>("trust_profile").map_err(db)?,
        )?,
        lifecycle: parse_lifecycle(&row.try_get::<String, _>("lifecycle").map_err(db)?)?,
        availability: parse_availability(&row.try_get::<String, _>("availability").map_err(db)?)?,
        current_cluster: uuid_opt(row, "current_cluster_id")?
            .map(kitsunebi_domain::ClusterId::from_uuid),
        access_policy: uuid_opt(row, "access_policy_id")?
            .map(kitsunebi_domain::PolicyId::from_uuid),
        backup_policy: {
            let value: Value = row.try_get("backup_policy").map_err(db)?;
            if value.is_null() {
                None
            } else if let Value::String(value) = value {
                Some(value)
            } else {
                Some(serde_json::to_string(&value).map_err(|error| invalid(error.to_string()))?)
            }
        },
        metadata: json_string(row, "metadata")?,
    })
}

fn row_cluster(row: &MySqlRow) -> Result<GameCluster, StorageError> {
    Ok(GameCluster {
        id: kitsunebi_domain::ClusterId::from_uuid(uuid(row, "id")?),
        service_id: kitsunebi_domain::ServiceId::from_uuid(uuid(row, "service_id")?),
        key: row.try_get("key").map_err(db)?,
        current_revision: uuid_opt(row, "current_revision_id")?
            .map(kitsunebi_domain::RevisionId::from_uuid),
    })
}

fn row_revision(row: &MySqlRow) -> Result<ClusterRevision, StorageError> {
    let world_bindings =
        parse_id_vec(row.try_get("world_bindings").map_err(db)?, "world_bindings")?
            .into_iter()
            .map(kitsunebi_domain::WorldId::from_uuid)
            .collect();
    let endpoint_bindings = parse_id_vec(
        row.try_get("endpoint_bindings").map_err(db)?,
        "endpoint_bindings",
    )?
    .into_iter()
    .map(kitsunebi_domain::BindingId::from_uuid)
    .collect();
    Ok(ClusterRevision {
        id: kitsunebi_domain::RevisionId::from_uuid(uuid(row, "id")?),
        number: row.try_get::<u64, _>("revision_number").map_err(db)?,
        runtime_profile: kitsunebi_domain::RuntimeProfileId::from_uuid(uuid(
            row,
            "runtime_profile_id",
        )?),
        minecraft_version: row.try_get("minecraft_version").map_err(db)?,
        java_requirement: row.try_get("java_requirement").map_err(db)?,
        artifact_set: kitsunebi_domain::ArtifactSetId::from_uuid(uuid(row, "artifact_set_id")?),
        config_baseline: kitsunebi_domain::ConfigBaselineId::from_uuid(uuid(
            row,
            "config_baseline_id",
        )?),
        world_bindings,
        endpoint_bindings,
        placement_requirements: json_col(row, "placement_requirements")?,
        resource_requirements: json_string(row, "resource_requirements")?,
        health_checks: json_col(row, "health_checks")?,
        startup_parameters: json_col(row, "startup_parameters")?,
    })
}

fn row_runtime(row: &MySqlRow) -> Result<RuntimeProfile, StorageError> {
    Ok(RuntimeProfile {
        id: kitsunebi_domain::RuntimeProfileId::from_uuid(uuid(row, "id")?),
        family: row.try_get("family").map_err(db)?,
        minecraft_version: row.try_get("minecraft_version").map_err(db)?,
        runtime_version: row.try_get("runtime_version").map_err(db)?,
        artifact_source: row.try_get("artifact_source").map_err(db)?,
        artifact_digest: row.try_get("artifact_digest").map_err(db)?,
        java_requirement: row.try_get("java_requirement").map_err(db)?,
        startup_capability: row.try_get("startup_capability").map_err(db)?,
        console_capability: row.try_get("console_capability").map_err(db)?,
        health_capability: row.try_get("health_capability").map_err(db)?,
        world_execution_capability: parse_execution_model(
            &row.try_get::<String, _>("world_execution_capability")
                .map_err(db)?,
        )?,
        metadata: json_string(row, "metadata")?,
    })
}

fn row_world(row: &MySqlRow, writers: Vec<Uuid>) -> Result<World, StorageError> {
    Ok(World {
        id: kitsunebi_domain::WorldId::from_uuid(uuid(row, "id")?),
        key: row.try_get("key").map_err(db)?,
        display_name: row.try_get("display_name").map_err(db)?,
        persistence: row.try_get("persistence").map_err(db)?,
        storage_ref: row.try_get("storage_ref").map_err(db)?,
        write_mode: parse_world_mode(&row.try_get::<String, _>("write_mode").map_err(db)?)?,
        execution_model: parse_execution_model(
            &row.try_get::<String, _>("execution_model").map_err(db)?,
        )?,
        current_writers: writers
            .into_iter()
            .map(kitsunebi_domain::ClusterId::from_uuid)
            .collect(),
        backup_policy: {
            let value: Value = row.try_get("backup_policy").map_err(db)?;
            if value.is_null() {
                None
            } else if let Value::String(value) = value {
                Some(value)
            } else {
                Some(serde_json::to_string(&value).map_err(|error| invalid(error.to_string()))?)
            }
        },
        metadata: json_string(row, "metadata")?,
    })
}

fn row_proxy_pool(row: &MySqlRow, instances: Vec<Uuid>) -> Result<ProxyPool, StorageError> {
    Ok(ProxyPool {
        id: kitsunebi_domain::ProxyPoolId::from_uuid(uuid(row, "id")?),
        key: row.try_get("key").map_err(db)?,
        instances: instances
            .into_iter()
            .map(kitsunebi_domain::ProxyInstanceId::from_uuid)
            .collect(),
    })
}

fn row_proxy_instance(row: &MySqlRow) -> Result<ProxyInstance, StorageError> {
    Ok(ProxyInstance {
        id: kitsunebi_domain::ProxyInstanceId::from_uuid(uuid(row, "id")?),
        pool_id: kitsunebi_domain::ProxyPoolId::from_uuid(uuid(row, "pool_id")?),
        key: row.try_get("key").map_err(db)?,
        state: parse_proxy_state(&row.try_get::<String, _>("state").map_err(db)?)?,
    })
}

fn row_tcp_shield_backend_set(row: &MySqlRow) -> Result<TcpShieldBackendSet, StorageError> {
    let mut backend_set = TcpShieldBackendSet::new(
        kitsunebi_domain::ProxyPoolId::from_uuid(uuid(row, "pool_id")?),
        row.try_get("provider_network_id").map_err(db)?,
        &row.try_get::<String, _>("backend_set_id").map_err(db)?,
    )?;
    backend_set.domain_network_id =
        uuid_opt(row, "domain_network_id")?.map(kitsunebi_domain::NetworkId::from_uuid);
    Ok(backend_set)
}

fn row_proxy_instance_binding(row: &MySqlRow) -> Result<ProxyInstanceBinding, StorageError> {
    ProxyInstanceBinding::new(
        kitsunebi_domain::ProxyInstanceId::from_uuid(uuid(row, "instance_id")?),
        kitsunebi_domain::BindingId::from_uuid(uuid(row, "gameap_binding_id")?),
        &row.try_get::<String, _>("backend_address").map_err(db)?,
    )
    .map_err(StorageError::Domain)
}

fn row_endpoint(row: &MySqlRow) -> Result<ExternalEndpoint, StorageError> {
    Ok(ExternalEndpoint {
        id: kitsunebi_domain::EndpointId::from_uuid(uuid(row, "id")?),
        key: row.try_get("key").map_err(db)?,
        kind: row.try_get("kind").map_err(db)?,
        logical_hostname: row.try_get("logical_hostname").map_err(db)?,
        port: row.try_get("port").map_err(db)?,
        role: row.try_get("role").map_err(db)?,
        metadata: json_string(row, "metadata")?,
    })
}

fn row_binding(row: &MySqlRow) -> Result<EndpointBinding, StorageError> {
    Ok(EndpointBinding {
        id: kitsunebi_domain::BindingId::from_uuid(uuid(row, "id")?),
        endpoint_id: kitsunebi_domain::EndpointId::from_uuid(uuid(row, "endpoint_id")?),
        cluster_id: kitsunebi_domain::ClusterId::from_uuid(uuid(row, "cluster_id")?),
        revision_id: kitsunebi_domain::RevisionId::from_uuid(uuid(row, "revision_id")?),
        binding_key: row.try_get("binding_key").map_err(db)?,
        metadata: json_string(row, "metadata")?,
    })
}

pub(crate) fn row_change_session(row: &MySqlRow) -> Result<ChangeSession, StorageError> {
    Ok(ChangeSession {
        id: kitsunebi_domain::ChangeSessionId::from_uuid(uuid(row, "id")?),
        target_cluster: kitsunebi_domain::ClusterId::from_uuid(
            Uuid::parse_str(
                row.try_get::<Value, _>("target")
                    .map_err(db)?
                    .get("cluster_id")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid("change target.cluster_id"))?,
            )
            .map_err(|error| invalid(error.to_string()))?,
        ),
        state: parse_change_state(&row.try_get::<String, _>("state").map_err(db)?)?,
        version: row.try_get("version").map_err(db)?,
    })
}

fn row_sftp_endpoint(row: &MySqlRow) -> Result<SftpEndpointMetadata, StorageError> {
    let endpoint = SftpEndpointMetadata {
        id: kitsunebi_domain::SftpEndpointId::from_uuid(uuid(row, "id")?),
        service_id: kitsunebi_domain::ServiceId::from_uuid(uuid(row, "service_id")?),
        execution_binding_id: kitsunebi_domain::BindingId::from_uuid(uuid(
            row,
            "execution_binding_id",
        )?),
        host: row.try_get("host").map_err(db)?,
        port: row.try_get("port").map_err(db)?,
        root: row.try_get("root").map_err(db)?,
        provisioning_owned: row.try_get("provisioning_owned").map_err(db)?,
    };
    endpoint.validate().map_err(StorageError::Domain)?;
    Ok(endpoint)
}

fn row_sftp_scan(row: &MySqlRow) -> Result<SftpScan, StorageError> {
    let scan = SftpScan {
        id: kitsunebi_domain::SftpScanId::from_uuid(uuid(row, "id")?),
        endpoint_id: kitsunebi_domain::SftpEndpointId::from_uuid(uuid(row, "endpoint_id")?),
        service_id: kitsunebi_domain::ServiceId::from_uuid(uuid(row, "service_id")?),
        execution_binding_id: kitsunebi_domain::BindingId::from_uuid(uuid(
            row,
            "execution_binding_id",
        )?),
        session_id: kitsunebi_domain::ChangeSessionId::from_uuid(uuid(row, "change_session_id")?),
        before_manifest_hash: row.try_get("before_manifest_hash").map_err(db)?,
        after_manifest_hash: row.try_get("after_manifest_hash").map_err(db)?,
        changed_paths: json_col(row, "changed_paths")?,
        observed_at: row.try_get("observed_at").map_err(db)?,
        source: parse_sftp_source(&row.try_get::<String, _>("source").map_err(db)?)?,
        idempotency_key: row.try_get("idempotency_key").map_err(db)?,
        request_hash: row.try_get("request_hash").map_err(db)?,
    };
    scan.validate().map_err(StorageError::Domain)?;
    Ok(scan)
}

fn row_node_capability(row: &MySqlRow) -> Result<NodeCapabilityObservation, StorageError> {
    let observation = NodeCapabilityObservation {
        id: kitsunebi_domain::NodeCapabilityId::from_uuid(uuid(row, "id")?),
        provider_node_ref: row.try_get("provider_node_ref").map_err(db)?,
        process_manager: parse_process_manager(
            &row.try_get::<String, _>("process_manager").map_err(db)?,
        )?,
        version: row.try_get("manager_version").map_err(db)?,
        capabilities: json_col(row, "capabilities")?,
        evidence_hash: row.try_get("evidence_hash").map_err(db)?,
        observed_at: row.try_get("observed_at").map_err(db)?,
    };
    observation.validate().map_err(StorageError::Domain)?;
    Ok(observation)
}

fn row_operation(row: &MySqlRow) -> Result<Operation, StorageError> {
    Ok(Operation {
        id: kitsunebi_domain::OperationId::from_uuid(uuid(row, "id")?),
        plan_id: kitsunebi_domain::PlanId::from_uuid(uuid(row, "plan_id")?),
        session_id: kitsunebi_domain::ChangeSessionId::from_uuid(uuid(row, "change_session_id")?),
        state: parse_operation_state(&row.try_get::<String, _>("state").map_err(db)?)?,
    })
}
pub(crate) fn row_operation_public(row: &MySqlRow) -> Result<Operation, StorageError> {
    row_operation(row)
}

fn row_backup(row: &MySqlRow) -> Result<BackupReference, StorageError> {
    let backup = BackupReference {
        id: kitsunebi_domain::BackupReferenceId::from_uuid(uuid(row, "id")?),
        session_id: kitsunebi_domain::ChangeSessionId::from_uuid(uuid(row, "change_session_id")?),
        kind: parse_backup_kind(&row.try_get::<String, _>("kind").map_err(db)?)?,
        target: json_col::<BackupTarget>(row, "target")?,
        provider: row.try_get("provider").map_err(db)?,
        provider_reference: row.try_get("reference").map_err(db)?,
        manifest_digest: row.try_get("manifest_digest").map_err(db)?,
        verified_at: row.try_get("verified_at").map_err(db)?,
        required: row.try_get("required").map_err(db)?,
    };
    backup.validate().map_err(StorageError::Domain)?;
    Ok(backup)
}

fn row_artifact(row: &MySqlRow) -> Result<Artifact, StorageError> {
    Ok(Artifact {
        id: kitsunebi_domain::ArtifactId::from_uuid(uuid(row, "id")?),
        kind: row.try_get("kind").map_err(db)?,
        name: row.try_get("name").map_err(db)?,
        version: row.try_get("artifact_version").map_err(db)?,
        source: row.try_get("source").map_err(db)?,
        source_id: row.try_get("source_id").map_err(db)?,
        digest: row.try_get("digest").map_err(db)?,
        filename: row.try_get("filename").map_err(db)?,
        compatibility: json_string(row, "compatibility")?,
        metadata: json_string(row, "metadata")?,
    })
}

fn row_artifact_set(row: &MySqlRow, artifacts: Vec<Uuid>) -> Result<ArtifactSet, StorageError> {
    Ok(ArtifactSet {
        id: kitsunebi_domain::ArtifactSetId::from_uuid(uuid(row, "id")?),
        artifacts: artifacts
            .into_iter()
            .map(kitsunebi_domain::ArtifactId::from_uuid)
            .collect(),
    })
}

fn row_config_baseline(row: &MySqlRow) -> Result<ConfigBaseline, StorageError> {
    let manifest: Value = row.try_get("manifest").map_err(db)?;
    let baseline = ConfigBaseline {
        id: kitsunebi_domain::ConfigBaselineId::from_uuid(uuid(row, "id")?),
        digest: manifest
            .get("digest")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("config baseline manifest digest"))?
            .to_owned(),
        files: manifest
            .get("files")
            .cloned()
            .ok_or_else(|| invalid("config baseline manifest files"))
            .and_then(|value| {
                serde_json::from_value::<Vec<ConfigBaselineEntry>>(value)
                    .map_err(|error| invalid(error.to_string()))
            })?,
    };
    let stored_digest: String = row.try_get("manifest_digest").map_err(db)?;
    if baseline.digest != stored_digest {
        return Err(invalid("config baseline digest column mismatch"));
    }
    baseline.validate().map_err(StorageError::Domain)?;
    Ok(baseline)
}

fn row_policy(row: &MySqlRow) -> Result<AccessPolicy, StorageError> {
    Ok(AccessPolicy {
        id: kitsunebi_domain::PolicyId::from_uuid(uuid(row, "id")?),
        grants: json_col(row, "policy")?,
    })
}

pub(crate) fn row_plan(row: &MySqlRow) -> Result<PlanDescriptor, StorageError> {
    let backup: kitsunebi_domain::BackupRequirements = json_col(row, "backup_requirements")?;
    let plan = PlanDescriptor {
        id: kitsunebi_domain::PlanId::from_uuid(uuid(row, "id")?),
        actor: kitsunebi_domain::ActorId::from_uuid(uuid_from_value(
            row.try_get::<String, _>("actor").map_err(db)?,
            "actor",
        )?),
        target: json_col::<PlanTarget>(row, "target")?,
        domain_revision: row.try_get("domain_revision").map_err(db)?,
        observed_state_hashes: json_col(row, "observed_execution_state")?,
        expected_file_hashes: json_col(row, "expected_file_hashes")?,
        expected_artifact_hashes: json_col(row, "expected_artifact_hashes")?,
        steps: json_col(row, "steps")?,
        backup_requirements: backup,
        rollback_instructions: json_col(row, "rollback_instructions")?,
        expiry: row.try_get("expires_at").map_err(db)?,
        plan_hash: row.try_get("plan_hash").map_err(db)?,
    };
    plan.validate().map_err(StorageError::Domain)?;
    Ok(plan)
}

fn uuid_from_value(value: String, column: &str) -> Result<Uuid, StorageError> {
    Uuid::parse_str(&value).map_err(|error| invalid(format!("{column}: {error}")))
}

pub(crate) fn classification(value: &FileClassification) -> &'static str {
    match value {
        FileClassification::Managed => "managed",
        FileClassification::MutableConfig => "mutable_config",
        FileClassification::Artifact => "artifact",
        FileClassification::Generated => "generated",
        FileClassification::State => "state",
        FileClassification::Secret => "secret",
        FileClassification::Unknown => "unknown",
    }
}

pub(crate) fn safe_evidence(event: &AuditEvent) -> Result<Value, StorageError> {
    if matches!(event.classification, FileClassification::Secret) {
        // The storage layer is a second line of defence: callers may pass a
        // command or content preview, but a secret-classified event persists
        // only the digest and byte count needed to audit the access.
        let safe = event
            .evidence
            .iter()
            .filter_map(|entry| {
                let (key, value) = entry.split_once('=')?;
                match key {
                    "digest"
                        if value.len() == 64
                            && value.bytes().all(|byte| byte.is_ascii_hexdigit()) =>
                    {
                        Some(format!("digest={}", value.to_ascii_lowercase()))
                    }
                    "bytes" => value
                        .parse::<u64>()
                        .ok()
                        .map(|bytes| format!("bytes={bytes}")),
                    _ => None,
                }
            })
            .collect::<Vec<_>>();
        Ok(json!(safe))
    } else {
        to_json(&event.evidence)
    }
}
fn parse_classification(value: &str) -> Result<FileClassification, StorageError> {
    match value {
        "managed" => Ok(FileClassification::Managed),
        "mutable_config" => Ok(FileClassification::MutableConfig),
        "artifact" => Ok(FileClassification::Artifact),
        "generated" => Ok(FileClassification::Generated),
        "state" => Ok(FileClassification::State),
        "secret" => Ok(FileClassification::Secret),
        "unknown" => Ok(FileClassification::Unknown),
        _ => Err(invalid(format!("classification: {value}"))),
    }
}

fn row_staged_content(row: &MySqlRow) -> Result<StagedContentOwnership, StorageError> {
    let ownership = StagedContentOwnership {
        id: kitsunebi_domain::StagedContentId::from_uuid(uuid(row, "id")?),
        session_id: kitsunebi_domain::ChangeSessionId::from_uuid(uuid(row, "change_session_id")?),
        actor: kitsunebi_domain::ActorId::from_uuid(uuid_from_value(
            row.try_get::<String, _>("actor").map_err(db)?,
            "actor",
        )?),
        content: StagedContentRef::new(
            &row.try_get::<String, _>("digest").map_err(db)?,
            row.try_get::<u64, _>("size_bytes").map_err(db)?,
        )?,
        classification: parse_classification(
            &row.try_get::<String, _>("classification").map_err(db)?,
        )?,
        idempotency_key: row.try_get("idempotency_key").map_err(db)?,
        request_hash: row.try_get("request_hash").map_err(db)?,
        expires_at: row.try_get("expires_at").map_err(db)?,
    };
    ownership.validate().map_err(StorageError::Domain)?;
    Ok(ownership)
}

pub(crate) fn audit_source(value: &str) -> Result<AuditSource, StorageError> {
    match value {
        "application" => Ok(AuditSource::Application),
        "api" => Ok(AuditSource::Api),
        "cli" => Ok(AuditSource::Cli),
        "system" => Ok(AuditSource::System),
        _ => Err(invalid(format!("audit source: {value}"))),
    }
}

pub(crate) fn audit_result(value: &str) -> Result<AuditResult, StorageError> {
    match value {
        "accepted" => Ok(AuditResult::Accepted),
        "success" => Ok(AuditResult::Success),
        "failure" => Ok(AuditResult::Failure),
        "rejected" => Ok(AuditResult::Rejected),
        _ => Err(invalid(format!("audit result: {value}"))),
    }
}

fn row_audit(row: &MySqlRow) -> Result<AuditEventRecord, StorageError> {
    let evidence: Vec<String> = json_col(row, "evidence")?;
    let scope = AuditScope {
        service_id: kitsunebi_domain::ServiceId::from_uuid(uuid(row, "service_id")?),
        cluster_id: uuid_opt(row, "cluster_id")?.map(kitsunebi_domain::ClusterId::from_uuid),
        world_id: uuid_opt(row, "world_id")?.map(kitsunebi_domain::WorldId::from_uuid),
        execution_unit_ref: row.try_get("execution_unit_ref").map_err(db)?,
        operation_id: uuid_opt(row, "operation_id")?.map(kitsunebi_domain::OperationId::from_uuid),
    };
    let event = AuditEvent {
        actor: kitsunebi_domain::ActorId::from_uuid(uuid_from_value(
            row.try_get("actor").map_err(db)?,
            "actor",
        )?),
        action: row.try_get("action").map_err(db)?,
        target: row.try_get("target").map_err(db)?,
        classification: parse_classification(
            &row.try_get::<String, _>("classification").map_err(db)?,
        )?,
        scope,
        source: audit_source(&row.try_get::<String, _>("source").map_err(db)?)?,
        result: audit_result(&row.try_get::<String, _>("result").map_err(db)?)?,
        before_revision: row.try_get("before_revision").map_err(db)?,
        after_revision: row.try_get("after_revision").map_err(db)?,
        plan_hash: row.try_get("plan_hash").map_err(db)?,
        request_id: row.try_get("request_id").map_err(db)?,
        evidence,
    };
    event.validate().map_err(StorageError::Domain)?;
    Ok(AuditEventRecord {
        event_id: uuid(row, "event_id")?,
        occurred_at: row.try_get("occurred_at").map_err(db)?,
        event,
    })
}

fn row_gameap(row: &MySqlRow) -> Result<GameAPBinding, StorageError> {
    let service_id: Option<String> = row.try_get("service_id").map_err(db)?;
    let cluster_id: Option<String> = row.try_get("cluster_id").map_err(db)?;
    let execution_unit_target: Option<String> = row.try_get("execution_unit_target").map_err(db)?;
    let world_id: Option<String> = row.try_get("world_id").map_err(db)?;
    let proxy_instance_id: Option<String> = row.try_get("proxy_instance_id").map_err(db)?;
    let target = match (
        service_id,
        cluster_id,
        execution_unit_target,
        world_id,
        proxy_instance_id,
    ) {
        (Some(id), None, None, None, None) => {
            GameAPBindingTarget::Service(kitsunebi_domain::ServiceId::from_uuid(
                Uuid::parse_str(&id).map_err(|error| invalid(format!("service_id: {error}")))?,
            ))
        }
        (None, Some(id), None, None, None) => {
            GameAPBindingTarget::Cluster(kitsunebi_domain::ClusterId::from_uuid(
                Uuid::parse_str(&id).map_err(|error| invalid(format!("cluster_id: {error}")))?,
            ))
        }
        (None, None, Some(id), None, None) => GameAPBindingTarget::ExecutionUnit(id),
        (None, None, None, Some(id), None) => {
            GameAPBindingTarget::World(kitsunebi_domain::WorldId::from_uuid(
                Uuid::parse_str(&id).map_err(|error| invalid(format!("world_id: {error}")))?,
            ))
        }
        (None, None, None, None, Some(id)) => {
            GameAPBindingTarget::ProxyInstance(kitsunebi_domain::ProxyInstanceId::from_uuid(
                Uuid::parse_str(&id)
                    .map_err(|error| invalid(format!("proxy_instance_id: {error}")))?,
            ))
        }
        _ => return Err(invalid("gameap binding target must be exactly one")),
    };
    Ok(GameAPBinding {
        execution_unit_id: row.try_get("execution_unit_ref").map_err(db)?,
        node_id: row.try_get("node_id").map_err(db)?,
        target,
    })
}

type BindingTargetColumns = (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

fn binding_target_columns(target: &GameAPBindingTarget) -> BindingTargetColumns {
    match target {
        GameAPBindingTarget::Service(id) => (Some(text(id.as_uuid())), None, None, None, None),
        GameAPBindingTarget::Cluster(id) => (None, Some(text(id.as_uuid())), None, None, None),
        GameAPBindingTarget::ExecutionUnit(id) => (None, None, Some(id.clone()), None, None),
        GameAPBindingTarget::World(id) => (None, None, None, Some(text(id.as_uuid())), None),
        GameAPBindingTarget::ProxyInstance(id) => {
            (None, None, None, None, Some(text(id.as_uuid())))
        }
    }
}

fn page_limit(limit: u32) -> usize {
    usize::try_from(limit.clamp(1, 100)).unwrap_or(100)
}

fn page_cursor(cursor: Option<&str>) -> Result<String, StorageError> {
    match cursor {
        Some(value) => Ok(text(
            Uuid::parse_str(value).map_err(|error| invalid(format!("cursor: {error}")))?,
        )),
        None => Ok(text(Uuid::nil())),
    }
}

fn trim_page_rows(
    mut rows: Vec<MySqlRow>,
    limit: usize,
) -> Result<(Vec<MySqlRow>, Option<String>), StorageError> {
    let next_cursor = if rows.len() > limit {
        Some(text(uuid(&rows[limit - 1], "id")?))
    } else {
        None
    };
    rows.truncate(limit);
    Ok((rows, next_cursor))
}

fn placeholders(count: usize) -> String {
    std::iter::repeat_n("?", count)
        .collect::<Vec<_>>()
        .join(", ")
}

fn service_ids_text(ids: &[kitsunebi_domain::ServiceId]) -> Vec<String> {
    ids.iter().map(|id| text(id.as_uuid())).collect()
}

impl MySqlStorage {
    /// Resolve a typed plan target through persisted ownership relationships.
    /// The result must be exactly one cluster; ambiguous relationships are
    /// rejected instead of selecting an arbitrary provider or route.
    pub async fn resolve_plan_target_cluster(
        &self,
        target: PlanTarget,
        service: kitsunebi_domain::ServiceId,
    ) -> Result<kitsunebi_domain::ClusterId, StorageError> {
        let service_id = text(service.as_uuid());
        let (statement, target_id, repeats) = match target {
            PlanTarget::Cluster(id) => (
                "SELECT id AS cluster_id FROM clusters WHERE id = ? AND service_id = ?",
                id.as_uuid(),
                1,
            ),
            PlanTarget::Service(id) => (
                "SELECT c.id AS cluster_id FROM services s JOIN clusters c ON c.id = s.current_cluster_id WHERE s.id = ? AND s.id = ?",
                id.as_uuid(),
                1,
            ),
            PlanTarget::World(id) => (
                "SELECT w.cluster_id AS cluster_id FROM worlds w JOIN clusters c ON c.id = w.cluster_id WHERE w.id = ? AND c.service_id = ?",
                id.as_uuid(),
                1,
            ),
            PlanTarget::ProxyPool(id) => (
                "SELECT r.cluster_id AS cluster_id FROM routes r JOIN clusters c ON c.id = r.cluster_id WHERE r.pool_id = ? AND c.service_id = ?",
                id.as_uuid(),
                1,
            ),
            PlanTarget::ProxyInstance(id) => (
                "SELECT r.cluster_id AS cluster_id FROM proxy_instances p JOIN routes r ON r.pool_id = p.pool_id JOIN clusters c ON c.id = r.cluster_id WHERE p.id = ? AND c.service_id = ?",
                id.as_uuid(),
                1,
            ),
            PlanTarget::Artifact(id) => (
                "SELECT r.cluster_id AS cluster_id FROM artifact_set_items i JOIN cluster_revisions r ON r.artifact_set_id = i.artifact_set_id JOIN clusters c ON c.id = r.cluster_id WHERE i.artifact_id = ? AND c.service_id = ?",
                id.as_uuid(),
                1,
            ),
            PlanTarget::ArtifactSet(id) => (
                "SELECT r.cluster_id AS cluster_id FROM cluster_revisions r JOIN clusters c ON c.id = r.cluster_id WHERE r.artifact_set_id = ? AND c.service_id = ?",
                id.as_uuid(),
                1,
            ),
            PlanTarget::Endpoint(id) => (
                "SELECT b.cluster_id AS cluster_id FROM endpoint_bindings b JOIN clusters c ON c.id = b.cluster_id WHERE b.endpoint_id = ? AND c.service_id = ?",
                id.as_uuid(),
                1,
            ),
            PlanTarget::EndpointBinding(id) => (
                "SELECT b.cluster_id AS cluster_id FROM endpoint_bindings b JOIN clusters c ON c.id = b.cluster_id WHERE b.id = ? AND c.service_id = ?",
                id.as_uuid(),
                1,
            ),
            PlanTarget::Backup(id) => (
                "SELECT c.id AS cluster_id FROM backup_references b JOIN change_sessions s ON s.id = b.change_session_id JOIN clusters c ON c.id = JSON_UNQUOTE(JSON_EXTRACT(s.target, '$.cluster_id')) WHERE b.id = ? AND c.service_id = ?",
                id.as_uuid(),
                1,
            ),
            PlanTarget::ExecutionUnit(id) => (
                "SELECT b.cluster_id AS cluster_id FROM gameap_bindings b JOIN clusters c ON c.id = b.cluster_id WHERE b.id = ? AND c.service_id = ? UNION SELECT w.cluster_id AS cluster_id FROM gameap_bindings b JOIN worlds w ON w.id = b.world_id JOIN clusters c ON c.id = w.cluster_id WHERE b.id = ? AND c.service_id = ? UNION SELECT r.cluster_id AS cluster_id FROM gameap_bindings b JOIN proxy_instances p ON p.id = b.proxy_instance_id JOIN routes r ON r.pool_id = p.pool_id JOIN clusters c ON c.id = r.cluster_id WHERE b.id = ? AND c.service_id = ?",
                id.as_uuid(),
                3,
            ),
            PlanTarget::AccessPolicy(id) => (
                "SELECT c.id AS cluster_id FROM services s JOIN clusters c ON c.id = s.current_cluster_id WHERE s.access_policy_id = ? AND s.id = ? UNION SELECT c.id AS cluster_id FROM access_policy_bindings b JOIN clusters c ON c.id = b.cluster_id WHERE b.policy_id = ? AND c.service_id = ?",
                id.as_uuid(),
                2,
            ),
        };
        let mut query = sqlx::query(statement);
        for _ in 0..repeats {
            query = query.bind(text(target_id));
            query = query.bind(&service_id);
        }
        let rows = query.fetch_all(self.pool()).await.map_err(db)?;
        let mut clusters = std::collections::BTreeSet::new();
        for row in rows {
            clusters.insert(kitsunebi_domain::ClusterId::from_uuid(uuid(
                &row,
                "cluster_id",
            )?));
        }
        match clusters.len() {
            1 => Ok(clusters.into_iter().next().expect("one cluster")),
            0 => Err(StorageError::NotFound {
                entity: "plan target cluster",
            }),
            _ => Err(StorageError::Conflict {
                entity: "plan target cluster",
            }),
        }
    }

    /// Unscoped snapshots are used only by the application repository after
    /// authorization has already been established by its caller.
    pub async fn list_all_services(&self) -> Result<Vec<Service>, StorageError> {
        let rows = sqlx::query("SELECT * FROM services ORDER BY id")
            .fetch_all(self.pool())
            .await
            .map_err(db)?;
        rows.iter().map(row_service).collect()
    }
    pub async fn list_all_clusters(&self) -> Result<Vec<GameCluster>, StorageError> {
        let rows = sqlx::query("SELECT * FROM clusters ORDER BY id")
            .fetch_all(self.pool())
            .await
            .map_err(db)?;
        rows.iter().map(row_cluster).collect()
    }
    pub async fn list_all_revisions(&self) -> Result<Vec<ClusterRevision>, StorageError> {
        let rows = sqlx::query("SELECT * FROM cluster_revisions ORDER BY id")
            .fetch_all(self.pool())
            .await
            .map_err(db)?;
        rows.iter().map(row_revision).collect()
    }
    pub async fn list_all_worlds(&self) -> Result<Vec<World>, StorageError> {
        let rows = sqlx::query("SELECT * FROM worlds ORDER BY id")
            .fetch_all(self.pool())
            .await
            .map_err(db)?;
        let mut worlds = Vec::with_capacity(rows.len());
        for row in &rows {
            let id = kitsunebi_domain::WorldId::from_uuid(uuid(row, "id")?);
            let writers = self.list_world_writers(id).await?;
            worlds.push(row_world(
                row,
                writers.iter().map(|v| v.as_uuid()).collect(),
            )?);
        }
        Ok(worlds)
    }
    pub async fn list_all_proxy_instances(&self) -> Result<Vec<ProxyInstance>, StorageError> {
        let rows = sqlx::query("SELECT * FROM proxy_instances ORDER BY id")
            .fetch_all(self.pool())
            .await
            .map_err(db)?;
        rows.iter().map(row_proxy_instance).collect()
    }
    /// Resolve the owning service(s) for a resource using server-side joins.
    /// Callers must use this result for authorization; a client-provided
    /// service id is deliberately not accepted by the actor-scoped methods.
    pub async fn resource_service_scope(
        &self,
        resource: ResourceKind,
        resource_id: Uuid,
    ) -> Result<Vec<kitsunebi_domain::ServiceId>, StorageError> {
        let (statement, repeats) = match resource {
            ResourceKind::Network => (
                "SELECT id AS service_id FROM services WHERE network_id = ?",
                1,
            ),
            ResourceKind::Service => ("SELECT id AS service_id FROM services WHERE id = ?", 1),
            ResourceKind::Cluster => ("SELECT service_id FROM clusters WHERE id = ?", 1),
            ResourceKind::Revision => (
                "SELECT c.service_id FROM cluster_revisions r JOIN clusters c ON c.id = r.cluster_id WHERE r.id = ?",
                1,
            ),
            ResourceKind::World => (
                "SELECT c.service_id FROM worlds w JOIN clusters c ON c.id = w.cluster_id WHERE w.id = ?",
                1,
            ),
            ResourceKind::WorldWriter => (
                "SELECT c.service_id FROM world_writers ww JOIN worlds w ON w.id = ww.world_id JOIN clusters c ON c.id = w.cluster_id WHERE ww.id = ?",
                1,
            ),
            ResourceKind::RuntimeProfile => (
                "SELECT c.service_id FROM cluster_revisions r JOIN clusters c ON c.id = r.cluster_id WHERE r.runtime_profile_id = ?",
                1,
            ),
            ResourceKind::ProxyPool => (
                "SELECT c.service_id FROM routes r JOIN clusters c ON c.id = r.cluster_id WHERE r.pool_id = ?",
                1,
            ),
            ResourceKind::ProxyInstance => (
                "SELECT c.service_id FROM proxy_instances pi JOIN routes r ON r.pool_id = pi.pool_id JOIN clusters c ON c.id = r.cluster_id WHERE pi.id = ?",
                1,
            ),
            ResourceKind::Route => (
                "SELECT c.service_id FROM routes r JOIN clusters c ON c.id = r.cluster_id WHERE r.id = ?",
                1,
            ),
            ResourceKind::Artifact => (
                "SELECT c.service_id FROM artifact_set_items i JOIN cluster_revisions r ON r.artifact_set_id = i.artifact_set_id JOIN clusters c ON c.id = r.cluster_id WHERE i.artifact_id = ?",
                1,
            ),
            ResourceKind::ArtifactSet => (
                "SELECT c.service_id FROM cluster_revisions r JOIN clusters c ON c.id = r.cluster_id WHERE r.artifact_set_id = ?",
                1,
            ),
            ResourceKind::ConfigBaseline => (
                "SELECT c.service_id FROM cluster_revisions r JOIN clusters c ON c.id = r.cluster_id WHERE r.config_baseline_id = ?",
                1,
            ),
            ResourceKind::Endpoint => (
                "SELECT c.service_id FROM endpoint_bindings b JOIN cluster_revisions r ON r.id = b.revision_id JOIN clusters c ON c.id = r.cluster_id WHERE b.endpoint_id = ?",
                1,
            ),
            ResourceKind::EndpointBinding => (
                "SELECT c.service_id FROM endpoint_bindings b JOIN cluster_revisions r ON r.id = b.revision_id JOIN clusters c ON c.id = r.cluster_id WHERE b.id = ?",
                1,
            ),
            ResourceKind::AccessPolicy => (
                "SELECT s.id AS service_id FROM services s WHERE s.access_policy_id = ? UNION SELECT s.id FROM access_policy_bindings b JOIN services s ON s.id = b.service_id WHERE b.policy_id = ? UNION SELECT c.service_id FROM access_policy_bindings b JOIN clusters c ON c.id = b.cluster_id WHERE b.policy_id = ?",
                3,
            ),
            ResourceKind::AccessPolicyBinding => (
                "SELECT service_id FROM access_policy_bindings WHERE id = ? AND service_id IS NOT NULL UNION SELECT c.service_id FROM access_policy_bindings b JOIN clusters c ON c.id = b.cluster_id WHERE b.id = ?",
                2,
            ),
            ResourceKind::ChangeSession => (
                "SELECT c.service_id FROM change_sessions s JOIN clusters c ON c.id = JSON_UNQUOTE(JSON_EXTRACT(s.target, '$.cluster_id')) WHERE s.id = ?",
                1,
            ),
            ResourceKind::Plan => (
                "SELECT c.service_id FROM plans p JOIN change_sessions s ON s.id = p.change_session_id JOIN clusters c ON c.id = JSON_UNQUOTE(JSON_EXTRACT(s.target, '$.cluster_id')) WHERE p.id = ?",
                1,
            ),
            ResourceKind::Operation => (
                "SELECT c.service_id FROM operations o JOIN change_sessions s ON s.id = o.change_session_id JOIN clusters c ON c.id = JSON_UNQUOTE(JSON_EXTRACT(s.target, '$.cluster_id')) WHERE o.id = ?",
                1,
            ),
            ResourceKind::BackupReference => (
                "SELECT c.service_id FROM backup_references b JOIN change_sessions s ON s.id = b.change_session_id JOIN clusters c ON c.id = JSON_UNQUOTE(JSON_EXTRACT(s.target, '$.cluster_id')) WHERE b.id = ?",
                1,
            ),
            ResourceKind::LifecycleDecision => {
                ("SELECT service_id FROM lifecycle_decisions WHERE id = ?", 1)
            }
            ResourceKind::GameAPBinding => (
                "SELECT service_id FROM gameap_bindings WHERE id = ? AND service_id IS NOT NULL UNION SELECT c.service_id FROM gameap_bindings b JOIN clusters c ON c.id = b.cluster_id WHERE b.id = ? UNION SELECT c.service_id FROM gameap_bindings b JOIN worlds w ON w.id = b.world_id JOIN clusters c ON c.id = w.cluster_id WHERE b.id = ? UNION SELECT c.service_id FROM gameap_bindings b JOIN proxy_instances p ON p.id = b.proxy_instance_id JOIN routes r ON r.pool_id = p.pool_id JOIN clusters c ON c.id = r.cluster_id WHERE b.id = ?",
                4,
            ),
            ResourceKind::AuditEvent => (
                "SELECT service_id FROM audit_events WHERE event_id = ? AND service_id IS NOT NULL UNION SELECT c.service_id FROM audit_events e JOIN clusters c ON c.id = e.cluster_id WHERE e.event_id = ? UNION SELECT c.service_id FROM audit_events e JOIN worlds w ON w.id = e.world_id JOIN clusters c ON c.id = w.cluster_id WHERE e.event_id = ?",
                3,
            ),
            ResourceKind::SftpEndpoint => ("SELECT service_id FROM sftp_endpoints WHERE id = ?", 1),
            ResourceKind::SftpScan => ("SELECT service_id FROM sftp_scans WHERE id = ?", 1),
        };
        let mut query = sqlx::query(statement);
        let value = text(resource_id);
        for _ in 0..repeats {
            query = query.bind(value.clone());
        }
        let rows = query.fetch_all(self.pool()).await.map_err(db)?;
        let mut services = rows
            .iter()
            .map(|row| uuid(row, "service_id").map(kitsunebi_domain::ServiceId::from_uuid))
            .collect::<Result<Vec<_>, _>>()?;
        services.sort_unstable();
        services.dedup();
        Ok(services)
    }

    /// Return service ids for which an actor has the requested permission.
    /// The policy JSON is evaluated against rows linked to each service; no
    /// authorization decision is made from an id supplied by the caller.
    pub async fn service_ids_for_actor(
        &self,
        actor: kitsunebi_domain::ActorId,
        permission: &Permission,
    ) -> Result<Vec<kitsunebi_domain::ServiceId>, StorageError> {
        self.service_ids_for_principal(&AccessPrincipal::Actor(actor), permission)
            .await
    }

    /// Return service ids for which an actor or named group has the requested
    /// action grant. Each candidate row is checked against its own service
    /// scope, so a grant on one service cannot leak into another.
    pub async fn service_ids_for_principal(
        &self,
        principal: &AccessPrincipal,
        permission: &Permission,
    ) -> Result<Vec<kitsunebi_domain::ServiceId>, StorageError> {
        if let AccessPrincipal::Actor(actor) = principal {
            self.require_actor_identity(*actor).await?;
        }
        let rows = sqlx::query(
            "SELECT s.id AS service_id, p.id AS policy_id, p.policy FROM services s JOIN access_policies p ON p.id = s.access_policy_id UNION SELECT s.id, p.id, p.policy FROM access_policy_bindings b JOIN services s ON s.id = b.service_id JOIN access_policies p ON p.id = b.policy_id UNION SELECT c.service_id, p.id, p.policy FROM access_policy_bindings b JOIN clusters c ON c.id = b.cluster_id JOIN access_policies p ON p.id = b.policy_id",
        )
        .fetch_all(self.pool())
        .await
        .map_err(db)?;
        let mut services = Vec::new();
        for row in rows {
            let service_id = kitsunebi_domain::ServiceId::from_uuid(uuid(&row, "service_id")?);
            let policy_id = kitsunebi_domain::PolicyId::from_uuid(uuid(&row, "policy_id")?);
            let grants: Vec<AccessGrant> = json_col(&row, "policy")?;
            let policy = AccessPolicy {
                id: policy_id,
                grants,
            };
            if policy.allows_principal(principal, service_id, *permission) {
                services.push(service_id);
            }
        }
        services.sort_unstable();
        services.dedup();
        Ok(services)
    }

    /// Evaluate a policy only after resolving the policy bindings for the
    /// requested service. This prevents a grant on service A from authorizing
    /// an object owned by service B merely because both rows share a policy
    /// table. The caller supplies an action-level permission; roles are not
    /// treated as grants and JWT claims are never consulted.
    pub async fn actor_can_access_service(
        &self,
        actor: kitsunebi_domain::ActorId,
        service: kitsunebi_domain::ServiceId,
        permission: &Permission,
    ) -> Result<bool, StorageError> {
        self.principal_can_access_service(&AccessPrincipal::Actor(actor), service, permission)
            .await
    }

    /// Evaluate an actor or named group against only the policies bound to the
    /// requested service. Group membership is resolved by the caller; the
    /// persistence layer never trusts role/scope claims from a token.
    pub async fn principal_can_access_service(
        &self,
        principal: &AccessPrincipal,
        service: kitsunebi_domain::ServiceId,
        permission: &Permission,
    ) -> Result<bool, StorageError> {
        if let AccessPrincipal::Actor(actor) = principal {
            self.require_actor_identity(*actor).await?;
        }
        let rows = sqlx::query(
            "SELECT p.id AS policy_id, p.policy FROM access_policies p JOIN services s ON s.access_policy_id = p.id WHERE s.id = ? UNION SELECT p.id, p.policy FROM access_policy_bindings b JOIN access_policies p ON p.id = b.policy_id WHERE b.service_id = ? UNION SELECT p.id, p.policy FROM access_policy_bindings b JOIN clusters c ON c.id = b.cluster_id JOIN access_policies p ON p.id = b.policy_id WHERE c.service_id = ?",
        )
        .bind(text(service.as_uuid()))
        .bind(text(service.as_uuid()))
        .bind(text(service.as_uuid()))
        .fetch_all(self.pool())
        .await
        .map_err(db)?;
        for row in rows {
            let policy_id = kitsunebi_domain::PolicyId::from_uuid(uuid(&row, "policy_id")?);
            let policy = AccessPolicy {
                id: policy_id,
                grants: json_col(&row, "policy")?,
            };
            if policy.allows_principal(principal, service, *permission) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub async fn list_services_for_actor(
        &self,
        actor: kitsunebi_domain::ActorId,
        permission: &Permission,
        limit: u32,
        cursor: Option<&str>,
    ) -> Result<Page<Service>, StorageError> {
        let service_ids = self.service_ids_for_actor(actor, permission).await?;
        let limit = page_limit(limit);
        if service_ids.is_empty() {
            return Ok(Page {
                items: Vec::new(),
                next_cursor: None,
            });
        }
        let ids = service_ids_text(&service_ids);
        let statement = format!(
            "SELECT * FROM services WHERE id IN ({}) AND id > ? ORDER BY id LIMIT ?",
            placeholders(ids.len())
        );
        let mut query = sqlx::query(&statement);
        for id in ids {
            query = query.bind(id);
        }
        query = query
            .bind(page_cursor(cursor)?)
            .bind(i64::try_from(limit + 1).unwrap_or(101));
        let (rows, next_cursor) =
            trim_page_rows(query.fetch_all(self.pool()).await.map_err(db)?, limit)?;
        Ok(Page {
            items: rows.iter().map(row_service).collect::<Result<_, _>>()?,
            next_cursor,
        })
    }

    pub async fn list_clusters_for_actor(
        &self,
        actor: kitsunebi_domain::ActorId,
        permission: &Permission,
        limit: u32,
        cursor: Option<&str>,
    ) -> Result<Page<GameCluster>, StorageError> {
        let service_ids = self.service_ids_for_actor(actor, permission).await?;
        let limit = page_limit(limit);
        if service_ids.is_empty() {
            return Ok(Page {
                items: Vec::new(),
                next_cursor: None,
            });
        }
        let ids = service_ids_text(&service_ids);
        let statement = format!(
            "SELECT c.* FROM clusters c WHERE c.service_id IN ({}) AND c.id > ? ORDER BY c.id LIMIT ?",
            placeholders(ids.len())
        );
        let mut query = sqlx::query(&statement);
        for id in ids {
            query = query.bind(id);
        }
        query = query
            .bind(page_cursor(cursor)?)
            .bind(i64::try_from(limit + 1).unwrap_or(101));
        let (rows, next_cursor) =
            trim_page_rows(query.fetch_all(self.pool()).await.map_err(db)?, limit)?;
        Ok(Page {
            items: rows.iter().map(row_cluster).collect::<Result<_, _>>()?,
            next_cursor,
        })
    }

    pub async fn list_revisions_for_actor(
        &self,
        actor: kitsunebi_domain::ActorId,
        permission: &Permission,
        limit: u32,
        cursor: Option<&str>,
    ) -> Result<Page<ClusterRevision>, StorageError> {
        let service_ids = self.service_ids_for_actor(actor, permission).await?;
        let limit = page_limit(limit);
        if service_ids.is_empty() {
            return Ok(Page {
                items: Vec::new(),
                next_cursor: None,
            });
        }
        let ids = service_ids_text(&service_ids);
        let statement = format!(
            "SELECT r.* FROM cluster_revisions r JOIN clusters c ON c.id = r.cluster_id WHERE c.service_id IN ({}) AND r.id > ? ORDER BY r.id LIMIT ?",
            placeholders(ids.len())
        );
        let mut query = sqlx::query(&statement);
        for id in ids {
            query = query.bind(id);
        }
        query = query
            .bind(page_cursor(cursor)?)
            .bind(i64::try_from(limit + 1).unwrap_or(101));
        let (rows, next_cursor) =
            trim_page_rows(query.fetch_all(self.pool()).await.map_err(db)?, limit)?;
        Ok(Page {
            items: rows.iter().map(row_revision).collect::<Result<_, _>>()?,
            next_cursor,
        })
    }

    pub async fn list_worlds_for_actor(
        &self,
        actor: kitsunebi_domain::ActorId,
        permission: &Permission,
        limit: u32,
        cursor: Option<&str>,
    ) -> Result<Page<World>, StorageError> {
        let service_ids = self.service_ids_for_actor(actor, permission).await?;
        let limit = page_limit(limit);
        if service_ids.is_empty() {
            return Ok(Page {
                items: Vec::new(),
                next_cursor: None,
            });
        }
        let ids = service_ids_text(&service_ids);
        let statement = format!(
            "SELECT w.* FROM worlds w JOIN clusters c ON c.id = w.cluster_id WHERE c.service_id IN ({}) AND w.id > ? ORDER BY w.id LIMIT ?",
            placeholders(ids.len())
        );
        let mut query = sqlx::query(&statement);
        for id in ids {
            query = query.bind(id);
        }
        query = query
            .bind(page_cursor(cursor)?)
            .bind(i64::try_from(limit + 1).unwrap_or(101));
        let (rows, next_cursor) =
            trim_page_rows(query.fetch_all(self.pool()).await.map_err(db)?, limit)?;
        let mut items = Vec::with_capacity(rows.len());
        for row in rows {
            let world_id = uuid(&row, "id")?;
            let writers = self
                .list_world_writers(kitsunebi_domain::WorldId::from_uuid(world_id))
                .await?;
            items.push(row_world(
                &row,
                writers.iter().map(|id| id.as_uuid()).collect(),
            )?);
        }
        Ok(Page { items, next_cursor })
    }

    pub async fn list_proxy_instances_for_actor(
        &self,
        actor: kitsunebi_domain::ActorId,
        permission: &Permission,
        limit: u32,
        cursor: Option<&str>,
    ) -> Result<Page<ProxyInstance>, StorageError> {
        let service_ids = self.service_ids_for_actor(actor, permission).await?;
        let limit = page_limit(limit);
        if service_ids.is_empty() {
            return Ok(Page {
                items: Vec::new(),
                next_cursor: None,
            });
        }
        let ids = service_ids_text(&service_ids);
        let statement = format!(
            "SELECT DISTINCT pi.* FROM proxy_instances pi JOIN routes r ON r.pool_id = pi.pool_id JOIN clusters c ON c.id = r.cluster_id WHERE c.service_id IN ({}) AND pi.id > ? ORDER BY pi.id LIMIT ?",
            placeholders(ids.len())
        );
        let mut query = sqlx::query(&statement);
        for id in ids {
            query = query.bind(id);
        }
        query = query
            .bind(page_cursor(cursor)?)
            .bind(i64::try_from(limit + 1).unwrap_or(101));
        let (rows, next_cursor) =
            trim_page_rows(query.fetch_all(self.pool()).await.map_err(db)?, limit)?;
        Ok(Page {
            items: rows
                .iter()
                .map(row_proxy_instance)
                .collect::<Result<_, _>>()?,
            next_cursor,
        })
    }

    pub async fn list_routes_for_actor(
        &self,
        actor: kitsunebi_domain::ActorId,
        permission: &Permission,
        limit: u32,
        cursor: Option<&str>,
    ) -> Result<Page<Route>, StorageError> {
        let service_ids = self.service_ids_for_actor(actor, permission).await?;
        let limit = page_limit(limit);
        if service_ids.is_empty() {
            return Ok(Page {
                items: Vec::new(),
                next_cursor: None,
            });
        }
        let ids = service_ids_text(&service_ids);
        let statement = format!(
            "SELECT r.id, r.cluster_id, r.priority, r.disabled, r.metadata FROM routes r WHERE r.cluster_id IN (SELECT c.id FROM clusters c WHERE c.service_id IN ({})) AND r.id > ? ORDER BY r.id LIMIT ?",
            placeholders(ids.len())
        );
        let mut query = sqlx::query(&statement);
        for id in ids {
            query = query.bind(id);
        }
        query = query
            .bind(page_cursor(cursor)?)
            .bind(i64::try_from(limit + 1).unwrap_or(101));
        let (rows, next_cursor) =
            trim_page_rows(query.fetch_all(self.pool()).await.map_err(db)?, limit)?;
        let mut items = Vec::with_capacity(rows.len());
        for row in rows {
            let metadata: Value = row.try_get("metadata").map_err(db)?;
            items.push(Route {
                id: kitsunebi_domain::RouteId::from_uuid(uuid(&row, "id")?),
                key: metadata
                    .get("key")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                target_cluster: kitsunebi_domain::ClusterId::from_uuid(uuid(&row, "cluster_id")?),
                priority: row.try_get("priority").map_err(db)?,
                disabled: row.try_get("disabled").map_err(db)?,
            });
        }
        Ok(Page { items, next_cursor })
    }

    pub async fn list_endpoint_bindings_for_actor(
        &self,
        actor: kitsunebi_domain::ActorId,
        permission: &Permission,
        limit: u32,
        cursor: Option<&str>,
    ) -> Result<Page<EndpointBinding>, StorageError> {
        let service_ids = self.service_ids_for_actor(actor, permission).await?;
        let limit = page_limit(limit);
        if service_ids.is_empty() {
            return Ok(Page {
                items: Vec::new(),
                next_cursor: None,
            });
        }
        let ids = service_ids_text(&service_ids);
        let statement = format!(
            "SELECT b.id, b.endpoint_id, b.revision_id, b.cluster_id, b.binding_key, b.metadata FROM endpoint_bindings b JOIN cluster_revisions r ON r.id = b.revision_id JOIN clusters c ON c.id = r.cluster_id WHERE c.service_id IN ({}) AND b.id > ? ORDER BY b.id LIMIT ?",
            placeholders(ids.len())
        );
        let mut query = sqlx::query(&statement);
        for id in ids {
            query = query.bind(id);
        }
        query = query
            .bind(page_cursor(cursor)?)
            .bind(i64::try_from(limit + 1).unwrap_or(101));
        let (rows, next_cursor) =
            trim_page_rows(query.fetch_all(self.pool()).await.map_err(db)?, limit)?;
        Ok(Page {
            items: rows.iter().map(row_binding).collect::<Result<_, _>>()?,
            next_cursor,
        })
    }

    pub async fn create_network(&self, network: &MCPlayNetwork) -> Result<(), StorageError> {
        sqlx::query("INSERT INTO networks (id, `key`, display_name, metadata) VALUES (?, ?, ?, ?)")
            .bind(text(network.id.as_uuid()))
            .bind(&network.key)
            .bind(&network.display_name)
            .bind(to_json(&network.metadata)?)
            .execute(self.pool())
            .await
            .map(|_| ())
            .map_err(db)
    }

    pub async fn get_network(
        &self,
        id: kitsunebi_domain::NetworkId,
    ) -> Result<Option<MCPlayNetwork>, StorageError> {
        sqlx::query("SELECT id, `key`, display_name, metadata FROM networks WHERE id = ?")
            .bind(text(id.as_uuid()))
            .fetch_optional(self.pool())
            .await
            .map_err(db)?
            .map(|row| row_network(&row))
            .transpose()
    }

    pub async fn list_networks(&self) -> Result<Vec<MCPlayNetwork>, StorageError> {
        let rows = sqlx::query(
            "SELECT id, `key`, display_name, metadata FROM networks ORDER BY `key`, id",
        )
        .fetch_all(self.pool())
        .await
        .map_err(db)?;
        rows.iter().map(row_network).collect()
    }

    pub async fn update_network(
        &self,
        network: &MCPlayNetwork,
        expected_version: u64,
    ) -> Result<(), StorageError> {
        let result = sqlx::query(
            "UPDATE networks SET `key` = ?, display_name = ?, metadata = ?, version = version + 1 WHERE id = ? AND version = ?",
        )
        .bind(&network.key)
        .bind(&network.display_name)
        .bind(to_json(&network.metadata)?)
        .bind(text(network.id.as_uuid()))
        .bind(expected_version)
        .execute(self.pool())
        .await
        .map_err(db)?;
        if result.rows_affected() == 0 {
            return Err(StorageError::Conflict { entity: "network" });
        }
        Ok(())
    }

    pub async fn create_service(
        &self,
        network_id: kitsunebi_domain::NetworkId,
        service: &Service,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO services (id, network_id, `key`, display_name, ownership, audience, operator_model, trust_profile, lifecycle, availability, current_cluster_id, access_policy_id, backup_policy, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(text(service.id.as_uuid()))
        .bind(text(network_id.as_uuid()))
        .bind(&service.key)
        .bind(&service.display_name)
        .bind(ownership(&service.ownership))
        .bind(audience(&service.audience))
        .bind(operator_model(&service.operator_model))
        .bind(trust_profile(&service.trust_profile))
        .bind(lifecycle(&service.lifecycle))
        .bind(availability(&service.availability))
        .bind(service.current_cluster.map(|id| text(id.as_uuid())))
        .bind(service.access_policy.map(|id| text(id.as_uuid())))
        .bind(to_json(&service.backup_policy)?)
        .bind(to_json(&service.metadata)?)
        .execute(self.pool())
        .await
        .map(|_| ())
        .map_err(db)
    }

    pub async fn get_service(
        &self,
        id: kitsunebi_domain::ServiceId,
    ) -> Result<Option<Service>, StorageError> {
        sqlx::query("SELECT * FROM services WHERE id = ?")
            .bind(text(id.as_uuid()))
            .fetch_optional(self.pool())
            .await
            .map_err(db)?
            .map(|row| row_service(&row))
            .transpose()
    }

    pub async fn list_services(
        &self,
        network_id: kitsunebi_domain::NetworkId,
    ) -> Result<Vec<Service>, StorageError> {
        let rows = sqlx::query("SELECT * FROM services WHERE network_id = ? ORDER BY `key`, id")
            .bind(text(network_id.as_uuid()))
            .fetch_all(self.pool())
            .await
            .map_err(db)?;
        rows.iter().map(row_service).collect()
    }

    pub async fn update_service(
        &self,
        service: &Service,
        expected_version: u64,
    ) -> Result<(), StorageError> {
        let result = sqlx::query(
            "UPDATE services SET `key` = ?, display_name = ?, ownership = ?, audience = ?, operator_model = ?, trust_profile = ?, lifecycle = ?, availability = ?, current_cluster_id = ?, access_policy_id = ?, backup_policy = ?, metadata = ?, version = version + 1 WHERE id = ? AND version = ?",
        )
        .bind(&service.key)
        .bind(&service.display_name)
        .bind(ownership(&service.ownership))
        .bind(audience(&service.audience))
        .bind(operator_model(&service.operator_model))
        .bind(trust_profile(&service.trust_profile))
        .bind(lifecycle(&service.lifecycle))
        .bind(availability(&service.availability))
        .bind(service.current_cluster.map(|id| text(id.as_uuid())))
        .bind(service.access_policy.map(|id| text(id.as_uuid())))
        .bind(to_json(&service.backup_policy)?)
        .bind(to_json(&service.metadata)?)
        .bind(text(service.id.as_uuid()))
        .bind(expected_version)
        .execute(self.pool())
        .await
        .map_err(db)?;
        if result.rows_affected() == 0 {
            return Err(StorageError::Conflict { entity: "service" });
        }
        Ok(())
    }

    pub async fn create_cluster(&self, cluster: &GameCluster) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO clusters (id, service_id, `key`, display_name, current_revision_id, metadata) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(text(cluster.id.as_uuid()))
        .bind(text(cluster.service_id.as_uuid()))
        .bind(&cluster.key)
        .bind(&cluster.key)
        .bind(cluster.current_revision.map(|id| text(id.as_uuid())))
        .bind(json!({}))
        .execute(self.pool())
        .await
        .map(|_| ())
        .map_err(db)
    }

    pub async fn get_cluster(
        &self,
        id: kitsunebi_domain::ClusterId,
    ) -> Result<Option<GameCluster>, StorageError> {
        sqlx::query("SELECT * FROM clusters WHERE id = ?")
            .bind(text(id.as_uuid()))
            .fetch_optional(self.pool())
            .await
            .map_err(db)?
            .map(|row| row_cluster(&row))
            .transpose()
    }

    pub async fn list_clusters(
        &self,
        service_id: kitsunebi_domain::ServiceId,
    ) -> Result<Vec<GameCluster>, StorageError> {
        let rows = sqlx::query("SELECT * FROM clusters WHERE service_id = ? ORDER BY `key`, id")
            .bind(text(service_id.as_uuid()))
            .fetch_all(self.pool())
            .await
            .map_err(db)?;
        rows.iter().map(row_cluster).collect()
    }

    pub async fn update_cluster(
        &self,
        cluster: &GameCluster,
        expected_version: u64,
    ) -> Result<(), StorageError> {
        let result = sqlx::query(
            "UPDATE clusters SET `key` = ?, current_revision_id = ?, version = version + 1 WHERE id = ? AND version = ?",
        )
        .bind(&cluster.key)
        .bind(cluster.current_revision.map(|id| text(id.as_uuid())))
        .bind(text(cluster.id.as_uuid()))
        .bind(expected_version)
        .execute(self.pool())
        .await
        .map_err(db)?;
        if result.rows_affected() == 0 {
            return Err(StorageError::Conflict { entity: "cluster" });
        }
        Ok(())
    }

    pub async fn activate_cluster_revision(
        &self,
        cluster_id: kitsunebi_domain::ClusterId,
        expected: Option<kitsunebi_domain::RevisionId>,
        revision: kitsunebi_domain::RevisionId,
    ) -> Result<(), StorageError> {
        let result = sqlx::query(
            "UPDATE clusters SET current_revision_id = ?, version = version + 1 WHERE id = ? AND ((current_revision_id IS NULL AND ? IS NULL) OR current_revision_id = ?)",
        )
        .bind(text(revision.as_uuid()))
        .bind(text(cluster_id.as_uuid()))
        .bind(expected.map(|id| text(id.as_uuid())))
        .bind(expected.map(|id| text(id.as_uuid())))
        .execute(self.pool())
        .await
        .map_err(db)?;
        if result.rows_affected() == 0 {
            return Err(StorageError::Conflict {
                entity: "cluster revision",
            });
        }
        Ok(())
    }

    pub async fn activate_revision(
        &self,
        cluster_id: kitsunebi_domain::ClusterId,
        expected: Option<kitsunebi_domain::RevisionId>,
        revision: kitsunebi_domain::RevisionId,
    ) -> Result<(), StorageError> {
        self.activate_cluster_revision(cluster_id, expected, revision)
            .await
    }

    pub async fn create_revision(
        &self,
        cluster_id: kitsunebi_domain::ClusterId,
        revision: &ClusterRevision,
    ) -> Result<(), StorageError> {
        revision
            .placement_requirements
            .validate()
            .map_err(StorageError::Domain)?;
        sqlx::query(
            "INSERT INTO cluster_revisions (id, cluster_id, revision_number, runtime_profile_id, minecraft_version, java_requirement, artifact_set_id, config_baseline_id, world_bindings, endpoint_bindings, placement_requirements, resource_requirements, health_checks, startup_parameters, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(text(revision.id.as_uuid()))
        .bind(text(cluster_id.as_uuid()))
        .bind(revision.number)
        .bind(text(revision.runtime_profile.as_uuid()))
        .bind(&revision.minecraft_version)
        .bind(&revision.java_requirement)
        .bind(text(revision.artifact_set.as_uuid()))
        .bind(text(revision.config_baseline.as_uuid()))
        .bind(id_vec(revision.world_bindings.iter().map(|id| id.as_uuid())))
        .bind(id_vec(revision.endpoint_bindings.iter().map(|id| id.as_uuid())))
        .bind(to_json(&revision.placement_requirements)?)
        .bind(to_json(&revision.resource_requirements)?)
        .bind(to_json(&revision.health_checks)?)
        .bind(to_json(&revision.startup_parameters)?)
        .bind(json!({}))
        .execute(self.pool())
        .await
        .map(|_| ())
        .map_err(db)
    }

    /// Insert an immutable revision and every endpoint binding belonging to
    /// it in one transaction.  A revision is not usable until its complete
    /// binding set is present, so partial inserts are never committed.
    pub async fn create_revision_with_bindings(
        &self,
        cluster_id: kitsunebi_domain::ClusterId,
        revision: &ClusterRevision,
        bindings: &[EndpointBinding],
    ) -> Result<(), StorageError> {
        revision
            .placement_requirements
            .validate()
            .map_err(StorageError::Domain)?;
        let binding_ids = bindings
            .iter()
            .map(|binding| binding.id)
            .collect::<std::collections::BTreeSet<_>>();
        let revision_ids = revision
            .endpoint_bindings
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>();
        if binding_ids.len() != bindings.len()
            || revision_ids.len() != revision.endpoint_bindings.len()
            || binding_ids != revision_ids
            || bindings.iter().any(|binding| {
                binding.validate().is_err()
                    || binding.cluster_id != cluster_id
                    || binding.revision_id != revision.id
            })
        {
            return Err(StorageError::InvalidData(
                "revision endpoint binding set is incomplete or mismatched".into(),
            ));
        }
        let mut tx = self.pool().begin().await.map_err(db)?;
        sqlx::query(
            "INSERT INTO cluster_revisions (id, cluster_id, revision_number, runtime_profile_id, minecraft_version, java_requirement, artifact_set_id, config_baseline_id, world_bindings, endpoint_bindings, placement_requirements, resource_requirements, health_checks, startup_parameters, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(text(revision.id.as_uuid()))
        .bind(text(cluster_id.as_uuid()))
        .bind(revision.number)
        .bind(text(revision.runtime_profile.as_uuid()))
        .bind(&revision.minecraft_version)
        .bind(&revision.java_requirement)
        .bind(text(revision.artifact_set.as_uuid()))
        .bind(text(revision.config_baseline.as_uuid()))
        .bind(id_vec(revision.world_bindings.iter().map(|id| id.as_uuid())))
        .bind(id_vec(revision.endpoint_bindings.iter().map(|id| id.as_uuid())))
        .bind(to_json(&revision.placement_requirements)?)
        .bind(to_json(&revision.resource_requirements)?)
        .bind(to_json(&revision.health_checks)?)
        .bind(to_json(&revision.startup_parameters)?)
        .bind(json!({}))
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        for binding in bindings {
            sqlx::query(
                "INSERT INTO endpoint_bindings (id, revision_id, endpoint_id, cluster_id, binding_key, metadata) VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind(text(binding.id.as_uuid()))
            .bind(text(binding.revision_id.as_uuid()))
            .bind(text(binding.endpoint_id.as_uuid()))
            .bind(text(binding.cluster_id.as_uuid()))
            .bind(&binding.binding_key)
            .bind(to_json(&binding.metadata)?)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        }
        tx.commit().await.map_err(db)
    }

    pub async fn get_revision(
        &self,
        id: kitsunebi_domain::RevisionId,
    ) -> Result<Option<ClusterRevision>, StorageError> {
        sqlx::query("SELECT * FROM cluster_revisions WHERE id = ?")
            .bind(text(id.as_uuid()))
            .fetch_optional(self.pool())
            .await
            .map_err(db)?
            .map(|row| row_revision(&row))
            .transpose()
    }

    pub async fn get_revision_cluster(
        &self,
        id: kitsunebi_domain::RevisionId,
    ) -> Result<Option<kitsunebi_domain::ClusterId>, StorageError> {
        sqlx::query_scalar("SELECT cluster_id FROM cluster_revisions WHERE id = ?")
            .bind(text(id.as_uuid()))
            .fetch_optional(self.pool())
            .await
            .map_err(db)?
            .map(|value: String| {
                Uuid::parse_str(&value)
                    .map(kitsunebi_domain::ClusterId::from_uuid)
                    .map_err(|error| invalid(format!("revision cluster: {error}")))
            })
            .transpose()
    }

    pub async fn resolve_artifact_activation(
        &self,
        revision_id: kitsunebi_domain::RevisionId,
        artifact_id: kitsunebi_domain::ArtifactId,
        binding_id: Uuid,
    ) -> Result<
        (
            ClusterRevision,
            Artifact,
            GameAPBinding,
            kitsunebi_domain::ClusterId,
        ),
        StorageError,
    > {
        let revision = self
            .get_revision(revision_id)
            .await?
            .ok_or(StorageError::NotFound { entity: "revision" })?;
        let revision_cluster: String =
            sqlx::query_scalar("SELECT cluster_id FROM cluster_revisions WHERE id = ?")
                .bind(text(revision_id.as_uuid()))
                .fetch_one(self.pool())
                .await
                .map_err(db)?;
        let revision_cluster = Uuid::parse_str(&revision_cluster)
            .map(kitsunebi_domain::ClusterId::from_uuid)
            .map_err(|error| invalid(format!("revision cluster: {error}")))?;
        let artifact = self
            .get_artifact(artifact_id)
            .await?
            .ok_or(StorageError::NotFound { entity: "artifact" })?;
        let set =
            self.get_artifact_set(revision.artifact_set)
                .await?
                .ok_or(StorageError::NotFound {
                    entity: "artifact set",
                })?;
        if !set.artifacts.contains(&artifact_id) {
            return Err(StorageError::Conflict {
                entity: "artifact revision",
            });
        }
        let cluster_record = self
            .get_cluster(revision_cluster)
            .await?
            .ok_or(StorageError::NotFound { entity: "cluster" })?;
        let binding = self
            .get_gameap_binding_for_scope(binding_id, cluster_record.service_id, revision_cluster)
            .await?
            .ok_or(StorageError::Conflict {
                entity: "artifact execution ownership",
            })?;
        let cluster = self
            .resolve_gameap_binding_cluster(binding_id)
            .await?
            .ok_or(StorageError::Conflict {
                entity: "GameAP binding target",
            })?;
        if cluster != revision_cluster {
            return Err(StorageError::Conflict {
                entity: "artifact execution ownership",
            });
        }
        Ok((revision, artifact, binding, revision_cluster))
    }

    pub async fn list_revisions(
        &self,
        cluster_id: kitsunebi_domain::ClusterId,
    ) -> Result<Vec<ClusterRevision>, StorageError> {
        let rows = sqlx::query(
            "SELECT * FROM cluster_revisions WHERE cluster_id = ? ORDER BY revision_number",
        )
        .bind(text(cluster_id.as_uuid()))
        .fetch_all(self.pool())
        .await
        .map_err(db)?;
        rows.iter().map(row_revision).collect()
    }

    /// A revision is a historical configuration snapshot. It can be activated
    /// on a cluster, but its contents cannot be changed after insertion.
    pub async fn update_revision(&self, _revision: &ClusterRevision) -> Result<(), StorageError> {
        Err(StorageError::Immutable {
            entity: "cluster revision",
        })
    }

    pub async fn create_world(
        &self,
        cluster_id: kitsunebi_domain::ClusterId,
        world: &World,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO worlds (id, cluster_id, `key`, display_name, persistence, storage_ref, write_mode, execution_model, backup_policy, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(text(world.id.as_uuid()))
        .bind(text(cluster_id.as_uuid()))
        .bind(&world.key)
        .bind(&world.display_name)
        .bind(&world.persistence)
        .bind(&world.storage_ref)
        .bind(world_mode(&world.write_mode))
        .bind(execution_model(&world.execution_model))
        .bind(to_json(&world.backup_policy)?)
        .bind(to_json(&world.metadata)?)
        .execute(self.pool())
        .await
        .map(|_| ())
        .map_err(db)
    }

    pub async fn get_world(
        &self,
        id: kitsunebi_domain::WorldId,
    ) -> Result<Option<World>, StorageError> {
        let Some(row) = sqlx::query("SELECT * FROM worlds WHERE id = ?")
            .bind(text(id.as_uuid()))
            .fetch_optional(self.pool())
            .await
            .map_err(db)?
        else {
            return Ok(None);
        };
        let writers = sqlx::query("SELECT cluster_id FROM world_writers WHERE world_id = ? AND active ORDER BY cluster_id")
            .bind(text(id.as_uuid()))
            .fetch_all(self.pool())
            .await
            .map_err(db)?
            .iter()
            .map(|row| uuid(row, "cluster_id"))
            .collect::<Result<Vec<_>, _>>()?;
        row_world(&row, writers).map(Some)
    }

    pub async fn list_worlds(
        &self,
        cluster_id: kitsunebi_domain::ClusterId,
    ) -> Result<Vec<World>, StorageError> {
        let rows = sqlx::query("SELECT * FROM worlds WHERE cluster_id = ? ORDER BY `key`, id")
            .bind(text(cluster_id.as_uuid()))
            .fetch_all(self.pool())
            .await
            .map_err(db)?;
        let mut worlds = Vec::with_capacity(rows.len());
        for row in rows {
            let id = uuid(&row, "id")?;
            let writers = sqlx::query("SELECT cluster_id FROM world_writers WHERE world_id = ? AND active ORDER BY cluster_id")
                .bind(text(id))
                .fetch_all(self.pool())
                .await
                .map_err(db)?
                .iter()
                .map(|writer| uuid(writer, "cluster_id"))
                .collect::<Result<Vec<_>, _>>()?;
            worlds.push(row_world(&row, writers)?);
        }
        Ok(worlds)
    }

    pub async fn update_world(
        &self,
        world: &World,
        expected_version: u64,
    ) -> Result<(), StorageError> {
        let result = sqlx::query(
            "UPDATE worlds SET `key` = ?, display_name = ?, persistence = ?, storage_ref = ?, write_mode = ?, execution_model = ?, backup_policy = ?, metadata = ?, version = version + 1 WHERE id = ? AND version = ?",
        )
        .bind(&world.key)
        .bind(&world.display_name)
        .bind(&world.persistence)
        .bind(&world.storage_ref)
        .bind(world_mode(&world.write_mode))
        .bind(execution_model(&world.execution_model))
        .bind(to_json(&world.backup_policy)?)
        .bind(to_json(&world.metadata)?)
        .bind(text(world.id.as_uuid()))
        .bind(expected_version)
        .execute(self.pool())
        .await
        .map_err(db)?;
        if result.rows_affected() == 0 {
            return Err(StorageError::Conflict { entity: "world" });
        }
        Ok(())
    }

    pub async fn cutover_world_writer(
        &self,
        world_id: kitsunebi_domain::WorldId,
        expected_version: u64,
        expected_writer: Option<kitsunebi_domain::ClusterId>,
        cluster_id: kitsunebi_domain::ClusterId,
    ) -> Result<(), StorageError> {
        let mut tx = self.pool().begin().await.map_err(db)?;
        let row = sqlx::query("SELECT w.write_mode, w.version, ww.cluster_id AS current_writer_cluster, ww.active AS current_writer_active FROM worlds w LEFT JOIN world_writers ww ON ww.id = w.current_writer_id WHERE w.id = ? FOR UPDATE")
            .bind(text(world_id.as_uuid()))
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?
            .ok_or(StorageError::NotFound { entity: "world" })?;
        let version: u64 = row.try_get("version").map_err(db)?;
        if version != expected_version {
            return Err(StorageError::Conflict {
                entity: "world writer",
            });
        }
        let current_writer = row
            .try_get::<Option<String>, _>("current_writer_cluster")
            .map_err(db)?
            .map(|value| {
                Uuid::parse_str(&value)
                    .map(kitsunebi_domain::ClusterId::from_uuid)
                    .map_err(|error| invalid(format!("world writer: {error}")))
            })
            .transpose()?;
        let current_writer_active = row
            .try_get::<Option<bool>, _>("current_writer_active")
            .map_err(db)?;
        let mode: String = row.try_get("write_mode").map_err(db)?;
        let active: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM world_writers WHERE world_id = ? AND active")
                .bind(text(world_id.as_uuid()))
                .fetch_one(&mut *tx)
                .await
                .map_err(db)?;
        let expected_matches = current_writer == expected_writer
            && match expected_writer {
                Some(_) => current_writer_active == Some(true),
                None => current_writer_active.is_none() && active == 0,
            };
        if !expected_matches || (mode == "single_writer" && active > 1) {
            return Err(StorageError::Conflict {
                entity: "world writer",
            });
        }
        if mode == "single_writer" && active > 0 {
            sqlx::query("UPDATE world_writers SET active = FALSE, released_at = CURRENT_TIMESTAMP(6) WHERE world_id = ? AND active")
                .bind(text(world_id.as_uuid()))
                .execute(&mut *tx)
                .await
                .map_err(db)?;
        }
        let writer_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO world_writers (id, world_id, cluster_id, active) VALUES (?, ?, ?, TRUE)",
        )
        .bind(text(writer_id))
        .bind(text(world_id.as_uuid()))
        .bind(text(cluster_id.as_uuid()))
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        let result = sqlx::query("UPDATE worlds SET current_writer_id = ?, version = version + 1 WHERE id = ? AND version = ?")
            .bind(text(writer_id))
            .bind(text(world_id.as_uuid()))
            .bind(expected_version)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        if result.rows_affected() == 0 {
            return Err(StorageError::Conflict {
                entity: "world writer",
            });
        }
        tx.commit().await.map_err(db)
    }

    pub async fn list_world_writers(
        &self,
        world_id: kitsunebi_domain::WorldId,
    ) -> Result<Vec<kitsunebi_domain::ClusterId>, StorageError> {
        sqlx::query("SELECT cluster_id FROM world_writers WHERE world_id = ? AND active ORDER BY cluster_id")
            .bind(text(world_id.as_uuid()))
            .fetch_all(self.pool())
            .await
            .map_err(db)?
            .iter()
            .map(|row| Ok(kitsunebi_domain::ClusterId::from_uuid(uuid(row, "cluster_id")?)))
            .collect()
    }

    pub async fn create_runtime_profile(
        &self,
        profile: &RuntimeProfile,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO runtime_profiles (id, `key`, family, minecraft_version, runtime_version, artifact_source, artifact_digest, java_requirement, startup_capability, console_capability, health_capability, world_execution_capability, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(text(profile.id.as_uuid()))
        .bind(text(profile.id.as_uuid()))
        .bind(&profile.family)
        .bind(&profile.minecraft_version)
        .bind(&profile.runtime_version)
        .bind(&profile.artifact_source)
        .bind(&profile.artifact_digest)
        .bind(&profile.java_requirement)
        .bind(profile.startup_capability)
        .bind(profile.console_capability)
        .bind(profile.health_capability)
        .bind(execution_model(&profile.world_execution_capability))
        .bind(to_json(&profile.metadata)?)
        .execute(self.pool())
        .await
        .map(|_| ())
        .map_err(db)
    }

    pub async fn get_runtime_profile(
        &self,
        id: kitsunebi_domain::RuntimeProfileId,
    ) -> Result<Option<RuntimeProfile>, StorageError> {
        sqlx::query("SELECT * FROM runtime_profiles WHERE id = ?")
            .bind(text(id.as_uuid()))
            .fetch_optional(self.pool())
            .await
            .map_err(db)?
            .map(|row| row_runtime(&row))
            .transpose()
    }

    pub async fn list_runtime_profiles(&self) -> Result<Vec<RuntimeProfile>, StorageError> {
        let rows =
            sqlx::query("SELECT * FROM runtime_profiles ORDER BY family, minecraft_version, id")
                .fetch_all(self.pool())
                .await
                .map_err(db)?;
        rows.iter().map(row_runtime).collect()
    }

    pub async fn update_runtime_profile(
        &self,
        profile: &RuntimeProfile,
        expected_version: u64,
    ) -> Result<(), StorageError> {
        let result = sqlx::query(
            "UPDATE runtime_profiles SET family = ?, minecraft_version = ?, runtime_version = ?, artifact_source = ?, artifact_digest = ?, java_requirement = ?, startup_capability = ?, console_capability = ?, health_capability = ?, world_execution_capability = ?, metadata = ?, version = version + 1 WHERE id = ? AND version = ?",
        )
        .bind(&profile.family)
        .bind(&profile.minecraft_version)
        .bind(&profile.runtime_version)
        .bind(&profile.artifact_source)
        .bind(&profile.artifact_digest)
        .bind(&profile.java_requirement)
        .bind(profile.startup_capability)
        .bind(profile.console_capability)
        .bind(profile.health_capability)
        .bind(execution_model(&profile.world_execution_capability))
        .bind(to_json(&profile.metadata)?)
        .bind(text(profile.id.as_uuid()))
        .bind(expected_version)
        .execute(self.pool())
        .await
        .map_err(db)?;
        if result.rows_affected() == 0 {
            return Err(StorageError::Conflict {
                entity: "runtime profile",
            });
        }
        Ok(())
    }

    pub async fn create_proxy_pool(&self, pool: &ProxyPool) -> Result<(), StorageError> {
        sqlx::query("INSERT INTO proxy_pools (id, `key`, metadata) VALUES (?, ?, ?)")
            .bind(text(pool.id.as_uuid()))
            .bind(&pool.key)
            .bind(json!({}))
            .execute(self.pool())
            .await
            .map(|_| ())
            .map_err(db)
    }

    async fn proxy_instance_ids(
        &self,
        pool_id: kitsunebi_domain::ProxyPoolId,
    ) -> Result<Vec<Uuid>, StorageError> {
        sqlx::query("SELECT id FROM proxy_instances WHERE pool_id = ? ORDER BY `key`, id")
            .bind(text(pool_id.as_uuid()))
            .fetch_all(self.pool())
            .await
            .map_err(db)?
            .iter()
            .map(|row| uuid(row, "id"))
            .collect()
    }

    pub async fn get_proxy_pool(
        &self,
        id: kitsunebi_domain::ProxyPoolId,
    ) -> Result<Option<ProxyPool>, StorageError> {
        let Some(row) = sqlx::query("SELECT * FROM proxy_pools WHERE id = ?")
            .bind(text(id.as_uuid()))
            .fetch_optional(self.pool())
            .await
            .map_err(db)?
        else {
            return Ok(None);
        };
        row_proxy_pool(&row, self.proxy_instance_ids(id).await?).map(Some)
    }

    pub async fn list_proxy_pools(&self) -> Result<Vec<ProxyPool>, StorageError> {
        let rows = sqlx::query("SELECT * FROM proxy_pools ORDER BY `key`, id")
            .fetch_all(self.pool())
            .await
            .map_err(db)?;
        let mut pools = Vec::with_capacity(rows.len());
        for row in rows {
            let id = kitsunebi_domain::ProxyPoolId::from_uuid(uuid(&row, "id")?);
            pools.push(row_proxy_pool(&row, self.proxy_instance_ids(id).await?)?);
        }
        Ok(pools)
    }

    pub async fn update_proxy_pool(
        &self,
        pool: &ProxyPool,
        expected_version: u64,
    ) -> Result<(), StorageError> {
        let result = sqlx::query(
            "UPDATE proxy_pools SET `key` = ?, version = version + 1 WHERE id = ? AND version = ?",
        )
        .bind(&pool.key)
        .bind(text(pool.id.as_uuid()))
        .bind(expected_version)
        .execute(self.pool())
        .await
        .map_err(db)?;
        if result.rows_affected() == 0 {
            return Err(StorageError::Conflict {
                entity: "proxy pool",
            });
        }
        Ok(())
    }

    pub async fn create_proxy_instance(
        &self,
        instance: &ProxyInstance,
    ) -> Result<(), StorageError> {
        sqlx::query("INSERT INTO proxy_instances (id, pool_id, `key`, state, metadata) VALUES (?, ?, ?, ?, ?)")
            .bind(text(instance.id.as_uuid()))
            .bind(text(instance.pool_id.as_uuid()))
            .bind(&instance.key)
            .bind(proxy_state(&instance.state))
            .bind(json!({}))
            .execute(self.pool())
            .await
            .map(|_| ())
            .map_err(db)
    }

    pub async fn get_proxy_instance(
        &self,
        id: kitsunebi_domain::ProxyInstanceId,
    ) -> Result<Option<ProxyInstance>, StorageError> {
        sqlx::query("SELECT * FROM proxy_instances WHERE id = ?")
            .bind(text(id.as_uuid()))
            .fetch_optional(self.pool())
            .await
            .map_err(db)?
            .map(|row| row_proxy_instance(&row))
            .transpose()
    }

    pub async fn list_proxy_instances(
        &self,
        pool_id: kitsunebi_domain::ProxyPoolId,
    ) -> Result<Vec<ProxyInstance>, StorageError> {
        let rows =
            sqlx::query("SELECT * FROM proxy_instances WHERE pool_id = ? ORDER BY `key`, id")
                .bind(text(pool_id.as_uuid()))
                .fetch_all(self.pool())
                .await
                .map_err(db)?;
        rows.iter().map(row_proxy_instance).collect()
    }

    pub async fn update_proxy_instance(
        &self,
        instance: &ProxyInstance,
        expected_version: u64,
    ) -> Result<(), StorageError> {
        let result = sqlx::query(
            "UPDATE proxy_instances SET `key` = ?, state = ?, version = version + 1 WHERE id = ? AND version = ?",
        )
        .bind(&instance.key)
        .bind(proxy_state(&instance.state))
        .bind(text(instance.id.as_uuid()))
        .bind(expected_version)
        .execute(self.pool())
        .await
        .map_err(db)?;
        if result.rows_affected() == 0 {
            return Err(StorageError::Conflict {
                entity: "proxy instance",
            });
        }
        Ok(())
    }

    pub async fn create_tcp_shield_backend_set(
        &self,
        backend_set: &TcpShieldBackendSet,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO tcp_shield_backend_sets (pool_id, provider_network_id, domain_network_id, backend_set_id) VALUES (?, ?, ?, ?)",
        )
        .bind(text(backend_set.pool_id.as_uuid()))
        .bind(backend_set.provider_network_id)
        .bind(backend_set.domain_network_id.map(|id| text(id.as_uuid())))
        .bind(&backend_set.backend_set_id)
        .execute(self.pool())
        .await
        .map(|_| ())
        .map_err(db)
    }

    pub async fn get_tcp_shield_backend_set(
        &self,
        pool_id: kitsunebi_domain::ProxyPoolId,
    ) -> Result<Option<TcpShieldBackendSet>, StorageError> {
        sqlx::query("SELECT * FROM tcp_shield_backend_sets WHERE pool_id = ?")
            .bind(text(pool_id.as_uuid()))
            .fetch_optional(self.pool())
            .await
            .map_err(db)?
            .map(|row| row_tcp_shield_backend_set(&row))
            .transpose()
    }

    pub async fn update_tcp_shield_backend_set(
        &self,
        backend_set: &TcpShieldBackendSet,
        expected_version: u64,
    ) -> Result<(), StorageError> {
        let result = sqlx::query(
            "UPDATE tcp_shield_backend_sets SET provider_network_id = ?, domain_network_id = ?, backend_set_id = ?, version = version + 1 WHERE pool_id = ? AND version = ?",
        )
        .bind(backend_set.provider_network_id)
        .bind(backend_set.domain_network_id.map(|id| text(id.as_uuid())))
        .bind(&backend_set.backend_set_id)
        .bind(text(backend_set.pool_id.as_uuid()))
        .bind(expected_version)
        .execute(self.pool())
        .await
        .map_err(db)?;
        if result.rows_affected() == 0 {
            return Err(StorageError::Conflict {
                entity: "TCPShield backend set",
            });
        }
        Ok(())
    }

    pub async fn create_proxy_instance_binding(
        &self,
        binding: &ProxyInstanceBinding,
    ) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO proxy_instance_bindings (instance_id, gameap_binding_id, backend_address) VALUES (?, ?, ?)",
        )
        .bind(text(binding.instance_id.as_uuid()))
        .bind(text(binding.gameap_binding_id.as_uuid()))
        .bind(&binding.backend_address)
        .execute(self.pool())
        .await
        .map(|_| ())
        .map_err(db)
    }

    pub async fn get_proxy_instance_binding(
        &self,
        instance_id: kitsunebi_domain::ProxyInstanceId,
    ) -> Result<Option<ProxyInstanceBinding>, StorageError> {
        sqlx::query("SELECT * FROM proxy_instance_bindings WHERE instance_id = ?")
            .bind(text(instance_id.as_uuid()))
            .fetch_optional(self.pool())
            .await
            .map_err(db)?
            .map(|row| row_proxy_instance_binding(&row))
            .transpose()
    }

    pub async fn update_proxy_instance_binding(
        &self,
        binding: &ProxyInstanceBinding,
        expected_version: u64,
    ) -> Result<(), StorageError> {
        let result = sqlx::query(
            "UPDATE proxy_instance_bindings SET gameap_binding_id = ?, backend_address = ?, version = version + 1 WHERE instance_id = ? AND version = ?",
        )
        .bind(text(binding.gameap_binding_id.as_uuid()))
        .bind(&binding.backend_address)
        .bind(text(binding.instance_id.as_uuid()))
        .bind(expected_version)
        .execute(self.pool())
        .await
        .map_err(db)?;
        if result.rows_affected() == 0 {
            return Err(StorageError::Conflict {
                entity: "proxy instance binding",
            });
        }
        Ok(())
    }

    pub async fn create_route(
        &self,
        pool_id: kitsunebi_domain::ProxyPoolId,
        route: &Route,
    ) -> Result<(), StorageError> {
        sqlx::query("INSERT INTO routes (id, pool_id, service_id, cluster_id, priority, disabled, metadata) VALUES (?, ?, ?, ?, ?, ?, ?)")
            .bind(text(route.id.as_uuid()))
            .bind(text(pool_id.as_uuid()))
            .bind(Option::<String>::None)
            .bind(text(route.target_cluster.as_uuid()))
            .bind(route.priority)
            .bind(route.disabled)
            .bind(json!({"key": route.key}))
            .execute(self.pool())
            .await
            .map(|_| ())
            .map_err(db)
    }

    pub async fn get_route(
        &self,
        id: kitsunebi_domain::RouteId,
    ) -> Result<Option<Route>, StorageError> {
        let Some(row) = sqlx::query(
            "SELECT id, cluster_id, priority, disabled, metadata FROM routes WHERE id = ?",
        )
        .bind(text(id.as_uuid()))
        .fetch_optional(self.pool())
        .await
        .map_err(db)?
        else {
            return Ok(None);
        };
        let metadata: Value = row.try_get("metadata").map_err(db)?;
        Ok(Some(Route {
            id,
            key: metadata
                .get("key")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            target_cluster: kitsunebi_domain::ClusterId::from_uuid(uuid(&row, "cluster_id")?),
            priority: row.try_get("priority").map_err(db)?,
            disabled: row.try_get("disabled").map_err(db)?,
        }))
    }

    pub async fn list_routes(
        &self,
        pool_id: kitsunebi_domain::ProxyPoolId,
    ) -> Result<Vec<Route>, StorageError> {
        let rows = sqlx::query("SELECT id, cluster_id, priority, disabled, metadata FROM routes WHERE pool_id = ? ORDER BY priority, id")
            .bind(text(pool_id.as_uuid()))
            .fetch_all(self.pool())
            .await
            .map_err(db)?;
        rows.iter()
            .map(|row| {
                let metadata: Value = row.try_get("metadata").map_err(db)?;
                Ok(Route {
                    id: kitsunebi_domain::RouteId::from_uuid(uuid(row, "id")?),
                    key: metadata
                        .get("key")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                    target_cluster: kitsunebi_domain::ClusterId::from_uuid(uuid(
                        row,
                        "cluster_id",
                    )?),
                    priority: row.try_get("priority").map_err(db)?,
                    disabled: row.try_get("disabled").map_err(db)?,
                })
            })
            .collect()
    }

    pub async fn update_route(
        &self,
        route: &Route,
        expected_version: u64,
    ) -> Result<(), StorageError> {
        let result = sqlx::query(
            "UPDATE routes SET cluster_id = ?, priority = ?, disabled = ?, metadata = ?, version = version + 1 WHERE id = ? AND version = ?",
        )
        .bind(text(route.target_cluster.as_uuid()))
        .bind(route.priority)
        .bind(route.disabled)
        .bind(json!({"key": route.key}))
        .bind(text(route.id.as_uuid()))
        .bind(expected_version)
        .execute(self.pool())
        .await
        .map_err(db)?;
        if result.rows_affected() == 0 {
            return Err(StorageError::Conflict { entity: "route" });
        }
        Ok(())
    }

    /// Read the persisted blockers that must be clear before service archive
    /// or purge.  This is deliberately a query over all ownership paths, not
    /// a projection of the requested plan.
    pub async fn retirement_safety(
        &self,
        service: kitsunebi_domain::ServiceId,
    ) -> Result<RetirementSafety, StorageError> {
        let service_id = text(service.as_uuid());
        let active_routes: i64 = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM routes r WHERE r.disabled = FALSE AND (r.service_id = ? OR r.cluster_id IN (SELECT c.id FROM clusters c WHERE c.service_id = ?)))")
            .bind(&service_id)
            .bind(&service_id)
            .fetch_one(self.pool())
            .await
            .map_err(db)?;
        let active_world_writers: i64 = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM world_writers ww JOIN worlds w ON w.id = ww.world_id JOIN clusters c ON c.id = w.cluster_id WHERE ww.active AND c.service_id = ?)")
            .bind(&service_id)
            .fetch_one(self.pool())
            .await
            .map_err(db)?;
        let active_execution_bindings: i64 = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM gameap_bindings b LEFT JOIN clusters c ON c.id = b.cluster_id LEFT JOIN worlds w ON w.id = b.world_id LEFT JOIN proxy_instances pi ON pi.id = b.proxy_instance_id LEFT JOIN routes r ON r.pool_id = pi.pool_id WHERE (b.service_id = ? OR c.service_id = ? OR w.cluster_id IN (SELECT id FROM clusters WHERE service_id = ?) OR r.service_id = ? OR r.cluster_id IN (SELECT id FROM clusters WHERE service_id = ?)) AND COALESCE(JSON_EXTRACT(b.metadata, '$.revoked'), FALSE) = FALSE)")
            .bind(&service_id)
            .bind(&service_id)
            .bind(&service_id)
            .bind(&service_id)
            .bind(&service_id)
            .fetch_one(self.pool())
            .await
            .map_err(db)?;
        let policy_rows = sqlx::query("SELECT p.policy FROM access_policies p JOIN services s ON s.access_policy_id = p.id WHERE s.id = ? UNION SELECT p.policy FROM access_policy_bindings b JOIN access_policies p ON p.id = b.policy_id WHERE b.service_id = ? UNION SELECT p.policy FROM access_policy_bindings b JOIN access_policies p ON p.id = b.policy_id JOIN clusters c ON c.id = b.cluster_id WHERE c.service_id = ?")
            .bind(&service_id)
            .bind(&service_id)
            .bind(&service_id)
            .fetch_all(self.pool())
            .await
            .map_err(db)?;
        let mut effective_access_grants = Vec::new();
        for row in policy_rows {
            let policy: Value = row.try_get("policy").map_err(db)?;
            let grants: Vec<AccessGrant> = serde_json::from_value(policy)
                .map_err(|error| invalid(format!("retirement access policy: {error}")))?;
            effective_access_grants.extend(grants);
        }
        Ok(RetirementSafety {
            active_routes: active_routes != 0,
            active_world_writers: active_world_writers != 0,
            active_execution_bindings: active_execution_bindings != 0,
            effective_access_grants,
        })
    }

    pub async fn create_artifact(&self, artifact: &Artifact) -> Result<(), StorageError> {
        sqlx::query(
            "INSERT INTO artifacts (id, kind, name, version, source, source_id, digest, filename, compatibility, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(text(artifact.id.as_uuid()))
        .bind(&artifact.kind)
        .bind(&artifact.name)
        .bind(&artifact.version)
        .bind(&artifact.source)
        .bind(&artifact.source_id)
        .bind(&artifact.digest)
        .bind(&artifact.filename)
        .bind(to_json(&artifact.compatibility)?)
        .bind(to_json(&artifact.metadata)?)
        .execute(self.pool())
        .await
        .map(|_| ())
        .map_err(db)
    }

    pub async fn get_artifact(
        &self,
        id: kitsunebi_domain::ArtifactId,
    ) -> Result<Option<Artifact>, StorageError> {
        sqlx::query("SELECT * FROM artifacts WHERE id = ?")
            .bind(text(id.as_uuid()))
            .fetch_optional(self.pool())
            .await
            .map_err(db)?
            .map(|row| row_artifact(&row))
            .transpose()
    }

    pub async fn list_artifacts(&self) -> Result<Vec<Artifact>, StorageError> {
        let rows = sqlx::query("SELECT * FROM artifacts ORDER BY name, version, id")
            .fetch_all(self.pool())
            .await
            .map_err(db)?;
        rows.iter().map(row_artifact).collect()
    }

    pub async fn update_artifact(
        &self,
        artifact: &Artifact,
        expected_version: u64,
    ) -> Result<(), StorageError> {
        let result = sqlx::query("UPDATE artifacts SET kind = ?, name = ?, artifact_version = ?, source = ?, source_id = ?, digest = ?, filename = ?, compatibility = ?, metadata = ?, version = version + 1 WHERE id = ? AND version = ?")
            .bind(&artifact.kind)
            .bind(&artifact.name)
            .bind(&artifact.version)
            .bind(&artifact.source)
            .bind(&artifact.source_id)
            .bind(&artifact.digest)
            .bind(&artifact.filename)
            .bind(to_json(&artifact.compatibility)?)
            .bind(to_json(&artifact.metadata)?)
            .bind(text(artifact.id.as_uuid()))
            .bind(expected_version)
            .execute(self.pool())
            .await
            .map_err(db)?;
        if result.rows_affected() == 0 {
            return Err(StorageError::Conflict { entity: "artifact" });
        }
        Ok(())
    }

    pub async fn create_artifact_set(&self, set: &ArtifactSet) -> Result<(), StorageError> {
        let mut tx = self.pool().begin().await.map_err(db)?;
        sqlx::query("INSERT INTO artifact_sets (id, `key`, manifest_digest, manifest, metadata) VALUES (?, ?, ?, ?, ?)")
            .bind(text(set.id.as_uuid()))
            .bind(text(set.id.as_uuid()))
            .bind("")
            .bind(json!({"artifacts": set.artifacts.iter().map(|id| text(id.as_uuid())).collect::<Vec<_>>() }))
            .bind(json!({}))
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        for artifact in &set.artifacts {
            sqlx::query(
                "INSERT INTO artifact_set_items (artifact_set_id, artifact_id) VALUES (?, ?)",
            )
            .bind(text(set.id.as_uuid()))
            .bind(text(artifact.as_uuid()))
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        }
        tx.commit().await.map_err(db)
    }

    async fn artifact_ids(
        &self,
        set_id: kitsunebi_domain::ArtifactSetId,
    ) -> Result<Vec<Uuid>, StorageError> {
        sqlx::query("SELECT artifact_id FROM artifact_set_items WHERE artifact_set_id = ? ORDER BY artifact_id")
            .bind(text(set_id.as_uuid()))
            .fetch_all(self.pool())
            .await
            .map_err(db)?
            .iter()
            .map(|row| uuid(row, "artifact_id"))
            .collect()
    }

    pub async fn get_artifact_set(
        &self,
        id: kitsunebi_domain::ArtifactSetId,
    ) -> Result<Option<ArtifactSet>, StorageError> {
        let Some(row) = sqlx::query("SELECT * FROM artifact_sets WHERE id = ?")
            .bind(text(id.as_uuid()))
            .fetch_optional(self.pool())
            .await
            .map_err(db)?
        else {
            return Ok(None);
        };
        row_artifact_set(&row, self.artifact_ids(id).await?).map(Some)
    }

    pub async fn list_artifact_sets(&self) -> Result<Vec<ArtifactSet>, StorageError> {
        let rows = sqlx::query("SELECT * FROM artifact_sets ORDER BY `key`, id")
            .fetch_all(self.pool())
            .await
            .map_err(db)?;
        let mut sets = Vec::with_capacity(rows.len());
        for row in rows {
            let id = kitsunebi_domain::ArtifactSetId::from_uuid(uuid(&row, "id")?);
            sets.push(row_artifact_set(&row, self.artifact_ids(id).await?)?);
        }
        Ok(sets)
    }

    pub async fn update_artifact_set(
        &self,
        set: &ArtifactSet,
        expected_version: u64,
    ) -> Result<(), StorageError> {
        let mut tx = self.pool().begin().await.map_err(db)?;
        let result = sqlx::query("UPDATE artifact_sets SET manifest = ?, version = version + 1 WHERE id = ? AND version = ?")
            .bind(json!({"artifacts": set.artifacts.iter().map(|id| text(id.as_uuid())).collect::<Vec<_>>() }))
            .bind(text(set.id.as_uuid()))
            .bind(expected_version)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        if result.rows_affected() == 0 {
            return Err(StorageError::Conflict {
                entity: "artifact set",
            });
        }
        sqlx::query("DELETE FROM artifact_set_items WHERE artifact_set_id = ?")
            .bind(text(set.id.as_uuid()))
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        for artifact in &set.artifacts {
            sqlx::query(
                "INSERT INTO artifact_set_items (artifact_set_id, artifact_id) VALUES (?, ?)",
            )
            .bind(text(set.id.as_uuid()))
            .bind(text(artifact.as_uuid()))
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        }
        tx.commit().await.map_err(db)
    }

    pub async fn create_config_baseline(
        &self,
        baseline: &ConfigBaseline,
    ) -> Result<(), StorageError> {
        baseline.validate().map_err(StorageError::Domain)?;
        sqlx::query("INSERT INTO config_baselines (id, `key`, manifest_digest, manifest, metadata) VALUES (?, ?, ?, ?, ?)")
            .bind(text(baseline.id.as_uuid()))
            .bind(text(baseline.id.as_uuid()))
            .bind(&baseline.digest)
            .bind(json!({"digest": baseline.digest, "files": baseline.files}))
            .bind(json!({}))
            .execute(self.pool())
            .await
            .map(|_| ())
            .map_err(db)
    }

    pub async fn get_config_baseline(
        &self,
        id: kitsunebi_domain::ConfigBaselineId,
    ) -> Result<Option<ConfigBaseline>, StorageError> {
        sqlx::query("SELECT * FROM config_baselines WHERE id = ?")
            .bind(text(id.as_uuid()))
            .fetch_optional(self.pool())
            .await
            .map_err(db)?
            .map(|row| row_config_baseline(&row))
            .transpose()
    }

    pub async fn list_config_baselines(&self) -> Result<Vec<ConfigBaseline>, StorageError> {
        let rows = sqlx::query("SELECT * FROM config_baselines ORDER BY `key`, id")
            .fetch_all(self.pool())
            .await
            .map_err(db)?;
        rows.iter().map(row_config_baseline).collect()
    }

    /// Resolve the current configuration baseline for an opaque execution
    /// reference through its persisted binding and the owning cluster's
    /// current immutable revision. The subquery returns baseline ids rather
    /// than manifest rows so a proxy binding that happens to join multiple
    /// routes cannot duplicate an otherwise valid result.
    pub async fn get_config_baseline_for_execution_unit(
        &self,
        execution_unit_ref: &str,
    ) -> Result<Option<ConfigBaseline>, StorageError> {
        if execution_unit_ref.trim().is_empty() {
            return Err(invalid("execution unit reference"));
        }
        let rows = sqlx::query(
            "SELECT cb.* FROM config_baselines cb WHERE cb.id IN (SELECT DISTINCT r.config_baseline_id FROM gameap_bindings b JOIN clusters c ON c.current_revision_id IS NOT NULL JOIN cluster_revisions r ON r.id = c.current_revision_id LEFT JOIN services s ON s.id = b.service_id LEFT JOIN worlds w ON w.id = b.world_id LEFT JOIN proxy_instances pi ON pi.id = b.proxy_instance_id LEFT JOIN routes pr ON pr.pool_id = pi.pool_id AND pr.cluster_id = c.id WHERE b.execution_unit_ref = ? AND (b.cluster_id = c.id OR s.current_cluster_id = c.id OR w.cluster_id = c.id OR pr.cluster_id = c.id))",
        )
        .bind(execution_unit_ref)
        .fetch_all(self.pool())
        .await
        .map_err(db)?;
        if rows.len() > 1 {
            return Err(StorageError::Conflict {
                entity: "execution config baseline",
            });
        }
        rows.first().map(row_config_baseline).transpose()
    }

    /// Resolve a baseline through one persisted binding, the owning cluster's
    /// current immutable revision, and that revision's manifest. The query is
    /// deliberately binding-id based so an opaque provider reference cannot
    /// select an unrelated service or revision.
    pub async fn get_config_baseline_for_binding(
        &self,
        binding_id: kitsunebi_domain::BindingId,
    ) -> Result<Option<ConfigBaseline>, StorageError> {
        let rows = sqlx::query(
            "SELECT DISTINCT cb.* FROM gameap_bindings b JOIN clusters c ON c.current_revision_id IS NOT NULL JOIN cluster_revisions r ON r.id = c.current_revision_id JOIN config_baselines cb ON cb.id = r.config_baseline_id LEFT JOIN services s ON s.id = b.service_id LEFT JOIN worlds w ON w.id = b.world_id LEFT JOIN proxy_instances pi ON pi.id = b.proxy_instance_id LEFT JOIN routes pr ON pr.pool_id = pi.pool_id AND pr.cluster_id = c.id WHERE b.id = ? AND (b.cluster_id = c.id OR s.current_cluster_id = c.id OR w.cluster_id = c.id OR pr.cluster_id = c.id)",
        )
        .bind(text(binding_id.as_uuid()))
        .fetch_all(self.pool())
        .await
        .map_err(db)?;
        if rows.len() > 1 {
            return Err(StorageError::Conflict {
                entity: "binding config baseline",
            });
        }
        rows.first().map(row_config_baseline).transpose()
    }

    pub async fn update_config_baseline(
        &self,
        baseline: &ConfigBaseline,
        expected_version: u64,
    ) -> Result<(), StorageError> {
        baseline.validate().map_err(StorageError::Domain)?;
        let result = sqlx::query("UPDATE config_baselines SET manifest_digest = ?, manifest = ?, version = version + 1 WHERE id = ? AND version = ?")
            .bind(&baseline.digest)
            .bind(json!({"digest": baseline.digest, "files": baseline.files}))
            .bind(text(baseline.id.as_uuid()))
            .bind(expected_version)
            .execute(self.pool())
            .await
            .map_err(db)?;
        if result.rows_affected() == 0 {
            return Err(StorageError::Conflict {
                entity: "config baseline",
            });
        }
        Ok(())
    }

    pub async fn create_endpoint(&self, endpoint: &ExternalEndpoint) -> Result<(), StorageError> {
        sqlx::query("INSERT INTO external_endpoints (id, `key`, kind, logical_hostname, port, `role`, metadata) VALUES (?, ?, ?, ?, ?, ?, ?)")
            .bind(text(endpoint.id.as_uuid()))
            .bind(&endpoint.key)
            .bind(&endpoint.kind)
            .bind(&endpoint.logical_hostname)
            .bind(endpoint.port)
            .bind(&endpoint.role)
            .bind(to_json(&endpoint.metadata)?)
            .execute(self.pool())
            .await
            .map(|_| ())
            .map_err(db)
    }

    pub async fn get_endpoint(
        &self,
        id: kitsunebi_domain::EndpointId,
    ) -> Result<Option<ExternalEndpoint>, StorageError> {
        sqlx::query("SELECT * FROM external_endpoints WHERE id = ?")
            .bind(text(id.as_uuid()))
            .fetch_optional(self.pool())
            .await
            .map_err(db)?
            .map(|row| row_endpoint(&row))
            .transpose()
    }

    pub async fn list_endpoints(&self) -> Result<Vec<ExternalEndpoint>, StorageError> {
        let rows = sqlx::query("SELECT * FROM external_endpoints ORDER BY `key`, id")
            .fetch_all(self.pool())
            .await
            .map_err(db)?;
        rows.iter().map(row_endpoint).collect()
    }

    pub async fn update_endpoint(
        &self,
        endpoint: &ExternalEndpoint,
        expected_version: u64,
    ) -> Result<(), StorageError> {
        let result = sqlx::query("UPDATE external_endpoints SET `key` = ?, kind = ?, logical_hostname = ?, port = ?, `role` = ?, metadata = ?, version = version + 1 WHERE id = ? AND version = ?")
            .bind(&endpoint.key)
            .bind(&endpoint.kind)
            .bind(&endpoint.logical_hostname)
            .bind(endpoint.port)
            .bind(&endpoint.role)
            .bind(to_json(&endpoint.metadata)?)
            .bind(text(endpoint.id.as_uuid()))
            .bind(expected_version)
            .execute(self.pool())
            .await
            .map_err(db)?;
        if result.rows_affected() == 0 {
            return Err(StorageError::Conflict {
                entity: "external endpoint",
            });
        }
        Ok(())
    }

    pub async fn create_endpoint_binding(
        &self,
        binding: &EndpointBinding,
    ) -> Result<(), StorageError> {
        binding.validate().map_err(StorageError::Domain)?;
        let revision_cluster: Option<Uuid> =
            sqlx::query_scalar("SELECT cluster_id FROM cluster_revisions WHERE id = ?")
                .bind(text(binding.revision_id.as_uuid()))
                .fetch_optional(self.pool())
                .await
                .map_err(db)?
                .map(|value: String| Uuid::parse_str(&value))
                .transpose()
                .map_err(|error| invalid(format!("endpoint binding cluster: {error}")))?;
        if revision_cluster != Some(binding.cluster_id.as_uuid()) {
            return Err(StorageError::Conflict {
                entity: "endpoint binding cluster",
            });
        }
        sqlx::query("INSERT INTO endpoint_bindings (id, revision_id, endpoint_id, cluster_id, binding_key, metadata) VALUES (?, ?, ?, ?, ?, ?)")
            .bind(text(binding.id.as_uuid()))
            .bind(text(binding.revision_id.as_uuid()))
            .bind(text(binding.endpoint_id.as_uuid()))
            .bind(text(binding.cluster_id.as_uuid()))
            .bind(&binding.binding_key)
            .bind(to_json(&binding.metadata)?)
            .execute(self.pool())
            .await
            .map(|_| ())
            .map_err(db)
    }

    pub async fn get_endpoint_binding(
        &self,
        id: kitsunebi_domain::BindingId,
    ) -> Result<Option<EndpointBinding>, StorageError> {
        sqlx::query(
            "SELECT id, endpoint_id, revision_id, cluster_id, binding_key, metadata FROM endpoint_bindings WHERE id = ?",
        )
        .bind(text(id.as_uuid()))
        .fetch_optional(self.pool())
        .await
        .map_err(db)?
        .map(|row| row_binding(&row))
        .transpose()
    }

    pub async fn list_endpoint_bindings(
        &self,
        revision_id: kitsunebi_domain::RevisionId,
    ) -> Result<Vec<EndpointBinding>, StorageError> {
        let rows = sqlx::query("SELECT id, endpoint_id, revision_id, cluster_id, binding_key, metadata FROM endpoint_bindings WHERE revision_id = ? ORDER BY id")
            .bind(text(revision_id.as_uuid()))
            .fetch_all(self.pool())
            .await
            .map_err(db)?;
        rows.iter().map(row_binding).collect()
    }

    /// Activate endpoint bindings with an explicit cluster version and
    /// revision CAS. Callers that observed the cluster as part of a plan use
    /// this form so a concurrent revision cannot be mistaken for success.
    pub async fn activate_endpoint_bindings_at_version(
        &self,
        expected: &EndpointBinding,
        target: &EndpointBinding,
        expected_cluster_version: u64,
    ) -> Result<(), StorageError> {
        let mut tx = self.pool().begin().await.map_err(db)?;
        let rows = sqlx::query("SELECT b.id, b.cluster_id, b.endpoint_id, b.revision_id, b.binding_key, c.current_revision_id, c.version AS cluster_version FROM endpoint_bindings b JOIN clusters c ON c.id = b.cluster_id WHERE b.id IN (?, ?) FOR UPDATE")
            .bind(text(expected.id.as_uuid()))
            .bind(text(target.id.as_uuid()))
            .fetch_all(&mut *tx)
            .await
            .map_err(db)?;
        if rows.len() != 2 {
            return Err(StorageError::NotFound {
                entity: "endpoint binding",
            });
        }
        let expected_row = rows
            .iter()
            .find(|row| uuid(row, "id").ok() == Some(expected.id.as_uuid()))
            .ok_or(StorageError::NotFound {
                entity: "expected endpoint binding",
            })?;
        let target_row = rows
            .iter()
            .find(|row| uuid(row, "id").ok() == Some(target.id.as_uuid()))
            .ok_or(StorageError::NotFound {
                entity: "target endpoint binding",
            })?;
        let expected_cluster =
            kitsunebi_domain::ClusterId::from_uuid(uuid(expected_row, "cluster_id")?);
        let target_cluster =
            kitsunebi_domain::ClusterId::from_uuid(uuid(target_row, "cluster_id")?);
        let expected_revision =
            kitsunebi_domain::RevisionId::from_uuid(uuid(expected_row, "revision_id")?);
        let target_revision =
            kitsunebi_domain::RevisionId::from_uuid(uuid(target_row, "revision_id")?);
        let current_revision = uuid_opt(expected_row, "current_revision_id")?
            .map(kitsunebi_domain::RevisionId::from_uuid);
        let current_version: u64 = expected_row.try_get("cluster_version").map_err(db)?;
        let expected_key: String = expected_row.try_get("binding_key").map_err(db)?;
        let target_key: String = target_row.try_get("binding_key").map_err(db)?;
        if expected_cluster != target_cluster
            || expected_cluster != expected.cluster_id
            || expected_revision != expected.revision_id
            || target_revision != target.revision_id
            || expected_key != expected.binding_key
            || target_key != target.binding_key
            || expected.binding_key != target.binding_key
            || current_revision != Some(expected.revision_id)
            || current_version != expected_cluster_version
        {
            return Err(StorageError::Conflict {
                entity: "endpoint binding pair",
            });
        }
        let result = sqlx::query(
            "UPDATE clusters SET current_revision_id = ?, version = version + 1 WHERE id = ? AND current_revision_id = ? AND version = ?",
        )
        .bind(text(target.revision_id.as_uuid()))
        .bind(text(expected_cluster.as_uuid()))
        .bind(text(expected.revision_id.as_uuid()))
        .bind(expected_cluster_version)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        if result.rows_affected() != 1 {
            return Err(StorageError::Conflict {
                entity: "cluster revision",
            });
        }
        tx.commit().await.map_err(db)
    }

    pub async fn rollback_endpoint_bindings_at_version(
        &self,
        cluster_id: kitsunebi_domain::ClusterId,
        expected_binding: kitsunebi_domain::BindingId,
        target_binding: kitsunebi_domain::BindingId,
        expected_cluster_version: u64,
    ) -> Result<(), StorageError> {
        let mut tx = self.pool().begin().await.map_err(db)?;
        let row = sqlx::query(
            "SELECT current_revision_id, version FROM clusters WHERE id = ? FOR UPDATE",
        )
        .bind(text(cluster_id.as_uuid()))
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?
        .ok_or(StorageError::NotFound { entity: "cluster" })?;
        let current_revision =
            uuid_opt(&row, "current_revision_id")?.map(kitsunebi_domain::RevisionId::from_uuid);
        let current_version: u64 = row.try_get("version").map_err(db)?;
        if current_version != expected_cluster_version {
            return Err(StorageError::Conflict {
                entity: "cluster revision",
            });
        }
        let bindings = sqlx::query("SELECT id, cluster_id, revision_id, binding_key FROM endpoint_bindings WHERE id IN (?, ?) FOR UPDATE")
            .bind(text(expected_binding.as_uuid()))
            .bind(text(target_binding.as_uuid()))
            .fetch_all(&mut *tx)
            .await
            .map_err(db)?;
        if bindings.len() != 2 {
            return Err(StorageError::NotFound {
                entity: "endpoint binding",
            });
        }
        let old = bindings
            .iter()
            .find(|row| uuid(row, "id").ok() == Some(expected_binding.as_uuid()))
            .ok_or(StorageError::NotFound {
                entity: "expected endpoint binding",
            })?;
        let new = bindings
            .iter()
            .find(|row| uuid(row, "id").ok() == Some(target_binding.as_uuid()))
            .ok_or(StorageError::NotFound {
                entity: "target endpoint binding",
            })?;
        let old_cluster = kitsunebi_domain::ClusterId::from_uuid(uuid(old, "cluster_id")?);
        let new_cluster = kitsunebi_domain::ClusterId::from_uuid(uuid(new, "cluster_id")?);
        let old_revision = kitsunebi_domain::RevisionId::from_uuid(uuid(old, "revision_id")?);
        let target_revision = kitsunebi_domain::RevisionId::from_uuid(uuid(new, "revision_id")?);
        let old_key: String = old.try_get("binding_key").map_err(db)?;
        let new_key: String = new.try_get("binding_key").map_err(db)?;
        if old_cluster != cluster_id
            || new_cluster != cluster_id
            || old_key != new_key
            || current_revision != Some(target_revision)
        {
            return Err(StorageError::Conflict {
                entity: "endpoint binding pair",
            });
        }
        if old_revision == target_revision {
            tx.commit().await.map_err(db)?;
            return Ok(());
        }
        let result = sqlx::query(
            "UPDATE clusters SET current_revision_id = ?, version = version + 1 WHERE id = ? AND current_revision_id = ? AND version = ?",
        )
        .bind(text(old_revision.as_uuid()))
        .bind(text(cluster_id.as_uuid()))
        .bind(text(target_revision.as_uuid()))
        .bind(expected_cluster_version)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        if result.rows_affected() != 1 {
            return Err(StorageError::Conflict {
                entity: "cluster revision",
            });
        }
        tx.commit().await.map_err(db)
    }

    pub async fn register_actor_identity(
        &self,
        actor: kitsunebi_domain::ActorId,
        kind: ActorKind,
        subject: &str,
        service: Option<kitsunebi_domain::ServiceId>,
    ) -> Result<(), StorageError> {
        if subject.trim().is_empty()
            || (matches!(kind, ActorKind::Browser) && service.is_some())
            || (matches!(kind, ActorKind::Service) && service.is_none())
        {
            return Err(invalid("actor identity mapping"));
        }
        sqlx::query(
            "INSERT INTO actor_identities (actor_id, kind, subject, service_id) VALUES (?, ?, ?, ?)",
        )
        .bind(text(actor.as_uuid()))
        .bind(kind.as_str())
        .bind(subject.trim())
        .bind(service.map(|id| text(id.as_uuid())))
        .execute(self.pool())
        .await
        .map(|_| ())
        .map_err(|error| {
            if is_duplicate_key(&error) {
                StorageError::Conflict {
                    entity: "actor identity",
                }
            } else {
                db(error)
            }
        })
    }

    pub async fn actor_identity(
        &self,
        actor: kitsunebi_domain::ActorId,
    ) -> Result<Option<ActorIdentity>, StorageError> {
        let row = sqlx::query(
            "SELECT actor_id, kind, subject, service_id FROM actor_identities WHERE actor_id = ?",
        )
        .bind(text(actor.as_uuid()))
        .fetch_optional(self.pool())
        .await
        .map_err(db)?;
        row.map(|row| {
            let kind = match row.try_get::<String, _>("kind").map_err(db)?.as_str() {
                "browser" => ActorKind::Browser,
                "service" => ActorKind::Service,
                value => return Err(invalid(format!("actor kind: {value}"))),
            };
            let service_id =
                uuid_opt(&row, "service_id")?.map(kitsunebi_domain::ServiceId::from_uuid);
            if (matches!(kind, ActorKind::Browser) && service_id.is_some())
                || (matches!(kind, ActorKind::Service) && service_id.is_none())
            {
                return Err(invalid("actor identity mapping"));
            }
            let subject: String = row.try_get("subject").map_err(db)?;
            if subject.trim().is_empty() {
                return Err(invalid("actor identity subject"));
            }
            Ok(ActorIdentity {
                actor_id: kitsunebi_domain::ActorId::from_uuid(uuid(&row, "actor_id")?),
                kind,
                subject,
                service_id,
            })
        })
        .transpose()
    }

    async fn require_actor_identity(
        &self,
        actor: kitsunebi_domain::ActorId,
    ) -> Result<ActorIdentity, StorageError> {
        self.actor_identity(actor)
            .await?
            .ok_or(StorageError::NotFound {
                entity: "actor identity",
            })
    }

    pub async fn create_access_policy(&self, policy: &AccessPolicy) -> Result<(), StorageError> {
        sqlx::query("INSERT INTO access_policies (id, `key`, policy) VALUES (?, ?, ?)")
            .bind(text(policy.id.as_uuid()))
            .bind(text(policy.id.as_uuid()))
            .bind(to_json(&policy.grants)?)
            .execute(self.pool())
            .await
            .map(|_| ())
            .map_err(db)
    }

    pub async fn get_access_policy(
        &self,
        id: kitsunebi_domain::PolicyId,
    ) -> Result<Option<AccessPolicy>, StorageError> {
        sqlx::query("SELECT * FROM access_policies WHERE id = ?")
            .bind(text(id.as_uuid()))
            .fetch_optional(self.pool())
            .await
            .map_err(db)?
            .map(|row| row_policy(&row))
            .transpose()
    }

    pub async fn list_access_policies(&self) -> Result<Vec<AccessPolicy>, StorageError> {
        let rows = sqlx::query("SELECT * FROM access_policies ORDER BY `key`, id")
            .fetch_all(self.pool())
            .await
            .map_err(db)?;
        rows.iter().map(row_policy).collect()
    }

    pub async fn update_access_policy(
        &self,
        policy: &AccessPolicy,
        expected_version: u64,
    ) -> Result<(), StorageError> {
        let service_ids = sqlx::query(
            "SELECT service_id FROM services WHERE access_policy_id = ? UNION SELECT service_id FROM access_policy_bindings WHERE policy_id = ? AND service_id IS NOT NULL UNION SELECT c.service_id FROM access_policy_bindings b JOIN clusters c ON c.id = b.cluster_id WHERE b.policy_id = ?",
        )
        .bind(text(policy.id.as_uuid()))
        .bind(text(policy.id.as_uuid()))
        .bind(text(policy.id.as_uuid()))
        .fetch_all(self.pool())
        .await
        .map_err(db)?;
        let mut ids = service_ids
            .iter()
            .map(|row| uuid(row, "service_id").map(kitsunebi_domain::ServiceId::from_uuid))
            .collect::<Result<Vec<_>, _>>()?;
        ids.sort_unstable();
        ids.dedup();
        let service = ids.first().copied().ok_or(StorageError::Conflict {
            entity: "access policy owner",
        })?;
        if ids.len() != 1 {
            return Err(StorageError::Conflict {
                entity: "access policy owner",
            });
        }
        self.update_access_policy_for_service(policy, service, expected_version)
            .await
    }

    async fn validate_policy_grant_identities(
        tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
        grants: &[AccessGrant],
        service_id: kitsunebi_domain::ServiceId,
    ) -> Result<(), StorageError> {
        let mut actors = std::collections::BTreeSet::new();
        for grant in grants {
            if !actors.insert(grant.actor) {
                continue;
            }
            let row = sqlx::query(
                "SELECT kind, service_id FROM actor_identities WHERE actor_id = ? FOR UPDATE",
            )
            .bind(text(grant.actor.as_uuid()))
            .fetch_optional(&mut **tx)
            .await
            .map_err(db)?;
            let Some(row) = row else {
                return Err(StorageError::Conflict {
                    entity: "access policy actor identity",
                });
            };
            let kind: String = row.try_get("kind").map_err(db)?;
            let identity_service: Option<String> = row.try_get("service_id").map_err(db)?;
            let valid = policy_grant_identity_matches(
                kind.as_str(),
                identity_service.as_deref(),
                grant.service_scope,
                service_id,
            );
            if !valid
                || grants
                    .iter()
                    .filter(|candidate| candidate.actor == grant.actor)
                    .any(|candidate| candidate.service_scope != Some(service_id))
            {
                return Err(StorageError::Conflict {
                    entity: "access policy actor identity",
                });
            }
        }
        Ok(())
    }

    /// Update an access policy only while holding the target service lock and
    /// proving that the policy is exclusively attached to that service.
    pub async fn update_access_policy_for_service(
        &self,
        policy: &AccessPolicy,
        service_id: kitsunebi_domain::ServiceId,
        expected_version: u64,
    ) -> Result<(), StorageError> {
        if policy
            .grants
            .iter()
            .any(|grant| grant.service_scope != Some(service_id))
        {
            return Err(StorageError::Conflict {
                entity: "access policy service scope",
            });
        }
        let mut tx = self.pool().begin().await.map_err(db)?;
        let service_exists: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM services WHERE id = ? FOR UPDATE")
                .bind(text(service_id.as_uuid()))
                .fetch_optional(&mut *tx)
                .await
                .map_err(db)?;
        if service_exists.is_none() {
            return Err(StorageError::NotFound { entity: "service" });
        }
        let direct_owner: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM services WHERE id = ? AND access_policy_id = ? FOR UPDATE",
        )
        .bind(text(service_id.as_uuid()))
        .bind(text(policy.id.as_uuid()))
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?;
        let service_bindings = sqlx::query(
            "SELECT service_id FROM access_policy_bindings WHERE policy_id = ? AND service_id IS NOT NULL FOR UPDATE",
        )
        .bind(text(policy.id.as_uuid()))
        .fetch_all(&mut *tx)
        .await
        .map_err(db)?;
        let cluster_bindings = sqlx::query(
            "SELECT c.service_id FROM access_policy_bindings b JOIN clusters c ON c.id = b.cluster_id WHERE b.policy_id = ? FOR UPDATE",
        )
        .bind(text(policy.id.as_uuid()))
        .fetch_all(&mut *tx)
        .await
        .map_err(db)?;
        let mut owners = Vec::new();
        if direct_owner.is_some() {
            owners.push(service_id);
        }
        for row in service_bindings.iter().chain(cluster_bindings.iter()) {
            owners.push(kitsunebi_domain::ServiceId::from_uuid(uuid(
                row,
                "service_id",
            )?));
        }
        owners.sort_unstable();
        owners.dedup();
        if owners != [service_id] {
            return Err(StorageError::Conflict {
                entity: "access policy owner",
            });
        }
        Self::validate_policy_grant_identities(&mut tx, &policy.grants, service_id).await?;
        // Lock all policy rows before checking the account-wide invariants.
        // This serializes two concurrent updates that might otherwise both
        // remove the final administrator or final access grant.
        let rows = sqlx::query("SELECT id, policy, version FROM access_policies FOR UPDATE")
            .fetch_all(&mut *tx)
            .await
            .map_err(db)?;
        let policy_id = text(policy.id.as_uuid());
        let mut current = None;
        for row in &rows {
            if uuid(row, "id")? == policy.id.as_uuid() {
                current = Some(row);
                break;
            }
        }
        let current = current.ok_or(StorageError::Conflict {
            entity: "access policy",
        })?;
        let current_version: u64 = current.try_get("version").map_err(db)?;
        if current_version != expected_version {
            return Err(StorageError::Conflict {
                entity: "access policy",
            });
        }
        let current_grants: Vec<AccessGrant> = json_col(current, "policy")?;
        if current_grants
            .iter()
            .any(|grant| grant.service_scope != Some(service_id))
        {
            return Err(StorageError::Conflict {
                entity: "access policy service scope",
            });
        }
        Self::validate_policy_grant_identities(&mut tx, &current_grants, service_id).await?;
        let current_has_admin = current_grants
            .iter()
            .any(|grant| grant.role == kitsunebi_domain::Role::PlatformAdmin);
        let current_has_access = !current_grants.is_empty();
        let replacement_has_admin = policy.has_platform_admin();
        let replacement_has_access = policy.has_access_grant();
        let mut other_grants = Vec::new();
        for row in &rows {
            if uuid(row, "id")? != policy.id.as_uuid() {
                other_grants.push(json_col::<Vec<AccessGrant>>(row, "policy")?);
            }
        }
        let other_has_admin = other_grants
            .iter()
            .flatten()
            .any(|grant| grant.role == kitsunebi_domain::Role::PlatformAdmin);
        let other_has_access = other_grants.iter().flatten().next().is_some();
        if current_has_admin && !replacement_has_admin && !other_has_admin {
            return Err(StorageError::Domain(
                kitsunebi_domain::DomainError::LastPlatformAdministrator,
            ));
        }
        if current_has_access && !replacement_has_access && !other_has_access {
            return Err(StorageError::Domain(
                kitsunebi_domain::DomainError::LastAccessGrant,
            ));
        }
        let result = sqlx::query("UPDATE access_policies SET policy = ?, version = version + 1 WHERE id = ? AND version = ?")
            .bind(to_json(&policy.grants)?)
            .bind(&policy_id)
            .bind(expected_version)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        if result.rows_affected() == 0 {
            return Err(StorageError::Conflict {
                entity: "access policy",
            });
        }
        tx.commit().await.map_err(db)
    }

    /// Restore a previously observed policy under the same ownership and
    /// version guard used for ordinary policy updates.
    pub async fn rollback_access_policy_for_service(
        &self,
        policy: &AccessPolicy,
        service_id: kitsunebi_domain::ServiceId,
        expected_version: u64,
    ) -> Result<(), StorageError> {
        self.update_access_policy_for_service(policy, service_id, expected_version)
            .await
    }

    pub async fn bind_access_policy_to_service(
        &self,
        policy_id: kitsunebi_domain::PolicyId,
        service_id: kitsunebi_domain::ServiceId,
    ) -> Result<Uuid, StorageError> {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO access_policy_bindings (id, policy_id, service_id) VALUES (?, ?, ?)",
        )
        .bind(text(id))
        .bind(text(policy_id.as_uuid()))
        .bind(text(service_id.as_uuid()))
        .execute(self.pool())
        .await
        .map_err(db)?;
        Ok(id)
    }

    pub async fn create_change_session(
        &self,
        session: &ChangeSession,
        actor: kitsunebi_domain::ActorId,
        idempotency_key: &str,
        request_hash: &str,
    ) -> Result<(), StorageError> {
        if idempotency_key.trim().is_empty()
            || request_hash.len() != 64
            || !request_hash.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(invalid("change session request identity"));
        }
        self.require_actor_identity(actor).await?;
        sqlx::query("INSERT INTO change_sessions (id, actor, state, target, idempotency_key, request_hash, metadata) VALUES (?, ?, ?, ?, ?, ?, ?)")
            .bind(text(session.id.as_uuid()))
            .bind(text(actor.as_uuid()))
            .bind(change_state(&session.state))
            .bind(json!({"cluster_id": text(session.target_cluster.as_uuid())}))
            .bind(idempotency_key)
            .bind(request_hash)
            .bind(json!({}))
            .execute(self.pool())
            .await
            .map(|_| ())
            .map_err(db)
    }

    pub async fn get_change_session(
        &self,
        id: kitsunebi_domain::ChangeSessionId,
    ) -> Result<Option<ChangeSession>, StorageError> {
        sqlx::query("SELECT * FROM change_sessions WHERE id = ?")
            .bind(text(id.as_uuid()))
            .fetch_optional(self.pool())
            .await
            .map_err(db)?
            .map(|row| row_change_session(&row))
            .transpose()
    }

    /// Resolve a session only when the persisted actor owns it.  The actor
    /// column is part of the authorization boundary; callers must not infer
    /// ownership from the session's target cluster or a request payload.
    pub async fn get_change_session_for_actor(
        &self,
        id: kitsunebi_domain::ChangeSessionId,
        actor: kitsunebi_domain::ActorId,
    ) -> Result<Option<ChangeSession>, StorageError> {
        sqlx::query("SELECT * FROM change_sessions WHERE id = ? AND actor = ?")
            .bind(text(id.as_uuid()))
            .bind(text(actor.as_uuid()))
            .fetch_optional(self.pool())
            .await
            .map_err(db)?
            .map(|row| row_change_session(&row))
            .transpose()
    }

    pub async fn list_change_sessions(&self) -> Result<Vec<ChangeSession>, StorageError> {
        let rows = sqlx::query("SELECT * FROM change_sessions ORDER BY created_at, id")
            .fetch_all(self.pool())
            .await
            .map_err(db)?;
        rows.iter().map(row_change_session).collect()
    }

    /// Grant one active session/actor access to a CAS object. Digest, size,
    /// and classification are part of the authorization identity.
    pub async fn create_staged_content_ownership(
        &self,
        ownership: &StagedContentOwnership,
        expected_session_version: u64,
    ) -> Result<StagedContentOwnership, StorageError> {
        ownership.validate()?;
        if expected_session_version == 0 {
            return Err(invalid("staged content session version"));
        }
        let mut tx = self.pool().begin().await.map_err(db)?;
        let session = sqlx::query(
            "SELECT actor, state, version FROM change_sessions WHERE id = ? FOR UPDATE",
        )
        .bind(text(ownership.session_id.as_uuid()))
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?
        .ok_or(StorageError::NotFound {
            entity: "change session",
        })?;
        let session_actor: String = session.try_get("actor").map_err(db)?;
        if session_actor != text(ownership.actor.as_uuid()) {
            return Err(StorageError::NotFound {
                entity: "change session",
            });
        }
        let registered: Option<String> =
            sqlx::query_scalar("SELECT kind FROM actor_identities WHERE actor_id = ? FOR UPDATE")
                .bind(&session_actor)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db)?;
        if registered.is_none() {
            return Err(StorageError::NotFound {
                entity: "actor identity",
            });
        }
        let session_state: String = session.try_get("state").map_err(db)?;
        if !matches!(
            session_state.as_str(),
            "open" | "editing" | "ready" | "applying" | "verifying"
        ) {
            return Err(StorageError::Conflict {
                entity: "change session state",
            });
        }
        let session_version: u64 = session.try_get("version").map_err(db)?;
        if session_version != expected_session_version {
            return Err(StorageError::Conflict {
                entity: "change session version",
            });
        }
        let existing = sqlx::query("SELECT * FROM staged_content_ownership WHERE change_session_id = ? AND actor = ? AND idempotency_key = ? FOR UPDATE")
            .bind(text(ownership.session_id.as_uuid()))
            .bind(text(ownership.actor.as_uuid()))
            .bind(&ownership.idempotency_key)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?;
        if let Some(row) = existing {
            let existing = row_staged_content(&row)?;
            if existing.content != ownership.content
                || existing.classification != ownership.classification
                || existing.request_hash != ownership.request_hash
            {
                return Err(StorageError::StagedContentConflict);
            }
            tx.commit().await.map_err(db)?;
            return Ok(existing);
        }
        let result = sqlx::query("INSERT INTO staged_content_ownership (id, change_session_id, actor, digest, size_bytes, classification, idempotency_key, request_hash, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(text(ownership.id.as_uuid()))
            .bind(text(ownership.session_id.as_uuid()))
            .bind(text(ownership.actor.as_uuid()))
            .bind(&ownership.content.digest)
            .bind(ownership.content.size)
            .bind(classification(&ownership.classification))
            .bind(&ownership.idempotency_key)
            .bind(&ownership.request_hash)
            .bind(ownership.expires_at)
            .execute(&mut *tx)
            .await
            .map_err(|error| {
                if is_duplicate_key(&error) {
                    StorageError::StagedContentConflict
                } else {
                    db(error)
                }
            })?;
        if result.rows_affected() != 1 {
            return Err(StorageError::Conflict {
                entity: "staged content ownership",
            });
        }
        tx.commit().await.map_err(db)?;
        Ok(ownership.clone())
    }

    pub async fn get_staged_content_by_idempotency(
        &self,
        session: kitsunebi_domain::ChangeSessionId,
        actor: kitsunebi_domain::ActorId,
        idempotency_key: &str,
    ) -> Result<Option<StagedContentOwnership>, StorageError> {
        let row = sqlx::query("SELECT * FROM staged_content_ownership WHERE change_session_id = ? AND actor = ? AND idempotency_key = ?")
            .bind(text(session.as_uuid()))
            .bind(text(actor.as_uuid()))
            .bind(idempotency_key)
            .fetch_optional(self.pool())
            .await
            .map_err(db)?;
        row.as_ref().map(row_staged_content).transpose()
    }

    pub async fn get_staged_content_for_actor(
        &self,
        session: kitsunebi_domain::ChangeSessionId,
        actor: kitsunebi_domain::ActorId,
        content: &StagedContentRef,
        file_classification: FileClassification,
        required_until: u64,
    ) -> Result<Option<StagedContentOwnership>, StorageError> {
        content.validate()?;
        let row = sqlx::query("SELECT o.* FROM staged_content_ownership o JOIN change_sessions s ON s.id = o.change_session_id WHERE o.change_session_id = ? AND o.actor = ? AND o.digest = ? AND o.size_bytes = ? AND o.classification = ? AND o.expires_at >= ? AND s.state IN ('open','editing','ready','applying','verifying')")
            .bind(text(session.as_uuid()))
            .bind(text(actor.as_uuid()))
            .bind(&content.digest)
            .bind(content.size)
            .bind(classification(&file_classification))
            .bind(required_until)
            .fetch_optional(self.pool())
            .await
            .map_err(db)?;
        row.as_ref().map(row_staged_content).transpose()
    }

    pub async fn update_change_session(
        &self,
        session: &ChangeSession,
        expected_version: u64,
    ) -> Result<(), StorageError> {
        let result = sqlx::query("UPDATE change_sessions SET state = ?, target = ?, version = version + 1, updated_at = CURRENT_TIMESTAMP(6) WHERE id = ? AND version = ?")
            .bind(change_state(&session.state))
            .bind(json!({"cluster_id": text(session.target_cluster.as_uuid())}))
            .bind(text(session.id.as_uuid()))
            .bind(expected_version)
            .execute(self.pool())
            .await
            .map_err(db)?;
        if result.rows_affected() == 0 {
            return Err(StorageError::Conflict {
                entity: "change session",
            });
        }
        Ok(())
    }

    /// Insert a plan with its caller-supplied audit event in one transaction.
    /// A repeated session/key with the same request hash returns the original
    /// plan; changing the request under an existing key is a replay conflict.
    pub async fn create_plan_atomic(
        &self,
        plan: &PlanDescriptor,
        session_id: kitsunebi_domain::ChangeSessionId,
        idempotency_key: &str,
        request_hash: &str,
        audit: &AuditEvent,
    ) -> Result<PlanDescriptor, StorageError> {
        self.create_plan_idempotent_with_audit(
            plan,
            session_id,
            idempotency_key,
            request_hash,
            audit,
        )
        .await
    }

    async fn create_plan_idempotent_with_audit(
        &self,
        plan: &PlanDescriptor,
        session_id: kitsunebi_domain::ChangeSessionId,
        idempotency_key: &str,
        request_hash: &str,
        audit_event: &AuditEvent,
    ) -> Result<PlanDescriptor, StorageError> {
        plan.validate().map_err(StorageError::Domain)?;
        if idempotency_key.trim().is_empty()
            || request_hash.len() != 64
            || !request_hash.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(invalid("plan request identity"));
        }
        let mut tx = self.pool().begin().await.map_err(db)?;
        let session =
            sqlx::query("SELECT actor, target FROM change_sessions WHERE id = ? FOR UPDATE")
                .bind(text(session_id.as_uuid()))
                .fetch_optional(&mut *tx)
                .await
                .map_err(db)?
                .ok_or(StorageError::NotFound {
                    entity: "change session",
                })?;
        let registered: Option<String> =
            sqlx::query_scalar("SELECT kind FROM actor_identities WHERE actor_id = ? FOR UPDATE")
                .bind(session.try_get::<String, _>("actor").map_err(db)?)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db)?;
        if registered.is_none() {
            return Err(StorageError::NotFound {
                entity: "actor identity",
            });
        }
        let session_actor = uuid_from_value(session.try_get("actor").map_err(db)?, "actor")?;
        if session_actor != plan.actor.as_uuid() {
            return Err(StorageError::Conflict {
                entity: "change session actor",
            });
        }
        if let Some(existing) = sqlx::query(
            "SELECT * FROM plans WHERE change_session_id = ? AND idempotency_key = ? FOR UPDATE",
        )
        .bind(text(session_id.as_uuid()))
        .bind(idempotency_key)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?
        {
            let existing_hash: String = existing.try_get("request_hash").map_err(db)?;
            if existing_hash != request_hash {
                return Err(StorageError::IdempotencyConflict);
            }
            let original = row_plan(&existing)?;
            let audit_count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM audit_events WHERE action = 'change.plan' AND actor = ? AND plan_hash = ?",
            )
            .bind(text(original.actor.as_uuid()))
            .bind(&original.plan_hash)
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
            if audit_count != 1 {
                return Err(StorageError::Conflict {
                    entity: "plan audit event",
                });
            }
            tx.commit().await.map_err(db)?;
            return Ok(original);
        }
        let session_target: Value = session.try_get("target").map_err(db)?;
        let session_cluster = session_target
            .get("cluster_id")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid("change session target"))
            .and_then(|value| Uuid::parse_str(value).map_err(|error| invalid(error.to_string())))?;
        let session_cluster = kitsunebi_domain::ClusterId::from_uuid(session_cluster);
        let service_id: Uuid = sqlx::query_scalar("SELECT service_id FROM clusters WHERE id = ?")
            .bind(text(session_cluster.as_uuid()))
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?
            .ok_or(StorageError::NotFound { entity: "cluster" })?;
        let resolved_cluster = self
            .resolve_plan_target_cluster(
                plan.target,
                kitsunebi_domain::ServiceId::from_uuid(service_id),
            )
            .await?;
        if resolved_cluster != session_cluster {
            return Err(StorageError::Conflict {
                entity: "plan target cluster",
            });
        }
        audit_event.validate().map_err(StorageError::Domain)?;
        if audit_event.actor != plan.actor
            || audit_event.scope.service_id != kitsunebi_domain::ServiceId::from_uuid(service_id)
            || audit_event.scope.cluster_id != Some(session_cluster)
            || audit_event.plan_hash.as_deref() != Some(plan.plan_hash.as_str())
        {
            return Err(StorageError::Conflict {
                entity: "plan audit context",
            });
        }
        sqlx::query("INSERT INTO plans (id, change_session_id, plan_hash, idempotency_key, request_hash, actor, target, domain_revision, observed_execution_state, expected_file_hashes, expected_artifact_hashes, steps, backup_requirements, rollback_instructions, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(text(plan.id.as_uuid()))
            .bind(text(session_id.as_uuid()))
            .bind(&plan.plan_hash)
            .bind(idempotency_key)
            .bind(request_hash)
            .bind(text(plan.actor.as_uuid()))
            .bind(to_json(&plan.target)?)
            .bind(plan.domain_revision)
            .bind(to_json(&plan.observed_state_hashes)?)
            .bind(to_json(&plan.expected_file_hashes)?)
            .bind(to_json(&plan.expected_artifact_hashes)?)
            .bind(to_json(&plan.steps)?)
            .bind(to_json(&plan.backup_requirements)?)
            .bind(to_json(&plan.rollback_instructions)?)
            .bind(plan.expiry)
            .execute(&mut *tx)
            .await
            .map_err(db)?;

        {
            let audit = sqlx::query("INSERT INTO audit_events (event_id, actor, action, target, classification, source, service_id, cluster_id, world_id, execution_unit_ref, operation_id, result, before_revision, after_revision, plan_hash, request_id, evidence) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
                .bind(text(Uuid::new_v4()))
                .bind(text(audit_event.actor.as_uuid()))
                .bind(&audit_event.action)
                .bind(&audit_event.target)
                .bind(classification(&audit_event.classification))
                .bind(audit_event.source.as_str())
                .bind(text(audit_event.scope.service_id.as_uuid()))
                .bind(audit_event.scope.cluster_id.map(|id| text(id.as_uuid())))
                .bind(audit_event.scope.world_id.map(|id| text(id.as_uuid())))
                .bind(&audit_event.scope.execution_unit_ref)
                .bind(audit_event.scope.operation_id.map(|id| text(id.as_uuid())))
                .bind(audit_event.result.as_str())
                .bind(audit_event.before_revision)
                .bind(audit_event.after_revision)
                .bind(&audit_event.plan_hash)
                .bind(&audit_event.request_id)
                .bind(safe_evidence(audit_event)?)
                .execute(&mut *tx)
                .await
                .map_err(db)?;
            if audit.rows_affected() != 1 {
                return Err(StorageError::InvalidData(
                    "plan audit event was not inserted".into(),
                ));
            }
        }
        tx.commit().await.map_err(db)?;
        Ok(plan.clone())
    }

    pub async fn get_plan(
        &self,
        id: kitsunebi_domain::PlanId,
    ) -> Result<Option<PlanDescriptor>, StorageError> {
        sqlx::query("SELECT * FROM plans WHERE id = ?")
            .bind(text(id.as_uuid()))
            .fetch_optional(self.pool())
            .await
            .map_err(db)?
            .map(|row| row_plan(&row))
            .transpose()
    }

    pub async fn get_plan_session(
        &self,
        id: kitsunebi_domain::PlanId,
    ) -> Result<Option<kitsunebi_domain::ChangeSessionId>, StorageError> {
        sqlx::query("SELECT change_session_id FROM plans WHERE id = ?")
            .bind(text(id.as_uuid()))
            .fetch_optional(self.pool())
            .await
            .map_err(db)?
            .map(|row| {
                uuid(&row, "change_session_id").map(kitsunebi_domain::ChangeSessionId::from_uuid)
            })
            .transpose()
    }

    pub async fn list_plans(
        &self,
        session_id: kitsunebi_domain::ChangeSessionId,
    ) -> Result<Vec<PlanDescriptor>, StorageError> {
        let rows =
            sqlx::query("SELECT * FROM plans WHERE change_session_id = ? ORDER BY created_at, id")
                .bind(text(session_id.as_uuid()))
                .fetch_all(self.pool())
                .await
                .map_err(db)?;
        rows.iter().map(row_plan).collect()
    }

    pub async fn create_operation(
        &self,
        operation: &Operation,
        operation_key: &str,
        actor: kitsunebi_domain::ActorId,
    ) -> Result<(), StorageError> {
        self.create_idempotent_operation(operation, operation_key, actor, json!({}))
            .await
            .map(|_| ())
    }

    /// Insert an operation exactly once for an idempotency key. A replay with
    /// the same payload returns the original operation; a different payload is
    /// rejected rather than silently reusing the key.
    pub async fn create_idempotent_operation(
        &self,
        operation: &Operation,
        operation_key: &str,
        actor: kitsunebi_domain::ActorId,
        payload: Value,
    ) -> Result<Operation, StorageError> {
        self.require_actor_identity(actor).await?;
        let payload = operation_payload_with_plan(payload, operation.plan_id);
        let mut tx = self.pool().begin().await.map_err(db)?;
        if let Some(row) =
            sqlx::query("SELECT * FROM operations WHERE operation_key = ? FOR UPDATE")
                .bind(operation_key)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db)?
        {
            let existing: Value = row.try_get("payload").map_err(db)?;
            let existing_actor: String = row.try_get("actor").map_err(db)?;
            let existing_session: String = row.try_get("change_session_id").map_err(db)?;
            let existing_plan: String = row.try_get("plan_id").map_err(db)?;
            if existing_actor != text(actor.as_uuid())
                || existing_session != text(operation.session_id.as_uuid())
                || existing_plan != text(operation.plan_id.as_uuid())
                || existing != payload
            {
                return Err(StorageError::IdempotencyConflict);
            }
            let value = row_operation(&row)?;
            tx.commit().await.map_err(db)?;
            return Ok(value);
        }
        // Apply is the first place where a plan receives an operation id. A
        // second apply key must not be able to create another operation for
        // the same plan id, even when the requests race before either insert.
        if let Some(row) = sqlx::query("SELECT * FROM operations WHERE id = ? FOR UPDATE")
            .bind(text(operation.id.as_uuid()))
            .fetch_optional(&mut *tx)
            .await
            .map_err(db)?
        {
            let existing: Value = row.try_get("payload").map_err(db)?;
            let existing_actor: String = row.try_get("actor").map_err(db)?;
            let existing_session: String = row.try_get("change_session_id").map_err(db)?;
            let existing_plan: String = row.try_get("plan_id").map_err(db)?;
            let existing_key: String = row.try_get("operation_key").map_err(db)?;
            if existing_actor != text(actor.as_uuid())
                || existing_session != text(operation.session_id.as_uuid())
                || existing_plan != text(operation.plan_id.as_uuid())
                || existing_key != operation_key
                || existing != payload
            {
                return Err(StorageError::IdempotencyConflict);
            }
            let value = row_operation(&row)?;
            tx.commit().await.map_err(db)?;
            return Ok(value);
        }
        let insert = sqlx::query("INSERT INTO operations (id, plan_id, change_session_id, operation_key, kind, state, actor, payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(text(operation.id.as_uuid()))
            .bind(text(operation.plan_id.as_uuid()))
            .bind(text(operation.session_id.as_uuid()))
            .bind(operation_key)
            .bind("operation")
            .bind(operation_state(&operation.state))
            .bind(text(actor.as_uuid()))
            .bind(&payload)
            .execute(&mut *tx)
            .await;
        if let Err(error) = insert {
            if is_duplicate_key(&error) {
                // A concurrent insert may have won either the operation-key
                // or operation-id unique index. Read both identities under
                // the same transaction before deciding whether this is a
                // safe replay or a conflicting apply request.
                let row = sqlx::query(
                    "SELECT * FROM operations WHERE operation_key = ? OR id = ? FOR UPDATE",
                )
                .bind(operation_key)
                .bind(text(operation.id.as_uuid()))
                .fetch_optional(&mut *tx)
                .await
                .map_err(db)?;
                if let Some(row) = row {
                    let existing: Value = row.try_get("payload").map_err(db)?;
                    let existing_actor: String = row.try_get("actor").map_err(db)?;
                    let existing_session: String = row.try_get("change_session_id").map_err(db)?;
                    let existing_plan: String = row.try_get("plan_id").map_err(db)?;
                    let existing_key: String = row.try_get("operation_key").map_err(db)?;
                    if existing_actor == text(actor.as_uuid())
                        && existing_session == text(operation.session_id.as_uuid())
                        && existing_plan == text(operation.plan_id.as_uuid())
                        && existing_key == operation_key
                        && existing == payload
                    {
                        let value = row_operation(&row)?;
                        tx.commit().await.map_err(db)?;
                        return Ok(value);
                    }
                    return Err(StorageError::IdempotencyConflict);
                }
            }
            return Err(db(error));
        }
        tx.commit().await.map_err(db)?;
        Ok(operation.clone())
    }

    pub async fn get_operation(
        &self,
        id: kitsunebi_domain::OperationId,
    ) -> Result<Option<Operation>, StorageError> {
        sqlx::query("SELECT * FROM operations WHERE id = ?")
            .bind(text(id.as_uuid()))
            .fetch_optional(self.pool())
            .await
            .map_err(db)?
            .map(|row| row_operation(&row))
            .transpose()
    }

    pub async fn get_operation_for_plan(
        &self,
        plan: kitsunebi_domain::PlanId,
    ) -> Result<Option<Operation>, StorageError> {
        sqlx::query("SELECT * FROM operations WHERE plan_id = ?")
            .bind(text(plan.as_uuid()))
            .fetch_optional(self.pool())
            .await
            .map_err(db)?
            .map(|row| row_operation(&row))
            .transpose()
    }

    pub async fn list_operations(&self) -> Result<Vec<Operation>, StorageError> {
        let rows = sqlx::query("SELECT * FROM operations ORDER BY created_at, id")
            .fetch_all(self.pool())
            .await
            .map_err(db)?;
        rows.iter().map(row_operation).collect()
    }

    pub async fn update_operation(
        &self,
        operation: &Operation,
        expected_version: u64,
    ) -> Result<(), StorageError> {
        let mut tx = self.pool().begin().await.map_err(db)?;
        let session_id: Option<String> =
            sqlx::query_scalar("SELECT change_session_id FROM operations WHERE id = ? FOR UPDATE")
                .bind(text(operation.id.as_uuid()))
                .fetch_optional(&mut *tx)
                .await
                .map_err(db)?;
        let result = sqlx::query("UPDATE operations SET state = ?, version = version + 1, updated_at = CURRENT_TIMESTAMP(6) WHERE id = ? AND version = ?")
            .bind(operation_state(&operation.state))
            .bind(text(operation.id.as_uuid()))
            .bind(expected_version)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        if result.rows_affected() == 0 {
            return Err(StorageError::Conflict {
                entity: "operation",
            });
        }
        if let Some(session_id) = session_id {
            sync_session_state(&mut tx, &session_id, &operation.state).await?;
        }
        tx.commit().await.map_err(db)
    }

    pub async fn claim_operation(
        &self,
        operation_id: kitsunebi_domain::OperationId,
        owner: &str,
        lease_seconds: u64,
    ) -> Result<OperationLease, StorageError> {
        let micros = i64::try_from(lease_seconds)
            .ok()
            .and_then(|seconds| seconds.checked_mul(1_000_000))
            .ok_or_else(|| invalid("lease duration is too large"))?;
        let result = sqlx::query("UPDATE operations SET lease_owner = ?, lease_until = TIMESTAMPADD(MICROSECOND, ?, CURRENT_TIMESTAMP(6)), attempt = attempt + 1, version = version + 1 WHERE id = ? AND (lease_until IS NULL OR lease_until <= CURRENT_TIMESTAMP(6)) AND state NOT IN ('accepted', 'rolled_back')")
            .bind(owner)
            .bind(micros)
            .bind(text(operation_id.as_uuid()))
            .execute(self.pool())
            .await
            .map_err(db)?;
        if result.rows_affected() == 0 {
            if self.get_operation(operation_id).await?.is_none() {
                return Err(StorageError::NotFound {
                    entity: "operation",
                });
            }
            return Err(StorageError::LeaseUnavailable);
        }
        let row = sqlx::query("SELECT * FROM operations WHERE id = ?")
            .bind(text(operation_id.as_uuid()))
            .fetch_one(self.pool())
            .await
            .map_err(db)?;
        Ok(OperationLease {
            owner: owner.to_owned(),
            attempt: row.try_get("attempt").map_err(db)?,
            operation: row_operation(&row)?,
        })
    }

    pub async fn renew_operation_lease(
        &self,
        operation_id: kitsunebi_domain::OperationId,
        owner: &str,
        lease_seconds: u64,
    ) -> Result<(), StorageError> {
        let micros = i64::try_from(lease_seconds)
            .ok()
            .and_then(|seconds| seconds.checked_mul(1_000_000))
            .ok_or_else(|| invalid("lease duration is too large"))?;
        let result = sqlx::query("UPDATE operations SET lease_until = TIMESTAMPADD(MICROSECOND, ?, CURRENT_TIMESTAMP(6)), version = version + 1 WHERE id = ? AND lease_owner = ? AND lease_until > CURRENT_TIMESTAMP(6)")
            .bind(micros)
            .bind(text(operation_id.as_uuid()))
            .bind(owner)
            .execute(self.pool())
            .await
            .map_err(db)?;
        if result.rows_affected() == 0 {
            return Err(StorageError::LeaseUnavailable);
        }
        Ok(())
    }

    pub async fn mark_operation_state(
        &self,
        operation_id: kitsunebi_domain::OperationId,
        state: OperationState,
        owner: &str,
    ) -> Result<(), StorageError> {
        let mut tx = self.pool().begin().await.map_err(db)?;
        let session_id: Option<String> =
            sqlx::query_scalar("SELECT change_session_id FROM operations WHERE id = ? FOR UPDATE")
                .bind(text(operation_id.as_uuid()))
                .fetch_optional(&mut *tx)
                .await
                .map_err(db)?;
        let result = sqlx::query("UPDATE operations SET state = ?, version = version + 1, updated_at = CURRENT_TIMESTAMP(6) WHERE id = ? AND lease_owner = ? AND lease_until > CURRENT_TIMESTAMP(6) AND state = 'planned'")
            .bind(operation_state(&state))
            .bind(text(operation_id.as_uuid()))
            .bind(owner)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        if result.rows_affected() == 0 {
            return Err(StorageError::LeaseUnavailable);
        }
        if let Some(session_id) = session_id {
            sync_session_state(&mut tx, &session_id, &state).await?;
        }
        tx.commit().await.map_err(db)
    }

    pub async fn mark_operation_failed(
        &self,
        operation_id: kitsunebi_domain::OperationId,
        code: &str,
        evidence: &[String],
        owner: &str,
    ) -> Result<(), StorageError> {
        let mut tx = self.pool().begin().await.map_err(db)?;
        let session_id: Option<String> =
            sqlx::query_scalar("SELECT change_session_id FROM operations WHERE id = ? FOR UPDATE")
                .bind(text(operation_id.as_uuid()))
                .fetch_optional(&mut *tx)
                .await
                .map_err(db)?;
        let result = sqlx::query("UPDATE operations SET state = 'failed', result = ?, lease_owner = NULL, lease_until = NULL, version = version + 1, updated_at = CURRENT_TIMESTAMP(6) WHERE id = ? AND lease_owner = ? AND lease_until > CURRENT_TIMESTAMP(6)")
            .bind(json!({ "code": code, "evidence": evidence }))
            .bind(text(operation_id.as_uuid()))
            .bind(owner)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        if result.rows_affected() == 0 {
            return Err(StorageError::LeaseUnavailable);
        }
        if let Some(session_id) = session_id {
            sync_session_state(&mut tx, &session_id, &OperationState::Failed).await?;
        }
        tx.commit().await.map_err(db)
    }

    pub async fn complete_operation(
        &self,
        operation_id: kitsunebi_domain::OperationId,
        owner: &str,
        state: OperationState,
        result_payload: Value,
    ) -> Result<(), StorageError> {
        let mut tx = self.pool().begin().await.map_err(db)?;
        let row =
            sqlx::query("SELECT change_session_id, state FROM operations WHERE id = ? FOR UPDATE")
                .bind(text(operation_id.as_uuid()))
                .fetch_optional(&mut *tx)
                .await
                .map_err(db)?;
        let (session_id, current_state): (Option<String>, Option<String>) = if let Some(row) = row {
            (
                Some(row.try_get::<String, _>("change_session_id").map_err(db)?),
                Some(row.try_get::<String, _>("state").map_err(db)?),
            )
        } else {
            (None, None)
        };
        let result = sqlx::query("UPDATE operations SET state = ?, result = ?, lease_owner = NULL, lease_until = NULL, version = version + 1, updated_at = CURRENT_TIMESTAMP(6) WHERE id = ? AND lease_owner = ? AND lease_until > CURRENT_TIMESTAMP(6) AND state IN ('applying', 'failed')")
            .bind(operation_state(&state))
            .bind(result_payload)
            .bind(text(operation_id.as_uuid()))
            .bind(owner)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        if result.rows_affected() == 0 {
            return Err(StorageError::LeaseUnavailable);
        }
        if current_state.as_deref() == Some("failed") {
            if state != OperationState::RolledBack {
                return Err(StorageError::Conflict {
                    entity: "failed operation transition",
                });
            }
            let evidence_count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM operation_steps WHERE operation_id = ? AND execution_evidence IS NOT NULL",
            )
            .bind(text(operation_id.as_uuid()))
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
            if evidence_count == 0 {
                return Err(StorageError::Conflict {
                    entity: "failed operation evidence",
                });
            }
            if let Some(session_id) = session_id {
                let session_result = sqlx::query(
                    "UPDATE change_sessions SET state = 'rolled_back', version = version + 1, updated_at = CURRENT_TIMESTAMP(6) WHERE id = ? AND state = 'aborted'",
                )
                .bind(session_id)
                .execute(&mut *tx)
                .await
                .map_err(db)?;
                if session_result.rows_affected() != 1 {
                    return Err(StorageError::Conflict {
                        entity: "change session rollback",
                    });
                }
            }
        } else if let Some(session_id) = session_id {
            sync_session_state(&mut tx, &session_id, &state).await?;
        }
        tx.commit().await.map_err(db)
    }

    pub async fn list_step_evidence(
        &self,
        operation_id: kitsunebi_domain::OperationId,
    ) -> Result<Vec<StepEvidence>, StorageError> {
        let rows = sqlx::query(
            "SELECT sequence, state_hash, result, execution_evidence FROM operation_steps WHERE operation_id = ? ORDER BY sequence",
        )
        .bind(text(operation_id.as_uuid()))
        .fetch_all(self.pool())
        .await
        .map_err(db)?;
        rows.into_iter()
            .map(|row| {
                Ok(StepEvidence {
                    sequence: row.try_get("sequence").map_err(db)?,
                    state_hash: row.try_get("state_hash").map_err(db)?,
                    result: row.try_get("result").map_err(db)?,
                    execution: row
                        .try_get::<Option<Value>, _>("execution_evidence")
                        .map_err(db)?
                        .map(serde_json::from_value)
                        .transpose()
                        .map_err(|_| StorageError::InvalidData("step execution evidence".into()))?,
                })
            })
            .collect()
    }

    /// Atomically finish a verification/acceptance/rollback transition. The
    /// operation lock, expected state, active lease holder and owning session
    /// predicate all participate in the same transaction.
    pub async fn finish_operation_stage(
        &self,
        lease: &ApplicationOperationLease,
        session_id: kitsunebi_domain::ChangeSessionId,
        target: OperationState,
        evidence: Value,
    ) -> Result<Operation, StorageError> {
        let mut tx = self.pool().begin().await.map_err(db)?;
        let row = sqlx::query(
            "SELECT change_session_id, state, result, version FROM operations WHERE id = ? FOR UPDATE",
        )
        .bind(text(lease.operation.as_uuid()))
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?
        .ok_or(StorageError::NotFound {
            entity: "operation",
        })?;
        let operation_session: String = row.try_get("change_session_id").map_err(db)?;
        let operation_version: u64 = row.try_get("version").map_err(db)?;
        if operation_session != text(session_id.as_uuid()) {
            return Err(StorageError::Conflict {
                entity: "operation session",
            });
        }
        let current_state: String = row.try_get("state").map_err(db)?;
        let previous_result: Option<Value> = row.try_get("result").map_err(db)?;
        let expected_states: &[&str] = match target {
            OperationState::Verifying => &["verifying"],
            OperationState::Verified => &["verifying"],
            OperationState::Accepted => &["verified"],
            OperationState::RolledBack => &["applying", "verifying", "verified", "failed"],
            _ => {
                return Err(StorageError::InvalidData(
                    "invalid operation finish state".into(),
                ));
            }
        };
        if !expected_states.contains(&current_state.as_str()) {
            return Err(StorageError::Conflict {
                entity: "operation state",
            });
        }
        if current_state == "failed" && target == OperationState::RolledBack {
            let evidence_count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM operation_steps WHERE operation_id = ? AND execution_evidence IS NOT NULL",
            )
            .bind(text(lease.operation.as_uuid()))
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
            if evidence_count == 0 {
                return Err(StorageError::Conflict {
                    entity: "failed operation evidence",
                });
            }
        }
        let session_row =
            sqlx::query("SELECT state, version FROM change_sessions WHERE id = ? FOR UPDATE")
                .bind(&operation_session)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db)?
                .ok_or(StorageError::NotFound {
                    entity: "change session",
                })?;
        let session_state: String = session_row.try_get("state").map_err(db)?;
        let session_version: u64 = session_row.try_get("version").map_err(db)?;
        let expected_session_states: &[&str] = match target {
            OperationState::Verifying => &["verifying"],
            OperationState::Verified => &["verifying"],
            OperationState::Accepted => &["verifying"],
            OperationState::RolledBack => &["applying", "verifying", "aborted"],
            _ => &[],
        };
        if !expected_session_states.contains(&session_state.as_str()) {
            return Err(StorageError::Conflict {
                entity: "change session state",
            });
        }
        let result_payload = match target {
            OperationState::Verifying | OperationState::Verified => evidence,
            OperationState::Accepted => {
                let mut result = previous_result.unwrap_or_else(|| json!({}));
                let Some(fields) = result.as_object_mut() else {
                    return Err(StorageError::InvalidData(
                        "operation result is not an object".into(),
                    ));
                };
                fields.insert("accepted".into(), Value::Bool(true));
                Value::Object(fields.clone())
            }
            OperationState::RolledBack => {
                let mut result = previous_result.unwrap_or_else(|| json!({}));
                let Some(fields) = result.as_object_mut() else {
                    return Err(StorageError::InvalidData(
                        "operation result is not an object".into(),
                    ));
                };
                fields.insert("rolled_back".into(), Value::Bool(true));
                Value::Object(fields.clone())
            }
            _ => unreachable!("finish state validated above"),
        };
        // Rollback is terminal and has no caller-side release step. Clear its
        // lease in the same write; verification and acceptance retain theirs
        // until the application explicitly releases after the transition.
        let state_predicate = match expected_states.len() {
            1 => "state = ?",
            2 => "state IN (?, ?)",
            3 => "state IN (?, ?, ?)",
            4 => "state IN (?, ?, ?, ?)",
            _ => unreachable!("finish state has a bounded predecessor set"),
        };
        let lease_columns = if matches!(target, OperationState::RolledBack) {
            ", lease_owner = NULL, lease_until = NULL"
        } else {
            ""
        };
        let operation_update_sql = format!(
            "UPDATE operations SET state = ?, result = ?{lease_columns}, version = version + 1, updated_at = CURRENT_TIMESTAMP(6) WHERE id = ? AND lease_owner = ? AND lease_until > CURRENT_TIMESTAMP(6) AND {state_predicate} AND version = ?"
        );
        let mut operation_update = sqlx::query(&operation_update_sql)
            .bind(operation_state(&target))
            .bind(result_payload)
            .bind(text(lease.operation.as_uuid()))
            .bind(&lease.holder);
        for expected in expected_states {
            operation_update = operation_update.bind(*expected);
        }
        let operation_update = operation_update
            .bind(operation_version)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        if operation_update.rows_affected() != 1 {
            return Err(StorageError::LeaseUnavailable);
        }
        if matches!(target, OperationState::Verified) {
            tx.commit().await.map_err(db)?;
            return self
                .get_operation(lease.operation)
                .await?
                .ok_or(StorageError::NotFound {
                    entity: "operation",
                });
        }
        let next_session = operation_state(&target);
        let session_state_predicate = match expected_session_states.len() {
            1 => "state = ?",
            2 => "state IN (?, ?)",
            3 => "state IN (?, ?, ?)",
            _ => unreachable!("session finish state has a bounded predecessor set"),
        };
        let session_update_sql = format!(
            "UPDATE change_sessions SET state = ?, version = version + 1, updated_at = CURRENT_TIMESTAMP(6) WHERE id = ? AND {session_state_predicate} AND version = ?"
        );
        let mut session_update = sqlx::query(&session_update_sql)
            .bind(next_session)
            .bind(&operation_session);
        for expected in expected_session_states {
            session_update = session_update.bind(*expected);
        }
        let session_update = session_update
            .bind(session_version)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        if session_update.rows_affected() != 1 {
            return Err(StorageError::Conflict {
                entity: "change session",
            });
        }
        tx.commit().await.map_err(db)?;
        self.get_operation(lease.operation)
            .await?
            .ok_or(StorageError::NotFound {
                entity: "operation",
            })
    }

    pub async fn create_backup_reference(
        &self,
        backup: &BackupReference,
    ) -> Result<(), StorageError> {
        backup.validate().map_err(StorageError::Domain)?;
        sqlx::query("INSERT INTO backup_references (id, change_session_id, kind, target, provider, reference, manifest_digest, verified_at, required, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(text(backup.id.as_uuid()))
            .bind(text(backup.session_id.as_uuid()))
            .bind(backup_kind(backup.kind))
            .bind(to_json(&backup.target)?)
            .bind(&backup.provider)
            .bind(&backup.provider_reference)
            .bind(&backup.manifest_digest)
            .bind(backup.verified_at)
            .bind(backup.required)
            .bind(json!({}))
            .execute(self.pool())
            .await
            .map(|_| ())
            .map_err(db)
    }

    pub async fn get_backup_reference(
        &self,
        id: kitsunebi_domain::BackupReferenceId,
    ) -> Result<Option<BackupReference>, StorageError> {
        sqlx::query("SELECT * FROM backup_references WHERE id = ?")
            .bind(text(id.as_uuid()))
            .fetch_optional(self.pool())
            .await
            .map_err(db)?
            .map(|row| row_backup(&row))
            .transpose()
    }

    pub async fn list_backup_references(&self) -> Result<Vec<BackupReference>, StorageError> {
        let rows = sqlx::query("SELECT * FROM backup_references ORDER BY created_at, id")
            .fetch_all(self.pool())
            .await
            .map_err(db)?;
        rows.iter().map(row_backup).collect()
    }

    pub async fn update_backup_reference(
        &self,
        backup: &BackupReference,
        expected_version: u64,
    ) -> Result<(), StorageError> {
        backup.validate().map_err(StorageError::Domain)?;
        if expected_version == 0 {
            return Err(invalid("backup reference expected version"));
        }
        let result = sqlx::query("UPDATE backup_references SET kind = ?, target = ?, provider = ?, reference = ?, manifest_digest = ?, verified_at = ?, required = ?, version = version + 1 WHERE id = ? AND version = ?")
            .bind(backup_kind(backup.kind))
            .bind(to_json(&backup.target)?)
            .bind(&backup.provider)
            .bind(&backup.provider_reference)
            .bind(&backup.manifest_digest)
            .bind(backup.verified_at)
            .bind(backup.required)
            .bind(text(backup.id.as_uuid()))
            .bind(expected_version)
            .execute(self.pool())
            .await
            .map_err(db)?;
        if result.rows_affected() == 0 {
            return Err(StorageError::Conflict {
                entity: "backup reference",
            });
        }
        Ok(())
    }

    pub async fn append_lifecycle_decision(
        &self,
        service_id: kitsunebi_domain::ServiceId,
        from_state: &str,
        decision: &LifecycleDecision,
        actor: &str,
        reason: &str,
    ) -> Result<Uuid, StorageError> {
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO lifecycle_decisions (id, service_id, from_state, to_state, actor, reason) VALUES (?, ?, ?, ?, ?, ?)")
            .bind(text(id))
            .bind(text(service_id.as_uuid()))
            .bind(from_state)
            .bind(lifecycle_decision(decision))
            .bind(actor)
            .bind(reason)
            .execute(self.pool())
            .await
            .map_err(db)?;
        Ok(id)
    }

    pub async fn list_lifecycle_decisions(
        &self,
        service_id: kitsunebi_domain::ServiceId,
    ) -> Result<Vec<LifecycleDecisionRecord>, StorageError> {
        let rows = sqlx::query("SELECT id, service_id, from_state, to_state, actor, reason FROM lifecycle_decisions WHERE service_id = ? ORDER BY created_at, id")
            .bind(text(service_id.as_uuid()))
            .fetch_all(self.pool())
            .await
            .map_err(db)?;
        rows.iter()
            .map(|row| {
                Ok(LifecycleDecisionRecord {
                    id: uuid(row, "id")?,
                    service_id: kitsunebi_domain::ServiceId::from_uuid(uuid(row, "service_id")?),
                    from_state: row.try_get("from_state").map_err(db)?,
                    to_state: row.try_get("to_state").map_err(db)?,
                    actor: row.try_get("actor").map_err(db)?,
                    reason: row.try_get("reason").map_err(db)?,
                })
            })
            .collect()
    }

    pub async fn create_gameap_binding(
        &self,
        binding: &GameAPBinding,
    ) -> Result<Uuid, StorageError> {
        let id = Uuid::new_v4();
        let query = match &binding.target {
            GameAPBindingTarget::Service(target) => sqlx::query("INSERT INTO gameap_bindings (id, service_id, execution_unit_ref, node_id, metadata) VALUES (?, ?, ?, ?, ?)")
                .bind(text(id)).bind(text(target.as_uuid())).bind(&binding.execution_unit_id).bind(&binding.node_id).bind(json!({})),
            GameAPBindingTarget::Cluster(target) => sqlx::query("INSERT INTO gameap_bindings (id, cluster_id, execution_unit_ref, node_id, metadata) VALUES (?, ?, ?, ?, ?)")
                .bind(text(id)).bind(text(target.as_uuid())).bind(&binding.execution_unit_id).bind(&binding.node_id).bind(json!({})),
            GameAPBindingTarget::ExecutionUnit(target) => sqlx::query("INSERT INTO gameap_bindings (id, execution_unit_target, execution_unit_ref, node_id, metadata) VALUES (?, ?, ?, ?, ?)")
                .bind(text(id)).bind(target).bind(&binding.execution_unit_id).bind(&binding.node_id).bind(json!({})),
            GameAPBindingTarget::World(target) => sqlx::query("INSERT INTO gameap_bindings (id, world_id, execution_unit_ref, node_id, metadata) VALUES (?, ?, ?, ?, ?)")
                .bind(text(id)).bind(text(target.as_uuid())).bind(&binding.execution_unit_id).bind(&binding.node_id).bind(json!({})),
            GameAPBindingTarget::ProxyInstance(target) => sqlx::query("INSERT INTO gameap_bindings (id, proxy_instance_id, execution_unit_ref, node_id, metadata) VALUES (?, ?, ?, ?, ?)")
                .bind(text(id)).bind(text(target.as_uuid())).bind(&binding.execution_unit_id).bind(&binding.node_id).bind(json!({})),
        };
        query.execute(self.pool()).await.map_err(|error| {
            if is_duplicate_key(&error) {
                StorageError::Conflict {
                    entity: "GameAP binding",
                }
            } else {
                db(error)
            }
        })?;
        Ok(id)
    }

    pub async fn get_gameap_binding(
        &self,
        id: Uuid,
    ) -> Result<Option<GameAPBinding>, StorageError> {
        sqlx::query("SELECT service_id, cluster_id, execution_unit_target, world_id, proxy_instance_id, execution_unit_ref, node_id FROM gameap_bindings WHERE id = ?")
            .bind(text(id))
            .fetch_optional(self.pool())
            .await
            .map_err(db)?
            .map(|row| row_gameap(&row))
            .transpose()
    }

    pub async fn resolve_gameap_binding_cluster(
        &self,
        id: Uuid,
    ) -> Result<Option<kitsunebi_domain::ClusterId>, StorageError> {
        let row = sqlx::query(
            "SELECT current_cluster_id AS cluster_id FROM gameap_bindings b JOIN services s ON s.id = b.service_id WHERE b.id = ? AND b.service_id IS NOT NULL UNION SELECT cluster_id FROM gameap_bindings WHERE id = ? AND cluster_id IS NOT NULL UNION SELECT w.cluster_id FROM gameap_bindings b JOIN worlds w ON w.id = b.world_id WHERE b.id = ? AND b.world_id IS NOT NULL UNION SELECT r.cluster_id FROM gameap_bindings b JOIN routes r ON r.pool_id = (SELECT pool_id FROM proxy_instances WHERE id = b.proxy_instance_id) WHERE b.id = ? AND b.proxy_instance_id IS NOT NULL LIMIT 1",
        )
        .bind(text(id))
        .bind(text(id))
        .bind(text(id))
        .bind(text(id))
        .fetch_optional(self.pool())
        .await
        .map_err(db)?;
        let Some(row) = row else { return Ok(None) };
        let value: Option<String> = row.try_get("cluster_id").map_err(db)?;
        value
            .map(|value| {
                Uuid::parse_str(&value)
                    .map(kitsunebi_domain::ClusterId::from_uuid)
                    .map_err(|error| invalid(format!("binding cluster: {error}")))
            })
            .transpose()
    }

    /// Resolve a binding only when both its persisted owner service and its
    /// derived cluster match the requested scope. Execution-unit-only rows do
    /// not carry enough ownership information and therefore remain
    /// intentionally unresolved.
    pub async fn get_gameap_binding_for_scope(
        &self,
        id: Uuid,
        service: kitsunebi_domain::ServiceId,
        cluster: kitsunebi_domain::ClusterId,
    ) -> Result<Option<GameAPBinding>, StorageError> {
        let Some(binding) = self.get_gameap_binding(id).await? else {
            return Ok(None);
        };
        let services = self
            .resource_service_scope(ResourceKind::GameAPBinding, id)
            .await?;
        let resolved_cluster = self.resolve_gameap_binding_cluster(id).await?;
        if services.contains(&service) && resolved_cluster == Some(cluster) {
            Ok(Some(binding))
        } else {
            Ok(None)
        }
    }

    pub async fn create_sftp_endpoint(
        &self,
        endpoint: &SftpEndpointMetadata,
    ) -> Result<(), StorageError> {
        endpoint.validate().map_err(StorageError::Domain)?;
        let owners = self
            .resource_service_scope(
                ResourceKind::GameAPBinding,
                endpoint.execution_binding_id.as_uuid(),
            )
            .await?;
        if !owners.contains(&endpoint.service_id) {
            return Err(StorageError::Conflict {
                entity: "sftp execution ownership",
            });
        }
        sqlx::query("INSERT INTO sftp_endpoints (id, service_id, execution_binding_id, host, port, root, provisioning_owned) VALUES (?, ?, ?, ?, ?, ?, ?)")
            .bind(text(endpoint.id.as_uuid()))
            .bind(text(endpoint.service_id.as_uuid()))
            .bind(text(endpoint.execution_binding_id.as_uuid()))
            .bind(&endpoint.host)
            .bind(endpoint.port)
            .bind(&endpoint.root)
            .bind(endpoint.provisioning_owned)
            .execute(self.pool())
            .await
            .map(|_| ())
            .map_err(db)
    }

    pub async fn get_sftp_endpoint(
        &self,
        id: kitsunebi_domain::SftpEndpointId,
    ) -> Result<Option<SftpEndpointMetadata>, StorageError> {
        sqlx::query("SELECT * FROM sftp_endpoints WHERE id = ? AND revoked = FALSE")
            .bind(text(id.as_uuid()))
            .fetch_optional(self.pool())
            .await
            .map_err(db)?
            .map(|row| row_sftp_endpoint(&row))
            .transpose()
    }

    pub async fn list_sftp_endpoints(
        &self,
        service_id: kitsunebi_domain::ServiceId,
    ) -> Result<Vec<SftpEndpointMetadata>, StorageError> {
        let rows = sqlx::query(
            "SELECT * FROM sftp_endpoints WHERE service_id = ? AND revoked = FALSE ORDER BY id",
        )
        .bind(text(service_id.as_uuid()))
        .fetch_all(self.pool())
        .await
        .map_err(db)?;
        rows.iter().map(row_sftp_endpoint).collect()
    }

    /// Save an out-of-band scan with request-key idempotency. The lookup and
    /// insert share one transaction so a replay cannot produce a second row.
    pub async fn create_sftp_scan(&self, scan: &SftpScan) -> Result<SftpScan, StorageError> {
        scan.validate().map_err(StorageError::Domain)?;
        let endpoint =
            self.get_sftp_endpoint(scan.endpoint_id)
                .await?
                .ok_or(StorageError::NotFound {
                    entity: "sftp endpoint",
                })?;
        if endpoint.service_id != scan.service_id
            || endpoint.execution_binding_id != scan.execution_binding_id
        {
            return Err(StorageError::Conflict {
                entity: "sftp endpoint scope",
            });
        }
        let session =
            self.get_change_session(scan.session_id)
                .await?
                .ok_or(StorageError::NotFound {
                    entity: "change session",
                })?;
        if !session.is_active() {
            return Err(StorageError::Conflict {
                entity: "sftp change session",
            });
        }
        let cluster = self
            .get_cluster(session.target_cluster)
            .await?
            .ok_or(StorageError::NotFound { entity: "cluster" })?;
        if cluster.service_id != scan.service_id {
            return Err(StorageError::Conflict {
                entity: "sftp service scope",
            });
        }
        self.get_gameap_binding_for_scope(
            scan.execution_binding_id.as_uuid(),
            scan.service_id,
            session.target_cluster,
        )
        .await?
        .ok_or(StorageError::Conflict {
            entity: "sftp execution ownership",
        })?;
        let mut tx = self.pool().begin().await.map_err(db)?;
        if let Some(row) = sqlx::query(
            "SELECT * FROM sftp_scans WHERE change_session_id = ? AND idempotency_key = ? FOR UPDATE",
        )
        .bind(text(scan.session_id.as_uuid()))
        .bind(&scan.idempotency_key)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?
        {
            let existing = row_sftp_scan(&row)?;
            if existing.request_hash != scan.request_hash {
                return Err(StorageError::IdempotencyConflict);
            }
            tx.commit().await.map_err(db)?;
            return Ok(existing);
        }
        let insert = sqlx::query("INSERT INTO sftp_scans (id, endpoint_id, service_id, execution_binding_id, change_session_id, before_manifest_hash, after_manifest_hash, changed_paths, observed_at, source, idempotency_key, request_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(text(scan.id.as_uuid()))
            .bind(text(scan.endpoint_id.as_uuid()))
            .bind(text(scan.service_id.as_uuid()))
            .bind(text(scan.execution_binding_id.as_uuid()))
            .bind(text(scan.session_id.as_uuid()))
            .bind(&scan.before_manifest_hash)
            .bind(&scan.after_manifest_hash)
            .bind(to_json(&scan.changed_paths)?)
            .bind(scan.observed_at)
            .bind(sftp_source(scan.source))
            .bind(&scan.idempotency_key)
            .bind(&scan.request_hash)
            .execute(&mut *tx)
            .await;
        if let Err(error) = insert {
            if is_duplicate_key(&error) {
                let row = sqlx::query(
                    "SELECT * FROM sftp_scans WHERE change_session_id = ? AND idempotency_key = ? FOR UPDATE",
                )
                .bind(text(scan.session_id.as_uuid()))
                .bind(&scan.idempotency_key)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db)?;
                if let Some(row) = row {
                    let existing = row_sftp_scan(&row)?;
                    if existing.request_hash == scan.request_hash {
                        tx.commit().await.map_err(db)?;
                        return Ok(existing);
                    }
                    return Err(StorageError::IdempotencyConflict);
                }
            }
            return Err(db(error));
        }
        tx.commit().await.map_err(db)?;
        Ok(scan.clone())
    }

    pub async fn get_sftp_scan(
        &self,
        id: kitsunebi_domain::SftpScanId,
    ) -> Result<Option<SftpScan>, StorageError> {
        sqlx::query("SELECT * FROM sftp_scans WHERE id = ?")
            .bind(text(id.as_uuid()))
            .fetch_optional(self.pool())
            .await
            .map_err(db)?
            .map(|row| row_sftp_scan(&row))
            .transpose()
    }

    pub async fn list_sftp_scans(
        &self,
        session_id: kitsunebi_domain::ChangeSessionId,
    ) -> Result<Vec<SftpScan>, StorageError> {
        let rows = sqlx::query(
            "SELECT * FROM sftp_scans WHERE change_session_id = ? ORDER BY observed_at, id",
        )
        .bind(text(session_id.as_uuid()))
        .fetch_all(self.pool())
        .await
        .map_err(db)?;
        rows.iter().map(row_sftp_scan).collect()
    }

    pub async fn record_node_capability(
        &self,
        observation: &NodeCapabilityObservation,
    ) -> Result<NodeCapabilityObservation, StorageError> {
        observation.validate().map_err(StorageError::Domain)?;
        let result = sqlx::query("INSERT INTO node_capability_observations (id, provider_node_ref, process_manager, manager_version, capabilities, evidence_hash, observed_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
            .bind(text(observation.id.as_uuid()))
            .bind(&observation.provider_node_ref)
            .bind(process_manager(&observation.process_manager))
            .bind(&observation.version)
            .bind(to_json(&observation.capabilities)?)
            .bind(&observation.evidence_hash)
            .bind(observation.observed_at)
            .execute(self.pool())
            .await;
        match result {
            Ok(_) => Ok(observation.clone()),
            Err(error) if is_duplicate_key(&error) => {
                sqlx::query("SELECT * FROM node_capability_observations WHERE provider_node_ref = ? AND observed_at = ? AND evidence_hash = ?")
                    .bind(&observation.provider_node_ref)
                    .bind(observation.observed_at)
                    .bind(&observation.evidence_hash)
                    .fetch_optional(self.pool())
                    .await
                    .map_err(db)?
                    .map(|row| row_node_capability(&row))
                    .transpose()?
                    .ok_or(StorageError::Conflict { entity: "node capability observation" })
            }
            Err(error) => Err(db(error)),
        }
    }

    pub async fn latest_node_capability(
        &self,
        provider_node_ref: &str,
    ) -> Result<Option<NodeCapabilityObservation>, StorageError> {
        sqlx::query("SELECT * FROM node_capability_observations WHERE provider_node_ref = ? ORDER BY observed_at DESC, created_at DESC, id DESC LIMIT 1")
            .bind(provider_node_ref)
            .fetch_optional(self.pool())
            .await
            .map_err(db)?
            .map(|row| row_node_capability(&row))
            .transpose()
    }

    pub async fn node_capability_history(
        &self,
        provider_node_ref: &str,
    ) -> Result<Vec<NodeCapabilityObservation>, StorageError> {
        let rows = sqlx::query("SELECT * FROM node_capability_observations WHERE provider_node_ref = ? ORDER BY observed_at, created_at, id")
            .bind(provider_node_ref)
            .fetch_all(self.pool())
            .await
            .map_err(db)?;
        rows.iter().map(row_node_capability).collect()
    }

    pub async fn list_gameap_bindings(&self) -> Result<Vec<GameAPBinding>, StorageError> {
        let rows = sqlx::query(
            "SELECT service_id, cluster_id, execution_unit_target, world_id, proxy_instance_id, execution_unit_ref, node_id FROM gameap_bindings ORDER BY created_at, id",
        )
        .fetch_all(self.pool())
        .await
        .map_err(db)?;
        rows.iter().map(row_gameap).collect()
    }

    pub async fn update_gameap_binding(
        &self,
        id: Uuid,
        binding: &GameAPBinding,
        expected_version: u64,
    ) -> Result<(), StorageError> {
        let (service_id, cluster_id, execution_unit_target, world_id, proxy_instance_id) =
            binding_target_columns(&binding.target);
        let result = sqlx::query("UPDATE gameap_bindings SET service_id = ?, cluster_id = ?, execution_unit_target = ?, world_id = ?, proxy_instance_id = ?, execution_unit_ref = ?, node_id = ?, version = version + 1 WHERE id = ? AND version = ?")
            .bind(service_id)
            .bind(cluster_id)
            .bind(execution_unit_target)
            .bind(world_id)
            .bind(proxy_instance_id)
            .bind(&binding.execution_unit_id)
            .bind(&binding.node_id)
            .bind(text(id))
            .bind(expected_version)
            .execute(self.pool())
            .await
            .map_err(|error| {
                if is_duplicate_key(&error) {
                    StorageError::Conflict {
                        entity: "GameAP binding",
                    }
                } else {
                    db(error)
                }
            })?;
        if result.rows_affected() == 0 {
            return Err(StorageError::Conflict {
                entity: "GameAP binding",
            });
        }
        Ok(())
    }

    pub async fn append_audit_event(&self, event: &AuditEvent) -> Result<Uuid, StorageError> {
        event.validate().map_err(StorageError::Domain)?;
        self.require_actor_identity(event.actor).await?;
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO audit_events (event_id, actor, action, target, classification, source, service_id, cluster_id, world_id, execution_unit_ref, operation_id, result, before_revision, after_revision, plan_hash, request_id, evidence) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(text(id))
            .bind(text(event.actor.as_uuid()))
            .bind(&event.action)
            .bind(&event.target)
            .bind(classification(&event.classification))
            .bind(event.source.as_str())
            .bind(text(event.scope.service_id.as_uuid()))
            .bind(event.scope.cluster_id.map(|id| text(id.as_uuid())))
            .bind(event.scope.world_id.map(|id| text(id.as_uuid())))
            .bind(&event.scope.execution_unit_ref)
            .bind(event.scope.operation_id.map(|id| text(id.as_uuid())))
            .bind(event.result.as_str())
            .bind(event.before_revision)
            .bind(event.after_revision)
            .bind(&event.plan_hash)
            .bind(&event.request_id)
            .bind(safe_evidence(event)?)
            .execute(self.pool())
            .await
            .map_err(db)?;
        Ok(id)
    }

    pub async fn read_audit_events(
        &self,
        limit: u32,
    ) -> Result<Vec<AuditEventRecord>, StorageError> {
        let limit = i64::from(limit.min(1000));
        let rows = sqlx::query("SELECT event_id, CAST(occurred_at AS CHAR) AS occurred_at, actor, action, target, classification, source, service_id, cluster_id, world_id, execution_unit_ref, operation_id, result, before_revision, after_revision, plan_hash, request_id, evidence FROM audit_events ORDER BY occurred_at DESC, event_id DESC LIMIT ?")
            .bind(limit)
            .fetch_all(self.pool())
            .await
            .map_err(db)?;
        rows.iter().map(row_audit).collect()
    }

    /// Revoke an archived service's mutable management surfaces while keeping
    /// audit, change-session, operation, and backup history intact. Runtime
    /// files are deliberately outside this repository primitive; no
    /// filesystem delete is attempted here.
    pub async fn purge_archived_service(
        &self,
        service_id: kitsunebi_domain::ServiceId,
        expected_version: u64,
        archived_at: u64,
    ) -> Result<ServiceTombstone, StorageError> {
        let mut tx = self.pool().begin().await.map_err(db)?;
        if let Some(row) = sqlx::query(
            "SELECT id, service_id, service_key, archived_at FROM service_tombstones WHERE service_id = ? FOR UPDATE",
        )
        .bind(text(service_id.as_uuid()))
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?
        {
            let tombstone = ServiceTombstone {
                id: kitsunebi_domain::ServiceTombstoneId::from_uuid(uuid(&row, "id")?),
                service_id: kitsunebi_domain::ServiceId::from_uuid(uuid(&row, "service_id")?),
                service_key: row.try_get("service_key").map_err(db)?,
                archived_at: row.try_get("archived_at").map_err(db)?,
            };
            tx.commit().await.map_err(db)?;
            return Ok(tombstone);
        }

        let service_row =
            sqlx::query("SELECT `key`, lifecycle, version FROM services WHERE id = ? FOR UPDATE")
                .bind(text(service_id.as_uuid()))
                .fetch_optional(&mut *tx)
                .await
                .map_err(db)?
                .ok_or(StorageError::NotFound { entity: "service" })?;
        let lifecycle_value: String = service_row.try_get("lifecycle").map_err(db)?;
        let current_version: u64 = service_row.try_get("version").map_err(db)?;
        if lifecycle_value != "archived" {
            return Err(StorageError::Conflict {
                entity: "archived service",
            });
        }
        if current_version != expected_version {
            return Err(StorageError::Conflict { entity: "service" });
        }
        let service_key: String = service_row.try_get("key").map_err(db)?;

        sqlx::query("DELETE b FROM access_policy_bindings b LEFT JOIN clusters c ON c.id = b.cluster_id WHERE b.service_id = ? OR c.service_id = ?")
            .bind(text(service_id.as_uuid()))
            .bind(text(service_id.as_uuid()))
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        sqlx::query("UPDATE services SET access_policy_id = NULL, metadata = JSON_SET(metadata, '$.purged', TRUE), version = version + 1, updated_at = CURRENT_TIMESTAMP(6) WHERE id = ? AND version = ?")
            .bind(text(service_id.as_uuid()))
            .bind(expected_version)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        sqlx::query("UPDATE gameap_bindings SET metadata = JSON_SET(metadata, '$.revoked', TRUE) WHERE service_id = ?")
            .bind(text(service_id.as_uuid()))
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        sqlx::query("UPDATE gameap_bindings b JOIN clusters c ON c.id = b.cluster_id SET b.metadata = JSON_SET(b.metadata, '$.revoked', TRUE) WHERE c.service_id = ?")
            .bind(text(service_id.as_uuid()))
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        sqlx::query("UPDATE gameap_bindings b JOIN worlds w ON w.id = b.world_id JOIN clusters c ON c.id = w.cluster_id SET b.metadata = JSON_SET(b.metadata, '$.revoked', TRUE) WHERE c.service_id = ?")
            .bind(text(service_id.as_uuid()))
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        sqlx::query("UPDATE gameap_bindings b JOIN proxy_instances pi ON pi.id = b.proxy_instance_id JOIN routes r ON r.pool_id = pi.pool_id JOIN clusters c ON c.id = r.cluster_id SET b.metadata = JSON_SET(b.metadata, '$.revoked', TRUE) WHERE c.service_id = ?")
            .bind(text(service_id.as_uuid()))
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        sqlx::query("UPDATE routes r JOIN clusters c ON c.id = r.cluster_id SET r.metadata = JSON_SET(r.metadata, '$.revoked', TRUE), r.version = r.version + 1 WHERE r.service_id = ? OR c.service_id = ?")
            .bind(text(service_id.as_uuid()))
            .bind(text(service_id.as_uuid()))
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        sqlx::query("UPDATE proxy_instances pi JOIN routes r ON r.pool_id = pi.pool_id JOIN clusters c ON c.id = r.cluster_id SET pi.metadata = JSON_SET(pi.metadata, '$.revoked', TRUE), pi.gameap_binding_ref = NULL, pi.version = pi.version + 1 WHERE c.service_id = ?")
            .bind(text(service_id.as_uuid()))
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        sqlx::query("UPDATE proxy_pools p JOIN routes r ON r.pool_id = p.id JOIN clusters c ON c.id = r.cluster_id SET p.metadata = JSON_SET(p.metadata, '$.revoked', TRUE), p.version = p.version + 1 WHERE c.service_id = ?")
            .bind(text(service_id.as_uuid()))
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        sqlx::query("DELETE pib FROM proxy_instance_bindings pib JOIN proxy_instances pi ON pi.id = pib.instance_id JOIN routes r ON r.pool_id = pi.pool_id JOIN clusters c ON c.id = r.cluster_id WHERE c.service_id = ?")
            .bind(text(service_id.as_uuid()))
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        sqlx::query("DELETE t FROM tcp_shield_backend_sets t JOIN routes r ON r.pool_id = t.pool_id JOIN clusters c ON c.id = r.cluster_id WHERE c.service_id = ?")
            .bind(text(service_id.as_uuid()))
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        sqlx::query(
            "UPDATE sftp_endpoints SET revoked = TRUE, version = version + 1 WHERE service_id = ?",
        )
        .bind(text(service_id.as_uuid()))
        .execute(&mut *tx)
        .await
        .map_err(db)?;

        let tombstone = ServiceTombstone::new(service_id, &service_key, archived_at)
            .map_err(StorageError::Domain)?;
        sqlx::query("INSERT INTO service_tombstones (id, service_id, service_key, archived_at) VALUES (?, ?, ?, ?)")
            .bind(text(tombstone.id.as_uuid()))
            .bind(text(tombstone.service_id.as_uuid()))
            .bind(&tombstone.service_key)
            .bind(tombstone.archived_at)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        tx.commit().await.map_err(db)?;
        Ok(tombstone)
    }
}

fn lifecycle_decision(value: &LifecycleDecision) -> &'static str {
    match value {
        LifecycleDecision::Start => "start",
        LifecycleDecision::Stop => "stop",
        LifecycleDecision::Restart => "restart",
        LifecycleDecision::Drain => "drain",
        LifecycleDecision::Accept => "accept",
        LifecycleDecision::Rollback => "rollback",
        LifecycleDecision::NoAction => "no_action",
    }
}
