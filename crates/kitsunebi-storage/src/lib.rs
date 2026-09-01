#![forbid(unsafe_code)]

//! Storage adapters.

use async_trait::async_trait;
use kitsunebi_application::{
    self as application, ApplicationError, OperationFailure,
    OperationLease as ApplicationOperationLease, OperationRequest, RetirementSafety, StepEvidence,
};
use kitsunebi_domain::{
    ActorId, AuditEvent, AuditResult, AuditSource, ChangeSession, FileClassification, Operation,
    PlanDescriptor,
};
use sqlx::MySqlPool;
use sqlx::mysql::{MySqlConnectOptions, MySqlPoolOptions};
use std::str::FromStr;

mod repositories;
pub use repositories::{
    ActorIdentity, ActorKind, AuditEventRecord, LifecycleDecisionRecord, OperationLease, Page,
    ResourceKind,
};

pub const CRATE_NAME: &str = "kitsunebi-storage";

/// Errors emitted by the persistence adapter.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("invalid database URL: {0}")]
    InvalidDatabaseUrl(#[from] sqlx::Error),
    #[error("database migration failed: {0}")]
    Migration(#[source] sqlx::migrate::MigrateError),
    #[error("database operation failed: {0}")]
    Database(#[source] sqlx::Error),
    #[error("{entity} was not found")]
    NotFound { entity: &'static str },
    #[error("optimistic concurrency check failed for {entity}")]
    Conflict { entity: &'static str },
    #[error("{entity} is immutable")]
    Immutable { entity: &'static str },
    #[error("idempotency key was already used with a different request")]
    IdempotencyConflict,
    #[error("staged content idempotency key was used with a different request")]
    StagedContentConflict,
    #[error("operation lease is not available")]
    LeaseUnavailable,
    #[error("invalid stored value: {0}")]
    InvalidData(String),
    #[error("domain invariant failed: {0}")]
    Domain(#[from] kitsunebi_domain::DomainError),
}

/// MySQL-backed Kitsunebi metadata storage.
#[derive(Clone, Debug)]
pub struct MySqlStorage {
    pool: MySqlPool,
}

impl MySqlStorage {
    /// Connect using a MySQL URL. The URL must be supplied by the caller; this
    /// type never logs or stores credentials.
    pub async fn connect(database_url: &str) -> Result<Self, StorageError> {
        let options = MySqlConnectOptions::from_str(database_url)?;
        let pool = MySqlPoolOptions::new()
            .max_connections(10)
            .connect_with(options)
            .await
            .map_err(StorageError::Database)?;
        Ok(Self { pool })
    }

    /// Apply the checked-in schema migrations, safely on every startup.
    pub async fn migrate(&self) -> Result<(), StorageError> {
        sqlx::migrate!("../../migrations")
            .run(&self.pool)
            .await
            .map_err(StorageError::Migration)
    }

    pub fn pool(&self) -> &MySqlPool {
        &self.pool
    }

    /// Expose a transaction boundary for repositories without exposing
    /// connection credentials or requiring compile-time SQLx metadata.
    pub async fn ping(&self) -> Result<(), StorageError> {
        sqlx::query("SELECT 1")
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(StorageError::Database)
    }
}

fn application_error(error: StorageError) -> ApplicationError {
    match error {
        StorageError::NotFound { entity } => ApplicationError::NotFound(entity),
        StorageError::Conflict { entity } => {
            ApplicationError::Conflict(Box::leak(entity.to_owned().into_boxed_str()))
        }
        StorageError::IdempotencyConflict => ApplicationError::Replay,
        StorageError::StagedContentConflict => {
            ApplicationError::Conflict("staged content idempotency")
        }
        StorageError::LeaseUnavailable => ApplicationError::Conflict("operation lease"),
        StorageError::Immutable { entity } => {
            ApplicationError::Conflict(Box::leak(entity.to_owned().into_boxed_str()))
        }
        other => ApplicationError::Port(other.to_string()),
    }
}

fn is_duplicate_key(error: &sqlx::Error) -> bool {
    matches!(error, sqlx::Error::Database(database) if database.code().as_deref() == Some("1062"))
}

/// MySQL is the production implementation of the application persistence port.
/// Every read delegates to the existing repositories, keeping scope resolution
/// and row decoding in one place.
#[async_trait]
impl application::DomainRepository for MySqlStorage {
    async fn network(
        &self,
        id: kitsunebi_domain::NetworkId,
    ) -> Result<kitsunebi_domain::MCPlayNetwork, ApplicationError> {
        self.get_network(id)
            .await
            .map_err(application_error)?
            .ok_or(ApplicationError::NotFound("network"))
    }
    async fn services(&self) -> Result<Vec<kitsunebi_domain::Service>, ApplicationError> {
        self.list_all_services().await.map_err(application_error)
    }
    async fn service(
        &self,
        id: kitsunebi_domain::ServiceId,
    ) -> Result<kitsunebi_domain::Service, ApplicationError> {
        self.get_service(id)
            .await
            .map_err(application_error)?
            .ok_or(ApplicationError::NotFound("service"))
    }
    async fn clusters(&self) -> Result<Vec<kitsunebi_domain::GameCluster>, ApplicationError> {
        self.list_all_clusters().await.map_err(application_error)
    }
    async fn cluster(
        &self,
        id: kitsunebi_domain::ClusterId,
    ) -> Result<kitsunebi_domain::GameCluster, ApplicationError> {
        self.get_cluster(id)
            .await
            .map_err(application_error)?
            .ok_or(ApplicationError::NotFound("cluster"))
    }
    async fn revisions(&self) -> Result<Vec<kitsunebi_domain::ClusterRevision>, ApplicationError> {
        self.list_all_revisions().await.map_err(application_error)
    }
    async fn revision_cluster(
        &self,
        id: kitsunebi_domain::RevisionId,
    ) -> Result<kitsunebi_domain::ClusterId, ApplicationError> {
        self.get_revision_cluster(id)
            .await
            .map_err(application_error)?
            .ok_or(ApplicationError::NotFound("revision cluster"))
    }
    async fn worlds(&self) -> Result<Vec<kitsunebi_domain::World>, ApplicationError> {
        self.list_all_worlds().await.map_err(application_error)
    }
    async fn proxies(&self) -> Result<Vec<kitsunebi_domain::ProxyInstance>, ApplicationError> {
        self.list_all_proxy_instances()
            .await
            .map_err(application_error)
    }
    async fn artifacts(&self) -> Result<Vec<kitsunebi_domain::Artifact>, ApplicationError> {
        self.list_artifacts().await.map_err(application_error)
    }
    async fn artifact_set(
        &self,
        id: kitsunebi_domain::ArtifactSetId,
    ) -> Result<kitsunebi_domain::ArtifactSet, ApplicationError> {
        self.get_artifact_set(id)
            .await
            .map_err(application_error)?
            .ok_or(ApplicationError::NotFound("artifact set"))
    }
    async fn endpoints(&self) -> Result<Vec<kitsunebi_domain::ExternalEndpoint>, ApplicationError> {
        self.list_endpoints().await.map_err(application_error)
    }
    async fn endpoint_binding(
        &self,
        id: kitsunebi_domain::BindingId,
    ) -> Result<kitsunebi_domain::EndpointBinding, ApplicationError> {
        self.get_endpoint_binding(id)
            .await
            .map_err(application_error)?
            .ok_or(ApplicationError::NotFound("endpoint binding"))
    }
    async fn access_policy(
        &self,
        id: kitsunebi_domain::PolicyId,
    ) -> Result<kitsunebi_domain::AccessPolicy, ApplicationError> {
        self.get_access_policy(id)
            .await
            .map_err(application_error)?
            .ok_or(ApplicationError::NotFound("access policy"))
    }
    async fn sessions(&self) -> Result<Vec<ChangeSession>, ApplicationError> {
        self.list_change_sessions().await.map_err(application_error)
    }
    async fn operations(&self) -> Result<Vec<Operation>, ApplicationError> {
        self.list_operations().await.map_err(application_error)
    }
    async fn backups(&self) -> Result<Vec<kitsunebi_domain::BackupReference>, ApplicationError> {
        self.list_backup_references()
            .await
            .map_err(application_error)
    }
    async fn retirement_safety(
        &self,
        service: kitsunebi_domain::ServiceId,
    ) -> Result<RetirementSafety, ApplicationError> {
        MySqlStorage::retirement_safety(self, service)
            .await
            .map_err(application_error)
    }
    async fn staged_content_for_actor(
        &self,
        session: kitsunebi_domain::ChangeSessionId,
        actor: kitsunebi_domain::ActorId,
        content: &kitsunebi_domain::StagedContentRef,
        classification: kitsunebi_domain::FileClassification,
        required_until: u64,
    ) -> Result<kitsunebi_domain::StagedContentOwnership, ApplicationError> {
        self.get_staged_content_for_actor(session, actor, content, classification, required_until)
            .await
            .map_err(application_error)?
            .ok_or(ApplicationError::Forbidden)
    }
    async fn gameap_binding(
        &self,
        id: kitsunebi_domain::BindingId,
        service: kitsunebi_domain::ServiceId,
        cluster: kitsunebi_domain::ClusterId,
    ) -> Result<kitsunebi_domain::GameAPBinding, ApplicationError> {
        self.get_gameap_binding_for_scope(id.as_uuid(), service, cluster)
            .await
            .map_err(application_error)?
            .ok_or(ApplicationError::NotFound("gameap binding"))
    }
    async fn change_session_for_actor(
        &self,
        id: kitsunebi_domain::ChangeSessionId,
        actor: kitsunebi_domain::ActorId,
    ) -> Result<ChangeSession, ApplicationError> {
        self.get_change_session_for_actor(id, actor)
            .await
            .map_err(application_error)?
            .ok_or(ApplicationError::NotFound("change session"))
    }
    async fn plan(&self, id: kitsunebi_domain::PlanId) -> Result<PlanDescriptor, ApplicationError> {
        self.get_plan(id)
            .await
            .map_err(application_error)?
            .ok_or(ApplicationError::NotFound("plan"))
    }
    async fn plan_session(
        &self,
        id: kitsunebi_domain::PlanId,
    ) -> Result<kitsunebi_domain::ChangeSessionId, ApplicationError> {
        self.get_plan_session(id)
            .await
            .map_err(application_error)?
            .ok_or(ApplicationError::NotFound("plan"))
    }
    async fn cluster_for_plan_target(
        &self,
        target: kitsunebi_domain::PlanTarget,
        service: kitsunebi_domain::ServiceId,
    ) -> Result<kitsunebi_domain::ClusterId, ApplicationError> {
        self.resolve_plan_target_cluster(target, service)
            .await
            .map_err(application_error)
    }
    async fn transaction(&self) -> Result<Box<dyn application::UnitOfWork>, ApplicationError> {
        let transaction = self
            .pool
            .begin()
            .await
            .map_err(|e| application_error(StorageError::Database(e)))?;
        Ok(Box::new(MySqlUnitOfWork {
            transaction: Some(transaction),
            sessions: Vec::new(),
            plans: Vec::new(),
        }))
    }
}

#[async_trait]
impl application::WorldStorage for MySqlStorage {
    async fn compare_and_swap_writer(
        &self,
        world: kitsunebi_domain::WorldId,
        expected_version: u64,
        expected: Option<kitsunebi_domain::ClusterId>,
        next: kitsunebi_domain::ClusterId,
    ) -> Result<(), ApplicationError> {
        self.cutover_world_writer(world, expected_version, expected, next)
            .await
            .map_err(application_error)
    }
}

#[async_trait]
impl application::EndpointBindingStore for MySqlStorage {
    async fn activate_revision(
        &self,
        expected: &kitsunebi_domain::EndpointBinding,
        target: &kitsunebi_domain::EndpointBinding,
        expected_version: u64,
    ) -> Result<(), ApplicationError> {
        self.activate_endpoint_bindings_at_version(expected, target, expected_version)
            .await
            .map_err(application_error)
    }

    async fn rollback_revision(
        &self,
        cluster: kitsunebi_domain::ClusterId,
        expected_binding: kitsunebi_domain::BindingId,
        target_binding: kitsunebi_domain::BindingId,
        expected_version: u64,
    ) -> Result<(), ApplicationError> {
        self.rollback_endpoint_bindings_at_version(
            cluster,
            expected_binding,
            target_binding,
            expected_version,
        )
        .await
        .map_err(application_error)
    }
}

#[async_trait]
impl application::SftpScanRepository for MySqlStorage {
    async fn sftp_endpoint(
        &self,
        id: kitsunebi_domain::SftpEndpointId,
    ) -> Result<kitsunebi_domain::SftpEndpointMetadata, ApplicationError> {
        self.get_sftp_endpoint(id)
            .await
            .map_err(application_error)?
            .ok_or(ApplicationError::NotFound("sftp endpoint"))
    }

    async fn save_sftp_scan(
        &self,
        scan: kitsunebi_domain::SftpScan,
    ) -> Result<kitsunebi_domain::SftpScan, ApplicationError> {
        self.create_sftp_scan(&scan)
            .await
            .map_err(application_error)
    }
}

#[async_trait]
impl application::NodeCapabilityRepository for MySqlStorage {
    async fn record_node_capability(
        &self,
        observation: kitsunebi_domain::NodeCapabilityObservation,
    ) -> Result<kitsunebi_domain::NodeCapabilityObservation, ApplicationError> {
        self.record_node_capability(&observation)
            .await
            .map_err(application_error)
    }

    async fn latest_node_capability(
        &self,
        provider_node_ref: &str,
    ) -> Result<Option<kitsunebi_domain::NodeCapabilityObservation>, ApplicationError> {
        self.latest_node_capability(provider_node_ref)
            .await
            .map_err(application_error)
    }

    async fn node_capability_history(
        &self,
        provider_node_ref: &str,
    ) -> Result<Vec<kitsunebi_domain::NodeCapabilityObservation>, ApplicationError> {
        self.node_capability_history(provider_node_ref)
            .await
            .map_err(application_error)
    }
}

struct MySqlUnitOfWork {
    transaction: Option<sqlx::Transaction<'static, sqlx::MySql>>,
    sessions: Vec<(ChangeSession, ActorId)>,
    plans: Vec<(
        PlanDescriptor,
        kitsunebi_domain::ChangeSessionId,
        String,
        String,
        AuditEvent,
    )>,
}
#[async_trait]
impl application::UnitOfWork for MySqlUnitOfWork {
    async fn save_session_for_actor(
        &mut self,
        session: ChangeSession,
        actor: ActorId,
    ) -> Result<(), ApplicationError> {
        self.sessions.push((session, actor));
        Ok(())
    }
    async fn save_session_idempotent_for_actor(
        &mut self,
        session: ChangeSession,
        actor: ActorId,
        idempotency_key: &str,
        request_hash: &str,
        audit: AuditEvent,
    ) -> Result<Option<ChangeSession>, ApplicationError> {
        if idempotency_key.trim().is_empty() || request_hash.trim().is_empty() {
            return Err(ApplicationError::Conflict("change begin identity"));
        }
        let tx = self.transaction.as_mut().ok_or_else(|| {
            ApplicationError::Port("unit of work transaction is not available".into())
        })?;
        let actor_text = actor.as_uuid().to_string();
        let registered = sqlx::query(
            "SELECT kind, service_id FROM actor_identities WHERE actor_id = ? FOR UPDATE",
        )
        .bind(&actor_text)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|error| application_error(StorageError::Database(error)))?;
        let valid_identity = registered.is_some_and(|row| {
            let kind = sqlx::Row::try_get::<String, _>(&row, "kind").ok();
            let service = sqlx::Row::try_get::<Option<String>, _>(&row, "service_id")
                .ok()
                .flatten();
            matches!(
                (kind.as_deref(), service.as_deref()),
                (Some("browser"), None) | (Some("service"), Some(_))
            )
        });
        if !valid_identity {
            return Err(ApplicationError::Forbidden);
        }
        let service_id: String =
            sqlx::query_scalar("SELECT service_id FROM clusters WHERE id = ? FOR UPDATE")
                .bind(session.target_cluster.as_uuid().to_string())
                .fetch_optional(&mut **tx)
                .await
                .map_err(|error| application_error(StorageError::Database(error)))?
                .ok_or(ApplicationError::NotFound("change session cluster"))?;
        let service_id = uuid::Uuid::parse_str(&service_id)
            .map(kitsunebi_domain::ServiceId::from_uuid)
            .map_err(|_| ApplicationError::Conflict("change begin audit context"))?;
        if audit.validate().is_err()
            || audit.actor != actor
            || audit.action != "change.begin"
            || audit.target != session.target_cluster.as_uuid().to_string()
            || audit.classification != FileClassification::Managed
            || audit.source != AuditSource::Application
            || audit.result != AuditResult::Success
            || audit.scope.service_id != service_id
            || audit.scope.cluster_id != Some(session.target_cluster)
            || audit.scope.world_id.is_some()
            || audit.scope.execution_unit_ref.is_some()
            || audit.scope.operation_id.is_some()
            || audit.before_revision.is_some()
            || audit.after_revision.is_some()
            || audit.plan_hash.is_some()
            || audit.request_id.as_deref() != Some(idempotency_key)
            || !audit.evidence.is_empty()
        {
            return Err(ApplicationError::Conflict("change begin audit context"));
        }
        let existing = sqlx::query(
            "SELECT * FROM change_sessions WHERE actor = ? AND idempotency_key = ? FOR UPDATE",
        )
        .bind(&actor_text)
        .bind(idempotency_key)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|error| application_error(StorageError::Database(error)))?;
        if let Some(row) = existing {
            let existing_hash: Option<String> = sqlx::Row::try_get(&row, "request_hash")
                .map_err(|error| application_error(StorageError::Database(error)))?;
            if existing_hash.as_deref() != Some(request_hash) {
                return Err(ApplicationError::Replay);
            }
            let audit_count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM audit_events WHERE actor = ? AND action = 'change.begin' AND target = ? AND classification = 'managed' AND source = 'application' AND service_id = ? AND cluster_id = ? AND world_id IS NULL AND execution_unit_ref IS NULL AND operation_id IS NULL AND result = 'success' AND before_revision IS NULL AND after_revision IS NULL AND plan_hash IS NULL AND request_id = ? AND JSON_LENGTH(evidence) = 0",
            )
            .bind(&actor_text)
            .bind(session.target_cluster.as_uuid().to_string())
            .bind(service_id.as_uuid().to_string())
            .bind(session.target_cluster.as_uuid().to_string())
            .bind(idempotency_key)
            .fetch_one(&mut **tx)
            .await
            .map_err(|error| application_error(StorageError::Database(error)))?;
            if audit_count != 1 {
                return Err(ApplicationError::Conflict("change begin audit event"));
            }
            return repositories::row_change_session(&row)
                .map(Some)
                .map_err(application_error);
        }

        let insert = sqlx::query("INSERT INTO change_sessions (id, actor, state, target, request_hash, idempotency_key, metadata) VALUES (?, ?, ?, ?, ?, ?, ?)")
            .bind(session.id.as_uuid().to_string())
            .bind(&actor_text)
            .bind(session_state(&session))
            .bind(serde_json::json!({"cluster_id": session.target_cluster.as_uuid().to_string()}))
            .bind(request_hash)
            .bind(idempotency_key)
            .bind(serde_json::json!({}))
            .execute(&mut **tx)
            .await;
        if let Err(error) = insert {
            if is_duplicate_key(&error) {
                let row = sqlx::query(
                    "SELECT * FROM change_sessions WHERE actor = ? AND idempotency_key = ? FOR UPDATE",
                )
                .bind(&actor_text)
                .bind(idempotency_key)
                .fetch_optional(&mut **tx)
                .await
                .map_err(|error| application_error(StorageError::Database(error)))?;
                if let Some(row) = row {
                    let existing_hash: Option<String> = sqlx::Row::try_get(&row, "request_hash")
                        .map_err(|error| application_error(StorageError::Database(error)))?;
                    if existing_hash.as_deref() == Some(request_hash) {
                        let audit_count: i64 = sqlx::query_scalar(
                            "SELECT COUNT(*) FROM audit_events WHERE actor = ? AND action = 'change.begin' AND target = ? AND classification = 'managed' AND source = 'application' AND service_id = ? AND cluster_id = ? AND world_id IS NULL AND execution_unit_ref IS NULL AND operation_id IS NULL AND result = 'success' AND before_revision IS NULL AND after_revision IS NULL AND plan_hash IS NULL AND request_id = ? AND JSON_LENGTH(evidence) = 0",
                        )
                        .bind(&actor_text)
                        .bind(session.target_cluster.as_uuid().to_string())
                        .bind(service_id.as_uuid().to_string())
                        .bind(session.target_cluster.as_uuid().to_string())
                        .bind(idempotency_key)
                        .fetch_one(&mut **tx)
                        .await
                        .map_err(|error| application_error(StorageError::Database(error)))?;
                        if audit_count != 1 {
                            return Err(ApplicationError::Conflict("change begin audit event"));
                        }
                        return repositories::row_change_session(&row)
                            .map(Some)
                            .map_err(application_error);
                    }
                    return Err(ApplicationError::Replay);
                }
            }
            return Err(application_error(StorageError::Database(error)));
        }
        let audit_insert = sqlx::query("INSERT INTO audit_events (event_id, actor, action, target, classification, source, service_id, cluster_id, world_id, execution_unit_ref, operation_id, result, before_revision, after_revision, plan_hash, request_id, evidence) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(audit.actor.as_uuid().to_string())
            .bind(&audit.action)
            .bind(&audit.target)
            .bind(repositories::classification(&audit.classification))
            .bind(audit.source.as_str())
            .bind(audit.scope.service_id.as_uuid().to_string())
            .bind(audit.scope.cluster_id.map(|id| id.as_uuid().to_string()))
            .bind(audit.scope.world_id.map(|id| id.as_uuid().to_string()))
            .bind(&audit.scope.execution_unit_ref)
            .bind(audit.scope.operation_id.map(|id| id.as_uuid().to_string()))
            .bind(audit.result.as_str())
            .bind(audit.before_revision)
            .bind(audit.after_revision)
            .bind(&audit.plan_hash)
            .bind(&audit.request_id)
            .bind(repositories::safe_evidence(&audit).map_err(application_error)?)
            .execute(&mut **tx)
            .await
            .map_err(|error| application_error(StorageError::Database(error)))?;
        if audit_insert.rows_affected() != 1 {
            return Err(ApplicationError::Conflict("change begin audit event"));
        }
        Ok(None)
    }
    async fn save_plan_idempotent(
        &mut self,
        plan: PlanDescriptor,
        session: kitsunebi_domain::ChangeSessionId,
        idempotency_key: &str,
        request_hash: &str,
        audit: AuditEvent,
    ) -> Result<Option<PlanDescriptor>, ApplicationError> {
        if idempotency_key.trim().is_empty()
            || request_hash.len() != 64
            || !request_hash.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(ApplicationError::Conflict("plan request identity"));
        }
        plan.validate()
            .map_err(|_| ApplicationError::Conflict("invalid plan"))?;
        audit
            .validate()
            .map_err(|_| ApplicationError::Conflict("plan audit context"))?;
        if audit.actor != plan.actor
            || audit.action != "change.plan"
            || audit.plan_hash.as_deref() != Some(plan.plan_hash.as_str())
        {
            return Err(ApplicationError::Conflict("plan audit context"));
        }
        let tx = self.transaction.as_mut().ok_or_else(|| {
            ApplicationError::Port("unit of work transaction is not available".into())
        })?;
        let actor: String =
            sqlx::query_scalar("SELECT actor FROM change_sessions WHERE id = ? FOR UPDATE")
                .bind(session.as_uuid().to_string())
                .fetch_optional(&mut **tx)
                .await
                .map_err(|error| application_error(StorageError::Database(error)))?
                .ok_or(ApplicationError::NotFound("change session"))?;
        if actor != plan.actor.as_uuid().to_string() {
            return Err(ApplicationError::Forbidden);
        }
        let registered = sqlx::query(
            "SELECT kind, service_id FROM actor_identities WHERE actor_id = ? FOR UPDATE",
        )
        .bind(&actor)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|error| application_error(StorageError::Database(error)))?;
        let valid_identity = registered.is_some_and(|row| {
            let kind = sqlx::Row::try_get::<String, _>(&row, "kind").ok();
            let service = sqlx::Row::try_get::<Option<String>, _>(&row, "service_id")
                .ok()
                .flatten();
            matches!(
                (kind.as_deref(), service.as_deref()),
                (Some("browser"), None) | (Some("service"), Some(_))
            )
        });
        if !valid_identity {
            return Err(ApplicationError::Forbidden);
        }
        if let Some((existing, _, _, existing_hash, _)) =
            self.plans
                .iter()
                .find(|(_, existing_session, existing_key, _, _)| {
                    *existing_session == session && existing_key == idempotency_key
                })
        {
            if existing_hash != request_hash {
                return Err(ApplicationError::Replay);
            }
            return Ok(Some(existing.clone()));
        }
        let existing = sqlx::query(
            "SELECT * FROM plans WHERE change_session_id = ? AND idempotency_key = ? FOR UPDATE",
        )
        .bind(session.as_uuid().to_string())
        .bind(idempotency_key)
        .fetch_optional(&mut **tx)
        .await
        .map_err(|error| application_error(StorageError::Database(error)))?;
        if let Some(existing) = existing {
            let existing_hash: String = sqlx::Row::try_get(&existing, "request_hash")
                .map_err(|error| application_error(StorageError::Database(error)))?;
            if existing_hash != request_hash {
                return Err(ApplicationError::Replay);
            }
            let original = repositories::row_plan(&existing).map_err(application_error)?;
            let audit_count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM audit_events WHERE action = 'change.plan' AND actor = ? AND plan_hash = ?",
            )
            .bind(original.actor.as_uuid().to_string())
            .bind(&original.plan_hash)
            .fetch_one(&mut **tx)
            .await
            .map_err(|error| application_error(StorageError::Database(error)))?;
            if audit_count != 1 {
                return Err(ApplicationError::Conflict("plan audit event"));
            }
            return Ok(Some(original));
        }
        self.plans.push((
            plan,
            session,
            idempotency_key.to_owned(),
            request_hash.to_owned(),
            audit,
        ));
        Ok(None)
    }
    async fn commit(self: Box<Self>) -> Result<(), ApplicationError> {
        let mut transaction = self.transaction.ok_or_else(|| {
            ApplicationError::Port("unit of work transaction is not available".into())
        })?;
        for (session, actor) in self.sessions {
            let (previous, alternate) = match session.state {
                kitsunebi_domain::ChangeSessionState::Editing => ("open", None),
                kitsunebi_domain::ChangeSessionState::Ready => ("editing", None),
                kitsunebi_domain::ChangeSessionState::Applying => ("ready", None),
                kitsunebi_domain::ChangeSessionState::Verifying => ("applying", None),
                kitsunebi_domain::ChangeSessionState::Accepted => ("verifying", None),
                kitsunebi_domain::ChangeSessionState::RolledBack => ("applying", Some("verifying")),
                kitsunebi_domain::ChangeSessionState::Aborted => ("open", None),
                kitsunebi_domain::ChangeSessionState::Conflicted => ("editing", None),
                kitsunebi_domain::ChangeSessionState::Open => {
                    return Err(ApplicationError::Conflict(
                        "invalid change session transition",
                    ));
                }
            };
            let statement = if alternate.is_some() {
                "UPDATE change_sessions SET state = ?, target = ?, version = version + 1 WHERE id = ? AND actor = ? AND state IN (?, ?) AND version = ?"
            } else {
                "UPDATE change_sessions SET state = ?, target = ?, version = version + 1 WHERE id = ? AND actor = ? AND state = ? AND version = ?"
            };
            let mut query = sqlx::query(statement)
                .bind(session_state(&session))
                .bind(serde_json::json!({
                    "cluster_id": session.target_cluster.as_uuid().to_string()
                }))
                .bind(session.id.as_uuid().to_string())
                .bind(actor.as_uuid().to_string())
                .bind(previous);
            if let Some(alternate) = alternate {
                query = query.bind(alternate);
            }
            query = query.bind(session.version.saturating_sub(1));
            let result = query
                .execute(&mut *transaction)
                .await
                .map_err(|e| application_error(StorageError::Database(e)))?;
            if result.rows_affected() == 0 {
                return Err(ApplicationError::Conflict("change session"));
            }
        }
        for (plan, session, idempotency_key, request_hash, audit) in self.plans {
            sqlx::query("INSERT INTO plans (id, change_session_id, plan_hash, idempotency_key, request_hash, actor, target, domain_revision, observed_execution_state, expected_file_hashes, expected_artifact_hashes, steps, backup_requirements, rollback_instructions, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
                .bind(plan.id.as_uuid().to_string()).bind(session.as_uuid().to_string()).bind(&plan.plan_hash).bind(&idempotency_key).bind(&request_hash).bind(plan.actor.as_uuid().to_string()).bind(serde_json::json!(plan.target)).bind(plan.domain_revision).bind(serde_json::json!(plan.observed_state_hashes)).bind(serde_json::json!(plan.expected_file_hashes)).bind(serde_json::json!(plan.expected_artifact_hashes)).bind(serde_json::json!(plan.steps)).bind(serde_json::json!(plan.backup_requirements)).bind(serde_json::json!(plan.rollback_instructions)).bind(plan.expiry).execute(&mut *transaction).await.map_err(|e| application_error(StorageError::Database(e)))?;
            let result = sqlx::query("INSERT INTO audit_events (event_id, actor, action, target, classification, source, service_id, cluster_id, world_id, execution_unit_ref, operation_id, result, before_revision, after_revision, plan_hash, request_id, evidence) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
                .bind(uuid::Uuid::new_v4().to_string())
                .bind(audit.actor.as_uuid().to_string())
                .bind(&audit.action)
                .bind(&audit.target)
                .bind(repositories::classification(&audit.classification))
                .bind(audit.source.as_str())
                .bind(audit.scope.service_id.as_uuid().to_string())
                .bind(audit.scope.cluster_id.map(|id| id.as_uuid().to_string()))
                .bind(audit.scope.world_id.map(|id| id.as_uuid().to_string()))
                .bind(&audit.scope.execution_unit_ref)
                .bind(audit.scope.operation_id.map(|id| id.as_uuid().to_string()))
                .bind(audit.result.as_str())
                .bind(audit.before_revision)
                .bind(audit.after_revision)
                .bind(&audit.plan_hash)
                .bind(&audit.request_id)
                .bind(repositories::safe_evidence(&audit).map_err(application_error)?)
                .execute(&mut *transaction)
                .await
                .map_err(|e| application_error(StorageError::Database(e)))?;
            if result.rows_affected() != 1 {
                return Err(ApplicationError::Conflict("plan audit event"));
            }
        }
        transaction
            .commit()
            .await
            .map_err(|e| application_error(StorageError::Database(e)))
    }
}

#[async_trait]
impl application::OperationStore for MySqlStorage {
    async fn find_idempotent(
        &self,
        request: &OperationRequest,
    ) -> Result<Option<Operation>, ApplicationError> {
        let row = sqlx::query("SELECT * FROM operations WHERE operation_key = ?")
            .bind(&request.key)
            .fetch_optional(self.pool())
            .await
            .map_err(|e| application_error(StorageError::Database(e)))?;
        let Some(row) = row else { return Ok(None) };
        let payload: serde_json::Value = sqlx::Row::try_get(&row, "payload")
            .map_err(|e| application_error(StorageError::Database(e)))?;
        let kind: String = sqlx::Row::try_get(&row, "kind")
            .map_err(|e| application_error(StorageError::Database(e)))?;
        if kind != "operation" || !operation_payload_matches(&payload, request) {
            return Err(ApplicationError::Replay);
        }
        repositories::row_operation_public(&row)
            .map(Some)
            .map_err(application_error)
    }
    async fn acquire_lease(
        &self,
        operation: kitsunebi_domain::OperationId,
        holder: &str,
        now: u64,
        ttl: u64,
    ) -> Result<ApplicationOperationLease, ApplicationError> {
        let lease = self
            .claim_operation(operation, holder, ttl)
            .await
            .map_err(application_error)?;
        Ok(ApplicationOperationLease {
            operation,
            holder: lease.owner,
            attempt: u32::try_from(lease.attempt).unwrap_or(u32::MAX),
            expires_at: now.saturating_add(ttl),
        })
    }
    async fn create_idempotent(
        &self,
        request: &OperationRequest,
        operation: Operation,
    ) -> Result<Operation, ApplicationError> {
        self.create_idempotent_operation(
            &operation,
            &request.key,
            request.actor,
            operation_payload(request),
        )
        .await
        .map_err(application_error)
    }
    async fn operation_for_plan(
        &self,
        plan: kitsunebi_domain::PlanId,
    ) -> Result<Option<Operation>, ApplicationError> {
        self.get_operation_for_plan(plan)
            .await
            .map_err(application_error)
    }
    async fn release_lease(
        &self,
        lease: &ApplicationOperationLease,
    ) -> Result<(), ApplicationError> {
        let result = sqlx::query("UPDATE operations SET lease_owner = NULL, lease_until = NULL, version = version + 1 WHERE id = ? AND lease_owner = ?")
            .bind(lease.operation.as_uuid().to_string()).bind(&lease.holder).execute(self.pool()).await.map_err(|e| application_error(StorageError::Database(e)))?;
        if result.rows_affected() == 0 {
            return Err(ApplicationError::Conflict("operation lease"));
        }
        Ok(())
    }
    async fn operation(
        &self,
        id: kitsunebi_domain::OperationId,
    ) -> Result<Operation, ApplicationError> {
        self.get_operation(id)
            .await
            .map_err(application_error)?
            .ok_or(ApplicationError::NotFound("operation"))
    }
    async fn record_step_owned(
        &self,
        operation: kitsunebi_domain::OperationId,
        evidence: StepEvidence,
        holder: &str,
    ) -> Result<(), ApplicationError> {
        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|error| application_error(StorageError::Database(error)))?;
        let active: Option<String> = sqlx::query_scalar(
            "SELECT lease_owner FROM operations WHERE id = ? AND lease_until > CURRENT_TIMESTAMP(6) FOR UPDATE",
        )
        .bind(operation.as_uuid().to_string())
        .fetch_optional(&mut *tx)
        .await
        .map_err(|error| application_error(StorageError::Database(error)))?;
        if active.as_deref() != Some(holder) {
            return Err(ApplicationError::Conflict("operation lease"));
        }
        sqlx::query("INSERT INTO operation_steps (operation_id, sequence, state_hash, result, execution_evidence) VALUES (?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE state_hash = VALUES(state_hash), result = VALUES(result), execution_evidence = VALUES(execution_evidence)")
            .bind(operation.as_uuid().to_string())
            .bind(evidence.sequence)
            .bind(evidence.state_hash)
            .bind(evidence.result)
            .bind(evidence.execution.map(|value| serde_json::to_value(value).map_err(|_| ApplicationError::Port("step execution evidence serialization failed".into())))
                .transpose()?)
            .execute(&mut *tx)
            .await
            .map_err(|error| application_error(StorageError::Database(error)))?;
        tx.commit()
            .await
            .map_err(|error| application_error(StorageError::Database(error)))
    }
    async fn step_evidence(
        &self,
        operation: kitsunebi_domain::OperationId,
    ) -> Result<Vec<StepEvidence>, ApplicationError> {
        self.list_step_evidence(operation)
            .await
            .map_err(application_error)
    }
    async fn mark_state(
        &self,
        operation: kitsunebi_domain::OperationId,
        state: kitsunebi_domain::OperationState,
        holder: &str,
    ) -> Result<(), ApplicationError> {
        self.mark_operation_state(operation, state, holder)
            .await
            .map_err(application_error)
    }
    async fn renew_lease(
        &self,
        lease: &ApplicationOperationLease,
        ttl: u64,
    ) -> Result<ApplicationOperationLease, ApplicationError> {
        self.renew_operation_lease(lease.operation, &lease.holder, ttl)
            .await
            .map_err(application_error)?;
        Ok(ApplicationOperationLease {
            expires_at: lease.expires_at.saturating_add(ttl),
            ..lease.clone()
        })
    }
    async fn finish_operation(
        &self,
        lease: &ApplicationOperationLease,
        state: kitsunebi_domain::OperationState,
        result: serde_json::Value,
    ) -> Result<Operation, ApplicationError> {
        self.complete_operation(lease.operation, &lease.holder, state, result)
            .await
            .map_err(application_error)?;
        self.get_operation(lease.operation)
            .await
            .map_err(application_error)?
            .ok_or(ApplicationError::NotFound("operation"))
    }
    async fn finish_verified(
        &self,
        lease: &ApplicationOperationLease,
        session: kitsunebi_domain::ChangeSessionId,
        evidence: Vec<String>,
    ) -> Result<Operation, ApplicationError> {
        self.finish_operation_stage(
            lease,
            session,
            kitsunebi_domain::OperationState::Verified,
            serde_json::json!({"verified": evidence}),
        )
        .await
        .map_err(application_error)
    }
    async fn finish_accepted(
        &self,
        lease: &ApplicationOperationLease,
        session: kitsunebi_domain::ChangeSessionId,
    ) -> Result<Operation, ApplicationError> {
        self.finish_operation_stage(
            lease,
            session,
            kitsunebi_domain::OperationState::Accepted,
            serde_json::json!({"accepted": true}),
        )
        .await
        .map_err(application_error)
    }
    async fn finish_rolled_back(
        &self,
        lease: &ApplicationOperationLease,
        session: kitsunebi_domain::ChangeSessionId,
    ) -> Result<Operation, ApplicationError> {
        self.finish_operation_stage(
            lease,
            session,
            kitsunebi_domain::OperationState::RolledBack,
            serde_json::json!({"rolled_back": true}),
        )
        .await
        .map_err(application_error)
    }
    async fn fail_operation(
        &self,
        operation: kitsunebi_domain::OperationId,
        failure: OperationFailure,
        holder: &str,
    ) -> Result<(), ApplicationError> {
        self.mark_operation_failed(operation, &failure.code, &failure.evidence, holder)
            .await
            .map_err(application_error)
    }
}
fn session_state(value: &ChangeSession) -> &'static str {
    match value.state {
        kitsunebi_domain::ChangeSessionState::Open => "open",
        kitsunebi_domain::ChangeSessionState::Editing => "editing",
        kitsunebi_domain::ChangeSessionState::Ready => "ready",
        kitsunebi_domain::ChangeSessionState::Applying => "applying",
        kitsunebi_domain::ChangeSessionState::Verifying => "verifying",
        kitsunebi_domain::ChangeSessionState::Accepted => "accepted",
        kitsunebi_domain::ChangeSessionState::RolledBack => "rolled_back",
        kitsunebi_domain::ChangeSessionState::Aborted => "aborted",
        kitsunebi_domain::ChangeSessionState::Conflicted => "conflicted",
    }
}

fn operation_payload_matches(
    payload: &serde_json::Value,
    request: &application::OperationRequest,
) -> bool {
    let actor = request.actor.as_uuid().to_string();
    let service = request.service.as_uuid().to_string();
    payload.get("kind").and_then(serde_json::Value::as_str) == Some("operation")
        && payload
            .get("idempotency_key")
            .and_then(serde_json::Value::as_str)
            == Some(request.key.as_str())
        && payload
            .get("request_hash")
            .and_then(serde_json::Value::as_str)
            == Some(request.request_hash.as_str())
        && payload.get("actor").and_then(serde_json::Value::as_str) == Some(actor.as_str())
        && payload.get("target").and_then(serde_json::Value::as_str)
            == Some(request.target.as_str())
        && payload
            .get("payload")
            .and_then(|value| value.get("service"))
            .and_then(serde_json::Value::as_str)
            == Some(service.as_str())
        && payload
            .get("session_id")
            .and_then(serde_json::Value::as_str)
            == Some(request.session_id.as_uuid().to_string().as_str())
}

fn operation_payload(request: &application::OperationRequest) -> serde_json::Value {
    serde_json::json!({
        "kind": "operation",
        "idempotency_key": request.key,
        "request_hash": request.request_hash,
        "actor": request.actor.as_uuid().to_string(),
        "target": request.target,
        "session_id": request.session_id.as_uuid().to_string(),
        "payload": {"service": request.service.as_uuid().to_string()},
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> application::OperationRequest {
        application::OperationRequest {
            key: "request-1".into(),
            actor: ActorId::new(),
            service: kitsunebi_domain::ServiceId::new(),
            session_id: kitsunebi_domain::ChangeSessionId::new(),
            target: "cluster-1".into(),
            request_hash: "hash-1".into(),
        }
    }

    #[test]
    fn operation_identity_requires_kind_actor_service_target_hash_and_session() {
        let request = request();
        let payload = operation_payload(&request);
        assert!(operation_payload_matches(&payload, &request));

        let mut changed = request.clone();
        changed.actor = ActorId::new();
        assert!(!operation_payload_matches(&payload, &changed));
        changed = request.clone();
        changed.session_id = kitsunebi_domain::ChangeSessionId::new();
        assert!(!operation_payload_matches(&payload, &changed));
        changed = request.clone();
        changed.key = "another-apply-key".into();
        assert!(!operation_payload_matches(&payload, &changed));
        changed = request.clone();
        changed.request_hash = "another-request-hash".into();
        assert!(!operation_payload_matches(&payload, &changed));
    }

    #[test]
    fn stored_policy_rejects_unknown_role_and_permission_values() {
        let unknown_permission = serde_json::json!([{
            "actor": uuid::Uuid::new_v4(),
            "role": "operator",
            "service_scope": uuid::Uuid::new_v4(),
            "permissions": ["console.unknown"]
        }]);
        assert!(
            serde_json::from_value::<Vec<kitsunebi_domain::AccessGrant>>(unknown_permission)
                .is_err()
        );

        let unknown_role = serde_json::json!([{
            "actor": uuid::Uuid::new_v4(),
            "role": "superuser",
            "service_scope": uuid::Uuid::new_v4(),
            "permissions": ["console.send"]
        }]);
        assert!(
            serde_json::from_value::<Vec<kitsunebi_domain::AccessGrant>>(unknown_role).is_err()
        );
    }

    #[test]
    fn stored_audit_source_and_result_are_closed() {
        assert_eq!(
            repositories::audit_source("application").unwrap(),
            kitsunebi_domain::AuditSource::Application
        );
        assert_eq!(
            repositories::audit_result("failure").unwrap(),
            kitsunebi_domain::AuditResult::Failure
        );
        assert!(repositories::audit_source("worker").is_err());
        assert!(repositories::audit_result("unknown").is_err());
    }

    #[test]
    fn secret_audit_evidence_keeps_only_digest_and_byte_count() {
        let digest = "A".repeat(64);
        let event = kitsunebi_domain::AuditEvent {
            actor: ActorId::new(),
            action: "console.send".into(),
            target: "execution-unit".into(),
            classification: kitsunebi_domain::FileClassification::Secret,
            scope: kitsunebi_domain::AuditScope::for_service(kitsunebi_domain::ServiceId::new()),
            source: kitsunebi_domain::AuditSource::Application,
            result: kitsunebi_domain::AuditResult::Success,
            before_revision: None,
            after_revision: None,
            plan_hash: None,
            request_id: None,
            evidence: vec![
                format!("digest={digest}"),
                "bytes=0042".into(),
                "say password=do-not-store".into(),
                "content=raw-content".into(),
                "digest=not-a-digest".into(),
                "bytes=-1".into(),
            ],
        };
        assert_eq!(
            repositories::safe_evidence(&event).unwrap(),
            serde_json::json!([
                format!("digest={}", digest.to_ascii_lowercase()),
                "bytes=42"
            ])
        );
    }

    #[test]
    fn policy_grant_identity_binding_requires_matching_kind_and_service() {
        let service = kitsunebi_domain::ServiceId::new();
        let other = kitsunebi_domain::ServiceId::new();
        let service_text = service.as_uuid().to_string();
        assert!(repositories::policy_grant_identity_matches(
            "service",
            Some(&service_text),
            Some(service),
            service,
        ));
        assert!(!repositories::policy_grant_identity_matches(
            "service",
            Some(&service_text),
            Some(other),
            service,
        ));
        assert!(repositories::policy_grant_identity_matches(
            "browser",
            None,
            Some(service),
            service,
        ));
        assert!(!repositories::policy_grant_identity_matches(
            "browser",
            Some(&service_text),
            Some(service),
            service,
        ));
        assert!(!repositories::policy_grant_identity_matches(
            "unknown",
            None,
            Some(service),
            service,
        ));
    }
}
