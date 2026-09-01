//! Optional MySQL migration smoke tests.
//!
//! Run with `DATABASE_URL='mysql://...' cargo test --test mysql-migrations`. Credentials
//! are consumed by SQLx and are never printed. Without DATABASE_URL this test
//! exits successfully, allowing unit-only development without a database.

use kitsunebi_application::OperationLease as ApplicationOperationLease;
use kitsunebi_domain::{
    AccessGrant, AccessPolicy, ActorId, Artifact, ArtifactSet, AuditEvent, AuditResult, AuditScope,
    AuditSource, ChangeSession, ChangeSessionState, ClusterRevision, ConfigBaseline,
    ConfigBaselineEntry, EndpointBinding, ExternalEndpoint, FileClassification, GameAPBinding,
    GameAPBindingTarget, GameCluster, MCPlayNetwork, Operation, OperationState, Permission,
    PlanDescriptor, PlanTarget, ProxyInstance, ProxyInstanceId, ProxyPool, ProxyPoolId, ProxyState,
    Role, RuntimeProfile, Service, World, WorldExecutionModel, WorldWriteMode,
};
use kitsunebi_domain::{Audience, OperatorModel, Ownership, TrustProfile};
use kitsunebi_storage::StorageError;
use kitsunebi_storage::{ActorKind, MySqlStorage};
use serde_json::json;
use uuid::Uuid;

#[test]
fn initial_schema_keeps_second_wave_contracts_closed_and_non_nullable() {
    let schema = include_str!("../../migrations/0001_initial.sql");

    assert!(schema.contains("idempotency_key VARCHAR(255) NOT NULL"));
    assert!(schema.contains("request_hash CHAR(64) NOT NULL"));
    assert!(schema.contains("CREATE TABLE actor_identities"));
    assert!(schema.contains("kind VARCHAR(16) NOT NULL"));
    assert!(schema.contains(
        "source_hash BINARY(32) GENERATED ALWAYS AS (UNHEX(SHA2(source, 256))) STORED NOT NULL"
    ));
    assert!(schema.contains("UNIQUE KEY uq_artifact_source (source_hash, source_id, digest)"));
    assert!(schema.contains("UNIQUE KEY uq_plan_request (change_session_id, idempotency_key)"));
    assert!(schema.contains("CREATE TRIGGER change_sessions_actor_identity"));
    assert!(schema.contains("CREATE TRIGGER plans_actor_identity"));
    assert!(schema.contains("change_session_id CHAR(36) NOT NULL"));
    assert!(schema.contains("CREATE TABLE sftp_endpoints"));
    assert!(schema.contains("CREATE TABLE sftp_scans"));
    assert!(schema.contains("CREATE TABLE node_capability_observations"));
    assert!(schema.contains("CREATE TABLE tcp_shield_backend_sets"));
    assert!(schema.contains("provider_network_id BIGINT UNSIGNED NOT NULL"));
    assert!(schema.contains("CREATE TABLE proxy_instance_bindings"));
    assert!(schema.contains("CREATE TABLE service_tombstones"));
    assert_eq!(schema.matches("UNIQUE KEY uq_operation_key").count(), 1);
    assert_eq!(schema.matches("fk_operation_session").count(), 1);
}

#[tokio::test]
async fn fresh_schema_is_repeatable() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        return;
    };
    let storage = MySqlStorage::connect(&url).await.expect("connect MySQL");
    storage.migrate().await.expect("first migration");
    storage.migrate().await.expect("second migration");
    storage.ping().await.expect("ping MySQL");
}

#[tokio::test]
async fn artifacts_round_trip_through_domain_and_db_version_columns() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        return;
    };
    let storage = MySqlStorage::connect(&url).await.expect("connect MySQL");
    storage.migrate().await.expect("migration");

    let suffix = Uuid::new_v4().simple().to_string();
    let artifact = Artifact {
        id: Default::default(),
        kind: "plugin".into(),
        name: format!("artifact-{suffix}"),
        version: "1.2.3".into(),
        source: "test".into(),
        source_id: format!("source-{suffix}"),
        digest: "a".repeat(64),
        filename: "plugin.jar".into(),
        compatibility: "{}".into(),
        metadata: "{}".into(),
    };
    storage
        .create_artifact(&artifact)
        .await
        .expect("artifact insert");
    assert_eq!(
        storage.get_artifact(artifact.id).await.unwrap(),
        Some(artifact.clone())
    );

    let mut updated = artifact.clone();
    updated.version = "1.2.4".into();
    storage
        .update_artifact(&updated, 1)
        .await
        .expect("artifact CAS update");
    assert_eq!(
        storage.get_artifact(artifact.id).await.unwrap(),
        Some(updated.clone())
    );
    assert!(matches!(
        storage.update_artifact(&updated, 1).await,
        Err(StorageError::Conflict { entity: "artifact" })
    ));
}

#[tokio::test]
async fn persistence_invariants_are_enforced() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        return;
    };
    let storage = MySqlStorage::connect(&url).await.expect("connect MySQL");
    storage.migrate().await.expect("migration");

    let suffix = Uuid::new_v4().simple().to_string();
    let network = MCPlayNetwork::new(&format!("test-{suffix}"), "migration test").unwrap();
    storage
        .create_network(&network)
        .await
        .expect("network insert");
    let mut changed = network.clone();
    changed.display_name = "changed".into();
    storage
        .update_network(&changed, 1)
        .await
        .expect("network CAS");
    assert!(matches!(
        storage.update_network(&changed, 1).await,
        Err(StorageError::Conflict { entity: "network" })
    ));

    let service = Service::new(
        &format!("service-{suffix}"),
        "migration service",
        Ownership::FirstParty,
        Audience::Public,
        OperatorModel::Central,
        TrustProfile::Trusted,
    )
    .unwrap();
    storage
        .create_service(network.id, &service)
        .await
        .expect("service insert");
    let cluster = GameCluster::new(service.id, &format!("cluster-{suffix}")).unwrap();
    storage
        .create_cluster(&cluster)
        .await
        .expect("cluster insert");
    let other_service = Service::new(
        &format!("other-service-{suffix}"),
        "other service",
        Ownership::FirstParty,
        Audience::Public,
        OperatorModel::Central,
        TrustProfile::Trusted,
    )
    .unwrap();
    storage
        .create_service(network.id, &other_service)
        .await
        .expect("other service insert");
    let other_cluster =
        GameCluster::new(other_service.id, &format!("other-cluster-{suffix}")).unwrap();
    storage
        .create_cluster(&other_cluster)
        .await
        .expect("other cluster insert");
    let world = World::new(
        &format!("world-{suffix}"),
        "migration world",
        WorldWriteMode::SingleWriter,
        WorldExecutionModel::SingleProcess,
    )
    .unwrap();
    storage
        .create_world(cluster.id, &world)
        .await
        .expect("world insert");
    storage
        .cutover_world_writer(world.id, 1, None, cluster.id)
        .await
        .expect("writer cutover");
    assert!(matches!(
        storage
            .cutover_world_writer(world.id, 1, None, cluster.id)
            .await,
        Err(StorageError::Conflict {
            entity: "world writer"
        })
    ));
    assert!(matches!(
        storage
            .cutover_world_writer(world.id, 2, Some(other_cluster.id), other_cluster.id)
            .await,
        Err(StorageError::Conflict {
            entity: "world writer"
        })
    ));
    assert_eq!(
        storage.list_world_writers(world.id).await.unwrap(),
        vec![cluster.id]
    );

    let session = ChangeSession {
        id: Default::default(),
        target_cluster: cluster.id,
        state: ChangeSessionState::Ready,
        version: 1,
    };
    let actor = ActorId::new();
    let unregistered_actor = ActorId::new();
    assert!(matches!(
        storage
            .create_change_session(
                &session,
                unregistered_actor,
                &format!("unregistered-{suffix}"),
                &"u".repeat(64),
            )
            .await,
        Err(StorageError::NotFound {
            entity: "actor identity"
        })
    ));
    storage
        .register_actor_identity(
            actor,
            ActorKind::Browser,
            &format!("browser-{suffix}"),
            None,
        )
        .await
        .expect("browser actor identity");
    let service_actor = ActorId::new();
    storage
        .register_actor_identity(
            service_actor,
            ActorKind::Service,
            &format!("service-{suffix}"),
            Some(service.id),
        )
        .await
        .expect("service actor identity");
    assert_eq!(
        storage.actor_identity(service_actor).await.unwrap(),
        Some(kitsunebi_storage::ActorIdentity {
            actor_id: service_actor,
            kind: ActorKind::Service,
            subject: format!("service-{suffix}"),
            service_id: Some(service.id),
        })
    );
    let policy = AccessPolicy {
        id: Default::default(),
        grants: vec![AccessGrant {
            actor,
            role: Role::Operator,
            service_scope: Some(service.id),
            permissions: vec![Permission::ServiceRead, Permission::WorldRead],
        }],
    };
    storage
        .create_access_policy(&policy)
        .await
        .expect("policy insert");
    storage
        .bind_access_policy_to_service(policy.id, service.id)
        .await
        .expect("policy binding");
    let cross_scope_policy = AccessPolicy {
        id: policy.id,
        grants: vec![AccessGrant {
            actor,
            role: Role::Operator,
            service_scope: Some(other_service.id),
            permissions: vec![Permission::ServiceRead],
        }],
    };
    assert!(matches!(
        storage
            .update_access_policy_for_service(&cross_scope_policy, service.id, 1)
            .await,
        Err(StorageError::Conflict {
            entity: "access policy service scope"
        })
    ));
    let global_scope_policy = AccessPolicy {
        id: policy.id,
        grants: vec![AccessGrant {
            actor,
            role: Role::Operator,
            service_scope: None,
            permissions: vec![Permission::ServiceRead],
        }],
    };
    assert!(matches!(
        storage
            .update_access_policy_for_service(&global_scope_policy, service.id, 1)
            .await,
        Err(StorageError::Conflict {
            entity: "access policy service scope"
        })
    ));
    storage
        .bind_access_policy_to_service(policy.id, other_service.id)
        .await
        .expect("shared policy binding");
    assert!(matches!(
        storage
            .update_access_policy_for_service(&policy, service.id, 1)
            .await,
        Err(StorageError::Conflict {
            entity: "access policy owner"
        })
    ));
    assert_eq!(
        storage
            .resource_service_scope(
                kitsunebi_storage::ResourceKind::Cluster,
                cluster.id.as_uuid(),
            )
            .await
            .expect("cluster scope"),
        vec![service.id]
    );
    let visible = storage
        .list_clusters_for_actor(actor, &Permission::ServiceRead, 100, None)
        .await
        .expect("actor cluster list");
    assert!(visible.items.iter().any(|item| item.id == cluster.id));
    assert!(!visible.items.iter().any(|item| item.id == other_cluster.id));
    let visible_worlds = storage
        .list_worlds_for_actor(actor, &Permission::WorldRead, 100, None)
        .await
        .expect("actor world list");
    assert!(visible_worlds.items.iter().any(|item| item.id == world.id));
    storage
        .create_change_session(
            &session,
            actor,
            &format!("migration-session-{suffix}"),
            &"d".repeat(64),
        )
        .await
        .expect("session insert");
    let plan = PlanDescriptor::new(
        actor,
        PlanTarget::Cluster(cluster.id),
        1,
        4_000_000_000,
        vec![],
    )
    .unwrap();
    let plan_request_key = format!("migration-plan-{suffix}");
    let plan_request_hash = "p".repeat(64);
    let plan_audit = AuditEvent {
        actor,
        action: "change.plan".into(),
        target: format!("cluster:{}", cluster.id.as_uuid()),
        classification: FileClassification::Managed,
        scope: AuditScope::for_cluster(service.id, cluster.id),
        source: AuditSource::Application,
        result: AuditResult::Success,
        before_revision: None,
        after_revision: None,
        plan_hash: Some(plan.plan_hash.clone()),
        request_id: Some(format!("request-{suffix}")),
        evidence: vec!["plan-evidence:digest".into()],
    };
    let persisted_plan = storage
        .create_plan_atomic(
            &plan,
            session.id,
            &plan_request_key,
            &plan_request_hash,
            &plan_audit,
        )
        .await
        .expect("plan insert");
    assert_eq!(persisted_plan, plan);
    let replayed_plan = storage
        .create_plan_atomic(
            &plan,
            session.id,
            &plan_request_key,
            &plan_request_hash,
            &plan_audit,
        )
        .await
        .expect("plan replay");
    assert_eq!(replayed_plan, plan);
    assert!(matches!(
        storage
            .create_plan_atomic(
                &plan,
                session.id,
                &plan_request_key,
                &"x".repeat(64),
                &plan_audit,
            )
            .await,
        Err(StorageError::IdempotencyConflict)
    ));
    let audit_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_events WHERE action = 'change.plan' AND plan_hash = ?",
    )
    .bind(&plan.plan_hash)
    .fetch_one(storage.pool())
    .await
    .unwrap();
    assert_eq!(audit_count, 1);
    let stored_plan_audit = storage
        .read_audit_events(20)
        .await
        .unwrap()
        .into_iter()
        .find(|record| record.event.action == "change.plan")
        .expect("stored plan audit");
    assert_eq!(stored_plan_audit.event.request_id, plan_audit.request_id);
    assert_eq!(stored_plan_audit.event.evidence, plan_audit.evidence);
    let proxy_pool = ProxyPool {
        id: ProxyPoolId::new(),
        key: format!("binding-pool-{suffix}"),
        instances: vec![],
    };
    storage
        .create_proxy_pool(&proxy_pool)
        .await
        .expect("proxy pool for binding targets");
    let proxy = ProxyInstance {
        id: ProxyInstanceId::new(),
        pool_id: proxy_pool.id,
        key: format!("binding-proxy-{suffix}"),
        state: ProxyState::Preparing,
    };
    storage
        .create_proxy_instance(&proxy)
        .await
        .expect("proxy for binding targets");
    let binding_inputs = vec![
        (GameAPBindingTarget::Service(service.id), "binding-service"),
        (GameAPBindingTarget::Cluster(cluster.id), "binding-cluster"),
        (
            GameAPBindingTarget::ExecutionUnit(format!("binding-execution-{suffix}")),
            "binding-execution",
        ),
        (GameAPBindingTarget::World(world.id), "binding-world"),
        (
            GameAPBindingTarget::ProxyInstance(proxy.id),
            "binding-proxy",
        ),
    ];
    let mut binding_ids = Vec::new();
    for (target, label) in &binding_inputs {
        let binding = GameAPBinding {
            execution_unit_id: format!("gameap-{suffix}-{label}"),
            node_id: format!("node-{suffix}"),
            target: target.clone(),
        };
        let id = storage
            .create_gameap_binding(&binding)
            .await
            .expect("binding target insert");
        let stored = storage
            .get_gameap_binding(id)
            .await
            .expect("binding target read")
            .expect("binding exists");
        assert_eq!(stored, binding);
        if matches!(
            target,
            GameAPBindingTarget::Service(_)
                | GameAPBindingTarget::Cluster(_)
                | GameAPBindingTarget::World(_)
        ) {
            assert_eq!(
                storage
                    .resource_service_scope(kitsunebi_storage::ResourceKind::GameAPBinding, id,)
                    .await
                    .expect("binding actor scope"),
                vec![service.id]
            );
        }
        binding_ids.push(id);
    }
    let duplicate_ref = GameAPBinding {
        execution_unit_id: format!("gameap-{suffix}-binding-service"),
        node_id: format!("node-{suffix}"),
        target: GameAPBindingTarget::Service(service.id),
    };
    assert!(matches!(
        storage.create_gameap_binding(&duplicate_ref).await,
        Err(StorageError::Conflict {
            entity: "GameAP binding"
        })
    ));
    let conflicting_update = GameAPBinding {
        execution_unit_id: format!("gameap-{suffix}-binding-cluster"),
        node_id: format!("node-{suffix}"),
        target: GameAPBindingTarget::Service(service.id),
    };
    assert!(matches!(
        storage
            .update_gameap_binding(binding_ids[0], &conflicting_update, 1)
            .await,
        Err(StorageError::Conflict {
            entity: "GameAP binding"
        })
    ));
    assert!(sqlx::query("INSERT INTO gameap_bindings (id, execution_unit_ref, node_id, metadata) VALUES (?, ?, ?, ?)")
        .bind(Uuid::new_v4().to_string())
        .bind("invalid-target")
        .bind("node")
        .bind(json!({}))
        .execute(storage.pool())
        .await
        .is_err());
    let operation = Operation {
        id: Default::default(),
        plan_id: plan.id,
        session_id: session.id,
        state: OperationState::Planned,
    };
    let first = storage
        .create_idempotent_operation(&operation, &format!("op-{suffix}"), actor, json!({"x": 1}))
        .await
        .expect("operation insert");
    assert_eq!(first.id, operation.id);
    let replay = storage
        .create_idempotent_operation(&operation, &format!("op-{suffix}"), actor, json!({"x": 1}))
        .await
        .expect("idempotent replay");
    assert_eq!(replay.id, operation.id);
    assert!(matches!(
        storage
            .create_idempotent_operation(
                &operation,
                &format!("op-{suffix}"),
                actor,
                json!({"x": 2})
            )
            .await,
        Err(StorageError::IdempotencyConflict)
    ));
    storage
        .claim_operation(operation.id, "worker-a", 60)
        .await
        .expect("lease claim");
    assert!(matches!(
        storage.claim_operation(operation.id, "worker-b", 60).await,
        Err(StorageError::LeaseUnavailable)
    ));
    storage
        .mark_operation_state(operation.id, OperationState::Applying, "worker-a")
        .await
        .expect("operation applying");
    storage
        .mark_operation_failed(operation.id, "execution_failed", &[], "worker-a")
        .await
        .expect("operation failure");
    let failed_lease = storage
        .claim_operation(operation.id, "worker-a", 60)
        .await
        .expect("failed operation lease");
    let failed_application_lease = ApplicationOperationLease {
        operation: failed_lease.operation.id,
        holder: failed_lease.owner.clone(),
        attempt: u32::try_from(failed_lease.attempt).expect("lease attempt fits in u32"),
        expires_at: u64::MAX,
    };
    assert!(matches!(
        storage
            .mark_operation_state(operation.id, OperationState::Applying, "worker-a")
            .await,
        Err(StorageError::LeaseUnavailable)
    ));
    assert!(matches!(
        storage
            .finish_operation_stage(
                &failed_application_lease,
                session.id,
                OperationState::RolledBack,
                json!({"rollback": "without-evidence"}),
            )
            .await,
        Err(StorageError::Conflict {
            entity: "failed operation evidence"
        })
    ));
    sqlx::query(
        "INSERT INTO operation_steps (operation_id, sequence, state_hash, result, execution_evidence) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(operation.id.as_uuid().to_string())
    .bind(1_u32)
    .bind("e".repeat(64))
    .bind("failed")
    .bind(json!({"provider": "digest:rollback"}))
    .execute(storage.pool())
    .await
    .expect("rollback evidence");
    storage
        .finish_operation_stage(
            &failed_application_lease,
            session.id,
            OperationState::RolledBack,
            json!({"rollback": "complete"}),
        )
        .await
        .expect("evidence-backed rollback");
    assert!(matches!(
        storage.claim_operation(operation.id, "worker-a", 60).await,
        Err(StorageError::LeaseUnavailable)
    ));
    let synced_state: String = sqlx::query_scalar("SELECT state FROM change_sessions WHERE id = ?")
        .bind(session.id.as_uuid().to_string())
        .fetch_one(storage.pool())
        .await
        .expect("synced change session state");
    assert_eq!(synced_state, "rolled_back");
    let orphan_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM operations o LEFT JOIN change_sessions s ON s.id = o.change_session_id WHERE s.id IS NULL",
    )
    .fetch_one(storage.pool())
    .await
    .expect("operation orphan count");
    assert_eq!(orphan_count, 0);

    let event = AuditEvent {
        actor,
        action: "migration-test".into(),
        target: "target-is-not-used-for-scope".into(),
        classification: FileClassification::Unknown,
        scope: AuditScope {
            service_id: service.id,
            cluster_id: Some(cluster.id),
            world_id: Some(world.id),
            execution_unit_ref: Some(format!("audit-execution-{suffix}")),
            operation_id: Some(operation.id),
        },
        source: AuditSource::System,
        result: AuditResult::Success,
        before_revision: Some(4),
        after_revision: Some(5),
        plan_hash: Some(format!("plan-{suffix}")),
        request_id: Some(format!("request-{suffix}")),
        evidence: vec!["hash:example".into()],
    };
    let event_id = storage
        .append_audit_event(&event)
        .await
        .expect("audit append");
    let events = storage.read_audit_events(10).await.expect("audit read");
    assert!(events.iter().any(|stored| stored.event == event));
    assert_eq!(
        storage
            .resource_service_scope(kitsunebi_storage::ResourceKind::AuditEvent, event_id)
            .await
            .expect("audit service scope"),
        vec![service.id]
    );
    assert!(
        sqlx::query("UPDATE audit_events SET action = 'tampered'")
            .execute(storage.pool())
            .await
            .is_err()
    );
    assert!(
        sqlx::query("DELETE FROM audit_events")
            .execute(storage.pool())
            .await
            .is_err()
    );

    // The fixture is disposable by contract (DATABASE_URL must point to a test
    // schema). Audit rows intentionally remain because the table is append-only;
    // remove the other rows created by this test without dropping a database or
    // touching unrelated data.
    for binding_id in binding_ids {
        sqlx::query("DELETE FROM gameap_bindings WHERE id = ?")
            .bind(binding_id.to_string())
            .execute(storage.pool())
            .await
            .expect("binding cleanup");
    }
    sqlx::query("DELETE FROM proxy_instances WHERE id = ?")
        .bind(proxy.id.as_uuid().to_string())
        .execute(storage.pool())
        .await
        .expect("proxy cleanup");
    sqlx::query("DELETE FROM proxy_pools WHERE id = ?")
        .bind(proxy_pool.id.as_uuid().to_string())
        .execute(storage.pool())
        .await
        .expect("proxy pool cleanup");
    sqlx::query("DELETE FROM operation_steps WHERE operation_id = ?")
        .bind(operation.id.as_uuid().to_string())
        .execute(storage.pool())
        .await
        .expect("operation step cleanup");
    sqlx::query("DELETE FROM operations WHERE id = ?")
        .bind(operation.id.as_uuid().to_string())
        .execute(storage.pool())
        .await
        .expect("operation cleanup");
    sqlx::query("DELETE FROM plans WHERE id = ?")
        .bind(plan.id.as_uuid().to_string())
        .execute(storage.pool())
        .await
        .expect("plan cleanup");
    sqlx::query("DELETE FROM change_sessions WHERE id = ?")
        .bind(session.id.as_uuid().to_string())
        .execute(storage.pool())
        .await
        .expect("session cleanup");
    sqlx::query("DELETE FROM world_writers WHERE world_id = ?")
        .bind(world.id.as_uuid().to_string())
        .execute(storage.pool())
        .await
        .expect("writer cleanup");
    sqlx::query("DELETE FROM worlds WHERE id = ?")
        .bind(world.id.as_uuid().to_string())
        .execute(storage.pool())
        .await
        .expect("world cleanup");
    sqlx::query("DELETE FROM clusters WHERE id = ?")
        .bind(cluster.id.as_uuid().to_string())
        .execute(storage.pool())
        .await
        .expect("cluster cleanup");
    sqlx::query("DELETE FROM clusters WHERE id = ?")
        .bind(other_cluster.id.as_uuid().to_string())
        .execute(storage.pool())
        .await
        .expect("other cluster cleanup");
    sqlx::query("DELETE FROM access_policy_bindings WHERE policy_id = ?")
        .bind(policy.id.as_uuid().to_string())
        .execute(storage.pool())
        .await
        .expect("policy binding cleanup");
    sqlx::query("DELETE FROM access_policies WHERE id = ?")
        .bind(policy.id.as_uuid().to_string())
        .execute(storage.pool())
        .await
        .expect("policy cleanup");
    sqlx::query("DELETE FROM actor_identities WHERE actor_id IN (?, ?)")
        .bind(actor.as_uuid().to_string())
        .bind(service_actor.as_uuid().to_string())
        .execute(storage.pool())
        .await
        .expect("actor identity cleanup");
    sqlx::query("DELETE FROM services WHERE id = ?")
        .bind(service.id.as_uuid().to_string())
        .execute(storage.pool())
        .await
        .expect("service cleanup");
    sqlx::query("DELETE FROM services WHERE id = ?")
        .bind(other_service.id.as_uuid().to_string())
        .execute(storage.pool())
        .await
        .expect("other service cleanup");
    sqlx::query("DELETE FROM networks WHERE id = ?")
        .bind(network.id.as_uuid().to_string())
        .execute(storage.pool())
        .await
        .expect("network cleanup");
}

#[tokio::test]
async fn current_binding_resolves_manifest_and_endpoint_revision_cas() {
    let Ok(url) = std::env::var("DATABASE_URL") else {
        return;
    };
    let storage = MySqlStorage::connect(&url).await.expect("connect MySQL");
    storage.migrate().await.expect("migration");

    let suffix = Uuid::new_v4().simple().to_string();
    let network =
        MCPlayNetwork::new(&format!("manifest-network-{suffix}"), "manifest test").unwrap();
    storage
        .create_network(&network)
        .await
        .expect("network insert");
    let service = Service::new(
        &format!("manifest-service-{suffix}"),
        "manifest service",
        Ownership::FirstParty,
        Audience::Public,
        OperatorModel::Central,
        TrustProfile::Trusted,
    )
    .unwrap();
    storage
        .create_service(network.id, &service)
        .await
        .expect("service insert");
    let cluster = GameCluster::new(service.id, &format!("manifest-cluster-{suffix}")).unwrap();
    storage
        .create_cluster(&cluster)
        .await
        .expect("cluster insert");

    let baseline = ConfigBaseline::new(vec![
        ConfigBaselineEntry::new(
            "server.properties",
            &"a".repeat(64),
            FileClassification::Managed,
        )
        .unwrap(),
        ConfigBaselineEntry::new("secrets/token", &"b".repeat(64), FileClassification::Secret)
            .unwrap(),
    ])
    .unwrap();
    storage
        .create_config_baseline(&baseline)
        .await
        .expect("baseline insert");
    let profile = RuntimeProfile {
        id: Default::default(),
        family: "paper".into(),
        minecraft_version: "1.21".into(),
        runtime_version: "17".into(),
        artifact_source: "test".into(),
        artifact_digest: "c".repeat(64),
        java_requirement: "17".into(),
        startup_capability: true,
        console_capability: true,
        health_capability: true,
        world_execution_capability: WorldExecutionModel::SingleProcess,
        metadata: String::new(),
    };
    storage
        .create_runtime_profile(&profile)
        .await
        .expect("runtime profile insert");
    let artifacts = ArtifactSet {
        id: Default::default(),
        artifacts: vec![],
    };
    storage
        .create_artifact_set(&artifacts)
        .await
        .expect("artifact set insert");

    let first_revision =
        ClusterRevision::new(1, profile.id, "1.21", artifacts.id, baseline.id).unwrap();
    storage
        .create_revision(cluster.id, &first_revision)
        .await
        .expect("first revision insert");
    storage
        .activate_revision(cluster.id, None, first_revision.id)
        .await
        .expect("first revision activation");

    let execution = GameAPBinding {
        execution_unit_id: format!("execution-{suffix}"),
        node_id: format!("node-{suffix}"),
        target: GameAPBindingTarget::Cluster(cluster.id),
    };
    storage
        .create_gameap_binding(&execution)
        .await
        .expect("execution binding insert");
    assert_eq!(
        storage
            .get_config_baseline_for_execution_unit(&execution.execution_unit_id)
            .await
            .expect("baseline resolution")
            .expect("resolved baseline"),
        baseline
    );

    let endpoint = ExternalEndpoint {
        id: Default::default(),
        key: format!("endpoint-{suffix}"),
        kind: "tcp".into(),
        logical_hostname: "play.example.test".into(),
        port: 25_565,
        role: "game".into(),
        metadata: String::new(),
    };
    storage
        .create_endpoint(&endpoint)
        .await
        .expect("endpoint insert");
    let first_binding = EndpointBinding::new(endpoint.id, cluster.id, first_revision.id, "game")
        .expect("first endpoint binding");
    storage
        .create_endpoint_binding(&first_binding)
        .await
        .expect("first endpoint binding insert");
    assert_eq!(
        storage
            .get_endpoint_binding(first_binding.id)
            .await
            .expect("endpoint binding read")
            .expect("endpoint binding exists"),
        first_binding
    );
    assert!(
        sqlx::query("UPDATE endpoint_bindings SET cluster_id = ? WHERE id = ?")
            .bind(cluster.id.as_uuid().to_string())
            .bind(first_binding.id.as_uuid().to_string())
            .execute(storage.pool())
            .await
            .is_err()
    );
    assert!(
        sqlx::query("DELETE FROM endpoint_bindings WHERE id = ?")
            .bind(first_binding.id.as_uuid().to_string())
            .execute(storage.pool())
            .await
            .is_err()
    );

    let second_revision =
        ClusterRevision::new(2, profile.id, "1.21", artifacts.id, baseline.id).unwrap();
    storage
        .create_revision(cluster.id, &second_revision)
        .await
        .expect("second revision insert");
    let second_binding = EndpointBinding::new(endpoint.id, cluster.id, second_revision.id, "game")
        .expect("second endpoint binding");
    storage
        .create_endpoint_binding(&second_binding)
        .await
        .expect("second endpoint binding insert");
    let revision_activated_version: u64 =
        sqlx::query_scalar("SELECT version FROM clusters WHERE id = ?")
            .bind(cluster.id.as_uuid().to_string())
            .fetch_one(storage.pool())
            .await
            .expect("revision-activated cluster version");
    storage
        .activate_endpoint_bindings_at_version(
            &first_binding,
            &second_binding,
            revision_activated_version,
        )
        .await
        .expect("endpoint revision activation");
    let activated_version: u64 = sqlx::query_scalar("SELECT version FROM clusters WHERE id = ?")
        .bind(cluster.id.as_uuid().to_string())
        .fetch_one(storage.pool())
        .await
        .expect("activated cluster version");
    assert_eq!(activated_version, revision_activated_version + 1);
    assert!(matches!(
        storage
            .activate_endpoint_bindings_at_version(
                &first_binding,
                &second_binding,
                revision_activated_version,
            )
            .await,
        Err(StorageError::Conflict {
            entity: "endpoint binding pair"
        })
    ));
    assert!(matches!(
        storage
            .activate_endpoint_bindings_at_version(
                &first_binding,
                &second_binding,
                activated_version,
            )
            .await,
        Err(StorageError::Conflict {
            entity: "endpoint binding pair"
        })
    ));
    assert_eq!(
        storage
            .get_cluster(cluster.id)
            .await
            .expect("cluster read")
            .expect("cluster exists")
            .current_revision,
        Some(second_revision.id)
    );
    assert!(matches!(
        storage
            .rollback_endpoint_bindings_at_version(
                cluster.id,
                first_binding.id,
                second_binding.id,
                revision_activated_version,
            )
            .await,
        Err(StorageError::Conflict {
            entity: "cluster revision"
        })
    ));
    storage
        .rollback_endpoint_bindings_at_version(
            cluster.id,
            first_binding.id,
            second_binding.id,
            activated_version,
        )
        .await
        .expect("endpoint revision rollback");
    assert_eq!(
        storage
            .get_cluster(cluster.id)
            .await
            .expect("cluster read after rollback")
            .expect("cluster exists after rollback")
            .current_revision,
        Some(first_revision.id)
    );
    let rolled_back_version: u64 = sqlx::query_scalar("SELECT version FROM clusters WHERE id = ?")
        .bind(cluster.id.as_uuid().to_string())
        .fetch_one(storage.pool())
        .await
        .expect("rolled-back cluster version");
    assert_eq!(rolled_back_version, activated_version + 1);
    assert!(matches!(
        storage
            .rollback_endpoint_bindings_at_version(
                cluster.id,
                first_binding.id,
                second_binding.id,
                activated_version,
            )
            .await,
        Err(StorageError::Conflict {
            entity: "cluster revision"
        })
    ));

    // Revisions and endpoint bindings are intentionally immutable. This
    // fixture therefore targets a disposable schema and leaves only those
    // append-only rows behind for the next run's unique suffix.
}
