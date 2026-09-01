-- Kitsunebi owns metadata and desired state.  Runtime data, secrets and binaries
-- remain in GameAP, the artifact store and the backup system respectively.

CREATE TABLE networks (
    id CHAR(36) NOT NULL PRIMARY KEY,
    `key` VARCHAR(128) NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    metadata JSON NOT NULL,
    version BIGINT UNSIGNED NOT NULL DEFAULT 1,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_network_key (`key`)
) ENGINE=InnoDB;

CREATE TABLE services (
    id CHAR(36) NOT NULL PRIMARY KEY,
    network_id CHAR(36) NOT NULL,
    `key` VARCHAR(128) NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    ownership VARCHAR(32) NOT NULL,
    audience VARCHAR(32) NOT NULL,
    operator_model VARCHAR(32) NOT NULL,
    trust_profile VARCHAR(32) NOT NULL,
    lifecycle VARCHAR(32) NOT NULL,
    availability VARCHAR(32) NOT NULL,
    current_cluster_id CHAR(36) NULL,
    access_policy_id CHAR(36) NULL,
    backup_policy JSON NOT NULL,
    metadata JSON NOT NULL,
    version BIGINT UNSIGNED NOT NULL DEFAULT 1,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_service_key (network_id, `key`),
    CONSTRAINT fk_service_network FOREIGN KEY (network_id) REFERENCES networks(id),
    CONSTRAINT ck_service_lifecycle CHECK (lifecycle IN ('planned','testing','active','maintenance','sunsetting','archived')),
    CONSTRAINT ck_service_availability CHECK (availability IN ('always_on','scheduled','on_demand','disabled'))
) ENGINE=InnoDB;

-- Actor ids are opaque references in the domain, but their origin and scope
-- are persisted here.  Every actor-bearing mutation must resolve through this
-- registry; an unknown or malformed identity is never treated as a browser or
-- service principal by convention.
CREATE TABLE actor_identities (
    actor_id CHAR(36) NOT NULL PRIMARY KEY,
    kind VARCHAR(16) NOT NULL,
    subject VARCHAR(255) NOT NULL,
    service_id CHAR(36) NULL,
    version BIGINT UNSIGNED NOT NULL DEFAULT 1,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_actor_subject (kind, subject),
    UNIQUE KEY uq_service_actor (service_id),
    CONSTRAINT fk_actor_service FOREIGN KEY (service_id) REFERENCES services(id),
    CONSTRAINT ck_actor_kind_scope CHECK (
        (kind = 'browser' AND service_id IS NULL)
        OR (kind = 'service' AND service_id IS NOT NULL)
    ),
    CONSTRAINT ck_actor_id_format CHECK (CHAR_LENGTH(actor_id) = 36)
) ENGINE=InnoDB;

CREATE TABLE runtime_profiles (
    id CHAR(36) NOT NULL PRIMARY KEY,
    `key` VARCHAR(128) NOT NULL UNIQUE,
    family VARCHAR(64) NOT NULL,
    minecraft_version VARCHAR(64) NOT NULL,
    runtime_version VARCHAR(128) NOT NULL,
    artifact_source VARCHAR(1024) NOT NULL,
    artifact_digest CHAR(64) NOT NULL,
    java_requirement VARCHAR(128) NOT NULL,
    startup_capability BOOLEAN NOT NULL,
    console_capability BOOLEAN NOT NULL,
    health_capability BOOLEAN NOT NULL,
    world_execution_capability VARCHAR(32) NOT NULL,
    metadata JSON NOT NULL,
    version BIGINT UNSIGNED NOT NULL DEFAULT 1,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT ck_runtime_world_execution CHECK (world_execution_capability IN ('single_process','region_parallel','partitioned_world','externally_distributed'))
) ENGINE=InnoDB;

CREATE TABLE clusters (
    id CHAR(36) NOT NULL PRIMARY KEY,
    service_id CHAR(36) NOT NULL,
    `key` VARCHAR(128) NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    current_revision_id CHAR(36) NULL,
    version BIGINT UNSIGNED NOT NULL DEFAULT 1,
    metadata JSON NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_cluster_key (service_id, `key`),
    CONSTRAINT fk_cluster_service FOREIGN KEY (service_id) REFERENCES services(id)
) ENGINE=InnoDB;

ALTER TABLE services ADD CONSTRAINT fk_service_cluster FOREIGN KEY (current_cluster_id) REFERENCES clusters(id);

CREATE TABLE artifact_sets (
    id CHAR(36) NOT NULL PRIMARY KEY,
    `key` VARCHAR(128) NOT NULL UNIQUE,
    manifest JSON NOT NULL,
    manifest_digest CHAR(64) NOT NULL,
    metadata JSON NOT NULL,
    version BIGINT UNSIGNED NOT NULL DEFAULT 1,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB;
CREATE TABLE artifacts (
    id CHAR(36) NOT NULL PRIMARY KEY,
    kind VARCHAR(64) NOT NULL,
    name VARCHAR(255) NOT NULL,
    artifact_version VARCHAR(128) NOT NULL,
    source VARCHAR(1024) NOT NULL,
    source_id VARCHAR(255) NOT NULL,
    digest CHAR(64) NOT NULL,
    filename VARCHAR(255) NOT NULL,
    compatibility JSON NOT NULL,
    metadata JSON NOT NULL,
    version BIGINT UNSIGNED NOT NULL DEFAULT 1,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    -- Keep the full source value while indexing a fixed-width digest.  The
    -- three original utf8mb4 columns can exceed InnoDB's 3072-byte key limit.
    source_hash BINARY(32) GENERATED ALWAYS AS (UNHEX(SHA2(source, 256))) STORED NOT NULL,
    UNIQUE KEY uq_artifact_source (source_hash, source_id, digest)
) ENGINE=InnoDB;
CREATE TABLE artifact_set_items (
    artifact_set_id CHAR(36) NOT NULL,
    artifact_id CHAR(36) NOT NULL,
    PRIMARY KEY (artifact_set_id, artifact_id),
    CONSTRAINT fk_artifact_set_item_set FOREIGN KEY (artifact_set_id) REFERENCES artifact_sets(id),
    CONSTRAINT fk_artifact_set_item_artifact FOREIGN KEY (artifact_id) REFERENCES artifacts(id)
) ENGINE=InnoDB;

CREATE TABLE config_baselines (
    id CHAR(36) NOT NULL PRIMARY KEY,
    `key` VARCHAR(128) NOT NULL UNIQUE,
    manifest JSON NOT NULL,
    manifest_digest CHAR(64) NOT NULL,
    metadata JSON NOT NULL,
    version BIGINT UNSIGNED NOT NULL DEFAULT 1,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB;

CREATE TABLE cluster_revisions (
    id CHAR(36) NOT NULL PRIMARY KEY,
    cluster_id CHAR(36) NOT NULL,
    revision_number BIGINT UNSIGNED NOT NULL,
    runtime_profile_id CHAR(36) NOT NULL,
    minecraft_version VARCHAR(64) NOT NULL,
    java_requirement VARCHAR(128) NOT NULL,
    artifact_set_id CHAR(36) NOT NULL,
    config_baseline_id CHAR(36) NOT NULL,
    world_bindings JSON NOT NULL,
    endpoint_bindings JSON NOT NULL,
    placement_requirements JSON NOT NULL,
    resource_requirements JSON NOT NULL,
    health_checks JSON NOT NULL,
    startup_parameters JSON NOT NULL,
    metadata JSON NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_cluster_revision (cluster_id, revision_number),
    CONSTRAINT fk_revision_cluster FOREIGN KEY (cluster_id) REFERENCES clusters(id),
    CONSTRAINT fk_revision_runtime FOREIGN KEY (runtime_profile_id) REFERENCES runtime_profiles(id),
    CONSTRAINT fk_revision_artifacts FOREIGN KEY (artifact_set_id) REFERENCES artifact_sets(id),
    CONSTRAINT fk_revision_config FOREIGN KEY (config_baseline_id) REFERENCES config_baselines(id)
) ENGINE=InnoDB;
ALTER TABLE clusters ADD CONSTRAINT fk_cluster_revision FOREIGN KEY (current_revision_id) REFERENCES cluster_revisions(id);
CREATE TRIGGER cluster_revisions_no_update BEFORE UPDATE ON cluster_revisions FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'cluster revisions are immutable';
CREATE TRIGGER cluster_revisions_no_delete BEFORE DELETE ON cluster_revisions FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'cluster revisions are immutable';

CREATE TABLE worlds (
    id CHAR(36) NOT NULL PRIMARY KEY,
    cluster_id CHAR(36) NOT NULL,
    `key` VARCHAR(128) NOT NULL,
    display_name VARCHAR(255) NOT NULL,
    persistence VARCHAR(32) NOT NULL,
    storage_ref VARCHAR(1024) NOT NULL,
    write_mode VARCHAR(32) NOT NULL,
    execution_model VARCHAR(32) NOT NULL,
    current_writer_id CHAR(36) NULL,
    backup_policy JSON NOT NULL,
    metadata JSON NOT NULL,
    version BIGINT UNSIGNED NOT NULL DEFAULT 1,
    UNIQUE KEY uq_world_key (cluster_id, `key`),
    CONSTRAINT fk_world_cluster FOREIGN KEY (cluster_id) REFERENCES clusters(id),
    CONSTRAINT ck_world_write_mode CHECK (write_mode IN ('single_writer','externally_coordinated')),
    CONSTRAINT ck_world_execution_model CHECK (execution_model IN ('single_process','region_parallel','partitioned_world','externally_distributed'))
) ENGINE=InnoDB;

CREATE TABLE world_writers (
    id CHAR(36) NOT NULL PRIMARY KEY,
    world_id CHAR(36) NOT NULL,
    cluster_id CHAR(36) NOT NULL,
    execution_unit_ref VARCHAR(255) NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    acquired_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    released_at DATETIME(6) NULL,
    UNIQUE KEY uq_world_writer (world_id, id),
    CONSTRAINT fk_writer_world FOREIGN KEY (world_id) REFERENCES worlds(id),
    CONSTRAINT fk_writer_cluster FOREIGN KEY (cluster_id) REFERENCES clusters(id)
) ENGINE=InnoDB;
ALTER TABLE worlds ADD CONSTRAINT fk_world_writer FOREIGN KEY (current_writer_id) REFERENCES world_writers(id);
CREATE TRIGGER world_writers_single_writer_insert BEFORE INSERT ON world_writers
FOR EACH ROW
BEGIN
    IF NEW.active AND (SELECT write_mode FROM worlds WHERE id = NEW.world_id) = 'single_writer'
       AND EXISTS (SELECT 1 FROM world_writers WHERE world_id = NEW.world_id AND active) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'single-writer world already has an active writer';
    END IF;
END;
CREATE TRIGGER world_writers_single_writer_update BEFORE UPDATE ON world_writers
FOR EACH ROW
BEGIN
    IF NEW.active AND (SELECT write_mode FROM worlds WHERE id = NEW.world_id) = 'single_writer'
       AND EXISTS (SELECT 1 FROM world_writers WHERE world_id = NEW.world_id AND active AND id <> OLD.id) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'single-writer world already has an active writer';
    END IF;
END;

CREATE TABLE proxy_pools (
    id CHAR(36) NOT NULL PRIMARY KEY, `key` VARCHAR(128) NOT NULL UNIQUE,
    metadata JSON NOT NULL, version BIGINT UNSIGNED NOT NULL DEFAULT 1, created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB;
CREATE TABLE proxy_instances (
    id CHAR(36) NOT NULL PRIMARY KEY, pool_id CHAR(36) NOT NULL, `key` VARCHAR(128) NOT NULL,
    state VARCHAR(32) NOT NULL, gameap_binding_ref VARCHAR(255) NULL, metadata JSON NOT NULL, version BIGINT UNSIGNED NOT NULL DEFAULT 1,
    UNIQUE KEY uq_proxy_instance (pool_id, `key`), CONSTRAINT fk_proxy_pool FOREIGN KEY (pool_id) REFERENCES proxy_pools(id),
    CONSTRAINT ck_proxy_state CHECK (state IN ('preparing','ready','accepting','draining','stopped','failed'))
) ENGINE=InnoDB;
CREATE TABLE routes (
    id CHAR(36) NOT NULL PRIMARY KEY, pool_id CHAR(36) NOT NULL, service_id CHAR(36) NULL,
    cluster_id CHAR(36) NOT NULL, priority INT NOT NULL DEFAULT 0, disabled BOOLEAN NOT NULL DEFAULT FALSE, metadata JSON NOT NULL, version BIGINT UNSIGNED NOT NULL DEFAULT 1,
    UNIQUE KEY uq_route (pool_id, service_id), CONSTRAINT fk_route_pool FOREIGN KEY (pool_id) REFERENCES proxy_pools(id),
    CONSTRAINT fk_route_service FOREIGN KEY (service_id) REFERENCES services(id), CONSTRAINT fk_route_cluster FOREIGN KEY (cluster_id) REFERENCES clusters(id)
) ENGINE=InnoDB;

CREATE TABLE external_endpoints (
    id CHAR(36) NOT NULL PRIMARY KEY, `key` VARCHAR(128) NOT NULL UNIQUE, kind VARCHAR(64) NOT NULL,
    logical_hostname VARCHAR(255) NOT NULL, port SMALLINT UNSIGNED NOT NULL, `role` VARCHAR(64) NOT NULL,
    metadata JSON NOT NULL, version BIGINT UNSIGNED NOT NULL DEFAULT 1, created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT ck_endpoint_port CHECK (port > 0)
) ENGINE=InnoDB;
CREATE TABLE endpoint_bindings (
    id CHAR(36) NOT NULL PRIMARY KEY, revision_id CHAR(36) NOT NULL, endpoint_id CHAR(36) NOT NULL, cluster_id CHAR(36) NOT NULL,
    binding_key VARCHAR(128) NOT NULL, metadata JSON NOT NULL, version BIGINT UNSIGNED NOT NULL DEFAULT 1,
    UNIQUE KEY uq_endpoint_binding (revision_id, binding_key), CONSTRAINT fk_binding_revision FOREIGN KEY (revision_id) REFERENCES cluster_revisions(id),
    CONSTRAINT fk_binding_endpoint FOREIGN KEY (endpoint_id) REFERENCES external_endpoints(id),
    CONSTRAINT fk_binding_cluster FOREIGN KEY (cluster_id) REFERENCES clusters(id)
) ENGINE=InnoDB;
CREATE TRIGGER endpoint_bindings_no_update BEFORE UPDATE ON endpoint_bindings FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'endpoint bindings are immutable';
CREATE TRIGGER endpoint_bindings_no_delete BEFORE DELETE ON endpoint_bindings FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'endpoint bindings are immutable';

CREATE TABLE access_policies (
    id CHAR(36) NOT NULL PRIMARY KEY, `key` VARCHAR(128) NOT NULL UNIQUE, policy JSON NOT NULL,
    version BIGINT UNSIGNED NOT NULL DEFAULT 1, created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT ck_access_policy_array CHECK (JSON_TYPE(policy) = 'ARRAY')
) ENGINE=InnoDB;
ALTER TABLE services ADD CONSTRAINT fk_service_access_policy FOREIGN KEY (access_policy_id) REFERENCES access_policies(id);
CREATE TABLE access_policy_bindings (
    id CHAR(36) NOT NULL PRIMARY KEY, policy_id CHAR(36) NOT NULL, service_id CHAR(36) NULL, cluster_id CHAR(36) NULL,
    UNIQUE KEY uq_policy_binding (policy_id, service_id, cluster_id), CONSTRAINT fk_policy_binding_policy FOREIGN KEY (policy_id) REFERENCES access_policies(id),
    CONSTRAINT fk_policy_binding_service FOREIGN KEY (service_id) REFERENCES services(id), CONSTRAINT fk_policy_binding_cluster FOREIGN KEY (cluster_id) REFERENCES clusters(id),
    CONSTRAINT ck_policy_binding_target CHECK (service_id IS NOT NULL OR cluster_id IS NOT NULL)
) ENGINE=InnoDB;

CREATE TABLE change_sessions (
    id CHAR(36) NOT NULL PRIMARY KEY, actor VARCHAR(255) NOT NULL, state VARCHAR(32) NOT NULL,
    target JSON NOT NULL, before_snapshot JSON NULL, plan_hash CHAR(64) NULL,
    idempotency_key VARCHAR(255) NOT NULL, request_hash CHAR(64) NOT NULL, metadata JSON NOT NULL,
    version BIGINT UNSIGNED NOT NULL DEFAULT 1,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6), updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_change_session_request (actor, idempotency_key),
    CONSTRAINT ck_change_state CHECK (state IN ('open','editing','ready','applying','verifying','accepted','rolled_back','aborted','conflicted')),
    CONSTRAINT ck_change_request_hash CHECK (CHAR_LENGTH(request_hash) = 64)
) ENGINE=InnoDB;
CREATE TRIGGER change_sessions_actor_identity
BEFORE INSERT ON change_sessions FOR EACH ROW
BEGIN
    IF CHAR_LENGTH(NEW.actor) <> 36 OR NOT EXISTS (
        SELECT 1 FROM actor_identities WHERE actor_id = NEW.actor
    ) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'change session requires a registered actor identity';
    END IF;
END;
CREATE TABLE plans (
    id CHAR(36) NOT NULL PRIMARY KEY, change_session_id CHAR(36) NOT NULL, plan_hash CHAR(64) NOT NULL,
    idempotency_key VARCHAR(255) NOT NULL, request_hash CHAR(64) NOT NULL,
    actor VARCHAR(255) NOT NULL, target JSON NOT NULL, domain_revision BIGINT UNSIGNED NOT NULL,
    observed_execution_state JSON NOT NULL, expected_file_hashes JSON NOT NULL, expected_artifact_hashes JSON NOT NULL,
    steps JSON NOT NULL, backup_requirements JSON NOT NULL, rollback_instructions JSON NOT NULL, expires_at BIGINT UNSIGNED NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_plan_hash (change_session_id, plan_hash),
    UNIQUE KEY uq_plan_request (change_session_id, idempotency_key),
    UNIQUE KEY uq_plan_session (id, change_session_id),
    CONSTRAINT fk_plan_session FOREIGN KEY (change_session_id) REFERENCES change_sessions(id),
    CONSTRAINT ck_plan_request_hash CHECK (CHAR_LENGTH(request_hash) = 64)
) ENGINE=InnoDB;
CREATE TRIGGER plans_actor_identity
BEFORE INSERT ON plans FOR EACH ROW
BEGIN
    IF CHAR_LENGTH(NEW.actor) <> 36 OR NOT EXISTS (
        SELECT 1 FROM actor_identities WHERE actor_id = NEW.actor
    ) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'plan requires a registered actor identity';
    END IF;
END;

-- Uploads live in the content-addressed store. This record only grants an
-- active session and actor the right to reference a digest with its exact
-- size and classification before the plan is resolved.
CREATE TABLE staged_content_ownership (
    id CHAR(36) NOT NULL PRIMARY KEY,
    change_session_id CHAR(36) NOT NULL,
    actor VARCHAR(255) NOT NULL,
    digest CHAR(64) NOT NULL,
    size_bytes BIGINT UNSIGNED NOT NULL,
    classification VARCHAR(32) NOT NULL,
    idempotency_key VARCHAR(255) NOT NULL,
    request_hash CHAR(64) NOT NULL,
    expires_at BIGINT UNSIGNED NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_staged_content (change_session_id, actor, digest, size_bytes, classification),
    UNIQUE KEY uq_staged_content_request (change_session_id, actor, idempotency_key),
    CONSTRAINT fk_staged_content_session FOREIGN KEY (change_session_id) REFERENCES change_sessions(id),
    CONSTRAINT ck_staged_content_digest CHECK (CHAR_LENGTH(digest) = 64),
    CONSTRAINT ck_staged_content_request_hash CHECK (CHAR_LENGTH(request_hash) = 64),
    CONSTRAINT ck_staged_content_classification CHECK (classification IN ('managed','mutable_config','artifact','generated'))
) ENGINE=InnoDB;
CREATE TRIGGER staged_content_ownership_active
BEFORE INSERT ON staged_content_ownership FOR EACH ROW
BEGIN
    IF CHAR_LENGTH(NEW.actor) <> 36 OR NOT EXISTS (
        SELECT 1 FROM actor_identities WHERE actor_id = NEW.actor
    ) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'staged content requires a registered actor identity';
    END IF;
    IF NEW.expires_at <= UNIX_TIMESTAMP() OR NOT EXISTS (
        SELECT 1 FROM change_sessions
        WHERE id = NEW.change_session_id
          AND state IN ('open','editing','ready','applying','verifying')
    ) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'staged content requires an active change session';
    END IF;
END;
CREATE TRIGGER staged_content_ownership_active_update
BEFORE UPDATE ON staged_content_ownership FOR EACH ROW
BEGIN
    IF CHAR_LENGTH(NEW.actor) <> 36 OR NOT EXISTS (
        SELECT 1 FROM actor_identities WHERE actor_id = NEW.actor
    ) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'staged content requires a registered actor identity';
    END IF;
    IF NEW.expires_at <= UNIX_TIMESTAMP() OR NOT EXISTS (
        SELECT 1 FROM change_sessions
        WHERE id = NEW.change_session_id
          AND state IN ('open','editing','ready','applying','verifying')
    ) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'staged content requires an active change session';
    END IF;
END;

CREATE TABLE operations (
    id CHAR(36) NOT NULL PRIMARY KEY, plan_id CHAR(36) NOT NULL, change_session_id CHAR(36) NOT NULL, operation_key VARCHAR(255) NOT NULL,
    kind VARCHAR(64) NOT NULL, state VARCHAR(32) NOT NULL, actor VARCHAR(255) NOT NULL, payload JSON NOT NULL,
    result JSON NULL, lease_owner VARCHAR(255) NULL, lease_until DATETIME(6) NULL, attempt BIGINT UNSIGNED NOT NULL DEFAULT 0,
    version BIGINT UNSIGNED NOT NULL DEFAULT 1,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6), updated_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_operation_key (operation_key), UNIQUE KEY uq_operation_plan (plan_id),
    CONSTRAINT fk_operation_plan FOREIGN KEY (plan_id) REFERENCES plans(id),
    CONSTRAINT fk_operation_plan_session FOREIGN KEY (plan_id, change_session_id) REFERENCES plans(id, change_session_id),
    CONSTRAINT fk_operation_session FOREIGN KEY (change_session_id) REFERENCES change_sessions(id),
    CONSTRAINT ck_operation_state CHECK (state IN ('planned','applying','verifying','verified','accepted','rolled_back','failed'))
) ENGINE=InnoDB;
CREATE TRIGGER operations_actor_identity
BEFORE INSERT ON operations FOR EACH ROW
BEGIN
    IF CHAR_LENGTH(NEW.actor) <> 36 OR NOT EXISTS (
        SELECT 1 FROM actor_identities WHERE actor_id = NEW.actor
    ) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'operation requires a registered actor identity';
    END IF;
END;
CREATE TABLE operation_steps (
    operation_id CHAR(36) NOT NULL,
    sequence INT UNSIGNED NOT NULL,
    state_hash CHAR(64) NOT NULL,
    result VARCHAR(64) NOT NULL,
    execution_evidence JSON NULL,
    recorded_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (operation_id, sequence),
    CONSTRAINT fk_operation_step_operation FOREIGN KEY (operation_id) REFERENCES operations(id)
) ENGINE=InnoDB;
CREATE TABLE backup_references (
    id CHAR(36) NOT NULL PRIMARY KEY, change_session_id CHAR(36) NOT NULL, kind VARCHAR(64) NOT NULL,
    target JSON NOT NULL, provider VARCHAR(128) NOT NULL, reference VARCHAR(1024) NOT NULL,
    manifest_digest CHAR(64) NOT NULL, verified_at BIGINT UNSIGNED NULL,
    required BOOLEAN NOT NULL DEFAULT FALSE, version BIGINT UNSIGNED NOT NULL DEFAULT 1, metadata JSON NOT NULL, created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT fk_backup_session FOREIGN KEY (change_session_id) REFERENCES change_sessions(id),
    CONSTRAINT ck_backup_kind CHECK (kind IN ('change-snapshot','world','service-consistent','external-database-reference'))
) ENGINE=InnoDB;
CREATE TABLE lifecycle_decisions (
    id CHAR(36) NOT NULL PRIMARY KEY, service_id CHAR(36) NOT NULL, from_state VARCHAR(32) NOT NULL,
    to_state VARCHAR(32) NOT NULL, actor VARCHAR(255) NOT NULL, reason TEXT NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6), CONSTRAINT fk_lifecycle_service FOREIGN KEY (service_id) REFERENCES services(id)
) ENGINE=InnoDB;
CREATE TABLE gameap_bindings (
    id CHAR(36) NOT NULL PRIMARY KEY, service_id CHAR(36) NULL, cluster_id CHAR(36) NULL, execution_unit_target VARCHAR(255) NULL, world_id CHAR(36) NULL, proxy_instance_id CHAR(36) NULL,
    execution_unit_ref VARCHAR(255) NOT NULL, node_id VARCHAR(255) NOT NULL, version BIGINT UNSIGNED NOT NULL DEFAULT 1, metadata JSON NOT NULL, created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_gameap_execution_unit_ref (execution_unit_ref),
    CONSTRAINT fk_gameap_service FOREIGN KEY (service_id) REFERENCES services(id), CONSTRAINT fk_gameap_cluster FOREIGN KEY (cluster_id) REFERENCES clusters(id), CONSTRAINT fk_gameap_world FOREIGN KEY (world_id) REFERENCES worlds(id),
    CONSTRAINT fk_gameap_proxy FOREIGN KEY (proxy_instance_id) REFERENCES proxy_instances(id),
    CONSTRAINT ck_gameap_target CHECK ((service_id IS NOT NULL) + (cluster_id IS NOT NULL) + (execution_unit_target IS NOT NULL) + (world_id IS NOT NULL) + (proxy_instance_id IS NOT NULL) = 1)
) ENGINE=InnoDB;
CREATE TABLE audit_events (
    event_id CHAR(36) NOT NULL PRIMARY KEY, occurred_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6), actor VARCHAR(255) NOT NULL,
    action VARCHAR(255) NOT NULL, target VARCHAR(1024) NOT NULL, classification VARCHAR(32) NOT NULL,
    source VARCHAR(128) NOT NULL, service_id CHAR(36) NULL, cluster_id CHAR(36) NULL, world_id CHAR(36) NULL, execution_unit_ref VARCHAR(255) NULL,
    operation_id CHAR(36) NULL, result VARCHAR(32) NOT NULL, before_revision BIGINT UNSIGNED NULL, after_revision BIGINT UNSIGNED NULL,
    plan_hash CHAR(64) NULL, request_id VARCHAR(255) NULL, evidence JSON NOT NULL,
    CONSTRAINT fk_audit_service FOREIGN KEY (service_id) REFERENCES services(id), CONSTRAINT fk_audit_cluster FOREIGN KEY (cluster_id) REFERENCES clusters(id),
    CONSTRAINT fk_audit_world FOREIGN KEY (world_id) REFERENCES worlds(id), CONSTRAINT fk_audit_operation FOREIGN KEY (operation_id) REFERENCES operations(id),
    CONSTRAINT ck_audit_classification CHECK (classification IN ('managed','mutable_config','artifact','generated','state','secret','unknown'))
) ENGINE=InnoDB;
CREATE TRIGGER audit_events_actor_identity
BEFORE INSERT ON audit_events FOR EACH ROW
BEGIN
    IF CHAR_LENGTH(NEW.actor) <> 36 OR NOT EXISTS (
        SELECT 1 FROM actor_identities WHERE actor_id = NEW.actor
    ) THEN
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit event requires a registered actor identity';
    END IF;
END;
CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit events are append-only';
CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'audit events are append-only';

-- SFTP is an out-of-band observation boundary. Kitsunebi stores endpoint
-- metadata and content-addressed scan results only; it does not run an SFTP
-- server and no credential value is represented here.
CREATE TABLE sftp_endpoints (
    id CHAR(36) NOT NULL PRIMARY KEY,
    service_id CHAR(36) NOT NULL,
    execution_binding_id CHAR(36) NOT NULL,
    host VARCHAR(255) NOT NULL,
    port SMALLINT UNSIGNED NOT NULL,
    root VARCHAR(1024) NOT NULL,
    provisioning_owned BOOLEAN NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    version BIGINT UNSIGNED NOT NULL DEFAULT 1,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_sftp_service_binding (service_id, execution_binding_id),
    CONSTRAINT fk_sftp_endpoint_service FOREIGN KEY (service_id) REFERENCES services(id),
    CONSTRAINT fk_sftp_endpoint_binding FOREIGN KEY (execution_binding_id) REFERENCES gameap_bindings(id),
    CONSTRAINT ck_sftp_endpoint_port CHECK (port > 0),
    CONSTRAINT ck_sftp_endpoint_owned CHECK (provisioning_owned = TRUE)
) ENGINE=InnoDB;

CREATE TABLE sftp_scans (
    id CHAR(36) NOT NULL PRIMARY KEY,
    endpoint_id CHAR(36) NOT NULL,
    service_id CHAR(36) NOT NULL,
    execution_binding_id CHAR(36) NOT NULL,
    change_session_id CHAR(36) NOT NULL,
    before_manifest_hash CHAR(64) NOT NULL,
    after_manifest_hash CHAR(64) NOT NULL,
    changed_paths JSON NOT NULL,
    observed_at BIGINT UNSIGNED NOT NULL,
    source VARCHAR(32) NOT NULL,
    idempotency_key VARCHAR(255) NOT NULL,
    request_hash CHAR(64) NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_sftp_scan_request (change_session_id, idempotency_key),
    CONSTRAINT fk_sftp_scan_endpoint FOREIGN KEY (endpoint_id) REFERENCES sftp_endpoints(id),
    CONSTRAINT fk_sftp_scan_service FOREIGN KEY (service_id) REFERENCES services(id),
    CONSTRAINT fk_sftp_scan_binding FOREIGN KEY (execution_binding_id) REFERENCES gameap_bindings(id),
    CONSTRAINT fk_sftp_scan_session FOREIGN KEY (change_session_id) REFERENCES change_sessions(id),
    CONSTRAINT ck_sftp_scan_source CHECK (source IN ('out_of_band','provisioning','operator'))
) ENGINE=InnoDB;

-- Provider node references are opaque and observations are append-only. The
-- latest observation is selected by observed_at at the repository boundary.
CREATE TABLE node_capability_observations (
    id CHAR(36) NOT NULL PRIMARY KEY,
    provider_node_ref VARCHAR(255) NOT NULL,
    process_manager VARCHAR(32) NOT NULL,
    manager_version VARCHAR(128) NULL,
    capabilities JSON NOT NULL,
    evidence_hash CHAR(64) NOT NULL,
    observed_at BIGINT UNSIGNED NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_node_capability_observation (provider_node_ref, observed_at, evidence_hash),
    CONSTRAINT ck_node_process_manager CHECK (process_manager IN ('systemd','docker','podman','unknown'))
) ENGINE=InnoDB;

CREATE TABLE tcp_shield_backend_sets (
    pool_id CHAR(36) NOT NULL PRIMARY KEY,
    provider_network_id BIGINT UNSIGNED NOT NULL,
    domain_network_id CHAR(36) NULL,
    backend_set_id VARCHAR(255) NOT NULL,
    version BIGINT UNSIGNED NOT NULL DEFAULT 1,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    UNIQUE KEY uq_tcp_shield_backend_set (provider_network_id, backend_set_id),
    CONSTRAINT fk_tcp_shield_pool FOREIGN KEY (pool_id) REFERENCES proxy_pools(id),
    CONSTRAINT fk_tcp_shield_domain_network FOREIGN KEY (domain_network_id) REFERENCES networks(id),
    CONSTRAINT ck_tcp_shield_provider_network CHECK (provider_network_id > 0)
) ENGINE=InnoDB;

CREATE TABLE proxy_instance_bindings (
    instance_id CHAR(36) NOT NULL PRIMARY KEY,
    gameap_binding_id CHAR(36) NOT NULL,
    backend_address VARCHAR(1024) NOT NULL,
    version BIGINT UNSIGNED NOT NULL DEFAULT 1,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT fk_proxy_instance_binding_instance FOREIGN KEY (instance_id) REFERENCES proxy_instances(id),
    CONSTRAINT fk_proxy_instance_binding_gameap FOREIGN KEY (gameap_binding_id) REFERENCES gameap_bindings(id)
) ENGINE=InnoDB;

-- Purge leaves this tombstone and does not remove append-only history.
CREATE TABLE service_tombstones (
    id CHAR(36) NOT NULL PRIMARY KEY,
    service_id CHAR(36) NOT NULL UNIQUE,
    service_key VARCHAR(128) NOT NULL,
    archived_at BIGINT UNSIGNED NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT fk_service_tombstone_service FOREIGN KEY (service_id) REFERENCES services(id)
) ENGINE=InnoDB;
