-- Deterministic local policy and topology fixture. Provider credentials remain
-- compose-only; every object here is non-secret and scoped to service A.
SET FOREIGN_KEY_CHECKS = 1;

INSERT IGNORE INTO networks (id, `key`, display_name, metadata)
VALUES ('00000000-0000-4000-8000-000000000001', 'fixture-network', 'Integration fixture network', '{}');
INSERT IGNORE INTO actor_identities (actor_id, kind, subject, service_id)
VALUES ('00000000-0000-4000-8000-0000000000aa', 'browser', '00000000-0000-4000-8000-0000000000aa', NULL);
INSERT IGNORE INTO access_policies (id, `key`, policy)
VALUES ('00000000-0000-4000-8000-000000000010', 'fixture-operator-policy', '[{"actor":"00000000-0000-4000-8000-0000000000aa","role":"operator","service_scope":"00000000-0000-4000-8000-0000000000a1","permissions":["service.read","change.plan","change.approve","change.apply","change.verify","change.accept","change.rollback","lifecycle.start","lifecycle.stop","lifecycle.restart","operation.read","audit.read","files.read","files.write"]}]');
INSERT IGNORE INTO runtime_profiles (id, `key`, family, minecraft_version, runtime_version, artifact_source, artifact_digest, java_requirement, startup_capability, console_capability, health_capability, world_execution_capability, metadata)
VALUES ('00000000-0000-4000-8000-000000000010', 'fixture-runtime', 'paper', '1.21.4', '1.0.0', 'manual', REPEAT('a', 64), 'java-21', TRUE, TRUE, TRUE, 'single_process', '{}');
INSERT IGNORE INTO services (id, network_id, `key`, display_name, ownership, audience, operator_model, trust_profile, lifecycle, availability, current_cluster_id, access_policy_id, backup_policy, metadata)
VALUES ('00000000-0000-4000-8000-0000000000a1', '00000000-0000-4000-8000-000000000001', 'fixture-service-a', 'Integration service A', 'first_party', 'public', 'central', 'trusted', 'planned', 'disabled', NULL, '00000000-0000-4000-8000-000000000010', '{}', '{}'), ('00000000-0000-4000-8000-0000000000b1', '00000000-0000-4000-8000-000000000001', 'fixture-service-b', 'Integration service B', 'first_party', 'public', 'central', 'trusted', 'planned', 'disabled', NULL, NULL, '{}', '{}');
INSERT IGNORE INTO clusters (id, service_id, `key`, display_name, current_revision_id, metadata)
VALUES ('00000000-0000-4000-8000-0000000000a2', '00000000-0000-4000-8000-0000000000a1', 'fixture-cluster-a', 'Integration cluster A', NULL, '{}'), ('00000000-0000-4000-8000-0000000000b2', '00000000-0000-4000-8000-0000000000b1', 'fixture-cluster-b', 'Integration cluster B', NULL, '{}');

INSERT IGNORE INTO artifact_sets (id, `key`, manifest, manifest_digest, metadata)
VALUES ('00000000-0000-4000-8000-000000000020', 'fixture-artifacts', '[]', REPEAT('b', 64), '{}');
INSERT IGNORE INTO artifacts (id, kind, name, artifact_version, source, source_id, digest, filename, compatibility, metadata)
VALUES ('00000000-0000-4000-8000-000000000021', 'plugin', 'Fixture plugin', '1.0.0', 'manual', 'fixture-plugin', REPEAT('c', 64), 'fixture.jar', '{"minecraft":"1.21.4"}', '{}');
INSERT IGNORE INTO artifact_set_items (artifact_set_id, artifact_id) VALUES ('00000000-0000-4000-8000-000000000020', '00000000-0000-4000-8000-000000000021');
INSERT IGNORE INTO config_baselines (id, `key`, manifest, manifest_digest, metadata) VALUES ('00000000-0000-4000-8000-000000000022', 'fixture-config', '{"digest":"cbceed45366c6ea11a10fd9a171040b48339ca04eda6424bdf26568a2e7fc752","files":[{"path":"configs/example.conf","digest":"4f0d571ed3f2c25fb1151b1b6e0f668d317f8c3a0370ea48e9ec4fbce99c7719","classification":"mutable_config"},{"path":"configs/integration-upload.conf","digest":"3a2063bd16edb6a147baa60030b66e0d8ad8a0f11ef326e9c0c28e6afd59032b","classification":"artifact"},{"path":"secrets/token","digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","classification":"secret"},{"path":"state/server.dat","digest":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","classification":"state"}]}', 'cbceed45366c6ea11a10fd9a171040b48339ca04eda6424bdf26568a2e7fc752', '{}');
INSERT IGNORE INTO cluster_revisions (id, cluster_id, revision_number, runtime_profile_id, minecraft_version, java_requirement, artifact_set_id, config_baseline_id, world_bindings, endpoint_bindings, placement_requirements, resource_requirements, health_checks, startup_parameters, metadata)
VALUES ('00000000-0000-4000-8000-000000000023', '00000000-0000-4000-8000-0000000000a2', 1, '00000000-0000-4000-8000-000000000010', '1.21.4', 'java-21', '00000000-0000-4000-8000-000000000020', '00000000-0000-4000-8000-000000000022', '[]', '[]', '{}', '{}', '[]', '{}', '{}');
UPDATE clusters SET current_revision_id = '00000000-0000-4000-8000-000000000023' WHERE id = '00000000-0000-4000-8000-0000000000a2';
UPDATE services SET current_cluster_id = CASE id WHEN '00000000-0000-4000-8000-0000000000a1' THEN '00000000-0000-4000-8000-0000000000a2' WHEN '00000000-0000-4000-8000-0000000000b1' THEN '00000000-0000-4000-8000-0000000000b2' ELSE current_cluster_id END WHERE id IN ('00000000-0000-4000-8000-0000000000a1', '00000000-0000-4000-8000-0000000000b1');

INSERT IGNORE INTO worlds (id, cluster_id, `key`, display_name, persistence, storage_ref, write_mode, execution_model, current_writer_id, backup_policy, metadata)
VALUES ('00000000-0000-4000-8000-000000000030', '00000000-0000-4000-8000-0000000000a2', 'fixture-world', 'Integration world', 'persistent', 'fixture/world', 'single_writer', 'single_process', NULL, '{}', '{}');
INSERT IGNORE INTO world_writers (id, world_id, cluster_id, execution_unit_ref, active)
VALUES ('00000000-0000-4000-8000-000000000031', '00000000-0000-4000-8000-000000000030', '00000000-0000-4000-8000-0000000000a2', '6', TRUE);
UPDATE worlds SET current_writer_id = '00000000-0000-4000-8000-000000000031' WHERE id = '00000000-0000-4000-8000-000000000030';
INSERT IGNORE INTO proxy_pools (id, `key`, metadata) VALUES ('00000000-0000-4000-8000-000000000040', 'fixture-proxy-pool', '{}');
INSERT IGNORE INTO proxy_instances (id, pool_id, `key`, state, gameap_binding_ref, metadata)
VALUES ('00000000-0000-4000-8000-000000000041', '00000000-0000-4000-8000-000000000040', 'fixture-proxy-a', 'accepting', NULL, '{}'), ('00000000-0000-4000-8000-000000000042', '00000000-0000-4000-8000-000000000040', 'fixture-proxy-b', 'ready', NULL, '{}');
INSERT IGNORE INTO routes (id, pool_id, service_id, cluster_id, priority, metadata) VALUES ('00000000-0000-4000-8000-000000000043', '00000000-0000-4000-8000-000000000040', '00000000-0000-4000-8000-0000000000a1', '00000000-0000-4000-8000-0000000000a2', 1, '{}');
INSERT IGNORE INTO external_endpoints (id, `key`, kind, logical_hostname, port, `role`, metadata) VALUES ('00000000-0000-4000-8000-000000000050', 'fixture-endpoint', 'minecraft', 'fixture.example.invalid', 25565, 'primary', '{}');
INSERT IGNORE INTO endpoint_bindings (id, revision_id, endpoint_id, cluster_id, binding_key, metadata) VALUES ('00000000-0000-4000-8000-000000000051', '00000000-0000-4000-8000-000000000023', '00000000-0000-4000-8000-000000000050', '00000000-0000-4000-8000-0000000000a2', 'fixture-binding', '{}');

INSERT IGNORE INTO access_policy_bindings (id, policy_id, service_id) VALUES ('00000000-0000-4000-8000-000000000011', '00000000-0000-4000-8000-000000000010', '00000000-0000-4000-8000-0000000000a1');
INSERT IGNORE INTO gameap_bindings (id, service_id, cluster_id, execution_unit_target, world_id, proxy_instance_id, execution_unit_ref, node_id, metadata)
VALUES ('00000000-0000-4000-8000-0000000000a3', NULL, '00000000-0000-4000-8000-0000000000a2', NULL, NULL, NULL, '6', '1', '{}'), ('00000000-0000-4000-8000-0000000000b3', NULL, '00000000-0000-4000-8000-0000000000b2', NULL, NULL, NULL, '7', '1', '{}');
