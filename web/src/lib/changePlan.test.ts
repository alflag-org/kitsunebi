import { describe, expect, it } from 'vitest';
import { buildChangePlan, buildPlanStep, PLAN_STEP_KINDS } from './changePlan';
import type { JsonObject } from './types';

const uuid = '11111111-1111-4111-8111-111111111111';
const digest = 'a'.repeat(64);

describe('typed ChangePlan builder', () => {
  it('keeps the complete closed PlanStepAction set', () => {
    expect(PLAN_STEP_KINDS).toEqual([
      'execution_provision', 'execution_delete', 'service_lifecycle_transition', 'cluster_revision_create',
      'execution_lifecycle', 'file_write', 'file_move', 'file_quarantine', 'file_batch', 'artifact_register',
      'artifact_stage', 'artifact_activate', 'proxy_rollout', 'world_writer_cutover',
      'endpoint_rollout', 'access_policy_update', 'route_policy_update', 'backup_create', 'backup_restore',
      'service_archive', 'service_purge'
    ]);
  });

  it('builds staged file and backup steps with provider observations', async () => {
    const file = buildPlanStep('file_write', {
      binding_id: uuid, path: 'server.properties', expected_binding_hash: digest, domain_revision: '4',
      expected_before_digest: digest, content_digest: digest, content_size: '12', classification: 'mutable_config',
      observed: { id: uuid, binding_hash: digest, provider_token: 'never copied' }
    });
    const backup = buildPlanStep('backup_create', {
      kind: 'external-database-reference', target: { kind: 'service', value: uuid }, request_hash: digest,
      observed: { id: uuid, version: 2 }
    });
    const plan = await buildChangePlan({ sessionId: uuid, serviceId: uuid, targetKind: 'cluster', targetId: uuid, domainRevision: 4, steps: [file, backup], backupRequired: true });
    expect(plan.steps).toEqual([
      { action: { kind: 'file_write', value: expect.objectContaining({ content: { digest, size: 12 }, classification: 'mutable_config' }) } },
      { action: { kind: 'backup_create', value: expect.objectContaining({ kind: 'external-database-reference', target: { kind: 'service', value: uuid } }) } }
    ]);
    expect(plan.observed_state_hashes).toEqual([digest, expect.stringMatching(/^[0-9a-f]{64}$/)]);
    expect(plan.backup_required).toBe(true);
  });

  it('keeps manual artifact bytes out of the plan and stores a staged reference', () => {
    const step = buildPlanStep('artifact_register', {
      artifact_id: uuid, kind: 'plugin', name: 'Example', version: '1', source: 'manual', source_id: 'example',
      digest, filename: 'example.jar', compatibility: '1.21', metadata: '{}', content_digest: digest, content_size: '4', expected_version: '2', domain_revision: '3'
    });
    expect(step.value).toEqual({ kind: 'artifact_register', value: expect.objectContaining({ content: { digest, size: 4 }, expected_version: 2, domain_revision: 3 }) });
    expect(JSON.stringify(step)).not.toContain('manual_content');
  });

  it('does not accept a generic command step', () => {
    expect(() => buildPlanStep('file_move', { kind: 'run', command: 'rm -rf' })).not.toThrow();
    const step = buildPlanStep('file_move', { kind: 'run', command: 'rm -rf' });
    expect(step.value).toEqual({ kind: 'file_move', value: expect.objectContaining({ from: '', to: '' }) });
    expect(step.value.value).not.toHaveProperty('command');
  });

  it('encodes file batch operations as the API tagged union', () => {
    const step = buildPlanStep('file_batch', {
      binding_id: uuid, expected_binding_hash: digest, domain_revision: 1,
      operations: [{ kind: 'write', path: 'server.properties', content: { digest, size: 4 }, classification: 'mutable_config' }]
    });
    expect(step.value.value).toEqual(expect.objectContaining({
      operations: [{ kind: 'write', value: { path: 'server.properties', expected_before_digest: null, content: { digest, size: 4 }, classification: 'mutable_config' } }]
    }));
  });

  it('round-trips every typed action in the canonical plan envelope', async () => {
    const fields: Record<string, Record<string, unknown>> = {
      execution_provision: { binding_id: uuid, expected_binding_hash: digest, domain_revision: 1 },
      execution_delete: { binding_id: uuid, expected_binding_hash: digest, expected_state_hash: digest, domain_revision: 1, expected_version: 1 },
      service_lifecycle_transition: { service_id: uuid, expected_state: 'Testing', next_state: 'Active', expected_version: 1, reason: 'release' },
      cluster_revision_create: {
        cluster_id: uuid,
        revision: {
          id: uuid, number: 2, runtime_profile: uuid, minecraft_version: '1.21', java_requirement: '21',
          artifact_set: uuid, config_baseline: uuid, world_bindings: [], endpoint_bindings: [],
          placement_requirements: { process_managers: ['docker'], required_capabilities: [] },
          resource_requirements: '', health_checks: [], startup_parameters: []
        }, new_endpoint_bindings: [{ id: uuid, endpoint_id: uuid, cluster_id: uuid, revision_id: uuid, binding_key: 'game', metadata: '{}' }], expected_current_number: null
      },
      execution_lifecycle: { binding_id: uuid, action: 'restart', expected_binding_hash: digest, expected_state_hash: digest, domain_revision: 1 },
      file_write: { binding_id: uuid, path: 'server.properties', expected_binding_hash: digest, domain_revision: 1, content_digest: digest, content_size: 1, classification: 'mutable_config' },
      file_move: { binding_id: uuid, from: 'a', to: 'b', expected_binding_hash: digest, domain_revision: 1, classification: 'mutable_config' },
      file_quarantine: { binding_id: uuid, path: 'a', expected_binding_hash: digest, domain_revision: 1, classification: 'managed' },
      file_batch: { binding_id: uuid, expected_binding_hash: digest, domain_revision: 1, operations: [] },
      artifact_register: { artifact_id: uuid, kind: 'plugin', name: 'Example', version: '1', source: 'manual', source_id: 'example', digest, filename: 'example.jar', compatibility: '1.21', metadata: '{}', content: { digest, size: 1 }, expected_version: 1, domain_revision: 1 },
      artifact_stage: { artifact_id: uuid, expected_digest: digest, expected_version: 1, domain_revision: 1 },
      artifact_activate: { artifact_id: uuid, artifact_set_id: uuid, binding_id: uuid, expected_binding_hash: digest, cluster_id: uuid, expected_revision: uuid, target_revision: uuid, expected_digest: digest, expected_version: 1, destination_path: 'plugins/example.jar' },
      proxy_rollout: { pool_id: uuid, expected_instance_id: uuid, target_instance_id: '22222222-2222-4222-8222-222222222222', expected_instance_version: 1, target_instance_version: 2, expected_instance_state: 'accepting', target_instance_state: 'ready', target_binding_id: uuid, target_binding_hash: digest, domain_revision: 1, desired_state: 'accepting', configuration: [{ kind: 'write', path: 'server.properties', content: { digest, size: 1 }, classification: 'mutable_config' }] },
      world_writer_cutover: { world_id: uuid, expected_version: 1, expected_writer: null, next_writer: uuid, expected_writer_binding_id: null, target_writer_binding_id: uuid, expected_writer_binding_hash: null, target_writer_binding_hash: digest, domain_revision: 1 },
      endpoint_rollout: { expected_binding_id: uuid, target_binding_id: '22222222-2222-4222-8222-222222222222', cluster_id: uuid, expected_revision: uuid, target_revision: '22222222-2222-4222-8222-222222222222', expected_version: 1, runtime_binding_ids: [uuid], runtime_binding_hashes: [digest] },
      access_policy_update: {
        policy_id: uuid, service_id: uuid, expected_version: 1,
        desired_grants: [{ actor_id: uuid, role: 'operator', service_scope: uuid, permissions: ['service.read', 'change.plan', 'files.write'] }],
        desired_policy_hash: digest
      },
      route_policy_update: { route_id: uuid, pool_id: uuid, service_id: uuid, expected_cluster: uuid, target_cluster: uuid, expected_priority: 1, target_priority: 2, expected_version: 1, disabled: false },
      backup_create: { kind: 'external-database-reference', target: { kind: 'service', value: uuid }, request_hash: digest },
      backup_restore: { reference_id: uuid, target: { kind: 'service', value: uuid }, expected_manifest_digest: digest, rollback_reference_id: '22222222-2222-4222-8222-222222222222', expected_rollback_manifest_digest: digest, expected_version: 1 },
      service_archive: { service_id: uuid, expected_version: 1, sunsetting_evidence_hash: digest },
      service_purge: { service_id: uuid, expected_version: 1, archive_evidence_hash: digest, verified_backup_id: uuid, archived_at: 1 }
    };
    const steps = PLAN_STEP_KINDS.map((kind) => buildPlanStep(kind, fields[kind]));
    const plan = await buildChangePlan({ sessionId: uuid, serviceId: uuid, targetKind: 'cluster', targetId: uuid, domainRevision: 1, steps, backupRequired: true });
    const fixture = JSON.stringify({ action: { kind: 'execution_provision', value: fields.execution_provision } });
    expect(JSON.parse(fixture)).toEqual({ action: { kind: 'execution_provision', value: fields.execution_provision } });
    const planSteps = plan.steps as JsonObject[];
    expect(planSteps).toHaveLength(PLAN_STEP_KINDS.length);
    expect(planSteps.every((step) => Object.keys(step).length === 1 && 'action' in step)).toBe(true);
    expect(planSteps.map((step) => (step.action as JsonObject).kind)).toEqual([...PLAN_STEP_KINDS]);
    expect(JSON.parse(JSON.stringify(plan))).toEqual(plan);
  });
});
