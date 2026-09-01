import type { JsonObject } from './types';
import { sha256Json } from './api';

export const PLAN_STEP_KINDS = [
  'execution_provision', 'execution_delete', 'service_lifecycle_transition', 'cluster_revision_create',
  'execution_lifecycle', 'file_write', 'file_move', 'file_quarantine', 'file_batch',
  'artifact_register', 'artifact_stage', 'artifact_activate', 'proxy_rollout', 'world_writer_cutover',
  'endpoint_rollout', 'access_policy_update', 'route_policy_update', 'backup_create', 'backup_restore',
  'service_archive', 'service_purge'
] as const;

export type PlanStepKind = typeof PLAN_STEP_KINDS[number];
export type StagedContent = { digest: string; size: number };
export type StagedFile = { sessionId: string; path: string; content: StagedContent; classification: string; expectedBeforeDigest?: string };

export type PlanStepDraft = {
  kind: PlanStepKind;
  value: JsonObject;
  observed?: JsonObject;
};

export type ChangePlanDraft = {
  sessionId: string;
  serviceId: string;
  targetKind: string;
  targetId: string;
  domainRevision: number;
  steps: PlanStepDraft[];
  backupRequired: boolean;
  backupReferences?: string[];
  rollbackInstructions?: string[];
  expiresAt?: number;
};

const text = (value: unknown): string => String(value ?? '').trim();
const number = (value: unknown): number => {
  const parsed = Number(value ?? 0);
  return Number.isSafeInteger(parsed) && parsed >= 0 ? parsed : 0;
};
const id = (value: unknown): string => text(value);
const digest = (value: unknown): string => text(value).toLowerCase();
const target = (kind: string, value: unknown): JsonObject => ({ kind, value: id(value) });
const optionalDigest = (value: unknown): string | null => value === null || value === undefined || text(value) === '' ? null : digest(value);

function batchOperation(value: unknown): JsonObject {
  const raw = value && typeof value === 'object' ? value as JsonObject : {};
  const input = raw.value && typeof raw.value === 'object' ? { ...(raw.value as JsonObject), kind: raw.kind } : raw;
  const kind = text(input.kind);
  if (kind === 'write') return {
    kind: 'write', value: {
      path: text(input.path), expected_before_digest: optionalDigest(input.expected_before_digest),
      content: stagedContent((input.content as JsonObject | undefined)?.digest, (input.content as JsonObject | undefined)?.size),
      classification: text(input.classification)
    }
  };
  if (kind === 'move') return {
    kind: 'move', value: {
      from: text(input.from), to: text(input.to), expected_before_digest: optionalDigest(input.expected_before_digest),
      expected_target_digest: optionalDigest(input.expected_target_digest), classification: text(input.classification)
    }
  };
  if (kind === 'quarantine') return {
    kind: 'quarantine', value: {
      path: text(input.path), expected_before_digest: optionalDigest(input.expected_before_digest), classification: text(input.classification)
    }
  };
  return { kind: '', value: {} };
}

export function stagedContent(digestValue: unknown, sizeValue: unknown): StagedContent {
  return { digest: digest(digestValue), size: number(sizeValue) };
}

/** Build one closed PlanStepAction. No untyped command or provider identifier is accepted. */
export function buildPlanStep(kind: PlanStepKind, fields: JsonObject): PlanStepDraft {
  const value: JsonObject = (() => {
    switch (kind) {
      case 'execution_provision': return {
        binding_id: id(fields.binding_id), expected_binding_hash: digest(fields.expected_binding_hash), domain_revision: number(fields.domain_revision)
      };
      case 'execution_delete': return {
        binding_id: id(fields.binding_id), expected_binding_hash: digest(fields.expected_binding_hash), expected_state_hash: digest(fields.expected_state_hash), domain_revision: number(fields.domain_revision), expected_version: number(fields.expected_version)
      };
      case 'service_lifecycle_transition': return {
        service_id: id(fields.service_id), expected_state: text(fields.expected_state), next_state: text(fields.next_state), expected_version: number(fields.expected_version), reason: text(fields.reason)
      };
      case 'cluster_revision_create': return {
        cluster_id: id(fields.cluster_id), revision: fields.revision && typeof fields.revision === 'object' ? fields.revision as JsonObject : {
          id: id(fields.revision_id), number: number(fields.revision_number), runtime_profile: id(fields.runtime_profile),
          minecraft_version: text(fields.minecraft_version), java_requirement: text(fields.java_requirement), artifact_set: id(fields.artifact_set),
          config_baseline: id(fields.config_baseline), world_bindings: String(fields.world_bindings ?? '').split(',').map(id).filter(Boolean),
          endpoint_bindings: String(fields.endpoint_bindings ?? '').split(',').map(id).filter(Boolean),
          placement_requirements: {
            process_managers: String(fields.process_managers ?? '').split(',').map(text).filter(Boolean),
            required_capabilities: String(fields.required_capabilities ?? '').split(',').map(text).filter(Boolean)
          },
          resource_requirements: text(fields.resource_requirements), health_checks: String(fields.health_checks ?? '').split(',').map(text).filter(Boolean),
          startup_parameters: String(fields.startup_parameters ?? '').split(',').map(text).filter(Boolean)
        }, new_endpoint_bindings: Array.isArray(fields.new_endpoint_bindings) ? fields.new_endpoint_bindings : [], expected_current_number: fields.expected_current_number == null || fields.expected_current_number === '' ? null : number(fields.expected_current_number)
      };
      case 'execution_lifecycle': return {
        binding_id: id(fields.binding_id), action: text(fields.action),
        expected_binding_hash: digest(fields.expected_binding_hash), expected_state_hash: digest(fields.expected_state_hash),
        domain_revision: number(fields.domain_revision)
      };
      case 'file_write': return {
        binding_id: id(fields.binding_id), path: text(fields.path), expected_binding_hash: digest(fields.expected_binding_hash),
        domain_revision: number(fields.domain_revision), expected_before_digest: fields.expected_before_digest ? digest(fields.expected_before_digest) : null,
        content: stagedContent(fields.content_digest, fields.content_size), classification: text(fields.classification)
      };
      case 'file_move': return {
        binding_id: id(fields.binding_id), from: text(fields.from), to: text(fields.to), expected_binding_hash: digest(fields.expected_binding_hash),
        domain_revision: number(fields.domain_revision), expected_before_digest: fields.expected_before_digest ? digest(fields.expected_before_digest) : null,
        expected_target_digest: fields.expected_target_digest ? digest(fields.expected_target_digest) : null, classification: text(fields.classification)
      };
      case 'file_quarantine': return {
        binding_id: id(fields.binding_id), path: text(fields.path), expected_binding_hash: digest(fields.expected_binding_hash),
        domain_revision: number(fields.domain_revision), expected_before_digest: fields.expected_before_digest ? digest(fields.expected_before_digest) : null,
        classification: text(fields.classification)
      };
      case 'file_batch': return {
        binding_id: id(fields.binding_id), expected_binding_hash: digest(fields.expected_binding_hash),
        domain_revision: number(fields.domain_revision), operations: Array.isArray(fields.operations) ? fields.operations.map(batchOperation) : []
      };
      case 'artifact_stage': return {
        artifact_id: id(fields.artifact_id), expected_digest: digest(fields.expected_digest), expected_version: number(fields.expected_version), domain_revision: number(fields.domain_revision)
      };
      case 'artifact_register': return {
        artifact: {
          id: id(fields.artifact_id), kind: text(fields.kind), name: text(fields.name), version: text(fields.version), source: text(fields.source), source_id: text(fields.source_id), digest: digest(fields.digest), filename: text(fields.filename), compatibility: text(fields.compatibility), metadata: text(fields.metadata)
        }, content: stagedContent(fields.content_digest, fields.content_size), expected_version: number(fields.expected_version), domain_revision: number(fields.domain_revision)
      };
      case 'artifact_activate': return {
        artifact_id: id(fields.artifact_id), artifact_set_id: id(fields.artifact_set_id), binding_id: id(fields.binding_id), expected_binding_hash: digest(fields.expected_binding_hash), cluster_id: id(fields.cluster_id),
        expected_revision: id(fields.expected_revision), target_revision: id(fields.target_revision), expected_digest: digest(fields.expected_digest), expected_version: number(fields.expected_version), destination_path: text(fields.destination_path), expected_before_digest: fields.expected_before_digest ? digest(fields.expected_before_digest) : null
      };
      case 'proxy_rollout': return {
        pool_id: id(fields.pool_id), expected_instance_id: id(fields.expected_instance_id), target_instance_id: id(fields.target_instance_id),
        expected_instance_version: number(fields.expected_instance_version), target_instance_version: number(fields.target_instance_version),
        expected_instance_state: text(fields.expected_instance_state), target_instance_state: text(fields.target_instance_state),
        target_binding_id: id(fields.target_binding_id), target_binding_hash: digest(fields.target_binding_hash),
        domain_revision: number(fields.domain_revision), desired_state: text(fields.desired_state),
        configuration: Array.isArray(fields.configuration) ? fields.configuration.map(batchOperation) : []
      };
      case 'world_writer_cutover': return {
        world_id: id(fields.world_id), expected_version: number(fields.expected_version), expected_writer: fields.expected_writer ? id(fields.expected_writer) : null, next_writer: id(fields.next_writer),
        expected_writer_binding_id: fields.expected_writer_binding_id ? id(fields.expected_writer_binding_id) : null,
        target_writer_binding_id: id(fields.target_writer_binding_id), expected_writer_binding_hash: optionalDigest(fields.expected_writer_binding_hash),
        target_writer_binding_hash: digest(fields.target_writer_binding_hash), domain_revision: number(fields.domain_revision)
      };
      case 'endpoint_rollout': return {
        expected_binding_id: id(fields.expected_binding_id), target_binding_id: id(fields.target_binding_id), cluster_id: id(fields.cluster_id),
        expected_revision: id(fields.expected_revision), target_revision: id(fields.target_revision), expected_version: number(fields.expected_version),
        runtime_binding_ids: Array.isArray(fields.runtime_binding_ids) ? fields.runtime_binding_ids.map(id) : [],
        runtime_binding_hashes: Array.isArray(fields.runtime_binding_hashes) ? fields.runtime_binding_hashes.map(digest) : []
      };
      case 'access_policy_update': return {
        policy_id: id(fields.policy_id), service_id: id(fields.service_id), expected_version: number(fields.expected_version),
        desired_grants: Array.isArray(fields.desired_grants) ? fields.desired_grants : [], desired_policy_hash: digest(fields.desired_policy_hash)
      };
      case 'route_policy_update': return {
        route_id: id(fields.route_id), pool_id: id(fields.pool_id), service_id: id(fields.service_id), expected_cluster: id(fields.expected_cluster), target_cluster: id(fields.target_cluster), expected_priority: number(fields.expected_priority), target_priority: number(fields.target_priority), expected_version: number(fields.expected_version), disabled: fields.disabled === true || fields.disabled === 'true'
      };
      case 'backup_create': return {
        kind: text(fields.kind), target: target(text((fields.target as JsonObject | undefined)?.kind), (fields.target as JsonObject | undefined)?.value), request_hash: digest(fields.request_hash)
      };
      case 'backup_restore': return {
        reference_id: id(fields.reference_id), target: target(text((fields.target as JsonObject | undefined)?.kind), (fields.target as JsonObject | undefined)?.value), expected_manifest_digest: digest(fields.expected_manifest_digest),
        rollback_reference_id: id(fields.rollback_reference_id), expected_rollback_manifest_digest: digest(fields.expected_rollback_manifest_digest), expected_version: number(fields.expected_version)
      };
      case 'service_archive': return { service_id: id(fields.service_id), expected_version: number(fields.expected_version), sunsetting_evidence_hash: digest(fields.sunsetting_evidence_hash) };
      case 'service_purge': return {
        service_id: id(fields.service_id), expected_version: number(fields.expected_version), archive_evidence_hash: digest(fields.archive_evidence_hash), verified_backup_id: id(fields.verified_backup_id), archived_at: number(fields.archived_at)
      };
    }
  })();
  return { kind, value: { kind, value }, observed: fields.observed && typeof fields.observed === 'object' ? fields.observed as JsonObject : undefined };
}

/** Select a provider-observed hash from a loaded resource, preserving no opaque provider object. */
export async function observedResourceHash(resource: JsonObject): Promise<string> {
  const candidate = resource.observed_hash ?? resource.state_hash ?? resource.binding_hash ?? resource.hash ?? resource.digest;
  if (/^[0-9a-f]{64}$/i.test(String(candidate ?? ''))) return String(candidate).toLowerCase();
  return sha256Json(resource);
}

export async function buildChangePlan(draft: ChangePlanDraft): Promise<JsonObject> {
  if (!draft.steps.length) throw new Error('Add at least one typed change step.');
  const observed = await Promise.all(draft.steps.map((step) => step.observed ? observedResourceHash(step.observed) : observedResourceHash(step.value)));
  const expiresAt = draft.expiresAt ?? Math.floor(Date.now() / 1000) + 1800;
  return {
    session_id: draft.sessionId,
    service_id: draft.serviceId,
    target: target(draft.targetKind, draft.targetId),
    domain_revision: number(draft.domainRevision),
    observed_state_hashes: observed,
    expected_file_hashes: draft.steps.filter((step) => step.kind.startsWith('file_')).map((step) => digest((step.value.value as JsonObject).expected_before_digest)).filter(Boolean),
    expected_artifact_hashes: draft.steps.filter((step) => step.kind.startsWith('artifact_')).map((step) => digest((step.value.value as JsonObject).expected_digest)).filter(Boolean),
    steps: draft.steps.map((step) => ({ action: step.value })),
    backup_required: draft.backupRequired,
    backup_references: draft.backupReferences ?? [],
    rollback_instructions: draft.rollbackInstructions ?? [],
    expires_at: expiresAt
  };
}
