import type { ApiError, ApiResult, JsonObject, OperationEvent } from './types';

const API_PREFIX = '/api/v1';

function isAbortError(cause: unknown): boolean {
  return cause instanceof Error && cause.name === 'AbortError';
}

async function readError(response: Response): Promise<ApiError> {
  const requestId = response.headers.get('x-request-id') ?? undefined;
  let message = response.status === 0 ? 'Controller is unreachable' : `Request failed (${response.status})`;
  let code: string | undefined;
  try {
    const body = await response.json() as { message?: string; error?: string; code?: string };
    code = body.code;
    message = body.message ?? body.error ?? message;
  } catch {
    // Some gateways return an empty body. Keep the status-derived message.
  }
  return { status: response.status, message, requestId, code };
}

async function request<T>(url: string, init: RequestInit = {}): Promise<ApiResult<T>> {
  const headers = new Headers(init.headers);
  headers.set('Accept', 'application/json');
  if (init.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
  let response: Response;
  try {
    response = await fetch(url, { ...init, credentials: 'same-origin', headers });
  } catch (cause) {
    if (isAbortError(cause)) throw cause;
    return { error: { status: 0, message: 'Controller is unreachable' } };
  }
  if (!response.ok) return { error: await readError(response) };
  if (response.status === 204) return { data: undefined as T };
  const contentType = response.headers.get('content-type') ?? '';
  if (!contentType.includes('json')) return { error: { status: 502, message: 'Controller returned a non-JSON response' } };
  try {
    return { data: await response.json() as T };
  } catch {
    return { error: { status: 502, message: 'Controller returned invalid JSON' } };
  }
}

/** Versioned management resources. Authentication is supplied by the same-origin session. */
export function api<T>(path: string, init: RequestInit = {}): Promise<ApiResult<T>> {
  return request<T>(`${API_PREFIX}${path}`, init);
}

/** Public controller endpoints such as /health remain outside the versioned resource API. */
export function publicApi<T>(path: string, init: RequestInit = {}): Promise<ApiResult<T>> {
  return request<T>(path, init);
}

export type SessionResponse = { csrf_token: string };

/** Fetch the short-lived CSRF token from the authenticated same-origin session. */
export function session(): Promise<ApiResult<SessionResponse>> {
  return api<SessionResponse>('/session', { method: 'POST' });
}

export type StagedContentResponse = { digest: string; size: number };

/** Change Session versions are strong entity tags, not arbitrary client etags. */
export function strongSessionVersionTag(version: string | number): string {
  const value = String(version).trim().replace(/^"|"$/g, '');
  if (!/^[1-9]\d*$/.test(value)) throw new Error('Change Session version must be a positive integer.');
  return `"${value}"`;
}

/** Store bytes under a Change Session and return only the content-addressed reference. */
export function stageSessionContent(sessionId: string, bytes: number[], csrfToken?: string, version?: string, classification = 'mutable_config'): Promise<ApiResult<StagedContentResponse>> {
  const headers = new Headers({
    'Content-Type': 'application/octet-stream',
    'Idempotency-Key': crypto.randomUUID(),
    'x-kitsunebi-classification': classification,
  });
  if (csrfToken) headers.set('X-CSRF-Token', csrfToken);
  if (version) headers.set('If-Match', strongSessionVersionTag(version));
  return api<StagedContentResponse>(`/change-sessions/${encodeURIComponent(sessionId)}/staged-content`, {
    method: 'POST', headers, body: new Uint8Array(bytes),
  });
}

export function mutationHeaders(requestHash: string, version: string, key: string, csrfToken?: string): Headers {
  const headers = new Headers({
    'Idempotency-Key': key,
    'If-Match': version,
    'X-Request-Hash': requestHash,
  });
  // Cloudflare Access remains a same-origin cookie/header concern. The UI never stores an Access token.
  if (csrfToken) headers.set('X-CSRF-Token', csrfToken);
  return headers;
}

function textFrom(value: JsonObject, key: string): string {
  return String(value[key] ?? '');
}

function numberFrom(value: JsonObject, key: string): number {
  const result = Number(value[key] ?? 0);
  return Number.isFinite(result) && result >= 0 ? Math.floor(result) : 0;
}

function normalizeBatchOperation(value: unknown): JsonObject {
  const raw = value && typeof value === 'object' ? value as JsonObject : {};
  const input = raw.value && typeof raw.value === 'object' ? { ...(raw.value as JsonObject), kind: raw.kind } : raw;
  const kind = String(input.kind ?? '');
  const optionalDigest = (key: string): string | null => input[key] == null || input[key] === '' ? null : String(input[key]);
  if (kind === 'write') {
    const content = input.content && typeof input.content === 'object' ? input.content as JsonObject : {};
    return { kind, value: {
      path: String(input.path ?? ''), expected_before_digest: optionalDigest('expected_before_digest'),
      content: { digest: textFrom(content, 'digest'), size: numberFrom(content, 'size') }, classification: String(input.classification ?? '')
    } };
  }
  if (kind === 'move') return { kind, value: {
    from: String(input.from ?? ''), to: String(input.to ?? ''), expected_before_digest: optionalDigest('expected_before_digest'),
    expected_target_digest: optionalDigest('expected_target_digest'), classification: String(input.classification ?? '')
  } };
  if (kind === 'quarantine') return { kind, value: {
    path: String(input.path ?? ''), expected_before_digest: optionalDigest('expected_before_digest'), classification: String(input.classification ?? '')
  } };
  return { kind: '', value: {} };
}

/**
 * Build the closed payload shape used by the controller's MutationRequest.
 * Keeping the field order here mirrors the Rust DTO order, so the SHA-256
 * sent in request_hash is stable for the structured Change Session form.
 */
export function changeMutationPayload(command: string, input: JsonObject): JsonObject {
  const text = (key: string): string => textFrom(input, key);
  const number = (key: string): number => numberFrom(input, key);
  const targetInput = input.target && typeof input.target === 'object' ? input.target as JsonObject : {};
  const targetKind = String(targetInput.kind ?? '');
  const target = ['service', 'cluster', 'world', 'proxy_pool', 'proxy_instance', 'artifact', 'artifact_set', 'endpoint', 'endpoint_binding', 'access_policy', 'backup', 'execution_unit'].includes(targetKind)
    ? { kind: targetKind, value: String(targetInput.value ?? '') }
    : { kind: 'cluster', value: '' };
  const steps = Array.isArray(input.steps)
    ? input.steps.map((step) => {
        const wrapper = step && typeof step === 'object' ? step as JsonObject : {};
        const value = wrapper.action && typeof wrapper.action === 'object' ? wrapper.action as JsonObject : wrapper;
        const kind = String(value.kind ?? 'execution_lifecycle');
        const detail = value.value && typeof value.value === 'object' ? value.value as JsonObject : value;
        const fields: Record<string, string[]> = {
          execution_provision: ['binding_id', 'expected_binding_hash', 'domain_revision'],
          execution_delete: ['binding_id', 'expected_binding_hash', 'expected_state_hash', 'domain_revision', 'expected_version'],
          service_lifecycle_transition: ['service_id', 'expected_state', 'next_state', 'expected_version', 'reason'],
          cluster_revision_create: ['cluster_id', 'revision', 'new_endpoint_bindings', 'expected_current_number'],
          execution_lifecycle: ['binding_id', 'action', 'expected_binding_hash', 'expected_state_hash', 'domain_revision'],
          file_write: ['binding_id', 'path', 'expected_binding_hash', 'domain_revision', 'expected_before_digest', 'content', 'classification'],
          file_move: ['binding_id', 'from', 'to', 'expected_binding_hash', 'domain_revision', 'expected_before_digest', 'expected_target_digest', 'classification'],
          file_quarantine: ['binding_id', 'path', 'expected_binding_hash', 'domain_revision', 'expected_before_digest', 'classification'],
          file_batch: ['binding_id', 'expected_binding_hash', 'domain_revision', 'operations'],
          artifact_register: ['artifact', 'content', 'expected_version', 'domain_revision'],
          artifact_stage: ['artifact_id', 'expected_digest', 'expected_version', 'domain_revision'],
          artifact_activate: ['artifact_id', 'artifact_set_id', 'binding_id', 'expected_binding_hash', 'cluster_id', 'expected_revision', 'target_revision', 'expected_digest', 'expected_version', 'destination_path', 'expected_before_digest'],
          proxy_rollout: ['pool_id', 'expected_instance_id', 'target_instance_id', 'expected_instance_version', 'target_instance_version', 'expected_instance_state', 'target_instance_state', 'target_binding_id', 'target_binding_hash', 'domain_revision', 'desired_state', 'configuration'],
          world_writer_cutover: ['world_id', 'expected_version', 'expected_writer', 'next_writer', 'expected_writer_binding_id', 'target_writer_binding_id', 'expected_writer_binding_hash', 'target_writer_binding_hash', 'domain_revision'],
          endpoint_rollout: ['expected_binding_id', 'target_binding_id', 'cluster_id', 'expected_revision', 'target_revision', 'expected_version', 'runtime_binding_ids', 'runtime_binding_hashes'],
          access_policy_update: ['policy_id', 'service_id', 'expected_version', 'desired_grants', 'desired_policy_hash'],
          route_policy_update: ['route_id', 'pool_id', 'service_id', 'expected_cluster', 'target_cluster', 'expected_priority', 'target_priority', 'expected_version', 'disabled'],
          backup_create: ['kind', 'target', 'request_hash'],
          backup_restore: ['reference_id', 'target', 'expected_manifest_digest', 'rollback_reference_id', 'expected_rollback_manifest_digest', 'expected_version'],
          service_archive: ['service_id', 'expected_version', 'sunsetting_evidence_hash'],
          service_purge: ['service_id', 'expected_version', 'archive_evidence_hash', 'verified_backup_id', 'archived_at']
        };
        const allowed = fields[kind];
        if (!allowed) return { kind: '', value: {} };
        const normalized: JsonObject = {};
        for (const key of allowed) {
          if (key === 'domain_revision' || key.endsWith('_version') || key === 'expected_version' || key === 'archived_at' || key === 'expected_priority' || key === 'target_priority' || key === 'expected_current_number') normalized[key] = numberFrom(detail, key);
          else if (key === 'disabled') normalized[key] = detail[key] === true || detail[key] === 'true';
          else if (key === 'artifact') {
            normalized[key] = detail[key] && typeof detail[key] === 'object' ? detail[key] : {};
          } else if (key === 'content') {
            const content = detail.content && typeof detail.content === 'object' ? detail.content as JsonObject : {};
            normalized[key] = { digest: textFrom(content, 'digest'), size: numberFrom(content, 'size') };
          } else if (key === 'revision') {
            normalized[key] = detail[key] && typeof detail[key] === 'object' ? detail[key] : {};
          } else if (key === 'new_endpoint_bindings' || key === 'runtime_binding_ids' || key === 'runtime_binding_hashes') normalized[key] = Array.isArray(detail[key]) ? detail[key] : [];
          else if (key === 'expected_before_digest' || key === 'expected_target_digest' || key === 'expected_writer' || key === 'expected_writer_binding_id' || key === 'expected_writer_binding_hash') normalized[key] = detail[key] == null || detail[key] === '' ? null : String(detail[key]);
          else if (key === 'operations' || key === 'configuration') normalized[key] = Array.isArray(detail[key]) ? detail[key].map(normalizeBatchOperation) : [];
          else if (key === 'desired_grants' || key === 'target') normalized[key] = Array.isArray(detail[key]) ? detail[key] : (detail[key] && typeof detail[key] === 'object' ? detail[key] : {});
          else normalized[key] = textFrom(detail, key);
        }
        return { action: { kind, value: normalized } };
      })
    : [];
  switch (command) {
    case 'plan':
      return { kind: 'change-plan', value: {
        session_id: text('session_id'), service_id: text('service_id'), target, domain_revision: number('domain_revision'),
        observed_state_hashes: Array.isArray(input.observed_state_hashes) ? input.observed_state_hashes.map(String) : [],
        expected_file_hashes: Array.isArray(input.expected_file_hashes) ? input.expected_file_hashes.map(String) : [],
        expected_artifact_hashes: Array.isArray(input.expected_artifact_hashes) ? input.expected_artifact_hashes.map(String) : [],
        steps, backup_required: Boolean(input.backup_required),
        backup_references: Array.isArray(input.backup_references) ? input.backup_references.map(String) : [],
        rollback_instructions: Array.isArray(input.rollback_instructions) ? input.rollback_instructions.map(String) : [],
        expires_at: number('expires_at')
      } };
    case 'approve':
      return { kind: 'change-approve', value: { session_id: text('session_id'), plan_id: text('plan_id'), plan_hash: text('plan_hash') } };
    case 'apply':
      return { kind: 'change-apply', value: { session_id: text('session_id'), plan_id: text('plan_id') } };
    case 'verify':
      return { kind: 'change-verify', value: { session_id: text('session_id'), operation_id: text('operation_id') } };
    case 'accept':
      return { kind: 'change-accept', value: { session_id: text('session_id'), operation_id: text('operation_id') } };
    case 'rollback':
      return { kind: 'change-rollback', value: { session_id: text('session_id'), operation_id: text('operation_id'), reason: text('reason') } };
    default:
      throw new Error(`Unsupported Change Session command: ${command}`);
  }
}

export function collection<T extends JsonObject = JsonObject>(value: unknown): T[] {
  if (Array.isArray(value)) return value as T[];
  if (value && typeof value === 'object' && Array.isArray((value as { items?: unknown }).items)) {
    return (value as { items: T[] }).items;
  }
  return [];
}

export function resourceValue(resource: JsonObject, ...keys: string[]): unknown {
  for (const key of keys) if (resource[key] !== undefined && resource[key] !== null) return resource[key];
  return undefined;
}

export function resourceLabel(resource: JsonObject): string {
  return String(resourceValue(resource, 'name', 'title', 'label', 'id') ?? 'Unnamed record');
}

/** Return true only when a binding carries enough persisted scope to match both selectors. */
export function bindingMatchesScope(binding: JsonObject, service: string, cluster: string): boolean {
  const explicitService = resourceValue(binding, 'service_id', 'service');
  const explicitCluster = resourceValue(binding, 'cluster_id', 'cluster');
  const scope = resourceValue(binding, 'scope');
  const scopeRecord = scope && typeof scope === 'object' ? scope as JsonObject : {};
  const scopedService = explicitService ?? resourceValue(scopeRecord, 'service_id', 'service');
  const scopedCluster = explicitCluster ?? resourceValue(scopeRecord, 'cluster_id', 'cluster');
  const target = resourceValue(binding, 'target');
  const targetRecord = target && typeof target === 'object' ? target as JsonObject : {};
  const targetService = targetRecord.Service ?? targetRecord.service;
  const targetCluster = targetRecord.Cluster ?? targetRecord.cluster;
  if (scopedService !== undefined && String(scopedService) !== service) return false;
  if (scopedCluster !== undefined && String(scopedCluster) !== cluster) return false;
  if (targetService !== undefined && String(targetService) !== service) return false;
  if (targetCluster !== undefined && String(targetCluster) !== cluster) return false;
  return scopedCluster !== undefined || targetCluster !== undefined;
}

export function wsUrl(path: string): string {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${protocol}//${window.location.host}${API_PREFIX}${path}`;
}

export function parseSseEvent(raw: string): OperationEvent | undefined {
  const data = raw.split('\n').filter((line) => line.startsWith('data:')).map((line) => line.slice(5).trim()).join('\n');
  if (!data) return undefined;
  try { return JSON.parse(data) as OperationEvent; } catch { return undefined; }
}

export async function sha256Json(value: JsonObject): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(JSON.stringify(value)));
  return [...new Uint8Array(digest)].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}
