import { afterEach, describe, expect, it, vi } from 'vitest';
import { api, bindingMatchesScope, changeMutationPayload, collection, mutationHeaders, publicApi, session, sha256Json, stageSessionContent, strongSessionVersionTag } from './api';
import { driftState, isOfflineError, isSensitiveKey, isUnsupportedError, safeDisplay, stateTone } from './state';

afterEach(() => vi.restoreAllMocks());

describe('api client', () => {
  it('uses the versioned same-origin endpoint and parses successful JSON', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('{"items":[{"id":"svc-1"}]}', { status: 200, headers: { 'content-type': 'application/json' } }));

    const result = await api<{ items: { id: string }[] }>('/services');

    expect(result.data?.items[0].id).toBe('svc-1');
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/services', expect.objectContaining({ credentials: 'same-origin' }));
    expect(fetchMock.mock.calls[0][1]).toEqual(expect.objectContaining({ headers: expect.any(Headers) }));
    const headers = (fetchMock.mock.calls[0][1] as RequestInit).headers as Headers;
    expect(headers.get('Accept')).toBe('application/json');
  });

  it('returns the request id and server message on API errors', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('{"message":"capability unavailable"}', { status: 409, headers: { 'x-request-id': 'req-42' } }));

    await expect(api('/services')).resolves.toEqual({ error: { status: 409, message: 'capability unavailable', requestId: 'req-42' } });
  });

  it('keeps public health endpoints outside the versioned resource prefix', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('{"status":"healthy"}', { status: 200, headers: { 'content-type': 'application/json' } }));

    await expect(publicApi<{ status: string }>('/health')).resolves.toEqual({ data: { status: 'healthy' } });
    expect(fetchMock).toHaveBeenCalledWith('/health', expect.objectContaining({ credentials: 'same-origin' }));
  });

  it('fetches the authenticated same-origin session for CSRF initialization', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('{"csrf_token":"csrf-1"}', { status: 200, headers: { 'content-type': 'application/json' } }));

    await expect(session()).resolves.toEqual({ data: { csrf_token: 'csrf-1' } });
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/session', expect.objectContaining({ method: 'POST', credentials: 'same-origin' }));
  });

  it('does not treat an HTML fallback page as a successful API response', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('<html>fallback</html>', { status: 200, headers: { 'content-type': 'text/html' } }));

    await expect(api('/services')).resolves.toEqual({ error: { status: 502, message: 'Controller returned a non-JSON response' } });
  });

  it('stages bytes under the selected Change Session and keeps only the returned ref', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('{"digest":"' + 'a'.repeat(64) + '","size":2}', { status: 200, headers: { 'content-type': 'application/json' } }));
    await expect(stageSessionContent('session-1', [111, 107], 'csrf-1', '7')).resolves.toEqual({ data: { digest: 'a'.repeat(64), size: 2 } });
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/change-sessions/session-1/staged-content', expect.objectContaining({ method: 'POST', body: new Uint8Array([111, 107]) }));
    const headers = (fetchMock.mock.calls[0][1] as RequestInit).headers as Headers;
    expect(headers.get('Content-Type')).toBe('application/octet-stream');
    expect(headers.get('Idempotency-Key')).toMatch(/^[0-9a-f-]{36}$/);
    expect(headers.get('X-CSRF-Token')).toBe('csrf-1');
    expect(headers.get('If-Match')).toBe('"7"');
    expect(headers.get('x-kitsunebi-classification')).toBe('mutable_config');
  });

  it('serializes only positive Change Session versions as strong tags', () => {
    expect(strongSessionVersionTag(7)).toBe('"7"');
    expect(strongSessionVersionTag('"8"')).toBe('"8"');
    expect(() => strongSessionVersionTag('etag-7')).toThrow(/positive integer/);
  });
});

describe('change safety helpers', () => {
  it('requires the plan hash, optimistic version, and idempotency key', () => {
    const headers = mutationHeaders('sha256:abc', 'revision-7', 'change-123', 'csrf-1');
    expect(headers.get('Idempotency-Key')).toBe('change-123');
    expect(headers.get('If-Match')).toBe('revision-7');
    expect(headers.get('X-Request-Hash')).toBe('sha256:abc');
    expect(headers.get('X-CSRF-Token')).toBe('csrf-1');
  });

  it('accepts both API collection shapes without inventing local records', () => {
    expect(collection<{ id: string }>({ items: [{ id: 'one' }] })).toEqual([{ id: 'one' }]);
    expect(collection<{ id: string }>({ unexpected: true })).toEqual([]);
  });

  it('produces the stable payload hash sent in a MutationRequest', async () => {
    await expect(sha256Json({ steps: [] })).resolves.toHaveLength(64);
  });

  it('normalizes the typed change payload before hashing', async () => {
    const payload = changeMutationPayload('plan', {
      steps: [{ action: { kind: 'execution_lifecycle', value: { binding_id: 'binding-1', action: 'start', ignored: true } } }],
      observed_state_hashes: ['observed'],
      service_id: 'svc-1',
      target: { kind: 'cluster', value: 'cluster-1' },
      session_id: 'change-1',
      domain_revision: '7'
    });

    expect(payload).toEqual({
      kind: 'change-plan',
      value: {
        session_id: 'change-1',
        service_id: 'svc-1',
        target: { kind: 'cluster', value: 'cluster-1' },
        domain_revision: 7,
        observed_state_hashes: ['observed'],
        expected_file_hashes: [],
        expected_artifact_hashes: [],
        steps: [{ action: { kind: 'execution_lifecycle', value: {
          action: 'start', binding_id: 'binding-1', domain_revision: 0,
          expected_binding_hash: '', expected_state_hash: ''
        } } }],
        backup_required: false,
        backup_references: [],
        rollback_instructions: [],
        expires_at: 0
      }
    });
  });

  it('normalizes the complete change lifecycle payloads', () => {
    expect(changeMutationPayload('verify', { session_id: 'session-1', operation_id: 'operation-1', evidence_hash: 'ignored' })).toEqual({ kind: 'change-verify', value: { session_id: 'session-1', operation_id: 'operation-1' } });
    expect(changeMutationPayload('accept', { session_id: 'session-1', operation_id: 'operation-1' })).toEqual({ kind: 'change-accept', value: { session_id: 'session-1', operation_id: 'operation-1' } });
    expect(changeMutationPayload('rollback', { session_id: 'session-1', operation_id: 'operation-1', reason: 'restore' })).toEqual({ kind: 'change-rollback', value: { session_id: 'session-1', operation_id: 'operation-1', reason: 'restore' } });
  });

  it('preserves tagged file batch operations while normalizing the plan', () => {
    expect(changeMutationPayload('plan', {
      session_id: 'change-1', service_id: 'service-1', target: { kind: 'cluster', value: 'cluster-1' },
      domain_revision: 1, observed_state_hashes: ['a'.repeat(64)], steps: [{ action: { kind: 'file_batch', value: {
        binding_id: 'binding-1', expected_binding_hash: 'a'.repeat(64), domain_revision: 1,
        operations: [{ kind: 'write', value: { path: 'server.properties', expected_before_digest: null, content: { digest: 'b'.repeat(64), size: 3 }, classification: 'mutable_config' } }]
      } } }]
    })).toMatchObject({ value: { steps: [{ action: { value: { operations: [{ kind: 'write', value: { path: 'server.properties', content: { digest: 'b'.repeat(64), size: 3 } } }] } } }] } });
  });

  it('preserves the current binding, runtime, proxy, and restore fields', () => {
    const id = '11111111-1111-4111-8111-111111111111';
    const targetId = '22222222-2222-4222-8222-222222222222';
    const hash = 'a'.repeat(64);
    const payload = changeMutationPayload('plan', {
      session_id: id, service_id: id, target: { kind: 'cluster', value: id }, domain_revision: 4,
      observed_state_hashes: [hash], steps: [
        { action: { kind: 'proxy_rollout', value: {
          pool_id: id, expected_instance_id: id, target_instance_id: targetId, expected_instance_version: 2,
          target_instance_version: 3, expected_instance_state: 'accepting', target_instance_state: 'ready',
          target_binding_id: targetId, target_binding_hash: hash, domain_revision: 4, desired_state: 'accepting',
          configuration: [{ kind: 'write', value: { path: 'server.properties', expected_before_digest: null, content: { digest: hash, size: 1 }, classification: 'mutable_config' } }]
        } } },
        { action: { kind: 'endpoint_rollout', value: {
          expected_binding_id: id, target_binding_id: targetId, cluster_id: id, expected_revision: id,
          target_revision: targetId, expected_version: 2, runtime_binding_ids: [id], runtime_binding_hashes: [hash]
        } } },
        { action: { kind: 'backup_restore', value: {
          reference_id: id, target: { kind: 'service', value: id }, expected_manifest_digest: hash,
          rollback_reference_id: targetId, expected_rollback_manifest_digest: hash, expected_version: 2
        } } }
      ]
    });
    expect(payload).toMatchObject({ value: { steps: [
      { action: { value: { expected_instance_id: id, target_instance_id: targetId, expected_instance_version: 2, target_instance_version: 3, target_binding_id: targetId, target_binding_hash: hash, configuration: [{ kind: 'write', value: { path: 'server.properties', content: { digest: hash, size: 1 }, classification: 'mutable_config' } }] } } },
      { action: { value: { expected_binding_id: id, target_binding_id: targetId, runtime_binding_ids: [id], runtime_binding_hashes: [hash] } } },
      { action: { value: { rollback_reference_id: targetId, expected_rollback_manifest_digest: hash } } }
    ] } });
  });

  it('filters binding candidates to the selected service and cluster scope', () => {
    expect(bindingMatchesScope({ binding_id: 'a', service_id: 'service-1', cluster_id: 'cluster-1' }, 'service-1', 'cluster-1')).toBe(true);
    expect(bindingMatchesScope({ binding_id: 'b', service_id: 'service-1', cluster_id: 'cluster-2' }, 'service-1', 'cluster-1')).toBe(false);
    expect(bindingMatchesScope({ binding_id: 'c', service_id: 'service-1' }, 'service-1', 'cluster-1')).toBe(false);
    expect(bindingMatchesScope({ binding_id: 'd', target: { Cluster: 'cluster-1' } }, 'service-1', 'cluster-1')).toBe(true);
    expect(bindingMatchesScope({ binding_id: 'e', target: { Cluster: 'cluster-2' } }, 'service-1', 'cluster-1')).toBe(false);
    expect(bindingMatchesScope({ binding_id: 'f', target: { ExecutionUnit: 'unit-1' } }, 'service-1', 'cluster-1')).toBe(false);
  });
});

describe('resource state helpers', () => {
  it('distinguishes unsupported and unavailable capabilities', () => {
    expect(isUnsupportedError({ status: 501, message: 'not implemented' })).toBe(true);
    expect(isUnsupportedError({ status: 403, message: 'forbidden' })).toBe(false);
    expect(isOfflineError({ status: 0, message: 'Controller is unreachable' })).toBe(true);
  });

  it('keeps stopped on-demand services neutral and marks explicit failure states', () => {
    expect(stateTone('stopped')).toBe('neutral');
    expect(stateTone('failed')).toBe('bad');
    expect(stateTone('accepting')).toBe('good');
  });

  it('only calls an explicit drift signal a problem', () => {
    expect(driftState({ id: 'svc-1', drift: 'drift detected' })).toBe('drift');
    expect(driftState({ id: 'svc-2', drift: 'in sync' })).toBe('in-sync');
    expect(driftState({ id: 'svc-3', state: 'stopped' })).toBe('unknown');
  });

  it('redacts credential-shaped fields before rendering API records', () => {
    expect(isSensitiveKey('gameap_token')).toBe(true);
    expect(safeDisplay('gameap_token', 'should-not-render')).toBe('[redacted by policy]');
    expect(safeDisplay('version', 'rev-7')).toBe('rev-7');
  });
});
