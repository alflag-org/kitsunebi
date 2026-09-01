import { test, expect, type Page, type Route } from '@playwright/test';

const service = '00000000-0000-4000-8000-0000000000a1';
const cluster = '00000000-0000-4000-8000-0000000000a2';
const binding = '00000000-0000-4000-8000-0000000000a3';
const sessionId = '00000000-0000-4000-8000-0000000000a4';
const planId = '00000000-0000-4000-8000-0000000000a6';
const operationId = '00000000-0000-4000-8000-0000000000a5';
const digest = 'a'.repeat(64);
const persistedPlanHash = 'b'.repeat(64);

type CapturedRequest = { method: string; url: string; headers: Record<string, string>; body?: unknown };
type MockState = { requests: CapturedRequest[]; sessionState: string; version: number; stalePlan: boolean; started: boolean };

async function json(route: Route, value: unknown, status = 200): Promise<void> {
  await route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(value) });
}

function installMock(page: Page, options: { stalePlan?: boolean; aborted?: boolean } = {}): MockState {
  const state: MockState = { requests: [], sessionState: options.aborted ? 'aborted' : 'editing', version: 1, stalePlan: options.stalePlan ?? false, started: false };
  void page.route('**/*', async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (url.pathname === '/health') return json(route, { status: 'healthy', capabilities: 'mock', backup_mutation: 'enabled' });
    if (!url.pathname.startsWith('/api/v1/')) return route.continue();

    const body = request.method() === 'POST' && request.headers()['content-type']?.includes('json') ? request.postDataJSON() : undefined;
    state.requests.push({ method: request.method(), url: url.pathname, headers: request.headers(), body });
    if (url.pathname === '/api/v1/session' && request.method() === 'POST') return json(route, { csrf_token: 'csrf-e2e' });
    if (url.pathname === '/api/v1/services') return json(route, [{ id: service, name: 'Smoke service', state: 'Active' }]);
    if (url.pathname === '/api/v1/clusters') return json(route, [{ id: cluster, name: 'Smoke cluster', service_id: service }]);
    if (url.pathname === '/api/v1/execution-units') return json(route, [{ id: binding, binding_id: binding, name: 'Smoke binding', service_id: service, cluster_id: cluster, observed_hash: digest }]);
    if (url.pathname === '/api/v1/proxy-pools') return json(route, []);
    if (url.pathname === '/api/v1/change-sessions' && request.method() === 'GET') return json(route, state.started || options.aborted ? [{ id: sessionId, name: 'Smoke session', service_id: service, cluster_id: cluster, state: state.sessionState, version: state.version, ...(options.aborted ? { operation_id: operationId } : {}) }] : []);
    if (url.pathname === '/api/v1/change-sessions' && request.method() === 'POST') { state.started = true; return json(route, { id: sessionId, service_id: service, cluster_id: cluster, state: state.sessionState, version: state.version }); }
    if (url.pathname === `/api/v1/change-sessions/${sessionId}/staged-content`) return json(route, { digest, size: request.postDataBuffer()?.length ?? 0 });
    if (url.pathname === `/api/v1/change-sessions/${sessionId}/plan`) {
      if (state.stalePlan) return json(route, { message: 'stale session version' }, 412);
      state.sessionState = 'ready';
      return json(route, { plan_id: planId, plan_hash: persistedPlanHash, session_id: sessionId, state: state.sessionState });
    }
    if (url.pathname === `/api/v1/change-sessions/${sessionId}/approve`) {
      state.sessionState = 'ready';
      return json(route, { plan_id: planId, plan_hash: persistedPlanHash, session_id: sessionId, state: state.sessionState });
    }
    if (url.pathname === `/api/v1/change-sessions/${sessionId}/apply`) {
      state.sessionState = 'verifying';
      return json(route, { id: operationId, status: 'applying', plan_hash: persistedPlanHash, request_id: 'req-apply' });
    }
    if (url.pathname === `/api/v1/change-sessions/${sessionId}/verify`) return json(route, { id: operationId, status: 'verified', plan_hash: persistedPlanHash, request_id: 'req-verify' });
    if (url.pathname === `/api/v1/change-sessions/${sessionId}/accept`) {
      state.sessionState = 'accepted';
      return json(route, { id: operationId, status: 'accepted', plan_hash: persistedPlanHash, request_id: 'req-accept' });
    }
    if (url.pathname === `/api/v1/change-sessions/${sessionId}/rollback`) {
      state.sessionState = 'rolled_back';
      return json(route, { id: operationId, status: 'rolled_back', plan_hash: persistedPlanHash, request_id: 'req-rollback' });
    }
    if (url.pathname.includes('/files') && url.pathname.endsWith('/read')) return json(route, { path: 'secret.properties', content_type: 'application/vnd.kitsunebi.secret-metadata', content: [115, 101, 99, 114, 101, 116] });
    if (url.pathname.includes('/files')) return json(route, [{ path: 'secret.properties', size: 6, digest, classification: 'secret' }, { path: 'unknown.properties', size: 1, digest, classification: 'unknown' }]);
    return json(route, []);
  });
  return state;
}

function request(state: MockState, suffix: string, method = 'POST'): CapturedRequest {
  const result = state.requests.find((entry) => entry.method === method && entry.url.endsWith(suffix));
  if (!result) throw new Error(`No captured ${method} ${suffix}`);
  return result;
}

async function openChangeSession(page: Page): Promise<void> {
  await page.goto('/change-sessions');
  await expect(page.getByRole('heading', { name: 'Change sessions' })).toBeVisible();
  await page.getByLabel('Service').first().selectOption(service);
  await page.getByLabel('Cluster').first().selectOption(cluster);
  await page.getByRole('button', { name: 'Begin session', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Smoke session', exact: true })).toBeVisible();
}

test('stages a typed file plan through verified acceptance and protects classified files', async ({ page }) => {
  const state = installMock(page);
  await openChangeSession(page);
  await page.getByLabel('Step').selectOption('file_write');
  await page.getByLabel('Binding Id').selectOption(binding);
  await page.getByLabel('Path').fill('server.properties');
  await page.getByLabel('Expected Binding Hash').fill(digest);
  await page.getByLabel('Domain Revision').fill('1');
  await page.getByLabel('Classification').selectOption('mutable_config');
  await page.locator('input[type="file"]').first().setInputFiles({ name: 'server.properties', mimeType: 'text/plain', buffer: Buffer.from('motd=smoke\n') });
  await expect(page.getByText(/Staged bytes/)).toBeVisible();

  const staged = request(state, '/staged-content');
  expect(staged.headers['content-type']).toBe('application/octet-stream');
  expect(staged.headers['x-csrf-token']).toBe('csrf-e2e');
  expect(staged.headers['x-kitsunebi-classification']).toBe('mutable_config');
  expect(staged.headers['if-match']).toBe('"1"');
  expect(staged.headers['idempotency-key']).toMatch(/^[0-9a-f-]{36}$/);

  await page.getByRole('button', { name: 'Plan', exact: true }).click();
  await expect(page.getByText(`Plan ${planId} is ready for approval.`)).toBeVisible();
  const planned = request(state, '/plan');
  expect(planned.headers['if-match']).toBe('"1"');
  expect(planned.headers['x-csrf-token']).toBe('csrf-e2e');
  expect(planned.headers['x-request-hash']).toBe((planned.body as Record<string, unknown>).request_hash);
  expect((planned.body as Record<string, unknown>).request_hash).not.toBe(persistedPlanHash);
  const planPayload = ((planned.body as Record<string, unknown>).payload as Record<string, unknown>).value as Record<string, unknown>;
  expect(planPayload.observed_state_hashes).toHaveLength(1);
  expect(planPayload.steps).toEqual([{ action: { kind: 'file_write', value: expect.objectContaining({ content: { digest, size: 11 }, classification: 'mutable_config' }) } }]);

  await page.getByRole('button', { name: 'Approve', exact: true }).click();
  await expect(page.getByText(`Plan ${planId} is approved.`)).toBeVisible();
  const approved = request(state, '/approve');
  expect(approved.headers['x-request-hash']).toBe((approved.body as Record<string, unknown>).request_hash);
  expect(((approved.body as Record<string, unknown>).payload as Record<string, unknown>).value).toEqual(expect.objectContaining({ plan_hash: persistedPlanHash }));
  expect((approved.body as Record<string, unknown>).request_hash).not.toBe(persistedPlanHash);
  expect(approved.headers['if-match']).toBe(persistedPlanHash);
  await page.getByRole('button', { name: 'Apply', exact: true }).click();
  await expect(page.getByText(/Operation .* is now applying/)).toBeVisible();
  const applied = request(state, '/apply');
  expect(applied.headers['x-request-hash']).toBe((applied.body as Record<string, unknown>).request_hash);
  expect(applied.headers['if-match']).toBe(persistedPlanHash);
  await page.getByRole('button', { name: 'Verify', exact: true }).click();
  await expect(page.getByText('Verification status: verified')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Accept', exact: true })).toBeEnabled();
  await page.getByRole('button', { name: 'Accept', exact: true }).click();
  await expect(page.getByText(/Operation .* is now accepted/)).toBeVisible();

  await page.getByRole('button', { name: /Files/ }).click();
  await page.getByRole('button', { name: 'Browse', exact: true }).click();
  await page.getByRole('button', { name: /secret\.properties/ }).click();
  await expect(page.getByText(/Secret metadata is protected/)).toBeVisible();
  await expect(page.getByRole('button', { name: 'Stage in Change Session', exact: true }).first()).toBeDisabled();
});

test('does not advance after a stale plan response', async ({ page }) => {
  const state = installMock(page, { stalePlan: true });
  await openChangeSession(page);
  await page.getByLabel('Step').selectOption('execution_lifecycle');
  await page.getByLabel('Binding Id').selectOption(binding);
  await page.getByLabel('Expected Binding Hash').fill(digest);
  await page.getByLabel('Expected State Hash').fill(digest);
  await page.getByRole('button', { name: 'Plan', exact: true }).click();
  await expect(page.getByText(/persisted Change Session or plan is stale/)).toBeVisible();
  await expect(page.getByRole('button', { name: 'Approve', exact: true })).toBeDisabled();
  expect(state.requests.filter((entry) => entry.url.endsWith('/approve'))).toHaveLength(0);
});

test('allows explicit rollback for an aborted session with persisted operation evidence', async ({ page }) => {
  const state = installMock(page, { aborted: true });
  await page.goto('/change-sessions');
  await expect(page.getByRole('heading', { name: 'Smoke session', exact: true })).toBeVisible();
  await expect(page.getByText(`Operation ${operationId}`)).toBeVisible();
  await expect(page.getByRole('button', { name: 'Apply', exact: true })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Rollback', exact: true })).toBeDisabled();
  await page.getByLabel('Rollback reason').fill('Restore the retained inverse evidence.');
  await expect(page.getByRole('button', { name: 'Rollback', exact: true })).toBeEnabled();
  await page.getByRole('button', { name: 'Rollback', exact: true }).click();
  await expect(page.getByText(/Operation .* is now rolled_back/)).toBeVisible();
  const rollback = request(state, '/rollback');
  const payload = ((rollback.body as Record<string, unknown>).payload as Record<string, unknown>).value as Record<string, unknown>;
  expect(payload).toEqual(expect.objectContaining({ operation_id: operationId, reason: 'Restore the retained inverse evidence.' }));
  expect(state.requests.filter((entry) => entry.url.endsWith('/apply'))).toHaveLength(0);
});
