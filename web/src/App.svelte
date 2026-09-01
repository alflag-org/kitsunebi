<script lang="ts">
  import { onMount } from 'svelte';
  import { api, changeMutationPayload, collection, mutationHeaders, publicApi, resourceLabel, resourceValue, session, sha256Json, stageSessionContent, strongSessionVersionTag } from './lib/api';
  import { driftState, isUnsupportedError, stateTone } from './lib/state';
  import type { ApiResult, JsonObject, Operation } from './lib/types';
  import type { StagedFile } from './lib/changePlan';
  import StateMessage from './lib/components/StateMessage.svelte';
  import ResourceList from './lib/components/ResourceList.svelte';
  import ResourceDetail from './lib/components/ResourceDetail.svelte';
  import ChangePanel from './lib/components/ChangePanel.svelte';
  import OperationsPanel from './lib/components/OperationsPanel.svelte';
  import ConsolePanel from './lib/components/ConsolePanel.svelte';
  import FilesPanel from './lib/components/FilesPanel.svelte';
  import type { Surface } from './lib/navigation';

  export let initialActive: Surface = 'Dashboard';

  const nav = [
    { group: 'Observe', items: ['Dashboard', 'Services', 'Service detail', 'Clusters', 'Cluster revisions', 'Execution units', 'Worlds', 'Proxy pools', 'Proxy instances', 'External endpoints'] },
    { group: 'Operate', items: ['Console', 'Files', 'File diff', 'Artifacts', 'Plugins / mods', 'Change sessions', 'Operations', 'Backups / restore'] },
    { group: 'Govern', items: ['Access policies', 'Lifecycle / decisions', 'Audit'] }
  ];
  const endpoints: Record<string, string> = {
    Dashboard: '/services', Services: '/services', 'Service detail': '/services', Clusters: '/clusters', 'Cluster revisions': '/cluster-revisions', 'Execution units': '/execution-units', Worlds: '/worlds', 'Proxy pools': '/proxy-pools', 'Proxy instances': '/proxy-instances', 'External endpoints': '/endpoints', Console: '/execution-units', Files: '/execution-units', 'File diff': '/execution-units', Artifacts: '/artifacts', 'Plugins / mods': '/artifacts?kind=plugin', 'Change sessions': '/change-sessions', Operations: '/operations', 'Backups / restore': '/backups', 'Access policies': '/access-policies', 'Lifecycle / decisions': '/services', Audit: '/audit-events'
  };
  const unsupportedReasons: Record<string, string> = {
    // Keep this map for future capabilities that are intentionally visible but not exposed by the controller.
  };

  let active: Surface = initialActive; let menuOpen = false; let loading = false; let error = ''; let loaded = false; let activeUnsupported = false; let lastObserved = ''; let csrfToken = ''; let sessionReady = false; let sessionError = '';
  let resources: JsonObject[] = []; let selectedResourceId = ''; let selectedServiceId = ''; let selectedUnitId = ''; let selectedChangeId = ''; let changeServices: JsonObject[] = []; let changeClusters: JsonObject[] = []; let changeBindings: JsonObject[] = []; let stagedFiles: StagedFile[] = []; let detailResource: JsonObject | undefined; let actionBusy = false; let actionMessage = '';
  let dashboardLoading = false; let dashboardErrors: Record<string, string> = {}; let dashboardServices: JsonObject[] = []; let dashboardProxies: JsonObject[] = []; let dashboardChanges: JsonObject[] = [];
  let controllerState = 'unknown'; let capabilityState = 'unknown'; let backupMutationState = 'unknown'; let requestController: AbortController | null = null;

  function endpointFor(surface: string): string {
    if (surface === 'Service detail' && selectedServiceId) return `/services/${encodeURIComponent(selectedServiceId)}`;
    if (surface === 'Console' || surface === 'Files' || surface === 'File diff') return '/execution-units';
    return endpoints[surface] ?? '';
  }
  function errorText(result: ApiResult<unknown>): string {
    if (!result.error) return '';
    return `${result.error.message}${result.error.requestId ? ` · request ${result.error.requestId}` : ''}`;
  }
  function markObserved() { lastObserved = new Date().toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' }); }
  function isAbort(cause: unknown): boolean { return cause instanceof Error && cause.name === 'AbortError'; }

  async function loadDashboard() {
    requestController?.abort(); const controller = new AbortController(); requestController = controller; dashboardLoading = true; dashboardErrors = {}; dashboardServices = []; dashboardProxies = []; dashboardChanges = [];
    try {
      const [services, proxies, changes, health] = await Promise.all([api<unknown>('/services', { signal: controller.signal }), api<unknown>('/proxy-pools', { signal: controller.signal }), api<unknown>('/change-sessions', { signal: controller.signal }), publicApi<JsonObject>('/health', { signal: controller.signal })]);
      if (controller.signal.aborted) return;
      if (services.error) dashboardErrors.services = errorText(services); else dashboardServices = collection<JsonObject>(services.data);
      if (proxies.error) dashboardErrors.proxies = errorText(proxies); else dashboardProxies = collection<JsonObject>(proxies.data);
      if (changes.error) dashboardErrors.changes = errorText(changes); else dashboardChanges = collection<JsonObject>(changes.data);
      if (health.error) { controllerState = 'offline'; capabilityState = 'unknown'; backupMutationState = 'unknown'; } else { const state = String(resourceValue(health.data ?? {}, 'status', 'state') ?? 'unknown'); controllerState = state; capabilityState = String(resourceValue(health.data ?? {}, 'capabilities', 'gameap_capabilities') ?? 'unknown'); backupMutationState = String(resourceValue(health.data ?? {}, 'backup_mutation') ?? 'unknown'); }
      if (!services.error || !proxies.error || !changes.error || !health.error) markObserved();
    } catch (cause) { if (!isAbort(cause)) { dashboardErrors = { services: 'Controller is unreachable', proxies: 'Controller is unreachable', changes: 'Controller is unreachable', health: 'Controller is unreachable' }; controllerState = 'offline'; capabilityState = 'unknown'; } }
    finally { if (requestController === controller) { requestController = null; dashboardLoading = false; } }
  }

  async function observeHealth() {
    const result = await publicApi<JsonObject>('/health');
    if (result.error) { controllerState = 'offline'; capabilityState = 'unknown'; backupMutationState = 'unknown'; return; }
    const health = result.data ?? {};
    controllerState = String(resourceValue(health, 'status', 'state') ?? 'unknown');
    capabilityState = String(resourceValue(health, 'capabilities', 'gameap_capabilities') ?? 'unknown');
    backupMutationState = String(resourceValue(health, 'backup_mutation') ?? 'unknown');
  }

  async function initializeSession() {
    const result = await session();
    if (result.error) {
      sessionError = errorText(result);
      csrfToken = '';
      sessionReady = false;
      return;
    }
    const token = result.data?.csrf_token;
    if (!token) {
      sessionError = 'Authenticated session did not provide a CSRF token.';
      csrfToken = '';
      sessionReady = false;
      return;
    }
    csrfToken = token;
    sessionError = '';
    sessionReady = true;
  }

  async function loadActive() {
    if (active === 'Dashboard') { detailResource = undefined; await loadDashboard(); return; }
    const unsupported = unsupportedReasons[active]; if (unsupported) { loading = false; loaded = false; activeUnsupported = true; error = ''; resources = []; return; }
    requestController?.abort(); const controller = new AbortController(); requestController = controller; loading = true; loaded = false; activeUnsupported = false; error = ''; resources = []; detailResource = undefined; actionMessage = '';
    let path = endpointFor(active); if (active === 'File diff' && selectedUnitId) path = `/execution-units/${encodeURIComponent(selectedUnitId)}/files`; try {
      if (active === 'Change sessions') {
        const [sessions, services, clusters, bindings] = await Promise.all([api<unknown>('/change-sessions', { signal: controller.signal }), api<unknown>('/services', { signal: controller.signal }), api<unknown>('/clusters', { signal: controller.signal }), api<unknown>('/execution-units', { signal: controller.signal })]);
        if (controller.signal.aborted) return;
        if (sessions.error) { error = errorText(sessions); activeUnsupported = isUnsupportedError(sessions.error); } else resources = collection<JsonObject>(sessions.data);
        changeServices = services.error ? [] : collection<JsonObject>(services.data);
        changeClusters = clusters.error ? [] : collection<JsonObject>(clusters.data);
        changeBindings = bindings.error ? [] : collection<JsonObject>(bindings.data);
        loaded = !sessions.error; markObserved();
        if (!selectedChangeId && resources.length) selectedChangeId = String(resources[0].id);
      } else {
      const result = await api<unknown>(path, { signal: controller.signal });
      if (controller.signal.aborted) return;
      if (result.error) { error = errorText(result); activeUnsupported = isUnsupportedError(result.error); } else { if (active === 'Service detail' && result.data && typeof result.data === 'object' && !Array.isArray(result.data) && !Array.isArray((result.data as { items?: unknown }).items)) detailResource = result.data as JsonObject; resources = collection<JsonObject>(result.data); loaded = true; markObserved(); if (['Execution units', 'Console', 'Files', 'File diff'].includes(active) && resources.length && !selectedUnitId) selectedUnitId = String(resources[0].id); }
      }
    } catch (cause) { if (!isAbort(cause)) error = 'Controller is unreachable'; }
    finally { if (requestController === controller) { requestController = null; loading = false; } }
  }

  function selectSurface(surface: string) { active = surface as Surface; menuOpen = false; selectedResourceId = ''; actionMessage = ''; void loadActive(); }
  function selectResource(id: string) {
    selectedResourceId = id;
    if (active === 'Services' || active === 'Service detail') { selectedServiceId = id; active = 'Service detail'; void loadActive(); return; }
    if (active === 'Execution units') { selectedUnitId = id; }
  }
  function selectedResource(): JsonObject | undefined { return resources.find((resource) => String(resource.id) === selectedResourceId); }
  function backToServices() { active = 'Services'; selectedResourceId = ''; void loadActive(); }
  function surfaceDescription(surface: string): string { const descriptions: Record<string, string> = { Services: 'Service intent, observed state, and current drift.', Clusters: 'Game cluster ownership and execution boundaries.', 'Cluster revisions': 'Immutable revision inputs for a cluster.', 'Execution units': 'GameAP bindings, observed runtime state, and capabilities.', Worlds: 'World ownership and writer safety.', 'Proxy pools': 'Pool intent and rollout state.', 'Proxy instances': 'Observed proxy members and their current state.', 'External endpoints': 'Logical endpoint bindings by revision.', Artifacts: 'Candidate and active artifact sets.', 'Plugins / mods': 'Artifact candidates classified as plugins or mods.', 'Backups / restore': 'Backup references, verification, and restore plans.', 'Access policies': 'Actor roles, permissions, and service scopes.', Audit: 'Immutable evidence for management actions.' }; return descriptions[surface] ?? `Current ${surface.toLowerCase()} records from the controller.`; }
  function resourceTitle(surface: string): string { return surface === 'Plugins / mods' ? 'Plugins / mods' : surface; }

  async function beginChangeSession(serviceId: string, clusterId: string) {
    if (!sessionReady || !csrfToken) { actionMessage = 'Action disabled: authenticated CSRF session is unavailable.'; return; }
    actionBusy = true; actionMessage = '';
    const headers = new Headers({ 'Idempotency-Key': crypto.randomUUID(), 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken });
    const result = await api<JsonObject>('/change-sessions', { method: 'POST', headers, body: JSON.stringify({ service_id: serviceId, cluster_id: clusterId }) });
    if (result.error) actionMessage = `${result.error.message}${result.error.requestId ? ` · request ${result.error.requestId}` : ''}`;
    else if (!result.data?.id) actionMessage = 'Controller returned no Change Session result.';
    else { actionMessage = `Change Session ${String(result.data.id)} is ready.`; await loadActive(); }
    actionBusy = false;
  }

  async function performChangeAction(id: string, command: string, input: JsonObject): Promise<JsonObject | undefined> {
    if (!sessionReady || !csrfToken) { actionMessage = 'Action disabled: authenticated CSRF session is unavailable.'; return undefined; }
    const payload = changeMutationPayload(command, input);
    const requestHash = await sha256Json(payload);
    const observed = Array.isArray(input.observed_state_hashes) && input.observed_state_hashes.length
      ? String(input.observed_state_hashes[0])
      : requestHash;
    // If-Match is the persisted Change Session version token. The payload
    // hash remains a separate header used to bind the typed request body.
    const session = resources.find((resource) => String(resource.id) === id) ?? {};
    const sessionVersion = String(resourceValue(session, 'version', 'etag', 'updated_version') ?? '');
    const ifMatch = command === 'plan'
      ? (sessionVersion ? strongSessionVersionTag(sessionVersion) : observed)
      : String(input.plan_hash || observed);
    const headers = mutationHeaders(requestHash, ifMatch, crypto.randomUUID(), csrfToken);
    headers.set('Content-Type', 'application/json');
    actionBusy = true; actionMessage = '';
    const result = await api<JsonObject>(`/change-sessions/${encodeURIComponent(id)}/${command}`, { method: 'POST', headers, body: JSON.stringify({ command, action: 'change', request_hash: requestHash, expires_at: Math.floor(Date.now() / 1000) + 1800, target_revision: null, payload }) });
    if (result.error) {
      const stale = result.error.status === 409 || result.error.status === 412;
      actionMessage = `${stale ? 'The persisted Change Session or plan is stale; refresh observations before retrying.' : result.error.message}${result.error.requestId ? ` · request ${result.error.requestId}` : ''}`;
    }
    else if (!result.data || (command === 'plan' || command === 'approve' ? !result.data.plan_id || !result.data.plan_hash : !result.data.id)) actionMessage = 'Controller returned no mutation result.';
    else {
      const message = command === 'plan' ? `Plan ${String(result.data.plan_id)} is ready for approval.` : command === 'approve' ? `Plan ${String(result.data.plan_id)} is approved.` : `Operation ${String(result.data.id)} is now ${String(result.data.status ?? 'returned')}.`;
      await loadActive();
      actionMessage = message;
    }
    actionBusy = false;
    return result.data;
  }


  async function stageContent(sessionId: string, bytes: number[], classification = 'mutable_config') {
    if (!sessionReady || !csrfToken) { actionMessage = 'Staging disabled: authenticated CSRF session is unavailable.'; return undefined; }
    const selected = resources.find((resource) => String(resource.id) === sessionId) ?? {};
    const version = String(resourceValue(selected, 'version', 'etag', 'updated_version') ?? '');
    const result = await stageSessionContent(sessionId, bytes, csrfToken, version, classification);
    if (result.error) { actionMessage = `${result.error.message}${result.error.requestId ? ` · request ${result.error.requestId}` : ''}`; return undefined; }
    return result.data;
  }
  function recordStagedFile(file: StagedFile) {
    stagedFiles = [...stagedFiles.filter((item) => !(item.sessionId === file.sessionId && item.path === file.path)), file];
  }
  function unitChange(id: string) { selectedUnitId = id; }
  onMount(async () => { await initializeSession(); if (active === 'Dashboard') void loadDashboard(); else { void observeHealth(); void loadActive(); } });
</script>

<svelte:head><title>Kitsunebi · MCPlayNetwork</title><meta name="description" content="MCPlayNetwork service operations" /></svelte:head>
<a class="skip" href="#main">Skip to content</a>
<div class="shell">
  <aside class:open={menuOpen} class="sidebar" aria-label="Primary navigation">
    <div class="brand"><span class="mark">K</span><div><strong>Kitsunebi</strong><small>MCPlayNetwork</small></div><button class="close" aria-label="Close navigation" onclick={() => menuOpen = false}>×</button></div>
    <nav>{#each nav as section}<div class="nav-group"><h2>{section.group}</h2>{#each section.items as item}<button class:current={active === item} aria-current={active === item ? 'page' : undefined} onclick={() => selectSurface(item)}>{item === 'Dashboard' ? '▦' : item === 'Services' ? '◌' : item === 'Clusters' ? '⌘' : item === 'Console' ? '›_' : item === 'Audit' ? '≡' : '·'}<span>{item}</span>{#if unsupportedReasons[item]}<em>Unavailable</em>{/if}</button>{/each}</div>{/each}</nav>
    <div class="side-foot"><span class="status-dot {controllerState === 'offline' ? 'bad' : controllerState === 'unknown' ? 'neutral' : 'good'}"></span><span>Controller {controllerState}</span><small>GameAP capabilities · {capabilityState}</small></div>
  </aside>
  <main id="main" class="main">
    <header class="topbar"><button class="menu" aria-label="Open navigation" onclick={() => menuOpen = true}>☰</button><div class="crumb"><span>MCPlayNetwork</span><b>/</b><strong>{active}</strong></div><div class="top-actions"><span class="operator"><i></i> Access session</span><button class="icon-btn" aria-label="Notifications">◔</button><button class="avatar" aria-label="Account menu">AS</button></div></header>
    <div class="content">
      {#if sessionError}<StateMessage kind="error" title="Authenticated session unavailable" detail={sessionError} />{/if}
      {#if active === 'Dashboard'}
        <div class="page-heading"><div><p class="eyebrow">Operational overview</p><h1>Service topology</h1><p class="lede">Current state across services, runtimes, and change work.</p></div><button class="quiet" onclick={loadDashboard} disabled={dashboardLoading}>{dashboardLoading ? 'Observing…' : 'Refresh state ↻'}</button></div>
        {#if dashboardLoading}<StateMessage kind="loading" title="Observing controller state…" detail="Reading independent service, proxy, change, and health endpoints." />{:else if Object.keys(dashboardErrors).length === 4}<StateMessage kind="offline" title="Controller unavailable" detail="No local records are substituted; mutations remain disabled." />{:else if dashboardServices.length === 0 && !dashboardErrors.services}<StateMessage kind="empty" title="No services returned" detail="The controller has no service records for this scope." />{/if}
        <div class="dashboard-grid">
          <ResourceList title="Services" description="Intent and observed runtime state" endpoint="/api/v1/services" resources={dashboardServices} loading={dashboardLoading} error={dashboardErrors.services ?? ''} unsupported={dashboardErrors.services ? /unsupported|capability/i.test(dashboardErrors.services) : false} onSelect={(id) => { selectedServiceId = id; active = 'Service detail'; void loadActive(); }} />
          <aside class="rail"><section class="rail-block"><div class="rail-title"><h2>Proxy pools</h2><button class="text-link" onclick={() => selectSurface('Proxy pools')}>Manage →</button></div>{#if dashboardErrors.proxies}<StateMessage kind="error" title="Proxy state unavailable" detail={dashboardErrors.proxies} />{:else if dashboardProxies.length === 0}<p class="rail-empty">No proxy pool observations.</p>{:else}{#each dashboardProxies as proxy}<div class="proxy"><span class="status-text {stateTone(resourceValue(proxy, 'state', 'status'))}">{String(resourceValue(proxy, 'state', 'status') ?? 'Unknown')}</span><div><strong>{resourceLabel(proxy)}</strong><small>{String(resourceValue(proxy, 'version', 'runtime') ?? 'Version unknown')}</small></div></div>{/each}{/if}</section><section class="rail-block problems"><h2>Problems</h2>{#if dashboardServices.some((service) => driftState(service) === 'drift')}<p class="problem">Observed drift requires review before a Change Session is applied.</p>{:else if dashboardErrors.services || dashboardServices.some((service) => driftState(service) === 'unknown')}<p class="rail-empty">Drift state is unknown until the controller reports desired and observed values.</p>{:else}<p class="clear"><span>✓</span> No current service-impacting signals</p>{/if}</section><section class="rail-block"><div class="rail-title"><h2>Active changes</h2><button class="text-link" onclick={() => selectSurface('Change sessions')}>All →</button></div>{#if dashboardErrors.changes}<StateMessage kind="error" title="Changes unavailable" detail={dashboardErrors.changes} />{:else if dashboardChanges.length === 0}<p class="rail-empty">No active changes.</p>{:else}{#each dashboardChanges as change}<div class="change"><span class="change-id">{String(change.id)}</span><div><strong>{resourceLabel(change)}</strong><small>{String(resourceValue(change, 'state', 'status') ?? 'Unknown')} · {String(resourceValue(change, 'updated_at', 'age') ?? '—')}</small></div></div>{/each}{/if}</section></aside>
        </div>
        <section class="decision"><div class="decision-icon">↗</div><div><h2>Plan a change</h2><p>Review a proposed update in a Change Session before anything is applied. A snapshot and rollback path are created first.</p></div><button class="primary" onclick={() => selectSurface('Change sessions')}>Start Change Session <span>→</span></button></section>
      {:else if unsupportedReasons[active]}
        <div class="page-heading"><div><p class="eyebrow">Capability boundary</p><h1>{active}</h1><p class="lede">This control stays visible so an operator can distinguish unavailable API capability from an empty result.</p></div></div><StateMessage kind="info" title="Disabled by API capability" detail={unsupportedReasons[active]} />
      {:else if active === 'Change sessions'}
        <div class="page-heading"><div><p class="eyebrow">Operate</p><h1>Change sessions</h1><p class="lede">Explicit, reviewable changes with snapshot, plan, verify, accept, or rollback.</p></div><button class="quiet" onclick={loadActive} disabled={loading}>{loading ? 'Loading…' : 'Refresh state ↻'}</button></div>
        {#if actionMessage}<StateMessage kind={actionMessage.startsWith('Operation') || actionMessage.startsWith('Plan') || actionMessage.startsWith('Change Session') ? 'success' : 'error'} title={actionMessage.startsWith('Operation') || actionMessage.startsWith('Plan') || actionMessage.startsWith('Change Session') ? 'Change state updated' : 'Action not applied'} detail={actionMessage} />{/if}<ChangePanel resources={resources} services={changeServices} clusters={changeClusters} bindings={changeBindings} stagedFiles={stagedFiles} selectedId={selectedChangeId} loading={loading} error={error} unsupported={activeUnsupported} csrfAvailable={Boolean(sessionReady && csrfToken)} busy={actionBusy} onSelect={(id) => selectedChangeId = id} onBegin={beginChangeSession} onAction={performChangeAction} onStageContent={(bytes, classification) => stageContent(selectedChangeId, bytes, classification)} />
      {:else if active === 'Lifecycle / decisions'}
        <div class="page-heading"><div><p class="eyebrow">Govern</p><h1>Lifecycle / decisions</h1><p class="lede">Review the current service lifecycle. Transitions are composed as typed steps in a Change Session.</p></div><button class="quiet" onclick={loadActive} disabled={loading}>{loading ? 'Loading…' : 'Refresh services ↻'}</button></div>
        <StateMessage kind="info" title="Lifecycle changes use Change Sessions" detail="Open Change sessions to prepare, approve, apply, verify, and accept or roll back a lifecycle transition." />
        <ResourceList title="Services" description="Current lifecycle state; no direct transition is available here." endpoint="/api/v1/services" resources={resources} loading={loading} error={error} unsupported={activeUnsupported} onSelect={selectResource} />
      {:else if active === 'Operations'}
        <div class="page-heading"><div><p class="eyebrow">Operate</p><h1>Operations</h1><p class="lede">Observe operation progress from the authenticated SSE stream.</p></div><button class="quiet" onclick={loadActive} disabled={loading}>{loading ? 'Loading…' : 'Refresh state ↻'}</button></div><OperationsPanel resources={resources} loading={loading} error={error} unsupported={activeUnsupported} />
      {:else if active === 'Execution units'}
        <div class="page-heading"><div><p class="eyebrow">Observe</p><h1>Execution units</h1><p class="lede">Inspect persisted GameAP bindings and observed runtime capabilities. Lifecycle changes are planned from a Change Session.</p></div><button class="quiet" onclick={loadActive} disabled={loading}>{loading ? 'Loading…' : 'Refresh units ↻'}</button></div><ResourceList title="Execution Units" description="Persisted bindings returned for this access scope." endpoint="/api/v1/execution-units" resources={resources} loading={loading} error={error} unsupported={activeUnsupported} onSelect={unitChange} />
      {:else if active === 'Console'}
        <div class="page-heading"><div><p class="eyebrow">Operate</p><h1>Console</h1><p class="lede">Kitsunebi-brokered WebSocket console for a selected Execution Unit.</p></div><button class="quiet" onclick={loadActive} disabled={loading}>{loading ? 'Loading…' : 'Refresh units ↻'}</button></div><ResourceList title="Execution Units" description="Choose the backend binding before connecting to Console." endpoint="/api/v1/execution-units" resources={resources} loading={loading} error={error} unsupported={activeUnsupported} onSelect={unitChange} /><ConsolePanel selectedUnitId={selectedUnitId} csrfToken={csrfToken} onUnitChange={unitChange} unsupported={activeUnsupported} />
      {:else if active === 'Files' || active === 'File diff'}
        <div class="page-heading"><div><p class="eyebrow">Observe</p><h1>{active === 'Files' ? 'Files' : 'File diff'}</h1><p class="lede">Browse, read, diff, and download through the brokered file API. Changes are staged in Change Sessions.</p></div><button class="quiet" onclick={loadActive} disabled={loading}>{loading ? 'Loading…' : 'Refresh units ↻'}</button></div><ResourceList title="Execution Units" description="Select the binding whose files you want to inspect." endpoint="/api/v1/execution-units" resources={resources} loading={loading} error={error} unsupported={activeUnsupported} onSelect={unitChange} /><FilesPanel initialUnitId={selectedUnitId} sessionId={selectedChangeId} onUnitChange={unitChange} unsupported={activeUnsupported} csrfAvailable={Boolean(sessionReady && csrfToken)} onStageContent={(bytes, classification) => stageContent(selectedChangeId, bytes, classification)} onStagedFile={recordStagedFile} />
      {:else if active === 'Service detail'}
        <div class="page-heading"><div><p class="eyebrow">Observe</p><h1>Service detail</h1><p class="lede">Inspect one Service's desired and observed state before planning a mutation.</p></div><button class="quiet" onclick={loadActive} disabled={loading}>{loading ? 'Loading…' : 'Refresh state ↻'}</button></div>{#if selectedServiceId}<ResourceDetail title="Service detail" endpoint={`/api/v1${endpointFor(active)}`} resource={detailResource} loading={loading} error={error} unsupported={activeUnsupported} onBack={backToServices} />{:else}<ResourceList title="Services" description="Select a Service to open its current detail." endpoint="/api/v1/services" resources={resources} loading={loading} error={error} unsupported={activeUnsupported} onSelect={selectResource} />{/if}
      {:else}
        <div class="page-heading"><div><p class="eyebrow">{nav.find((section) => section.items.includes(active))?.group}</p><h1>{resourceTitle(active)}</h1><p class="lede">{surfaceDescription(active)}</p></div><button class="quiet" onclick={loadActive} disabled={loading}>{loading ? 'Loading…' : 'Refresh state ↻'}</button></div>{#if active === 'Backups / restore' && backupMutationState.toLowerCase() === 'disabled'}<StateMessage kind="info" title="Restore actions disabled by controller" detail="This screen remains read-only until the controller reports the verified backup capability." />{/if}<ResourceList title={resourceTitle(active)} description={surfaceDescription(active)} endpoint={`/api/v1${endpointFor(active)}`} resources={resources} loading={loading} error={error} unsupported={activeUnsupported} onSelect={selectResource} />{#if selectedResourceId}<ResourceDetail title="Selected record" endpoint={`/api/v1${endpointFor(active)}`} resource={selectedResource()} loading={false} error="" onBack={() => selectedResourceId = ''} />{/if}
      {/if}
    </div>
    <footer><span>{lastObserved ? `Last state observation ${lastObserved} JST` : 'No state observation yet'}</span><span>API /api/v1 · same-origin session</span></footer>
  </main>
</div>
