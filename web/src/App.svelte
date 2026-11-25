<script lang="ts">
  import { onMount } from 'svelte';
  import Menu from '@lucide/svelte/icons/menu';
  import PanelLeft from '@lucide/svelte/icons/panel-left';
  import RefreshCw from '@lucide/svelte/icons/refresh-cw';
  import Navigation from './lib/components/Navigation.svelte';
  import ServiceOverview from './lib/components/ServiceOverview.svelte';
  import { api, changeMutationPayload, collection, mutationHeaders, publicApi, resourceLabel, resourceValue, session, sha256Json, stageSessionContent, strongSessionVersionTag } from './lib/api';
  import { isUnsupportedError, stateTone } from './lib/state';
  import type { ApiResult, JsonObject } from './lib/types';
  import type { StagedFile } from './lib/changePlan';
  import StateMessage from './lib/components/StateMessage.svelte';
  import ResourceList from './lib/components/ResourceList.svelte';
  import ResourceDetail from './lib/components/ResourceDetail.svelte';
  import LifecyclePanel from './lib/components/LifecyclePanel.svelte';
  import ChangePanel from './lib/components/ChangePanel.svelte';
  import OperationsPanel from './lib/components/OperationsPanel.svelte';
  import ConsolePanel from './lib/components/ConsolePanel.svelte';
  import FilesPanel from './lib/components/FilesPanel.svelte';
  import { servicePath, surfacePath, type Surface } from './lib/navigation';

  export let initialActive: Surface = 'Dashboard';

  export let serviceId = '';
  let mounted = false;
  let drawer: HTMLDialogElement;
  let unitBusy = false;
  const endpoints: Record<string, string> = {
    Dashboard: '/services', Services: '/services', 'Service detail': '/services', Clusters: '/clusters', 'Cluster revisions': '/cluster-revisions', 'Execution units': '/execution-units', Worlds: '/worlds', 'Proxy pools': '/proxy-pools', 'Proxy instances': '/proxy-instances', 'External endpoints': '/endpoints', Console: '/execution-units', Files: '/execution-units', 'File diff': '/execution-units', Artifacts: '/artifacts', 'Plugins / mods': '/artifacts?kind=plugin', 'Change sessions': '/change-sessions', Operations: '/operations', 'Backups / restore': '/backups', 'Access policies': '/access-policies', 'Lifecycle / decisions': '/services', Audit: '/audit-events'
  };
  let active: Surface = initialActive;
  let loading = true;
  let error = '';
  let activeUnsupported = false;
  let csrfToken = '';
  let sessionReady = false;
  let sessionError = '';
  let resources: JsonObject[] = [];
  let selectedResourceId = '';
  let selectedServiceId = '';
  let selectedUnitId = '';
  let selectedChangeId = '';
  let changeServices: JsonObject[] = [];
  let changeClusters: JsonObject[] = [];
  let changeBindings: JsonObject[] = [];
  let stagedFiles: StagedFile[] = [];
  let detailResource: JsonObject | undefined;
  let actionBusy = false;
  let actionMessage = '';
  let integrationStatus: Record<string, string> = {};
  let controllerState = 'unknown';
  let requestController: AbortController | null = null;
  let healthRequest: AbortController | undefined;

  function endpointFor(surface: string): string {
    if (surface === 'Service detail' && selectedServiceId) return `/services/${encodeURIComponent(selectedServiceId)}`;
    return endpoints[surface] ?? '';
  }
  function errorText(result: ApiResult<unknown>): string {
    if (!result.error) return '';
    return `${result.error.message}${result.error.requestId ? ` · request ${result.error.requestId}` : ''}`;
  }
  function isAbort(cause: unknown): boolean { return cause instanceof Error && cause.name === 'AbortError'; }

  async function observeIntegrations(signal: AbortSignal) {
    const result = await api<JsonObject>('/health/providers', { signal });
    if (signal.aborted) return;
    integrationStatus = Object.fromEntries(['backup', 'monitoring'].map((name) => [
      name, result.error ? 'unavailable' : String((result.data?.[name] as JsonObject | undefined)?.status ?? 'unknown')
    ]));
  }

  async function observeHealth() {
    healthRequest?.abort();
    const controller = new AbortController();
    healthRequest = controller;
    try {
      const result = await publicApi<JsonObject>('/health', { signal: controller.signal });
      if (controller.signal.aborted) return;
      controllerState = result.error
        ? (result.error.status === 0 ? 'unreachable' : 'unknown')
        : String(resourceValue(result.data ?? {}, 'status', 'state') ?? 'unknown');
    } catch (cause) {
      if (!isAbort(cause)) throw cause;
    }
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
    void observeHealth();
    requestController?.abort();
    const controller = new AbortController();
    requestController = controller;
    loading = true;
    activeUnsupported = false;
    error = '';
    resources = [];
    detailResource = undefined;
    actionMessage = '';
    integrationStatus = {};
    try {
      if (['Backups / restore', 'Proxy pools', 'Proxy instances'].includes(active)) {
        void observeIntegrations(controller.signal).catch((cause) => { if (!isAbort(cause)) throw cause; });
      }
      if (active === 'Change sessions') {
        const [sessions, services, clusters, bindings] = await Promise.all([api<unknown>('/change-sessions', { signal: controller.signal }), api<unknown>('/services', { signal: controller.signal }), api<unknown>('/clusters', { signal: controller.signal }), api<unknown>('/execution-units', { signal: controller.signal })]);
        if (controller.signal.aborted) return;
        if (sessions.error) { error = errorText(sessions); activeUnsupported = isUnsupportedError(sessions.error); } else resources = collection<JsonObject>(sessions.data);
        changeServices = services.error ? [] : collection<JsonObject>(services.data);
        changeClusters = clusters.error ? [] : collection<JsonObject>(clusters.data);
        changeBindings = bindings.error ? [] : collection<JsonObject>(bindings.data);
        if (!sessions.error && !resources.some((item) => String(item.id) === selectedChangeId)) {
          selectedChangeId = String(resources[0]?.id ?? '');
        }
      } else {
        const result = await api<unknown>(endpointFor(active), { signal: controller.signal });
        if (controller.signal.aborted) return;
        if (result.error) {
          error = errorText(result);
          activeUnsupported = isUnsupportedError(result.error);
        } else if (active === 'Service detail' && selectedServiceId) {
          detailResource = result.data as JsonObject;
        } else {
          const items = collection<JsonObject>(result.data);
          resources = active === 'Execution units' && selectedServiceId
            ? items.filter((item) => item.service_id === selectedServiceId)
            : items;
          if (['Execution units', 'Console', 'Files', 'File diff'].includes(active) &&
              !resources.some((item) => String(item.id) === selectedUnitId)) {
            selectedUnitId = String(resources[0]?.id ?? '');
          }
        }
      }
    } catch (cause) { if (!isAbort(cause)) error = 'Controller is unreachable'; }
    finally { if (requestController === controller) { loading = false; } }
  }

  function openSurface(next: Surface, id: string) {
    requestController?.abort();
    drawer?.close();
    active = next;
    selectedServiceId = next === 'Service detail' || next === 'Execution units' ? id : '';
    selectedResourceId = '';
    actionMessage = '';
    error = '';
    unitBusy = false;
    if (next !== 'Dashboard' && next !== 'Services') {
      void loadActive();
    }
  }
  $: if (mounted) openSurface(initialActive, serviceId);
  $: selectedRecord = resources.find((item) => String(item.id) === selectedResourceId);

  async function beginChangeSession(serviceId: string, clusterId: string) {
    if (!sessionReady || !csrfToken) { actionMessage = 'Action disabled: authenticated CSRF session is unavailable.'; return; }
    actionBusy = true; actionMessage = '';
    const headers = new Headers({ 'Idempotency-Key': crypto.randomUUID(), 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken });
    const result = await api<JsonObject>('/change-sessions', { method: 'POST', headers, body: JSON.stringify({ service_id: serviceId, cluster_id: clusterId }) });
    if (result.error) actionMessage = `${result.error.message}${result.error.requestId ? ` · request ${result.error.requestId}` : ''}`;
    else if (!result.data?.id) actionMessage = 'Controller returned no Change Session result.';
    else { selectedChangeId = String(result.data.id); await loadActive(); actionMessage = `Change Session ${selectedChangeId} is ready.`; }
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
  onMount(() => {
    mounted = true;
    void initializeSession();
    const desktop = window.matchMedia('(min-width: 52.01rem)');
    const closeDrawer = () => { if (desktop.matches) drawer.close(); };
    desktop.addEventListener('change', closeDrawer);
    return () => {
      requestController?.abort();
      healthRequest?.abort();
      desktop.removeEventListener('change', closeDrawer);
    };
  });
</script>

<svelte:head><title>{active} · Kitsunebi</title><meta name="description" content="MCPlayNetwork service operations" /></svelte:head>
<a class="skip" href="#main">Skip to content</a>
<div class="shell">
  <aside class="sidebar"><Navigation {active} /></aside>
  <dialog class="drawer" aria-label="Workspace navigation" bind:this={drawer}>
    <Navigation {active} onClose={() => drawer.close()} />
  </dialog>
  <main id="main" class="main" tabindex="-1">
    <header class="topbar">
      <button class="menu icon-control" aria-label="Open navigation" aria-haspopup="dialog" onclick={() => drawer.showModal()}><Menu size={20} /></button>
      <div class="crumb"><PanelLeft size={16} /><span>MCPlayNetwork</span><b>/</b><strong>{active}</strong></div>
      <div class="controller-status"><i class="status-dot {controllerState === 'unreachable' ? 'bad' : stateTone(controllerState)}"></i>Controller <strong>{controllerState}</strong></div>
    </header>
    <div class="content">
      {#if sessionError}<StateMessage kind="error" title="Authenticated session unavailable" detail={sessionError} />{/if}
      {#if active === 'Dashboard' || active === 'Services'}
        {#key active}<ServiceOverview overview={active === 'Dashboard'} onRefreshHealth={observeHealth} />{/key}
      {:else}
        <div class="page-heading">
          <h1>{active === 'Service detail' && detailResource ? resourceLabel(detailResource) : active}</h1>
          <button class="quiet" onclick={loadActive} disabled={loading || unitBusy}><RefreshCw size={15} />{loading ? 'Refreshing…' : 'Refresh'}</button>
        </div>
        {#if active === 'Backups / restore' && integrationStatus.backup === 'not_configured'}
          <StateMessage title="Backup provider not configured" detail="Backup creation and restore are unavailable." />
        {:else if ['Proxy pools', 'Proxy instances'].includes(active) && integrationStatus.monitoring === 'not_configured'}
          <StateMessage title="Connection monitoring not configured" detail="Proxy rollout requires connection-drain evidence." />
        {:else if integrationStatus.backup === 'unavailable' && active === 'Backups / restore'}
          <StateMessage title="Backup provider status unavailable" />
        {:else if integrationStatus.monitoring === 'unavailable' && ['Proxy pools', 'Proxy instances'].includes(active)}
          <StateMessage title="Connection monitoring status unavailable" />
        {/if}
        {#if active === 'Change sessions'}
          {#if actionMessage}<StateMessage kind={/^(Operation|Plan|Change Session)/.test(actionMessage) ? 'success' : 'error'} title={actionMessage} />{/if}
          <ChangePanel {csrfToken} {resources} services={changeServices} clusters={changeClusters} bindings={changeBindings} {stagedFiles}
            selectedId={selectedChangeId} {loading} {error} unsupported={activeUnsupported} csrfAvailable={Boolean(sessionReady && csrfToken)}
            busy={actionBusy} onSelect={(id) => selectedChangeId = id} onBegin={beginChangeSession} onAction={performChangeAction}
            onStageContent={(bytes, classification) => stageContent(selectedChangeId, bytes, classification)} />
        {:else if active === 'Operations'}
          <OperationsPanel {resources} {loading} {error} unsupported={activeUnsupported} />
        {:else if active === 'Service detail' && selectedServiceId}
          {#if detailResource}
            <div class="detail-actions"><a class="quiet" href={`${surfacePath('Execution units')}?service=${encodeURIComponent(selectedServiceId)}`}>View execution units →</a></div>
          {/if}
          <ResourceDetail title="Service configuration" resource={detailResource} {loading} {error} unsupported={activeUnsupported} backHref={surfacePath('Services')} />
        {:else if active === 'Files' || active === 'File diff' || active === 'Console'}
          {#if loading}<p class="section-state">Loading execution units…</p>
          {:else if error}<StateMessage kind="error" title="Execution units unavailable" detail={error} />
          {:else if !resources.length}<p class="section-state">No execution units in your access scope.</p>
          {:else if active === 'Console'}
            {#key selectedUnitId}<ConsolePanel units={resources} {selectedUnitId} {csrfToken} onUnitChange={(id) => selectedUnitId = id} />{/key}
          {:else}
            {#key selectedUnitId}<FilesPanel units={resources} initialUnitId={selectedUnitId} sessionId={selectedChangeId}
              onUnitChange={(id) => selectedUnitId = id} csrfAvailable={Boolean(sessionReady && csrfToken)}
              onStageContent={(bytes, classification) => stageContent(selectedChangeId, bytes, classification)} onStagedFile={recordStagedFile} />{/key}
          {/if}
        {:else if active === 'Execution units'}
          {#if selectedServiceId}<a class="back-link" href={servicePath(selectedServiceId)}>← Back to service</a>{/if}
          <ResourceList title={selectedServiceId ? 'Targets for this service' : 'Available targets'} {resources} {loading} {error} unsupported={activeUnsupported}
            selectedId={selectedUnitId} disabled={unitBusy} onSelect={(id) => selectedUnitId = id} />
          {#if !loading && !error && resources.length}
            {#key selectedUnitId}<LifecyclePanel units={resources} bind:unit={selectedUnitId} bind:busy={unitBusy} {csrfToken} />{/key}
          {/if}
        {:else}
          {#if active === 'Lifecycle / decisions'}<a class="rail-link" href={surfacePath('Change sessions')}>Plan a lifecycle transition →</a>{/if}
          <ResourceList title={active === 'Service detail' || active === 'Lifecycle / decisions' ? 'Services' : active}
            {resources} {loading} {error} unsupported={activeUnsupported} selectedId={selectedResourceId}
            linkServices={active === 'Service detail' || active === 'Lifecycle / decisions'} onSelect={(id) => selectedResourceId = id} />
          {#if selectedRecord}<ResourceDetail title="Selected record" resource={selectedRecord} onBack={() => selectedResourceId = ''} />{/if}
        {/if}
      {/if}
    </div>
  </main>
</div>
