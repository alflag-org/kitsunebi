<script lang="ts">
  import { onMount } from 'svelte';
  import ArrowRight from '@lucide/svelte/icons/arrow-right';
  import Check from '@lucide/svelte/icons/check';
  import ClipboardList from '@lucide/svelte/icons/clipboard-list';
  import GitBranch from '@lucide/svelte/icons/git-branch';
  import Layers from '@lucide/svelte/icons/layers';
  import Network from '@lucide/svelte/icons/network';
  import Plus from '@lucide/svelte/icons/plus';
  import RefreshCw from '@lucide/svelte/icons/refresh-cw';
  import Search from '@lucide/svelte/icons/search';
  import { api, collection, resourceLabel, resourceValue } from '../api';
  import { servicePath, surfacePath } from '../navigation';
  import { driftState } from '../state';
  import type { ApiResult, JsonObject } from '../types';
  import StateMessage from './StateMessage.svelte';

  export let overview = true;
  export let onRefreshHealth: () => void;

  type List = { items: JsonObject[]; error?: string };
  let services: List | undefined;
  let clusters: List | undefined;
  let sessions: List | undefined;
  let pools: List | undefined;
  let request: AbortController | undefined;
  let busy = true;
  let observed = '';
  let query = '';
  let filter = '';
  const phases = ['Active', 'Testing', 'Planned', 'Maintenance', 'Sunsetting', 'Archived'];
  const activeStates = new Set(['open', 'editing', 'ready', 'applying', 'verifying']);

  function list(result: ApiResult<unknown>): List {
    const error = result.error;
    return error
      ? { items: [], error: error.message + (error.requestId ? ` · request ${error.requestId}` : '') }
      : { items: collection(result.data) };
  }

  async function refresh() {
    request?.abort();
    const controller = new AbortController();
    request = controller;
    busy = true;
    observed = '';
    services = clusters = sessions = pools = undefined;
    onRefreshHealth();
    async function read(path: string, receive: (value: List) => void) {
      const result = await api<unknown>(path, { signal: controller.signal });
      if (!controller.signal.aborted) receive(list(result));
    }
    try {
      await Promise.all([
        read('/services', (value) => services = value),
        read('/clusters', (value) => clusters = value),
        ...(overview ? [
          read('/change-sessions', (value) => sessions = value),
          read('/proxy-pools', (value) => pools = value)
        ] : [])
      ]);
      if (!controller.signal.aborted) observed = new Intl.DateTimeFormat(undefined, {
        hour: '2-digit', minute: '2-digit', timeZoneName: 'short'
      }).format(new Date());
    } catch (cause) {
      if (!controller.signal.aborted) throw cause;
    } finally {
      if (!controller.signal.aborted) busy = false;
    }
  }
  onMount(() => { void refresh(); return () => request?.abort(); });

  function phase(item: JsonObject): string {
    const raw = String(resourceValue(item, 'lifecycle', 'state') ?? 'Unknown');
    return phases.find((value) => value.toLowerCase() === raw.toLowerCase()) ?? raw;
  }
  function tone(value: string) {
    return phases.includes(value) ? value.toLowerCase() : 'unknown';
  }
  function groupPhases(items: JsonObject[]) {
    const counts = new Map<string, number>();
    for (const item of items) counts.set(phase(item), (counts.get(phase(item)) ?? 0) + 1);
    return [...new Set([...phases, ...counts.keys()])].filter((name) => counts.has(name))
      .map((name) => ({ name, count: counts.get(name)! }));
  }
  $: all = services?.items ?? [];
  $: groups = groupPhases(all);
  $: clusterNames = new Map(clusters?.items.map((item) => [String(item.id), resourceLabel(item)]));
  $: term = query.trim().toLowerCase();
  $: matches = all.filter((item) => (!filter || phase(item) === filter) &&
    [resourceLabel(item), item.key, clusterNames.get(String(item.current_cluster))].some((value) => String(value ?? '').toLowerCase().includes(term)));
  $: openSessions = (sessions?.items ?? []).filter((item) => activeStates.has(String(item.state ?? '').toLowerCase()));
</script>

<div class="page-heading overview-heading">
  <div><h1>{overview ? 'Service overview' : 'Services'}</h1><p class="lede">{overview ? 'Service lifecycle, cluster assignments and changes in progress.' : 'Find a service and inspect its current configuration.'}</p></div>
  <div class="heading-actions">
    <button class="quiet" onclick={refresh} disabled={busy}><RefreshCw size={15} />{busy ? 'Refreshing…' : 'Refresh'}</button>
    {#if overview}<a class="primary" href={surfacePath('Change sessions')}><Plus size={16} />Plan a change</a>{/if}
  </div>
</div>

<div class="overview-layout" class:directory-only={!overview}>
  <section class="directory panel" aria-labelledby="directory-title">
    <div class="directory-intro">
      <div class="section-title"><Layers size={19} /><h2 id="directory-title">Service directory</h2></div>
      {#if services && !services.error}<span class="number-note">{all.length} {all.length === 1 ? 'service' : 'services'}</span>{/if}
    </div>
    {#if !services}<p class="section-state" role="status">Loading services…</p>
    {:else if services.error}<StateMessage kind="error" title="Services unavailable" detail={services.error} />
    {:else if !all.length}<p class="section-state">No services in your access scope.</p>
    {:else}
      <div class="lifecycle-strip">
        <h3>Service lifecycle</h3>
        <div class="phase-track" aria-hidden="true">
          {#each groups as group}<span class={'phase-' + tone(group.name)} style:flex-grow={group.count}></span>{/each}
        </div>
        <div class="phase-filters" aria-label="Filter by lifecycle" role="group">
          {#each groups as group}
            <button aria-pressed={filter === group.name} onclick={() => filter = filter === group.name ? '' : group.name}>
              <i class={'phase-dot phase-' + tone(group.name)}></i>{group.name}<b>{group.count}</b>
            </button>
          {/each}
        </div>
      </div>
      <div class="directory-tools">
        <label class="search-box"><Search size={16} /><span class="sr-only">Search services</span><input type="search" placeholder="Search services or clusters" bind:value={query} /></label>
        {#if term || filter}<button class="text-link" onclick={() => { query = ''; filter = ''; }}>Clear filters</button>{/if}
      </div>
      {#if clusters?.error}<StateMessage kind="error" title="Cluster names unavailable" detail={clusters.error} />{/if}
      {#if matches.length}
        <table class="services-table">
          <thead><tr><th scope="col">Service</th><th scope="col">Current cluster</th><th scope="col">Lifecycle</th></tr></thead>
          <tbody>{#each matches as item}
            <tr>
              <td><a class="service-link" href={servicePath(String(item.id))}><strong>{resourceLabel(item)}</strong>{#if item.key && item.key !== resourceLabel(item)}<small>{item.key}</small>{/if}</a>
                {#if driftState(item) === 'drift'}<small class="drift-label">Drift detected</small>{/if}
              </td>
              <td><span class="cluster-ref">{item.current_cluster ? (clusterNames.get(String(item.current_cluster)) ?? (clusters ? 'Name unavailable' : 'Loading…')) : item.current_cluster === null ? 'Unassigned' : 'Unknown'}</span></td>
              <td><span class="phase-badge"><i class={'phase-dot phase-' + tone(phase(item))}></i>{phase(item)}</span></td>
            </tr>
          {/each}</tbody>
        </table>
      {:else}<p class="section-state" role="status">No services match these filters.</p>{/if}
    {/if}
    {#if services && !services.error && all.length}<div class="directory-foot"><span>{matches.length} of {all.length} shown</span>{#if observed}<span>Checked {observed}</span>{/if}</div>{/if}
  </section>

  {#if overview}
    <aside class="overview-rail" aria-label="Related operations">
      <section class="rail-section">
        <div class="section-title"><ClipboardList size={18} /><h2>Active changes</h2></div>
        {#if !sessions}<p class="rail-note">Loading changes…</p>
        {:else if sessions.error}<StateMessage kind="error" title="Changes unavailable" detail={sessions.error} />
        {:else if !openSessions.length}<p class="rail-note"><Check size={15} />No active change sessions.</p>
        {:else}<ul>{#each openSessions as item}<li><GitBranch size={16} /><div><strong>{clusterNames.get(String(item.target_cluster ?? item.cluster_id)) ?? resourceLabel(item)}</strong><small>{item.state}</small></div></li>{/each}</ul>{/if}
        <a class="rail-link" href={surfacePath('Change sessions')}>Change sessions <ArrowRight size={15} /></a>
      </section>
      <section class="rail-section">
        <div class="section-title"><Network size={18} /><h2>Proxy pools</h2></div>
        {#if !pools}<p class="rail-note">Loading pools…</p>
        {:else if pools.error}<StateMessage kind="error" title="Proxy pools unavailable" detail={pools.error} />
        {:else if !pools.items.length}<p class="rail-note">No proxy pools in your access scope.</p>
        {:else}<ul>{#each pools.items as pool}<li><Network size={16} /><div><strong>{resourceLabel(pool)}</strong><small>{Array.isArray(pool.instances) ? `${pool.instances.length} ${pool.instances.length === 1 ? 'instance' : 'instances'}` : 'Membership unknown'}</small></div></li>{/each}</ul>{/if}
        <a class="rail-link" href={surfacePath('Proxy pools')}>View proxy pools <ArrowRight size={15} /></a>
      </section>
    </aside>
  {/if}
</div>
