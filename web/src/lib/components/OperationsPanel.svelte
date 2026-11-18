<script lang="ts">
  import { onDestroy } from 'svelte';
  import { resourceLabel, resourceValue, parseSseEvent } from '../api';
  import type { JsonObject, OperationEvent } from '../types';
  export let resources: JsonObject[] = [];
  export let loading = false;
  export let error = '';
  export let endpoint = '/api/v1/operations';
  export let unsupported = false;
  let selectedId = ''; let stream: EventSource | undefined; let streamState: 'idle' | 'connecting' | 'connected' | 'closed' | 'error' = 'idle'; let streamError = ''; let events: OperationEvent[] = [];
  $: if (!selectedId && resources.length) selectedId = String(resources[0].id);
  function closeStream() { stream?.close(); stream = undefined; streamState = 'closed'; }
  function openStream() { closeStream(); if (!selectedId) return; streamState = 'connecting'; streamError = ''; events = []; stream = new EventSource(`/api/v1/operations/${encodeURIComponent(selectedId)}/events`, { withCredentials: true }); stream.addEventListener('operation', (event) => { const parsed = parseSseEvent(`data: ${(event as MessageEvent).data}`); if (parsed) events = [...events.slice(-119), parsed]; streamState = 'connected'; }); stream.onerror = () => { streamState = 'error'; streamError = 'The operation stream closed or is unavailable. Retry after checking the operation permission.'; stream?.close(); stream = undefined; }; }
  function status(item: JsonObject): string { return String(resourceValue(item, 'status', 'state') ?? 'Unknown'); }
  onDestroy(closeStream);
</script>

<section class="operations-workspace" aria-labelledby="operations-title">
  <div class="change-intro"><div><p class="eyebrow">Server-sent progress</p><h2 id="operations-title">Operations</h2><p>Progress is observed from the controller; this screen never assumes that an operation succeeded.</p></div><span class="endpoint-label">{endpoint}/&#123;id&#125;/events</span></div>
  {#if loading}<div class="state-message loading"><span class="state-mark">…</span><div><strong>Loading operations…</strong><span>Reading current operation records.</span></div></div>{:else if error}<div class="state-message error"><span class="state-mark">!</span><div><strong>{unsupported ? 'Operation capability unavailable' : 'Unable to load operations'}</strong><span>{error}</span></div></div>{:else if resources.length === 0}<div class="state-message empty"><span class="state-mark">·</span><div><strong>No operations returned</strong><span>Start an explicit change operation before opening a progress stream.</span></div></div>{:else}<div class="operation-layout"><div class="operation-list"><h3>Recent operations</h3>{#each resources as operation}<button class:selected={String(operation.id) === selectedId} class="operation-row" onclick={() => { selectedId = String(operation.id); openStream(); }}><span><strong>{resourceLabel(operation)}</strong><small>{operation.id}</small></span><span>{status(operation)}</span></button>{/each}</div><div class="operation-detail"><div class="operation-toolbar"><label>Operation<select bind:value={selectedId} aria-label="Operation"><option value="">Select operation</option>{#each resources as operation}<option value={String(operation.id)}>{resourceLabel(operation)} · {operation.id}</option>{/each}</select></label><button class="quiet" onclick={openStream} disabled={!selectedId || streamState === 'connecting'}>{streamState === 'connected' ? 'Reconnect stream' : 'Open progress stream'}</button></div>{#if streamError}<div class="state-message error" role="alert"><span class="state-mark">!</span><div><strong>Stream unavailable</strong><span>{streamError}</span></div></div>{/if}<div class="stream-state"><span class="status-dot {streamState === 'connected' ? 'good' : streamState === 'error' ? 'bad' : 'neutral'}"></span>{streamState}</div>{#if events.length === 0}<p class="muted-copy">No progress events received yet.</p>{:else}<ol class="event-log">{#each events as event}<li><span class="event-seq">#{event.sequence}</span><strong>{event.status}</strong>{#if event.progress !== undefined}<span>{event.progress}%</span>{/if}{#if event.message}<p>{event.message}</p>{/if}</li>{/each}</ol>{/if}</div></div>{/if}
</section>
