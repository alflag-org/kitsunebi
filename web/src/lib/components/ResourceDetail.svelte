<script lang="ts">
  import { resourceLabel, resourceValue } from '../api';
  import { safeDisplay } from '../state';
  import type { JsonObject } from '../types';
  export let resource: JsonObject | undefined;
  export let title: string;
  export let endpoint = '';
  export let loading = false;
  export let error = '';
  export let unsupported = false;
  export let onBack: () => void = () => {};
  const priority = ['state', 'status', 'desired_state', 'observed_state', 'lifecycle', 'cluster', 'revision', 'world', 'runtime', 'version', 'etag', 'updated_at'];
</script>

<section class="panel detail-panel" aria-labelledby="detail-title">
  <div class="panel-head"><div><button class="back-link" onclick={onBack}>← Back to list</button><h2 id="detail-title">{title}</h2>{#if resource}<p>{resourceLabel(resource)} · {resource.id}</p>{/if}</div><span class="endpoint-label">{endpoint}</span></div>
  {#if loading}<div class="detail-loading"><span class="skeleton-line"></span><span class="skeleton-line"></span><span class="skeleton-line short"></span></div>
  {:else if error}<div class="list-state"><div class="state-message error"><span class="state-mark">!</span><div><strong>{unsupported ? 'Capability unavailable' : 'Unable to load detail'}</strong><span>{error}</span></div></div></div>
  {:else if resource}<dl class="detail-grid">{#each [...priority.filter((key) => resource[key] !== undefined), ...Object.keys(resource).filter((key) => !priority.includes(key) && key !== 'id')] as key}<div><dt>{key.replaceAll('_', ' ')}</dt><dd>{safeDisplay(key, resourceValue(resource, key))}</dd></div>{/each}</dl>
  {:else}<div class="list-state"><div class="state-message empty"><span class="state-mark">·</span><div><strong>Select a record</strong><span>Choose a resource from the list to inspect its current state.</span></div></div></div>{/if}
</section>
