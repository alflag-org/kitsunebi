<script lang="ts">
  import { resourceLabel, resourceValue } from '../api';
  import { safeDisplay, stateTone } from '../state';
  import type { JsonObject } from '../types';
  export let title: string;
  export let description = '';
  export let resources: JsonObject[] = [];
  export let loading = false;
  export let error = '';
  export let unsupported = false;
  export let endpoint = '';
  export let onSelect: (id: string) => void = () => {};

  const preferred = ['name', 'status', 'state', 'runtime', 'cluster', 'world', 'revision', 'updated_at', 'classification'];
  function columns(): string[] {
    const keys = resources.flatMap((resource) => Object.keys(resource).filter((key) => key !== 'id'));
    return [...new Set([...preferred.filter((key) => keys.includes(key)), ...keys])].slice(0, 6);
  }
</script>

<section class="panel resource-list" aria-labelledby="{title.replaceAll(' ', '-').toLowerCase()}">
  <div class="panel-head"><div><h2 id={title.replaceAll(' ', '-').toLowerCase()}>{title}</h2>{#if description}<p>{description}</p>{/if}</div><span class="endpoint-label">{endpoint}</span></div>
  {#if loading}<div class="list-state"><span class="skeleton-line"></span><span class="skeleton-line short"></span><span class="skeleton-line"></span></div>
  {:else if error}<div class="list-state"><div class="state-message error"><span class="state-mark">!</span><div><strong>{unsupported ? 'Capability unavailable' : 'Unable to load this resource'}</strong><span>{error}</span></div></div></div>
  {:else if resources.length === 0}<div class="list-state"><div class="state-message empty"><span class="state-mark">·</span><div><strong>No records in this scope</strong><span>The controller returned an empty collection. No local records are substituted.</span></div></div></div>
  {:else}<div class="table-wrap"><table><thead><tr><th scope="col">Record</th>{#each columns() as column}<th scope="col">{column.replaceAll('_', ' ')}</th>{/each}</tr></thead><tbody>{#each resources as resource}<tr><td><button class="row-link" onclick={() => onSelect(String(resource.id))}><strong>{resourceLabel(resource)}</strong><small>{resource.id}</small></button></td>{#each columns() as column}<td><span class="cell-value {stateTone(resourceValue(resource, column))}">{safeDisplay(column, resourceValue(resource, column))}</span></td>{/each}</tr>{/each}</tbody></table></div>{/if}
</section>
