<script lang="ts">
  import { resourceLabel } from '../api';
  import { servicePath } from '../navigation';
  import { safeDisplay, stateTone } from '../state';
  import type { JsonObject } from '../types';
  import StateMessage from './StateMessage.svelte';

  export let title: string;
  export let description = '';
  export let resources: JsonObject[] = [];
  export let loading = false;
  export let error = '';
  export let unsupported = false;
  export let endpoint = '';
  export let selectedId = '';
  export let disabled = false;
  export let linkServices = false;
  export let onSelect: (id: string) => void = () => {};

  const preferred = ['lifecycle', 'state', 'status', 'availability', 'runtime', 'node_id', 'world', 'revision', 'updated_at', 'classification'];
  const identity = ['id', 'key', 'name', 'title', 'label', 'display_name'];
  function columnsFor(items: JsonObject[]) {
    const keys = new Set(items.flatMap(Object.keys));
    return [...new Set([...preferred.filter((key) => keys.has(key)), ...keys])]
      .filter((key) => !identity.includes(key) && items.some((item) => item[key] != null && typeof item[key] !== 'object'))
      .slice(0, 3);
  }
  $: columns = columnsFor(resources);
</script>

<section class="panel resource-list" aria-label={title}>
  <div class="panel-head"><div><h2>{title}</h2>{#if description}<p>{description}</p>{/if}</div>
    {#if !loading && !error}<span class="number-note" title={endpoint}>{resources.length} {resources.length === 1 ? 'record' : 'records'}</span>{/if}
  </div>
  {#if loading}<p class="section-state" role="status">Loading records…</p>
  {:else if error}<StateMessage kind="error" title={unsupported ? 'Capability unavailable' : 'Unable to load records'} detail={error} />
  {:else if !resources.length}<p class="section-state">No records in your access scope.</p>
  {:else}
    <div class="table-wrap"><table><thead><tr><th scope="col">Record</th>{#each columns as key}<th scope="col">{key.replaceAll('_', ' ')}</th>{/each}</tr></thead>
      <tbody>{#each resources as item}
        <tr class:selected-row={String(item.id) === selectedId}><td>
          {#if linkServices}<a class="row-link" href={servicePath(String(item.id))}>{resourceLabel(item)}</a>
          {:else}<button class="row-link" {disabled} aria-pressed={String(item.id) === selectedId} onclick={() => onSelect(String(item.id))}>{resourceLabel(item)}</button>{/if}
        </td>{#each columns as key}
          <td><span class:cell-value={['status', 'state', 'lifecycle'].includes(key)} class={stateTone(item[key])}>{safeDisplay(key, item[key])}</span></td>
        {/each}</tr>
      {/each}</tbody>
    </table></div>
  {/if}
</section>
