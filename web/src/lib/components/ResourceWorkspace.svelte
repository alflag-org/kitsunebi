<script lang="ts">
  import ResourceList from './ResourceList.svelte';
  import ResourceDetail from './ResourceDetail.svelte';
  import type { JsonObject } from '../types';
  export let title: string;
  export let description = '';
  export let endpoint = '';
  export let resources: JsonObject[] = [];
  export let selected: JsonObject | undefined;
  export let loading = false;
  export let error = '';
  export let unsupported = false;
  export let onSelect: (id: string) => void = () => {};
  export let onBack: () => void = () => {};
  export let detail = false;
</script>

{#if detail}<ResourceDetail {title} {endpoint} resource={selected} {loading} {error} {unsupported} {onBack} />{:else}<ResourceList {title} {description} {endpoint} {resources} {loading} {error} {unsupported} {onSelect} />{/if}
