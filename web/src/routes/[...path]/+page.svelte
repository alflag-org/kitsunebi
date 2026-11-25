<script lang="ts">
  import { browser } from '$app/env';
  import { page } from '$app/state';
  import App from '../../App.svelte';
  import { surfaceFromPath } from '../../lib/navigation';
  import '../../styles.css';

  let { data }: { data: { surface: string } } = $props();
  const surface = $derived(surfaceFromPath(data.surface));
</script>

<App initialActive={surface}
  serviceId={browser ? page.url.searchParams.get(surface === 'Execution units' ? 'service' : 'id') ?? '' : ''} />
