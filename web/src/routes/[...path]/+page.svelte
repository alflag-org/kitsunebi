<script lang="ts">
  import App from '../../App.svelte';
  import { surfaceFromPath } from '../../lib/navigation';
  import '../../styles.css';

  export let data: { surface?: string };
</script>

<App initialActive={surfaceFromPath(data.surface)} />
