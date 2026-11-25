<script lang="ts">
  import Activity from '@lucide/svelte/icons/activity';
  import Boxes from '@lucide/svelte/icons/boxes';
  import ChevronDown from '@lucide/svelte/icons/chevron-down';
  import ClipboardList from '@lucide/svelte/icons/clipboard-list';
  import Files from '@lucide/svelte/icons/files';
  import Flame from '@lucide/svelte/icons/flame';
  import FolderTree from '@lucide/svelte/icons/folder-tree';
  import Layers from '@lucide/svelte/icons/layers';
  import LayoutDashboard from '@lucide/svelte/icons/layout-dashboard';
  import Server from '@lucide/svelte/icons/server';
  import Settings2 from '@lucide/svelte/icons/settings-2';
  import SquareTerminal from '@lucide/svelte/icons/square-terminal';
  import X from '@lucide/svelte/icons/x';
  import { surfacePath, type Surface } from '../navigation';

  export let active: Surface;
  export let onClose: (() => void) | undefined = undefined;

  const workspace = [
    { name: 'Dashboard', icon: LayoutDashboard }, { name: 'Services', icon: Layers },
    { name: 'Execution units', icon: Server }, { name: 'Console', icon: SquareTerminal },
    { name: 'Files', icon: Files }, { name: 'Change sessions', icon: ClipboardList },
    { name: 'Operations', icon: Activity }
  ] as const;
  const sections = [
    { name: 'Infrastructure', icon: Boxes, items: ['Clusters', 'Cluster revisions', 'Worlds', 'Proxy pools', 'Proxy instances', 'External endpoints'] },
    { name: 'Content', icon: FolderTree, items: ['Artifacts', 'Plugins / mods', 'Backups / restore'] },
    { name: 'Governance', icon: Settings2, items: ['Access policies', 'Lifecycle / decisions', 'Audit'] }
  ] satisfies { name: string; icon: typeof Boxes; items: Surface[] }[];
  $: current = active === 'Service detail' ? 'Services' : active === 'File diff' ? 'Files' : active;
</script>

<div class="brand">
  <span class="brand-mark"><Flame size={25} strokeWidth={2.2} /></span>
  <strong>Kitsunebi</strong>
  {#if onClose}<button class="icon-control" aria-label="Close navigation" onclick={onClose}><X size={20} /></button>{/if}
</div>
<nav class="workspace-nav" aria-label="Primary">
  <h2>Workspace</h2>
  {#each workspace as item}
    <a href={surfacePath(item.name)} aria-current={current === item.name ? 'page' : undefined} onclick={onClose}>
      <svelte:component this={item.icon} size={17} /><span>{item.name}</span>
    </a>
  {/each}
  <h2>Resources</h2>
  {#each sections as section}
    <details open={section.items.some((name) => name === current)}>
      <summary><svelte:component this={section.icon} size={17} />{section.name}<ChevronDown class="nav-chevron" size={15} /></summary>
      {#each section.items as item}
        <a class="sub-link" href={surfacePath(item)} aria-current={current === item ? 'page' : undefined} onclick={onClose}>{item}</a>
      {/each}
    </details>
  {/each}
</nav>
