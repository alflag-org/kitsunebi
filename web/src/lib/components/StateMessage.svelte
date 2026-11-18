<script lang="ts">
  export let kind: 'loading' | 'error' | 'empty' | 'success' | 'offline' | 'info' = 'info';
  export let title: string;
  export let detail = '';
</script>

<div class="state-message {kind}" role={kind === 'error' || kind === 'offline' ? 'alert' : 'status'}>
  <span class="state-mark" aria-hidden="true">{kind === 'loading' ? '…' : kind === 'error' ? '!' : kind === 'offline' ? '×' : kind === 'success' ? '✓' : '·'}</span>
  <div><strong>{title}</strong>{#if detail}<span>{detail}</span>{/if}</div>
</div>
