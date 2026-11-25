<script lang="ts">
  import { onDestroy } from 'svelte';
  import type { JsonObject } from '../types';
  import { resourceLabel, wsUrl } from '../api';
  export let units: JsonObject[] = [];
  export let selectedUnitId = '';
  export let csrfToken = '';
  export let onUnitChange: (id: string) => void = () => {};
  export let unsupported = false;
  let socket: WebSocket | undefined; let command = ''; let connection: 'idle' | 'connecting' | 'connected' | 'closed' | 'error' = 'idle'; let message = ''; let frames: string[] = [];
  function connect() {
    if (!selectedUnitId || !csrfToken || unsupported || socket) return;
    connection = 'connecting';
    message = '';
    frames = [];
    const relay = new WebSocket(wsUrl(`/execution-units/${encodeURIComponent(selectedUnitId)}/console`), ['kitsunebi.v1', `csrf.${csrfToken}`]);
    socket = relay;
    relay.onopen = () => {
      if (socket !== relay) return;
      if (relay.protocol !== 'kitsunebi.v1') {
        message = 'Console relay negotiated an unexpected protocol.';
        relay.close(1002, 'protocol mismatch');
      } else connection = 'connected';
    };
    relay.onmessage = (event) => {
      if (socket === relay) frames = [...frames.slice(-199), typeof event.data === 'string' ? event.data : '[binary frame]'];
    };
    relay.onerror = () => {
      if (socket !== relay) return;
      connection = 'error';
      message = 'Console connection failed.';
    };
    relay.onclose = () => {
      if (socket !== relay) return;
      if (connection !== 'error') connection = 'closed';
      socket = undefined;
    };
  }
  function send() { if (!socket || connection !== 'connected' || !command.trim()) return; socket.send(command); frames = [...frames, `> ${command}`]; command = ''; }
  function close() { socket?.close(); socket = undefined; if (connection === 'connected' || connection === 'connecting') connection = 'closed'; }
  onDestroy(close);
</script>

<section class="console-workspace" aria-label="Execution console">
  {#if unsupported}<div class="state-message info" role="status"><span class="state-mark">·</span><div><strong>Console disabled by API capability</strong><span>The controller does not expose console access for this scope.</span></div></div>{/if}
  <div class="console-toolbar"><label>Execution Unit<select value={selectedUnitId} onchange={(event) => onUnitChange(event.currentTarget.value)}>{#each units as unit}<option value={String(unit.id)}>{resourceLabel(unit)}</option>{/each}</select></label><span class="stream-state"><span class="status-dot {connection === 'connected' ? 'good' : connection === 'error' ? 'bad' : 'neutral'}"></span>{connection}</span><button class="quiet" onclick={connect} disabled={Boolean(socket) || unsupported || !csrfToken || !selectedUnitId}>Connect</button><button class="quiet" onclick={close} disabled={!socket}>Disconnect</button></div>
  {#if message}<div class="state-message error" role="alert"><span class="state-mark">!</span><div><strong>Console not available</strong><span>{message}</span></div></div>{/if}
  <div class="console-screen" aria-live="polite">{#if frames.length === 0}<span class="console-empty">No console frames received.</span>{:else}{#each frames as frame}<pre>{frame}</pre>{/each}{/if}</div>
  <div class="command-bar"><label class="sr-only" for="command">Command</label><input id="command" bind:value={command} onkeydown={(event) => event.key === 'Enter' && send()} placeholder="Send a command" disabled={connection !== 'connected'} /><button class="primary" onclick={send} disabled={connection !== 'connected' || !command.trim()}>Send</button></div>
</section>
