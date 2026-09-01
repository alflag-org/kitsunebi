<script lang="ts">
  import { onDestroy } from 'svelte';
  import { wsUrl } from '../api';
  export let selectedUnitId = '';
  export let csrfToken = '';
  export let onUnitChange: (id: string) => void = () => {};
  export let unsupported = false;
  let socket: WebSocket | undefined; let command = ''; let connection: 'idle' | 'connecting' | 'connected' | 'closed' | 'error' = 'idle'; let message = ''; let frames: string[] = [];
  function connect() { close(); if (!selectedUnitId) { message = 'Select an Execution Unit before opening its console.'; return; } if (unsupported) { message = 'Console capability is unavailable for this execution unit.'; return; } if (!csrfToken) { message = 'Console commands are disabled until the authenticated session provides CSRF material.'; return; } connection = 'connecting'; message = ''; frames = []; socket = new WebSocket(wsUrl(`/execution-units/${encodeURIComponent(selectedUnitId)}/console`), ['kitsunebi.v1', `csrf.${csrfToken}`]); socket.onopen = () => { if (socket?.protocol !== 'kitsunebi.v1') { message = 'Console relay negotiated an unexpected protocol.'; socket?.close(1002, 'protocol mismatch'); return; } connection = 'connected'; }; socket.onmessage = (event) => { frames = [...frames.slice(-199), typeof event.data === 'string' ? event.data : '[binary frame]']; }; socket.onerror = () => { connection = 'error'; message = 'Console relay unavailable. Kitsunebi did not expose a GameAP credential to the browser.'; }; socket.onclose = () => { if (connection !== 'error') connection = 'closed'; socket = undefined; }; }
  function send() { if (!socket || connection !== 'connected' || !command.trim()) return; socket.send(command); frames = [...frames, `> ${command}`]; command = ''; }
  function close() { socket?.close(); socket = undefined; if (connection === 'connected' || connection === 'connecting') connection = 'closed'; }
  onDestroy(close);
</script>

<section class="console-workspace" aria-labelledby="console-title">
  <div class="change-intro"><div><p class="eyebrow">Brokered WebSocket</p><h2 id="console-title">Console</h2><p>Commands travel through Kitsunebi to the execution backend. GameAP credentials never enter this page.</p></div><span class="endpoint-label">/api/v1/execution-units/&#123;id&#125;/console</span></div>
  {#if unsupported}<div class="state-message info" role="status"><span class="state-mark">·</span><div><strong>Console disabled by API capability</strong><span>The controller does not expose console access for this scope.</span></div></div>{/if}
  <div class="console-toolbar"><label>Execution Unit<input value={selectedUnitId} oninput={(event) => onUnitChange(event.currentTarget.value)} placeholder="Execution Unit id" autocomplete="off" /></label><span class="stream-state"><span class="status-dot {connection === 'connected' ? 'good' : connection === 'error' ? 'bad' : 'neutral'}"></span>{connection}</span><button class="quiet" onclick={connect} disabled={connection === 'connecting' || unsupported}>Connect</button><button class="quiet" onclick={close} disabled={!socket}>Disconnect</button></div>
  {#if message}<div class="state-message error" role="alert"><span class="state-mark">!</span><div><strong>Console not available</strong><span>{message}</span></div></div>{/if}
  <div class="console-screen" aria-live="polite">{#if frames.length === 0}<span class="console-empty">No console frames received.</span>{:else}{#each frames as frame}<pre>{frame}</pre>{/each}{/if}</div>
  <div class="command-bar"><label class="sr-only" for="command">Command</label><input id="command" bind:value={command} onkeydown={(event) => event.key === 'Enter' && send()} placeholder="Send a command" disabled={connection !== 'connected'} /><button class="primary" onclick={send} disabled={connection !== 'connected' || !command.trim()}>Send</button></div>
</section>
