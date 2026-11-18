<script lang="ts">
  import { api, resourceLabel } from '../api';
  import type { JsonObject, Operation } from '../types';
  export let units: JsonObject[] = [];
  export let csrfToken = '';
  type Preview = { session_id: string; plan_id: string; plan_hash: string; action: string; target_name: string; running: boolean; impact: string; expires_at: number };
  let unit = '';
  let action = 'restart';
  let preview: Preview | undefined;
  let result: Operation | undefined;
  let key = '';
  let busy = false;
  let error = '';
  $: if (!units.some((value) => String(value.id) === unit)) { unit = String(units[0]?.id ?? ''); preview = undefined; }
  function reset() { preview = undefined; result = undefined; error = ''; }
  function headers(id: string) { return { 'X-CSRF-Token': csrfToken, 'Idempotency-Key': id }; }
  async function prepare() {
    if (busy || !unit || !csrfToken) return;
    busy = true; reset();
    try {
      const response = await api<Preview>(`/execution-units/${encodeURIComponent(unit)}/lifecycle/prepare`, { method: 'POST', headers: headers(crypto.randomUUID()), body: JSON.stringify({ action }) });
      if (response.error) error = [403, 404].includes(response.error.status) ? 'The target is unavailable or you lack the lifecycle, planning, approval, execution, verification or acceptance permission.' : response.error.message;
      else { preview = response.data; key = crypto.randomUUID(); }
    } finally { busy = false; }
  }
  async function execute() {
    if (busy || !preview || !csrfToken) return;
    busy = true; error = '';
    try {
      const response = await api<Operation>(`/change-sessions/${encodeURIComponent(preview.session_id)}/execute-lifecycle`, { method: 'POST', headers: headers(key), body: JSON.stringify({ plan_id: preview.plan_id, plan_hash: preview.plan_hash }) });
      if (response.error) {
        error = response.error.status === 409 ? 'The confirmed state changed or the operation could not be verified. Inspect operation history before preparing another change.' : `${response.error.message}. Inspect operation history before retrying.`;
        if (response.error.status === 409) preview = undefined;
      } else result = response.data;
    } finally { busy = false; }
  }
</script>

<section class="panel" aria-labelledby="lifecycle-title">
  <h2 id="lifecycle-title">Start, stop or restart</h2>
  <div class="file-toolbar">
    <label>Target<select bind:value={unit} onchange={reset} disabled={busy}>{#each units as item}<option value={String(item.id)}>{resourceLabel(item)}</option>{/each}</select></label>
    <label>Operation<select bind:value={action} onchange={reset} disabled={busy}><option value="start">Start</option><option value="stop">Stop</option><option value="restart">Restart</option></select></label>
    <button class="quiet" onclick={prepare} disabled={busy || !unit || !csrfToken}>Review operation</button>
  </div>
  {#if preview && !result}
    <div class="panel-head"><div><h3>{preview.target_name}</h3><p>Currently {preview.running ? 'running' : 'stopped'}. {preview.impact}</p></div></div>
    <button class="primary" onclick={execute} disabled={busy || Date.now() >= preview.expires_at * 1000}>{busy ? 'Executing…' : `Confirm ${preview.action}`}</button>
  {/if}
  {#if result}<p role="status">Operation {result.status === 'accepted' ? 'completed and verified' : result.status}.</p><p>View the recorded evidence in Operations.</p>{/if}
  {#if error}<p role="alert">{error}</p>{/if}
</section>
