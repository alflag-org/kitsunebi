<script lang="ts">
  import { bindingMatchesScope, resourceLabel, resourceValue } from '../api';
  import { buildChangePlan, buildPlanStep, PLAN_STEP_KINDS, type PlanStepKind, type StagedContent, type StagedFile } from '../changePlan';
  import type { JsonObject } from '../types';

  export let resources: JsonObject[] = [];
  export let services: JsonObject[] = [];
  export let clusters: JsonObject[] = [];
  export let bindings: JsonObject[] = [];
  export let stagedFiles: StagedFile[] = [];
  export let selectedId = '';
  export let loading = false;
  export let error = '';
  export let csrfAvailable = false;
  export let busy = false;
  export let unsupported = false;
  export let onSelect: (id: string) => void = () => {};
  export let onBegin: (serviceId: string, clusterId: string) => void | Promise<void> = () => {};
  export let onAction: (id: string, command: string, input: JsonObject) => Promise<JsonObject | undefined> | void = () => {};
  export let onStageContent: (bytes: number[], classification?: string) => Promise<StagedContent | undefined> = async () => undefined;

  let serviceId = '';
  let clusterId = '';
  let stepKind: PlanStepKind = 'execution_lifecycle';
  let fields: JsonObject = { action: 'restart', classification: 'mutable_config', domain_revision: '0', expected_version: '0' };
  let planId = '';
  let planHash = '';
  let operationId = '';
  let verificationStatus = '';
  let rollbackReason = '';
  let verified = false;
  let staged: StagedContent | undefined;
  let stageError = '';
  let grants: JsonObject[] = [{ actor_id: '', role: 'operator', service_scope: '', permissions: [] }];
  let batchOperations: JsonObject[] = [];
  let endpointBindingRecords: JsonObject[] = [];
  let selected: JsonObject | undefined;

  $: selected = resources.find((resource) => String(resource.id) === selectedId);
  $: if (!serviceId && services.length) serviceId = String(services[0].id);
  $: availableClusters = clusters.filter((cluster) => String(resourceValue(cluster, 'service_id', 'service')) === serviceId);
  $: if (!availableClusters.some((cluster) => String(cluster.id) === clusterId)) clusterId = String(availableClusters[0]?.id ?? '');
  $: selectedService = String(resourceValue(selected ?? {}, 'service_id', 'service') ?? serviceId);
  $: selectedCluster = String(resourceValue(selected ?? {}, 'cluster_id', 'cluster') ?? clusterId);
  $: availableBindings = bindings.filter((binding) => bindingMatchesScope(binding, selectedService, selectedCluster));
  $: sessionState = String(resourceValue(selected ?? {}, 'state', 'status') ?? '').toLowerCase();
  $: sessionVersion = String(resourceValue(selected ?? {}, 'version', 'etag', 'updated_version') ?? '');
  $: selectedBinding = availableBindings.find((binding) => String(resourceValue(binding, 'binding_id', 'id')) === String(fields.binding_id));

  const labels: Record<PlanStepKind, string> = {
    execution_provision: 'Provision execution unit', execution_delete: 'Delete execution unit', service_lifecycle_transition: 'Transition service lifecycle', cluster_revision_create: 'Create cluster revision',
    execution_lifecycle: 'Execution lifecycle', file_write: 'Write a staged file', file_move: 'Move a file', file_quarantine: 'Quarantine a file', file_batch: 'Batch file changes', artifact_register: 'Register staged artifact',
    artifact_stage: 'Stage artifact', artifact_activate: 'Activate artifact', proxy_rollout: 'Proxy rolling update', world_writer_cutover: 'World writer cutover', endpoint_rollout: 'Endpoint rollout',
    access_policy_update: 'Update access policy', route_policy_update: 'Update route policy', backup_create: 'Create backup reference', backup_restore: 'Restore backup reference', service_archive: 'Archive service', service_purge: 'Purge service'
  };
  const hashPattern = /^[0-9a-f]{64}$/i;
  function observedHash(resource: JsonObject): string { const value = resourceValue(resource, 'observed_hash', 'state_hash', 'binding_hash', 'hash', 'digest'); return hashPattern.test(String(value ?? '')) ? String(value) : ''; }
  function operationIdFor(resource: JsonObject | undefined): string {
    return resource ? String(resourceValue(resource, 'operation_id', 'operationId') ?? '') : '';
  }
  function select(id: string) {
    onSelect(id); planId = ''; planHash = ''; verificationStatus = ''; verified = false;
    operationId = operationIdFor(resources.find((resource) => String(resource.id) === id));
  }
  function chooseStep(kind: PlanStepKind) { stepKind = kind; fields = { action: 'restart', classification: 'mutable_config', domain_revision: '0', expected_version: '0' }; staged = undefined; stageError = ''; batchOperations = []; endpointBindingRecords = []; }
  function setField(name: string, value: string) { fields = { ...fields, [name]: value }; }
  function inputType(name: string): string { return ['domain_revision', 'expected_version', 'expected_world_version', 'archived_at', 'content_size', 'expected_priority', 'target_priority', 'expected_current_number', 'revision_number'].includes(name) ? 'number' : 'text'; }
  function fieldNames(kind: PlanStepKind): string[] {
    const map: Record<PlanStepKind, string[]> = {
      execution_provision: ['binding_id', 'expected_binding_hash', 'domain_revision'], execution_delete: ['binding_id', 'expected_binding_hash', 'expected_state_hash', 'domain_revision', 'expected_version'],
      service_lifecycle_transition: ['service_id', 'expected_state', 'next_state', 'expected_version', 'reason'], cluster_revision_create: ['cluster_id', 'revision_id', 'revision_number', 'runtime_profile', 'minecraft_version', 'java_requirement', 'artifact_set', 'config_baseline', 'world_bindings', 'endpoint_bindings', 'process_managers', 'required_capabilities', 'resource_requirements', 'health_checks', 'startup_parameters', 'new_endpoint_bindings', 'expected_current_number'],
      execution_lifecycle: ['binding_id', 'action', 'expected_binding_hash', 'expected_state_hash', 'domain_revision'],
      file_write: ['binding_id', 'path', 'expected_binding_hash', 'domain_revision', 'expected_before_digest', 'classification'],
      file_move: ['binding_id', 'from', 'to', 'expected_binding_hash', 'domain_revision', 'expected_before_digest', 'expected_target_digest', 'classification'],
      file_quarantine: ['binding_id', 'path', 'expected_binding_hash', 'domain_revision', 'expected_before_digest', 'classification'],
      file_batch: ['binding_id', 'expected_binding_hash', 'domain_revision'], artifact_register: ['artifact_id', 'kind', 'name', 'version', 'source', 'source_id', 'digest', 'filename', 'compatibility', 'metadata', 'expected_version', 'domain_revision'], artifact_stage: ['artifact_id', 'expected_digest', 'expected_version', 'domain_revision'],
      artifact_activate: ['artifact_id', 'artifact_set_id', 'binding_id', 'expected_binding_hash', 'cluster_id', 'expected_revision', 'target_revision', 'expected_digest', 'expected_version', 'destination_path', 'expected_before_digest'],
      proxy_rollout: ['pool_id', 'expected_instance_id', 'target_instance_id', 'expected_instance_version', 'target_instance_version', 'expected_instance_state', 'target_instance_state', 'target_binding_id', 'target_binding_hash', 'domain_revision', 'desired_state'],
      world_writer_cutover: ['world_id', 'expected_version', 'expected_writer', 'next_writer', 'expected_writer_binding_id', 'target_writer_binding_id', 'expected_writer_binding_hash', 'target_writer_binding_hash', 'domain_revision'], endpoint_rollout: ['expected_binding_id', 'target_binding_id', 'cluster_id', 'expected_revision', 'target_revision', 'expected_version', 'runtime_binding_ids', 'runtime_binding_hashes'],
      access_policy_update: ['policy_id', 'service_id', 'expected_version', 'desired_policy_hash'], route_policy_update: ['route_id', 'pool_id', 'service_id', 'expected_cluster', 'target_cluster', 'expected_priority', 'target_priority', 'expected_version', 'disabled'], backup_create: ['kind', 'target', 'request_hash'], backup_restore: ['reference_id', 'target', 'expected_manifest_digest', 'rollback_reference_id', 'expected_rollback_manifest_digest', 'expected_version'],
      service_archive: ['service_id', 'expected_version', 'sunsetting_evidence_hash'], service_purge: ['service_id', 'expected_version', 'archive_evidence_hash', 'verified_backup_id', 'archived_at']
    };
    return map[kind];
  }
  function label(name: string): string { return name.replaceAll('_', ' ').replace(/\b\w/g, (value) => value.toUpperCase()); }
  function selectOptions(name: string): string[] | undefined {
    if (['binding_id', 'expected_binding_id', 'target_binding_id'].includes(name) && availableBindings.length) return availableBindings.map((binding) => String(resourceValue(binding, 'binding_id', 'id')));
    if (name === 'action') return ['start', 'stop', 'restart'];
    if (name === 'classification') return ['managed', 'mutable_config', 'artifact', 'generated'];
    if (['desired_state', 'expected_instance_state', 'target_instance_state'].includes(name)) return ['preparing', 'ready', 'accepting', 'draining', 'stopped', 'failed'];
    if (name === 'kind') return ['change-snapshot', 'world', 'service-consistent', 'external-database-reference'];
    if (name === 'expected_state' || name === 'next_state') return ['Planned', 'Testing', 'Active', 'Maintenance', 'Sunsetting', 'Archived'];
    if (name === 'disabled') return ['false', 'true'];
    return undefined;
  }
  async function stageFile(event: Event) {
    const file = (event.currentTarget as HTMLInputElement).files?.[0]; if (!file) return;
    stageError = ''; staged = undefined;
    if (file.size > 50 * 1024 * 1024) { stageError = 'Staged content must be at most 50 MiB.'; return; }
    const result = await onStageContent([...new Uint8Array(await file.arrayBuffer())], String(fields.classification ?? (stepKind === 'artifact_register' ? 'artifact' : 'mutable_config')));
    if (!result) stageError = 'The controller did not return staged content metadata.'; else {
      staged = result;
      setField(stepKind === 'artifact_register' ? 'filename' : 'path', stepKind === 'artifact_register' ? file.name : fields.path ? String(fields.path) : file.name);
      if (stepKind === 'artifact_register') setField('digest', result.digest);
    }
  }
  function addBatch(kind: string) { const available = stagedFiles.filter((item) => item.sessionId === selectedId); batchOperations = [...batchOperations, kind === 'write' ? { kind: 'write', path: available[0]?.path ?? '', expected_before_digest: available[0]?.expectedBeforeDigest ?? null, content: staged ?? available[0]?.content ?? { digest: '', size: 0 }, classification: available[0]?.classification ?? 'mutable_config' } : kind === 'move' ? { kind: 'move', from: '', to: '', expected_before_digest: null, expected_target_digest: null, classification: 'mutable_config' } : { kind: 'quarantine', path: '', expected_before_digest: null, classification: 'mutable_config' }]; }
  function addProxyConfiguration() { const available = stagedFiles.filter((item) => item.sessionId === selectedId); const content = staged ?? available[0]?.content; if (!content) { stageError = 'Stage a configuration file before adding it.'; return; } batchOperations = [...batchOperations, { kind: 'write', path: fields.path ? String(fields.path) : available[0]?.path ?? '', expected_before_digest: available[0]?.expectedBeforeDigest ?? null, content, classification: 'mutable_config' }]; }
  function updateBatch(index: number, key: string, value: string) { batchOperations = batchOperations.map((item, itemIndex) => itemIndex === index ? { ...item, [key]: value } : item); }
  function addEndpointBinding() { endpointBindingRecords = [...endpointBindingRecords, { id: '', endpoint_id: '', cluster_id: selectedCluster, revision_id: '', binding_key: '', metadata: '' }]; }
  function updateEndpointBinding(index: number, key: string, value: string) { endpointBindingRecords = endpointBindingRecords.map((item, itemIndex) => itemIndex === index ? { ...item, [key]: value } : item); }
  function removeEndpointBinding(index: number) { endpointBindingRecords = endpointBindingRecords.filter((_, itemIndex) => itemIndex !== index); }
  function toggleGrant(index: number, permission: string) { grants = grants.map((grant, grantIndex) => grantIndex === index ? { ...grant, permissions: (grant.permissions as string[]).includes(permission) ? (grant.permissions as string[]).filter((item) => item !== permission) : [...grant.permissions as string[], permission] } : grant); }
  function updateGrant(index: number, key: string, value: string) { grants = grants.map((grant, grantIndex) => grantIndex === index ? { ...grant, [key]: value } : grant); }
  async function run(command: string) {
    if (!selectedId || !csrfAvailable || busy) return;
    const detail: JsonObject = { ...fields, binding_id: fields.binding_id || resourceValue(availableBindings[0] ?? {}, 'binding_id', 'id') };
    if (!detail.expected_binding_hash && selectedBinding) detail.expected_binding_hash = observedHash(selectedBinding);
    const sessionStagedFiles = stagedFiles.filter((item) => item.sessionId === selectedId);
    const stagedForStep = staged ?? sessionStagedFiles.find((item) => item.path === String(detail.path))?.content ?? sessionStagedFiles[0]?.content;
    if (stepKind === 'file_write' || stepKind === 'artifact_register') { detail.content_digest = stagedForStep?.digest ?? ''; detail.content_size = stagedForStep?.size ?? 0; if (stepKind === 'file_write' && !detail.expected_before_digest) detail.expected_before_digest = sessionStagedFiles.find((item) => item.path === String(detail.path))?.expectedBeforeDigest ?? null; }
    if (stepKind === 'file_batch') detail.operations = batchOperations;
    if (stepKind === 'proxy_rollout') detail.configuration = batchOperations;
    if (stepKind === 'cluster_revision_create') detail.new_endpoint_bindings = endpointBindingRecords;
    if (stepKind === 'endpoint_rollout') {
      detail.runtime_binding_ids = String(detail.runtime_binding_ids ?? '').split(',').map((value) => value.trim()).filter(Boolean);
      detail.runtime_binding_hashes = String(detail.runtime_binding_hashes ?? '').split(',').map((value) => value.trim().toLowerCase()).filter(Boolean);
    }
    if (stepKind === 'access_policy_update') detail.desired_grants = grants;
    if (stepKind === 'backup_create' || stepKind === 'backup_restore') detail.target = { kind: 'service', value: selectedService };
    const step = buildPlanStep(stepKind, { ...detail, observed: selectedBinding ?? selected ?? {} });
    const plan = command === 'plan' ? await buildChangePlan({ sessionId: selectedId, serviceId: selectedService, targetKind: 'cluster', targetId: selectedCluster, domainRevision: Number(fields.domain_revision ?? 0), steps: [step], backupRequired: stepKind === 'backup_restore' || stepKind === 'service_purge', rollbackInstructions: ['Re-observe provider state before accepting; rollback requires an explicit reason.'] }) : undefined;
    const persistedOperationId = operationId || operationIdFor(selected);
    const persistedPlanHash = planHash || String(resourceValue(selected ?? {}, 'plan_hash', 'planHash') ?? '');
    const input: JsonObject = command === 'plan' ? (plan ?? {}) : command === 'approve' ? { session_id: selectedId, plan_id: planId, plan_hash: persistedPlanHash } : command === 'apply' ? { session_id: selectedId, plan_id: planId, plan_hash: persistedPlanHash } : command === 'verify' ? { session_id: selectedId, operation_id: persistedOperationId, plan_hash: persistedPlanHash } : command === 'accept' ? { session_id: selectedId, operation_id: persistedOperationId, plan_hash: persistedPlanHash } : { session_id: selectedId, operation_id: persistedOperationId, plan_hash: persistedPlanHash, reason: rollbackReason.trim() };
    const result = await onAction(selectedId, command, input);
    if (!result) return;
    if (command === 'plan') { planId = String(result.plan_id ?? ''); planHash = String(result.plan_hash ?? ''); }
    else if (command === 'verify') { operationId = String(result.id ?? operationId); verified = String(result.status ?? '').toLowerCase() === 'verified' || Boolean(result.verified); verificationStatus = String(result.status ?? 'verified'); }
    else if (command === 'apply' || command === 'accept' || command === 'rollback') operationId = String(result.id ?? operationId);
  }
</script>

<section class="change-workspace" aria-labelledby="change-title">
  <div class="change-intro"><div><p class="eyebrow">Persisted Change Session</p><h2 id="change-title">Observe → plan → approve → apply → verify → accept</h2><p>Every write becomes one closed typed step. Provider identifiers, state hashes, backup references, and staged bytes are recorded before apply.</p></div><span class="endpoint-label">/api/v1/change-sessions</span></div>
  {#if loading}<div class="state-message loading"><span class="state-mark">…</span><div><strong>Loading change sessions…</strong><span>Reading the controller record before enabling operations.</span></div></div>
  {:else if error}<div class="state-message error"><span class="state-mark">!</span><div><strong>{unsupported ? 'Change capability unavailable' : 'Change sessions unavailable'}</strong><span>{error}</span></div></div>
  {:else}
    <div class="change-form begin-form"><h3>Begin a Change Session</h3><div class="form-grid"><label>Service<select bind:value={serviceId}><option value="" disabled>Select a Service</option>{#each services as service}<option value={String(service.id)}>{resourceLabel(service)}</option>{/each}</select></label><label>Cluster<select bind:value={clusterId}><option value="" disabled>Select a Cluster</option>{#each availableClusters as cluster}<option value={String(cluster.id)}>{resourceLabel(cluster)}</option>{/each}</select></label></div><button class="action-button" disabled={busy || !serviceId || !clusterId || !csrfAvailable} onclick={() => onBegin(serviceId, clusterId)}>Begin session</button></div>
    {#if resources.length === 0}<div class="state-message empty"><span class="state-mark">·</span><div><strong>No Change Session selected</strong><span>Begin a session above, then choose the persisted record to plan a typed step.</span></div></div>
    {:else}<div class="change-grid"><div class="change-list"><h3>Sessions</h3>{#each resources as resource}<button class:selected={String(resource.id) === selectedId} class="change-row" onclick={() => select(String(resource.id))}><span><strong>{resourceLabel(resource)}</strong><small>{resource.id}</small></span><span class="status-text">{String(resourceValue(resource, 'state', 'status') ?? 'Unknown')}</span></button>{/each}</div><div class="change-form"><h3>{selected ? resourceLabel(selected) : 'Select a session'}</h3>{#if selected}<div class="safety-summary"><strong>Typed, provider-observed step</strong><span>Secret, state, unknown, and unclassified writes cannot be selected. Accept is enabled only after a Verified operation response.</span></div><div class="form-grid"><label>Step<select bind:value={stepKind} onchange={(event) => chooseStep((event.currentTarget as HTMLSelectElement).value as PlanStepKind)}>{#each PLAN_STEP_KINDS as kind}<option value={kind}>{labels[kind]}</option>{/each}</select></label><label>Target Service<input value={selectedService} readonly /></label><label>Target Cluster<input value={selectedCluster} readonly /></label></div><div class="scoped-fields">{#each fieldNames(stepKind) as name}{#if name !== 'new_endpoint_bindings'}<label>{label(name)}{#if selectOptions(name)}<select value={fields[name] ?? ''} onchange={(event) => setField(name, (event.currentTarget as HTMLSelectElement).value)}><option value="">Select {label(name).toLowerCase()}</option>{#each selectOptions(name) ?? [] as option}<option value={option}>{option}</option>{/each}</select>{:else}<input type={inputType(name)} value={fields[name] ?? ''} oninput={(event) => setField(name, (event.currentTarget as HTMLInputElement).value)} placeholder={name.includes('hash') || name.includes('digest') ? '64-character digest' : name.includes('id') ? 'canonical UUID' : ''} autocomplete="off" />{/if}</label>{/if}{/each}</div>
      {#if stepKind === 'cluster_revision_create'}<div class="batch-builder" aria-label="New endpoint bindings"><div class="panel-head"><div><h3>New endpoint bindings</h3><p class="muted-copy">Add complete binding records for the revision; provider addresses do not belong in this form.</p></div><button type="button" class="quiet" onclick={addEndpointBinding}>Add binding</button></div>{#each endpointBindingRecords as record, index}<div class="scoped-fields"><label>Binding ID<input value={record.id ?? ''} placeholder="canonical UUID" oninput={(event) => updateEndpointBinding(index, 'id', (event.currentTarget as HTMLInputElement).value)} /></label><label>Endpoint ID<input value={record.endpoint_id ?? ''} placeholder="canonical UUID" oninput={(event) => updateEndpointBinding(index, 'endpoint_id', (event.currentTarget as HTMLInputElement).value)} /></label><label>Cluster ID<input value={record.cluster_id ?? selectedCluster} placeholder="canonical UUID" oninput={(event) => updateEndpointBinding(index, 'cluster_id', (event.currentTarget as HTMLInputElement).value)} /></label><label>Revision ID<input value={record.revision_id ?? ''} placeholder="canonical UUID" oninput={(event) => updateEndpointBinding(index, 'revision_id', (event.currentTarget as HTMLInputElement).value)} /></label><label>Binding key<input value={record.binding_key ?? ''} oninput={(event) => updateEndpointBinding(index, 'binding_key', (event.currentTarget as HTMLInputElement).value)} /></label><label>Metadata<input value={record.metadata ?? ''} oninput={(event) => updateEndpointBinding(index, 'metadata', (event.currentTarget as HTMLInputElement).value)} /></label><button type="button" class="quiet" onclick={() => removeEndpointBinding(index)}>Remove binding</button></div>{/each}</div>{/if}
      {#if stepKind === 'file_write' || stepKind === 'artifact_register' || stepKind === 'proxy_rollout'}<label class="scoped-field-full">Staged content<input type="file" onchange={stageFile} disabled={!csrfAvailable || busy} /></label>{#if staged}<p class="muted-copy">Staged bytes {staged.size.toLocaleString()} · {staged.digest}</p>{/if}{#if stageError}<p class="disabled-reason">{stageError}</p>{/if}{/if}
      {#if stepKind === 'file_batch'}<div class="batch-builder"><div class="panel-head"><div><h3>Batch operations</h3><p class="muted-copy">Stage bytes once, then attach them to a typed write operation.</p></div><div><input type="file" aria-label="Stage batch file" onchange={stageFile} disabled={!csrfAvailable || busy} /><button class="quiet" type="button" onclick={() => addBatch('write')}>Add write</button><button class="quiet" type="button" onclick={() => addBatch('move')}>Add move</button><button class="quiet" type="button" onclick={() => addBatch('quarantine')}>Add quarantine</button></div></div>{#each batchOperations as item, index}<div class="scoped-fields"><strong>{String(item.kind)}</strong><input value={item.path ?? item.from ?? ''} placeholder="relative path" oninput={(event) => updateBatch(index, item.kind === 'move' ? 'from' : 'path', (event.currentTarget as HTMLInputElement).value)} />{#if item.kind === 'move'}<input value={item.to ?? ''} placeholder="destination" oninput={(event) => updateBatch(index, 'to', (event.currentTarget as HTMLInputElement).value)} />{/if}</div>{/each}</div>{/if}
      {#if stepKind === 'proxy_rollout'}<div class="batch-builder" aria-label="Proxy target configuration"><div class="panel-head"><div><h3>Target configuration</h3><p class="muted-copy">Stage at least one mutable configuration file. It is written after target creation and before start.</p></div><button class="quiet" type="button" onclick={addProxyConfiguration}>Add write</button></div>{#each batchOperations as item, index}<div class="scoped-fields"><strong>write</strong><input value={item.path ?? ''} placeholder="relative path" oninput={(event) => updateBatch(index, 'path', (event.currentTarget as HTMLInputElement).value)} /><small>{String((item.content as JsonObject | undefined)?.digest ?? '')}</small></div>{/each}</div>{/if}
      {#if stepKind === 'access_policy_update'}<div class="grant-list" aria-label="Desired access grants">{#each grants as grant, index}<fieldset class="grant-editor"><legend>Grant {index + 1}</legend><div class="scoped-fields"><label>Actor ID<input value={grant.actor_id ?? ''} oninput={(event) => updateGrant(index, 'actor_id', (event.currentTarget as HTMLInputElement).value)} /></label><label>Role<select value={grant.role ?? 'operator'} onchange={(event) => updateGrant(index, 'role', (event.currentTarget as HTMLSelectElement).value)}>{#each ['platform_admin', 'operator', 'service_maintainer', 'auditor'] as role}<option value={role}>{role}</option>{/each}</select></label><label>Service scope<input value={grant.service_scope ?? ''} oninput={(event) => updateGrant(index, 'service_scope', (event.currentTarget as HTMLInputElement).value)} /></label></div><span class="grant-label">Permissions</span><div class="permission-grid">{#each ['service.read', 'change.plan', 'change.apply', 'change.verify', 'change.accept', 'files.write', 'artifact.stage', 'artifact.activate', 'proxy.rollout', 'backup.restore', 'world.write', 'endpoint.write', 'access.manage'] as permission}<label class="check-label"><input type="checkbox" checked={(grant.permissions as string[]).includes(permission)} onchange={() => toggleGrant(index, permission)} />{permission}</label>{/each}</div></fieldset>{/each}<button type="button" class="quiet" onclick={() => grants = [...grants, { actor_id: '', role: 'operator', service_scope: '', permissions: [] }]}>Add grant</button></div>{/if}
      {#if planId}<p class="muted-copy">Plan {planId} · hash {planHash}</p>{/if}{#if operationId || operationIdFor(selected)}<p class="muted-copy">Operation {operationId || operationIdFor(selected)}</p>{/if}{#if verificationStatus}<p class="muted-copy">Verification status: {verificationStatus}</p>{/if}<label>Rollback reason<input bind:value={rollbackReason} placeholder="Required for rollback" autocomplete="off" /></label>{#if !csrfAvailable}<p class="disabled-reason">State-changing actions are disabled because no same-origin CSRF session is available.</p>{/if}<div class="workflow-actions"><button class="action-button" disabled={busy || sessionState !== 'editing' || !csrfAvailable} onclick={() => run('plan')}>Plan</button><button class="action-button" disabled={busy || !planId || !planHash || !csrfAvailable || !['editing', 'ready'].includes(sessionState)} onclick={() => run('approve')}>Approve</button><button class="action-button" disabled={busy || !planId || !planHash || !csrfAvailable || sessionState !== 'ready'} onclick={() => run('apply')}>Apply</button><button class="action-button" disabled={busy || !(operationId || operationIdFor(selected)) || !csrfAvailable || sessionState !== 'verifying' || verified} onclick={() => run('verify')}>Verify</button><button class="action-button" disabled={busy || !(operationId || operationIdFor(selected)) || !csrfAvailable || !['verifying'].includes(sessionState) || !verified} onclick={() => run('accept')}>Accept</button><button class="action-button danger" disabled={busy || !(operationId || operationIdFor(selected)) || !rollbackReason.trim() || !csrfAvailable || !['applying', 'verifying', 'aborted'].includes(sessionState)} onclick={() => run('rollback')}>Rollback</button></div>{:else}<p class="muted-copy">Select a persisted session to inspect its scope and plan work.</p>{/if}</div></div>{/if}
  {/if}
</section>
