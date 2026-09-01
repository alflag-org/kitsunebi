#![forbid(unsafe_code)]
//! Application layer: stable ports and orchestration for MCPlayNetwork.
//! Provider SDK, HTTP, DNS, SQL, and secret transport types stay behind these
//! ports; the application owns only opaque execution and edge bindings.
use async_trait::async_trait;
use domain::*;
pub use kitsunebi_domain as domain;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fmt,
    sync::{Arc, Mutex},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplicationError {
    NotFound(&'static str),
    Forbidden,
    Conflict(&'static str),
    RollbackConflict(String),
    StalePlan,
    ExpiredPlan,
    Replay,
    BackupUnavailable,
    VerificationFailed(String),
    Port(String),
}

/// Durable retirement state used by archive and purge planning.  These are
/// observations of current persisted state, not declarations made by a plan.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RetirementSafety {
    pub active_routes: bool,
    pub active_world_writers: bool,
    pub active_execution_bindings: bool,
    pub effective_access_grants: Vec<AccessGrant>,
}
impl fmt::Display for ApplicationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ApplicationError {}

/// Persistence boundary. Implementations must provide an atomic transaction.
#[async_trait]
pub trait DomainRepository: Send + Sync {
    async fn network(&self, id: NetworkId) -> Result<MCPlayNetwork, ApplicationError>;
    async fn services(&self) -> Result<Vec<Service>, ApplicationError>;
    async fn service(&self, id: ServiceId) -> Result<Service, ApplicationError>;
    async fn clusters(&self) -> Result<Vec<GameCluster>, ApplicationError>;
    async fn cluster(&self, id: ClusterId) -> Result<GameCluster, ApplicationError>;
    async fn revisions(&self) -> Result<Vec<ClusterRevision>, ApplicationError>;
    async fn revision_cluster(&self, _id: RevisionId) -> Result<ClusterId, ApplicationError> {
        Err(ApplicationError::NotFound("revision cluster"))
    }
    async fn worlds(&self) -> Result<Vec<World>, ApplicationError>;
    async fn proxies(&self) -> Result<Vec<ProxyInstance>, ApplicationError>;
    async fn artifacts(&self) -> Result<Vec<Artifact>, ApplicationError>;
    async fn artifact_set(&self, _id: ArtifactSetId) -> Result<ArtifactSet, ApplicationError> {
        Err(ApplicationError::NotFound("artifact set"))
    }
    async fn endpoints(&self) -> Result<Vec<ExternalEndpoint>, ApplicationError>;
    async fn endpoint_binding(&self, _id: BindingId) -> Result<EndpointBinding, ApplicationError> {
        Err(ApplicationError::NotFound("endpoint binding"))
    }
    async fn access_policy(&self, _id: PolicyId) -> Result<AccessPolicy, ApplicationError> {
        Err(ApplicationError::NotFound("access policy"))
    }
    async fn sessions(&self) -> Result<Vec<ChangeSession>, ApplicationError>;
    async fn operations(&self) -> Result<Vec<Operation>, ApplicationError>;
    async fn backups(&self) -> Result<Vec<BackupReference>, ApplicationError>;
    /// Return the current persisted retirement blockers for a service. A
    /// storage adapter must implement this query; the fail-closed default is
    /// used by test repositories that do not model retirement.
    async fn retirement_safety(
        &self,
        _service: ServiceId,
    ) -> Result<RetirementSafety, ApplicationError> {
        Err(ApplicationError::NotFound("retirement safety"))
    }
    /// Authorize a content-addressed blob for one actor/session. Implementations
    /// must check the persisted ownership row, exact digest/size/classification,
    /// active session, and expiry; CAS presence alone is never authorization.
    async fn staged_content_for_actor(
        &self,
        session: ChangeSessionId,
        actor: ActorId,
        content: &StagedContentRef,
        classification: FileClassification,
        required_until: u64,
    ) -> Result<StagedContentOwnership, ApplicationError>;
    /// Resolve a persisted opaque provider binding only inside the requested
    /// service and cluster scope. Adapters must fail closed for unowned or
    /// ambiguous bindings.
    async fn gameap_binding(
        &self,
        _id: BindingId,
        _service: ServiceId,
        _cluster: ClusterId,
    ) -> Result<GameAPBinding, ApplicationError> {
        Err(ApplicationError::NotFound("gameap binding"))
    }
    /// Resolve a change session together with the persisted actor ownership.
    /// The default deliberately fails closed; adapters with change-session
    /// persistence must implement this method rather than infer ownership from
    /// a request payload.
    async fn change_session_for_actor(
        &self,
        _id: ChangeSessionId,
        _actor: ActorId,
    ) -> Result<ChangeSession, ApplicationError> {
        Err(ApplicationError::NotFound("change session"))
    }
    async fn plan(&self, _id: PlanId) -> Result<PlanDescriptor, ApplicationError> {
        Err(ApplicationError::NotFound("plan"))
    }
    /// Return the owning session recorded with a persisted plan. Execution
    /// paths use this association to reject a valid plan replayed through a
    /// different session.
    async fn plan_session(&self, _id: PlanId) -> Result<ChangeSessionId, ApplicationError> {
        Err(ApplicationError::NotFound("plan"))
    }
    /// Resolve the cluster that owns a typed plan target. Adapters must use
    /// persisted ownership relationships; a target's display string is never
    /// interpreted as a cluster identifier.
    async fn cluster_for_plan_target(
        &self,
        target: PlanTarget,
        _service: ServiceId,
    ) -> Result<ClusterId, ApplicationError> {
        match target {
            PlanTarget::Cluster(cluster) => Ok(cluster),
            _ => Err(ApplicationError::NotFound("plan target cluster")),
        }
    }
    async fn transaction(&self) -> Result<Box<dyn UnitOfWork>, ApplicationError>;
}
#[async_trait]
pub trait UnitOfWork: Send {
    async fn save_session_for_actor(
        &mut self,
        session: ChangeSession,
        actor: ActorId,
    ) -> Result<(), ApplicationError>;
    /// Atomically associate a user-created session with its begin request. A
    /// successful replay returns the original session and does not enqueue a
    /// second insert. Every adapter must implement the idempotency check in
    /// its transaction; silently falling back to an ordinary save is unsafe.
    async fn save_session_idempotent_for_actor(
        &mut self,
        session: ChangeSession,
        actor: ActorId,
        idempotency_key: &str,
        request_hash: &str,
        audit: AuditEvent,
    ) -> Result<Option<ChangeSession>, ApplicationError>;
    async fn save_plan_idempotent(
        &mut self,
        plan: PlanDescriptor,
        session: ChangeSessionId,
        idempotency_key: &str,
        request_hash: &str,
        audit: AuditEvent,
    ) -> Result<Option<PlanDescriptor>, ApplicationError>;
    async fn commit(self: Box<Self>) -> Result<(), ApplicationError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionStatus {
    pub running: bool,
    pub state_hash: String,
    pub node: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileEntry {
    pub path: String,
    pub classification: FileClassification,
    pub digest: String,
    pub size: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileChange {
    pub path: String,
    pub content_digest: String,
    pub classification: FileClassification,
}
/// A complete file mutation owned by the application boundary. `bytes` are
/// kept here so adapters cannot invent content, while `expected_before` makes
/// the compare-and-set precondition explicit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileMutation {
    pub change: FileChange,
    pub bytes: Vec<u8>,
    pub expected_before: Option<String>,
    pub mode: FileMutationMode,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileRestoreSnapshot {
    pub path: String,
    pub bytes: Vec<u8>,
    pub digest: String,
    pub classification: FileClassification,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileMutationMode {
    Text,
    Binary,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileSnapshot {
    pub files: Vec<FileEntry>,
    pub digest: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DiffKind {
    Added,
    Removed,
    Changed,
    Conflict,
    Unchanged,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileDiff {
    pub path: String,
    pub kind: DiffKind,
    pub classification: FileClassification,
}
pub fn snapshot_files(mut files: Vec<FileEntry>) -> FileSnapshot {
    files.sort_by(|a, b| a.path.cmp(&b.path));
    let digest = files
        .iter()
        .map(|f| format!("{}:{}:{}", f.path, f.digest, f.size))
        .collect::<Vec<_>>()
        .join("|");
    FileSnapshot { files, digest }
}

/// Convert a content-addressed baseline manifest into the comparison shape
/// used by the application. A baseline has no file bytes, so its entries use
/// a zero size; diffing compares the digest and classification rather than
/// retaining or reconstructing file contents.
pub fn snapshot_from_config_baseline(
    baseline: &ConfigBaseline,
) -> Result<FileSnapshot, ApplicationError> {
    baseline
        .validate()
        .map_err(|_| ApplicationError::Conflict("invalid config baseline"))?;
    Ok(snapshot_files(
        baseline
            .files
            .iter()
            .map(|entry| FileEntry {
                path: entry.path.clone(),
                classification: entry.classification.clone(),
                digest: entry.digest.clone(),
                size: 0,
            })
            .collect(),
    ))
}

pub fn diff_files(before: &FileSnapshot, after: &FileSnapshot) -> Vec<FileDiff> {
    let old = before
        .files
        .iter()
        .map(|f| (&f.path, f))
        .collect::<BTreeMap<_, _>>();
    let new = after
        .files
        .iter()
        .map(|f| (&f.path, f))
        .collect::<BTreeMap<_, _>>();
    old.keys()
        .chain(new.keys())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .map(|path| match (old.get(path), new.get(path)) {
            (None, Some(v)) => FileDiff {
                path: (*path).clone(),
                kind: DiffKind::Added,
                classification: v.classification.clone(),
            },
            (Some(v), None) => FileDiff {
                path: (*path).clone(),
                kind: DiffKind::Removed,
                classification: v.classification.clone(),
            },
            (Some(a), Some(b)) => FileDiff {
                path: (*path).clone(),
                kind: if a.digest == b.digest {
                    DiffKind::Unchanged
                } else {
                    DiffKind::Changed
                },
                classification: b.classification.clone(),
            },
            _ => unreachable!(),
        })
        .collect()
}
pub fn three_way_diff(
    base: &FileSnapshot,
    ours: &FileSnapshot,
    theirs: &FileSnapshot,
) -> Vec<FileDiff> {
    let mut result = Vec::new();
    let paths = base
        .files
        .iter()
        .chain(ours.files.iter())
        .chain(theirs.files.iter())
        .map(|f| f.path.clone())
        .collect::<std::collections::BTreeSet<_>>();
    for path in paths {
        let value = |snapshot: &FileSnapshot| {
            snapshot
                .files
                .iter()
                .find(|f| f.path == path)
                .map(|f| (f.digest.clone(), f.classification.clone()))
        };
        let (b, o, t) = (value(base), value(ours), value(theirs));
        let kind = if o == t {
            DiffKind::Unchanged
        } else if o == b || t == b {
            DiffKind::Changed
        } else {
            DiffKind::Conflict
        };
        result.push(FileDiff {
            path,
            kind,
            classification: o
                .or(t)
                .or(b)
                .map(|(_, c)| c)
                .unwrap_or(FileClassification::Unknown),
        });
    }
    result
}
/// Opaque execution capability; GameAP concepts never cross this boundary.
#[async_trait]
pub trait ExecutionBackend: Send + Sync {
    async fn create(&self, binding: &GameAPBinding) -> Result<(), ApplicationError>;
    async fn delete(&self, binding: &GameAPBinding) -> Result<(), ApplicationError>;
    async fn start(&self, binding: &GameAPBinding) -> Result<(), ApplicationError>;
    async fn stop(&self, binding: &GameAPBinding) -> Result<(), ApplicationError>;
    async fn restart(&self, binding: &GameAPBinding) -> Result<(), ApplicationError>;
    async fn status(&self, binding: &GameAPBinding) -> Result<ExecutionStatus, ApplicationError>;
    async fn files(
        &self,
        binding: &GameAPBinding,
        path: &str,
    ) -> Result<Vec<FileEntry>, ApplicationError>;
    async fn read_file(
        &self,
        binding: &GameAPBinding,
        path: &str,
    ) -> Result<Vec<u8>, ApplicationError>;
    async fn write_file(
        &self,
        binding: &GameAPBinding,
        change: &FileChange,
        bytes: &[u8],
    ) -> Result<(), ApplicationError>;
    async fn upload(
        &self,
        binding: &GameAPBinding,
        change: &FileChange,
        bytes: &[u8],
    ) -> Result<(), ApplicationError>;
    async fn download(
        &self,
        binding: &GameAPBinding,
        path: &str,
    ) -> Result<Vec<u8>, ApplicationError>;
    async fn move_file(
        &self,
        binding: &GameAPBinding,
        from: &str,
        to: &str,
    ) -> Result<(), ApplicationError>;
    /// Compare the source and destination before moving and fail closed if
    /// either side changed. Providers implement this through their native
    /// conditional operation; a backend without that capability cannot be
    /// used for a rollback-safe move.
    async fn move_file_checked(
        &self,
        _binding: &GameAPBinding,
        _from: &str,
        _to: &str,
        _expected_source_digest: &str,
        _expected_destination_digest: Option<&str>,
    ) -> Result<(), ApplicationError> {
        Err(ApplicationError::Conflict("checked file move unavailable"))
    }
    async fn quarantine(&self, binding: &GameAPBinding, path: &str)
    -> Result<(), ApplicationError>;
    async fn restore_quarantined_file_checked(
        &self,
        _binding: &GameAPBinding,
        _path: &str,
        _expected_digest: &str,
    ) -> Result<(), ApplicationError> {
        Err(ApplicationError::Conflict(
            "checked quarantine restore unavailable",
        ))
    }
    async fn delete_file_checked(
        &self,
        _binding: &GameAPBinding,
        _path: &str,
        _expected_digest: &str,
    ) -> Result<(), ApplicationError> {
        Err(ApplicationError::Conflict(
            "checked file delete unavailable",
        ))
    }
    async fn observe_file_optional(
        &self,
        _binding: &GameAPBinding,
        _path: &str,
    ) -> Result<Option<(String, u64)>, ApplicationError> {
        Err(ApplicationError::Conflict(
            "optional file observation unavailable",
        ))
    }
    async fn restore_file(
        &self,
        _binding: &GameAPBinding,
        _change: &FileChange,
    ) -> Result<(), ApplicationError> {
        Err(ApplicationError::Conflict("file rollback unavailable"))
    }
    async fn restore_file_snapshot(
        &self,
        binding: &GameAPBinding,
        snapshot: &FileRestoreSnapshot,
    ) -> Result<(), ApplicationError> {
        self.restore_file(
            binding,
            &FileChange {
                path: snapshot.path.clone(),
                content_digest: snapshot.digest.clone(),
                classification: snapshot.classification.clone(),
            },
        )
        .await
    }
    async fn command(
        &self,
        binding: &GameAPBinding,
        masked_command: &str,
    ) -> Result<(), ApplicationError>;
    /// Open an API-independent streaming console. Adapters translate this
    /// port to their provider's stream and must not expose provider types.
    async fn open_console(
        &self,
        _binding: &GameAPBinding,
    ) -> Result<Box<dyn ExecutionConsole>, ApplicationError> {
        Err(ApplicationError::Conflict("console stream unavailable"))
    }
}

/// A transport-neutral bidirectional console stream. `None` from `receive`
/// means the stream reached EOF; chunks are opaque bytes owned by the caller.
#[async_trait]
pub trait ExecutionConsole: Send {
    async fn send(&mut self, command: &str) -> Result<(), ApplicationError>;
    async fn receive(&mut self) -> Result<Option<Vec<u8>>, ApplicationError>;
    async fn close(&mut self) -> Result<(), ApplicationError>;
}
/// Application-owned identity for a TCPShield-compatible edge backend.
///
/// The adapter is responsible for translating these opaque values into its
/// provider request. Keeping the network, backend set, address, revision, and
/// observation hash together prevents a rollout from accidentally applying a
/// plan to a different edge object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyEdgeBinding {
    pub instance_id: ProxyInstanceId,
    pub provider_network_id: u64,
    pub domain_network_id: Option<NetworkId>,
    pub backend_set_id: String,
    pub backend_address: String,
    pub revision: RevisionId,
    pub observed_hash: String,
}
impl ProxyEdgeBinding {
    pub fn validate(&self) -> Result<(), ApplicationError> {
        if self.provider_network_id == 0
            || self.backend_set_id.trim().is_empty()
            || self.backend_address.trim().is_empty()
            || self.observed_hash.trim().is_empty()
        {
            return Err(ApplicationError::Conflict("incomplete proxy edge binding"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyEdgeObservation {
    pub instance_id: ProxyInstanceId,
    pub provider_network_id: u64,
    pub domain_network_id: Option<NetworkId>,
    pub backend_set_id: String,
    pub backend_address: String,
    pub revision: RevisionId,
    pub evidence_hash: String,
}
#[async_trait]
pub trait ProxyEdgeResolver: Send + Sync {
    async fn resolve(
        &self,
        binding: &ProxyEdgeBinding,
    ) -> Result<ProxyEdgeObservation, ApplicationError>;
}
#[async_trait]
pub trait ProxyEdge: Send + Sync {
    async fn prepare(&self, binding: &ProxyEdgeBinding) -> Result<(), ApplicationError>;
    async fn configure(&self, binding: &ProxyEdgeBinding) -> Result<(), ApplicationError>;
    async fn add(&self, binding: &ProxyEdgeBinding) -> Result<(), ApplicationError>;
    async fn remove(&self, binding: &ProxyEdgeBinding) -> Result<(), ApplicationError>;
    async fn drain(&self, binding: &ProxyEdgeBinding) -> Result<(), ApplicationError>;
    async fn real_connect(
        &self,
        binding: &ProxyEdgeBinding,
    ) -> Result<ConnectionEvidence, ApplicationError>;
    async fn stop(&self, binding: &ProxyEdgeBinding) -> Result<(), ApplicationError>;
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionEvidence {
    pub active: u64,
    pub observed: bool,
    pub hash: String,
}
#[async_trait]
pub trait ConnectionObserver: Send + Sync {
    async fn observe(&self, target: &str) -> Result<ConnectionEvidence, ApplicationError>;
}
#[async_trait]
pub trait WorldRuntime: Send + Sync {
    async fn stop_and_flush(
        &self,
        cluster: ClusterId,
        world: WorldId,
    ) -> Result<(), ApplicationError>;
    async fn start(&self, cluster: ClusterId, world: WorldId) -> Result<(), ApplicationError>;
}
#[async_trait]
pub trait WorldStorage: Send + Sync {
    async fn compare_and_swap_writer(
        &self,
        world: WorldId,
        expected_version: u64,
        expected: Option<ClusterId>,
        next: ClusterId,
    ) -> Result<(), ApplicationError>;
}
#[async_trait]
pub trait EndpointBindingStore: Send + Sync {
    async fn activate_revision(
        &self,
        expected: &EndpointBinding,
        target: &EndpointBinding,
        expected_version: u64,
    ) -> Result<(), ApplicationError>;
    async fn rollback_revision(
        &self,
        cluster: ClusterId,
        expected_binding: BindingId,
        target_binding: BindingId,
        expected_version: u64,
    ) -> Result<(), ApplicationError>;
}
#[async_trait]
pub trait EndpointRuntime: Send + Sync {
    async fn restart_and_reconnect(
        &self,
        binding: &EndpointBinding,
    ) -> Result<(), ApplicationError>;
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactCandidate {
    pub artifact: Artifact,
}
/// Bytes returned by an artifact source. The application computes the digest
/// before allowing them into the content-addressed store.
#[async_trait]
pub trait ArtifactProvider: Send + Sync {
    async fn discover(&self, query: &str) -> Result<Vec<ArtifactCandidate>, ApplicationError>;
    async fn download(&self, candidate: &ArtifactCandidate) -> Result<Vec<u8>, ApplicationError>;
}
#[async_trait]
pub trait ArtifactStore: Send + Sync {
    async fn has(&self, digest: &str) -> Result<bool, ApplicationError>;
    /// Store bytes under a digest after the application has verified them.
    /// Implementations must retain CAS semantics and must not activate files.
    async fn put(&self, digest: &str, bytes: &[u8]) -> Result<(), ApplicationError>;
    async fn read(&self, digest: &str) -> Result<Vec<u8>, ApplicationError>;
}
#[async_trait]
pub trait BackupProvider: Send + Sync {
    async fn create(&self, request: &BackupRequest) -> Result<BackupReference, ApplicationError>;
    async fn verify(
        &self,
        reference: &BackupReference,
    ) -> Result<BackupObservation, ApplicationError>;
    /// Apply a restore once and return the opaque provider invocation. This
    /// invocation is persisted as operation evidence and is the only input
    /// accepted by `verify_restore` during the later change-session verify.
    async fn restore(
        &self,
        request: &BackupRestoreRequest,
    ) -> Result<BackupRestoreInvocation, ApplicationError>;
    async fn verify_restore(
        &self,
        invocation: &BackupRestoreInvocation,
    ) -> Result<BackupObservation, ApplicationError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupRequest {
    pub session_id: ChangeSessionId,
    pub kind: BackupKind,
    pub target: BackupTarget,
    pub idempotency_key: String,
    pub request_hash: String,
    /// Verified component references for a service-consistent manifest. The
    /// application fills this from durable same-session references; callers
    /// must not invent component identities.
    pub components: Vec<BackupComponent>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BackupComponent {
    pub reference_id: BackupReferenceId,
    pub kind: BackupKind,
    pub target: BackupTarget,
    pub provider_reference: String,
    pub manifest_digest: String,
}

impl BackupRequest {
    pub fn validate(&self) -> Result<(), ApplicationError> {
        if self.idempotency_key.trim().is_empty() || self.request_hash.trim().is_empty() {
            return Err(ApplicationError::Conflict("backup request identity"));
        }
        if self.kind != BackupKind::ServiceConsistent {
            if self.components.is_empty() {
                return Ok(());
            }
            return Err(ApplicationError::Conflict(
                "backup components on non-manifest",
            ));
        }
        if !matches!(self.target, BackupTarget::Service(_)) || self.components.is_empty() {
            return Err(ApplicationError::Conflict(
                "service-consistent backup components",
            ));
        }
        let mut ids = std::collections::BTreeSet::new();
        let mut world_ids = std::collections::BTreeSet::new();
        let mut worlds = 0_u8;
        let mut databases = 0_u8;
        for component in &self.components {
            if component.reference_id.as_uuid().is_nil()
                || !ids.insert(component.reference_id)
                || component.provider_reference.trim().is_empty()
                || component.manifest_digest.len() != 64
                || !component
                    .manifest_digest
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit())
            {
                return Err(ApplicationError::Conflict("invalid backup component"));
            }
            match component.kind {
                BackupKind::World => {
                    let BackupTarget::World(world_id) = component.target else {
                        return Err(ApplicationError::Conflict("backup world component target"));
                    };
                    if !world_ids.insert(world_id) {
                        return Err(ApplicationError::Conflict(
                            "duplicate service backup world component",
                        ));
                    }
                    worlds = worlds.saturating_add(1);
                }
                BackupKind::ExternalDatabaseReference => {
                    if component.target != self.target {
                        return Err(ApplicationError::Conflict(
                            "backup database component target",
                        ));
                    }
                    databases = databases.saturating_add(1);
                }
                BackupKind::ChangeSnapshot | BackupKind::ServiceConsistent => {
                    return Err(ApplicationError::Conflict(
                        "invalid service backup component",
                    ));
                }
            }
        }
        if worlds == 0 || databases != 1 {
            return Err(ApplicationError::Conflict(
                "incomplete service backup components",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BackupRestoreRequest {
    pub session_id: ChangeSessionId,
    pub plan_id: PlanId,
    pub plan_expiry: u64,
    pub idempotency_key: String,
    pub reference: BackupReference,
    /// Verified pre-restore snapshot used by compensation.
    pub rollback_reference: BackupReference,
    pub target: BackupTarget,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BackupRestoreInvocation {
    pub plan_id: PlanId,
    pub reference_id: BackupReferenceId,
    pub target: BackupTarget,
    pub expected_manifest_digest: String,
    pub rollback_reference_id: BackupReferenceId,
    pub expected_rollback_manifest_digest: String,
    pub provider_invocation: String,
}
/// Explicit fail-closed implementation used until an approved backup
/// infrastructure adapter is configured; it never pretends a backup exists.
pub struct UnconfiguredBackupProvider;
#[async_trait]
impl BackupProvider for UnconfiguredBackupProvider {
    async fn create(&self, _request: &BackupRequest) -> Result<BackupReference, ApplicationError> {
        Err(ApplicationError::BackupUnavailable)
    }
    async fn verify(
        &self,
        _reference: &BackupReference,
    ) -> Result<BackupObservation, ApplicationError> {
        Err(ApplicationError::BackupUnavailable)
    }
    async fn restore(
        &self,
        _request: &BackupRestoreRequest,
    ) -> Result<BackupRestoreInvocation, ApplicationError> {
        Err(ApplicationError::BackupUnavailable)
    }
    async fn verify_restore(
        &self,
        _invocation: &BackupRestoreInvocation,
    ) -> Result<BackupObservation, ApplicationError> {
        Err(ApplicationError::BackupUnavailable)
    }
}
#[async_trait]
pub trait DnsResolver: Send + Sync {
    async fn resolve(&self, hostname: &str, port: u16) -> Result<Vec<String>, ApplicationError>;
}
#[async_trait]
pub trait HealthVerifier: Send + Sync {
    async fn verify(&self, target: &str) -> Result<(), ApplicationError>;
}
#[async_trait]
pub trait AuditSink: Send + Sync {
    async fn record(&self, event: AuditEvent) -> Result<(), ApplicationError>;
}
#[async_trait]
impl<T: AuditSink + ?Sized> AuditSink for &T {
    async fn record(&self, event: AuditEvent) -> Result<(), ApplicationError> {
        (**self).record(event).await
    }
}

fn audit_scope_for_binding(
    service_id: ServiceId,
    binding: &GameAPBinding,
) -> Result<AuditScope, ApplicationError> {
    let mut scope = AuditScope::for_execution_unit(service_id, binding.execution_unit_id.clone())
        .map_err(|_| ApplicationError::Conflict("invalid audit scope"))?;
    match &binding.target {
        GameAPBindingTarget::Cluster(cluster_id) => {
            scope = scope.with_cluster(*cluster_id);
        }
        GameAPBindingTarget::World(world_id) => {
            scope = scope.with_world(*world_id);
        }
        GameAPBindingTarget::Service(_)
        | GameAPBindingTarget::ExecutionUnit(_)
        | GameAPBindingTarget::ProxyInstance(_) => {}
    }
    Ok(scope)
}

#[allow(clippy::too_many_arguments)]
fn application_audit_event(
    actor: ActorId,
    action: impl Into<String>,
    target: impl Into<String>,
    classification: FileClassification,
    scope: AuditScope,
    result: AuditResult,
    before_revision: Option<u64>,
    after_revision: Option<u64>,
    plan_hash: Option<String>,
    request_id: Option<String>,
    evidence: Vec<String>,
) -> AuditEvent {
    AuditEvent {
        actor,
        action: action.into(),
        target: target.into(),
        classification,
        scope,
        source: AuditSource::Application,
        result,
        before_revision,
        after_revision,
        plan_hash,
        request_id,
        evidence,
    }
}

fn validate_begin_audit(
    audit: &AuditEvent,
    actor: ActorId,
    service: ServiceId,
    cluster: ClusterId,
    idempotency_key: &str,
) -> Result<(), ApplicationError> {
    if audit.validate().is_err()
        || audit.actor != actor
        || audit.action != "change.begin"
        || audit.target != cluster.as_uuid().to_string()
        || audit.classification != FileClassification::Managed
        || audit.scope != AuditScope::for_cluster(service, cluster)
        || audit.source != AuditSource::Application
        || audit.result != AuditResult::Success
        || audit.before_revision.is_some()
        || audit.after_revision.is_some()
        || audit.plan_hash.is_some()
        || audit.request_id.as_deref() != Some(idempotency_key)
        || !audit.evidence.is_empty()
    {
        return Err(ApplicationError::Conflict("change begin audit event"));
    }
    Ok(())
}

#[async_trait]
pub trait Clock: Send + Sync {
    async fn now(&self) -> u64;
}

/// Durable operation identity. Adapters persist this tuple and return the
/// original operation for a repeated request, making controller restarts safe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationRequest {
    pub key: String,
    pub actor: ActorId,
    pub service: ServiceId,
    pub session_id: ChangeSessionId,
    pub target: String,
    pub request_hash: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationLease {
    pub operation: OperationId,
    pub holder: String,
    pub attempt: u32,
    pub expires_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationFailure {
    pub code: String,
    pub evidence: Vec<String>,
}

impl OperationFailure {
    pub fn from_error(error: &ApplicationError, evidence: Vec<String>) -> Self {
        let code = match error {
            ApplicationError::NotFound(_) => "not_found",
            ApplicationError::Forbidden => "forbidden",
            ApplicationError::Conflict(_) => "conflict",
            ApplicationError::RollbackConflict(_) => "rollback_conflict",
            ApplicationError::StalePlan => "stale_plan",
            ApplicationError::ExpiredPlan => "expired_plan",
            ApplicationError::Replay => "replay",
            ApplicationError::BackupUnavailable => "backup_unavailable",
            ApplicationError::VerificationFailed(_) => "verification_failed",
            ApplicationError::Port(_) => "port",
        };
        Self {
            code: code.into(),
            evidence,
        }
    }
}

#[async_trait]
pub trait OperationStore: Send + Sync {
    async fn find_idempotent(
        &self,
        request: &OperationRequest,
    ) -> Result<Option<Operation>, ApplicationError>;
    async fn acquire_lease(
        &self,
        operation: OperationId,
        holder: &str,
        now: u64,
        ttl: u64,
    ) -> Result<OperationLease, ApplicationError>;
    async fn release_lease(&self, lease: &OperationLease) -> Result<(), ApplicationError>;
    async fn create_idempotent(
        &self,
        request: &OperationRequest,
        operation: Operation,
    ) -> Result<Operation, ApplicationError>;
    /// A plan may have only one durable execution operation. Adapters must
    /// resolve this relationship from persisted state before accepting a
    /// second apply identity for the same plan.
    async fn operation_for_plan(&self, plan: PlanId)
    -> Result<Option<Operation>, ApplicationError>;
    async fn operation(&self, id: OperationId) -> Result<Operation, ApplicationError>;
    async fn record_step_owned(
        &self,
        operation: OperationId,
        evidence: StepEvidence,
        holder: &str,
    ) -> Result<(), ApplicationError>;
    async fn step_evidence(
        &self,
        operation: OperationId,
    ) -> Result<Vec<StepEvidence>, ApplicationError>;
    async fn mark_state(
        &self,
        operation: OperationId,
        state: OperationState,
        holder: &str,
    ) -> Result<(), ApplicationError>;
    async fn renew_lease(
        &self,
        lease: &OperationLease,
        ttl: u64,
    ) -> Result<OperationLease, ApplicationError>;
    async fn finish_operation(
        &self,
        lease: &OperationLease,
        state: OperationState,
        result: serde_json::Value,
    ) -> Result<Operation, ApplicationError>;
    /// Atomically record verified postconditions and synchronize the owning
    /// change session. This leaves the operation pending acceptance.
    async fn finish_verified(
        &self,
        lease: &OperationLease,
        session: ChangeSessionId,
        evidence: Vec<String>,
    ) -> Result<Operation, ApplicationError>;
    /// Atomically accept an operation and its owning change session.
    async fn finish_accepted(
        &self,
        lease: &OperationLease,
        session: ChangeSessionId,
    ) -> Result<Operation, ApplicationError>;
    async fn finish_rolled_back(
        &self,
        lease: &OperationLease,
        session: ChangeSessionId,
    ) -> Result<Operation, ApplicationError>;
    /// Atomically persist a terminal failure, retain its code/evidence, and
    /// clear the lease. The holder predicate must be part of this write so a
    /// worker whose lease expired cannot overwrite a newer worker's state.
    async fn fail_operation(
        &self,
        operation: OperationId,
        failure: OperationFailure,
        holder: &str,
    ) -> Result<(), ApplicationError>;
}
#[async_trait]
impl<T: OperationStore + ?Sized> OperationStore for &T {
    async fn find_idempotent(
        &self,
        request: &OperationRequest,
    ) -> Result<Option<Operation>, ApplicationError> {
        (**self).find_idempotent(request).await
    }
    async fn acquire_lease(
        &self,
        operation: OperationId,
        holder: &str,
        now: u64,
        ttl: u64,
    ) -> Result<OperationLease, ApplicationError> {
        (**self).acquire_lease(operation, holder, now, ttl).await
    }
    async fn release_lease(&self, lease: &OperationLease) -> Result<(), ApplicationError> {
        (**self).release_lease(lease).await
    }
    async fn create_idempotent(
        &self,
        request: &OperationRequest,
        operation: Operation,
    ) -> Result<Operation, ApplicationError> {
        (**self).create_idempotent(request, operation).await
    }
    async fn operation_for_plan(
        &self,
        plan: PlanId,
    ) -> Result<Option<Operation>, ApplicationError> {
        (**self).operation_for_plan(plan).await
    }
    async fn operation(&self, id: OperationId) -> Result<Operation, ApplicationError> {
        (**self).operation(id).await
    }
    async fn record_step_owned(
        &self,
        operation: OperationId,
        evidence: StepEvidence,
        holder: &str,
    ) -> Result<(), ApplicationError> {
        (**self)
            .record_step_owned(operation, evidence, holder)
            .await
    }
    async fn step_evidence(
        &self,
        operation: OperationId,
    ) -> Result<Vec<StepEvidence>, ApplicationError> {
        (**self).step_evidence(operation).await
    }
    async fn mark_state(
        &self,
        operation: OperationId,
        state: OperationState,
        holder: &str,
    ) -> Result<(), ApplicationError> {
        (**self).mark_state(operation, state, holder).await
    }
    async fn renew_lease(
        &self,
        lease: &OperationLease,
        ttl: u64,
    ) -> Result<OperationLease, ApplicationError> {
        (**self).renew_lease(lease, ttl).await
    }
    async fn finish_operation(
        &self,
        lease: &OperationLease,
        state: OperationState,
        result: serde_json::Value,
    ) -> Result<Operation, ApplicationError> {
        (**self).finish_operation(lease, state, result).await
    }
    async fn finish_verified(
        &self,
        lease: &OperationLease,
        session: ChangeSessionId,
        evidence: Vec<String>,
    ) -> Result<Operation, ApplicationError> {
        (**self).finish_verified(lease, session, evidence).await
    }
    async fn finish_accepted(
        &self,
        lease: &OperationLease,
        session: ChangeSessionId,
    ) -> Result<Operation, ApplicationError> {
        (**self).finish_accepted(lease, session).await
    }
    async fn finish_rolled_back(
        &self,
        lease: &OperationLease,
        session: ChangeSessionId,
    ) -> Result<Operation, ApplicationError> {
        (**self).finish_rolled_back(lease, session).await
    }
    async fn fail_operation(
        &self,
        operation: OperationId,
        failure: OperationFailure,
        holder: &str,
    ) -> Result<(), ApplicationError> {
        (**self).fail_operation(operation, failure, holder).await
    }
}

/// The finite set of high-impact work the controller may ask the application
/// layer to perform. It is deliberately typed instead of accepting a command
/// language or adapter payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OperationStep {
    ExecutionProvision {
        binding: GameAPBinding,
    },
    ExecutionDelete {
        binding: GameAPBinding,
        expected_state_hash: String,
        expected_version: u64,
        session_id: ChangeSessionId,
    },
    ServiceLifecycleTransition {
        service_id: ServiceId,
        expected_state: ServiceLifecycle,
        next_state: ServiceLifecycle,
        expected_version: u64,
        reason: String,
    },
    ClusterRevisionCreate {
        cluster: ClusterId,
        revision: ClusterRevision,
        new_endpoint_bindings: Vec<EndpointBinding>,
        expected_current_number: Option<u64>,
    },
    ExecutionStart {
        binding: GameAPBinding,
    },
    ExecutionStop {
        binding: GameAPBinding,
    },
    ExecutionRestart {
        binding: GameAPBinding,
    },
    FileWrite {
        binding: GameAPBinding,
        change: FileChange,
        content: StagedContentRef,
        expected_before_digest: Option<String>,
        domain_revision: u64,
    },
    FileMove {
        binding: GameAPBinding,
        from: String,
        to: String,
        expected_before_digest: Option<String>,
        expected_target_digest: Option<String>,
        classification: FileClassification,
        domain_revision: u64,
    },
    FileQuarantine {
        binding: GameAPBinding,
        path: String,
        expected_before_digest: Option<String>,
        classification: FileClassification,
        domain_revision: u64,
    },
    FileBatch {
        binding: GameAPBinding,
        operations: Vec<FileBatchOperation>,
        domain_revision: u64,
    },
    ArtifactStage {
        artifact: ArtifactId,
        expected_digest: String,
        expected_version: u64,
        domain_revision: u64,
    },
    ArtifactRegister {
        artifact: Artifact,
        content: StagedContentRef,
        expected_version: u64,
        domain_revision: u64,
    },
    ArtifactActivate {
        binding_id: BindingId,
        binding: GameAPBinding,
        artifact: ArtifactId,
        artifact_set: ArtifactSetId,
        cluster: ClusterId,
        expected_revision: RevisionId,
        target_revision: RevisionId,
        expected_digest: String,
        expected_version: u64,
        destination_path: String,
        expected_before_digest: Option<String>,
    },
    ProxyRollout {
        expected_instance: ProxyInstanceId,
        target_instance: ProxyInstanceId,
        pool: ProxyPoolId,
        binding: GameAPBinding,
        expected_instance_version: u64,
        target_instance_version: u64,
        expected_instance_state: ProxyState,
        target_instance_state: ProxyState,
        target_binding_id: BindingId,
        domain_revision: u64,
        desired_state: ProxyState,
        configuration: Vec<FileBatchOperation>,
    },
    WorldWriterCutover {
        world: WorldId,
        from: Option<ClusterId>,
        to: ClusterId,
        expected_version: u64,
        expected_writer_binding_id: Option<BindingId>,
        target_writer_binding_id: BindingId,
        expected_writer_binding_hash: Option<String>,
        target_writer_binding_hash: String,
        domain_revision: u64,
        session_id: ChangeSessionId,
    },
    EndpointReconnect {
        expected_binding_id: BindingId,
        target_binding_id: BindingId,
        cluster: ClusterId,
        expected_version: u64,
        expected_revision: RevisionId,
        target_revision: RevisionId,
        runtime_binding_ids: Vec<BindingId>,
        runtime_binding_hashes: Vec<String>,
    },
    BackupCreate {
        session_id: ChangeSessionId,
        plan_id: PlanId,
        plan_expiry: u64,
        idempotency_key: String,
        kind: BackupKind,
        target: BackupTarget,
        request_hash: String,
    },
    BackupRestore {
        session_id: ChangeSessionId,
        plan_id: PlanId,
        plan_expiry: u64,
        idempotency_key: String,
        reference: BackupReferenceId,
        target: BackupTarget,
        expected_manifest_digest: String,
        rollback_reference: BackupReferenceId,
        expected_rollback_manifest_digest: String,
        expected_version: u64,
    },
    AccessPolicyUpdate {
        policy_id: PolicyId,
        service_id: ServiceId,
        expected_version: u64,
        desired_grants: Vec<AccessGrant>,
        desired_policy_hash: String,
    },
    RoutePolicyUpdate {
        route_id: RouteId,
        pool_id: ProxyPoolId,
        service_id: ServiceId,
        expected_cluster: ClusterId,
        target_cluster: ClusterId,
        expected_priority: u32,
        target_priority: u32,
        expected_version: u64,
        disabled: bool,
    },
    ServiceArchive {
        service_id: ServiceId,
        expected_version: u64,
        sunsetting_evidence_hash: String,
        session_id: ChangeSessionId,
    },
    ServicePurge {
        service_id: ServiceId,
        expected_version: u64,
        archive_evidence_hash: String,
        verified_backup_id: BackupReferenceId,
        archived_at: u64,
        session_id: ChangeSessionId,
    },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepObservation {
    pub state_hash: String,
    pub completed: bool,
    pub unambiguous: bool,
}
/// Result of an external mutation. Inverse evidence is returned by the
/// provider before control is released, so rollback can never guess from the
/// desired plan state after a crash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepApplyResult {
    pub observation: StepObservation,
    pub evidence: Option<StepExecutionEvidence>,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FileInverse {
    pub binding_id: BindingId,
    pub path: String,
    pub prior_digest: Option<String>,
    pub prior_size: Option<u64>,
    pub prior_exists: bool,
    pub target_path: Option<String>,
    pub target_digest: Option<String>,
    pub target_size: Option<u64>,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EndpointRuntimeObservation {
    pub binding_id: BindingId,
    pub prior_running: bool,
    pub prior_state_hash: String,
}
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum StepExecutionEvidence {
    BackupCreate(BackupReference),
    BackupRestore(BackupRestoreInvocation),
    File {
        inverse: FileInverse,
    },
    FileBatch {
        entries: Vec<FileInverse>,
    },
    Execution {
        binding_id: BindingId,
        prior_state_hash: String,
        prior_running: bool,
        prior_exists: bool,
        prior_binding: Option<GameAPBinding>,
        created_provider_unit: Option<String>,
        provider_idempotency_key: String,
    },
    Lifecycle {
        service_id: ServiceId,
        prior_state: ServiceLifecycle,
    },
    Artifact {
        binding_id: BindingId,
        cluster_id: ClusterId,
        prior_revision: Option<RevisionId>,
        destination_path: String,
        prior_digest: Option<String>,
        prior_size: Option<u64>,
        prior_exists: bool,
    },
    Proxy {
        expected_instance_id: ProxyInstanceId,
        target_instance_id: ProxyInstanceId,
        prior_expected_state: ProxyState,
        prior_expected_version: u64,
        prior_target_state: ProxyState,
        prior_target_version: u64,
        prior_edge_hash: String,
        prior_target_member: bool,
        new_state: ProxyState,
        new_version: u64,
        post_add_edge_hash: String,
        final_edge_hash: String,
        target_execution_existed: bool,
        target_execution_was_running: bool,
        target_execution_created: bool,
        target_execution_started: bool,
        old_execution_was_running: bool,
        configuration_inverse: Vec<FileInverse>,
    },
    World {
        world_id: WorldId,
        prior_writer: Option<ClusterId>,
        prior_version: u64,
        expected_writer_binding_id: Option<BindingId>,
        target_writer_binding_id: BindingId,
        prior_writer_binding_hash: Option<String>,
        target_writer_binding_hash: String,
    },
    Endpoint {
        expected_binding_id: BindingId,
        target_binding_id: BindingId,
        prior_revision: RevisionId,
        prior_binding: EndpointBinding,
        target_binding: EndpointBinding,
        runtime: Vec<EndpointRuntimeObservation>,
    },
    Access {
        policy_id: PolicyId,
        prior_policy_hash: String,
        prior_grants: Vec<AccessGrant>,
    },
    Route {
        route_id: RouteId,
        prior_cluster: ClusterId,
        prior_priority: u32,
        prior_disabled: bool,
        prior_version: u64,
    },
    Noop,
}
impl StepExecutionEvidence {
    fn valid_hash(value: &str) -> bool {
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
    }

    fn validate_file_inverse(inverse: &FileInverse) -> Result<(), ApplicationError> {
        if inverse.binding_id.as_uuid().is_nil() || inverse.path.trim().is_empty() {
            return Err(ApplicationError::StalePlan);
        }
        if inverse
            .prior_digest
            .as_deref()
            .is_some_and(|value| !Self::valid_hash(value))
            || inverse
                .target_digest
                .as_deref()
                .is_some_and(|value| !Self::valid_hash(value))
            || inverse
                .target_path
                .as_deref()
                .is_some_and(|value| value.trim().is_empty())
            || inverse.prior_digest.is_some() != inverse.prior_size.is_some()
            || inverse.target_digest.is_some() != inverse.target_size.is_some()
        {
            return Err(ApplicationError::Conflict("invalid file inverse evidence"));
        }
        Ok(())
    }

    pub fn validate_for(&self, step: &OperationStep) -> Result<(), ApplicationError> {
        match (self, step) {
            (
                Self::BackupCreate(reference),
                OperationStep::BackupCreate {
                    session_id,
                    kind,
                    target,
                    ..
                },
            ) => {
                if reference.session_id != *session_id
                    || reference.kind != *kind
                    || reference.target != *target
                {
                    return Err(ApplicationError::StalePlan);
                }
                reference
                    .validate()
                    .map_err(|_| ApplicationError::Conflict("backup evidence is not verified"))
            }
            (
                Self::BackupRestore(invocation),
                OperationStep::BackupRestore {
                    plan_id,
                    reference,
                    target,
                    expected_manifest_digest,
                    rollback_reference,
                    expected_rollback_manifest_digest,
                    ..
                },
            ) => {
                if invocation.plan_id != *plan_id
                    || invocation.reference_id != *reference
                    || invocation.target != *target
                    || invocation.expected_manifest_digest != *expected_manifest_digest
                    || invocation.rollback_reference_id != *rollback_reference
                    || invocation.expected_rollback_manifest_digest
                        != *expected_rollback_manifest_digest
                    || invocation.provider_invocation.trim().is_empty()
                {
                    return Err(ApplicationError::StalePlan);
                }
                Ok(())
            }
            (
                Self::File { inverse },
                OperationStep::FileWrite { binding: _, .. }
                | OperationStep::FileMove { binding: _, .. }
                | OperationStep::FileQuarantine { binding: _, .. },
            ) => Self::validate_file_inverse(inverse),
            (Self::FileBatch { entries }, OperationStep::FileBatch { .. }) => {
                if entries.is_empty() || entries.len() > 1024 {
                    return Err(ApplicationError::Conflict("empty file inverse evidence"));
                }
                let mut paths = std::collections::BTreeSet::new();
                for inverse in entries {
                    Self::validate_file_inverse(inverse)?;
                    if !paths.insert(&inverse.path)
                        || inverse
                            .target_path
                            .as_ref()
                            .is_some_and(|path| !paths.insert(path))
                    {
                        return Err(ApplicationError::Conflict("duplicate file inverse path"));
                    }
                }
                Ok(())
            }
            (
                Self::Execution {
                    binding_id,
                    prior_state_hash,
                    prior_binding,
                    created_provider_unit,
                    provider_idempotency_key,
                    ..
                },
                OperationStep::ExecutionProvision { binding: _ }
                | OperationStep::ExecutionDelete { binding: _, .. }
                | OperationStep::ExecutionStart { binding: _ }
                | OperationStep::ExecutionStop { binding: _ }
                | OperationStep::ExecutionRestart { binding: _ },
            ) => {
                if binding_id.as_uuid().is_nil() || !Self::valid_hash(prior_state_hash) {
                    return Err(ApplicationError::StalePlan);
                }
                if matches!(step, OperationStep::ExecutionDelete { .. }) && prior_binding.is_none()
                {
                    return Err(ApplicationError::Conflict(
                        "execution delete lacks creation snapshot",
                    ));
                }
                if matches!(step, OperationStep::ExecutionProvision { .. })
                    && provider_idempotency_key.trim().is_empty()
                {
                    return Err(ApplicationError::Conflict(
                        "execution provision lacks idempotency identity",
                    ));
                }
                if matches!(step, OperationStep::ExecutionProvision { .. })
                    && !matches!(
                        created_provider_unit.as_deref(),
                        Some(provider_unit) if !provider_unit.trim().is_empty()
                    )
                {
                    return Err(ApplicationError::Conflict(
                        "execution provision lacks created provider identity",
                    ));
                }
                Ok(())
            }
            (
                Self::Lifecycle { service_id, .. },
                OperationStep::ServiceLifecycleTransition {
                    service_id: step_id,
                    ..
                },
            )
            | (
                Self::Lifecycle { service_id, .. },
                OperationStep::ServiceArchive {
                    service_id: step_id,
                    ..
                },
            ) => {
                if service_id != step_id {
                    Err(ApplicationError::StalePlan)
                } else {
                    Ok(())
                }
            }
            (
                Self::Artifact {
                    binding_id,
                    cluster_id,
                    destination_path,
                    prior_digest,
                    prior_size,
                    ..
                },
                OperationStep::ArtifactActivate { cluster, .. },
            ) => {
                if binding_id.as_uuid().is_nil()
                    || cluster_id != cluster
                    || destination_path.trim().is_empty()
                    || prior_digest
                        .as_deref()
                        .is_some_and(|value| !Self::valid_hash(value))
                    || prior_digest.is_some() != prior_size.is_some()
                {
                    Err(ApplicationError::StalePlan)
                } else {
                    Ok(())
                }
            }
            (
                Self::Artifact { cluster_id, .. },
                OperationStep::ClusterRevisionCreate { cluster, .. },
            ) => {
                if cluster_id != cluster {
                    Err(ApplicationError::StalePlan)
                } else {
                    Ok(())
                }
            }
            (
                Self::Proxy {
                    expected_instance_id,
                    target_instance_id,
                    prior_expected_version,
                    prior_target_version,
                    prior_edge_hash,
                    post_add_edge_hash,
                    final_edge_hash,
                    prior_target_member,
                    target_execution_existed,
                    target_execution_was_running,
                    target_execution_created,
                    target_execution_started,
                    configuration_inverse,
                    ..
                },
                OperationStep::ProxyRollout {
                    expected_instance,
                    target_instance,
                    configuration,
                    ..
                },
            ) => {
                if expected_instance_id != expected_instance
                    || target_instance_id != target_instance
                    || expected_instance_id.as_uuid().is_nil()
                    || target_instance_id.as_uuid().is_nil()
                    || *prior_expected_version == 0
                    || *prior_target_version == 0
                    || !Self::valid_hash(prior_edge_hash)
                    || !Self::valid_hash(post_add_edge_hash)
                    || !Self::valid_hash(final_edge_hash)
                    || *prior_target_member
                    || *target_execution_existed == *target_execution_created
                    || (*target_execution_started && *target_execution_was_running)
                    || configuration.is_empty()
                    || configuration_inverse.len() != configuration.len()
                {
                    Err(ApplicationError::StalePlan)
                } else {
                    for (operation, inverse) in configuration.iter().zip(configuration_inverse) {
                        let FileBatchOperation::Write {
                            path,
                            classification,
                            ..
                        } = operation
                        else {
                            return Err(ApplicationError::Conflict(
                                "proxy configuration action mismatch",
                            ));
                        };
                        if inverse.path != *path
                            || inverse.target_path.is_some()
                            || *classification != FileClassification::MutableConfig
                        {
                            return Err(ApplicationError::Conflict(
                                "proxy configuration inverse mismatch",
                            ));
                        }
                        Self::validate_file_inverse(inverse)?;
                    }
                    Ok(())
                }
            }
            (
                Self::World {
                    world_id,
                    prior_version,
                    expected_writer_binding_id,
                    target_writer_binding_id,
                    prior_writer_binding_hash,
                    target_writer_binding_hash,
                    ..
                },
                OperationStep::WorldWriterCutover {
                    world,
                    expected_version: step_expected_version,
                    expected_writer_binding_id: step_expected_writer_binding_id,
                    target_writer_binding_id: step_target_writer_binding_id,
                    expected_writer_binding_hash: step_expected_writer_binding_hash,
                    target_writer_binding_hash: step_target_writer_binding_hash,
                    domain_revision: step_domain_revision,
                    ..
                },
            ) => {
                if world_id != world
                    || *prior_version == 0
                    || *prior_version != *step_expected_version
                    || *step_domain_revision == 0
                    || expected_writer_binding_id != step_expected_writer_binding_id
                    || target_writer_binding_id != step_target_writer_binding_id
                    || prior_writer_binding_hash != step_expected_writer_binding_hash
                    || target_writer_binding_hash != step_target_writer_binding_hash
                    || target_writer_binding_id.as_uuid().is_nil()
                    || prior_writer_binding_hash
                        .as_deref()
                        .is_some_and(|value| !Self::valid_hash(value))
                    || !Self::valid_hash(target_writer_binding_hash)
                {
                    Err(ApplicationError::StalePlan)
                } else {
                    Ok(())
                }
            }
            (
                Self::Endpoint {
                    expected_binding_id,
                    target_binding_id,
                    prior_revision,
                    prior_binding,
                    target_binding,
                    runtime,
                },
                OperationStep::EndpointReconnect {
                    expected_binding_id: step_expected,
                    target_binding_id: step_target,
                    runtime_binding_ids,
                    ..
                },
            ) => {
                if expected_binding_id != step_expected
                    || target_binding_id != step_target
                    || prior_revision.as_uuid().is_nil()
                    || prior_binding.id != *step_expected
                    || prior_binding.revision_id != *prior_revision
                    || target_binding.id != *step_target
                    || target_binding.revision_id.as_uuid().is_nil()
                {
                    return Err(ApplicationError::StalePlan);
                }
                if runtime.len() != runtime_binding_ids.len() {
                    return Err(ApplicationError::Conflict(
                        "endpoint runtime evidence is incomplete",
                    ));
                }
                let mut observed = std::collections::BTreeSet::new();
                for entry in runtime {
                    if entry.binding_id.as_uuid().is_nil()
                        || !observed.insert(entry.binding_id)
                        || !runtime_binding_ids.contains(&entry.binding_id)
                        || !Self::valid_hash(&entry.prior_state_hash)
                    {
                        return Err(ApplicationError::Conflict(
                            "endpoint runtime evidence does not match plan",
                        ));
                    }
                }
                if observed.len() != runtime_binding_ids.len() {
                    return Err(ApplicationError::Conflict(
                        "endpoint runtime evidence does not match plan",
                    ));
                }
                Ok(())
            }
            (
                Self::Access {
                    policy_id,
                    prior_policy_hash,
                    ..
                },
                OperationStep::AccessPolicyUpdate {
                    policy_id: step_id, ..
                },
            ) => {
                if policy_id != step_id || !Self::valid_hash(prior_policy_hash) {
                    Err(ApplicationError::StalePlan)
                } else {
                    Ok(())
                }
            }
            (
                Self::Route {
                    route_id,
                    prior_cluster,
                    prior_version,
                    ..
                },
                OperationStep::RoutePolicyUpdate {
                    route_id: step_id, ..
                },
            ) => {
                if route_id != step_id || prior_cluster.as_uuid().is_nil() || *prior_version == 0 {
                    Err(ApplicationError::StalePlan)
                } else {
                    Ok(())
                }
            }
            (
                Self::Noop,
                OperationStep::ArtifactStage { .. }
                | OperationStep::ArtifactRegister { .. }
                | OperationStep::ClusterRevisionCreate { .. }
                | OperationStep::ServicePurge { .. },
            ) => Ok(()),
            _ => Err(ApplicationError::Conflict("step evidence/action mismatch")),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepEvidence {
    pub sequence: u32,
    pub state_hash: String,
    pub result: String,
    pub execution: Option<StepExecutionEvidence>,
}
#[async_trait]
pub trait DurableStepPort: Send + Sync {
    async fn observe(
        &self,
        step: &OperationStep,
        evidence: Option<&StepEvidence>,
    ) -> Result<StepObservation, ApplicationError>;
    async fn observe_restore(
        &self,
        step: &OperationStep,
        evidence: Option<&StepEvidence>,
    ) -> Result<StepObservation, ApplicationError>;
    async fn observe_backup(
        &self,
        step: &OperationStep,
        evidence: Option<&StepEvidence>,
    ) -> Result<StepObservation, ApplicationError>;
    /// Capture the inverse from the provider/CAS before applying the side
    /// effect. The executor durably records this result under the lease before
    /// invoking `apply`.
    async fn prepare(
        &self,
        step: &OperationStep,
    ) -> Result<Option<StepExecutionEvidence>, ApplicationError>;
    async fn apply(
        &self,
        step: &OperationStep,
        prepared: Option<&StepExecutionEvidence>,
    ) -> Result<StepApplyResult, ApplicationError>;
    async fn apply_backup(&self, step: &OperationStep)
    -> Result<BackupReference, ApplicationError>;
    async fn apply_restore(
        &self,
        step: &OperationStep,
    ) -> Result<BackupRestoreInvocation, ApplicationError>;
}
/// Provider-independent compensation port. Implementations must perform the
/// inverse of a step only when ownership is still held by the caller.
#[async_trait]
pub trait RollbackStepPort: Send + Sync {
    async fn rollback(
        &self,
        step: &OperationStep,
        evidence: Option<&StepEvidence>,
    ) -> Result<StepObservation, ApplicationError>;
}

async fn resolve_plan_steps<R: DomainRepository>(
    repository: &R,
    plan: &PlanDescriptor,
    service: ServiceId,
    session_id: ChangeSessionId,
) -> Result<Vec<OperationStep>, ApplicationError> {
    let cluster = plan_cluster_id(repository, plan, service).await?;
    let owner = repository.cluster(cluster).await?;
    if owner.service_id != service {
        return Err(ApplicationError::Forbidden);
    }
    let resolved = resolve_change_steps(repository, service, cluster, &plan.steps).await?;
    validate_plan_scope(repository, plan, service, cluster, session_id).await?;
    resolved
        .into_iter()
        .enumerate()
        .map(|(sequence, (step, binding))| {
            OperationStep::from_plan(&step, binding, plan.id, plan.expiry, session_id, sequence)
        })
        .collect()
}

#[allow(clippy::collapsible_match)]
async fn validate_plan_scope<R: DomainRepository>(
    repository: &R,
    plan: &PlanDescriptor,
    service: ServiceId,
    cluster: ClusterId,
    session_id: ChangeSessionId,
) -> Result<(), ApplicationError> {
    let service_record = repository.service(service).await?;
    if service_record.current_cluster != Some(cluster) {
        return Err(ApplicationError::Forbidden);
    }
    validate_service_consistent_sequence(repository, plan, service, cluster).await?;
    let persisted_backups = repository.backups().await?;
    // Planning may order a destructive step after a BackupCreate in the same
    // plan.  The create step is not treated as verified here; the controller
    // must re-read a persisted verified reference immediately before the
    // destructive provider call.
    let backup_available = |previous: &[PlanStep], kind: BackupKind, target: BackupTarget| {
        persisted_backups.iter().any(|backup| {
            backup.session_id == session_id
                && backup.kind == kind
                && backup.target == target
                && backup.verified_at.is_some()
        }) || previous.iter().any(|step| {
            matches!(
                step.action,
                PlanStepAction::BackupCreate {
                    kind: step_kind,
                    target: step_target,
                    ..
                } if step_kind == kind && step_target == target
            )
        })
    };
    let mut projected_lifecycle = service_record.lifecycle.clone();
    for (index, action) in plan.steps.iter().enumerate() {
        let previous = &plan.steps[..index];
        match &action.action {
            PlanStepAction::FileWrite {
                content,
                classification,
                ..
            } => {
                repository
                    .staged_content_for_actor(
                        session_id,
                        plan.actor,
                        content,
                        classification.clone(),
                        plan.expiry,
                    )
                    .await?;
            }
            PlanStepAction::FileBatch { operations, .. } => {
                for operation in operations {
                    if let FileBatchOperation::Write {
                        content,
                        classification,
                        ..
                    } = operation
                    {
                        repository
                            .staged_content_for_actor(
                                session_id,
                                plan.actor,
                                content,
                                classification.clone(),
                                plan.expiry,
                            )
                            .await?;
                    }
                }
            }
            PlanStepAction::ExecutionDelete { binding_id, .. } => {
                let binding = repository
                    .gameap_binding(*binding_id, service, cluster)
                    .await?;
                let required_backup = match binding.target {
                    GameAPBindingTarget::World(world_id) => {
                        let world = repository
                            .worlds()
                            .await?
                            .into_iter()
                            .find(|world| world.id == world_id)
                            .ok_or(ApplicationError::NotFound("world"))?;
                        if !world.current_writers.is_empty() {
                            return Err(ApplicationError::Conflict(
                                "execution delete has active world writer",
                            ));
                        }
                        (BackupKind::World, BackupTarget::World(world_id))
                    }
                    GameAPBindingTarget::Service(service_id) => (
                        BackupKind::ServiceConsistent,
                        BackupTarget::Service(service_id),
                    ),
                    GameAPBindingTarget::Cluster(cluster_id) => {
                        let owner = repository.cluster(cluster_id).await?;
                        (
                            BackupKind::ServiceConsistent,
                            BackupTarget::Service(owner.service_id),
                        )
                    }
                    GameAPBindingTarget::ExecutionUnit(_)
                    | GameAPBindingTarget::ProxyInstance(_) => (
                        BackupKind::ServiceConsistent,
                        BackupTarget::Service(service),
                    ),
                };
                if !backup_available(previous, required_backup.0, required_backup.1) {
                    return Err(ApplicationError::Conflict(
                        "execution delete backup ordering",
                    ));
                }
            }
            PlanStepAction::ServiceLifecycleTransition {
                service_id,
                expected_state,
                next_state,
                ..
            } => {
                if *service_id != service || projected_lifecycle != *expected_state {
                    return Err(ApplicationError::StalePlan);
                }
                let mut projected = service_record.clone();
                projected.lifecycle = projected_lifecycle.clone();
                projected
                    .transition(next_state.clone())
                    .map_err(|_| ApplicationError::Conflict("lifecycle transition ordering"))?;
                projected_lifecycle = next_state.clone();
            }
            PlanStepAction::ClusterRevisionCreate {
                cluster_id,
                revision,
                new_endpoint_bindings,
                expected_current_number,
            } => {
                if *cluster_id != cluster {
                    return Err(ApplicationError::Forbidden);
                }
                let revisions = repository.revisions().await?;
                if revisions.iter().any(|value| value.id == revision.id) {
                    return Err(ApplicationError::Conflict(
                        "cluster revision already exists",
                    ));
                }
                let current_number = repository
                    .cluster(cluster)
                    .await?
                    .current_revision
                    .and_then(|id| revisions.iter().find(|value| value.id == id))
                    .map(|value| value.number);
                if current_number != *expected_current_number {
                    return Err(ApplicationError::StalePlan);
                }
                if revision.number != current_number.map_or(1, |number| number.saturating_add(1)) {
                    return Err(ApplicationError::Conflict("cluster revision number"));
                }
                let binding_ids = new_endpoint_bindings
                    .iter()
                    .map(|binding| binding.id)
                    .collect::<std::collections::BTreeSet<_>>();
                let revision_binding_ids = revision
                    .endpoint_bindings
                    .iter()
                    .copied()
                    .collect::<std::collections::BTreeSet<_>>();
                if binding_ids.len() != new_endpoint_bindings.len()
                    || revision_binding_ids.len() != revision.endpoint_bindings.len()
                    || binding_ids != revision_binding_ids
                    || new_endpoint_bindings.iter().any(|binding| {
                        binding.cluster_id != *cluster_id || binding.revision_id != revision.id
                    })
                {
                    return Err(ApplicationError::Conflict(
                        "cluster revision endpoint bindings",
                    ));
                }
            }
            PlanStepAction::ArtifactRegister {
                artifact, content, ..
            } => {
                content
                    .validate()
                    .map_err(|_| ApplicationError::StalePlan)?;
                if content.digest != artifact.digest {
                    return Err(ApplicationError::StalePlan);
                }
                repository
                    .staged_content_for_actor(
                        session_id,
                        plan.actor,
                        content,
                        FileClassification::Artifact,
                        plan.expiry,
                    )
                    .await?;
                if repository
                    .artifacts()
                    .await?
                    .iter()
                    .any(|value| value.id == artifact.id || value.digest == artifact.digest)
                {
                    return Err(ApplicationError::Conflict("artifact already exists"));
                }
            }
            PlanStepAction::ArtifactStage {
                artifact_id,
                expected_digest,
                ..
            } => {
                let artifact = repository
                    .artifacts()
                    .await?
                    .into_iter()
                    .find(|artifact| artifact.id == *artifact_id)
                    .ok_or(ApplicationError::NotFound("artifact"))?;
                if artifact.digest != *expected_digest {
                    return Err(ApplicationError::StalePlan);
                }
            }
            PlanStepAction::ArtifactActivate {
                artifact_id,
                artifact_set_id,
                cluster_id,
                expected_revision,
                target_revision,
                ..
            } => {
                if *cluster_id != cluster
                    || !repository
                        .artifact_set(*artifact_set_id)
                        .await?
                        .artifacts
                        .contains(artifact_id)
                    || repository.revision_cluster(*expected_revision).await? != cluster
                    || repository.revision_cluster(*target_revision).await? != cluster
                {
                    return Err(ApplicationError::Forbidden);
                }
            }
            PlanStepAction::ProxyRollout {
                pool_id,
                expected_instance_id,
                target_instance_id,
                target_binding_id,
                configuration,
                ..
            } => {
                let proxies = repository.proxies().await?;
                let expected = proxies
                    .iter()
                    .find(|proxy| proxy.id == *expected_instance_id)
                    .ok_or(ApplicationError::NotFound("expected proxy instance"))?;
                let target = proxies
                    .iter()
                    .find(|proxy| proxy.id == *target_instance_id)
                    .ok_or(ApplicationError::NotFound("target proxy instance"))?;
                if expected.pool_id != *pool_id || target.pool_id != *pool_id {
                    return Err(ApplicationError::Forbidden);
                }
                let target_binding = repository
                    .gameap_binding(*target_binding_id, service, cluster)
                    .await?;
                if target_binding.target != GameAPBindingTarget::ProxyInstance(*target_instance_id)
                {
                    return Err(ApplicationError::Forbidden);
                }
                for operation in configuration {
                    let FileBatchOperation::Write {
                        content,
                        classification,
                        ..
                    } = operation
                    else {
                        return Err(ApplicationError::Conflict(
                            "proxy configuration must contain writes",
                        ));
                    };
                    repository
                        .staged_content_for_actor(
                            session_id,
                            plan.actor,
                            content,
                            classification.clone(),
                            plan.expiry,
                        )
                        .await?;
                }
            }
            PlanStepAction::WorldWriterCutover {
                world_id,
                expected_writer,
                next_writer,
                expected_writer_binding_id,
                target_writer_binding_id,
                expected_writer_binding_hash,
                target_writer_binding_hash,
                expected_version,
                domain_revision,
            } => {
                let world = repository
                    .worlds()
                    .await?
                    .into_iter()
                    .find(|world| world.id == *world_id)
                    .ok_or(ApplicationError::NotFound("world"))?;
                if *expected_version == 0 || *domain_revision == 0 {
                    return Err(ApplicationError::StalePlan);
                }
                let expected_writers = expected_writer.iter().copied().collect::<Vec<_>>();
                if world.current_writers != expected_writers {
                    return Err(ApplicationError::StalePlan);
                }
                let stop_position = match (expected_writer_binding_id, expected_writer_binding_hash)
                {
                    (Some(expected_binding), Some(expected_hash)) => previous
                        .iter()
                        .enumerate()
                        .find(|(_, step)| {
                            matches!(
                                &step.action,
                                PlanStepAction::ExecutionLifecycle {
                                    binding_id,
                                    action: ExecutionLifecycleAction::Stop,
                                    expected_binding_hash: binding_hash,
                                    ..
                                } if binding_id == expected_binding && binding_hash == expected_hash
                            )
                        })
                        .map(|(position, _)| position),
                    (None, None) => None,
                    _ => None,
                };
                if expected_writer.is_some() && stop_position.is_none() {
                    return Err(ApplicationError::Conflict(
                        "world cutover requires exact writer stop",
                    ));
                }
                let backup_after_stop = previous.iter().enumerate().any(|(position, step)| {
                    position > stop_position.unwrap_or(usize::MAX)
                        && matches!(
                            step.action,
                            PlanStepAction::BackupCreate {
                                kind: BackupKind::World,
                                target: BackupTarget::World(id),
                                ..
                            } if id == *world_id
                        )
                });
                if expected_writer.is_none() != expected_writer_binding_id.is_none()
                    || expected_writer_binding_id.is_none()
                        != expected_writer_binding_hash.is_none()
                    || !backup_available(
                        previous,
                        BackupKind::World,
                        BackupTarget::World(*world_id),
                    )
                    || (expected_writer.is_some() && !backup_after_stop)
                {
                    return Err(ApplicationError::Conflict("world cutover backup ordering"));
                }
                let target_cluster = repository.cluster(*next_writer).await?;
                if target_cluster.service_id != service {
                    return Err(ApplicationError::Forbidden);
                }
                repository
                    .gameap_binding(*target_writer_binding_id, service, *next_writer)
                    .await
                    .and_then(|binding| {
                        if binding.fingerprint() != *target_writer_binding_hash
                            || binding.target != GameAPBindingTarget::World(*world_id)
                        {
                            Err(ApplicationError::StalePlan)
                        } else {
                            Ok(binding)
                        }
                    })?;
                if let (Some(writer), Some(binding_id)) =
                    (expected_writer, expected_writer_binding_id)
                {
                    let expected_hash = expected_writer_binding_hash
                        .as_deref()
                        .ok_or(ApplicationError::StalePlan)?;
                    let binding = repository
                        .gameap_binding(*binding_id, service, *writer)
                        .await?;
                    if binding.fingerprint() != expected_hash
                        || binding.target != GameAPBindingTarget::World(*world_id)
                    {
                        return Err(ApplicationError::StalePlan);
                    }
                }
            }
            PlanStepAction::EndpointRollout {
                expected_binding_id,
                target_binding_id,
                cluster_id,
                expected_revision,
                target_revision,
                runtime_binding_ids,
                runtime_binding_hashes,
                ..
            } => {
                let expected_binding = repository.endpoint_binding(*expected_binding_id).await?;
                let target_binding = repository.endpoint_binding(*target_binding_id).await?;
                let endpoints = repository.endpoints().await?;
                let expected_endpoint = endpoints
                    .iter()
                    .find(|endpoint| endpoint.id == expected_binding.endpoint_id)
                    .ok_or(ApplicationError::NotFound("expected endpoint"))?;
                let target_endpoint = endpoints
                    .iter()
                    .find(|endpoint| endpoint.id == target_binding.endpoint_id)
                    .ok_or(ApplicationError::NotFound("target endpoint"))?;
                if expected_binding.cluster_id != *cluster_id
                    || target_binding.cluster_id != *cluster_id
                    || expected_binding.cluster_id != cluster
                    || expected_binding.revision_id != *expected_revision
                    || target_binding.revision_id != *target_revision
                    || expected_binding.binding_key != target_binding.binding_key
                    || expected_endpoint.kind != target_endpoint.kind
                    || expected_endpoint.role != target_endpoint.role
                    || expected_endpoint.port != target_endpoint.port
                    || repository.revision_cluster(*expected_revision).await? != cluster
                    || repository.revision_cluster(*target_revision).await? != cluster
                {
                    return Err(ApplicationError::Forbidden);
                }
                if runtime_binding_ids.len() != runtime_binding_hashes.len()
                    || runtime_binding_ids.is_empty()
                    || runtime_binding_ids.len() > 128
                {
                    return Err(ApplicationError::Conflict("endpoint runtime binding set"));
                }
                let mut runtime_ids = std::collections::BTreeSet::new();
                for (runtime_id, runtime_hash) in
                    runtime_binding_ids.iter().zip(runtime_binding_hashes)
                {
                    if !runtime_ids.insert(runtime_id)
                        || !runtime_hash.chars().all(|value| value.is_ascii_hexdigit())
                        || runtime_hash.len() != 64
                    {
                        return Err(ApplicationError::StalePlan);
                    }
                    let runtime_binding = repository
                        .gameap_binding(*runtime_id, service, *cluster_id)
                        .await?;
                    if runtime_binding.fingerprint() != *runtime_hash
                        || !matches!(
                            runtime_binding.target,
                            GameAPBindingTarget::ExecutionUnit(_)
                        )
                    {
                        return Err(ApplicationError::Forbidden);
                    }
                }
            }
            PlanStepAction::AccessPolicyUpdate {
                policy_id,
                service_id,
                ..
            } => {
                if *service_id != service || service_record.access_policy != Some(*policy_id) {
                    return Err(ApplicationError::Forbidden);
                }
                let _ = repository.access_policy(*policy_id).await?;
            }
            PlanStepAction::BackupRestore {
                reference_id,
                target,
                expected_manifest_digest,
                rollback_reference_id,
                expected_rollback_manifest_digest,
                ..
            } => {
                let backup = persisted_backups
                    .iter()
                    .find(|backup| backup.id == *reference_id)
                    .ok_or(ApplicationError::NotFound("backup reference"))?;
                let rollback = persisted_backups
                    .iter()
                    .find(|backup| backup.id == *rollback_reference_id)
                    .ok_or(ApplicationError::NotFound("rollback backup reference"))?;
                if backup.session_id != session_id
                    || backup.target != *target
                    || backup.manifest_digest != *expected_manifest_digest
                    || backup.verified_at.is_none()
                    || rollback.session_id != session_id
                    || rollback.target != *target
                    || rollback.manifest_digest != *expected_rollback_manifest_digest
                    || rollback.verified_at.is_none()
                    || backup.id == rollback.id
                {
                    return Err(ApplicationError::Forbidden);
                }
            }
            PlanStepAction::RoutePolicyUpdate {
                service_id,
                expected_cluster,
                target_cluster,
                ..
            } => {
                if *service_id != service
                    || (*expected_cluster != cluster && *target_cluster != cluster)
                {
                    return Err(ApplicationError::Forbidden);
                }
            }
            PlanStepAction::ServiceArchive { service_id, .. }
            | PlanStepAction::ServicePurge { service_id, .. } => {
                if *service_id != service {
                    return Err(ApplicationError::Forbidden);
                }
                let retirement = repository.retirement_safety(service).await?;
                if matches!(&action.action, PlanStepAction::ServiceArchive { .. }) {
                    let route_disabled = previous.iter().any(|step| {
                        matches!(
                            step.action,
                            PlanStepAction::RoutePolicyUpdate {
                                service_id: id,
                                disabled: true,
                                ..
                            } if id == service
                        )
                    });
                    let runtime_stopped = previous.iter().any(|step| {
                        matches!(
                            step.action,
                            PlanStepAction::ExecutionLifecycle {
                                action: ExecutionLifecycleAction::Stop,
                                ..
                            } | PlanStepAction::ExecutionDelete { .. }
                        )
                    });
                    let access_revoked = previous.iter().any(|step| {
                        matches!(
                            step.action,
                            PlanStepAction::AccessPolicyUpdate {
                                service_id: id,
                                ref desired_grants,
                                ..
                            } if id == service && desired_grants.is_empty()
                        )
                    });
                    let sunsetting_ready = service_record.lifecycle == ServiceLifecycle::Sunsetting
                        || previous.iter().any(|step| {
                            matches!(
                                step.action,
                                PlanStepAction::ServiceLifecycleTransition {
                                    service_id: id,
                                    ref expected_state,
                                    next_state: ServiceLifecycle::Sunsetting,
                                    ..
                                } if id == service
                                    && expected_state == &service_record.lifecycle
                            )
                        });
                    let persisted_routes_safe = !retirement.active_routes || route_disabled;
                    let persisted_writers_safe =
                        !retirement.active_world_writers || runtime_stopped;
                    let persisted_execution_safe =
                        !retirement.active_execution_bindings || runtime_stopped;
                    let persisted_access_safe =
                        retirement.effective_access_grants.is_empty() || access_revoked;
                    if !sunsetting_ready
                        || !route_disabled
                        || !runtime_stopped
                        || !access_revoked
                        || !persisted_routes_safe
                        || !persisted_writers_safe
                        || !persisted_execution_safe
                        || !persisted_access_safe
                        || !backup_available(
                            previous,
                            BackupKind::ServiceConsistent,
                            BackupTarget::Service(service),
                        )
                        || !backup_available(
                            previous,
                            BackupKind::ExternalDatabaseReference,
                            BackupTarget::Service(service),
                        )
                    {
                        return Err(ApplicationError::Conflict("archive prerequisites"));
                    }
                } else if service_record.lifecycle != ServiceLifecycle::Archived
                    || !backup_available(
                        previous,
                        BackupKind::ServiceConsistent,
                        BackupTarget::Service(service),
                    )
                    || !backup_available(
                        previous,
                        BackupKind::ExternalDatabaseReference,
                        BackupTarget::Service(service),
                    )
                    || previous.iter().any(|step| {
                        matches!(
                            step.action,
                            PlanStepAction::RoutePolicyUpdate {
                                service_id: id,
                                disabled: false,
                                ..
                            } if id == service
                        )
                    })
                    || retirement.active_routes
                    || retirement.active_world_writers
                    || retirement.active_execution_bindings
                    || !retirement.effective_access_grants.is_empty()
                {
                    return Err(ApplicationError::Conflict("purge prerequisites"));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

async fn validate_staged_content_scope<R: DomainRepository>(
    repository: &R,
    plan: &PlanDescriptor,
    session_id: ChangeSessionId,
) -> Result<(), ApplicationError> {
    for step in &plan.steps {
        match &step.action {
            PlanStepAction::FileWrite {
                content,
                classification,
                ..
            } => {
                repository
                    .staged_content_for_actor(
                        session_id,
                        plan.actor,
                        content,
                        classification.clone(),
                        plan.expiry,
                    )
                    .await?;
            }
            PlanStepAction::FileBatch { operations, .. } => {
                for operation in operations {
                    if let FileBatchOperation::Write {
                        content,
                        classification,
                        ..
                    } = operation
                    {
                        repository
                            .staged_content_for_actor(
                                session_id,
                                plan.actor,
                                content,
                                classification.clone(),
                                plan.expiry,
                            )
                            .await?;
                    }
                }
            }
            PlanStepAction::ProxyRollout { configuration, .. } => {
                for operation in configuration {
                    let FileBatchOperation::Write {
                        content,
                        classification,
                        ..
                    } = operation
                    else {
                        return Err(ApplicationError::Conflict(
                            "proxy configuration must contain writes",
                        ));
                    };
                    repository
                        .staged_content_for_actor(
                            session_id,
                            plan.actor,
                            content,
                            classification.clone(),
                            plan.expiry,
                        )
                        .await?;
                }
            }
            PlanStepAction::ArtifactRegister { content, .. } => {
                repository
                    .staged_content_for_actor(
                        session_id,
                        plan.actor,
                        content,
                        FileClassification::Artifact,
                        plan.expiry,
                    )
                    .await?;
            }
            _ => {}
        }
    }
    Ok(())
}

/// Re-read a verified backup reference from durable storage immediately before
/// a destructive provider call.  A `BackupCreate` step in a plan only gives
/// ordering; it never stands in for this persisted verification.
pub async fn require_verified_backup<R: DomainRepository>(
    repository: &R,
    session_id: ChangeSessionId,
    kind: BackupKind,
    target: BackupTarget,
) -> Result<BackupReference, ApplicationError> {
    repository
        .backups()
        .await?
        .into_iter()
        .filter(|reference| {
            reference.session_id == session_id
                && reference.kind == kind
                && reference.target == target
                && reference.verified_at.is_some()
        })
        .max_by_key(|reference| reference.verified_at)
        .ok_or(ApplicationError::BackupUnavailable)
        .and_then(|reference| {
            reference
                .validate()
                .map_err(|_| ApplicationError::BackupUnavailable)
                .map(|_| reference)
        })
}

/// Apply-time retirement gate.  This must be evaluated again by the
/// controller immediately before archive/purge, after all planned stop,
/// route-disable, and access-revoke effects have become observable.
pub async fn require_retirement_clear<R: DomainRepository>(
    repository: &R,
    service: ServiceId,
) -> Result<(), ApplicationError> {
    let safety = repository.retirement_safety(service).await?;
    if safety.active_routes
        || safety.active_world_writers
        || safety.active_execution_bindings
        || !safety.effective_access_grants.is_empty()
    {
        return Err(ApplicationError::Conflict("retirement safety gate"));
    }
    Ok(())
}

async fn plan_cluster_id<R: DomainRepository>(
    repository: &R,
    plan: &PlanDescriptor,
    service: ServiceId,
) -> Result<ClusterId, ApplicationError> {
    repository
        .cluster_for_plan_target(plan.target, service)
        .await
}

async fn resolve_change_steps<R: DomainRepository>(
    repository: &R,
    service: ServiceId,
    cluster: ClusterId,
    plan_steps: &[PlanStep],
) -> Result<Vec<(PlanStep, Option<GameAPBinding>)>, ApplicationError> {
    let owner = repository.cluster(cluster).await?;
    if owner.service_id != service {
        return Err(ApplicationError::Forbidden);
    }
    let mut resolved = Vec::with_capacity(plan_steps.len());
    for step in plan_steps {
        let Some(binding_id) = step.action.binding_id() else {
            step.validate().map_err(|_| ApplicationError::StalePlan)?;
            resolved.push((step.clone(), None));
            continue;
        };
        let binding_cluster = match &step.action {
            PlanStepAction::WorldWriterCutover { next_writer, .. } => *next_writer,
            _ => cluster,
        };
        let binding = repository
            .gameap_binding(binding_id, service, binding_cluster)
            .await?;
        let fingerprint = binding.fingerprint();
        if let Some(expected) = step.action.expected_binding_hash()
            && !expected.is_empty()
            && expected != fingerprint
        {
            return Err(ApplicationError::StalePlan);
        }
        let resolved_action = step.action.clone().with_binding_hash(fingerprint);
        let resolved_step =
            PlanStep::new(resolved_action).map_err(|_| ApplicationError::StalePlan)?;
        resolved.push((resolved_step, Some(binding)));
    }
    Ok(resolved)
}

/// Service-consistent backup is a typed sequence of ordinary steps. Keep its
/// ordering gate here, before execution resolution, so a plan cannot defer
/// the maintenance window contract until a provider is called.
async fn validate_service_consistent_sequence<R: DomainRepository>(
    repository: &R,
    plan: &PlanDescriptor,
    service: ServiceId,
    cluster: ClusterId,
) -> Result<(), ApplicationError> {
    let service_consistent = plan
        .steps
        .iter()
        .enumerate()
        .filter(|(_, step)| {
            matches!(
                &step.action,
                PlanStepAction::BackupCreate {
                    kind: BackupKind::ServiceConsistent,
                    ..
                }
            )
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if service_consistent.is_empty() {
        return Ok(());
    }
    if service_consistent.len() != 1 {
        return Err(ApplicationError::Conflict(
            "service-consistent backup must be created once",
        ));
    }
    let manifest = service_consistent[0];
    if !matches!(
        &plan.steps[manifest].action,
        PlanStepAction::BackupCreate {
            target: BackupTarget::Service(id),
            ..
        } if *id == service
    ) {
        return Err(ApplicationError::Forbidden);
    }
    let service_record = repository.service(service).await?;
    let original_lifecycle = service_record.lifecycle.clone();
    let maintenance = plan
        .steps
        .iter()
        .enumerate()
        .filter(|(index, step)| {
            *index < manifest
                && matches!(
                    &step.action,
                    PlanStepAction::ServiceLifecycleTransition {
                        service_id,
                        expected_state,
                        next_state: ServiceLifecycle::Maintenance,
                        ..
                    } if *service_id == service && expected_state == &original_lifecycle
                )
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if maintenance.len() != 1 || maintenance[0] != 0 {
        return Err(ApplicationError::Conflict(
            "service-consistent backup must enter maintenance first",
        ));
    }
    let maintenance = maintenance[0];

    let disabled_routes = plan
        .steps
        .iter()
        .enumerate()
        .filter_map(|(index, step)| match &step.action {
            PlanStepAction::RoutePolicyUpdate {
                route_id,
                service_id,
                disabled: true,
                ..
            } if index > maintenance && index < manifest && *service_id == service => {
                Some((*route_id, index))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    if disabled_routes.is_empty() {
        return Err(ApplicationError::Conflict(
            "service-consistent backup must stop new joins",
        ));
    }
    let first_disabled = disabled_routes
        .iter()
        .map(|(_, index)| *index)
        .min()
        .expect("non-empty route list");
    if first_disabled != maintenance + 1 {
        return Err(ApplicationError::Conflict(
            "service-consistent backup must stop joins immediately after maintenance",
        ));
    }
    let disabled_ids = disabled_routes
        .iter()
        .map(|(id, _)| *id)
        .collect::<std::collections::BTreeSet<_>>();
    if disabled_ids.len() != disabled_routes.len() {
        return Err(ApplicationError::Conflict(
            "service-consistent backup disables a route twice",
        ));
    }
    let last_disabled = disabled_routes
        .iter()
        .map(|(_, index)| *index)
        .max()
        .expect("non-empty route list");

    let mut stopped_bindings = Vec::new();
    let mut world_backups = Vec::new();
    let mut external_backups = Vec::new();
    for (index, step) in plan.steps.iter().enumerate() {
        if index <= first_disabled || index >= manifest {
            continue;
        }
        match &step.action {
            PlanStepAction::ExecutionLifecycle {
                binding_id,
                action: ExecutionLifecycleAction::Stop,
                ..
            } => {
                let binding = repository
                    .gameap_binding(*binding_id, service, cluster)
                    .await?;
                if !matches!(binding.target, GameAPBindingTarget::ExecutionUnit(_)) {
                    return Err(ApplicationError::Conflict(
                        "service-consistent backup stop is not a service runtime",
                    ));
                }
                if stopped_bindings.contains(binding_id) {
                    return Err(ApplicationError::Conflict(
                        "service-consistent backup runtime stopped twice",
                    ));
                }
                stopped_bindings.push(*binding_id);
            }
            PlanStepAction::BackupCreate {
                kind: BackupKind::World,
                target: BackupTarget::World(world),
                ..
            } => world_backups.push((*world, index)),
            PlanStepAction::BackupCreate {
                kind: BackupKind::ExternalDatabaseReference,
                target: BackupTarget::Service(id),
                ..
            } if *id == service => external_backups.push(index),
            PlanStepAction::RoutePolicyUpdate {
                service_id,
                disabled: true,
                ..
            } if *service_id == service => {}
            _ => {
                return Err(ApplicationError::Conflict(
                    "service-consistent backup contains an out-of-order step",
                ));
            }
        }
    }
    if stopped_bindings.is_empty() || world_backups.is_empty() || external_backups.len() != 1 {
        return Err(ApplicationError::Conflict(
            "service-consistent backup is missing a stop, world, or database step",
        ));
    }
    let mut world_ids = world_backups.iter().map(|(id, _)| *id).collect::<Vec<_>>();
    world_ids.sort_unstable();
    world_ids.dedup();
    if world_ids.len() != world_backups.len() {
        return Err(ApplicationError::Conflict(
            "service-consistent backup repeats a world component",
        ));
    }
    let first_stop = plan
        .steps
        .iter()
        .enumerate()
        .find_map(|(index, step)| {
            (index > first_disabled
                && index < manifest
                && matches!(
                    &step.action,
                    PlanStepAction::ExecutionLifecycle {
                        action: ExecutionLifecycleAction::Stop,
                        ..
                    }
                ))
            .then_some(index)
        })
        .expect("non-empty stopped runtime list");
    let last_stop = plan
        .steps
        .iter()
        .enumerate()
        .rev()
        .find_map(|(index, step)| {
            (index > first_disabled
                && index < manifest
                && matches!(
                    &step.action,
                    PlanStepAction::ExecutionLifecycle {
                        action: ExecutionLifecycleAction::Stop,
                        ..
                    }
                ))
            .then_some(index)
        })
        .expect("non-empty stopped runtime list");
    let first_world = world_backups
        .iter()
        .map(|(_, index)| *index)
        .min()
        .expect("non-empty world list");
    if last_disabled > first_stop || first_world <= last_stop {
        return Err(ApplicationError::Conflict(
            "service-consistent backup stop and world ordering",
        ));
    }
    let current_revision = repository.cluster(cluster).await?.current_revision;
    let known_worlds = match current_revision {
        Some(current) => repository
            .revisions()
            .await?
            .into_iter()
            .find(|revision| revision.id == current)
            .map(|revision| revision.world_bindings),
        None => None,
    }
    .unwrap_or_default();
    // A repository exposes revisions without their owning cluster. When it
    // cannot identify the current revision, the explicit world stop/backup
    // set above remains the source of truth; the controller rechecks exact
    // persisted world ownership before invoking the provider.
    if !known_worlds.is_empty()
        && known_worlds
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            != world_ids.iter().copied().collect()
    {
        return Err(ApplicationError::Conflict(
            "service-consistent backup does not cover every service world",
        ));
    }
    let external = external_backups[0];
    let last_world = world_backups
        .iter()
        .map(|(_, index)| *index)
        .max()
        .expect("non-empty world list");
    if last_world >= external || external >= manifest {
        return Err(ApplicationError::Conflict(
            "service-consistent backup components are out of order",
        ));
    }

    let restore_lifecycle = plan
        .steps
        .iter()
        .enumerate()
        .filter(|(index, step)| {
            *index > manifest
                && matches!(
                    &step.action,
                    PlanStepAction::ServiceLifecycleTransition {
                        service_id,
                        expected_state: ServiceLifecycle::Maintenance,
                        next_state,
                        ..
                    } if *service_id == service && next_state == &original_lifecycle
                )
        })
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if restore_lifecycle.len() != 1 {
        return Err(ApplicationError::Conflict(
            "service-consistent backup must restore its prior lifecycle",
        ));
    }
    let restore_lifecycle = restore_lifecycle[0];

    let has_restart = plan.steps.iter().enumerate().any(|(index, step)| {
        index > manifest
            && index < restore_lifecycle
            && matches!(
                &step.action,
                PlanStepAction::ExecutionLifecycle {
                    action: ExecutionLifecycleAction::Restart,
                    ..
                }
            )
    });
    let starts = plan
        .steps
        .iter()
        .enumerate()
        .filter_map(|(index, step)| match &step.action {
            PlanStepAction::ExecutionLifecycle {
                binding_id,
                action: ExecutionLifecycleAction::Start,
                ..
            } if index > manifest && index < restore_lifecycle => Some((*binding_id, index)),
            _ => None,
        })
        .collect::<Vec<_>>();
    for (index, step) in plan.steps.iter().enumerate() {
        if index <= manifest || index >= restore_lifecycle {
            continue;
        }
        let allowed = match &step.action {
            PlanStepAction::ExecutionLifecycle {
                action: ExecutionLifecycleAction::Start,
                ..
            } => true,
            PlanStepAction::RoutePolicyUpdate {
                service_id,
                disabled: false,
                ..
            } => *service_id == service,
            _ => false,
        };
        if !allowed {
            return Err(ApplicationError::Conflict(
                "service-consistent backup resume contains an out-of-order step",
            ));
        }
    }
    if has_restart
        || starts.len() != stopped_bindings.len()
        || starts
            .iter()
            .map(|(id, _)| *id)
            .collect::<std::collections::BTreeSet<_>>()
            != stopped_bindings.iter().copied().collect()
    {
        return Err(ApplicationError::Conflict(
            "service-consistent backup may only restart stopped runtimes",
        ));
    }
    let resumed_routes = plan
        .steps
        .iter()
        .enumerate()
        .filter_map(|(index, step)| match &step.action {
            PlanStepAction::RoutePolicyUpdate {
                route_id,
                service_id,
                disabled: false,
                ..
            } if index > manifest && index < restore_lifecycle && *service_id == service => {
                Some((*route_id, index))
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    if resumed_routes.len() != disabled_routes.len()
        || resumed_routes
            .iter()
            .map(|(id, _)| *id)
            .collect::<std::collections::BTreeSet<_>>()
            != disabled_ids
    {
        return Err(ApplicationError::Conflict(
            "service-consistent backup must resume joins",
        ));
    }
    if let Some((_, last_start)) = starts.iter().max_by_key(|(_, index)| *index)
        && resumed_routes.iter().any(|(_, index)| index < last_start)
    {
        return Err(ApplicationError::Conflict(
            "service-consistent backup must resume joins after runtimes",
        ));
    }
    for (route_id, _) in &resumed_routes {
        let Some(PlanStep {
            action:
                PlanStepAction::RoutePolicyUpdate {
                    expected_cluster: disabled_expected_cluster,
                    target_cluster: disabled_target_cluster,
                    expected_priority: disabled_expected_priority,
                    target_priority: disabled_target_priority,
                    route_id: disabled_route_id,
                    ..
                },
        }) = plan.steps[..manifest].iter().find(|step| {
            matches!(
                &step.action,
                PlanStepAction::RoutePolicyUpdate {
                    route_id: id,
                    disabled: true,
                    ..
                } if *id == *route_id
            )
        })
        else {
            return Err(ApplicationError::Conflict(
                "service-consistent backup route resume has no matching stop",
            ));
        };
        let resume = resumed_routes
            .iter()
            .find(|(id, _)| id == route_id)
            .and_then(|(_, index)| plan.steps.get(*index))
            .and_then(|step| match &step.action {
                PlanStepAction::RoutePolicyUpdate {
                    expected_cluster,
                    target_cluster,
                    expected_priority,
                    target_priority,
                    route_id,
                    ..
                } => Some((
                    expected_cluster,
                    target_cluster,
                    expected_priority,
                    target_priority,
                    route_id,
                )),
                _ => None,
            })
            .expect("resume route action");
        if *disabled_route_id != *route_id
            || resume.0 != disabled_target_cluster
            || resume.1 != disabled_expected_cluster
            || resume.2 != disabled_target_priority
            || resume.3 != disabled_expected_priority
        {
            return Err(ApplicationError::Conflict(
                "service-consistent backup route resume does not restore prior route",
            ));
        }
    }
    if restore_lifecycle + 1 != plan.steps.len() {
        return Err(ApplicationError::Conflict(
            "service-consistent backup lifecycle restore must be final",
        ));
    }
    Ok(())
}

pub struct ChangeExecutionWorkflow<R, O, V, B, C> {
    pub repository: R,
    pub operations: O,
    pub verification: V,
    pub rollback: B,
    pub audit: C,
}

impl<R: DomainRepository, O: OperationStore, V: DurableStepPort, B: RollbackStepPort, C: AuditSink>
    ChangeExecutionWorkflow<R, O, V, B, C>
{
    async fn resolved_steps(
        &self,
        plan: &PlanDescriptor,
        service: ServiceId,
        session_id: ChangeSessionId,
    ) -> Result<Vec<OperationStep>, ApplicationError> {
        resolve_plan_steps(&self.repository, plan, service, session_id).await
    }

    /// Reobserve every step and compare provider evidence with the durable
    /// evidence recorded during apply. Caller-supplied hashes are never used
    /// as verification evidence.
    pub async fn verify(
        &self,
        operation_id: OperationId,
        session_id: ChangeSessionId,
        plan: &PlanDescriptor,
        service: ServiceId,
        now: u64,
        holder: &str,
    ) -> Result<Operation, ApplicationError> {
        let operation = self.operations.operation(operation_id).await?;
        if operation.session_id != session_id || operation.state != OperationState::Verifying {
            return Err(ApplicationError::Conflict(
                "operation is not ready to verify",
            ));
        }
        if plan.id != operation.plan_id {
            return Err(ApplicationError::Conflict("operation plan mismatch"));
        }
        let plan_session = self.repository.plan_session(plan.id).await?;
        if plan_session != session_id {
            return Err(ApplicationError::Conflict("plan session mismatch"));
        }
        if plan.plan_hash != plan.compute_hash() {
            return Err(ApplicationError::StalePlan);
        }
        let evidence = self.operations.step_evidence(operation_id).await?;
        let steps = self.resolved_steps(plan, service, session_id).await?;
        let lease = self
            .operations
            .acquire_lease(operation_id, holder, now, 60)
            .await?;
        for (sequence, step) in steps.iter().enumerate() {
            let sequence = u32::try_from(sequence)
                .map_err(|_| ApplicationError::Conflict("too many operation steps"));
            let sequence = match sequence {
                Ok(sequence) => sequence,
                Err(error) => return Err(self.fail_verification(&lease, error, vec![]).await),
            };
            let stored = evidence
                .iter()
                .find(|item| item.sequence == sequence)
                .ok_or(ApplicationError::Conflict("missing step evidence"));
            let stored = match stored {
                Ok(stored) => stored,
                Err(error) => return Err(self.fail_verification(&lease, error, vec![]).await),
            };
            if matches!(
                step,
                OperationStep::BackupRestore { .. } | OperationStep::BackupCreate { .. }
            ) {
                let Some(execution) = stored.execution.as_ref() else {
                    return Err(self
                        .fail_verification(
                            &lease,
                            ApplicationError::Conflict("missing backup execution evidence"),
                            vec![format!("sequence={sequence}")],
                        )
                        .await);
                };
                if let Err(error) = execution.validate_for(step) {
                    return Err(self
                        .fail_verification(&lease, error, vec![format!("sequence={sequence}")])
                        .await);
                }
            }
            let observed = match match step {
                OperationStep::BackupRestore { .. } => {
                    self.verification.observe_restore(step, Some(stored)).await
                }
                OperationStep::BackupCreate { .. } => {
                    self.verification.observe_backup(step, Some(stored)).await
                }
                _ => self.verification.observe(step, Some(stored)).await,
            } {
                Ok(observed) => observed,
                Err(error) => {
                    return Err(self
                        .fail_verification(&lease, error, vec![format!("sequence={sequence}")])
                        .await);
                }
            };
            if !observed.completed || observed.state_hash != stored.state_hash {
                let error = ApplicationError::Conflict("verification evidence mismatch");
                return Err(self
                    .fail_verification(&lease, error, vec![format!("sequence={sequence}")])
                    .await);
            }
        }
        let result = self
            .operations
            .finish_verified(&lease, session_id, vec!["provider-postconditions".into()])
            .await;
        if result.is_err() {
            let error = result.expect_err("checked error");
            return Err(self.fail_verification(&lease, error, vec![]).await);
        }
        self.operations.release_lease(&lease).await?;
        result
    }

    async fn fail_verification(
        &self,
        lease: &OperationLease,
        error: ApplicationError,
        evidence: Vec<String>,
    ) -> ApplicationError {
        let failure = OperationFailure::from_error(&error, evidence);
        let _ = self
            .operations
            .fail_operation(lease.operation, failure, &lease.holder)
            .await;
        error
    }

    /// Acceptance is intentionally separate from verification: it only
    /// succeeds after the provider postconditions have been durably verified.
    pub async fn accept(
        &self,
        operation_id: OperationId,
        session_id: ChangeSessionId,
        now: u64,
        holder: &str,
    ) -> Result<Operation, ApplicationError> {
        let operation = self.operations.operation(operation_id).await?;
        if operation.session_id != session_id || operation.state != OperationState::Verified {
            return Err(ApplicationError::Conflict("operation is not verified"));
        }
        let lease = self
            .operations
            .acquire_lease(operation_id, holder, now, 60)
            .await?;
        let result = self.operations.finish_accepted(&lease, session_id).await;
        match result {
            Ok(operation) => {
                self.operations.release_lease(&lease).await?;
                Ok(operation)
            }
            Err(error) => Err(self.fail_verification(&lease, error, vec![]).await),
        }
    }

    /// Compensate in reverse order. A failed or unverifiable compensation is
    /// terminal and retains partial evidence in the failure record.
    pub async fn rollback(
        &self,
        operation_id: OperationId,
        session_id: ChangeSessionId,
        plan: &PlanDescriptor,
        service: ServiceId,
        now: u64,
        holder: &str,
    ) -> Result<Operation, ApplicationError> {
        let operation = self.operations.operation(operation_id).await?;
        if operation.session_id != session_id {
            return Err(ApplicationError::Conflict("operation session mismatch"));
        }
        if !matches!(
            operation.state,
            OperationState::Applying
                | OperationState::Verifying
                | OperationState::Verified
                | OperationState::Failed
        ) {
            return Err(ApplicationError::Conflict(
                "operation cannot be rolled back",
            ));
        }
        if plan.id != operation.plan_id {
            return Err(ApplicationError::Conflict("operation plan mismatch"));
        }
        let plan_session = self.repository.plan_session(plan.id).await?;
        if plan_session != session_id {
            return Err(ApplicationError::Conflict("plan session mismatch"));
        }
        if plan.plan_hash != plan.compute_hash() {
            return Err(ApplicationError::StalePlan);
        }
        let lease = self
            .operations
            .acquire_lease(operation_id, holder, now, 60)
            .await?;
        let steps = match self.resolved_steps(plan, service, session_id).await {
            Ok(steps) => steps,
            Err(error) => return Err(self.fail_verification(&lease, error, vec![]).await),
        };
        let mut partial = Vec::new();
        for (sequence, step) in steps.iter().enumerate().rev() {
            let sequence = u32::try_from(sequence)
                .map_err(|_| ApplicationError::RollbackConflict("invalid step sequence".into()));
            let sequence = match sequence {
                Ok(sequence) => sequence,
                Err(error) => return Err(self.fail_verification(&lease, error, vec![]).await),
            };
            let prior_evidence = self
                .operations
                .step_evidence(operation_id)
                .await?
                .into_iter()
                .find(|item| item.sequence == sequence);
            if DurableExecutor::<O, V, C>::requires_prepared_inverse(step)
                && prior_evidence
                    .as_ref()
                    .and_then(|item| item.execution.as_ref())
                    .is_none()
            {
                return Err(self
                    .fail_verification(
                        &lease,
                        ApplicationError::RollbackConflict(
                            "missing durable inverse evidence".into(),
                        ),
                        vec![format!("sequence={sequence}")],
                    )
                    .await);
            }
            if let Some(evidence) = prior_evidence
                .as_ref()
                .and_then(|item| item.execution.as_ref())
                && let Err(error) = evidence.validate_for(step)
            {
                return Err(self
                    .fail_verification(
                        &lease,
                        ApplicationError::RollbackConflict(error.to_string()),
                        vec![format!("sequence={sequence}")],
                    )
                    .await);
            }
            match self.rollback.rollback(step, prior_evidence.as_ref()).await {
                Ok(observed) if observed.completed => {
                    partial.push(format!("sequence={sequence}:{}", observed.state_hash));
                    let recorded = self
                        .operations
                        .record_step_owned(
                            operation_id,
                            StepEvidence {
                                sequence,
                                state_hash: observed.state_hash,
                                result: "rolled-back".into(),
                                // Keep the apply-time inverse untouched. The
                                // rollback result is represented by `result`
                                // and must not erase evidence needed for a
                                // later retry or audit.
                                execution: prior_evidence
                                    .as_ref()
                                    .and_then(|item| item.execution.clone()),
                            },
                            &lease.holder,
                        )
                        .await
                        .map_err(|error| ApplicationError::RollbackConflict(error.to_string()));
                    if let Err(error) = recorded {
                        return Err(self.fail_verification(&lease, error, partial).await);
                    }
                }
                Ok(observed) => {
                    return Err(self
                        .fail_verification(
                            &lease,
                            ApplicationError::RollbackConflict(
                                "rollback postcondition not complete".into(),
                            ),
                            [
                                partial,
                                vec![format!("sequence={sequence}:{}", observed.state_hash)],
                            ]
                            .concat(),
                        )
                        .await);
                }
                Err(error) => {
                    return Err(self
                        .fail_verification(
                            &lease,
                            ApplicationError::RollbackConflict(error.to_string()),
                            partial,
                        )
                        .await);
                }
            }
        }
        self.operations.finish_rolled_back(&lease, session_id).await
    }
}
#[async_trait]
impl<T: DurableStepPort + ?Sized> DurableStepPort for &T {
    async fn observe(
        &self,
        step: &OperationStep,
        evidence: Option<&StepEvidence>,
    ) -> Result<StepObservation, ApplicationError> {
        (**self).observe(step, evidence).await
    }
    async fn observe_restore(
        &self,
        step: &OperationStep,
        evidence: Option<&StepEvidence>,
    ) -> Result<StepObservation, ApplicationError> {
        (**self).observe_restore(step, evidence).await
    }
    async fn observe_backup(
        &self,
        step: &OperationStep,
        evidence: Option<&StepEvidence>,
    ) -> Result<StepObservation, ApplicationError> {
        (**self).observe_backup(step, evidence).await
    }
    async fn prepare(
        &self,
        step: &OperationStep,
    ) -> Result<Option<StepExecutionEvidence>, ApplicationError> {
        (**self).prepare(step).await
    }
    async fn apply(
        &self,
        step: &OperationStep,
        prepared: Option<&StepExecutionEvidence>,
    ) -> Result<StepApplyResult, ApplicationError> {
        (**self).apply(step, prepared).await
    }
    async fn apply_restore(
        &self,
        step: &OperationStep,
    ) -> Result<BackupRestoreInvocation, ApplicationError> {
        (**self).apply_restore(step).await
    }
    async fn apply_backup(
        &self,
        step: &OperationStep,
    ) -> Result<BackupReference, ApplicationError> {
        (**self).apply_backup(step).await
    }
}
/// The single entry point intended for the controller. Controllers translate
/// HTTP/CLI requests into these typed values and never orchestrate steps.
pub struct ApplicationService<R, O, S, A, C> {
    pub repository: R,
    pub operations: O,
    pub steps: S,
    pub authorizer: A,
    pub audit: C,
}
impl<R: DomainRepository, O: OperationStore, S: DurableStepPort, A: Authorizer, C: AuditSink>
    ApplicationService<R, O, S, A, C>
{
    pub async fn execute_plan(
        &self,
        request: &OperationRequest,
        plan_id: PlanId,
        now: u64,
        holder: &str,
    ) -> Result<Operation, ApplicationError> {
        self.authorizer
            .authorize(&Authorization {
                actor: request.actor,
                service: request.service,
                permission: Permission::ChangeApply,
            })
            .await?;
        let plan = self.repository.plan(plan_id).await?;
        if plan.actor != request.actor || plan.target.stable_string() != request.target {
            return Err(ApplicationError::Forbidden);
        }
        let plan_session = self.repository.plan_session(plan_id).await?;
        if plan_session != request.session_id {
            return Err(ApplicationError::Conflict("plan session mismatch"));
        }
        let resolved_steps =
            resolve_plan_steps(&self.repository, &plan, request.service, request.session_id)
                .await?;
        let audit_scope = AuditScope::for_cluster(
            request.service,
            plan_cluster_id(&self.repository, &plan, request.service).await?,
        );
        for step in &resolved_steps {
            self.authorizer
                .authorize(&Authorization {
                    actor: request.actor,
                    service: request.service,
                    permission: step.required_permission(),
                })
                .await?;
        }
        DurableExecutor {
            operations: &self.operations,
            steps: &self.steps,
            audit: &self.audit,
        }
        .run(request, &plan, &resolved_steps, audit_scope, now, holder)
        .await
    }
    pub async fn query_services(&self) -> Result<Vec<Service>, ApplicationError> {
        self.repository.services().await
    }
}

/// Durable executor contract. The operation store owns idempotency and lease
/// acquisition; the step port owns external calls. On restart, a completed
/// postcondition is recorded without repeating the external call. Ambiguous
/// observations stop in conflict rather than guessing.
pub struct DurableExecutor<O, S, C> {
    pub operations: O,
    pub steps: S,
    pub audit: C,
}
impl<O: OperationStore, S: DurableStepPort, C: AuditSink> DurableExecutor<O, S, C> {
    fn requires_prepared_inverse(step: &OperationStep) -> bool {
        !matches!(
            step,
            OperationStep::ArtifactStage { .. }
                | OperationStep::ArtifactRegister { .. }
                | OperationStep::ClusterRevisionCreate { .. }
                | OperationStep::BackupCreate { .. }
                | OperationStep::BackupRestore { .. }
                | OperationStep::ServicePurge { .. }
        )
    }

    fn reconcile_evidence(
        step: &OperationStep,
        prepared: Option<&StepExecutionEvidence>,
        applied: Option<StepExecutionEvidence>,
    ) -> Result<Option<StepExecutionEvidence>, ApplicationError> {
        match (prepared, applied) {
            (Some(expected), Some(actual)) if expected != &actual => {
                if let (
                    StepExecutionEvidence::Execution {
                        binding_id: expected_binding,
                        prior_state_hash: expected_hash,
                        prior_exists: expected_exists,
                        provider_idempotency_key: expected_key,
                        ..
                    },
                    StepExecutionEvidence::Execution {
                        binding_id: actual_binding,
                        prior_state_hash: actual_hash,
                        prior_exists: actual_exists,
                        provider_idempotency_key: actual_key,
                        created_provider_unit: Some(created),
                        ..
                    },
                ) = (expected, &actual)
                    && matches!(step, OperationStep::ExecutionProvision { .. })
                    && expected_binding == actual_binding
                    && expected_hash == actual_hash
                    && expected_exists == actual_exists
                    && expected_key == actual_key
                    && !created.trim().is_empty()
                {
                    return Ok(Some(actual));
                }
                Err(ApplicationError::Conflict(
                    "provider changed inverse evidence",
                ))
            }
            (Some(expected), _) => Ok(Some(expected.clone())),
            (None, actual) => Ok(actual),
        }
    }

    fn validate_backup_reference(
        step: &OperationStep,
        reference: &BackupReference,
    ) -> Result<(), ApplicationError> {
        let OperationStep::BackupCreate {
            session_id,
            kind,
            target,
            ..
        } = step
        else {
            return Err(ApplicationError::Conflict(
                "backup reference on non-create step",
            ));
        };
        if reference.session_id != *session_id
            || reference.kind != *kind
            || reference.target != *target
        {
            return Err(ApplicationError::StalePlan);
        }
        reference
            .validate()
            .map_err(|_| ApplicationError::Conflict("backup reference is not verified"))
    }

    fn validate_restore_invocation(
        step: &OperationStep,
        invocation: &BackupRestoreInvocation,
    ) -> Result<(), ApplicationError> {
        let OperationStep::BackupRestore {
            session_id,
            plan_id,
            reference,
            target,
            expected_manifest_digest,
            rollback_reference,
            expected_rollback_manifest_digest,
            ..
        } = step
        else {
            return Err(ApplicationError::Conflict(
                "restore invocation on non-restore step",
            ));
        };
        if invocation.plan_id != *plan_id
            || invocation.reference_id != *reference
            || invocation.target != *target
            || invocation.expected_manifest_digest != *expected_manifest_digest
            || invocation.rollback_reference_id != *rollback_reference
            || invocation.expected_rollback_manifest_digest != *expected_rollback_manifest_digest
            || invocation.provider_invocation.trim().is_empty()
        {
            return Err(ApplicationError::StalePlan);
        }
        let _ = session_id;
        Ok(())
    }

    async fn renew(&self, lease: &mut OperationLease) -> Result<(), ApplicationError> {
        *lease = self.operations.renew_lease(lease, 60).await?;
        Ok(())
    }

    async fn fail_and_release(
        &self,
        lease: &OperationLease,
        error: ApplicationError,
        evidence: Vec<String>,
    ) -> ApplicationError {
        let failure = OperationFailure::from_error(&error, evidence);
        // The store performs the state, evidence, and lease-clear atomically.
        // Its holder predicate prevents a worker with a lost lease from
        // overwriting a newer worker's state.
        let failed = self
            .operations
            .fail_operation(lease.operation, failure, &lease.holder)
            .await;
        if let Err(failure_error) = failed {
            if matches!(failure_error, ApplicationError::Conflict("operation lease")) {
                return failure_error;
            }
            // A persistence outage may prevent the atomic write. Release is
            // still attempted as a liveness fallback; ownership remains
            // checked by the adapter.
            if let Err(release_error) = self.operations.release_lease(lease).await
                && matches!(release_error, ApplicationError::Conflict("operation lease"))
            {
                return release_error;
            }
            return failure_error;
        }
        error
    }

    pub async fn run(
        &self,
        request: &OperationRequest,
        plan: &PlanDescriptor,
        resolved_steps: &[OperationStep],
        audit_scope: AuditScope,
        now: u64,
        holder: &str,
    ) -> Result<Operation, ApplicationError> {
        audit_scope
            .validate()
            .map_err(|_| ApplicationError::Conflict("invalid audit scope"))?;
        if plan.plan_hash != plan.compute_hash() {
            return Err(ApplicationError::StalePlan);
        }
        if plan.is_expired(now) {
            return Err(ApplicationError::ExpiredPlan);
        }
        let proposed = Operation {
            id: OperationId::new(),
            plan_id: plan.id,
            session_id: request.session_id,
            state: OperationState::Planned,
        };
        let operation = if let Some(existing) = self.operations.find_idempotent(request).await? {
            match existing.state {
                OperationState::Accepted | OperationState::RolledBack => return Ok(existing),
                OperationState::Planned | OperationState::Applying => existing,
                // A provider call may have taken effect before reporting an
                // error. Re-running a failed identity would therefore be an
                // unbounded double mutation. Require an explicit rollback
                // using the evidence already persisted for the operation.
                OperationState::Failed => return Err(ApplicationError::Replay),
                OperationState::Verifying | OperationState::Verified => {
                    return Err(ApplicationError::Replay);
                }
            }
        } else if let Some(existing) = self.operations.operation_for_plan(plan.id).await? {
            match existing.state {
                OperationState::Accepted | OperationState::RolledBack => return Ok(existing),
                OperationState::Planned
                | OperationState::Applying
                | OperationState::Verifying
                | OperationState::Verified
                | OperationState::Failed => return Err(ApplicationError::Replay),
            }
        } else {
            self.operations.create_idempotent(request, proposed).await?
        };
        let audit_scope = audit_scope.with_operation(operation.id);
        let mut lease = self
            .operations
            .acquire_lease(operation.id, holder, now, 60)
            .await?;
        if !plan.observed_state_hashes.is_empty()
            && plan.observed_state_hashes.len() != resolved_steps.len()
        {
            return Err(self
                .fail_and_release(
                    &lease,
                    ApplicationError::StalePlan,
                    vec![format!(
                        "expected {} step observations, got {}",
                        resolved_steps.len(),
                        plan.observed_state_hashes.len()
                    )],
                )
                .await);
        }
        let persisted_evidence = self.operations.step_evidence(operation.id).await?;
        if matches!(operation.state, OperationState::Planned)
            && let Err(error) = self
                .operations
                .mark_state(operation.id, OperationState::Applying, &lease.holder)
                .await
        {
            return Err(self.fail_and_release(&lease, error, vec![]).await);
        }
        for (sequence, operation_step) in resolved_steps.iter().enumerate() {
            let sequence = match u32::try_from(sequence) {
                Ok(sequence) => sequence,
                Err(error) => {
                    return Err(self
                        .fail_and_release(&lease, ApplicationError::Port(error.to_string()), vec![])
                        .await);
                }
            };
            if let Err(error) = self.renew(&mut lease).await {
                return Err(self.fail_and_release(&lease, error, vec![]).await);
            }
            let stored_evidence = persisted_evidence
                .iter()
                .find(|item| item.sequence == sequence);
            let observation = match match operation_step {
                OperationStep::BackupRestore { .. } => {
                    self.steps
                        .observe_restore(operation_step, stored_evidence)
                        .await
                }
                OperationStep::BackupCreate { .. } => {
                    self.steps
                        .observe_backup(operation_step, stored_evidence)
                        .await
                }
                _ => self.steps.observe(operation_step, stored_evidence).await,
            } {
                Ok(observation) => observation,
                Err(error) => {
                    return Err(self
                        .fail_and_release(&lease, error, vec![format!("sequence={sequence}")])
                        .await);
                }
            };
            if let Err(error) = self.renew(&mut lease).await {
                return Err(self.fail_and_release(&lease, error, vec![]).await);
            }
            if matches!(
                operation_step,
                OperationStep::BackupRestore { .. } | OperationStep::BackupCreate { .. }
            ) {
                let has_persisted_invocation = stored_evidence
                    .and_then(|item| item.execution.as_ref())
                    .is_some_and(|evidence| {
                        matches!(
                            evidence,
                            StepExecutionEvidence::BackupRestore(_)
                                | StepExecutionEvidence::BackupCreate(_)
                        )
                    });
                if observation.completed && !has_persisted_invocation {
                    return Err(self
                        .fail_and_release(
                            &lease,
                            ApplicationError::Conflict("restore completion lacks invocation"),
                            vec![format!("sequence={sequence}")],
                        )
                        .await);
                }
                if has_persisted_invocation && !observation.completed {
                    return Err(self
                        .fail_and_release(
                            &lease,
                            ApplicationError::Conflict("restore invocation is not verified"),
                            vec![format!("sequence={sequence}")],
                        )
                        .await);
                }
            }
            if observation.completed {
                if let Some(stored) = stored_evidence
                    && stored.state_hash != observation.state_hash
                {
                    return Err(self
                        .fail_and_release(
                            &lease,
                            ApplicationError::StalePlan,
                            vec![format!("sequence={sequence}")],
                        )
                        .await);
                }
                let state_hash = observation.state_hash.clone();
                if let Err(error) = self.renew(&mut lease).await {
                    return Err(self.fail_and_release(&lease, error, vec![]).await);
                }
                if let Err(error) = self
                    .operations
                    .record_step_owned(
                        operation.id,
                        StepEvidence {
                            sequence,
                            state_hash,
                            result: "already-complete".into(),
                            execution: stored_evidence.and_then(|item| item.execution.clone()),
                        },
                        &lease.holder,
                    )
                    .await
                {
                    return Err(self
                        .fail_and_release(
                            &lease,
                            error,
                            vec![
                                format!("sequence={sequence}"),
                                observation.state_hash.clone(),
                            ],
                        )
                        .await);
                }
                if let Err(error) = self.renew(&mut lease).await {
                    return Err(self.fail_and_release(&lease, error, vec![]).await);
                }
                continue;
            }
            if let Some(expected) = plan.observed_state_hashes.get(sequence as usize)
                && observation.state_hash != *expected
            {
                return Err(self
                    .fail_and_release(
                        &lease,
                        ApplicationError::StalePlan,
                        vec![
                            format!("sequence={sequence}"),
                            format!("observed={}", observation.state_hash),
                            format!("expected={expected}"),
                        ],
                    )
                    .await);
            }
            if !observation.unambiguous {
                return Err(self
                    .fail_and_release(
                        &lease,
                        ApplicationError::Conflict("ambiguous external step"),
                        vec![
                            format!("sequence={sequence}"),
                            observation.state_hash.clone(),
                        ],
                    )
                    .await);
            }
            if let Err(error) = self.renew(&mut lease).await {
                return Err(self.fail_and_release(&lease, error, vec![]).await);
            }
            let (result, step_execution_evidence) =
                if matches!(operation_step, OperationStep::BackupRestore { .. }) {
                    let invocation = match self.steps.apply_restore(operation_step).await {
                        Ok(invocation) => invocation,
                        Err(error) => {
                            return Err(self
                                .fail_and_release(
                                    &lease,
                                    error,
                                    vec![format!("sequence={sequence}")],
                                )
                                .await);
                        }
                    };
                    if let Err(error) =
                        Self::validate_restore_invocation(operation_step, &invocation)
                    {
                        return Err(self
                            .fail_and_release(&lease, error, vec![format!("sequence={sequence}")])
                            .await);
                    }
                    let OperationStep::BackupRestore {
                        expected_manifest_digest,
                        ..
                    } = operation_step
                    else {
                        unreachable!("backup invocation result belongs to restore step")
                    };
                    (
                        StepObservation {
                            state_hash: expected_manifest_digest.clone(),
                            completed: false,
                            unambiguous: true,
                        },
                        Some(StepExecutionEvidence::BackupRestore(invocation)),
                    )
                } else if matches!(operation_step, OperationStep::BackupCreate { .. }) {
                    let reference = match self.steps.apply_backup(operation_step).await {
                        Ok(reference) => reference,
                        Err(error) => {
                            return Err(self
                                .fail_and_release(
                                    &lease,
                                    error,
                                    vec![format!("sequence={sequence}")],
                                )
                                .await);
                        }
                    };
                    if let Err(error) = Self::validate_backup_reference(operation_step, &reference)
                    {
                        return Err(self
                            .fail_and_release(
                                &lease,
                                ApplicationError::Conflict("invalid backup reference"),
                                vec![format!("sequence={sequence}"), error.to_string()],
                            )
                            .await);
                    }
                    let state_hash = reference.manifest_digest.clone();
                    (
                        StepObservation {
                            state_hash,
                            completed: false,
                            unambiguous: true,
                        },
                        Some(StepExecutionEvidence::BackupCreate(reference)),
                    )
                } else {
                    let prepared_owned = if let Some(stored) = stored_evidence {
                        if let Some(evidence) = stored.execution.as_ref()
                            && let Err(error) = evidence.validate_for(operation_step)
                        {
                            return Err(self
                                .fail_and_release(
                                    &lease,
                                    error,
                                    vec![format!("sequence={sequence}")],
                                )
                                .await);
                        }
                        if stored.execution.is_none()
                            && Self::requires_prepared_inverse(operation_step)
                        {
                            return Err(self
                                .fail_and_release(
                                    &lease,
                                    ApplicationError::Conflict(
                                        "applied step lacks durable inverse evidence",
                                    ),
                                    vec![format!("sequence={sequence}")],
                                )
                                .await);
                        }
                        stored.execution.clone()
                    } else {
                        let prepared = match self.steps.prepare(operation_step).await {
                            Ok(prepared) => prepared,
                            Err(error) => {
                                return Err(self
                                    .fail_and_release(
                                        &lease,
                                        error,
                                        vec![format!("sequence={sequence}")],
                                    )
                                    .await);
                            }
                        };
                        if let Some(evidence) = prepared.as_ref()
                            && let Err(error) = evidence.validate_for(operation_step)
                        {
                            return Err(self
                                .fail_and_release(
                                    &lease,
                                    error,
                                    vec![format!("sequence={sequence}")],
                                )
                                .await);
                        }
                        if Self::requires_prepared_inverse(operation_step) && prepared.is_none() {
                            return Err(self
                                .fail_and_release(
                                    &lease,
                                    ApplicationError::Conflict(
                                        "step did not capture inverse evidence",
                                    ),
                                    vec![format!("sequence={sequence}")],
                                )
                                .await);
                        }
                        if let Err(error) = self.renew(&mut lease).await {
                            return Err(self.fail_and_release(&lease, error, vec![]).await);
                        }
                        if let Err(error) = self
                            .operations
                            .record_step_owned(
                                operation.id,
                                StepEvidence {
                                    sequence,
                                    state_hash: observation.state_hash.clone(),
                                    result: "prepared".into(),
                                    execution: prepared.clone(),
                                },
                                &lease.holder,
                            )
                            .await
                        {
                            return Err(self
                                .fail_and_release(
                                    &lease,
                                    error,
                                    vec![format!("sequence={sequence}")],
                                )
                                .await);
                        }
                        // Keep the owned value alive through the external call.
                        // A retry after this point must use the persisted copy.
                        prepared
                    };
                    let prepared = prepared_owned.as_ref();
                    let result = match self.steps.apply(operation_step, prepared).await {
                        Ok(result) => result,
                        Err(error) => {
                            return Err(self
                                .fail_and_release(
                                    &lease,
                                    error,
                                    vec![
                                        format!("sequence={sequence}"),
                                        observation.state_hash.clone(),
                                    ],
                                )
                                .await);
                        }
                    };
                    if let Some(evidence) = result.evidence.as_ref()
                        && let Err(error) = evidence.validate_for(operation_step)
                    {
                        return Err(self
                            .fail_and_release(&lease, error, vec![format!("sequence={sequence}")])
                            .await);
                    }
                    let evidence =
                        match Self::reconcile_evidence(operation_step, prepared, result.evidence) {
                            Ok(evidence) => evidence,
                            Err(error) => {
                                return Err(self
                                    .fail_and_release(
                                        &lease,
                                        error,
                                        vec![format!("sequence={sequence}")],
                                    )
                                    .await);
                            }
                        };
                    if Self::requires_prepared_inverse(operation_step) && evidence.is_none() {
                        return Err(self
                            .fail_and_release(
                                &lease,
                                ApplicationError::Conflict("missing applied inverse evidence"),
                                vec![format!("sequence={sequence}")],
                            )
                            .await);
                    }
                    if matches!(operation_step, OperationStep::ExecutionProvision { .. })
                        && !matches!(
                            &evidence,
                            Some(StepExecutionEvidence::Execution {
                                created_provider_unit: Some(_),
                                ..
                            })
                        )
                    {
                        return Err(self
                            .fail_and_release(
                                &lease,
                                ApplicationError::Conflict(
                                    "execution provision lacks created provider identity",
                                ),
                                vec![format!("sequence={sequence}")],
                            )
                            .await);
                    }
                    (result.observation, evidence)
                };
            if let Err(error) = self.renew(&mut lease).await {
                return Err(self.fail_and_release(&lease, error, vec![]).await);
            }
            let result_state_hash = result.state_hash.clone();
            if let Err(error) = self.renew(&mut lease).await {
                return Err(self.fail_and_release(&lease, error, vec![]).await);
            }
            if let Err(error) = self
                .operations
                .record_step_owned(
                    operation.id,
                    StepEvidence {
                        sequence,
                        state_hash: result_state_hash.clone(),
                        result: "applied".into(),
                        execution: step_execution_evidence,
                    },
                    &lease.holder,
                )
                .await
            {
                return Err(self
                    .fail_and_release(
                        &lease,
                        error,
                        vec![format!("sequence={sequence}"), result_state_hash],
                    )
                    .await);
            }
        }
        if let Err(error) = self.renew(&mut lease).await {
            return Err(self.fail_and_release(&lease, error, vec![]).await);
        }
        if let Err(error) = self
            .audit
            .record(application_audit_event(
                plan.actor,
                "operation.completed",
                plan.target.stable_string(),
                FileClassification::Managed,
                audit_scope,
                AuditResult::Success,
                Some(plan.domain_revision),
                None,
                Some(plan.plan_hash.clone()),
                None,
                vec![plan.plan_hash.clone()],
            ))
            .await
        {
            return Err(self
                .fail_and_release(&lease, error, vec![plan.plan_hash.clone()])
                .await);
        }
        if let Err(error) = self.renew(&mut lease).await {
            return Err(self.fail_and_release(&lease, error, vec![]).await);
        }
        self.operations
            .finish_operation(
                &lease,
                OperationState::Verifying,
                serde_json::json!({"plan_hash": plan.plan_hash}),
            )
            .await
    }
}
impl OperationStep {
    fn required_permission(&self) -> Permission {
        match self {
            Self::ExecutionProvision { .. } => Permission::LifecycleStart,
            Self::ExecutionDelete { .. } => Permission::LifecycleStop,
            Self::ServiceLifecycleTransition { .. } => Permission::ServiceLifecycle,
            Self::ClusterRevisionCreate { .. } => Permission::EndpointWrite,
            Self::ExecutionStart { .. } => Permission::LifecycleStart,
            Self::ExecutionStop { .. } => Permission::LifecycleStop,
            Self::ExecutionRestart { .. } => Permission::LifecycleRestart,
            Self::FileWrite { .. } => Permission::FilesWrite,
            Self::FileMove { .. } | Self::FileQuarantine { .. } | Self::FileBatch { .. } => {
                Permission::FilesWrite
            }
            Self::ArtifactStage { .. } => Permission::ArtifactStage,
            Self::ArtifactRegister { .. } => Permission::ArtifactStage,
            Self::ArtifactActivate { .. } => Permission::ArtifactActivate,
            Self::ProxyRollout { .. } => Permission::ProxyRollout,
            Self::WorldWriterCutover { .. } => Permission::WorldWrite,
            Self::EndpointReconnect { .. } => Permission::EndpointWrite,
            Self::BackupCreate { .. } => Permission::BackupCreate,
            Self::BackupRestore { .. } => Permission::BackupRestore,
            Self::AccessPolicyUpdate { .. } => Permission::AccessManage,
            Self::RoutePolicyUpdate { .. } => Permission::EndpointWrite,
            Self::ServiceArchive { .. } => Permission::ServiceArchive,
            Self::ServicePurge { .. } => Permission::ServicePurge,
        }
    }

    fn from_plan(
        step: &PlanStep,
        binding: Option<GameAPBinding>,
        plan_id: PlanId,
        plan_expiry: u64,
        session_id: ChangeSessionId,
        sequence: usize,
    ) -> Result<Self, ApplicationError> {
        let binding_for = |expected: &str| {
            let binding = binding
                .clone()
                .ok_or(ApplicationError::NotFound("gameap binding"))?;
            if binding.fingerprint() != expected {
                return Err(ApplicationError::StalePlan);
            }
            Ok(binding)
        };
        match &step.action {
            PlanStepAction::ExecutionProvision {
                expected_binding_hash,
                ..
            } => Ok(OperationStep::ExecutionProvision {
                binding: binding_for(expected_binding_hash)?,
            }),
            PlanStepAction::ServiceLifecycleTransition {
                service_id,
                expected_state,
                next_state,
                expected_version,
                reason,
            } => Ok(OperationStep::ServiceLifecycleTransition {
                service_id: *service_id,
                expected_state: expected_state.clone(),
                next_state: next_state.clone(),
                expected_version: *expected_version,
                reason: reason.clone(),
            }),
            PlanStepAction::ClusterRevisionCreate {
                cluster_id,
                revision,
                new_endpoint_bindings,
                expected_current_number,
            } => Ok(OperationStep::ClusterRevisionCreate {
                cluster: *cluster_id,
                revision: revision.clone(),
                new_endpoint_bindings: new_endpoint_bindings.clone(),
                expected_current_number: *expected_current_number,
            }),
            PlanStepAction::ExecutionDelete {
                expected_binding_hash,
                expected_state_hash,
                expected_version,
                ..
            } => Ok(OperationStep::ExecutionDelete {
                binding: binding_for(expected_binding_hash)?,
                expected_state_hash: expected_state_hash.clone(),
                expected_version: *expected_version,
                session_id,
            }),
            PlanStepAction::ExecutionLifecycle {
                action,
                expected_binding_hash,
                ..
            } => match action {
                ExecutionLifecycleAction::Start => Ok(OperationStep::ExecutionStart {
                    binding: binding_for(expected_binding_hash)?,
                }),
                ExecutionLifecycleAction::Stop => Ok(OperationStep::ExecutionStop {
                    binding: binding_for(expected_binding_hash)?,
                }),
                ExecutionLifecycleAction::Restart => Ok(OperationStep::ExecutionRestart {
                    binding: binding_for(expected_binding_hash)?,
                }),
            },
            PlanStepAction::FileWrite {
                binding_id: _,
                path,
                expected_binding_hash,
                domain_revision,
                expected_before_digest,
                content,
                classification,
            } => Ok(OperationStep::FileWrite {
                binding: binding_for(expected_binding_hash)?,
                change: FileChange {
                    path: path.clone(),
                    content_digest: content.digest.clone(),
                    classification: classification.clone(),
                },
                content: content.clone(),
                expected_before_digest: expected_before_digest.clone(),
                domain_revision: *domain_revision,
            }),
            PlanStepAction::FileMove {
                from,
                to,
                expected_binding_hash,
                domain_revision,
                expected_before_digest,
                expected_target_digest,
                classification,
                ..
            } => Ok(OperationStep::FileMove {
                binding: binding_for(expected_binding_hash)?,
                from: from.clone(),
                to: to.clone(),
                expected_before_digest: expected_before_digest.clone(),
                expected_target_digest: expected_target_digest.clone(),
                classification: classification.clone(),
                domain_revision: *domain_revision,
            }),
            PlanStepAction::FileQuarantine {
                path,
                expected_binding_hash,
                domain_revision,
                expected_before_digest,
                classification,
                ..
            } => Ok(OperationStep::FileQuarantine {
                binding: binding_for(expected_binding_hash)?,
                path: path.clone(),
                expected_before_digest: expected_before_digest.clone(),
                classification: classification.clone(),
                domain_revision: *domain_revision,
            }),
            PlanStepAction::FileBatch {
                operations,
                expected_binding_hash,
                domain_revision,
                ..
            } => Ok(OperationStep::FileBatch {
                binding: binding_for(expected_binding_hash)?,
                operations: operations.clone(),
                domain_revision: *domain_revision,
            }),
            PlanStepAction::ArtifactStage {
                artifact_id,
                expected_digest,
                expected_version,
                domain_revision,
            } => Ok(OperationStep::ArtifactStage {
                artifact: *artifact_id,
                expected_digest: expected_digest.clone(),
                expected_version: *expected_version,
                domain_revision: *domain_revision,
            }),
            PlanStepAction::ArtifactRegister {
                artifact,
                content,
                expected_version,
                domain_revision,
            } => Ok(OperationStep::ArtifactRegister {
                artifact: artifact.clone(),
                content: content.clone(),
                expected_version: *expected_version,
                domain_revision: *domain_revision,
            }),
            PlanStepAction::ArtifactActivate {
                artifact_id,
                artifact_set_id,
                binding_id,
                expected_binding_hash,
                cluster_id,
                expected_revision,
                target_revision,
                expected_digest,
                expected_version,
                destination_path,
                expected_before_digest,
            } => Ok(OperationStep::ArtifactActivate {
                binding_id: *binding_id,
                binding: binding_for(expected_binding_hash)?,
                artifact: *artifact_id,
                artifact_set: *artifact_set_id,
                cluster: *cluster_id,
                expected_revision: *expected_revision,
                target_revision: *target_revision,
                expected_digest: expected_digest.clone(),
                expected_version: *expected_version,
                destination_path: destination_path.clone(),
                expected_before_digest: expected_before_digest.clone(),
            }),
            PlanStepAction::ProxyRollout {
                pool_id,
                expected_instance_id,
                target_instance_id,
                expected_instance_version,
                target_instance_version,
                expected_instance_state,
                target_instance_state,
                target_binding_id,
                target_binding_hash,
                domain_revision,
                desired_state,
                configuration,
            } => Ok(OperationStep::ProxyRollout {
                expected_instance: *expected_instance_id,
                target_instance: *target_instance_id,
                pool: *pool_id,
                binding: binding_for(target_binding_hash)?,
                expected_instance_version: *expected_instance_version,
                target_instance_version: *target_instance_version,
                expected_instance_state: expected_instance_state.clone(),
                target_instance_state: target_instance_state.clone(),
                target_binding_id: *target_binding_id,
                domain_revision: *domain_revision,
                desired_state: desired_state.clone(),
                configuration: configuration.clone(),
            }),
            PlanStepAction::WorldWriterCutover {
                world_id,
                expected_writer,
                next_writer,
                expected_version,
                expected_writer_binding_id,
                target_writer_binding_id,
                expected_writer_binding_hash,
                target_writer_binding_hash,
                domain_revision,
            } => Ok(OperationStep::WorldWriterCutover {
                world: *world_id,
                from: *expected_writer,
                to: *next_writer,
                expected_version: *expected_version,
                expected_writer_binding_id: *expected_writer_binding_id,
                target_writer_binding_id: *target_writer_binding_id,
                expected_writer_binding_hash: expected_writer_binding_hash.clone(),
                target_writer_binding_hash: target_writer_binding_hash.clone(),
                domain_revision: *domain_revision,
                session_id,
            }),
            PlanStepAction::EndpointRollout {
                expected_binding_id,
                target_binding_id,
                cluster_id,
                expected_revision,
                target_revision,
                expected_version,
                runtime_binding_ids,
                runtime_binding_hashes,
            } => Ok(OperationStep::EndpointReconnect {
                expected_binding_id: *expected_binding_id,
                target_binding_id: *target_binding_id,
                cluster: *cluster_id,
                expected_version: *expected_version,
                expected_revision: *expected_revision,
                target_revision: *target_revision,
                runtime_binding_ids: runtime_binding_ids.clone(),
                runtime_binding_hashes: runtime_binding_hashes.clone(),
            }),
            PlanStepAction::AccessPolicyUpdate {
                policy_id,
                service_id,
                expected_version,
                desired_grants,
                desired_policy_hash,
            } => Ok(OperationStep::AccessPolicyUpdate {
                policy_id: *policy_id,
                service_id: *service_id,
                expected_version: *expected_version,
                desired_grants: desired_grants.clone(),
                desired_policy_hash: desired_policy_hash.clone(),
            }),
            PlanStepAction::RoutePolicyUpdate {
                route_id,
                pool_id,
                service_id,
                expected_cluster,
                target_cluster,
                expected_priority,
                target_priority,
                expected_version,
                disabled,
            } => Ok(OperationStep::RoutePolicyUpdate {
                route_id: *route_id,
                pool_id: *pool_id,
                service_id: *service_id,
                expected_cluster: *expected_cluster,
                target_cluster: *target_cluster,
                expected_priority: *expected_priority,
                target_priority: *target_priority,
                expected_version: *expected_version,
                disabled: *disabled,
            }),
            PlanStepAction::BackupCreate {
                kind,
                target,
                request_hash,
            } => Ok(OperationStep::BackupCreate {
                session_id,
                plan_id,
                plan_expiry,
                idempotency_key: format!("backup:{}:{sequence}", plan_id.as_uuid()),
                kind: *kind,
                target: *target,
                request_hash: request_hash.clone(),
            }),
            PlanStepAction::BackupRestore {
                reference_id,
                target,
                expected_manifest_digest,
                rollback_reference_id,
                expected_rollback_manifest_digest,
                expected_version,
            } => Ok(OperationStep::BackupRestore {
                session_id,
                plan_id,
                plan_expiry,
                idempotency_key: format!("restore:{}:{sequence}", plan_id.as_uuid()),
                reference: *reference_id,
                target: *target,
                expected_manifest_digest: expected_manifest_digest.clone(),
                rollback_reference: *rollback_reference_id,
                expected_rollback_manifest_digest: expected_rollback_manifest_digest.clone(),
                expected_version: *expected_version,
            }),
            PlanStepAction::ServiceArchive {
                service_id,
                expected_version,
                sunsetting_evidence_hash,
            } => Ok(OperationStep::ServiceArchive {
                service_id: *service_id,
                expected_version: *expected_version,
                sunsetting_evidence_hash: sunsetting_evidence_hash.clone(),
                session_id,
            }),
            PlanStepAction::ServicePurge {
                service_id,
                expected_version,
                archive_evidence_hash,
                verified_backup_id,
                archived_at,
            } => Ok(OperationStep::ServicePurge {
                service_id: *service_id,
                expected_version: *expected_version,
                archive_evidence_hash: archive_evidence_hash.clone(),
                verified_backup_id: *verified_backup_id,
                archived_at: *archived_at,
                session_id,
            }),
        }
    }
}

/// Safety gate for bulk edits. Unknown files can be observed but never
/// implicitly removed, and state/secret files are not accepted as config.
pub fn validate_file_batch(changes: &[FileChange]) -> Result<(), ApplicationError> {
    if changes.is_empty() {
        return Err(ApplicationError::Conflict("empty file batch"));
    }
    for change in changes {
        if change.path.is_empty()
            || change.path.starts_with('/')
            || change.path.split('/').any(|p| p == "..")
        {
            return Err(ApplicationError::Conflict("unsafe file path"));
        }
        if matches!(
            change.classification,
            FileClassification::Unknown | FileClassification::State | FileClassification::Secret
        ) {
            return Err(ApplicationError::Conflict(
                "file classification is not writable",
            ));
        }
    }
    Ok(())
}

/// Keep command/audit previews useful without retaining credentials.
pub fn mask_secret(value: &str) -> String {
    value
        .split_whitespace()
        .map(|part| {
            if part.contains('=')
                && (part.to_ascii_lowercase().contains("token")
                    || part.to_ascii_lowercase().contains("pass")
                    || part.to_ascii_lowercase().contains("secret"))
            {
                format!("{}=[REDACTED]", part.split('=').next().unwrap_or("secret"))
            } else {
                part.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authorization {
    pub actor: ActorId,
    pub service: ServiceId,
    pub permission: Permission,
}
#[async_trait]
pub trait Authorizer: Send + Sync {
    async fn authorize(&self, request: &Authorization) -> Result<(), ApplicationError>;
}

pub struct ReadFacade<R> {
    pub repository: R,
}
impl<R: DomainRepository> ReadFacade<R> {
    pub async fn services(&self) -> Result<Vec<Service>, ApplicationError> {
        self.repository.services().await
    }
    pub async fn service(&self, id: ServiceId) -> Result<Service, ApplicationError> {
        self.repository.service(id).await
    }
    pub async fn clusters(&self) -> Result<Vec<GameCluster>, ApplicationError> {
        self.repository.clusters().await
    }
    pub async fn revisions(&self) -> Result<Vec<ClusterRevision>, ApplicationError> {
        self.repository.revisions().await
    }
    pub async fn worlds(&self) -> Result<Vec<World>, ApplicationError> {
        self.repository.worlds().await
    }
    pub async fn proxies(&self) -> Result<Vec<ProxyInstance>, ApplicationError> {
        self.repository.proxies().await
    }
    pub async fn artifacts(&self) -> Result<Vec<Artifact>, ApplicationError> {
        self.repository.artifacts().await
    }
    pub async fn endpoints(&self) -> Result<Vec<ExternalEndpoint>, ApplicationError> {
        self.repository.endpoints().await
    }
    pub async fn sessions(&self) -> Result<Vec<ChangeSession>, ApplicationError> {
        self.repository.sessions().await
    }
    pub async fn operations(&self) -> Result<Vec<Operation>, ApplicationError> {
        self.repository.operations().await
    }
    pub async fn backups(&self) -> Result<Vec<BackupReference>, ApplicationError> {
        self.repository.backups().await
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChangeRequest {
    pub actor: ActorId,
    pub service: ServiceId,
    pub cluster: ClusterId,
    pub domain_revision: u64,
    pub idempotency_key: String,
    pub steps: Vec<PlanStep>,
    /// One observation hash for every step, captured before planning.  The
    /// controller never supplies a single hash for a multi-step plan.
    pub observed_state_hashes: Vec<String>,
    pub expiry: u64,
}

impl ChangeRequest {
    /// Stable request identity used with `Idempotency-Key`. The key itself is
    /// deliberately excluded: reusing a key with a changed payload must
    /// conflict, while an equivalent request with another key is independent.
    pub fn request_hash(&self) -> Result<String, ApplicationError> {
        if self.idempotency_key.trim().is_empty() {
            return Err(ApplicationError::Conflict("idempotency key"));
        }
        let mut canonical = String::new();
        for value in [
            self.actor.as_uuid().to_string(),
            self.service.as_uuid().to_string(),
            self.cluster.as_uuid().to_string(),
            self.domain_revision.to_string(),
            self.expiry.to_string(),
        ] {
            canonical.push_str(&value.len().to_string());
            canonical.push(':');
            canonical.push_str(&value);
        }
        canonical.push('[');
        for hash in &self.observed_state_hashes {
            canonical.push_str(&hash.len().to_string());
            canonical.push(':');
            canonical.push_str(hash);
        }
        canonical.push(']');
        canonical.push('[');
        for step in &self.steps {
            let value = step
                .canonical_bytes()
                .into_iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            canonical.push_str(&value.len().to_string());
            canonical.push(':');
            canonical.push_str(&value);
        }
        canonical.push(']');
        Ok(format!("{:x}", Sha256::digest(canonical.as_bytes())))
    }
}

/// Persistence port for metadata-only SFTP observations. The adapter must
/// resolve endpoint, session ownership and execution binding from durable
/// rows; no provider credential or file content crosses this boundary.
#[async_trait]
pub trait SftpScanRepository: DomainRepository {
    async fn sftp_endpoint(
        &self,
        id: SftpEndpointId,
    ) -> Result<SftpEndpointMetadata, ApplicationError>;
    async fn save_sftp_scan(&self, scan: SftpScan) -> Result<SftpScan, ApplicationError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SftpScanRequest {
    pub actor: ActorId,
    pub service: ServiceId,
    pub endpoint: SftpEndpointId,
    pub binding: BindingId,
    pub session: ChangeSessionId,
    pub before_manifest_hash: String,
    pub after_manifest_hash: String,
    pub changed_paths: Vec<SftpChangedPath>,
    pub observed_at: u64,
    pub source: SftpScanSource,
    pub idempotency_key: String,
    pub request_hash: String,
}

impl SftpScanRequest {
    /// Derive the request identity from the complete metadata payload. The
    /// caller-supplied hash is checked against this value before persistence;
    /// an idempotency key therefore cannot replay a different scan by simply
    /// reusing its old hash.
    pub fn computed_request_hash(&self) -> Result<String, ApplicationError> {
        if self.idempotency_key.trim().is_empty() {
            return Err(ApplicationError::Conflict("sftp scan idempotency key"));
        }
        let mut canonical = String::new();
        fn field(canonical: &mut String, value: String) {
            canonical.push_str(&value.len().to_string());
            canonical.push(':');
            canonical.push_str(&value);
        }
        for value in [
            self.actor.as_uuid().to_string(),
            self.service.as_uuid().to_string(),
            self.endpoint.as_uuid().to_string(),
            self.binding.as_uuid().to_string(),
            self.session.as_uuid().to_string(),
            self.before_manifest_hash.clone(),
            self.after_manifest_hash.clone(),
            self.observed_at.to_string(),
            self.source.as_str().to_owned(),
        ] {
            field(&mut canonical, value);
        }
        let mut paths = self.changed_paths.clone();
        paths.sort_by(|left, right| left.path.cmp(&right.path));
        canonical.push('[');
        for path in paths {
            field(&mut canonical, path.path);
            field(
                &mut canonical,
                match path.kind {
                    SftpChangeKind::Added => "added",
                    SftpChangeKind::Modified => "modified",
                    SftpChangeKind::Removed => "removed",
                }
                .to_owned(),
            );
            field(&mut canonical, path.before_digest.unwrap_or_default());
            field(&mut canonical, path.after_digest.unwrap_or_default());
            field(&mut canonical, path.classification.as_str().to_owned());
        }
        canonical.push(']');
        Ok(format!("{:x}", Sha256::digest(canonical.as_bytes())))
    }
}

pub struct SftpScanService<R, A, C> {
    pub repository: R,
    pub authorizer: A,
    pub audit: C,
}
impl<R: SftpScanRepository, A: Authorizer, C: AuditSink> SftpScanService<R, A, C> {
    pub async fn record_scan(
        &self,
        request: &SftpScanRequest,
    ) -> Result<SftpScan, ApplicationError> {
        let computed_request_hash = request.computed_request_hash()?;
        if request.request_hash != computed_request_hash {
            return Err(ApplicationError::Replay);
        }
        self.authorizer
            .authorize(&Authorization {
                actor: request.actor,
                service: request.service,
                permission: Permission::FilesRead,
            })
            .await?;
        let endpoint = self.repository.sftp_endpoint(request.endpoint).await?;
        if endpoint.service_id != request.service
            || endpoint.execution_binding_id != request.binding
        {
            return Err(ApplicationError::NotFound("sftp endpoint"));
        }
        let session = self
            .repository
            .change_session_for_actor(request.session, request.actor)
            .await?;
        let cluster = session.target_cluster;
        let binding = self
            .repository
            .gameap_binding(request.binding, request.service, cluster)
            .await?;
        let scan = SftpScan::new(
            &endpoint,
            &binding,
            &session,
            &request.before_manifest_hash,
            &request.after_manifest_hash,
            request.changed_paths.clone(),
            request.observed_at,
            request.source,
            &request.idempotency_key,
            &request.request_hash,
        )
        .map_err(|error| ApplicationError::Port(error.to_string()))?;
        let scan = self.repository.save_sftp_scan(scan).await?;
        self.audit
            .record(application_audit_event(
                request.actor,
                "sftp.scan",
                request.endpoint.as_uuid().to_string(),
                FileClassification::Managed,
                AuditScope::for_cluster(request.service, cluster),
                AuditResult::Success,
                None,
                None,
                None,
                Some(request.idempotency_key.clone()),
                vec![
                    scan.before_manifest_hash.clone(),
                    scan.after_manifest_hash.clone(),
                ],
            ))
            .await?;
        Ok(scan)
    }
}

/// Placement checks are intentionally small and provider-neutral. Unknown
/// observations and requirement mismatches are both mutation blockers.
pub fn validate_placement(
    requirements: &PlacementRequirements,
    observation: &NodeCapabilityObservation,
) -> Result<(), ApplicationError> {
    if !requirements.accepts(observation) {
        return Err(ApplicationError::Conflict(
            "node capability does not satisfy placement",
        ));
    }
    Ok(())
}

#[async_trait]
pub trait NodeCapabilityRepository: Send + Sync {
    async fn record_node_capability(
        &self,
        observation: NodeCapabilityObservation,
    ) -> Result<NodeCapabilityObservation, ApplicationError>;
    async fn latest_node_capability(
        &self,
        provider_node_ref: &str,
    ) -> Result<Option<NodeCapabilityObservation>, ApplicationError>;
    async fn node_capability_history(
        &self,
        provider_node_ref: &str,
    ) -> Result<Vec<NodeCapabilityObservation>, ApplicationError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplyResult {
    pub operation: Operation,
    pub accepted: bool,
}
pub struct ChangeCoordinator<R, A, C> {
    pub repository: R,
    pub authorizer: A,
    pub audit: C,
}
impl<R: DomainRepository, A: Authorizer, C: AuditSink> ChangeCoordinator<R, A, C> {
    pub async fn begin(&self, r: &ChangeRequest) -> Result<ChangeSession, ApplicationError> {
        self.authorizer
            .authorize(&Authorization {
                actor: r.actor,
                service: r.service,
                permission: Permission::ChangePlan,
            })
            .await?;
        let cluster = self.repository.cluster(r.cluster).await?;
        if cluster.service_id != r.service {
            return Err(ApplicationError::Forbidden);
        }
        let request_hash = r.request_hash()?;
        let audit = application_audit_event(
            r.actor,
            "change.begin",
            r.cluster.as_uuid().to_string(),
            FileClassification::Managed,
            AuditScope::for_cluster(r.service, r.cluster),
            AuditResult::Success,
            None,
            None,
            None,
            Some(r.idempotency_key.clone()),
            vec![],
        );
        let mut tx = self.repository.transaction().await?;
        let s = ChangeSession {
            id: ChangeSessionId::new(),
            target_cluster: r.cluster,
            // A begin request creates an immediately editable session. The
            // session and its scope are persisted in one transaction so a
            // client cannot observe an unusable Open-only session.
            state: ChangeSessionState::Editing,
            version: 1,
        };
        if let Some(existing) = tx
            .save_session_idempotent_for_actor(
                s.clone(),
                r.actor,
                &r.idempotency_key,
                &request_hash,
                audit,
            )
            .await?
        {
            tx.commit().await?;
            return Ok(existing);
        }
        tx.commit().await?;
        Ok(s)
    }
    pub async fn plan(&self, r: &ChangeRequest) -> Result<PlanDescriptor, ApplicationError> {
        self.authorizer
            .authorize(&Authorization {
                actor: r.actor,
                service: r.service,
                permission: Permission::ChangePlan,
            })
            .await?;
        let resolved_steps =
            resolve_change_steps(&self.repository, r.service, r.cluster, &r.steps).await?;
        if r.observed_state_hashes.len() != resolved_steps.len()
            || r.observed_state_hashes.iter().any(|hash| {
                hash.len() != 64
                    || !hash.bytes().all(|byte| byte.is_ascii_hexdigit())
                    || hash != &hash.to_ascii_lowercase()
            })
        {
            return Err(ApplicationError::Conflict("per-step observed state hashes"));
        }
        let mut p = PlanDescriptor::new(
            r.actor,
            PlanTarget::Cluster(r.cluster),
            r.domain_revision,
            r.expiry,
            resolved_steps
                .iter()
                .map(|(step, _)| step.clone())
                .collect(),
        )
        .map_err(|e| ApplicationError::Port(e.to_string()))?;
        p.observed_state_hashes = r.observed_state_hashes.clone();
        p.plan_hash = p.compute_hash();
        validate_service_consistent_sequence(&self.repository, &p, r.service, r.cluster).await?;
        Ok(p)
    }
    pub async fn plan_for_session(
        &self,
        request: &ChangeRequest,
        session: ChangeSessionId,
        expected_version: u64,
    ) -> Result<PlanDescriptor, ApplicationError> {
        // Resolve the persisted actor ownership before reading the session.
        // A caller-supplied service/cluster pair is not an ownership proof.
        let session_record = self
            .repository
            .change_session_for_actor(session, request.actor)
            .await?;
        if session_record.target_cluster != request.cluster
            || session_record.state != ChangeSessionState::Editing
            || session_record.version != expected_version
        {
            return Err(ApplicationError::Conflict(
                "session version or state is stale",
            ));
        }
        let plan = self.plan(request).await?;
        validate_service_consistent_sequence(
            &self.repository,
            &plan,
            request.service,
            request.cluster,
        )
        .await?;
        validate_staged_content_scope(&self.repository, &plan, session).await?;
        let request_hash = request.request_hash()?;
        let audit = application_audit_event(
            request.actor,
            "change.plan",
            plan.target.stable_string(),
            FileClassification::Managed,
            AuditScope::for_cluster(request.service, request.cluster),
            AuditResult::Success,
            Some(request.domain_revision),
            None,
            Some(plan.plan_hash.clone()),
            Some(request.idempotency_key.clone()),
            vec![plan.plan_hash.clone()],
        );
        let mut tx = self.repository.transaction().await?;
        let existing = tx
            .save_plan_idempotent(
                plan.clone(),
                session,
                &request.idempotency_key,
                &request_hash,
                audit,
            )
            .await?;
        tx.commit().await?;
        Ok(existing.unwrap_or(plan))
    }

    async fn transition(
        &self,
        id: ChangeSessionId,
        next: ChangeSessionState,
        actor: ActorId,
        service: ServiceId,
    ) -> Result<ChangeSession, ApplicationError> {
        let permission = match next {
            ChangeSessionState::Open | ChangeSessionState::Editing | ChangeSessionState::Ready => {
                Permission::ChangePlan
            }
            ChangeSessionState::Applying => Permission::ChangeApply,
            ChangeSessionState::Verifying => Permission::ChangeVerify,
            ChangeSessionState::Accepted => Permission::ChangeAccept,
            ChangeSessionState::RolledBack
            | ChangeSessionState::Aborted
            | ChangeSessionState::Conflicted => Permission::ChangeRollback,
        };
        self.authorizer
            .authorize(&Authorization {
                actor,
                service,
                permission,
            })
            .await?;
        let session = self.repository.change_session_for_actor(id, actor).await?;
        let mut changed = session.clone();
        changed
            .transition(next)
            .map_err(|e| ApplicationError::Conflict(Box::leak(e.to_string().into_boxed_str())))?;
        let mut tx = self.repository.transaction().await?;
        tx.save_session_for_actor(changed.clone(), actor).await?;
        tx.commit().await?;
        self.audit
            .record(application_audit_event(
                actor,
                "change.transition",
                id.as_uuid().to_string(),
                FileClassification::Managed,
                AuditScope::for_cluster(service, session.target_cluster),
                AuditResult::Success,
                None,
                None,
                None,
                None,
                vec![],
            ))
            .await?;
        Ok(changed)
    }
    pub async fn edit(
        &self,
        id: ChangeSessionId,
        actor: ActorId,
        service: ServiceId,
    ) -> Result<ChangeSession, ApplicationError> {
        self.transition(id, ChangeSessionState::Editing, actor, service)
            .await
    }
    pub async fn ready(
        &self,
        id: ChangeSessionId,
        actor: ActorId,
        service: ServiceId,
    ) -> Result<ChangeSession, ApplicationError> {
        self.transition(id, ChangeSessionState::Ready, actor, service)
            .await
    }
    pub async fn mark_applying(
        &self,
        id: ChangeSessionId,
        actor: ActorId,
        service: ServiceId,
    ) -> Result<ChangeSession, ApplicationError> {
        self.transition(id, ChangeSessionState::Applying, actor, service)
            .await
    }
    pub async fn verify_session(
        &self,
        id: ChangeSessionId,
        actor: ActorId,
        service: ServiceId,
    ) -> Result<ChangeSession, ApplicationError> {
        self.transition(id, ChangeSessionState::Verifying, actor, service)
            .await
    }
    pub async fn accept(
        &self,
        id: ChangeSessionId,
        actor: ActorId,
        service: ServiceId,
    ) -> Result<ChangeSession, ApplicationError> {
        self.transition(id, ChangeSessionState::Accepted, actor, service)
            .await
    }
    pub async fn rollback(
        &self,
        id: ChangeSessionId,
        actor: ActorId,
        service: ServiceId,
    ) -> Result<ChangeSession, ApplicationError> {
        self.transition(id, ChangeSessionState::RolledBack, actor, service)
            .await
    }
    pub async fn abort(
        &self,
        id: ChangeSessionId,
        actor: ActorId,
        service: ServiceId,
    ) -> Result<ChangeSession, ApplicationError> {
        self.transition(id, ChangeSessionState::Aborted, actor, service)
            .await
    }
    pub async fn conflict(
        &self,
        id: ChangeSessionId,
        actor: ActorId,
        service: ServiceId,
    ) -> Result<ChangeSession, ApplicationError> {
        self.transition(id, ChangeSessionState::Conflicted, actor, service)
            .await
    }
}

/// Application orchestration for execution operations. It intentionally does
/// not expose credentials or transport-specific values.
pub struct ExecutionService<B, A, C> {
    pub backend: B,
    pub authorizer: A,
    pub audit: C,
}
impl<B: ExecutionBackend, A: Authorizer, C: AuditSink> ExecutionService<B, A, C> {
    async fn auth(
        &self,
        actor: ActorId,
        service: ServiceId,
        permission: Permission,
    ) -> Result<(), ApplicationError> {
        self.authorizer
            .authorize(&Authorization {
                actor,
                service,
                permission,
            })
            .await
    }
    #[allow(clippy::too_many_arguments)]
    async fn audit_event(
        &self,
        actor: ActorId,
        action: &str,
        target: String,
        classification: FileClassification,
        scope: AuditScope,
        result: AuditResult,
        evidence: Vec<String>,
    ) -> Result<(), ApplicationError> {
        self.audit
            .record(application_audit_event(
                actor,
                action,
                target,
                classification,
                scope,
                result,
                None,
                None,
                None,
                None,
                evidence,
            ))
            .await
    }
    #[allow(clippy::too_many_arguments)]
    async fn audit_result<T>(
        &self,
        actor: ActorId,
        action: &str,
        target: String,
        classification: FileClassification,
        scope: AuditScope,
        mut evidence: Vec<String>,
        result: Result<T, ApplicationError>,
    ) -> Result<T, ApplicationError> {
        let outcome = if result.is_ok() { "success" } else { "failure" };
        evidence.push(format!("outcome={outcome}"));
        if let Err(error) = &result {
            evidence.push(format!("result_code={}", application_error_code(error)));
        }
        let audit = self
            .audit_event(
                actor,
                action,
                target,
                classification,
                scope,
                if result.is_ok() {
                    AuditResult::Success
                } else {
                    AuditResult::Failure
                },
                evidence,
            )
            .await;
        match result {
            Ok(value) => {
                audit?;
                Ok(value)
            }
            Err(error) => Err(error),
        }
    }
    pub async fn lifecycle(
        &self,
        binding: &GameAPBinding,
        action: LifecycleDecision,
        actor: ActorId,
        service: ServiceId,
    ) -> Result<(), ApplicationError> {
        let scope = audit_scope_for_binding(service, binding)?;
        let result = match action {
            LifecycleDecision::Start => {
                self.auth(actor, service, Permission::LifecycleStart)
                    .await?;
                self.backend.start(binding).await
            }
            LifecycleDecision::Stop => {
                self.auth(actor, service, Permission::LifecycleStop).await?;
                self.backend.stop(binding).await
            }
            LifecycleDecision::Restart => {
                self.auth(actor, service, Permission::LifecycleRestart)
                    .await?;
                self.backend.restart(binding).await
            }
            LifecycleDecision::NoAction | LifecycleDecision::Accept => Ok(()),
            _ => Err(ApplicationError::Conflict(
                "invalid execution lifecycle action",
            )),
        };
        self.audit_result(
            actor,
            "lifecycle",
            binding.execution_unit_id.clone(),
            FileClassification::State,
            scope,
            vec![format!("action={action:?}")],
            result,
        )
        .await
    }
    pub async fn console_command(
        &self,
        binding: &GameAPBinding,
        command: &str,
        actor: ActorId,
        service: ServiceId,
    ) -> Result<(), ApplicationError> {
        self.auth(actor, service, Permission::ConsoleSend).await?;
        let scope = audit_scope_for_binding(service, binding)?;
        // Providers need the exact command. Redaction is restricted to audit
        // evidence so command semantics (quoting and arguments) are intact.
        let result = self.backend.command(binding, command).await;
        let outcome = if result.is_ok() { "success" } else { "failure" };
        let audit = self
            .audit_event(
                actor,
                "console.command",
                binding.execution_unit_id.clone(),
                FileClassification::Secret,
                scope,
                if result.is_ok() {
                    AuditResult::Success
                } else {
                    AuditResult::Failure
                },
                vec![
                    format!("digest={}", digest_bytes(command.as_bytes())),
                    format!("bytes={}", command.len()),
                    format!("outcome={outcome}"),
                ],
            )
            .await;
        match result {
            Err(error) => Err(error),
            Ok(()) => audit,
        }
    }
    pub async fn files(
        &self,
        binding: &GameAPBinding,
        path: &str,
        actor: ActorId,
        service: ServiceId,
    ) -> Result<Vec<FileEntry>, ApplicationError> {
        self.auth(actor, service, Permission::FilesRead).await?;
        let scope = audit_scope_for_binding(service, binding)?;
        self.audit_result(
            actor,
            "files.list",
            binding.execution_unit_id.clone(),
            FileClassification::Managed,
            scope,
            vec![],
            self.backend.files(binding, path).await,
        )
        .await
    }
    pub async fn read_file(
        &self,
        binding: &GameAPBinding,
        path: &str,
        actor: ActorId,
        service: ServiceId,
    ) -> Result<Vec<u8>, ApplicationError> {
        self.auth(actor, service, Permission::FilesRead).await?;
        let scope = audit_scope_for_binding(service, binding)?;
        let result = self.backend.read_file(binding, path).await;
        let mut evidence = vec![path.into()];
        if let Ok(bytes) = &result {
            evidence.push(format!("digest={}", digest_bytes(bytes)));
            evidence.push(format!("bytes={}", bytes.len()));
        }
        self.audit_result(
            actor,
            "files.read",
            format!("{}:{path}", binding.execution_unit_id),
            FileClassification::Managed,
            scope,
            evidence,
            result,
        )
        .await
    }
    pub async fn download(
        &self,
        binding: &GameAPBinding,
        path: &str,
        actor: ActorId,
        service: ServiceId,
    ) -> Result<Vec<u8>, ApplicationError> {
        self.auth(actor, service, Permission::FilesRead).await?;
        let scope = audit_scope_for_binding(service, binding)?;
        let result = self.backend.download(binding, path).await;
        let mut evidence = vec![path.into()];
        if let Ok(bytes) = &result {
            evidence.push(format!("digest={}", digest_bytes(bytes)));
            evidence.push(format!("bytes={}", bytes.len()));
        }
        self.audit_result(
            actor,
            "files.download",
            format!("{}:{path}", binding.execution_unit_id),
            FileClassification::Managed,
            scope,
            evidence,
            result,
        )
        .await
    }
    pub async fn write(
        &self,
        binding: &GameAPBinding,
        mutation: &FileMutation,
        actor: ActorId,
        service: ServiceId,
    ) -> Result<(), ApplicationError> {
        self.auth(actor, service, Permission::FilesWrite).await?;
        let scope = audit_scope_for_binding(service, binding)?;
        let result = async {
            validate_file_batch(std::slice::from_ref(&mutation.change))?;
            if mutation.mode != FileMutationMode::Text {
                return Err(ApplicationError::Conflict(
                    "binary mutation requires upload",
                ));
            }
            self.apply_file_mutation(binding, mutation)
                .await
                .map(|_| ())
        }
        .await;
        self.audit_result(
            actor,
            "files.write",
            format!("{}:{}", binding.execution_unit_id, mutation.change.path),
            mutation.change.classification.clone(),
            scope,
            vec![
                mutation.change.content_digest.clone(),
                format!("bytes={}", mutation.bytes.len()),
            ],
            result,
        )
        .await
    }
    pub async fn upload(
        &self,
        binding: &GameAPBinding,
        mutation: &FileMutation,
        actor: ActorId,
        service: ServiceId,
    ) -> Result<(), ApplicationError> {
        self.auth(actor, service, Permission::FilesWrite).await?;
        let scope = audit_scope_for_binding(service, binding)?;
        let result = async {
            validate_file_batch(std::slice::from_ref(&mutation.change))?;
            if mutation.mode != FileMutationMode::Binary {
                return Err(ApplicationError::Conflict("text mutation requires write"));
            }
            self.apply_file_mutation(binding, mutation)
                .await
                .map(|_| ())
        }
        .await;
        self.audit_result(
            actor,
            "files.upload",
            format!("{}:{}", binding.execution_unit_id, mutation.change.path),
            mutation.change.classification.clone(),
            scope,
            vec![
                mutation.change.content_digest.clone(),
                mutation.bytes.len().to_string(),
            ],
            result,
        )
        .await
    }
    async fn apply_file_mutation(
        &self,
        binding: &GameAPBinding,
        mutation: &FileMutation,
    ) -> Result<FileRestoreSnapshot, ApplicationError> {
        if mutation.mode == FileMutationMode::Text && std::str::from_utf8(&mutation.bytes).is_err()
        {
            return Err(ApplicationError::VerificationFailed(
                "text mutation is not valid UTF-8".into(),
            ));
        }
        let before = self
            .backend
            .read_file(binding, &mutation.change.path)
            .await?;
        let before_digest = digest_bytes(&before);
        if let Some(expected) = &mutation.expected_before
            && *expected != before_digest
        {
            return Err(ApplicationError::StalePlan);
        }
        if digest_bytes(&mutation.bytes) == mutation.change.content_digest
            && before_digest == mutation.change.content_digest
        {
            return Ok(FileRestoreSnapshot {
                path: mutation.change.path.clone(),
                bytes: before,
                digest: before_digest,
                classification: mutation.change.classification.clone(),
            });
        }
        if digest_bytes(&mutation.bytes) != mutation.change.content_digest {
            return Err(ApplicationError::VerificationFailed(
                "file content digest does not match change".into(),
            ));
        }
        match mutation.mode {
            FileMutationMode::Text => {
                self.backend
                    .write_file(binding, &mutation.change, &mutation.bytes)
                    .await?;
            }
            FileMutationMode::Binary => {
                self.backend
                    .upload(binding, &mutation.change, &mutation.bytes)
                    .await?;
            }
        }
        let after = self
            .backend
            .read_file(binding, &mutation.change.path)
            .await?;
        if digest_bytes(&after) != mutation.change.content_digest {
            return Err(ApplicationError::VerificationFailed(
                "file content digest mismatch after mutation".into(),
            ));
        }
        Ok(FileRestoreSnapshot {
            path: mutation.change.path.clone(),
            bytes: before,
            digest: before_digest,
            classification: mutation.change.classification.clone(),
        })
    }
    pub async fn move_file(
        &self,
        binding: &GameAPBinding,
        from: &str,
        to: &str,
        actor: ActorId,
        service: ServiceId,
    ) -> Result<(), ApplicationError> {
        self.auth(actor, service, Permission::FilesWrite).await?;
        let scope = audit_scope_for_binding(service, binding)?;
        let result = if from.trim().is_empty() || to.trim().is_empty() || from == to {
            Err(ApplicationError::Conflict("invalid file move"))
        } else {
            self.backend.move_file(binding, from, to).await
        };
        self.audit_result(
            actor,
            "files.move",
            binding.execution_unit_id.clone(),
            FileClassification::Managed,
            scope,
            vec![from.into(), to.into()],
            result,
        )
        .await
    }
    pub async fn open_console(
        &self,
        binding: &GameAPBinding,
        actor: ActorId,
        service: ServiceId,
    ) -> Result<Box<dyn ExecutionConsole>, ApplicationError> {
        self.auth(actor, service, Permission::ConsoleRead).await?;
        let scope = audit_scope_for_binding(service, binding)?;
        let result = self.backend.open_console(binding).await;
        let audit = self
            .audit_event(
                actor,
                "console.open",
                binding.execution_unit_id.clone(),
                FileClassification::Secret,
                scope,
                if result.is_ok() {
                    AuditResult::Success
                } else {
                    AuditResult::Failure
                },
                vec![format!(
                    "outcome={}",
                    if result.is_ok() { "success" } else { "failure" }
                )],
            )
            .await;
        match result {
            Err(error) => Err(error),
            Ok(console) => {
                if let Err(error) = audit {
                    // Do not leak an unaudited live stream when the audit sink fails.
                    let mut console = console;
                    let _ = console.close().await;
                    return Err(error);
                }
                Ok(console)
            }
        }
    }
    pub async fn console_send(
        &self,
        console: &mut dyn ExecutionConsole,
        command: &str,
        actor: ActorId,
        service: ServiceId,
    ) -> Result<(), ApplicationError> {
        self.auth(actor, service, Permission::ConsoleSend).await?;
        let scope = AuditScope::for_service(service);
        // As with the one-shot command facade, only the audit receives a
        // digest. Sending a redacted command would change provider behavior.
        let result = console.send(command).await;
        let outcome = if result.is_ok() { "success" } else { "failure" };
        let audit = self
            .audit_event(
                actor,
                "console.send",
                "stream".into(),
                FileClassification::Secret,
                scope,
                if result.is_ok() {
                    AuditResult::Success
                } else {
                    AuditResult::Failure
                },
                vec![
                    format!("digest={}", digest_bytes(command.as_bytes())),
                    format!("bytes={}", command.len()),
                    format!("outcome={outcome}"),
                ],
            )
            .await;
        match result {
            Err(error) => Err(error),
            Ok(()) => audit,
        }
    }
    pub async fn console_receive(
        &self,
        console: &mut dyn ExecutionConsole,
        actor: ActorId,
        service: ServiceId,
    ) -> Result<Option<Vec<u8>>, ApplicationError> {
        self.auth(actor, service, Permission::ConsoleRead).await?;
        let scope = AuditScope::for_service(service);
        let result = console.receive().await;
        let mut evidence = result
            .as_ref()
            .ok()
            .and_then(|frame| frame.as_ref())
            .map_or_else(
                || vec!["eof".into()],
                |bytes| {
                    vec![
                        format!("digest={}", digest_bytes(bytes)),
                        format!("bytes={}", bytes.len()),
                    ]
                },
            );
        if let Err(error) = &result {
            evidence.push(format!("result_code={}", application_error_code(error)));
        }
        self.audit_result(
            actor,
            "console.receive",
            "stream".into(),
            FileClassification::Secret,
            scope,
            std::mem::take(&mut evidence),
            result,
        )
        .await
    }
    #[allow(clippy::question_mark)]
    pub async fn close_console(
        &self,
        console: &mut dyn ExecutionConsole,
        binding: &GameAPBinding,
        actor: ActorId,
        service: ServiceId,
    ) -> Result<(), ApplicationError> {
        let authorization = self.auth(actor, service, Permission::ConsoleRead).await;
        let scope = audit_scope_for_binding(service, binding)?;
        let result = console.close().await;
        let audit = self
            .audit_event(
                actor,
                "console.close",
                binding.execution_unit_id.clone(),
                FileClassification::Secret,
                scope,
                if result.is_ok() {
                    AuditResult::Success
                } else {
                    AuditResult::Failure
                },
                vec![format!(
                    "outcome={}",
                    if result.is_ok() { "success" } else { "failure" }
                )],
            )
            .await;
        if let Err(error) = authorization {
            return Err(error);
        }
        match result {
            Err(error) => Err(error),
            Ok(()) => audit,
        }
    }
    pub async fn apply_batch(
        &self,
        binding: &GameAPBinding,
        mutations: &[FileMutation],
        actor: ActorId,
        service: ServiceId,
    ) -> Result<(), ApplicationError> {
        self.auth(actor, service, Permission::FilesBatch).await?;
        let scope = audit_scope_for_binding(service, binding)?;
        let result = async {
            if mutations.is_empty() || mutations.len() > 1024 {
                return Err(ApplicationError::Conflict("file batch exceeds limit"));
            }
            let mut applied: Vec<(FileMutation, FileRestoreSnapshot)> =
                Vec::with_capacity(mutations.len());
            for mutation in mutations {
                validate_file_batch(std::slice::from_ref(&mutation.change))?;
                let snapshot = match self.apply_file_mutation(binding, mutation).await {
                    Ok(snapshot) => snapshot,
                    Err(error) => {
                        let mut rollback_evidence = Vec::new();
                        for (previous, snapshot) in applied.iter().rev() {
                            match self.backend.restore_file_snapshot(binding, snapshot).await {
                                Ok(()) => rollback_evidence
                                    .push(format!("restored={}", previous.change.path)),
                                Err(rollback_error) => {
                                    rollback_evidence.push(format!(
                                        "restore_failed={}:{}",
                                        previous.change.path, rollback_error
                                    ));
                                    return Err(ApplicationError::RollbackConflict(format!(
                                        "original={error:?}; {}",
                                        rollback_evidence.join(",")
                                    )));
                                }
                            }
                        }
                        return Err(error);
                    }
                };
                applied.push((mutation.clone(), snapshot));
            }
            Ok(())
        }
        .await;
        self.audit_result(
            actor,
            "files.batch_write",
            binding.execution_unit_id.clone(),
            FileClassification::MutableConfig,
            scope,
            vec![mutations.len().to_string()],
            result,
        )
        .await
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactActivation {
    pub operation: OperationId,
    pub change_session: ChangeSessionId,
    pub revision: RevisionId,
    pub execution: GameAPBinding,
    pub path: String,
    pub artifact: Artifact,
}

pub struct ArtifactService<P, S, A, C> {
    pub provider: P,
    pub store: S,
    pub authorizer: A,
    pub audit: C,
}
impl<P: ArtifactProvider, S: ArtifactStore, A: Authorizer, C: AuditSink>
    ArtifactService<P, S, A, C>
{
    pub async fn discover(
        &self,
        query: &str,
        actor: ActorId,
        service: ServiceId,
    ) -> Result<Vec<ArtifactCandidate>, ApplicationError> {
        self.authorizer
            .authorize(&Authorization {
                actor,
                service,
                permission: Permission::ArtifactDiscover,
            })
            .await?;
        self.provider.discover(query).await
    }
    pub async fn stage(
        &self,
        candidate: &ArtifactCandidate,
        actor: ActorId,
        service: ServiceId,
    ) -> Result<String, ApplicationError> {
        self.authorizer
            .authorize(&Authorization {
                actor,
                service,
                permission: Permission::ArtifactStage,
            })
            .await?;
        let artifact = &candidate.artifact;
        if artifact.digest.trim().is_empty() {
            return Err(ApplicationError::VerificationFailed(
                "artifact digest is missing".into(),
            ));
        }
        let bytes = self.provider.download(candidate).await?;
        let actual = digest_bytes(&bytes);
        if actual != artifact.digest {
            return Err(ApplicationError::VerificationFailed(
                "artifact digest mismatch".into(),
            ));
        }
        if self.store.has(&artifact.digest).await? {
            let existing = self.store.read(&artifact.digest).await?;
            if digest_bytes(&existing) != artifact.digest {
                return Err(ApplicationError::VerificationFailed(
                    "stored artifact digest mismatch".into(),
                ));
            }
        } else {
            self.store.put(&artifact.digest, &bytes).await?;
        }
        self.audit
            .record(application_audit_event(
                actor,
                "artifact.stage",
                artifact.digest.clone(),
                FileClassification::Artifact,
                AuditScope::for_service(service),
                AuditResult::Success,
                None,
                None,
                None,
                None,
                vec![actual.clone()],
            ))
            .await?;
        Ok(actual)
    }
    /// Activate a staged artifact through the execution file port. The CAS is
    /// deliberately unable to activate files; this method binds activation to
    /// an operation, change session, immutable revision, and execution unit.
    pub async fn activate<E: ExecutionBackend>(
        &self,
        activation: &ArtifactActivation,
        backend: &E,
        actor: ActorId,
        service: ServiceId,
    ) -> Result<(), ApplicationError> {
        self.authorizer
            .authorize(&Authorization {
                actor,
                service,
                permission: Permission::ArtifactActivate,
            })
            .await?;
        let artifact = &activation.artifact;
        if !self.store.has(&artifact.digest).await? {
            return Err(ApplicationError::Conflict("artifact is not staged"));
        }
        let bytes = self.store.read(&artifact.digest).await?;
        if digest_bytes(&bytes) != artifact.digest {
            return Err(ApplicationError::VerificationFailed(
                "staged artifact digest mismatch".into(),
            ));
        }
        let change = FileChange {
            path: activation.path.clone(),
            content_digest: artifact.digest.clone(),
            classification: FileClassification::Artifact,
        };
        validate_file_batch(std::slice::from_ref(&change))?;
        let before = backend
            .download(&activation.execution, &activation.path)
            .await?;
        if digest_bytes(&before) != artifact.digest
            && let Err(upload_error) = backend.upload(&activation.execution, &change, &bytes).await
        {
            let observed = backend
                .download(&activation.execution, &activation.path)
                .await?;
            if digest_bytes(&observed) != artifact.digest {
                return Err(upload_error);
            }
        }
        let observed = backend
            .download(&activation.execution, &activation.path)
            .await?;
        if digest_bytes(&observed) != artifact.digest {
            return Err(ApplicationError::VerificationFailed(
                "artifact activation digest mismatch".into(),
            ));
        }
        let scope = audit_scope_for_binding(service, &activation.execution)?
            .with_operation(activation.operation);
        self.audit
            .record(application_audit_event(
                actor,
                "artifact.activate",
                activation.execution.execution_unit_id.clone(),
                FileClassification::Artifact,
                scope,
                AuditResult::Success,
                None,
                None,
                None,
                None,
                vec![
                    activation.operation.as_uuid().to_string(),
                    activation.change_session.as_uuid().to_string(),
                    activation.revision.as_uuid().to_string(),
                    artifact.digest.clone(),
                ],
            ))
            .await
    }
}

fn digest_bytes(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn application_error_code(error: &ApplicationError) -> &'static str {
    match error {
        ApplicationError::NotFound(_) => "not_found",
        ApplicationError::Forbidden => "forbidden",
        ApplicationError::Conflict(_) => "conflict",
        ApplicationError::RollbackConflict(_) => "rollback_conflict",
        ApplicationError::StalePlan => "stale_plan",
        ApplicationError::ExpiredPlan => "expired_plan",
        ApplicationError::Replay => "replay",
        ApplicationError::BackupUnavailable => "backup_unavailable",
        ApplicationError::VerificationFailed(_) => "verification_failed",
        ApplicationError::Port(_) => "port",
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyRollout {
    pub new: ProxyEdgeBinding,
    pub old: ProxyEdgeBinding,
}
pub struct ProxyService<E, H, A, C> {
    pub edge: E,
    pub health: H,
    pub authorizer: A,
    pub audit: C,
}
impl<E: ProxyEdge, H: HealthVerifier, A: Authorizer, C: AuditSink> ProxyService<E, H, A, C> {
    async fn rollback_after_add(
        &self,
        new: &ProxyEdgeBinding,
        old: &ProxyEdgeBinding,
        old_removed: bool,
        error: ApplicationError,
    ) -> ApplicationError {
        let restore_old = if old_removed {
            Some(self.edge.add(old).await)
        } else {
            None
        };
        let remove_new = self.edge.remove(new).await;
        if restore_old.as_ref().is_some_and(|result| result.is_err()) || remove_new.is_err() {
            return ApplicationError::RollbackConflict(format!(
                "original={error:?}; restore_old={restore_old:?}; remove_new={remove_new:?}"
            ));
        }
        error
    }
    fn binding_with_hash(binding: &ProxyEdgeBinding, observed_hash: &str) -> ProxyEdgeBinding {
        let mut binding = binding.clone();
        binding.observed_hash = observed_hash.to_owned();
        binding
    }
    fn check_observation_identity(
        binding: &ProxyEdgeBinding,
        observation: &ProxyEdgeObservation,
    ) -> Result<(), ApplicationError> {
        if observation.instance_id != binding.instance_id
            || observation.provider_network_id != binding.provider_network_id
            || observation.domain_network_id != binding.domain_network_id
            || observation.backend_set_id != binding.backend_set_id
            || observation.backend_address != binding.backend_address
            || observation.revision != binding.revision
            || observation.evidence_hash.trim().is_empty()
        {
            return Err(ApplicationError::StalePlan);
        }
        Ok(())
    }
    fn check_observation(
        binding: &ProxyEdgeBinding,
        observation: &ProxyEdgeObservation,
    ) -> Result<(), ApplicationError> {
        Self::check_observation_identity(binding, observation)?;
        if observation.evidence_hash != binding.observed_hash {
            return Err(ApplicationError::StalePlan);
        }
        Ok(())
    }
    /// The only public rollout path. Both edge state and drain completion are
    /// observed through application-owned ports; a request cannot self-report
    /// a successful drain.
    pub async fn roll<O: ConnectionObserver, R: ProxyEdgeResolver>(
        &self,
        r: ProxyRollout,
        resolver: &R,
        observer: &O,
        actor: ActorId,
        service: ServiceId,
    ) -> Result<(), ApplicationError> {
        self.authorizer
            .authorize(&Authorization {
                actor,
                service,
                permission: Permission::ProxyRollout,
            })
            .await?;
        r.new.validate()?;
        r.old.validate()?;
        let new_observation = resolver.resolve(&r.new).await?;
        Self::check_observation(&r.new, &new_observation)?;
        let old_observation = resolver.resolve(&r.old).await?;
        Self::check_observation(&r.old, &old_observation)?;

        self.edge.prepare(&r.new).await?;
        self.edge.configure(&r.new).await?;
        self.health.verify(&r.new.backend_address).await?;
        self.edge.add(&r.new).await?;
        let post_add_observation = match resolver.resolve(&r.new).await {
            Ok(observation) => {
                if let Err(error) = Self::check_observation_identity(&r.new, &observation) {
                    return Err(self.rollback_after_add(&r.new, &r.old, false, error).await);
                }
                observation
            }
            Err(error) => {
                return Err(self.rollback_after_add(&r.new, &r.old, false, error).await);
            }
        };
        let post_add_new = Self::binding_with_hash(&r.new, &post_add_observation.evidence_hash);
        let post_add_old = Self::binding_with_hash(&r.old, &post_add_observation.evidence_hash);
        let connect_evidence = match self.edge.real_connect(&post_add_new).await {
            Ok(evidence) => evidence,
            Err(error) => {
                return Err(self
                    .rollback_after_add(&post_add_new, &post_add_old, false, error)
                    .await);
            }
        };
        if !connect_evidence.observed || connect_evidence.hash.trim().is_empty() {
            return Err(self
                .rollback_after_add(
                    &post_add_new,
                    &post_add_old,
                    false,
                    ApplicationError::VerificationFailed(
                        "real connection evidence unavailable".into(),
                    ),
                )
                .await);
        }
        if let Err(error) = self.edge.drain(&post_add_old).await {
            return Err(self
                .rollback_after_add(&post_add_new, &post_add_old, false, error)
                .await);
        }
        let old_removed = true;
        let final_observation = match resolver.resolve(&post_add_new).await {
            Ok(observation) => {
                if let Err(error) = Self::check_observation_identity(&post_add_new, &observation) {
                    return Err(self
                        .rollback_after_add(&post_add_new, &post_add_old, old_removed, error)
                        .await);
                }
                observation
            }
            Err(error) => {
                return Err(self
                    .rollback_after_add(&post_add_new, &post_add_old, old_removed, error)
                    .await);
            }
        };
        let final_old = Self::binding_with_hash(&post_add_old, &final_observation.evidence_hash);
        let evidence = match observer.observe(&r.old.backend_address).await {
            Ok(evidence) => evidence,
            Err(error) => {
                return Err(self
                    .rollback_after_add(&post_add_new, &final_old, old_removed, error)
                    .await);
            }
        };
        if !evidence.observed || evidence.active != 0 || evidence.hash.trim().is_empty() {
            return Err(self
                .rollback_after_add(
                    &post_add_new,
                    &final_old,
                    old_removed,
                    ApplicationError::Conflict("drain evidence unknown"),
                )
                .await);
        }
        if let Err(error) = self.edge.stop(&final_old).await {
            return Err(self
                .rollback_after_add(&post_add_new, &final_old, old_removed, error)
                .await);
        }
        let scope = AuditScope::for_service(service);
        match self
            .audit
            .record(application_audit_event(
                actor,
                "proxy.rollout",
                r.new.backend_set_id.clone(),
                FileClassification::Managed,
                scope,
                AuditResult::Success,
                None,
                None,
                None,
                None,
                vec![
                    new_observation.evidence_hash,
                    old_observation.evidence_hash,
                    post_add_observation.evidence_hash,
                    final_observation.evidence_hash,
                    connect_evidence.hash,
                    evidence.hash,
                ],
            ))
            .await
        {
            Ok(()) => Ok(()),
            Err(error) => Err(ApplicationError::RollbackConflict(format!(
                "post-stop failure requires operator rollback with restart and health check: {error:?}"
            ))),
        }
    }
}

pub struct WorldService<B, H, A, C> {
    pub backup: B,
    pub health: H,
    pub authorizer: A,
    pub audit: C,
}
impl<B: BackupProvider, H: HealthVerifier, A: Authorizer, C: AuditSink> WorldService<B, H, A, C> {
    async fn create_verified_backup(
        &self,
        request: &BackupRequest,
    ) -> Result<BackupReference, ApplicationError> {
        request.validate()?;
        let mut backup = self
            .backup
            .create(request)
            .await
            .map_err(|_| ApplicationError::BackupUnavailable)?;
        if backup.session_id != request.session_id
            || backup.kind != request.kind
            || backup.target != request.target
        {
            return Err(ApplicationError::Conflict("backup scope mismatch"));
        }
        let observation = self.backup.verify(&backup).await?;
        if observation.manifest_digest != backup.manifest_digest {
            return Err(ApplicationError::VerificationFailed(
                "backup manifest changed during verification".into(),
            ));
        }
        backup.verified_at = Some(observation.observed_at);
        backup
            .validate()
            .map_err(|error| ApplicationError::Port(error.to_string()))?;
        Ok(backup)
    }

    pub async fn cutover(
        &self,
        world: &mut World,
        from: ClusterId,
        to: ClusterId,
        backup_request: &BackupRequest,
        actor: ActorId,
        service: ServiceId,
    ) -> Result<BackupReference, ApplicationError> {
        self.authorizer
            .authorize(&Authorization {
                actor,
                service,
                permission: Permission::WorldWrite,
            })
            .await?;
        if !world.current_writers.contains(&from) {
            return Err(ApplicationError::Conflict("stale world writer"));
        }
        if backup_request.target != BackupTarget::World(world.id)
            || backup_request.kind != BackupKind::World
        {
            return Err(ApplicationError::Conflict("world backup scope"));
        }
        let backup = self.create_verified_backup(backup_request).await?;
        world.remove_writer(from);
        world
            .assign_writer(to)
            .map_err(|e| ApplicationError::Port(e.to_string()))?;
        self.health.verify(&world.key).await?;
        self.audit
            .record(application_audit_event(
                actor,
                "world.writer_cutover",
                world.key.clone(),
                FileClassification::State,
                AuditScope::for_world(service, world.id),
                AuditResult::Success,
                None,
                None,
                None,
                None,
                vec![backup.id.as_uuid().to_string()],
            ))
            .await?;
        Ok(backup)
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn cutover_with_runtime<R: WorldRuntime, S: WorldStorage>(
        &self,
        world: &mut World,
        from: ClusterId,
        to: ClusterId,
        expected_version: u64,
        backup_request: &BackupRequest,
        runtime: &R,
        storage: &S,
        actor: ActorId,
        service: ServiceId,
    ) -> Result<BackupReference, ApplicationError> {
        self.authorizer
            .authorize(&Authorization {
                actor,
                service,
                permission: Permission::WorldWrite,
            })
            .await?;
        if !world.current_writers.contains(&from) {
            return Err(ApplicationError::Conflict("stale world writer"));
        }
        if backup_request.target != BackupTarget::World(world.id)
            || backup_request.kind != BackupKind::World
        {
            return Err(ApplicationError::Conflict("world backup scope"));
        }
        let backup = self.create_verified_backup(backup_request).await?;
        runtime.stop_and_flush(from, world.id).await?;
        if let Err(error) = storage
            .compare_and_swap_writer(world.id, expected_version, Some(from), to)
            .await
        {
            let _ = runtime.start(from, world.id).await;
            return Err(error);
        }
        let applied_version = expected_version.saturating_add(1);
        world.remove_writer(from);
        if let Err(error) = world.assign_writer(to) {
            let _ = storage
                .compare_and_swap_writer(world.id, applied_version, Some(to), from)
                .await;
            let _ = runtime.start(from, world.id).await;
            return Err(ApplicationError::Port(error.to_string()));
        }
        if let Err(error) = runtime.start(to, world.id).await {
            let _ = storage
                .compare_and_swap_writer(world.id, applied_version, Some(to), from)
                .await;
            world.remove_writer(to);
            let _ = world.assign_writer(from);
            let _ = runtime.start(from, world.id).await;
            return Err(error);
        }
        if let Err(error) = self.health.verify(&world.key).await {
            let _ = storage
                .compare_and_swap_writer(world.id, applied_version, Some(to), from)
                .await;
            world.remove_writer(to);
            let _ = world.assign_writer(from);
            let _ = runtime.start(from, world.id).await;
            return Err(error);
        }
        self.audit
            .record(application_audit_event(
                actor,
                "world.writer_cutover",
                world.key.clone(),
                FileClassification::State,
                AuditScope::for_world(service, world.id),
                AuditResult::Success,
                None,
                None,
                None,
                None,
                vec![
                    backup.id.as_uuid().to_string(),
                    "stop-flush".into(),
                    "cas".into(),
                ],
            ))
            .await?;
        Ok(backup)
    }
}

pub struct EndpointService<D, H, A, C> {
    pub dns: D,
    pub health: H,
    pub authorizer: A,
    pub audit: C,
}
impl<D: DnsResolver, H: HealthVerifier, A: Authorizer, C: AuditSink> EndpointService<D, H, A, C> {
    pub async fn rollout(
        &self,
        endpoint: &ExternalEndpoint,
        binding: &EndpointBinding,
        actor: ActorId,
        service: ServiceId,
    ) -> Result<Vec<String>, ApplicationError> {
        self.authorizer
            .authorize(&Authorization {
                actor,
                service,
                permission: Permission::EndpointWrite,
            })
            .await?;
        let addresses = self
            .dns
            .resolve(&endpoint.logical_hostname, endpoint.port)
            .await?;
        if addresses.is_empty() {
            return Err(ApplicationError::VerificationFailed(
                "endpoint did not resolve".into(),
            ));
        }
        self.health
            .verify(&format!("{}:{}", endpoint.logical_hostname, endpoint.port))
            .await?;
        self.audit
            .record(application_audit_event(
                actor,
                "endpoint.rollout",
                binding.cluster_id.as_uuid().to_string(),
                FileClassification::Managed,
                AuditScope::for_cluster(service, binding.cluster_id),
                AuditResult::Success,
                None,
                None,
                None,
                None,
                addresses.clone(),
            ))
            .await?;
        Ok(addresses)
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn rollout_with_runtime<S: EndpointBindingStore, R: EndpointRuntime>(
        &self,
        expected_endpoint: &ExternalEndpoint,
        target_endpoint: &ExternalEndpoint,
        expected: &EndpointBinding,
        target: &EndpointBinding,
        expected_version: u64,
        store: &S,
        runtime: &R,
        actor: ActorId,
        service: ServiceId,
    ) -> Result<Vec<String>, ApplicationError> {
        self.authorizer
            .authorize(&Authorization {
                actor,
                service,
                permission: Permission::EndpointWrite,
            })
            .await?;
        if expected.endpoint_id != expected_endpoint.id
            || target.endpoint_id != target_endpoint.id
            || expected.cluster_id != target.cluster_id
            || expected.revision_id == target.revision_id
            || expected.binding_key != target.binding_key
            || expected_endpoint.kind != target_endpoint.kind
            || expected_endpoint.role != target_endpoint.role
            || expected_endpoint.port != target_endpoint.port
        {
            return Err(ApplicationError::Conflict("endpoint rollout binding pair"));
        }
        let addresses = self
            .dns
            .resolve(&target_endpoint.logical_hostname, target_endpoint.port)
            .await?;
        if addresses.is_empty() {
            return Err(ApplicationError::VerificationFailed(
                "endpoint did not resolve".into(),
            ));
        }
        store
            .activate_revision(expected, target, expected_version)
            .await?;
        if let Err(error) = runtime.restart_and_reconnect(target).await {
            return Err(Self::endpoint_compensation_error(
                error,
                store
                    .rollback_revision(
                        target.cluster_id,
                        expected.id,
                        target.id,
                        expected_version.saturating_add(1),
                    )
                    .await,
            ));
        }
        if let Err(error) = self
            .health
            .verify(&format!(
                "{}:{}",
                target_endpoint.logical_hostname, target_endpoint.port
            ))
            .await
        {
            return Err(Self::endpoint_compensation_error(
                error,
                store
                    .rollback_revision(
                        target.cluster_id,
                        expected.id,
                        target.id,
                        expected_version.saturating_add(1),
                    )
                    .await,
            ));
        }
        self.audit
            .record(application_audit_event(
                actor,
                "endpoint.rollout",
                target.cluster_id.as_uuid().to_string(),
                FileClassification::Managed,
                AuditScope::for_cluster(service, target.cluster_id),
                AuditResult::Success,
                None,
                None,
                None,
                None,
                addresses.clone(),
            ))
            .await?;
        Ok(addresses)
    }

    fn endpoint_compensation_error(
        original: ApplicationError,
        compensation: Result<(), ApplicationError>,
    ) -> ApplicationError {
        match compensation {
            Ok(()) => original,
            Err(error) => ApplicationError::RollbackConflict(format!(
                "endpoint rollout compensation failed after {original}: {error}"
            )),
        }
    }
}

pub struct BackupService<B, A> {
    pub provider: B,
    pub authorizer: A,
}
impl<B: BackupProvider, A: Authorizer> BackupService<B, A> {
    pub async fn create(
        &self,
        request: &BackupRequest,
        actor: ActorId,
        service: ServiceId,
    ) -> Result<BackupReference, ApplicationError> {
        self.authorizer
            .authorize(&Authorization {
                actor,
                service,
                permission: Permission::BackupCreate,
            })
            .await?;
        request.validate()?;
        let mut backup = self
            .provider
            .create(request)
            .await
            .map_err(|_| ApplicationError::BackupUnavailable)?;
        if backup.session_id != request.session_id
            || backup.kind != request.kind
            || backup.target != request.target
        {
            return Err(ApplicationError::Conflict("backup scope mismatch"));
        }
        let observation = self.provider.verify(&backup).await?;
        if observation.manifest_digest != backup.manifest_digest {
            return Err(ApplicationError::VerificationFailed(
                "backup manifest changed during verification".into(),
            ));
        }
        backup.verified_at = Some(observation.observed_at);
        backup
            .validate()
            .map_err(|error| ApplicationError::Port(error.to_string()))?;
        Ok(backup)
    }
    pub async fn restore(
        &self,
        request: &BackupRestoreRequest,
        actor: ActorId,
        service: ServiceId,
    ) -> Result<BackupRestoreInvocation, ApplicationError> {
        self.authorizer
            .authorize(&Authorization {
                actor,
                service,
                permission: Permission::BackupRestore,
            })
            .await?;
        if request.reference.session_id != request.session_id
            || request.reference.target != request.target
            || request.rollback_reference.session_id != request.session_id
            || request.rollback_reference.target != request.target
            || request.reference.id == request.rollback_reference.id
            || request.reference.verified_at.is_none()
            || request.rollback_reference.verified_at.is_none()
        {
            return Err(ApplicationError::Conflict("backup restore scope"));
        }
        if request.plan_id == PlanId::from_uuid(uuid::Uuid::nil())
            || request.plan_expiry == 0
            || request.idempotency_key.trim().is_empty()
        {
            return Err(ApplicationError::Conflict("backup restore plan"));
        }
        self.provider.restore(request).await
    }
}

pub async fn transition_service(
    service: &mut Service,
    next: ServiceLifecycle,
    actor: ActorId,
    authorizer: &impl Authorizer,
    audit: &impl AuditSink,
) -> Result<(), ApplicationError> {
    authorizer
        .authorize(&Authorization {
            actor,
            service: service.id,
            permission: Permission::ServiceLifecycle,
        })
        .await?;
    service
        .transition(next)
        .map_err(|e| ApplicationError::Conflict(Box::leak(e.to_string().into_boxed_str())))?;
    audit
        .record(application_audit_event(
            actor,
            "service.lifecycle",
            service.id.as_uuid().to_string(),
            FileClassification::Managed,
            AuditScope::for_service(service.id),
            AuditResult::Success,
            None,
            None,
            None,
            None,
            vec![],
        ))
        .await
}
pub async fn purge_service(
    service: &Service,
    actor: ActorId,
    authorizer: &impl Authorizer,
) -> Result<(), ApplicationError> {
    authorizer
        .authorize(&Authorization {
            actor,
            service: service.id,
            permission: Permission::ServicePurge,
        })
        .await?;
    if service.lifecycle != ServiceLifecycle::Archived {
        return Err(ApplicationError::Conflict(
            "only archived services may be purged",
        ));
    }
    Ok(())
}

#[derive(Default, Clone)]
pub struct MemoryRepository {
    inner: Arc<Mutex<MemoryState>>,
}
#[derive(Default)]
struct MemoryState {
    networks: BTreeMap<NetworkId, MCPlayNetwork>,
    services: BTreeMap<ServiceId, Service>,
    clusters: BTreeMap<ClusterId, GameCluster>,
    revisions: BTreeMap<RevisionId, (ClusterId, ClusterRevision)>,
    worlds: BTreeMap<WorldId, (ClusterId, World)>,
    proxy_pools: BTreeMap<ProxyPoolId, ProxyPool>,
    proxies: BTreeMap<ProxyInstanceId, ProxyInstance>,
    routes: BTreeMap<RouteId, Route>,
    route_pools: BTreeMap<RouteId, ProxyPoolId>,
    artifacts: BTreeMap<ArtifactId, Artifact>,
    artifact_sets: BTreeMap<ArtifactSetId, ArtifactSet>,
    endpoints: BTreeMap<EndpointId, ExternalEndpoint>,
    endpoint_bindings: BTreeMap<BindingId, EndpointBinding>,
    access_policies: BTreeMap<PolicyId, AccessPolicy>,
    policy_clusters: BTreeMap<PolicyId, Vec<ClusterId>>,
    bindings: BTreeMap<BindingId, (ServiceId, ClusterId, GameAPBinding)>,
    sessions: BTreeMap<ChangeSessionId, ChangeSession>,
    session_actors: BTreeMap<ChangeSessionId, ActorId>,
    begin_requests: BTreeMap<(ActorId, String), (String, ChangeSessionId)>,
    operations: BTreeMap<OperationId, Operation>,
    plans: BTreeMap<PlanId, (PlanDescriptor, ChangeSessionId)>,
    plan_requests: BTreeMap<(ChangeSessionId, String), (String, PlanId)>,
    audits: Vec<AuditEvent>,
    backups: BTreeMap<BackupReferenceId, BackupReference>,
    staged_content: BTreeMap<StagedContentId, StagedContentOwnership>,
}
#[async_trait]
impl DomainRepository for MemoryRepository {
    async fn network(&self, id: NetworkId) -> Result<MCPlayNetwork, ApplicationError> {
        self.inner
            .lock()
            .map_err(|_| ApplicationError::Port("memory repository lock poisoned".into()))?
            .networks
            .get(&id)
            .cloned()
            .ok_or(ApplicationError::NotFound("network"))
    }
    async fn services(&self) -> Result<Vec<Service>, ApplicationError> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| ApplicationError::Port("memory repository lock poisoned".into()))?
            .services
            .values()
            .cloned()
            .collect())
    }
    async fn service(&self, id: ServiceId) -> Result<Service, ApplicationError> {
        self.inner
            .lock()
            .map_err(|_| ApplicationError::Port("memory repository lock poisoned".into()))?
            .services
            .get(&id)
            .cloned()
            .ok_or(ApplicationError::NotFound("service"))
    }
    async fn clusters(&self) -> Result<Vec<GameCluster>, ApplicationError> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| ApplicationError::Port("memory repository lock poisoned".into()))?
            .clusters
            .values()
            .cloned()
            .collect())
    }
    async fn cluster(&self, id: ClusterId) -> Result<GameCluster, ApplicationError> {
        self.inner
            .lock()
            .map_err(|_| ApplicationError::Port("memory repository lock poisoned".into()))?
            .clusters
            .get(&id)
            .cloned()
            .ok_or(ApplicationError::NotFound("cluster"))
    }
    async fn revisions(&self) -> Result<Vec<ClusterRevision>, ApplicationError> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| ApplicationError::Port("memory repository lock poisoned".into()))?
            .revisions
            .values()
            .map(|(_, revision)| revision.clone())
            .collect())
    }
    async fn revision_cluster(&self, id: RevisionId) -> Result<ClusterId, ApplicationError> {
        self.inner
            .lock()
            .map_err(|_| ApplicationError::Port("memory repository lock poisoned".into()))?
            .revisions
            .get(&id)
            .map(|(cluster, _)| *cluster)
            .ok_or(ApplicationError::NotFound("revision cluster"))
    }
    async fn worlds(&self) -> Result<Vec<World>, ApplicationError> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| ApplicationError::Port("memory repository lock poisoned".into()))?
            .worlds
            .values()
            .map(|(_, world)| world.clone())
            .collect())
    }
    async fn proxies(&self) -> Result<Vec<ProxyInstance>, ApplicationError> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| ApplicationError::Port("memory repository lock poisoned".into()))?
            .proxies
            .values()
            .cloned()
            .collect())
    }
    async fn artifacts(&self) -> Result<Vec<Artifact>, ApplicationError> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| ApplicationError::Port("memory repository lock poisoned".into()))?
            .artifacts
            .values()
            .cloned()
            .collect())
    }
    async fn artifact_set(&self, id: ArtifactSetId) -> Result<ArtifactSet, ApplicationError> {
        self.inner
            .lock()
            .map_err(|_| ApplicationError::Port("memory repository lock poisoned".into()))?
            .artifact_sets
            .get(&id)
            .cloned()
            .ok_or(ApplicationError::NotFound("artifact set"))
    }
    async fn endpoints(&self) -> Result<Vec<ExternalEndpoint>, ApplicationError> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| ApplicationError::Port("memory repository lock poisoned".into()))?
            .endpoints
            .values()
            .cloned()
            .collect())
    }
    async fn endpoint_binding(&self, id: BindingId) -> Result<EndpointBinding, ApplicationError> {
        self.inner
            .lock()
            .map_err(|_| ApplicationError::Port("memory repository lock poisoned".into()))?
            .endpoint_bindings
            .get(&id)
            .cloned()
            .ok_or(ApplicationError::NotFound("endpoint binding"))
    }
    async fn access_policy(&self, id: PolicyId) -> Result<AccessPolicy, ApplicationError> {
        self.inner
            .lock()
            .map_err(|_| ApplicationError::Port("memory repository lock poisoned".into()))?
            .access_policies
            .get(&id)
            .cloned()
            .ok_or(ApplicationError::NotFound("access policy"))
    }
    async fn sessions(&self) -> Result<Vec<ChangeSession>, ApplicationError> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| ApplicationError::Port("memory repository lock poisoned".into()))?
            .sessions
            .values()
            .cloned()
            .collect())
    }
    async fn operations(&self) -> Result<Vec<Operation>, ApplicationError> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| ApplicationError::Port("memory repository lock poisoned".into()))?
            .operations
            .values()
            .cloned()
            .collect())
    }
    async fn plan(&self, id: PlanId) -> Result<PlanDescriptor, ApplicationError> {
        self.inner
            .lock()
            .map_err(|_| ApplicationError::Port("memory repository lock poisoned".into()))?
            .plans
            .get(&id)
            .map(|(plan, _)| plan.clone())
            .ok_or(ApplicationError::NotFound("plan"))
    }
    async fn plan_session(&self, id: PlanId) -> Result<ChangeSessionId, ApplicationError> {
        self.inner
            .lock()
            .map_err(|_| ApplicationError::Port("memory repository lock poisoned".into()))?
            .plans
            .get(&id)
            .map(|(_, session)| *session)
            .ok_or(ApplicationError::NotFound("plan"))
    }
    async fn backups(&self) -> Result<Vec<BackupReference>, ApplicationError> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| ApplicationError::Port("memory repository lock poisoned".into()))?
            .backups
            .values()
            .cloned()
            .collect())
    }
    async fn retirement_safety(
        &self,
        service: ServiceId,
    ) -> Result<RetirementSafety, ApplicationError> {
        let state = self
            .inner
            .lock()
            .map_err(|_| ApplicationError::Port("memory repository lock poisoned".into()))?;
        let service_clusters = state
            .clusters
            .values()
            .filter(|cluster| cluster.service_id == service)
            .map(|cluster| cluster.id)
            .collect::<std::collections::BTreeSet<_>>();
        let active_routes = state.routes.iter().any(|(route_id, route)| {
            !route.disabled
                && state
                    .route_pools
                    .get(route_id)
                    .is_some_and(|_| service_clusters.contains(&route.target_cluster))
        });
        let active_world_writers = state.worlds.values().any(|(cluster_id, world)| {
            service_clusters.contains(cluster_id) && !world.current_writers.is_empty()
        });
        let active_execution_bindings = state.bindings.values().any(|(owner, cluster_id, _)| {
            *owner == service && service_clusters.contains(cluster_id)
        });
        let effective_access_grants = state
            .services
            .get(&service)
            .and_then(|record| record.access_policy)
            .and_then(|policy_id| state.access_policies.get(&policy_id))
            .map(|policy| policy.grants.clone())
            .unwrap_or_default();
        Ok(RetirementSafety {
            active_routes,
            active_world_writers,
            active_execution_bindings,
            effective_access_grants,
        })
    }
    async fn staged_content_for_actor(
        &self,
        session: ChangeSessionId,
        actor: ActorId,
        content: &StagedContentRef,
        classification: FileClassification,
        required_until: u64,
    ) -> Result<StagedContentOwnership, ApplicationError> {
        let state = self
            .inner
            .lock()
            .map_err(|_| ApplicationError::Port("memory repository lock poisoned".into()))?;
        let ownership = state
            .staged_content
            .values()
            .find(|ownership| {
                ownership.session_id == session
                    && ownership.actor == actor
                    && ownership.content == *content
                    && ownership.classification == classification
            })
            .cloned()
            .ok_or(ApplicationError::Forbidden)?;
        if ownership.expires_at < required_until
            || !state
                .sessions
                .get(&session)
                .is_some_and(ChangeSession::is_active)
        {
            return Err(ApplicationError::Conflict("staged content expired"));
        }
        Ok(ownership)
    }
    async fn gameap_binding(
        &self,
        id: BindingId,
        service: ServiceId,
        cluster: ClusterId,
    ) -> Result<GameAPBinding, ApplicationError> {
        let state = self
            .inner
            .lock()
            .map_err(|_| ApplicationError::Port("memory repository lock poisoned".into()))?;
        let (owner, target_cluster, binding) = state
            .bindings
            .get(&id)
            .ok_or(ApplicationError::NotFound("gameap binding"))?;
        if *owner != service || *target_cluster != cluster {
            return Err(ApplicationError::NotFound("gameap binding"));
        }
        Ok(binding.clone())
    }
    async fn cluster_for_plan_target(
        &self,
        target: PlanTarget,
        service: ServiceId,
    ) -> Result<ClusterId, ApplicationError> {
        let state = self
            .inner
            .lock()
            .map_err(|_| ApplicationError::Port("memory repository lock poisoned".into()))?;
        let mut clusters = std::collections::BTreeSet::new();
        match target {
            PlanTarget::Service(id) => {
                if let Some(value) = state.services.get(&id).and_then(|s| s.current_cluster) {
                    clusters.insert(value);
                }
            }
            PlanTarget::Cluster(id) => {
                if state.clusters.contains_key(&id) {
                    clusters.insert(id);
                }
            }
            PlanTarget::World(id) => {
                if let Some((cluster, _)) = state.worlds.get(&id) {
                    clusters.insert(*cluster);
                }
            }
            PlanTarget::ProxyPool(id) => {
                if state.proxy_pools.contains_key(&id) {
                    for (route_id, route) in &state.routes {
                        if state.route_pools.get(route_id) == Some(&id) {
                            clusters.insert(route.target_cluster);
                        }
                    }
                }
            }
            PlanTarget::ProxyInstance(id) => {
                if let Some(proxy) = state.proxies.get(&id) {
                    for (route_id, route) in &state.routes {
                        if state.route_pools.get(route_id) == Some(&proxy.pool_id) {
                            clusters.insert(route.target_cluster);
                        }
                    }
                }
            }
            PlanTarget::Artifact(id) => {
                for set in state
                    .artifact_sets
                    .values()
                    .filter(|set| set.artifacts.contains(&id))
                {
                    for (cluster, revision) in state.revisions.values() {
                        if revision.artifact_set == set.id {
                            clusters.insert(*cluster);
                        }
                    }
                }
            }
            PlanTarget::ArtifactSet(id) => {
                for (cluster, revision) in state.revisions.values() {
                    if revision.artifact_set == id {
                        clusters.insert(*cluster);
                    }
                }
            }
            PlanTarget::Endpoint(id) => {
                for binding in state
                    .endpoint_bindings
                    .values()
                    .filter(|binding| binding.endpoint_id == id)
                {
                    clusters.insert(binding.cluster_id);
                }
            }
            PlanTarget::EndpointBinding(id) => {
                if let Some(binding) = state.endpoint_bindings.get(&id) {
                    clusters.insert(binding.cluster_id);
                }
            }
            PlanTarget::AccessPolicy(id) => {
                if let Some(service_record) = state
                    .services
                    .values()
                    .find(|record| record.access_policy == Some(id))
                    && let Some(cluster) = service_record.current_cluster
                {
                    clusters.insert(cluster);
                }
                if let Some(values) = state.policy_clusters.get(&id) {
                    clusters.extend(values.iter().copied());
                }
            }
            PlanTarget::Backup(id) => {
                if let Some(backup) = state.backups.get(&id) {
                    match backup.target {
                        BackupTarget::Service(value) => {
                            if let Some(cluster) =
                                state.services.get(&value).and_then(|s| s.current_cluster)
                            {
                                clusters.insert(cluster);
                            }
                        }
                        BackupTarget::Cluster(value) => {
                            clusters.insert(value);
                        }
                        BackupTarget::World(value) => {
                            if let Some((cluster, _)) = state.worlds.get(&value) {
                                clusters.insert(*cluster);
                            }
                        }
                        BackupTarget::ExecutionUnit(value) => {
                            if let Some((_, cluster, _)) = state.bindings.get(&value) {
                                clusters.insert(*cluster);
                            }
                        }
                    }
                }
            }
            PlanTarget::ExecutionUnit(id) => {
                if let Some((_, cluster, _)) = state.bindings.get(&id) {
                    clusters.insert(*cluster);
                }
            }
        }
        clusters.retain(|cluster| {
            state
                .clusters
                .get(cluster)
                .is_some_and(|value| value.service_id == service)
        });
        match clusters.len() {
            1 => Ok(*clusters.iter().next().expect("one cluster")),
            0 => Err(ApplicationError::NotFound("plan target cluster")),
            _ => Err(ApplicationError::Conflict("plan target cluster")),
        }
    }
    async fn change_session_for_actor(
        &self,
        id: ChangeSessionId,
        actor: ActorId,
    ) -> Result<ChangeSession, ApplicationError> {
        let state = self
            .inner
            .lock()
            .map_err(|_| ApplicationError::Port("memory repository lock poisoned".into()))?;
        if state.session_actors.get(&id) != Some(&actor) {
            return Err(ApplicationError::NotFound("change session"));
        }
        state
            .sessions
            .get(&id)
            .cloned()
            .ok_or(ApplicationError::NotFound("change session"))
    }
    async fn transaction(&self) -> Result<Box<dyn UnitOfWork>, ApplicationError> {
        Ok(Box::new(MemoryTx {
            repo: self.clone(),
            sessions: vec![],
            session_actors: vec![],
            begin_requests: vec![],
            begin_audits: vec![],
            operations: vec![],
            plans: vec![],
            plan_requests: vec![],
            audits: vec![],
        }))
    }
}
impl MemoryRepository {
    pub fn insert_network(&self, network: MCPlayNetwork) -> Result<(), ApplicationError> {
        self.inner
            .lock()
            .map_err(|_| ApplicationError::Port("memory repository lock poisoned".into()))?
            .networks
            .insert(network.id, network);
        Ok(())
    }

    pub fn insert_service(&self, service: Service) -> Result<(), ApplicationError> {
        self.inner
            .lock()
            .map_err(|_| ApplicationError::Port("memory repository lock poisoned".into()))?
            .services
            .insert(service.id, service);
        Ok(())
    }

    pub fn insert_cluster(&self, cluster: GameCluster) -> Result<(), ApplicationError> {
        self.inner
            .lock()
            .map_err(|_| ApplicationError::Port("memory repository lock poisoned".into()))?
            .clusters
            .insert(cluster.id, cluster);
        Ok(())
    }

    pub fn insert_revision(
        &self,
        cluster: ClusterId,
        revision: ClusterRevision,
    ) -> Result<(), ApplicationError> {
        self.inner
            .lock()
            .map_err(|_| ApplicationError::Port("memory repository lock poisoned".into()))?
            .revisions
            .insert(revision.id, (cluster, revision));
        Ok(())
    }

    pub fn insert_world(&self, cluster: ClusterId, world: World) -> Result<(), ApplicationError> {
        self.inner
            .lock()
            .map_err(|_| ApplicationError::Port("memory repository lock poisoned".into()))?
            .worlds
            .insert(world.id, (cluster, world));
        Ok(())
    }

    pub fn insert_proxy_pool(&self, pool: ProxyPool) -> Result<(), ApplicationError> {
        self.inner
            .lock()
            .map_err(|_| ApplicationError::Port("memory repository lock poisoned".into()))?
            .proxy_pools
            .insert(pool.id, pool);
        Ok(())
    }

    pub fn insert_proxy_instance(&self, proxy: ProxyInstance) -> Result<(), ApplicationError> {
        self.inner
            .lock()
            .map_err(|_| ApplicationError::Port("memory repository lock poisoned".into()))?
            .proxies
            .insert(proxy.id, proxy);
        Ok(())
    }

    pub fn insert_route(&self, pool: ProxyPoolId, route: Route) -> Result<(), ApplicationError> {
        let mut state = self
            .inner
            .lock()
            .map_err(|_| ApplicationError::Port("memory repository lock poisoned".into()))?;
        state.route_pools.insert(route.id, pool);
        state.routes.insert(route.id, route);
        Ok(())
    }

    pub fn insert_artifact(&self, artifact: Artifact) -> Result<(), ApplicationError> {
        self.inner
            .lock()
            .map_err(|_| ApplicationError::Port("memory repository lock poisoned".into()))?
            .artifacts
            .insert(artifact.id, artifact);
        Ok(())
    }

    pub fn insert_artifact_set(&self, set: ArtifactSet) -> Result<(), ApplicationError> {
        self.inner
            .lock()
            .map_err(|_| ApplicationError::Port("memory repository lock poisoned".into()))?
            .artifact_sets
            .insert(set.id, set);
        Ok(())
    }

    pub fn insert_endpoint(&self, endpoint: ExternalEndpoint) -> Result<(), ApplicationError> {
        self.inner
            .lock()
            .map_err(|_| ApplicationError::Port("memory repository lock poisoned".into()))?
            .endpoints
            .insert(endpoint.id, endpoint);
        Ok(())
    }

    pub fn insert_endpoint_binding(
        &self,
        binding: EndpointBinding,
    ) -> Result<(), ApplicationError> {
        self.inner
            .lock()
            .map_err(|_| ApplicationError::Port("memory repository lock poisoned".into()))?
            .endpoint_bindings
            .insert(binding.id, binding);
        Ok(())
    }

    pub fn insert_access_policy(
        &self,
        policy: AccessPolicy,
        clusters: Vec<ClusterId>,
    ) -> Result<(), ApplicationError> {
        let mut state = self
            .inner
            .lock()
            .map_err(|_| ApplicationError::Port("memory repository lock poisoned".into()))?;
        state.access_policies.insert(policy.id, policy.clone());
        state.policy_clusters.insert(policy.id, clusters);
        Ok(())
    }

    pub fn insert_backup(&self, backup: BackupReference) -> Result<(), ApplicationError> {
        backup
            .validate()
            .map_err(|_| ApplicationError::Conflict("invalid backup reference"))?;
        self.inner
            .lock()
            .map_err(|_| ApplicationError::Port("memory repository lock poisoned".into()))?
            .backups
            .insert(backup.id, backup);
        Ok(())
    }

    pub fn insert_staged_content_ownership(
        &self,
        ownership: StagedContentOwnership,
    ) -> Result<(), ApplicationError> {
        ownership
            .validate()
            .map_err(|_| ApplicationError::Conflict("invalid staged content ownership"))?;
        let mut state = self
            .inner
            .lock()
            .map_err(|_| ApplicationError::Port("memory repository lock poisoned".into()))?;
        if state.session_actors.get(&ownership.session_id) != Some(&ownership.actor)
            || !state
                .sessions
                .get(&ownership.session_id)
                .is_some_and(ChangeSession::is_active)
        {
            return Err(ApplicationError::Forbidden);
        }
        if let Some(existing) = state.staged_content.get_mut(&ownership.id) {
            if existing.session_id != ownership.session_id
                || existing.actor != ownership.actor
                || existing.content != ownership.content
                || existing.classification != ownership.classification
            {
                return Err(ApplicationError::Conflict("staged content id collision"));
            }
            existing.expires_at = existing.expires_at.max(ownership.expires_at);
            return Ok(());
        }
        if let Some(existing) = state.staged_content.values_mut().find(|existing| {
            existing.session_id == ownership.session_id
                && existing.actor == ownership.actor
                && existing.content == ownership.content
                && existing.classification == ownership.classification
        }) {
            existing.expires_at = existing.expires_at.max(ownership.expires_at);
            return Ok(());
        }
        state.staged_content.insert(ownership.id, ownership);
        Ok(())
    }

    pub fn insert_gameap_binding(
        &self,
        id: BindingId,
        service: ServiceId,
        cluster: ClusterId,
        binding: GameAPBinding,
    ) -> Result<(), ApplicationError> {
        self.inner
            .lock()
            .map_err(|_| ApplicationError::Port("memory repository lock poisoned".into()))?
            .bindings
            .insert(id, (service, cluster, binding));
        Ok(())
    }
}
struct MemoryTx {
    repo: MemoryRepository,
    sessions: Vec<ChangeSession>,
    session_actors: Vec<(ChangeSessionId, ActorId)>,
    begin_requests: Vec<((ActorId, String), (String, ChangeSessionId))>,
    begin_audits: Vec<AuditEvent>,
    operations: Vec<Operation>,
    plans: Vec<(PlanDescriptor, ChangeSessionId)>,
    plan_requests: Vec<((ChangeSessionId, String), (String, PlanId))>,
    audits: Vec<AuditEvent>,
}
#[async_trait]
impl UnitOfWork for MemoryTx {
    async fn save_session_for_actor(
        &mut self,
        s: ChangeSession,
        actor: ActorId,
    ) -> Result<(), ApplicationError> {
        self.session_actors.push((s.id, actor));
        self.sessions.push(s);
        Ok(())
    }
    async fn save_session_idempotent_for_actor(
        &mut self,
        session: ChangeSession,
        actor: ActorId,
        idempotency_key: &str,
        request_hash: &str,
        audit: AuditEvent,
    ) -> Result<Option<ChangeSession>, ApplicationError> {
        if idempotency_key.trim().is_empty() || request_hash.trim().is_empty() {
            return Err(ApplicationError::Conflict("change begin identity"));
        }
        let identity = (actor, idempotency_key.to_owned());
        let state = self
            .repo
            .inner
            .lock()
            .map_err(|_| ApplicationError::Port("memory repository lock poisoned".into()))?;
        let service = state
            .clusters
            .get(&session.target_cluster)
            .ok_or(ApplicationError::NotFound("change session cluster"))?
            .service_id;
        validate_begin_audit(
            &audit,
            actor,
            service,
            session.target_cluster,
            idempotency_key,
        )?;
        let existing_request = state.begin_requests.get(&identity).cloned().or_else(|| {
            self.begin_requests
                .iter()
                .find(|(pending_identity, _)| pending_identity == &identity)
                .map(|(_, value)| value.clone())
        });
        if let Some((existing_hash, session_id)) = existing_request {
            if existing_hash != request_hash {
                return Err(ApplicationError::Replay);
            }
            let audit_count = state
                .audits
                .iter()
                .chain(self.begin_audits.iter())
                .filter(|event| {
                    event.actor == actor
                        && event.action == "change.begin"
                        && event.target == session.target_cluster.as_uuid().to_string()
                        && event.scope == audit.scope
                        && event.classification == audit.classification
                        && event.source == audit.source
                        && event.result == audit.result
                        && event.before_revision == audit.before_revision
                        && event.after_revision == audit.after_revision
                        && event.request_id.as_deref() == Some(idempotency_key)
                        && event.plan_hash.is_none()
                        && event.evidence == audit.evidence
                })
                .count();
            if audit_count != 1 {
                return Err(ApplicationError::Conflict("change begin audit event"));
            }
            let existing = state
                .sessions
                .get(&session_id)
                .cloned()
                .or_else(|| {
                    self.sessions
                        .iter()
                        .find(|value| value.id == session_id)
                        .cloned()
                })
                .ok_or(ApplicationError::NotFound("change session"))?;
            return Ok(Some(existing));
        }
        drop(state);
        self.begin_requests
            .push((identity, (request_hash.to_owned(), session.id)));
        self.begin_audits.push(audit);
        self.session_actors.push((session.id, actor));
        self.sessions.push(session);
        Ok(None)
    }
    async fn save_plan_idempotent(
        &mut self,
        plan: PlanDescriptor,
        session: ChangeSessionId,
        idempotency_key: &str,
        request_hash: &str,
        audit: AuditEvent,
    ) -> Result<Option<PlanDescriptor>, ApplicationError> {
        if idempotency_key.trim().is_empty() || request_hash.trim().is_empty() {
            return Err(ApplicationError::Conflict("plan request identity"));
        }
        plan.validate()
            .map_err(|_| ApplicationError::Conflict("invalid plan"))?;
        let state = self
            .repo
            .inner
            .lock()
            .map_err(|_| ApplicationError::Port("memory repository lock poisoned".into()))?;
        let session_actor = state
            .session_actors
            .get(&session)
            .ok_or(ApplicationError::NotFound("change session"))?;
        if *session_actor != plan.actor {
            return Err(ApplicationError::Forbidden);
        }
        let session_record = state
            .sessions
            .get(&session)
            .ok_or(ApplicationError::NotFound("change session"))?;
        if let PlanTarget::Cluster(cluster) = plan.target
            && cluster != session_record.target_cluster
        {
            return Err(ApplicationError::Conflict("plan target cluster"));
        }
        let request_key = (session, idempotency_key.to_owned());
        if let Some((existing_hash, existing_id)) = state.plan_requests.get(&request_key) {
            if existing_hash != request_hash {
                return Err(ApplicationError::Replay);
            }
            let existing = state
                .plans
                .get(existing_id)
                .map(|(existing, _)| existing.clone())
                .ok_or(ApplicationError::NotFound("plan"))?;
            return Ok(Some(existing));
        }
        if state.plans.contains_key(&plan.id)
            || state.plans.values().any(|(existing, existing_session)| {
                *existing_session == session && existing.plan_hash == plan.plan_hash
            })
        {
            return Err(ApplicationError::Conflict("plan already exists"));
        }
        drop(state);
        let plan_id = plan.id;
        self.plans.push((plan, session));
        self.plan_requests
            .push((request_key, (request_hash.to_owned(), plan_id)));
        self.audits.push(audit);
        Ok(None)
    }
    async fn commit(self: Box<Self>) -> Result<(), ApplicationError> {
        let mut s = self
            .repo
            .inner
            .lock()
            .map_err(|_| ApplicationError::Port("memory repository lock poisoned".into()))?;
        for v in self.sessions {
            let Some(current) = s.sessions.get(&v.id) else {
                if v.state == ChangeSessionState::Editing {
                    s.sessions.insert(v.id, v);
                    continue;
                }
                return Err(ApplicationError::NotFound("change session"));
            };
            let valid = matches!(
                (&current.state, &v.state),
                (ChangeSessionState::Open, ChangeSessionState::Editing)
                    | (ChangeSessionState::Editing, ChangeSessionState::Ready)
                    | (ChangeSessionState::Ready, ChangeSessionState::Applying)
                    | (ChangeSessionState::Applying, ChangeSessionState::Verifying)
                    | (ChangeSessionState::Verifying, ChangeSessionState::Accepted)
                    | (ChangeSessionState::Applying, ChangeSessionState::RolledBack)
                    | (
                        ChangeSessionState::Verifying,
                        ChangeSessionState::RolledBack
                    )
                    | (ChangeSessionState::Open, ChangeSessionState::Aborted)
                    | (ChangeSessionState::Editing, ChangeSessionState::Conflicted)
            );
            if !valid {
                return Err(ApplicationError::Conflict("change session transition"));
            }
            s.sessions.insert(v.id, v);
        }
        for (session_id, actor) in self.session_actors {
            s.session_actors.insert(session_id, actor);
        }
        for (identity, value) in self.begin_requests {
            s.begin_requests.insert(identity, value);
        }
        s.audits.extend(self.begin_audits);
        for v in self.operations {
            s.operations.insert(v.id, v);
        }
        for (plan, session) in self.plans {
            s.plans.insert(plan.id, (plan, session));
        }
        for (request_key, value) in self.plan_requests {
            s.plan_requests.insert(request_key, value);
        }
        s.audits.extend(self.audits);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    struct Allow;
    #[async_trait]
    impl Authorizer for Allow {
        async fn authorize(&self, _: &Authorization) -> Result<(), ApplicationError> {
            Ok(())
        }
    }

    #[test]
    fn service_consistent_request_requires_world_and_database_components() {
        let service = BackupTarget::Service(ServiceId::new());
        let mut request = BackupRequest {
            session_id: ChangeSessionId::new(),
            kind: BackupKind::ServiceConsistent,
            target: service,
            idempotency_key: "service-backup".into(),
            request_hash: "a".repeat(64),
            components: vec![],
        };
        assert!(matches!(
            request.validate(),
            Err(ApplicationError::Conflict(
                "service-consistent backup components"
            ))
        ));
        request.components.push(BackupComponent {
            reference_id: BackupReferenceId::new(),
            kind: BackupKind::World,
            target: BackupTarget::World(WorldId::new()),
            provider_reference: "world".into(),
            manifest_digest: "b".repeat(64),
        });
        assert!(matches!(
            request.validate(),
            Err(ApplicationError::Conflict(
                "incomplete service backup components"
            ))
        ));
        request.components.push(BackupComponent {
            reference_id: BackupReferenceId::new(),
            kind: BackupKind::ExternalDatabaseReference,
            target: service,
            provider_reference: "database".into(),
            manifest_digest: "c".repeat(64),
        });
        assert!(request.validate().is_ok());
    }

    #[tokio::test]
    async fn service_consistent_plan_requires_ordered_maintenance_window() {
        let repository = MemoryRepository::default();
        let service = ServiceId::new();
        let cluster = ClusterId::new();
        let binding_id = BindingId::new();
        let world = WorldId::new();
        let route = RouteId::new();
        let other_cluster = ClusterId::new();
        let mut service_record = Service::new(
            "service",
            "Service",
            Ownership::FirstParty,
            Audience::Public,
            OperatorModel::Central,
            TrustProfile::Trusted,
        )
        .unwrap();
        service_record.id = service;
        service_record.lifecycle = ServiceLifecycle::Active;
        service_record.current_cluster = Some(cluster);
        repository.insert_service(service_record).unwrap();
        repository
            .insert_cluster(GameCluster {
                id: cluster,
                service_id: service,
                key: "cluster".into(),
                current_revision: None,
            })
            .unwrap();
        repository
            .insert_gameap_binding(
                binding_id,
                service,
                cluster,
                GameAPBinding {
                    execution_unit_id: "runtime".into(),
                    node_id: "node".into(),
                    target: GameAPBindingTarget::ExecutionUnit("runtime".into()),
                },
            )
            .unwrap();
        let hash = "a".repeat(64);
        let steps = vec![
            PlanStep::new(PlanStepAction::ServiceLifecycleTransition {
                service_id: service,
                expected_state: ServiceLifecycle::Active,
                next_state: ServiceLifecycle::Maintenance,
                expected_version: 1,
                reason: "service-consistent backup".into(),
            })
            .unwrap(),
            PlanStep::new(PlanStepAction::RoutePolicyUpdate {
                route_id: route,
                pool_id: ProxyPoolId::new(),
                service_id: service,
                expected_cluster: cluster,
                target_cluster: other_cluster,
                expected_priority: 1,
                target_priority: 1,
                expected_version: 1,
                disabled: true,
            })
            .unwrap(),
            PlanStep::new(PlanStepAction::ExecutionLifecycle {
                binding_id,
                action: ExecutionLifecycleAction::Stop,
                expected_binding_hash: hash.clone(),
                expected_state_hash: hash.clone(),
                domain_revision: 1,
            })
            .unwrap(),
            PlanStep::new(PlanStepAction::BackupCreate {
                kind: BackupKind::World,
                target: BackupTarget::World(world),
                request_hash: hash.clone(),
            })
            .unwrap(),
            PlanStep::new(PlanStepAction::BackupCreate {
                kind: BackupKind::ExternalDatabaseReference,
                target: BackupTarget::Service(service),
                request_hash: hash.clone(),
            })
            .unwrap(),
            PlanStep::new(PlanStepAction::BackupCreate {
                kind: BackupKind::ServiceConsistent,
                target: BackupTarget::Service(service),
                request_hash: hash.clone(),
            })
            .unwrap(),
            PlanStep::new(PlanStepAction::ExecutionLifecycle {
                binding_id,
                action: ExecutionLifecycleAction::Start,
                expected_binding_hash: hash.clone(),
                expected_state_hash: hash.clone(),
                domain_revision: 1,
            })
            .unwrap(),
            PlanStep::new(PlanStepAction::RoutePolicyUpdate {
                route_id: route,
                pool_id: ProxyPoolId::new(),
                service_id: service,
                expected_cluster: other_cluster,
                target_cluster: cluster,
                expected_priority: 1,
                target_priority: 1,
                expected_version: 2,
                disabled: false,
            })
            .unwrap(),
            PlanStep::new(PlanStepAction::ServiceLifecycleTransition {
                service_id: service,
                expected_state: ServiceLifecycle::Maintenance,
                next_state: ServiceLifecycle::Active,
                expected_version: 2,
                reason: "backup window complete".into(),
            })
            .unwrap(),
        ];
        let plan = PlanDescriptor::new(ActorId::new(), PlanTarget::Cluster(cluster), 1, 100, steps)
            .unwrap();
        validate_service_consistent_sequence(&repository, &plan, service, cluster)
            .await
            .unwrap();
        let mut invalid = plan.clone();
        invalid.steps.swap(3, 4);
        assert!(matches!(
            validate_service_consistent_sequence(&repository, &invalid, service, cluster).await,
            Err(ApplicationError::Conflict(
                "service-consistent backup components are out of order"
            ))
        ));
    }
    struct Audit;
    #[async_trait]
    impl AuditSink for Audit {
        async fn record(&self, _: AuditEvent) -> Result<(), ApplicationError> {
            Ok(())
        }
    }

    struct Healthy;
    #[async_trait]
    impl HealthVerifier for Healthy {
        async fn verify(&self, _: &str) -> Result<(), ApplicationError> {
            Ok(())
        }
    }

    struct TestBackup;
    #[async_trait]
    impl BackupProvider for TestBackup {
        async fn create(
            &self,
            request: &BackupRequest,
        ) -> Result<BackupReference, ApplicationError> {
            Ok(BackupReference {
                id: BackupReferenceId::new(),
                session_id: request.session_id,
                kind: request.kind,
                target: request.target,
                provider: "test-provider".into(),
                provider_reference: "provider-reference".into(),
                manifest_digest: "a".repeat(64),
                verified_at: None,
                required: true,
            })
        }

        async fn verify(
            &self,
            reference: &BackupReference,
        ) -> Result<BackupObservation, ApplicationError> {
            BackupObservation::new(&reference.manifest_digest, 1)
                .map_err(|error| ApplicationError::Port(error.to_string()))
        }

        async fn restore(
            &self,
            request: &BackupRestoreRequest,
        ) -> Result<BackupRestoreInvocation, ApplicationError> {
            Ok(BackupRestoreInvocation {
                plan_id: request.plan_id,
                reference_id: request.reference.id,
                target: request.target,
                expected_manifest_digest: request.reference.manifest_digest.clone(),
                rollback_reference_id: request.rollback_reference.id,
                expected_rollback_manifest_digest: request
                    .rollback_reference
                    .manifest_digest
                    .clone(),
                provider_invocation: "invocation".into(),
            })
        }

        async fn verify_restore(
            &self,
            _invocation: &BackupRestoreInvocation,
        ) -> Result<BackupObservation, ApplicationError> {
            BackupObservation::new(&"a".repeat(64), 1)
                .map_err(|error| ApplicationError::Port(error.to_string()))
        }
    }

    type WorldCasCall = (WorldId, u64, Option<ClusterId>, ClusterId);

    #[derive(Clone, Default)]
    struct RecordingWorldStorage {
        calls: Arc<Mutex<Vec<WorldCasCall>>>,
    }
    #[async_trait]
    impl WorldStorage for RecordingWorldStorage {
        async fn compare_and_swap_writer(
            &self,
            world: WorldId,
            expected_version: u64,
            expected: Option<ClusterId>,
            next: ClusterId,
        ) -> Result<(), ApplicationError> {
            self.calls
                .lock()
                .map_err(|_| ApplicationError::Port("test lock poisoned".into()))?
                .push((world, expected_version, expected, next));
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    struct RecordingWorldRuntime {
        calls: Arc<Mutex<Vec<(String, ClusterId)>>>,
        fail_start: Option<ClusterId>,
    }
    #[async_trait]
    impl WorldRuntime for RecordingWorldRuntime {
        async fn stop_and_flush(
            &self,
            cluster: ClusterId,
            _: WorldId,
        ) -> Result<(), ApplicationError> {
            self.calls
                .lock()
                .map_err(|_| ApplicationError::Port("test lock poisoned".into()))?
                .push(("stop".into(), cluster));
            Ok(())
        }

        async fn start(&self, cluster: ClusterId, _: WorldId) -> Result<(), ApplicationError> {
            self.calls
                .lock()
                .map_err(|_| ApplicationError::Port("test lock poisoned".into()))?
                .push(("start".into(), cluster));
            if self.fail_start == Some(cluster) {
                return Err(ApplicationError::Port("runtime start failed".into()));
            }
            Ok(())
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum EndpointStoreCall {
        Activate(BindingId, BindingId),
        Rollback(ClusterId, BindingId, BindingId),
    }
    #[derive(Clone, Default)]
    struct RecordingEndpointStore {
        calls: Arc<Mutex<Vec<EndpointStoreCall>>>,
    }
    #[async_trait]
    impl EndpointBindingStore for RecordingEndpointStore {
        async fn activate_revision(
            &self,
            expected: &EndpointBinding,
            target: &EndpointBinding,
            _: u64,
        ) -> Result<(), ApplicationError> {
            self.calls
                .lock()
                .map_err(|_| ApplicationError::Port("test lock poisoned".into()))?
                .push(EndpointStoreCall::Activate(expected.id, target.id));
            Ok(())
        }

        async fn rollback_revision(
            &self,
            cluster: ClusterId,
            expected_binding: BindingId,
            target_binding: BindingId,
            _: u64,
        ) -> Result<(), ApplicationError> {
            self.calls
                .lock()
                .map_err(|_| ApplicationError::Port("test lock poisoned".into()))?
                .push(EndpointStoreCall::Rollback(
                    cluster,
                    expected_binding,
                    target_binding,
                ));
            Ok(())
        }
    }

    struct EndpointDns;
    #[async_trait]
    impl DnsResolver for EndpointDns {
        async fn resolve(&self, _: &str, _: u16) -> Result<Vec<String>, ApplicationError> {
            Ok(vec!["127.0.0.1".into()])
        }
    }

    struct TestEndpointRuntime {
        fail: bool,
    }
    #[async_trait]
    impl EndpointRuntime for TestEndpointRuntime {
        async fn restart_and_reconnect(&self, _: &EndpointBinding) -> Result<(), ApplicationError> {
            if self.fail {
                Err(ApplicationError::Port("endpoint restart failed".into()))
            } else {
                Ok(())
            }
        }
    }

    #[derive(Clone)]
    struct RecordingEdge {
        calls: Arc<Mutex<Vec<String>>>,
    }
    #[async_trait]
    impl ProxyEdge for RecordingEdge {
        async fn prepare(&self, binding: &ProxyEdgeBinding) -> Result<(), ApplicationError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("prepare:{}", binding.backend_set_id));
            Ok(())
        }

        async fn configure(&self, binding: &ProxyEdgeBinding) -> Result<(), ApplicationError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("configure:{}", binding.backend_set_id));
            Ok(())
        }

        async fn add(&self, binding: &ProxyEdgeBinding) -> Result<(), ApplicationError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("add:{}", binding.backend_set_id));
            Ok(())
        }

        async fn remove(&self, binding: &ProxyEdgeBinding) -> Result<(), ApplicationError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("remove:{}", binding.backend_set_id));
            Ok(())
        }

        async fn drain(&self, binding: &ProxyEdgeBinding) -> Result<(), ApplicationError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("drain:{}", binding.backend_set_id));
            Ok(())
        }

        async fn real_connect(
            &self,
            binding: &ProxyEdgeBinding,
        ) -> Result<ConnectionEvidence, ApplicationError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("real-connect:{}", binding.backend_set_id));
            Ok(ConnectionEvidence {
                active: 1,
                observed: true,
                hash: "connect-evidence".into(),
            })
        }

        async fn stop(&self, binding: &ProxyEdgeBinding) -> Result<(), ApplicationError> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("stop:{}", binding.backend_set_id));
            Ok(())
        }
    }

    struct ProxyResolver;
    #[async_trait]
    impl ProxyEdgeResolver for ProxyResolver {
        async fn resolve(
            &self,
            binding: &ProxyEdgeBinding,
        ) -> Result<ProxyEdgeObservation, ApplicationError> {
            Ok(ProxyEdgeObservation {
                instance_id: binding.instance_id,
                provider_network_id: binding.provider_network_id,
                domain_network_id: binding.domain_network_id,
                backend_set_id: binding.backend_set_id.clone(),
                backend_address: binding.backend_address.clone(),
                revision: binding.revision,
                evidence_hash: binding.observed_hash.clone(),
            })
        }
    }

    struct ProxyObserver {
        active: u64,
        observed: bool,
    }
    #[async_trait]
    impl ConnectionObserver for ProxyObserver {
        async fn observe(&self, _: &str) -> Result<ConnectionEvidence, ApplicationError> {
            Ok(ConnectionEvidence {
                active: self.active,
                observed: self.observed,
                hash: "drain-evidence".into(),
            })
        }
    }

    fn proxy_edge_binding(set: &str, address: &str) -> ProxyEdgeBinding {
        ProxyEdgeBinding {
            instance_id: ProxyInstanceId::new(),
            provider_network_id: 1,
            domain_network_id: Some(NetworkId::new()),
            backend_set_id: set.into(),
            backend_address: address.into(),
            revision: RevisionId::new(),
            observed_hash: format!("hash-{set}"),
        }
    }

    fn request(actor: ActorId, service: ServiceId, cluster: ClusterId) -> ChangeRequest {
        ChangeRequest {
            actor,
            service,
            cluster,
            domain_revision: 1,
            idempotency_key: "once".into(),
            steps: vec![
                PlanStep::new(PlanStepAction::ExecutionLifecycle {
                    action: ExecutionLifecycleAction::Restart,
                    binding_id: BindingId::new(),
                    expected_binding_hash: "a".repeat(64),
                    expected_state_hash: "b".repeat(64),
                    domain_revision: 1,
                })
                .expect("valid test plan step"),
            ],
            observed_state_hashes: vec!["c".repeat(64)],
            expiry: 100,
        }
    }

    fn set_binding_id(step: &mut PlanStep, binding_id: BindingId) {
        let mut action = step.action.clone();
        match &mut action {
            PlanStepAction::ExecutionLifecycle {
                binding_id: current,
                ..
            }
            | PlanStepAction::FileWrite {
                binding_id: current,
                ..
            }
            | PlanStepAction::FileMove {
                binding_id: current,
                ..
            }
            | PlanStepAction::FileQuarantine {
                binding_id: current,
                ..
            }
            | PlanStepAction::FileBatch {
                binding_id: current,
                ..
            }
            | PlanStepAction::ProxyRollout {
                target_binding_id: current,
                ..
            } => *current = binding_id,
            _ => panic!("test step does not contain a binding"),
        }
        step.action = action;
    }

    fn set_binding_hash(step: &mut PlanStep, expected_binding_hash: String) {
        let mut action = step.action.clone();
        match &mut action {
            PlanStepAction::ExecutionLifecycle {
                expected_binding_hash: current,
                ..
            }
            | PlanStepAction::FileWrite {
                expected_binding_hash: current,
                ..
            }
            | PlanStepAction::FileMove {
                expected_binding_hash: current,
                ..
            }
            | PlanStepAction::FileQuarantine {
                expected_binding_hash: current,
                ..
            }
            | PlanStepAction::FileBatch {
                expected_binding_hash: current,
                ..
            }
            | PlanStepAction::ProxyRollout {
                target_binding_hash: current,
                ..
            } => *current = expected_binding_hash,
            _ => panic!("test step does not contain a binding"),
        }
        step.action = action;
    }

    #[test]
    fn config_baseline_snapshot_diff_uses_manifest_digests_without_contents() {
        let baseline = ConfigBaseline::new(vec![
            ConfigBaselineEntry::new(
                "server.properties",
                &digest_bytes(b"server"),
                FileClassification::Managed,
            )
            .unwrap(),
            ConfigBaselineEntry::new(
                "secrets/token",
                &digest_bytes(b"token"),
                FileClassification::Secret,
            )
            .unwrap(),
        ])
        .unwrap();
        let base = snapshot_from_config_baseline(&baseline).unwrap();
        let live = snapshot_files(vec![
            FileEntry {
                path: "server.properties".into(),
                classification: FileClassification::Managed,
                digest: digest_bytes(b"server"),
                size: 6,
            },
            FileEntry {
                path: "secrets/token".into(),
                classification: FileClassification::Secret,
                digest: digest_bytes(b"changed-token"),
                size: 13,
            },
            FileEntry {
                path: "new.properties".into(),
                classification: FileClassification::Managed,
                digest: digest_bytes(b"new"),
                size: 3,
            },
        ]);
        let diff = diff_files(&base, &live);
        assert!(
            diff.iter().any(|item| {
                item.path == "server.properties" && item.kind == DiffKind::Unchanged
            })
        );
        assert!(
            diff.iter()
                .any(|item| { item.path == "secrets/token" && item.kind == DiffKind::Changed })
        );
        assert!(
            diff.iter()
                .any(|item| { item.path == "new.properties" && item.kind == DiffKind::Added })
        );
        let manifest = serde_json::to_string(&baseline).unwrap();
        assert!(!manifest.contains("server-content"));
        assert!(!manifest.contains("token-content"));
    }

    #[tokio::test]
    async fn world_cutover_passes_version_and_writer_cas_and_rolls_back() {
        let service = ServiceId::new();
        let from = ClusterId::new();
        let to = ClusterId::new();
        let actor = ActorId::new();
        let mut world = World::new(
            "world-cas",
            "World CAS",
            WorldWriteMode::SingleWriter,
            WorldExecutionModel::SingleProcess,
        )
        .unwrap();
        world.assign_writer(from).unwrap();
        let storage = RecordingWorldStorage::default();
        let runtime = RecordingWorldRuntime::default();
        let backup_request = BackupRequest {
            session_id: ChangeSessionId::new(),
            kind: BackupKind::World,
            target: BackupTarget::World(world.id),
            idempotency_key: "world-cutover-once".into(),
            request_hash: "a".repeat(64),
            components: vec![],
        };
        let service_layer = WorldService {
            backup: TestBackup,
            health: Healthy,
            authorizer: Allow,
            audit: Audit,
        };
        service_layer
            .cutover_with_runtime(
                &mut world,
                from,
                to,
                7,
                &backup_request,
                &runtime,
                &storage,
                actor,
                service,
            )
            .await
            .unwrap();
        assert_eq!(
            storage.calls.lock().unwrap().as_slice(),
            &[(world.id, 7, Some(from), to)]
        );
        assert_eq!(world.current_writers, vec![to]);

        let mut failed_world = World::new(
            "world-cas-failure",
            "World CAS failure",
            WorldWriteMode::SingleWriter,
            WorldExecutionModel::SingleProcess,
        )
        .unwrap();
        failed_world.assign_writer(from).unwrap();
        let failed_storage = RecordingWorldStorage::default();
        let failed_runtime = RecordingWorldRuntime {
            calls: Arc::new(Mutex::new(Vec::new())),
            fail_start: Some(to),
        };
        let failed_backup_request = BackupRequest {
            session_id: ChangeSessionId::new(),
            kind: BackupKind::World,
            target: BackupTarget::World(failed_world.id),
            idempotency_key: "world-cutover-failure-once".into(),
            request_hash: "b".repeat(64),
            components: vec![],
        };
        assert_eq!(
            service_layer
                .cutover_with_runtime(
                    &mut failed_world,
                    from,
                    to,
                    7,
                    &failed_backup_request,
                    &failed_runtime,
                    &failed_storage,
                    actor,
                    service,
                )
                .await,
            Err(ApplicationError::Port("runtime start failed".into()))
        );
        assert_eq!(
            failed_storage.calls.lock().unwrap().as_slice(),
            &[
                (failed_world.id, 7, Some(from), to),
                (failed_world.id, 8, Some(to), from),
            ]
        );
        assert_eq!(failed_world.current_writers, vec![from]);
    }

    #[tokio::test]
    async fn endpoint_rollout_uses_revision_cas_and_rolls_back_failed_runtime() {
        let cluster = ClusterId::new();
        let service = ServiceId::new();
        let expected_revision = RevisionId::new();
        let target_revision = RevisionId::new();
        let endpoint = ExternalEndpoint {
            id: EndpointId::new(),
            key: "public".into(),
            kind: "tcp".into(),
            logical_hostname: "play.example.test".into(),
            port: 25_565,
            role: "game".into(),
            metadata: String::new(),
        };
        let expected_binding =
            EndpointBinding::new(endpoint.id, cluster, expected_revision, "public")
                .expect("valid expected endpoint binding");
        let binding = EndpointBinding::new(endpoint.id, cluster, target_revision, "public")
            .expect("valid target endpoint binding");
        let store = RecordingEndpointStore::default();
        let service_layer = EndpointService {
            dns: EndpointDns,
            health: Healthy,
            authorizer: Allow,
            audit: Audit,
        };
        assert_eq!(
            service_layer
                .rollout_with_runtime(
                    &endpoint,
                    &endpoint,
                    &expected_binding,
                    &binding,
                    1,
                    &store,
                    &TestEndpointRuntime { fail: true },
                    ActorId::new(),
                    service,
                )
                .await,
            Err(ApplicationError::Port("endpoint restart failed".into()))
        );
        assert_eq!(
            store.calls.lock().unwrap().as_slice(),
            &[
                EndpointStoreCall::Activate(expected_binding.id, binding.id),
                EndpointStoreCall::Rollback(cluster, expected_binding.id, binding.id),
            ]
        );
    }

    #[tokio::test]
    async fn proxy_rollout_requires_drain_evidence_and_rolls_back() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let proxy = ProxyService {
            edge: RecordingEdge {
                calls: calls.clone(),
            },
            health: Healthy,
            authorizer: Allow,
            audit: Audit,
        };
        let result = proxy
            .roll(
                ProxyRollout {
                    new: proxy_edge_binding("new-set", "new.example:25565"),
                    old: proxy_edge_binding("old-set", "old.example:25565"),
                },
                &ProxyResolver,
                &ProxyObserver {
                    active: 2,
                    observed: true,
                },
                ActorId::new(),
                ServiceId::new(),
            )
            .await;
        assert_eq!(
            result,
            Err(ApplicationError::Conflict("drain evidence unknown"))
        );
        {
            let calls = calls.lock().unwrap();
            assert!(calls.iter().any(|call| call == "prepare:new-set"));
            assert!(calls.iter().any(|call| call == "real-connect:new-set"));
            assert!(calls.iter().any(|call| call == "add:old-set"));
            assert!(calls.iter().any(|call| call == "remove:new-set"));
            assert!(!calls.iter().any(|call| call == "stop:old-set"));
        }

        let success_calls = Arc::new(Mutex::new(Vec::new()));
        let proxy = ProxyService {
            edge: RecordingEdge {
                calls: success_calls.clone(),
            },
            health: Healthy,
            authorizer: Allow,
            audit: Audit,
        };
        proxy
            .roll(
                ProxyRollout {
                    new: proxy_edge_binding("new-set", "new.example:25565"),
                    old: proxy_edge_binding("old-set", "old.example:25565"),
                },
                &ProxyResolver,
                &ProxyObserver {
                    active: 0,
                    observed: true,
                },
                ActorId::new(),
                ServiceId::new(),
            )
            .await
            .unwrap();
        let calls = success_calls.lock().unwrap();
        assert!(calls.iter().any(|call| call == "drain:old-set"));
        assert!(!calls.iter().any(|call| call == "remove:old-set"));
        assert!(calls.iter().any(|call| call == "stop:old-set"));
    }

    #[tokio::test]
    async fn plan_rejects_expired_and_stale_observation() {
        let repository = MemoryRepository::default();
        let actor = ActorId::new();
        let service = ServiceId::new();
        let cluster = ClusterId::new();
        repository
            .insert_cluster(GameCluster {
                id: cluster,
                service_id: service,
                key: "cluster".into(),
                current_revision: None,
            })
            .unwrap();
        let binding = GameAPBinding {
            execution_unit_id: "runtime".into(),
            node_id: "node".into(),
            target: GameAPBindingTarget::Cluster(cluster),
        };
        repository
            .insert_gameap_binding(
                BindingId::from_uuid(Uuid::nil()),
                service,
                cluster,
                binding.clone(),
            )
            .unwrap();
        let c = ChangeCoordinator {
            repository,
            authorizer: Allow,
            audit: Audit,
        };
        let mut r = request(actor, service, cluster);
        set_binding_id(&mut r.steps[0], BindingId::from_uuid(Uuid::nil()));
        set_binding_hash(&mut r.steps[0], binding.fingerprint());
        let p = c.plan(&r).await.unwrap();
        let session = c.begin(&r).await.unwrap();
        let persisted = c
            .plan_for_session(&r, session.id, session.version)
            .await
            .unwrap();
        assert_eq!(
            c.repository.plan_session(persisted.id).await.unwrap(),
            session.id
        );
        let replay = c
            .plan_for_session(&r, session.id, session.version)
            .await
            .unwrap();
        assert_eq!(replay, persisted);
        assert_eq!(
            c.repository.inner.lock().unwrap().audits.len(),
            2,
            "an exact plan replay must not append another audit"
        );
        assert_eq!(
            c.repository
                .inner
                .lock()
                .unwrap()
                .audits
                .iter()
                .filter(|event| event.action == "change.plan")
                .count(),
            1
        );
        let mut changed_request = r.clone();
        changed_request.expiry += 1;
        assert_eq!(
            c.plan_for_session(&changed_request, session.id, session.version)
                .await,
            Err(ApplicationError::Replay)
        );
        assert!(c.repository.operations().await.unwrap().is_empty());
        assert!(p.is_expired(100));
        let mut stale = p.clone();
        stale.observed_state_hashes[0] = "after".into();
        assert_ne!(p.plan_hash, stale.compute_hash());
    }

    #[tokio::test]
    async fn begin_replays_same_request_and_rejects_changed_payload() {
        let repository = MemoryRepository::default();
        let actor = ActorId::new();
        let service = ServiceId::new();
        let cluster = ClusterId::new();
        repository
            .insert_cluster(GameCluster {
                id: cluster,
                service_id: service,
                key: "begin-cluster".into(),
                current_revision: None,
            })
            .unwrap();
        let coordinator = ChangeCoordinator {
            repository: repository.clone(),
            authorizer: Allow,
            audit: Audit,
        };
        let request = request(actor, service, cluster);
        let first = coordinator.begin(&request).await.unwrap();
        let replay = coordinator.begin(&request).await.unwrap();
        assert_eq!(replay, first);
        assert_eq!(repository.sessions().await.unwrap().len(), 1);
        assert_eq!(
            repository
                .inner
                .lock()
                .unwrap()
                .audits
                .iter()
                .filter(|event| event.action == "change.begin")
                .count(),
            1,
            "an exact begin replay must not append another audit"
        );

        let mut changed = request;
        changed.expiry += 1;
        assert_eq!(
            coordinator.begin(&changed).await,
            Err(ApplicationError::Replay)
        );
        assert_eq!(repository.sessions().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn begin_replay_rejects_duplicate_original_audit() {
        let repository = MemoryRepository::default();
        let actor = ActorId::new();
        let service = ServiceId::new();
        let cluster = ClusterId::new();
        repository
            .insert_cluster(GameCluster {
                id: cluster,
                service_id: service,
                key: "duplicate-begin-audit".into(),
                current_revision: None,
            })
            .unwrap();
        let coordinator = ChangeCoordinator {
            repository: repository.clone(),
            authorizer: Allow,
            audit: Audit,
        };
        let request = request(actor, service, cluster);
        coordinator.begin(&request).await.unwrap();
        let duplicate = repository.inner.lock().unwrap().audits[0].clone();
        repository.inner.lock().unwrap().audits.push(duplicate);
        assert_eq!(
            coordinator.begin(&request).await,
            Err(ApplicationError::Conflict("change begin audit event"))
        );
    }

    #[tokio::test]
    async fn begin_rejects_invalid_audit_without_queueing_session() {
        let repository = MemoryRepository::default();
        let actor = ActorId::new();
        let service = ServiceId::new();
        let cluster = ClusterId::new();
        repository
            .insert_cluster(GameCluster {
                id: cluster,
                service_id: service,
                key: "atomic-begin".into(),
                current_revision: None,
            })
            .unwrap();
        let request = request(actor, service, cluster);
        let mut audit = application_audit_event(
            actor,
            "change.begin",
            cluster.as_uuid().to_string(),
            FileClassification::Managed,
            AuditScope::for_cluster(service, cluster),
            AuditResult::Success,
            None,
            None,
            None,
            Some(request.idempotency_key.clone()),
            vec![],
        );
        audit.target.clear();
        let session = ChangeSession {
            id: ChangeSessionId::new(),
            target_cluster: cluster,
            state: ChangeSessionState::Editing,
            version: 1,
        };
        let hash = request.request_hash().unwrap();
        let mut tx = repository.transaction().await.unwrap();
        assert_eq!(
            tx.save_session_idempotent_for_actor(
                session,
                actor,
                &request.idempotency_key,
                &hash,
                audit,
            )
            .await,
            Err(ApplicationError::Conflict("change begin audit event"))
        );
        drop(tx);
        assert!(repository.sessions().await.unwrap().is_empty());
        assert!(repository.inner.lock().unwrap().audits.is_empty());
    }

    #[tokio::test]
    async fn plan_rejects_binding_outside_service_and_cluster_scope() {
        let repository = MemoryRepository::default();
        let actor = ActorId::new();
        let service_a = ServiceId::new();
        let service_b = ServiceId::new();
        let cluster_a = ClusterId::new();
        let cluster_b = ClusterId::new();
        repository
            .insert_cluster(GameCluster {
                id: cluster_a,
                service_id: service_a,
                key: "cluster-a".into(),
                current_revision: None,
            })
            .unwrap();
        repository
            .insert_cluster(GameCluster {
                id: cluster_b,
                service_id: service_b,
                key: "cluster-b".into(),
                current_revision: None,
            })
            .unwrap();
        let binding_id = BindingId::new();
        repository
            .insert_gameap_binding(
                binding_id,
                service_b,
                cluster_b,
                GameAPBinding {
                    execution_unit_id: "provider-unit-b".into(),
                    node_id: "node-b".into(),
                    target: GameAPBindingTarget::Cluster(cluster_b),
                },
            )
            .unwrap();
        let coordinator = ChangeCoordinator {
            repository,
            authorizer: Allow,
            audit: Audit,
        };
        let mut change = request(actor, service_a, cluster_a);
        set_binding_id(&mut change.steps[0], binding_id);
        assert_eq!(
            coordinator.plan(&change).await,
            Err(ApplicationError::NotFound("gameap binding"))
        );
        set_binding_id(&mut change.steps[0], BindingId::new());
        assert_eq!(
            coordinator.plan(&change).await,
            Err(ApplicationError::NotFound("gameap binding"))
        );
    }

    #[tokio::test]
    async fn resolved_binding_fingerprint_rejects_provider_drift() {
        let repository = MemoryRepository::default();
        let actor = ActorId::new();
        let service = ServiceId::new();
        let cluster = ClusterId::new();
        repository
            .insert_cluster(GameCluster {
                id: cluster,
                service_id: service,
                key: "cluster".into(),
                current_revision: None,
            })
            .unwrap();
        let binding_id = BindingId::new();
        let binding = GameAPBinding {
            execution_unit_id: "provider-unit".into(),
            node_id: "node-a".into(),
            target: GameAPBindingTarget::Cluster(cluster),
        };
        repository
            .insert_gameap_binding(binding_id, service, cluster, binding.clone())
            .unwrap();
        let coordinator = ChangeCoordinator {
            repository: repository.clone(),
            authorizer: Allow,
            audit: Audit,
        };
        let mut change = request(actor, service, cluster);
        set_binding_id(&mut change.steps[0], binding_id);
        set_binding_hash(&mut change.steps[0], binding.fingerprint());
        let plan = coordinator.plan(&change).await.unwrap();
        let binding_hash = binding.fingerprint();
        assert_eq!(
            plan.steps[0].action.expected_binding_hash(),
            Some(binding_hash.as_str())
        );

        let drifted = GameAPBinding {
            node_id: "node-b".into(),
            ..binding.clone()
        };
        repository
            .insert_gameap_binding(binding_id, service, cluster, drifted.clone())
            .unwrap();
        assert_eq!(
            resolve_change_steps(&repository, service, cluster, &plan.steps).await,
            Err(ApplicationError::StalePlan)
        );
        assert_eq!(
            OperationStep::from_plan(
                &plan.steps[0],
                Some(drifted),
                plan.id,
                plan.expiry,
                ChangeSessionId::new(),
                0,
            ),
            Err(ApplicationError::StalePlan)
        );
    }

    #[derive(Clone, Default)]
    struct DurableMemory {
        state: Arc<Mutex<DurableMemoryState>>,
    }
    #[derive(Default)]
    struct DurableMemoryState {
        operation: Option<Operation>,
        failures: Vec<OperationFailure>,
        evidence: Vec<StepEvidence>,
        releases: usize,
        attempts: usize,
        lease_owner: Option<String>,
    }
    #[async_trait]
    impl OperationStore for DurableMemory {
        async fn find_idempotent(
            &self,
            _: &OperationRequest,
        ) -> Result<Option<Operation>, ApplicationError> {
            Ok(self
                .state
                .lock()
                .map_err(|_| ApplicationError::Port("test lock poisoned".into()))?
                .operation
                .clone())
        }
        async fn acquire_lease(
            &self,
            operation: OperationId,
            holder: &str,
            now: u64,
            ttl: u64,
        ) -> Result<OperationLease, ApplicationError> {
            let mut state = self
                .state
                .lock()
                .map_err(|_| ApplicationError::Port("test lock poisoned".into()))?;
            state.attempts += 1;
            state.lease_owner = Some(holder.into());
            Ok(OperationLease {
                operation,
                holder: holder.into(),
                attempt: state.attempts as u32,
                expires_at: now + ttl,
            })
        }
        async fn release_lease(&self, lease: &OperationLease) -> Result<(), ApplicationError> {
            let mut state = self
                .state
                .lock()
                .map_err(|_| ApplicationError::Port("test lock poisoned".into()))?;
            if state.lease_owner.as_deref() != Some(lease.holder.as_str()) {
                return Err(ApplicationError::Conflict("operation lease"));
            }
            state.lease_owner = None;
            state.releases += 1;
            Ok(())
        }
        async fn create_idempotent(
            &self,
            _: &OperationRequest,
            operation: Operation,
        ) -> Result<Operation, ApplicationError> {
            self.state
                .lock()
                .map_err(|_| ApplicationError::Port("test lock poisoned".into()))?
                .operation = Some(operation.clone());
            Ok(operation)
        }
        async fn operation_for_plan(
            &self,
            plan: PlanId,
        ) -> Result<Option<Operation>, ApplicationError> {
            Ok(self
                .state
                .lock()
                .map_err(|_| ApplicationError::Port("test lock poisoned".into()))?
                .operation
                .clone()
                .filter(|operation| operation.plan_id == plan))
        }
        async fn operation(&self, _: OperationId) -> Result<Operation, ApplicationError> {
            self.state
                .lock()
                .map_err(|_| ApplicationError::Port("test lock poisoned".into()))?
                .operation
                .clone()
                .ok_or(ApplicationError::NotFound("operation"))
        }
        async fn mark_state(
            &self,
            _: OperationId,
            state: OperationState,
            _: &str,
        ) -> Result<(), ApplicationError> {
            if let Some(operation) = self
                .state
                .lock()
                .map_err(|_| ApplicationError::Port("test lock poisoned".into()))?
                .operation
                .as_mut()
            {
                operation.state = state;
            }
            Ok(())
        }
        async fn renew_lease(
            &self,
            lease: &OperationLease,
            ttl: u64,
        ) -> Result<OperationLease, ApplicationError> {
            Ok(OperationLease {
                expires_at: lease.expires_at.saturating_add(ttl),
                ..lease.clone()
            })
        }
        async fn finish_operation(
            &self,
            lease: &OperationLease,
            state: OperationState,
            _result: serde_json::Value,
        ) -> Result<Operation, ApplicationError> {
            let mut state_guard = self
                .state
                .lock()
                .map_err(|_| ApplicationError::Port("test lock poisoned".into()))?;
            state_guard.releases += 1;
            let operation = state_guard
                .operation
                .as_mut()
                .ok_or(ApplicationError::NotFound("operation"))?;
            operation.state = state;
            let _ = lease;
            Ok(operation.clone())
        }
        async fn fail_operation(
            &self,
            _: OperationId,
            failure: OperationFailure,
            _: &str,
        ) -> Result<(), ApplicationError> {
            let mut state = self
                .state
                .lock()
                .map_err(|_| ApplicationError::Port("test lock poisoned".into()))?;
            state.failures.push(failure);
            state.releases += 1;
            state.lease_owner = None;
            if let Some(operation) = state.operation.as_mut() {
                operation.state = OperationState::Failed;
            }
            Ok(())
        }
        async fn record_step_owned(
            &self,
            _: OperationId,
            evidence: StepEvidence,
            holder: &str,
        ) -> Result<(), ApplicationError> {
            let mut state = self
                .state
                .lock()
                .map_err(|_| ApplicationError::Port("test lock poisoned".into()))?;
            if state.lease_owner.as_deref() != Some(holder) {
                return Err(ApplicationError::Conflict("operation lease"));
            }
            state
                .evidence
                .retain(|item| item.sequence != evidence.sequence);
            state.evidence.push(evidence);
            Ok(())
        }
        async fn step_evidence(
            &self,
            _: OperationId,
        ) -> Result<Vec<StepEvidence>, ApplicationError> {
            Ok(self
                .state
                .lock()
                .map_err(|_| ApplicationError::Port("test lock poisoned".into()))?
                .evidence
                .clone())
        }
        async fn finish_verified(
            &self,
            _: &OperationLease,
            _: ChangeSessionId,
            _: Vec<String>,
        ) -> Result<Operation, ApplicationError> {
            let mut state = self
                .state
                .lock()
                .map_err(|_| ApplicationError::Port("test lock poisoned".into()))?;
            let operation = state
                .operation
                .as_mut()
                .ok_or(ApplicationError::NotFound("operation"))?;
            operation.state = OperationState::Verified;
            Ok(operation.clone())
        }
        async fn finish_accepted(
            &self,
            _: &OperationLease,
            _: ChangeSessionId,
        ) -> Result<Operation, ApplicationError> {
            let mut state = self
                .state
                .lock()
                .map_err(|_| ApplicationError::Port("test lock poisoned".into()))?;
            let operation = state
                .operation
                .as_mut()
                .ok_or(ApplicationError::NotFound("operation"))?;
            operation.state = OperationState::Accepted;
            Ok(operation.clone())
        }
        async fn finish_rolled_back(
            &self,
            _: &OperationLease,
            _: ChangeSessionId,
        ) -> Result<Operation, ApplicationError> {
            let mut state = self
                .state
                .lock()
                .map_err(|_| ApplicationError::Port("test lock poisoned".into()))?;
            let operation = state
                .operation
                .as_mut()
                .ok_or(ApplicationError::NotFound("operation"))?;
            operation.state = OperationState::RolledBack;
            Ok(operation.clone())
        }
    }
    struct FailingStep {
        fail_once: Arc<Mutex<bool>>,
    }
    #[async_trait]
    impl DurableStepPort for FailingStep {
        async fn observe(
            &self,
            _: &OperationStep,
            _: Option<&StepEvidence>,
        ) -> Result<StepObservation, ApplicationError> {
            Ok(StepObservation {
                state_hash: "state".into(),
                completed: false,
                unambiguous: true,
            })
        }
        async fn observe_restore(
            &self,
            _: &OperationStep,
            _: Option<&StepEvidence>,
        ) -> Result<StepObservation, ApplicationError> {
            Err(ApplicationError::Port(
                "unexpected restore test step".into(),
            ))
        }
        async fn observe_backup(
            &self,
            _: &OperationStep,
            _: Option<&StepEvidence>,
        ) -> Result<StepObservation, ApplicationError> {
            Err(ApplicationError::Port("unexpected backup test step".into()))
        }
        async fn prepare(
            &self,
            _: &OperationStep,
        ) -> Result<Option<StepExecutionEvidence>, ApplicationError> {
            Ok(Some(StepExecutionEvidence::Execution {
                binding_id: BindingId::new(),
                prior_state_hash: "0".repeat(64),
                prior_running: true,
                prior_exists: true,
                prior_binding: None,
                created_provider_unit: None,
                provider_idempotency_key: "test-idempotency".into(),
            }))
        }
        async fn apply(
            &self,
            _: &OperationStep,
            _: Option<&StepExecutionEvidence>,
        ) -> Result<StepApplyResult, ApplicationError> {
            let mut fail = self
                .fail_once
                .lock()
                .map_err(|_| ApplicationError::Port("test lock poisoned".into()))?;
            if *fail {
                *fail = false;
                return Err(ApplicationError::Port("apply failed".into()));
            }
            Ok(StepApplyResult {
                observation: StepObservation {
                    state_hash: "state".into(),
                    completed: true,
                    unambiguous: true,
                },
                evidence: None,
            })
        }
        async fn apply_backup(
            &self,
            _: &OperationStep,
        ) -> Result<BackupReference, ApplicationError> {
            Err(ApplicationError::Port("unexpected backup test step".into()))
        }
        async fn apply_restore(
            &self,
            _: &OperationStep,
        ) -> Result<BackupRestoreInvocation, ApplicationError> {
            Err(ApplicationError::Port(
                "unexpected restore test step".into(),
            ))
        }
    }

    struct SequencedStep;
    #[async_trait]
    impl DurableStepPort for SequencedStep {
        async fn observe(
            &self,
            step: &OperationStep,
            _: Option<&StepEvidence>,
        ) -> Result<StepObservation, ApplicationError> {
            let state_hash = match step {
                OperationStep::ExecutionRestart { binding } => binding.execution_unit_id.clone(),
                _ => return Err(ApplicationError::Port("unexpected test step".into())),
            };
            Ok(StepObservation {
                state_hash,
                completed: false,
                unambiguous: true,
            })
        }

        async fn observe_restore(
            &self,
            _: &OperationStep,
            _: Option<&StepEvidence>,
        ) -> Result<StepObservation, ApplicationError> {
            Err(ApplicationError::Port(
                "unexpected restore test step".into(),
            ))
        }
        async fn observe_backup(
            &self,
            _: &OperationStep,
            _: Option<&StepEvidence>,
        ) -> Result<StepObservation, ApplicationError> {
            Err(ApplicationError::Port("unexpected backup test step".into()))
        }
        async fn prepare(
            &self,
            _: &OperationStep,
        ) -> Result<Option<StepExecutionEvidence>, ApplicationError> {
            Ok(Some(StepExecutionEvidence::Execution {
                binding_id: BindingId::new(),
                prior_state_hash: "0".repeat(64),
                prior_running: true,
                prior_exists: true,
                prior_binding: None,
                created_provider_unit: None,
                provider_idempotency_key: "test-idempotency".into(),
            }))
        }
        async fn apply(
            &self,
            step: &OperationStep,
            _: Option<&StepExecutionEvidence>,
        ) -> Result<StepApplyResult, ApplicationError> {
            let state_hash = match step {
                OperationStep::ExecutionRestart { binding } => binding.execution_unit_id.clone(),
                _ => return Err(ApplicationError::Port("unexpected test step".into())),
            };
            Ok(StepApplyResult {
                observation: StepObservation {
                    state_hash,
                    completed: true,
                    unambiguous: true,
                },
                evidence: None,
            })
        }
        async fn apply_backup(
            &self,
            _: &OperationStep,
        ) -> Result<BackupReference, ApplicationError> {
            Err(ApplicationError::Port("unexpected backup test step".into()))
        }
        async fn apply_restore(
            &self,
            _: &OperationStep,
        ) -> Result<BackupRestoreInvocation, ApplicationError> {
            Err(ApplicationError::Port(
                "unexpected restore test step".into(),
            ))
        }
    }

    struct RestoreStep {
        applies: Arc<Mutex<usize>>,
    }
    #[async_trait]
    impl DurableStepPort for RestoreStep {
        async fn observe(
            &self,
            _: &OperationStep,
            _: Option<&StepEvidence>,
        ) -> Result<StepObservation, ApplicationError> {
            Err(ApplicationError::Port(
                "restore requires restore observation".into(),
            ))
        }

        async fn observe_restore(
            &self,
            step: &OperationStep,
            evidence: Option<&StepEvidence>,
        ) -> Result<StepObservation, ApplicationError> {
            let OperationStep::BackupRestore {
                expected_manifest_digest,
                ..
            } = step
            else {
                return Err(ApplicationError::Port(
                    "unexpected restore test step".into(),
                ));
            };
            let completed = evidence
                .and_then(|evidence| evidence.execution.as_ref())
                .is_some();
            Ok(StepObservation {
                state_hash: expected_manifest_digest.clone(),
                completed,
                unambiguous: true,
            })
        }
        async fn observe_backup(
            &self,
            _: &OperationStep,
            _: Option<&StepEvidence>,
        ) -> Result<StepObservation, ApplicationError> {
            Err(ApplicationError::Port("unexpected backup test step".into()))
        }

        async fn prepare(
            &self,
            _: &OperationStep,
        ) -> Result<Option<StepExecutionEvidence>, ApplicationError> {
            Ok(Some(StepExecutionEvidence::Noop))
        }

        async fn apply(
            &self,
            _: &OperationStep,
            _: Option<&StepExecutionEvidence>,
        ) -> Result<StepApplyResult, ApplicationError> {
            Err(ApplicationError::Port(
                "restore requires restore apply".into(),
            ))
        }
        async fn apply_backup(
            &self,
            _: &OperationStep,
        ) -> Result<BackupReference, ApplicationError> {
            Err(ApplicationError::Port("unexpected backup test step".into()))
        }

        async fn apply_restore(
            &self,
            step: &OperationStep,
        ) -> Result<BackupRestoreInvocation, ApplicationError> {
            let OperationStep::BackupRestore {
                session_id,
                plan_id,
                plan_expiry: _,
                idempotency_key: _,
                reference,
                target,
                expected_manifest_digest,
                rollback_reference,
                expected_rollback_manifest_digest,
                expected_version: _,
            } = step
            else {
                return Err(ApplicationError::Port(
                    "unexpected restore test step".into(),
                ));
            };
            *self.applies.lock().unwrap() += 1;
            let _ = session_id;
            Ok(BackupRestoreInvocation {
                plan_id: *plan_id,
                reference_id: *reference,
                target: *target,
                expected_manifest_digest: expected_manifest_digest.clone(),
                rollback_reference_id: *rollback_reference,
                expected_rollback_manifest_digest: expected_rollback_manifest_digest.clone(),
                provider_invocation: "restore-invocation".into(),
            })
        }
    }

    fn durable_plan() -> PlanDescriptor {
        let binding = GameAPBinding {
            execution_unit_id: "runtime".into(),
            node_id: "node".into(),
            target: GameAPBindingTarget::ExecutionUnit("opaque".into()),
        };
        let mut plan = PlanDescriptor::new(
            ActorId::new(),
            PlanTarget::Cluster(ClusterId::new()),
            1,
            100,
            vec![
                PlanStep::new(PlanStepAction::ExecutionLifecycle {
                    action: ExecutionLifecycleAction::Restart,
                    binding_id: BindingId::from_uuid(Uuid::nil()),
                    expected_binding_hash: binding.fingerprint(),
                    expected_state_hash: "a".repeat(64),
                    domain_revision: 1,
                })
                .expect("valid durable test plan step"),
            ],
        )
        .unwrap();
        plan.observed_state_hashes.push("state".into());
        plan.plan_hash = plan.compute_hash();
        plan
    }

    #[tokio::test]
    async fn durable_failure_is_terminal_and_retains_prepared_inverse() {
        let operations = DurableMemory::default();
        let steps = FailingStep {
            fail_once: Arc::new(Mutex::new(true)),
        };
        let executor = DurableExecutor {
            operations: &operations,
            steps: &steps,
            audit: &Audit,
        };
        let plan = durable_plan();
        let resolved_steps = vec![OperationStep::ExecutionRestart {
            binding: GameAPBinding {
                execution_unit_id: "runtime".into(),
                node_id: "node".into(),
                target: GameAPBindingTarget::ExecutionUnit("opaque".into()),
            },
        }];
        let request = OperationRequest {
            key: "durable-retry".into(),
            actor: plan.actor,
            service: ServiceId::new(),
            session_id: ChangeSessionId::new(),
            target: plan.target.stable_string(),
            request_hash: "request-hash".into(),
        };
        let audit_scope =
            AuditScope::for_operation(request.service, OperationId::from_uuid(plan.id.as_uuid()));
        assert!(operations.state.lock().unwrap().operation.is_none());
        assert_eq!(
            executor
                .run(
                    &request,
                    &plan,
                    &resolved_steps,
                    audit_scope.clone(),
                    1,
                    "worker-a"
                )
                .await,
            Err(ApplicationError::Port("apply failed".into()))
        );
        {
            let state = operations.state.lock().unwrap();
            assert!(state.operation.is_some());
            assert_eq!(state.releases, 1);
            assert_eq!(state.attempts, 1);
            assert_eq!(
                state.operation.as_ref().unwrap().state,
                OperationState::Failed
            );
            assert_eq!(state.failures[0].code, "port");
            assert!(state.failures[0].evidence.iter().any(|v| v == "sequence=0"));
        }
        let operation_id = operations
            .state
            .lock()
            .unwrap()
            .operation
            .as_ref()
            .unwrap()
            .id;
        let evidence = operations.step_evidence(operation_id).await.unwrap();
        assert!(matches!(
            evidence.first().and_then(|item| item.execution.as_ref()),
            Some(StepExecutionEvidence::Execution { .. })
        ));
        assert_eq!(
            executor
                .run(&request, &plan, &resolved_steps, audit_scope, 1, "worker-b")
                .await,
            Err(ApplicationError::Replay)
        );
        let state = operations.state.lock().unwrap();
        assert_eq!(state.attempts, 1);
        assert_eq!(state.releases, 1);
    }

    #[tokio::test]
    async fn durable_executor_matches_observed_hashes_to_step_sequence() {
        let operations = DurableMemory::default();
        let steps = SequencedStep;
        let executor = DurableExecutor {
            operations: &operations,
            steps: &steps,
            audit: &Audit,
        };
        let first = GameAPBinding {
            execution_unit_id: "first".into(),
            node_id: "node".into(),
            target: GameAPBindingTarget::ExecutionUnit("opaque-first".into()),
        };
        let second = GameAPBinding {
            execution_unit_id: "second".into(),
            node_id: "node".into(),
            target: GameAPBindingTarget::ExecutionUnit("opaque-second".into()),
        };
        let mut plan = PlanDescriptor::new(
            ActorId::new(),
            PlanTarget::Cluster(ClusterId::new()),
            1,
            100,
            vec![
                PlanStep::new(PlanStepAction::ExecutionLifecycle {
                    action: ExecutionLifecycleAction::Restart,
                    binding_id: BindingId::new(),
                    expected_binding_hash: first.fingerprint(),
                    expected_state_hash: "a".repeat(64),
                    domain_revision: 1,
                })
                .unwrap(),
                PlanStep::new(PlanStepAction::ExecutionLifecycle {
                    action: ExecutionLifecycleAction::Restart,
                    binding_id: BindingId::new(),
                    expected_binding_hash: second.fingerprint(),
                    expected_state_hash: "b".repeat(64),
                    domain_revision: 1,
                })
                .unwrap(),
            ],
        )
        .unwrap();
        plan.observed_state_hashes = vec!["first".into(), "second".into()];
        plan.plan_hash = plan.compute_hash();
        let request = OperationRequest {
            key: "durable-sequence".into(),
            actor: plan.actor,
            service: ServiceId::new(),
            session_id: ChangeSessionId::new(),
            target: plan.target.stable_string(),
            request_hash: "request-hash".into(),
        };
        let resolved_steps = vec![
            OperationStep::ExecutionRestart { binding: first },
            OperationStep::ExecutionRestart { binding: second },
        ];
        let result = executor
            .run(
                &request,
                &plan,
                &resolved_steps,
                AuditScope::for_operation(
                    request.service,
                    OperationId::from_uuid(plan.id.as_uuid()),
                ),
                1,
                "worker-sequence",
            )
            .await
            .unwrap();
        assert_eq!(result.state, OperationState::Verifying);
    }

    #[tokio::test]
    async fn restore_apply_persists_invocation_for_reobservation_without_retry() {
        let operations = DurableMemory::default();
        let applies = Arc::new(Mutex::new(0));
        let steps = RestoreStep {
            applies: applies.clone(),
        };
        let executor = DurableExecutor {
            operations: &operations,
            steps: &steps,
            audit: &Audit,
        };
        let session_id = ChangeSessionId::new();
        let reference = BackupReferenceId::new();
        let rollback_reference = BackupReferenceId::new();
        let target = BackupTarget::Cluster(ClusterId::new());
        let digest = "a".repeat(64);
        let plan = PlanDescriptor::new(
            ActorId::new(),
            PlanTarget::Cluster(match target {
                BackupTarget::Cluster(cluster) => cluster,
                _ => unreachable!(),
            }),
            1,
            100,
            vec![],
        )
        .unwrap();
        let operation_step = OperationStep::BackupRestore {
            session_id,
            plan_id: plan.id,
            plan_expiry: 100,
            idempotency_key: "restore:deterministic".into(),
            reference,
            target,
            expected_manifest_digest: digest.clone(),
            rollback_reference,
            expected_rollback_manifest_digest: digest.clone(),
            expected_version: 1,
        };
        let request = OperationRequest {
            key: "restore-operation".into(),
            actor: plan.actor,
            service: ServiceId::new(),
            session_id,
            target: plan.target.stable_string(),
            request_hash: "request-hash".into(),
        };
        let result = executor
            .run(
                &request,
                &plan,
                std::slice::from_ref(&operation_step),
                AuditScope::for_operation(
                    request.service,
                    OperationId::from_uuid(plan.id.as_uuid()),
                ),
                1,
                "restore-worker",
            )
            .await
            .unwrap();
        assert_eq!(result.state, OperationState::Verifying);
        assert_eq!(*applies.lock().unwrap(), 1);
        let evidence = operations.step_evidence(result.id).await.unwrap();
        assert!(matches!(
            evidence[0].execution,
            Some(StepExecutionEvidence::BackupRestore(_))
        ));
    }

    #[tokio::test]
    async fn evidence_without_active_holder_is_rejected() {
        let operations = DurableMemory::default();
        operations.state.lock().unwrap().operation = Some(Operation {
            id: OperationId::new(),
            plan_id: PlanId::new(),
            session_id: ChangeSessionId::new(),
            state: OperationState::Applying,
        });
        let result = operations
            .record_step_owned(
                OperationId::new(),
                StepEvidence {
                    sequence: 0,
                    state_hash: "state".into(),
                    result: "applied".into(),
                    execution: None,
                },
                "worker-without-lease",
            )
            .await;
        assert_eq!(result, Err(ApplicationError::Conflict("operation lease")));
    }

    #[test]
    fn sftp_scan_request_hash_covers_metadata_and_is_order_independent() {
        let digest = "a".repeat(64);
        let changed = SftpChangedPath::new(
            "server.properties",
            SftpChangeKind::Modified,
            Some(&digest),
            Some(&"b".repeat(64)),
            FileClassification::Managed,
        )
        .unwrap();
        let mut request = SftpScanRequest {
            actor: ActorId::new(),
            service: ServiceId::new(),
            endpoint: SftpEndpointId::new(),
            binding: BindingId::new(),
            session: ChangeSessionId::new(),
            before_manifest_hash: digest.clone(),
            after_manifest_hash: "b".repeat(64),
            changed_paths: vec![changed],
            observed_at: 42,
            source: SftpScanSource::OutOfBand,
            idempotency_key: "scan-1".into(),
            request_hash: String::new(),
        };
        let first = request.computed_request_hash().unwrap();
        request.changed_paths.reverse();
        assert_eq!(request.computed_request_hash().unwrap(), first);
        request.after_manifest_hash = "c".repeat(64);
        assert_ne!(request.computed_request_hash().unwrap(), first);
    }

    #[derive(Clone, Default)]
    struct RecordingAudit {
        events: Arc<Mutex<Vec<AuditEvent>>>,
    }
    #[async_trait]
    impl AuditSink for RecordingAudit {
        async fn record(&self, event: AuditEvent) -> Result<(), ApplicationError> {
            self.events
                .lock()
                .map_err(|_| ApplicationError::Port("test lock poisoned".into()))?
                .push(event);
            Ok(())
        }
    }

    #[tokio::test]
    async fn change_audit_carries_cluster_scope_and_plan_metadata() {
        let repository = MemoryRepository::default();
        let actor = ActorId::new();
        let service = ServiceId::new();
        let cluster = ClusterId::new();
        repository
            .insert_cluster(GameCluster {
                id: cluster,
                service_id: service,
                key: "cluster".into(),
                current_revision: None,
            })
            .unwrap();
        let binding = GameAPBinding {
            execution_unit_id: "runtime".into(),
            node_id: "node".into(),
            target: GameAPBindingTarget::Cluster(cluster),
        };
        let binding_id = BindingId::from_uuid(Uuid::nil());
        repository
            .insert_gameap_binding(binding_id, service, cluster, binding.clone())
            .unwrap();
        let audit = RecordingAudit::default();
        let coordinator = ChangeCoordinator {
            repository,
            authorizer: Allow,
            audit: audit.clone(),
        };
        let mut request = request(actor, service, cluster);
        set_binding_id(&mut request.steps[0], binding_id);
        set_binding_hash(&mut request.steps[0], binding.fingerprint());
        let session = coordinator.begin(&request).await.unwrap();
        let plan = coordinator
            .plan_for_session(&request, session.id, session.version)
            .await
            .unwrap();
        let events = audit.events.lock().unwrap();
        assert!(events.is_empty());
        let stored_events = coordinator.repository.inner.lock().unwrap().audits.clone();
        assert_eq!(stored_events.len(), 2);
        let begin_event = stored_events
            .iter()
            .find(|event| event.action == "change.begin")
            .unwrap();
        assert_eq!(begin_event.scope, AuditScope::for_cluster(service, cluster));
        assert_eq!(
            begin_event.request_id.as_deref(),
            Some(request.idempotency_key.as_str())
        );
        let plan_event = stored_events
            .iter()
            .find(|event| event.action == "change.plan")
            .unwrap();
        assert_eq!(
            plan_event.plan_hash.as_deref(),
            Some(plan.plan_hash.as_str())
        );
        assert_eq!(plan_event.before_revision, Some(request.domain_revision));
        assert_eq!(
            plan_event.request_id.as_deref(),
            Some(request.idempotency_key.as_str())
        );
    }

    #[tokio::test]
    async fn execution_file_facades_audit_actor_and_validate_upload_digest() {
        let audit = RecordingAudit::default();
        let service = ExecutionService {
            backend: UploadBackend {
                bytes: Arc::new(Mutex::new(Vec::new())),
            },
            authorizer: Allow,
            audit: audit.clone(),
        };
        let binding = GameAPBinding {
            execution_unit_id: "execution-1".into(),
            node_id: "node-1".into(),
            target: GameAPBindingTarget::ExecutionUnit("execution-1".into()),
        };
        let actor = ActorId::new();
        let service_id = ServiceId::new();
        service
            .read_file(&binding, "server.properties", actor, service_id)
            .await
            .unwrap();
        let change = FileChange {
            path: "server.properties".into(),
            content_digest: digest_bytes(b"safe"),
            classification: FileClassification::MutableConfig,
        };
        service
            .upload(
                &binding,
                &FileMutation {
                    change: change.clone(),
                    bytes: b"safe".to_vec(),
                    expected_before: None,
                    mode: FileMutationMode::Binary,
                },
                actor,
                service_id,
            )
            .await
            .unwrap();
        assert_eq!(
            audit
                .events
                .lock()
                .unwrap()
                .iter()
                .map(|event| event.action.as_str())
                .collect::<Vec<_>>(),
            vec!["files.read", "files.upload"]
        );
        {
            let events = audit.events.lock().unwrap();
            assert!(events.iter().all(|event| {
                event.scope.service_id == service_id
                    && event.scope.execution_unit_ref.as_deref() == Some("execution-1")
                    && event.source == AuditSource::Application
                    && event.result == AuditResult::Success
            }));
        }
        assert!(
            service
                .upload(
                    &binding,
                    &FileMutation {
                        change,
                        bytes: b"tampered".to_vec(),
                        expected_before: None,
                        mode: FileMutationMode::Binary,
                    },
                    actor,
                    service_id,
                )
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn change_session_accept_and_rollback_paths_are_distinct() {
        let repository = MemoryRepository::default();
        let actor = ActorId::new();
        let service = ServiceId::new();
        let cluster = ClusterId::new();
        repository
            .insert_cluster(GameCluster {
                id: cluster,
                service_id: service,
                key: "cluster".into(),
                current_revision: None,
            })
            .unwrap();
        repository
            .insert_gameap_binding(
                BindingId::from_uuid(Uuid::nil()),
                service,
                cluster,
                GameAPBinding {
                    execution_unit_id: "runtime".into(),
                    node_id: "node".into(),
                    target: GameAPBindingTarget::Cluster(cluster),
                },
            )
            .unwrap();
        let c = ChangeCoordinator {
            repository: repository.clone(),
            authorizer: Allow,
            audit: Audit,
        };
        let r = request(actor, service, cluster);
        let accepted = c.begin(&r).await.unwrap();
        c.ready(accepted.id, r.actor, r.service).await.unwrap();
        c.mark_applying(accepted.id, r.actor, r.service)
            .await
            .unwrap();
        c.verify_session(accepted.id, r.actor, r.service)
            .await
            .unwrap();
        assert_eq!(
            c.accept(accepted.id, r.actor, r.service)
                .await
                .unwrap()
                .state,
            ChangeSessionState::Accepted
        );

        let mut rollback_request = r.clone();
        rollback_request.idempotency_key = "rollback-path".into();
        let rolled_back = c.begin(&rollback_request).await.unwrap();
        c.ready(
            rolled_back.id,
            rollback_request.actor,
            rollback_request.service,
        )
        .await
        .unwrap();
        c.mark_applying(
            rolled_back.id,
            rollback_request.actor,
            rollback_request.service,
        )
        .await
        .unwrap();
        assert_eq!(
            c.rollback(
                rolled_back.id,
                rollback_request.actor,
                rollback_request.service,
            )
            .await
            .unwrap()
            .state,
            ChangeSessionState::RolledBack
        );
    }
    #[test]
    fn file_batch_preserves_state_and_unknown_safety() {
        let c = FileChange {
            path: "world/region/r.0.0.mca".into(),
            content_digest: "x".into(),
            classification: FileClassification::State,
        };
        assert_eq!(
            validate_file_batch(&[c]),
            Err(ApplicationError::Conflict(
                "file classification is not writable"
            ))
        );
        assert_eq!(
            mask_secret("say token=abc mode=normal"),
            "say token=[REDACTED] mode=normal"
        );
    }

    struct ArtifactSource {
        bytes: Vec<u8>,
    }
    #[async_trait]
    impl ArtifactProvider for ArtifactSource {
        async fn discover(&self, _: &str) -> Result<Vec<ArtifactCandidate>, ApplicationError> {
            Ok(vec![])
        }
        async fn download(&self, _: &ArtifactCandidate) -> Result<Vec<u8>, ApplicationError> {
            Ok(self.bytes.clone())
        }
    }
    struct CasStore {
        bytes: Arc<Mutex<Option<Vec<u8>>>>,
    }
    #[async_trait]
    impl ArtifactStore for CasStore {
        async fn has(&self, _: &str) -> Result<bool, ApplicationError> {
            Ok(self
                .bytes
                .lock()
                .map_err(|_| ApplicationError::Port("artifact store lock poisoned".into()))?
                .is_some())
        }
        async fn put(&self, _: &str, bytes: &[u8]) -> Result<(), ApplicationError> {
            *self
                .bytes
                .lock()
                .map_err(|_| ApplicationError::Port("artifact store lock poisoned".into()))? =
                Some(bytes.to_vec());
            Ok(())
        }
        async fn read(&self, _: &str) -> Result<Vec<u8>, ApplicationError> {
            self.bytes
                .lock()
                .map_err(|_| ApplicationError::Port("artifact store lock poisoned".into()))?
                .clone()
                .ok_or(ApplicationError::NotFound("artifact"))
        }
    }
    struct UploadBackend {
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    #[async_trait]
    impl ExecutionBackend for UploadBackend {
        async fn create(&self, _: &GameAPBinding) -> Result<(), ApplicationError> {
            Ok(())
        }

        async fn delete(&self, _: &GameAPBinding) -> Result<(), ApplicationError> {
            Ok(())
        }

        async fn start(&self, _: &GameAPBinding) -> Result<(), ApplicationError> {
            Ok(())
        }

        async fn stop(&self, _: &GameAPBinding) -> Result<(), ApplicationError> {
            Ok(())
        }

        async fn restart(&self, _: &GameAPBinding) -> Result<(), ApplicationError> {
            Ok(())
        }

        async fn status(&self, _: &GameAPBinding) -> Result<ExecutionStatus, ApplicationError> {
            Ok(ExecutionStatus {
                running: true,
                state_hash: "state".into(),
                node: "node".into(),
            })
        }

        async fn files(
            &self,
            _: &GameAPBinding,
            _: &str,
        ) -> Result<Vec<FileEntry>, ApplicationError> {
            Ok(Vec::new())
        }

        async fn read_file(&self, _: &GameAPBinding, _: &str) -> Result<Vec<u8>, ApplicationError> {
            self.bytes
                .lock()
                .map_err(|_| ApplicationError::Port("upload backend lock poisoned".into()))
                .map(|bytes| bytes.clone())
        }

        async fn write_file(
            &self,
            _: &GameAPBinding,
            _: &FileChange,
            bytes: &[u8],
        ) -> Result<(), ApplicationError> {
            *self
                .bytes
                .lock()
                .map_err(|_| ApplicationError::Port("upload backend lock poisoned".into()))? =
                bytes.to_vec();
            Ok(())
        }

        async fn upload(
            &self,
            binding: &GameAPBinding,
            change: &FileChange,
            bytes: &[u8],
        ) -> Result<(), ApplicationError> {
            self.write_file(binding, change, bytes).await
        }

        async fn download(
            &self,
            binding: &GameAPBinding,
            path: &str,
        ) -> Result<Vec<u8>, ApplicationError> {
            self.read_file(binding, path).await
        }

        async fn move_file(
            &self,
            _: &GameAPBinding,
            _: &str,
            _: &str,
        ) -> Result<(), ApplicationError> {
            Ok(())
        }

        async fn quarantine(&self, _: &GameAPBinding, _: &str) -> Result<(), ApplicationError> {
            Ok(())
        }

        async fn command(&self, _: &GameAPBinding, _: &str) -> Result<(), ApplicationError> {
            Ok(())
        }

        async fn restore_file(
            &self,
            _: &GameAPBinding,
            _: &FileChange,
        ) -> Result<(), ApplicationError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn artifact_stage_verifies_bytes_and_activation_binds_operation_context() {
        let bytes = b"artifact-bytes".to_vec();
        let digest = digest_bytes(&bytes);
        let artifact = Artifact {
            id: ArtifactId::new(),
            kind: "plugin".into(),
            name: "test-plugin".into(),
            version: "1".into(),
            source: "test".into(),
            source_id: "source-1".into(),
            digest: digest.clone(),
            filename: "test.jar".into(),
            compatibility: String::new(),
            metadata: String::new(),
        };
        let service = ArtifactService {
            provider: ArtifactSource {
                bytes: bytes.clone(),
            },
            store: CasStore {
                bytes: Arc::new(Mutex::new(None)),
            },
            authorizer: Allow,
            audit: Audit,
        };
        let candidate = ArtifactCandidate {
            artifact: artifact.clone(),
        };
        assert_eq!(
            service
                .stage(&candidate, ActorId::new(), ServiceId::new())
                .await
                .unwrap(),
            digest
        );
        let backend = UploadBackend {
            bytes: Arc::new(Mutex::new(Vec::new())),
        };
        service
            .activate(
                &ArtifactActivation {
                    operation: OperationId::new(),
                    change_session: ChangeSessionId::new(),
                    revision: RevisionId::new(),
                    execution: GameAPBinding {
                        execution_unit_id: "execution-1".into(),
                        node_id: "node-1".into(),
                        target: GameAPBindingTarget::ExecutionUnit("execution-1".into()),
                    },
                    path: "plugins/test.jar".into(),
                    artifact,
                },
                &backend,
                ActorId::new(),
                ServiceId::new(),
            )
            .await
            .unwrap();
        assert_eq!(*backend.bytes.lock().unwrap(), bytes);
    }

    #[test]
    fn step_inverse_evidence_roundtrips_and_rejects_action_mismatch() {
        let route = RouteId::new();
        let cluster = ClusterId::new();
        let evidence = StepExecutionEvidence::Route {
            route_id: route,
            prior_cluster: cluster,
            prior_priority: 10,
            prior_disabled: false,
            prior_version: 3,
        };
        let encoded = serde_json::to_vec(&evidence).unwrap();
        let decoded: StepExecutionEvidence = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, evidence);
        let step = OperationStep::RoutePolicyUpdate {
            route_id: route,
            pool_id: ProxyPoolId::new(),
            service_id: ServiceId::new(),
            expected_cluster: cluster,
            target_cluster: ClusterId::new(),
            expected_priority: 10,
            target_priority: 11,
            expected_version: 3,
            disabled: true,
        };
        assert!(evidence.validate_for(&step).is_ok());
        let mismatched = OperationStep::AccessPolicyUpdate {
            policy_id: PolicyId::new(),
            service_id: ServiceId::new(),
            expected_version: 1,
            desired_grants: vec![],
            desired_policy_hash: "a".repeat(64),
        };
        assert_eq!(
            evidence.validate_for(&mismatched),
            Err(ApplicationError::Conflict("step evidence/action mismatch"))
        );
    }

    #[test]
    fn file_batch_inverse_requires_each_entry_to_be_typed() {
        let evidence = StepExecutionEvidence::FileBatch { entries: vec![] };
        let step = OperationStep::FileBatch {
            binding: GameAPBinding {
                execution_unit_id: "unit".into(),
                node_id: "node".into(),
                target: GameAPBindingTarget::Service(ServiceId::new()),
            },
            operations: vec![],
            domain_revision: 1,
        };
        assert_eq!(
            evidence.validate_for(&step),
            Err(ApplicationError::Conflict("empty file inverse evidence"))
        );
    }
}
