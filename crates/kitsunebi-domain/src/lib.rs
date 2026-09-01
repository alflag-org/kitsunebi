#![forbid(unsafe_code)]

//! Pure MCPlayNetwork domain model. GameAP is represented only by opaque bindings.
use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as DeError};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

pub const CRATE_NAME: &str = "kitsunebi-domain";

macro_rules! id_type {
    ($name:ident) => {
        #[derive(
            Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
        )]
        pub struct $name(Uuid);
        impl $name {
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }
            pub fn from_uuid(v: Uuid) -> Self {
                Self(v)
            }
            pub fn as_uuid(&self) -> Uuid {
                self.0
            }
        }
        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }
    };
}
id_type!(NetworkId);
id_type!(ServiceId);
id_type!(ClusterId);
id_type!(RevisionId);
id_type!(WorldId);
id_type!(RuntimeProfileId);
id_type!(ProxyPoolId);
id_type!(ProxyInstanceId);
id_type!(RouteId);
id_type!(ArtifactId);
id_type!(ArtifactSetId);
id_type!(ConfigBaselineId);
id_type!(EndpointId);
id_type!(BindingId);
id_type!(PolicyId);
id_type!(ChangeSessionId);
id_type!(OperationId);
id_type!(BackupReferenceId);
id_type!(PlanId);
id_type!(ActorId);
id_type!(SftpEndpointId);
id_type!(SftpScanId);
id_type!(NodeCapabilityId);
id_type!(ServiceTombstoneId);
id_type!(StagedContentId);

/// A policy may be attached to an actor or to a named identity group. Group
/// membership is resolved by the identity mapper; JWT role/scope claims are
/// never used as policy input.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum AccessPrincipal {
    Actor(ActorId),
    Group(String),
}

/// Object scopes used by the persistence adapter when resolving a resource to
/// its owning service. The scope and the explicit action grant are both
/// required for an authorization decision.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum AccessScope {
    Global,
    Network(NetworkId),
    Service(ServiceId),
    Cluster(ClusterId),
    Revision(RevisionId),
    World(WorldId),
    ProxyPool(ProxyPoolId),
    ProxyInstance(ProxyInstanceId),
    Route(RouteId),
    RuntimeProfile(RuntimeProfileId),
    Artifact(ArtifactId),
    ArtifactSet(ArtifactSetId),
    ConfigBaseline(ConfigBaselineId),
    Endpoint(EndpointId),
    Binding(BindingId),
    ChangeSession(ChangeSessionId),
    Operation(OperationId),
    Backup(BackupReferenceId),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DomainError {
    #[error("invalid value: {0}")]
    InvalidValue(&'static str),
    #[error("invalid state transition from {from} to {to}")]
    InvalidTransition { from: String, to: String },
    #[error("revision is immutable")]
    ImmutableRevision,
    #[error("expected revision does not match current revision")]
    RevisionMismatch,
    #[error("multiple writers require externally coordinated mode")]
    MultipleWritersNotAllowed,
    #[error("access denied")]
    AccessDenied,
    #[error("the last platform administrator cannot be removed")]
    LastPlatformAdministrator,
    #[error("the last access grant cannot be removed")]
    LastAccessGrant,
    #[error("plan has expired")]
    PlanExpired,
    #[error("unknown process manager cannot satisfy placement")]
    UnknownProcessManager,
    #[error("sftp scan is only valid for an active change session")]
    InactiveChangeSession,
    #[error("unknown or state files cannot be removed")]
    ProtectedFileRemoval,
}
fn required(v: &str, what: &'static str) -> Result<String, DomainError> {
    let v = v.trim();
    if v.is_empty() {
        Err(DomainError::InvalidValue(what))
    } else {
        Ok(v.to_owned())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MCPlayNetwork {
    pub id: NetworkId,
    pub key: String,
    pub display_name: String,
    pub metadata: String,
}
impl MCPlayNetwork {
    pub fn new(key: &str, name: &str) -> Result<Self, DomainError> {
        Ok(Self {
            id: NetworkId::new(),
            key: required(key, "network key")?,
            display_name: required(name, "display name")?,
            metadata: String::new(),
        })
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Ownership {
    FirstParty,
    Hosted,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Audience {
    Public,
    Allowlist,
    OperatorOnly,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum OperatorModel {
    Central,
    Delegated,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum TrustProfile {
    Trusted,
    Constrained,
    Untrusted,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ServiceLifecycle {
    Planned,
    Testing,
    Active,
    Maintenance,
    Sunsetting,
    Archived,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Availability {
    AlwaysOn,
    Scheduled,
    OnDemand,
    Disabled,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Service {
    pub id: ServiceId,
    pub key: String,
    pub display_name: String,
    pub ownership: Ownership,
    pub audience: Audience,
    pub operator_model: OperatorModel,
    pub trust_profile: TrustProfile,
    pub lifecycle: ServiceLifecycle,
    pub availability: Availability,
    pub current_cluster: Option<ClusterId>,
    pub access_policy: Option<PolicyId>,
    pub backup_policy: Option<String>,
    pub metadata: String,
}
impl Service {
    pub fn new(
        key: &str,
        name: &str,
        ownership: Ownership,
        audience: Audience,
        operator_model: OperatorModel,
        trust_profile: TrustProfile,
    ) -> Result<Self, DomainError> {
        Ok(Self {
            id: ServiceId::new(),
            key: required(key, "service key")?,
            display_name: required(name, "display name")?,
            ownership,
            audience,
            operator_model,
            trust_profile,
            lifecycle: ServiceLifecycle::Planned,
            availability: Availability::Disabled,
            current_cluster: None,
            access_policy: None,
            backup_policy: None,
            metadata: String::new(),
        })
    }
    pub fn transition(&mut self, next: ServiceLifecycle) -> Result<(), DomainError> {
        let ok = matches!(
            (&self.lifecycle, &next),
            (ServiceLifecycle::Planned, ServiceLifecycle::Testing)
                | (ServiceLifecycle::Testing, ServiceLifecycle::Active)
                | (ServiceLifecycle::Active, ServiceLifecycle::Maintenance)
                | (ServiceLifecycle::Maintenance, ServiceLifecycle::Active)
                | (ServiceLifecycle::Active, ServiceLifecycle::Sunsetting)
                | (ServiceLifecycle::Maintenance, ServiceLifecycle::Sunsetting)
                | (ServiceLifecycle::Sunsetting, ServiceLifecycle::Archived)
                | (ServiceLifecycle::Testing, ServiceLifecycle::Archived)
        );
        if !ok {
            return Err(DomainError::InvalidTransition {
                from: format!("{:?}", self.lifecycle),
                to: format!("{next:?}"),
            });
        }
        self.lifecycle = next;
        Ok(())
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GameCluster {
    pub id: ClusterId,
    pub service_id: ServiceId,
    pub key: String,
    pub current_revision: Option<RevisionId>,
}
impl GameCluster {
    pub fn new(service_id: ServiceId, key: &str) -> Result<Self, DomainError> {
        Ok(Self {
            id: ClusterId::new(),
            service_id,
            key: required(key, "cluster key")?,
            current_revision: None,
        })
    }
    pub fn activate(
        &mut self,
        expected: Option<RevisionId>,
        revision: RevisionId,
    ) -> Result<(), DomainError> {
        if self.current_revision != expected {
            return Err(DomainError::RevisionMismatch);
        }
        self.current_revision = Some(revision);
        Ok(())
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ClusterRevision {
    pub id: RevisionId,
    pub number: u64,
    pub runtime_profile: RuntimeProfileId,
    pub minecraft_version: String,
    pub java_requirement: String,
    pub artifact_set: ArtifactSetId,
    pub config_baseline: ConfigBaselineId,
    pub world_bindings: Vec<WorldId>,
    pub endpoint_bindings: Vec<BindingId>,
    pub placement_requirements: PlacementRequirements,
    pub resource_requirements: String,
    pub health_checks: Vec<String>,
    pub startup_parameters: Vec<String>,
}

/// Provider-neutral process managers observed on a runtime node. Provider
/// adapters may map their own names to this closed set, but the domain never
/// receives a provider SDK type or a provider-specific node object.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessManager {
    Systemd,
    Docker,
    Podman,
    Unknown,
}
impl ProcessManager {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Systemd => "systemd",
            Self::Docker => "docker",
            Self::Podman => "podman",
            Self::Unknown => "unknown",
        }
    }

    pub fn parse(value: &str) -> Result<Self, DomainError> {
        match value {
            "systemd" => Ok(Self::Systemd),
            "docker" => Ok(Self::Docker),
            "podman" => Ok(Self::Podman),
            "unknown" => Ok(Self::Unknown),
            _ => Err(DomainError::InvalidValue("process manager")),
        }
    }
}

/// The minimum node capability a revision is willing to run on. An empty
/// manager list means that no manager restriction was requested; it does not
/// make an unknown observation safe for mutation.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct PlacementRequirements {
    pub process_managers: Vec<ProcessManager>,
    pub required_capabilities: Vec<String>,
}
impl PlacementRequirements {
    pub fn new(
        process_managers: Vec<ProcessManager>,
        required_capabilities: Vec<String>,
    ) -> Result<Self, DomainError> {
        if process_managers.contains(&ProcessManager::Unknown) {
            return Err(DomainError::UnknownProcessManager);
        }
        let mut requirements = Self {
            process_managers,
            required_capabilities: required_capabilities
                .into_iter()
                .map(|capability| capability.trim().to_owned())
                .collect(),
        };
        requirements
            .required_capabilities
            .retain(|capability| !capability.is_empty());
        requirements.process_managers.sort_unstable();
        requirements.process_managers.dedup();
        requirements.required_capabilities.sort_unstable();
        requirements.required_capabilities.dedup();
        Ok(requirements)
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        if self.process_managers.contains(&ProcessManager::Unknown) {
            return Err(DomainError::UnknownProcessManager);
        }
        if self
            .required_capabilities
            .iter()
            .any(|capability| capability.trim().is_empty())
        {
            return Err(DomainError::InvalidValue("placement capability"));
        }
        Ok(())
    }

    pub fn accepts(&self, observation: &NodeCapabilityObservation) -> bool {
        if self.validate().is_err() || observation.process_manager == ProcessManager::Unknown {
            return false;
        }
        (self.process_managers.is_empty()
            || self.process_managers.contains(&observation.process_manager))
            && self.required_capabilities.iter().all(|required| {
                observation
                    .capabilities
                    .iter()
                    .any(|value| value == required)
            })
    }
}

/// A provider-neutral node observation. `provider_node_ref` is intentionally
/// opaque and is only meaningful to the adapter that produced it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NodeCapabilityObservation {
    pub id: NodeCapabilityId,
    pub provider_node_ref: String,
    pub process_manager: ProcessManager,
    pub version: Option<String>,
    pub capabilities: Vec<String>,
    pub evidence_hash: String,
    pub observed_at: u64,
}
impl NodeCapabilityObservation {
    pub fn new(
        provider_node_ref: &str,
        process_manager: ProcessManager,
        version: Option<String>,
        capabilities: Vec<String>,
        evidence_hash: &str,
        observed_at: u64,
    ) -> Result<Self, DomainError> {
        let provider_node_ref = required(provider_node_ref, "provider node reference")?;
        let evidence_hash = normalize_sha256_digest(evidence_hash)?;
        let version = version
            .map(|value| required(&value, "process manager version"))
            .transpose()?;
        let mut observation = Self {
            id: NodeCapabilityId::new(),
            provider_node_ref,
            process_manager,
            version,
            capabilities: capabilities
                .into_iter()
                .map(|capability| capability.trim().to_owned())
                .collect(),
            evidence_hash,
            observed_at,
        };
        observation.capabilities.retain(|value| !value.is_empty());
        observation.capabilities.sort_unstable();
        observation.capabilities.dedup();
        observation.validate()?;
        Ok(observation)
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        if self.provider_node_ref.trim().is_empty() {
            return Err(DomainError::InvalidValue("provider node reference"));
        }
        normalize_sha256_digest(&self.evidence_hash)?;
        if self
            .capabilities
            .iter()
            .any(|capability| capability.trim().is_empty())
        {
            return Err(DomainError::InvalidValue("node capability"));
        }
        Ok(())
    }
}

impl ClusterRevision {
    pub fn new(
        number: u64,
        runtime_profile: RuntimeProfileId,
        minecraft_version: &str,
        artifact_set: ArtifactSetId,
        config_baseline: ConfigBaselineId,
    ) -> Result<Self, DomainError> {
        Ok(Self {
            id: RevisionId::new(),
            number,
            runtime_profile,
            minecraft_version: required(minecraft_version, "minecraft version")?,
            java_requirement: String::new(),
            artifact_set,
            config_baseline,
            world_bindings: vec![],
            endpoint_bindings: vec![],
            placement_requirements: PlacementRequirements::default(),
            resource_requirements: String::new(),
            health_checks: vec![],
            startup_parameters: vec![],
        })
    }

    /// Validate and return the typed placement contract.
    pub fn typed_placement_requirements(&self) -> Result<PlacementRequirements, DomainError> {
        self.placement_requirements.validate()?;
        Ok(self.placement_requirements.clone())
    }

    /// Build a revision with typed placement requirements without exposing a
    /// post-creation mutation API for the immutable revision itself.
    pub fn with_placement_requirements(
        mut self,
        requirements: PlacementRequirements,
    ) -> Result<Self, DomainError> {
        requirements.validate()?;
        self.placement_requirements = requirements;
        Ok(self)
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum WorldWriteMode {
    SingleWriter,
    ExternallyCoordinated,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum WorldExecutionModel {
    SingleProcess,
    RegionParallel,
    PartitionedWorld,
    ExternallyDistributed,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct World {
    pub id: WorldId,
    pub key: String,
    pub display_name: String,
    pub persistence: String,
    pub storage_ref: String,
    pub write_mode: WorldWriteMode,
    pub execution_model: WorldExecutionModel,
    pub current_writers: Vec<ClusterId>,
    pub backup_policy: Option<String>,
    pub metadata: String,
}
impl World {
    pub fn new(
        key: &str,
        name: &str,
        mode: WorldWriteMode,
        execution_model: WorldExecutionModel,
    ) -> Result<Self, DomainError> {
        Ok(Self {
            id: WorldId::new(),
            key: required(key, "world key")?,
            display_name: required(name, "display name")?,
            persistence: String::new(),
            storage_ref: String::new(),
            write_mode: mode,
            execution_model,
            current_writers: vec![],
            backup_policy: None,
            metadata: String::new(),
        })
    }
    pub fn assign_writer(&mut self, cluster: ClusterId) -> Result<(), DomainError> {
        if self.write_mode == WorldWriteMode::SingleWriter
            && !self.current_writers.is_empty()
            && !self.current_writers.contains(&cluster)
        {
            return Err(DomainError::MultipleWritersNotAllowed);
        }
        if !self.current_writers.contains(&cluster) {
            self.current_writers.push(cluster)
        }
        Ok(())
    }
    pub fn remove_writer(&mut self, cluster: ClusterId) {
        self.current_writers.retain(|v| *v != cluster)
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RuntimeProfile {
    pub id: RuntimeProfileId,
    pub family: String,
    pub minecraft_version: String,
    pub runtime_version: String,
    pub artifact_source: String,
    pub artifact_digest: String,
    pub java_requirement: String,
    pub startup_capability: bool,
    pub console_capability: bool,
    pub health_capability: bool,
    pub world_execution_capability: WorldExecutionModel,
    pub metadata: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProxyPool {
    pub id: ProxyPoolId,
    pub key: String,
    pub instances: Vec<ProxyInstanceId>,
}

/// Explicit TCPShield edge metadata. `backend_set_id` is provider-owned and
/// is never derived from the local pool key.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TcpShieldBackendSet {
    pub pool_id: ProxyPoolId,
    pub provider_network_id: u64,
    pub domain_network_id: Option<NetworkId>,
    pub backend_set_id: String,
}
impl TcpShieldBackendSet {
    pub fn new(
        pool_id: ProxyPoolId,
        provider_network_id: u64,
        backend_set_id: &str,
    ) -> Result<Self, DomainError> {
        if provider_network_id == 0 {
            return Err(DomainError::InvalidValue("TCPShield provider network id"));
        }
        Ok(Self {
            pool_id,
            provider_network_id,
            domain_network_id: None,
            backend_set_id: required(backend_set_id, "TCPShield backend set id")?,
        })
    }

    pub fn with_domain_network(mut self, network_id: NetworkId) -> Self {
        self.domain_network_id = Some(network_id);
        self
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ProxyState {
    Preparing,
    Ready,
    Accepting,
    Draining,
    Stopped,
    Failed,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProxyInstance {
    pub id: ProxyInstanceId,
    pub pool_id: ProxyPoolId,
    pub key: String,
    pub state: ProxyState,
}

/// The provider backend address and execution binding are separate from the
/// local proxy instance key. The address is metadata, not a credential.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProxyInstanceBinding {
    pub instance_id: ProxyInstanceId,
    pub gameap_binding_id: BindingId,
    pub backend_address: String,
}
impl ProxyInstanceBinding {
    pub fn new(
        instance_id: ProxyInstanceId,
        gameap_binding_id: BindingId,
        backend_address: &str,
    ) -> Result<Self, DomainError> {
        Ok(Self {
            instance_id,
            gameap_binding_id,
            backend_address: required(backend_address, "proxy backend address")?,
        })
    }
}
impl ProxyInstance {
    pub fn transition(&mut self, next: ProxyState) -> Result<(), DomainError> {
        let ok = matches!(
            (&self.state, &next),
            (ProxyState::Preparing, ProxyState::Ready)
                | (ProxyState::Ready, ProxyState::Accepting)
                | (ProxyState::Accepting, ProxyState::Draining)
                | (ProxyState::Draining, ProxyState::Stopped)
                | (ProxyState::Ready, ProxyState::Failed)
                | (ProxyState::Accepting, ProxyState::Failed)
                | (ProxyState::Draining, ProxyState::Failed)
                | (ProxyState::Failed, ProxyState::Preparing)
        );
        if !ok {
            return Err(DomainError::InvalidTransition {
                from: format!("{:?}", self.state),
                to: format!("{next:?}"),
            });
        }
        self.state = next;
        Ok(())
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Route {
    pub id: RouteId,
    pub key: String,
    pub target_cluster: ClusterId,
    pub priority: u32,
    pub disabled: bool,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Artifact {
    pub id: ArtifactId,
    pub kind: String,
    pub name: String,
    pub version: String,
    pub source: String,
    pub source_id: String,
    pub digest: String,
    pub filename: String,
    pub compatibility: String,
    pub metadata: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ArtifactSet {
    pub id: ArtifactSetId,
    pub artifacts: Vec<ArtifactId>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConfigBaseline {
    pub id: ConfigBaselineId,
    pub digest: String,
    pub files: Vec<ConfigBaselineEntry>,
}
impl ConfigBaseline {
    pub fn new(files: Vec<ConfigBaselineEntry>) -> Result<Self, DomainError> {
        let mut baseline = Self {
            id: ConfigBaselineId::new(),
            digest: String::new(),
            files,
        };
        baseline
            .files
            .sort_by(|left, right| left.path.cmp(&right.path));
        baseline.validate_entries()?;
        baseline.digest = baseline.compute_digest();
        Ok(baseline)
    }

    pub fn compute_digest(&self) -> String {
        baseline_digest(&self.files)
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        self.validate_entries()?;
        if normalize_sha256_digest(&self.digest)? != self.digest {
            return Err(DomainError::InvalidValue(
                "config baseline digest is not normalized",
            ));
        }
        if self.digest != self.compute_digest() {
            return Err(DomainError::InvalidValue("config baseline digest"));
        }
        Ok(())
    }

    fn validate_entries(&self) -> Result<(), DomainError> {
        let mut paths = std::collections::BTreeSet::new();
        for entry in &self.files {
            entry.validate()?;
            if !paths.insert(&entry.path) {
                return Err(DomainError::InvalidValue(
                    "config baseline contains duplicate path",
                ));
            }
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExternalEndpoint {
    pub id: EndpointId,
    pub key: String,
    pub kind: String,
    pub logical_hostname: String,
    pub port: u16,
    pub role: String,
    pub metadata: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EndpointBinding {
    pub id: BindingId,
    pub endpoint_id: EndpointId,
    pub cluster_id: ClusterId,
    pub revision_id: RevisionId,
    /// Stable logical identity of the endpoint role within a revision. The
    /// binding id is immutable storage identity; this key is what lets a
    /// rollout pair the old and new records for the same endpoint role.
    pub binding_key: String,
    /// Provider-neutral metadata for the binding (for example connection
    /// mode). Provider credentials and provider ids do not belong here.
    pub metadata: String,
}
impl EndpointBinding {
    pub fn new(
        endpoint_id: EndpointId,
        cluster_id: ClusterId,
        revision_id: RevisionId,
        binding_key: &str,
    ) -> Result<Self, DomainError> {
        Ok(Self {
            id: BindingId::new(),
            endpoint_id,
            cluster_id,
            revision_id,
            binding_key: required(binding_key, "endpoint binding key")?,
            metadata: String::new(),
        })
    }

    pub fn with_metadata(mut self, metadata: &str) -> Result<Self, DomainError> {
        self.metadata = metadata.to_owned();
        self.validate()?;
        Ok(self)
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        if self.id.as_uuid().is_nil()
            || self.endpoint_id.as_uuid().is_nil()
            || self.cluster_id.as_uuid().is_nil()
            || self.revision_id.as_uuid().is_nil()
        {
            return Err(DomainError::InvalidValue("endpoint binding identity"));
        }
        required(&self.binding_key, "endpoint binding key")?;
        if self.metadata.contains('\0') {
            return Err(DomainError::InvalidValue("endpoint binding metadata"));
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    PlatformAdmin,
    Operator,
    ServiceMaintainer,
    Auditor,
}
/// An explicit action grant.  Roles are an upper bound/convenience label; a
/// role alone never authorizes an action.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Permission {
    ServiceRead,
    LifecycleStart,
    LifecycleStop,
    LifecycleRestart,
    ServiceLifecycle,
    ConsoleRead,
    ConsoleSend,
    FilesRead,
    FilesWrite,
    FilesBatch,
    ArtifactDiscover,
    ArtifactStage,
    ArtifactActivate,
    ProxyRollout,
    BackupCreate,
    BackupRestore,
    WorldRead,
    WorldWrite,
    EndpointRead,
    EndpointWrite,
    ServiceArchive,
    ServicePurge,
    ChangePlan,
    ChangeApprove,
    ChangeApply,
    ChangeVerify,
    ChangeAccept,
    ChangeRollback,
    AuditRead,
    AccessRead,
    AccessManage,
    OperationRead,
}
impl Permission {
    pub const ACTIONS: [Self; 32] = [
        Self::ServiceRead,
        Self::LifecycleStart,
        Self::LifecycleStop,
        Self::LifecycleRestart,
        Self::ServiceLifecycle,
        Self::ConsoleRead,
        Self::ConsoleSend,
        Self::FilesRead,
        Self::FilesWrite,
        Self::FilesBatch,
        Self::ArtifactDiscover,
        Self::ArtifactStage,
        Self::ArtifactActivate,
        Self::ProxyRollout,
        Self::BackupCreate,
        Self::BackupRestore,
        Self::WorldRead,
        Self::WorldWrite,
        Self::EndpointRead,
        Self::EndpointWrite,
        Self::ServiceArchive,
        Self::ServicePurge,
        Self::ChangePlan,
        Self::ChangeApprove,
        Self::ChangeApply,
        Self::ChangeVerify,
        Self::ChangeAccept,
        Self::ChangeRollback,
        Self::AuditRead,
        Self::AccessRead,
        Self::AccessManage,
        Self::OperationRead,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ServiceRead => "service.read",
            Self::LifecycleStart => "lifecycle.start",
            Self::LifecycleStop => "lifecycle.stop",
            Self::LifecycleRestart => "lifecycle.restart",
            Self::ServiceLifecycle => "service.lifecycle",
            Self::ConsoleRead => "console.read",
            Self::ConsoleSend => "console.send",
            Self::FilesRead => "files.read",
            Self::FilesWrite => "files.write",
            Self::FilesBatch => "files.batch",
            Self::ArtifactDiscover => "artifact.discover",
            Self::ArtifactStage => "artifact.stage",
            Self::ArtifactActivate => "artifact.activate",
            Self::ProxyRollout => "proxy.rollout",
            Self::BackupCreate => "backup.create",
            Self::BackupRestore => "backup.restore",
            Self::WorldRead => "world.read",
            Self::WorldWrite => "world.write",
            Self::EndpointRead => "endpoint.read",
            Self::EndpointWrite => "endpoint.write",
            Self::ServiceArchive => "service.archive",
            Self::ServicePurge => "service.purge",
            Self::ChangePlan => "change.plan",
            Self::ChangeApprove => "change.approve",
            Self::ChangeApply => "change.apply",
            Self::ChangeVerify => "change.verify",
            Self::ChangeAccept => "change.accept",
            Self::ChangeRollback => "change.rollback",
            Self::AuditRead => "audit.read",
            Self::AccessRead => "access.read",
            Self::AccessManage => "access.manage",
            Self::OperationRead => "operation.read",
        }
    }

    pub const fn all() -> [Self; 32] {
        Self::ACTIONS
    }

    pub const fn role_allows(self, role: Role) -> bool {
        match role {
            Role::PlatformAdmin => true,
            Role::Operator => !matches!(self, Self::AccessManage | Self::ServicePurge),
            Role::ServiceMaintainer => matches!(
                self,
                Self::ServiceRead
                    | Self::LifecycleStart
                    | Self::LifecycleStop
                    | Self::LifecycleRestart
                    | Self::ServiceLifecycle
                    | Self::ConsoleRead
                    | Self::ConsoleSend
                    | Self::FilesRead
                    | Self::FilesWrite
                    | Self::FilesBatch
                    | Self::ArtifactDiscover
                    | Self::ArtifactStage
                    | Self::ArtifactActivate
                    | Self::ProxyRollout
                    | Self::BackupCreate
                    | Self::BackupRestore
                    | Self::WorldRead
                    | Self::WorldWrite
                    | Self::EndpointRead
                    | Self::EndpointWrite
                    | Self::ChangePlan
                    | Self::ChangeApprove
                    | Self::ChangeApply
                    | Self::ChangeVerify
                    | Self::ChangeAccept
                    | Self::ChangeRollback
                    | Self::OperationRead
            ),
            Role::Auditor => matches!(
                self,
                Self::ServiceRead
                    | Self::ConsoleRead
                    | Self::FilesRead
                    | Self::WorldRead
                    | Self::EndpointRead
                    | Self::AuditRead
                    | Self::AccessRead
                    | Self::OperationRead
            ),
        }
    }

    /// Parse only the public action-level spelling. Coarse call-site names
    /// are deliberately not accepted at an API/storage boundary.
    pub fn parse_action(value: &str) -> Option<Self> {
        Self::ACTIONS
            .into_iter()
            .find(|permission| permission.as_str() == value)
    }

    fn parse_wire(value: &str) -> Option<Self> {
        Self::parse_action(value)
    }
}

impl Serialize for Permission {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Permission {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse_wire(&value)
            .ok_or_else(|| D::Error::custom(format!("unknown permission: {value}")))
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AccessPolicy {
    pub id: PolicyId,
    pub grants: Vec<AccessGrant>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AccessGrant {
    pub actor: ActorId,
    pub role: Role,
    pub service_scope: Option<ServiceId>,
    pub permissions: Vec<Permission>,
}
impl AccessGrant {
    pub fn for_actor(
        actor: ActorId,
        role: Role,
        service_scope: Option<ServiceId>,
        permissions: impl Into<Vec<Permission>>,
    ) -> Self {
        Self {
            actor,
            role,
            service_scope,
            permissions: permissions.into(),
        }
    }

    /// Encode a named group as a stable synthetic principal. Callers should
    /// use `allows_principal` so the same mapping is applied on both sides;
    /// the group name itself is never supplied by JWT.
    pub fn for_group(
        group: &str,
        role: Role,
        service_scope: Option<ServiceId>,
        permissions: impl Into<Vec<Permission>>,
    ) -> Result<Self, DomainError> {
        let group = required(group, "group")?;
        Ok(Self {
            actor: group_actor_id(&group),
            role,
            service_scope,
            permissions: permissions.into(),
        })
    }
}

fn group_actor_id(group: &str) -> ActorId {
    let digest = Sha256::digest(group.as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    // RFC 4122 version/variant bits make the synthetic principal unambiguous
    // when it is stored in a CHAR(36) actor column.
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    ActorId::from_uuid(Uuid::from_bytes(bytes))
}
impl AccessPolicy {
    /// Whether this policy contributes at least one platform administrator to
    /// the account-wide administrator invariant. A role is counted here even
    /// before action authorization, because removing the final administrative
    /// principal must never lock the account out.
    pub fn has_platform_admin(&self) -> bool {
        self.grants
            .iter()
            .any(|grant| grant.role == Role::PlatformAdmin)
    }

    /// Whether this policy contributes any principal to the account-wide
    /// access invariant.
    pub fn has_access_grant(&self) -> bool {
        !self.grants.is_empty()
    }

    /// Replace grants while preserving a policy-local last-admin/access
    /// invariant. Storage adapters additionally check the other policies so
    /// the account-wide invariant remains true under concurrent updates.
    pub fn replace_grants(&mut self, grants: Vec<AccessGrant>) -> Result<(), DomainError> {
        if self.has_platform_admin()
            && !grants.iter().any(|grant| grant.role == Role::PlatformAdmin)
        {
            return Err(DomainError::LastPlatformAdministrator);
        }
        if self.has_access_grant() && grants.is_empty() {
            return Err(DomainError::LastAccessGrant);
        }
        self.grants = grants;
        Ok(())
    }

    pub fn allows(&self, actor: ActorId, service: ServiceId, permission: Permission) -> bool {
        self.grants.iter().any(|g| {
            g.actor == actor
                // Role is only an upper bound. Every action grant must carry
                // an explicit service scope, including platform administrators.
                && g.service_scope == Some(service)
                && g.permissions.contains(&permission)
                && permission.role_allows(g.role)
        })
    }

    pub fn allows_principal(
        &self,
        principal: &AccessPrincipal,
        service: ServiceId,
        permission: Permission,
    ) -> bool {
        let actor = match principal {
            AccessPrincipal::Actor(actor) => *actor,
            AccessPrincipal::Group(group) if !group.trim().is_empty() => group_actor_id(group),
            AccessPrincipal::Group(_) => return false,
        };
        self.allows(actor, service, permission)
    }

    /// Check the object scope resolved by the adapter and the action grant in
    /// one operation. A global object is only valid when the owning service is
    /// still supplied, preventing an unscoped action lookup.
    pub fn allows_object(
        &self,
        principal: &AccessPrincipal,
        service: ServiceId,
        object: AccessScope,
        permission: Permission,
    ) -> bool {
        let scoped = match object {
            AccessScope::Global => true,
            AccessScope::Service(id) => id == service,
            AccessScope::Network(_)
            | AccessScope::Cluster(_)
            | AccessScope::Revision(_)
            | AccessScope::World(_)
            | AccessScope::ProxyPool(_)
            | AccessScope::ProxyInstance(_)
            | AccessScope::Route(_)
            | AccessScope::RuntimeProfile(_)
            | AccessScope::Artifact(_)
            | AccessScope::ArtifactSet(_)
            | AccessScope::ConfigBaseline(_)
            | AccessScope::Endpoint(_)
            | AccessScope::Binding(_)
            | AccessScope::ChangeSession(_)
            | AccessScope::Operation(_)
            | AccessScope::Backup(_) => true,
        };
        scoped && self.allows_principal(principal, service, permission)
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ChangeSessionState {
    Open,
    Editing,
    Ready,
    Applying,
    Verifying,
    Accepted,
    RolledBack,
    Aborted,
    Conflicted,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ChangeSession {
    pub id: ChangeSessionId,
    pub target_cluster: ClusterId,
    pub state: ChangeSessionState,
    /// Monotonic persisted version used as the session edit token.  It is
    /// incremented for every state transition and must be compared by the
    /// API before a plan is created.
    pub version: u64,
}
impl ChangeSession {
    pub fn is_active(&self) -> bool {
        !matches!(
            self.state,
            ChangeSessionState::Accepted
                | ChangeSessionState::RolledBack
                | ChangeSessionState::Aborted
                | ChangeSessionState::Conflicted
        )
    }

    pub fn transition(&mut self, next: ChangeSessionState) -> Result<(), DomainError> {
        let ok = matches!(
            (&self.state, &next),
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
        if !ok {
            return Err(DomainError::InvalidTransition {
                from: format!("{:?}", self.state),
                to: format!("{next:?}"),
            });
        }
        self.state = next;
        self.version = self.version.saturating_add(1);
        Ok(())
    }
}

/// Connection metadata for an out-of-band SFTP observation. Kitsunebi does
/// not implement an SFTP server and this type deliberately contains no
/// password, private key, or other credential value.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SftpEndpointMetadata {
    pub id: SftpEndpointId,
    pub service_id: ServiceId,
    pub execution_binding_id: BindingId,
    pub host: String,
    pub port: u16,
    pub root: String,
    pub provisioning_owned: bool,
}
impl SftpEndpointMetadata {
    pub fn new(
        service_id: ServiceId,
        execution_binding_id: BindingId,
        host: &str,
        port: u16,
        root: &str,
    ) -> Result<Self, DomainError> {
        let host = required(host, "sftp host")?;
        let root = required(root, "sftp root")?;
        if port == 0 {
            return Err(DomainError::InvalidValue("sftp port"));
        }
        if !root.starts_with('/') || root.contains('\0') {
            return Err(DomainError::InvalidValue("sftp root"));
        }
        Ok(Self {
            id: SftpEndpointId::new(),
            service_id,
            execution_binding_id,
            host,
            port,
            root,
            provisioning_owned: true,
        })
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        if self.host.trim().is_empty()
            || self.host.contains('\0')
            || self.port == 0
            || !self.root.starts_with('/')
            || self.root.contains('\0')
        {
            return Err(DomainError::InvalidValue("sftp endpoint metadata"));
        }
        if !self.provisioning_owned {
            return Err(DomainError::InvalidValue("sftp endpoint ownership"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SftpScanSource {
    OutOfBand,
    Provisioning,
    Operator,
}
impl SftpScanSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OutOfBand => "out_of_band",
            Self::Provisioning => "provisioning",
            Self::Operator => "operator",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SftpChangeKind {
    Added,
    Modified,
    Removed,
}

/// Metadata-only description of a changed path. There is intentionally no
/// content field: secret bytes and arbitrary file payloads must not enter the
/// metadata database.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SftpChangedPath {
    pub path: String,
    pub kind: SftpChangeKind,
    pub before_digest: Option<String>,
    pub after_digest: Option<String>,
    pub classification: FileClassification,
}
impl SftpChangedPath {
    pub fn new(
        path: &str,
        kind: SftpChangeKind,
        before_digest: Option<&str>,
        after_digest: Option<&str>,
        classification: FileClassification,
    ) -> Result<Self, DomainError> {
        let path = normalize_relative_path(path)?;
        let before_digest = before_digest.map(normalize_sha256_digest).transpose()?;
        let after_digest = after_digest.map(normalize_sha256_digest).transpose()?;
        match kind {
            SftpChangeKind::Added if before_digest.is_some() || after_digest.is_none() => {
                return Err(DomainError::InvalidValue("sftp added path digest"));
            }
            SftpChangeKind::Modified if before_digest.is_none() || after_digest.is_none() => {
                return Err(DomainError::InvalidValue("sftp modified path digest"));
            }
            SftpChangeKind::Removed if before_digest.is_none() || after_digest.is_some() => {
                return Err(DomainError::InvalidValue("sftp removed path digest"));
            }
            _ => {}
        }
        if matches!(kind, SftpChangeKind::Removed)
            && matches!(
                classification,
                FileClassification::Unknown | FileClassification::State
            )
        {
            return Err(DomainError::ProtectedFileRemoval);
        }
        Ok(Self {
            path,
            kind,
            before_digest,
            after_digest,
            classification,
        })
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        if normalize_relative_path(&self.path)? != self.path {
            return Err(DomainError::InvalidValue("sftp path is not normalized"));
        }
        let before = self
            .before_digest
            .as_deref()
            .map(normalize_sha256_digest)
            .transpose()?;
        let after = self
            .after_digest
            .as_deref()
            .map(normalize_sha256_digest)
            .transpose()?;
        match self.kind {
            SftpChangeKind::Added if before.is_some() || after.is_none() => {
                return Err(DomainError::InvalidValue("sftp added path digest"));
            }
            SftpChangeKind::Modified if before.is_none() || after.is_none() => {
                return Err(DomainError::InvalidValue("sftp modified path digest"));
            }
            SftpChangeKind::Removed if before.is_none() || after.is_some() => {
                return Err(DomainError::InvalidValue("sftp removed path digest"));
            }
            _ => {}
        }
        if matches!(self.kind, SftpChangeKind::Removed)
            && matches!(
                self.classification,
                FileClassification::Unknown | FileClassification::State
            )
        {
            return Err(DomainError::ProtectedFileRemoval);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SftpScan {
    pub id: SftpScanId,
    pub endpoint_id: SftpEndpointId,
    pub service_id: ServiceId,
    pub execution_binding_id: BindingId,
    pub session_id: ChangeSessionId,
    pub before_manifest_hash: String,
    pub after_manifest_hash: String,
    pub changed_paths: Vec<SftpChangedPath>,
    pub observed_at: u64,
    pub source: SftpScanSource,
    pub idempotency_key: String,
    pub request_hash: String,
}
impl SftpScan {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        endpoint: &SftpEndpointMetadata,
        binding: &GameAPBinding,
        session: &ChangeSession,
        before_manifest_hash: &str,
        after_manifest_hash: &str,
        changed_paths: Vec<SftpChangedPath>,
        observed_at: u64,
        source: SftpScanSource,
        idempotency_key: &str,
        request_hash: &str,
    ) -> Result<Self, DomainError> {
        endpoint.validate()?;
        if !session.is_active() {
            return Err(DomainError::InactiveChangeSession);
        }
        if binding.execution_unit_id.trim().is_empty() || binding.node_id.trim().is_empty() {
            return Err(DomainError::InvalidValue("sftp execution binding"));
        }
        let before_manifest_hash = normalize_sha256_digest(before_manifest_hash)?;
        let after_manifest_hash = normalize_sha256_digest(after_manifest_hash)?;
        let idempotency_key = required(idempotency_key, "sftp scan idempotency key")?;
        let request_hash = normalize_sha256_digest(request_hash)?;
        let mut paths = changed_paths;
        paths.sort_by(|left, right| left.path.cmp(&right.path));
        for path in &paths {
            path.validate()?;
        }
        for pair in paths.windows(2) {
            if pair[0].path == pair[1].path {
                return Err(DomainError::InvalidValue("duplicate sftp scan path"));
            }
        }
        Ok(Self {
            id: SftpScanId::new(),
            endpoint_id: endpoint.id,
            service_id: endpoint.service_id,
            execution_binding_id: endpoint.execution_binding_id,
            session_id: session.id,
            before_manifest_hash,
            after_manifest_hash,
            changed_paths: paths,
            observed_at,
            source,
            idempotency_key,
            request_hash,
        })
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        normalize_sha256_digest(&self.before_manifest_hash)?;
        normalize_sha256_digest(&self.after_manifest_hash)?;
        normalize_sha256_digest(&self.request_hash)?;
        required(&self.idempotency_key, "sftp scan idempotency key")?;
        for pair in self.changed_paths.windows(2) {
            if pair[0].path >= pair[1].path {
                return Err(DomainError::InvalidValue("sftp scan paths are not sorted"));
            }
        }
        for path in &self.changed_paths {
            path.validate()?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ServiceTombstone {
    pub id: ServiceTombstoneId,
    pub service_id: ServiceId,
    pub service_key: String,
    pub archived_at: u64,
}
impl ServiceTombstone {
    pub fn new(
        service_id: ServiceId,
        service_key: &str,
        archived_at: u64,
    ) -> Result<Self, DomainError> {
        Ok(Self {
            id: ServiceTombstoneId::new(),
            service_id,
            service_key: required(service_key, "service tombstone key")?,
            archived_at,
        })
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum OperationState {
    Planned,
    Applying,
    Verifying,
    Verified,
    Accepted,
    RolledBack,
    Failed,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Operation {
    pub id: OperationId,
    pub plan_id: PlanId,
    pub session_id: ChangeSessionId,
    pub state: OperationState,
}
impl Operation {
    pub fn transition(&mut self, next: OperationState) -> Result<(), DomainError> {
        let valid = matches!(
            (&self.state, &next),
            (OperationState::Planned, OperationState::Applying)
                | (OperationState::Applying, OperationState::Verifying)
                | (OperationState::Verifying, OperationState::Verified)
                | (OperationState::Verified, OperationState::Accepted)
                | (OperationState::Applying, OperationState::Failed)
                | (OperationState::Verifying, OperationState::Failed)
                | (OperationState::Verified, OperationState::Failed)
                // A failed operation is terminal for automatic execution,
                // but may be explicitly compensated when durable inverse
                // evidence is available to the application layer.
                | (OperationState::Failed, OperationState::RolledBack)
                | (OperationState::Applying, OperationState::RolledBack)
                | (OperationState::Verifying, OperationState::RolledBack)
                | (OperationState::Verified, OperationState::RolledBack)
        );
        if !valid {
            return Err(DomainError::InvalidTransition {
                from: format!("{:?}", self.state),
                to: format!("{next:?}"),
            });
        }
        self.state = next;
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BackupKind {
    ChangeSnapshot,
    World,
    ServiceConsistent,
    ExternalDatabaseReference,
}
impl BackupKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ChangeSnapshot => "change-snapshot",
            Self::World => "world",
            Self::ServiceConsistent => "service-consistent",
            Self::ExternalDatabaseReference => "external-database-reference",
        }
    }

    pub fn parse(value: &str) -> Result<Self, DomainError> {
        match value {
            "change-snapshot" => Ok(Self::ChangeSnapshot),
            "world" => Ok(Self::World),
            "service-consistent" => Ok(Self::ServiceConsistent),
            "external-database-reference" => Ok(Self::ExternalDatabaseReference),
            _ => Err(DomainError::InvalidValue("backup kind")),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum BackupTarget {
    Service(ServiceId),
    Cluster(ClusterId),
    World(WorldId),
    ExecutionUnit(BindingId),
}

/// A provider-generated backup reference. The provider reference is opaque;
/// the domain only accepts it after the provider has returned a verified
/// manifest digest. It is always attached to the explicit change session that
/// requested the backup.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BackupReference {
    pub id: BackupReferenceId,
    pub session_id: ChangeSessionId,
    pub kind: BackupKind,
    pub target: BackupTarget,
    /// Provider identity returned by the backup provider, never plan input.
    pub provider: String,
    pub provider_reference: String,
    pub manifest_digest: String,
    pub verified_at: Option<u64>,
    pub required: bool,
}
impl BackupReference {
    pub fn validate_unverified(&self) -> Result<(), DomainError> {
        required(&self.provider, "backup provider")?;
        required(&self.provider_reference, "backup provider reference")?;
        normalize_sha256_digest(&self.manifest_digest)?;
        Ok(())
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        self.validate_unverified()?;
        if self.verified_at.is_none() {
            return Err(DomainError::InvalidValue("backup is not verified"));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BackupObservation {
    pub manifest_digest: String,
    pub observed_at: u64,
}
impl BackupObservation {
    pub fn new(manifest_digest: &str, observed_at: u64) -> Result<Self, DomainError> {
        Ok(Self {
            manifest_digest: normalize_sha256_digest(manifest_digest)?,
            observed_at,
        })
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BackupRequirements {
    pub required: bool,
    pub references: Vec<BackupReferenceId>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum LifecycleDecision {
    Start,
    Stop,
    Restart,
    Drain,
    Accept,
    Rollback,
    NoAction,
}

/// Stopped on-demand work is intentional, and is therefore not a failure.
pub fn evaluate_availability(availability: &Availability, running: bool) -> LifecycleDecision {
    match (availability, running) {
        (Availability::OnDemand, false) | (Availability::Disabled, false) => {
            LifecycleDecision::NoAction
        }
        (Availability::OnDemand, true) | (Availability::Disabled, true) => LifecycleDecision::Stop,
        (_, true) => LifecycleDecision::Accept,
        (_, false) => LifecycleDecision::Start,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn on_demand_stopped_is_no_action() {
        assert_eq!(
            evaluate_availability(&Availability::OnDemand, false),
            LifecycleDecision::NoAction
        );
        assert_eq!(
            evaluate_availability(&Availability::AlwaysOn, false),
            LifecycleDecision::Start
        );
    }

    #[test]
    fn lifecycle_supports_maintenance_sunset_archive_but_not_purge_state() {
        let mut service = Service::new(
            "s",
            "S",
            Ownership::FirstParty,
            Audience::Public,
            OperatorModel::Central,
            TrustProfile::Trusted,
        )
        .unwrap();
        service.transition(ServiceLifecycle::Testing).unwrap();
        service.transition(ServiceLifecycle::Active).unwrap();
        service.transition(ServiceLifecycle::Maintenance).unwrap();
        service.transition(ServiceLifecycle::Sunsetting).unwrap();
        service.transition(ServiceLifecycle::Archived).unwrap();
    }

    #[test]
    fn single_writer_rejects_second_cluster() {
        let mut world = World::new(
            "w",
            "W",
            WorldWriteMode::SingleWriter,
            WorldExecutionModel::SingleProcess,
        )
        .unwrap();
        let first = ClusterId::new();
        world.assign_writer(first).unwrap();
        assert_eq!(
            world.assign_writer(ClusterId::new()),
            Err(DomainError::MultipleWritersNotAllowed)
        );
    }

    #[test]
    fn externally_coordinated_world_allows_multiple_writers() {
        let mut world = World::new(
            "w-external",
            "External",
            WorldWriteMode::ExternallyCoordinated,
            WorldExecutionModel::PartitionedWorld,
        )
        .unwrap();
        let first = ClusterId::new();
        let second = ClusterId::new();
        world.assign_writer(first).unwrap();
        world.assign_writer(second).unwrap();
        assert_eq!(world.current_writers, vec![first, second]);
    }

    #[test]
    fn plan_hash_is_canonical_and_detects_changes() {
        let actor = ActorId::new();
        let binding = GameAPBinding {
            execution_unit_id: "unit".into(),
            node_id: "node".into(),
            target: GameAPBindingTarget::ExecutionUnit("opaque".into()),
        };
        let binding_id = BindingId::new();
        let binding_hash = binding.fingerprint();
        let mut plan = PlanDescriptor::new(
            actor,
            PlanTarget::Cluster(ClusterId::new()),
            4,
            99,
            vec![
                PlanStep::new(PlanStepAction::ExecutionLifecycle {
                    binding_id,
                    action: ExecutionLifecycleAction::Restart,
                    expected_binding_hash: binding_hash.clone(),
                    expected_state_hash: "a".repeat(64),
                    domain_revision: 4,
                })
                .unwrap(),
            ],
        )
        .unwrap();
        assert_eq!(plan.plan_hash, plan.compute_hash());
        plan.steps.push(
            PlanStep::new(PlanStepAction::ExecutionLifecycle {
                binding_id,
                action: ExecutionLifecycleAction::Start,
                expected_binding_hash: binding_hash,
                expected_state_hash: "b".repeat(64),
                domain_revision: 4,
            })
            .unwrap(),
        );
        assert_ne!(plan.plan_hash, plan.compute_hash());
    }

    #[test]
    fn proxy_and_change_transitions_reject_skips() {
        let pool = ProxyPoolId::new();
        let mut proxy = ProxyInstance {
            id: ProxyInstanceId::new(),
            pool_id: pool,
            key: "p".into(),
            state: ProxyState::Preparing,
        };
        assert_eq!(
            proxy.transition(ProxyState::Accepting),
            Err(DomainError::InvalidTransition {
                from: "Preparing".into(),
                to: "Accepting".into()
            })
        );
        let mut session = ChangeSession {
            id: ChangeSessionId::new(),
            target_cluster: ClusterId::new(),
            state: ChangeSessionState::Open,
            version: 1,
        };
        assert_eq!(
            session.transition(ChangeSessionState::Accepted),
            Err(DomainError::InvalidTransition {
                from: "Open".into(),
                to: "Accepted".into()
            })
        );
    }

    #[test]
    fn operation_acceptance_requires_durable_verification_state() {
        let mut operation = Operation {
            id: OperationId::new(),
            plan_id: PlanId::new(),
            session_id: ChangeSessionId::new(),
            state: OperationState::Verifying,
        };
        assert!(operation.transition(OperationState::Accepted).is_err());
        operation.transition(OperationState::Verified).unwrap();
        operation.transition(OperationState::Accepted).unwrap();
    }

    #[test]
    fn failed_operation_can_only_finish_by_explicit_rollback() {
        let mut operation = Operation {
            id: OperationId::new(),
            plan_id: PlanId::new(),
            session_id: ChangeSessionId::new(),
            state: OperationState::Failed,
        };
        assert!(operation.transition(OperationState::Applying).is_err());
        operation.transition(OperationState::RolledBack).unwrap();
    }

    #[test]
    fn access_is_service_scoped() {
        let actor = ActorId::new();
        let service = ServiceId::new();
        let other = ServiceId::new();
        let policy = AccessPolicy {
            id: PolicyId::new(),
            grants: vec![AccessGrant {
                actor,
                role: Role::ServiceMaintainer,
                service_scope: Some(service),
                permissions: vec![Permission::ChangeApply],
            }],
        };
        assert!(policy.allows(actor, service, Permission::ChangeApply));
        assert!(!policy.allows(actor, other, Permission::ChangeApply));
    }

    #[test]
    fn change_apply_does_not_expand_to_dangerous_actions() {
        let actor = ActorId::new();
        let service = ServiceId::new();
        let policy = AccessPolicy {
            id: PolicyId::new(),
            grants: vec![AccessGrant::for_actor(
                actor,
                Role::Operator,
                Some(service),
                vec![Permission::ChangeApply],
            )],
        };
        assert!(!policy.allows(actor, service, Permission::ConsoleRead));
        assert!(!policy.allows(actor, service, Permission::ProxyRollout));
        assert!(!policy.allows(actor, service, Permission::ArtifactActivate));
        assert!(!policy.allows(actor, service, Permission::BackupRestore));
    }

    #[test]
    fn action_grant_and_object_scope_are_required() {
        let actor = ActorId::new();
        let service = ServiceId::new();
        let cluster = ClusterId::new();
        let policy = AccessPolicy {
            id: PolicyId::new(),
            grants: vec![AccessGrant::for_actor(
                actor,
                Role::ServiceMaintainer,
                Some(service),
                vec![Permission::ProxyRollout],
            )],
        };
        assert!(policy.allows_object(
            &AccessPrincipal::Actor(actor),
            service,
            AccessScope::Cluster(cluster),
            Permission::ProxyRollout
        ));
        assert!(!policy.allows_object(
            &AccessPrincipal::Actor(actor),
            ServiceId::new(),
            AccessScope::Cluster(cluster),
            Permission::ProxyRollout
        ));
    }

    #[test]
    fn group_principal_uses_same_explicit_action_and_scope() {
        let service = ServiceId::new();
        let grant = AccessGrant::for_group(
            "operators",
            Role::Operator,
            Some(service),
            vec![Permission::ConsoleRead],
        )
        .unwrap();
        let policy = AccessPolicy {
            id: PolicyId::new(),
            grants: vec![grant],
        };
        assert!(policy.allows_principal(
            &AccessPrincipal::Group("operators".into()),
            service,
            Permission::ConsoleRead
        ));
        assert!(!policy.allows_principal(
            &AccessPrincipal::Group("operators".into()),
            service,
            Permission::ConsoleSend
        ));
    }

    #[test]
    fn access_policy_keeps_last_admin_and_access_grants() {
        let actor = ActorId::new();
        let service = ServiceId::new();
        let mut policy = AccessPolicy {
            id: PolicyId::new(),
            grants: vec![AccessGrant::for_actor(
                actor,
                Role::PlatformAdmin,
                Some(service),
                vec![Permission::AccessManage],
            )],
        };
        assert_eq!(
            policy.replace_grants(Vec::new()),
            Err(DomainError::LastPlatformAdministrator)
        );
        assert_eq!(
            policy.replace_grants(vec![AccessGrant::for_actor(
                actor,
                Role::Operator,
                Some(service),
                vec![Permission::ServiceRead],
            )]),
            Err(DomainError::LastPlatformAdministrator)
        );
        let mut access_only = AccessPolicy {
            id: PolicyId::new(),
            grants: vec![AccessGrant::for_actor(
                actor,
                Role::Operator,
                Some(service),
                vec![Permission::ServiceRead],
            )],
        };
        assert_eq!(
            access_only.replace_grants(Vec::new()),
            Err(DomainError::LastAccessGrant)
        );
    }

    #[test]
    fn access_policy_plan_rejects_unscoped_or_cross_service_grants() {
        let actor = ActorId::new();
        let service = ServiceId::new();
        let other_service = ServiceId::new();
        let base = |service_scope| PlanStepAction::AccessPolicyUpdate {
            policy_id: PolicyId::new(),
            service_id: service,
            expected_version: 1,
            desired_grants: vec![AccessGrant::for_actor(
                actor,
                Role::Operator,
                service_scope,
                vec![Permission::ServiceRead],
            )],
            desired_policy_hash: "a".repeat(64),
        };

        assert!(PlanStep::new(base(Some(service))).is_ok());
        assert_eq!(
            PlanStep::new(base(None)),
            Err(DomainError::InvalidValue(
                "plan access grants must target the plan service"
            ))
        );
        assert_eq!(
            PlanStep::new(base(Some(other_service))),
            Err(DomainError::InvalidValue(
                "plan access grants must target the plan service"
            ))
        );
    }

    #[test]
    fn unknown_action_spelling_is_rejected() {
        assert!(Permission::parse_action("apply").is_none());
        assert!(serde_json::from_str::<Permission>("\"not-a-permission\"").is_err());
        assert_eq!(
            serde_json::to_string(&Permission::ConsoleSend).unwrap(),
            "\"console.send\""
        );
        assert_eq!(
            serde_json::from_str::<Permission>("\"console.send\"").unwrap(),
            Permission::ConsoleSend
        );
        assert!(serde_json::from_str::<Permission>("\"console_send\"").is_err());
    }

    #[test]
    fn audit_scope_is_typed_and_rejects_blank_execution_reference() {
        let service = ServiceId::new();
        let cluster = ClusterId::new();
        let world = WorldId::new();
        let operation = OperationId::new();
        let scope = AuditScope::for_execution_unit(service, "unit-1")
            .unwrap()
            .with_cluster(cluster)
            .with_world(world)
            .with_operation(operation);
        assert_eq!(scope.service_id, service);
        assert_eq!(scope.cluster_id, Some(cluster));
        assert_eq!(scope.world_id, Some(world));
        assert_eq!(scope.operation_id, Some(operation));
        assert_eq!(scope.execution_unit_ref.as_deref(), Some("unit-1"));
        assert_eq!(scope.validate(), Ok(()));

        assert_eq!(
            AuditScope::for_execution_unit(service, "  "),
            Err(DomainError::InvalidValue("audit execution unit ref"))
        );
    }

    #[test]
    fn config_baseline_manifest_normalizes_and_validates_entries() {
        let digest = "A".repeat(64);
        let entry = ConfigBaselineEntry::new(
            "./config\\server.properties",
            &digest,
            FileClassification::Secret,
        )
        .unwrap();
        assert_eq!(entry.path, "config/server.properties");
        assert_eq!(entry.digest, digest.to_ascii_lowercase());

        let baseline = ConfigBaseline::new(vec![entry.clone()]).unwrap();
        assert_eq!(baseline.digest, baseline.compute_digest());
        assert_eq!(baseline.validate(), Ok(()));
        assert_eq!(baseline.files[0].classification, FileClassification::Secret);
        let second = ConfigBaselineEntry::new(
            "config/other.properties",
            &"b".repeat(64),
            FileClassification::Managed,
        )
        .unwrap();
        let forward = ConfigBaseline::new(vec![entry.clone(), second.clone()]).unwrap();
        let reverse = ConfigBaseline::new(vec![second, entry.clone()]).unwrap();
        assert_eq!(forward.digest, reverse.digest);
        let encoded = serde_json::to_value(&forward).unwrap();
        assert_eq!(
            serde_json::from_value::<ConfigBaseline>(encoded).unwrap(),
            forward
        );

        assert!(
            ConfigBaselineEntry::new(
                "../config/server.properties",
                &digest,
                FileClassification::Managed,
            )
            .is_err()
        );
        assert!(
            ConfigBaselineEntry::new(
                "config/server.properties",
                "not-a-sha256",
                FileClassification::Managed,
            )
            .is_err()
        );
        assert!(ConfigBaseline::new(vec![entry.clone(), entry]).is_err());
    }

    #[test]
    fn audit_event_validates_scope_and_optional_metadata() {
        let service = ServiceId::new();
        let event = AuditEvent {
            actor: ActorId::new(),
            action: "change.plan".into(),
            target: "cluster".into(),
            classification: FileClassification::Managed,
            scope: AuditScope::for_service(service),
            source: AuditSource::Application,
            result: AuditResult::Success,
            before_revision: Some(2),
            after_revision: Some(3),
            plan_hash: Some("hash".into()),
            request_id: Some("request".into()),
            evidence: vec![],
        };
        assert_eq!(event.validate(), Ok(()));
        let mut invalid = event;
        invalid.request_id = Some(" ".into());
        assert_eq!(
            invalid.validate(),
            Err(DomainError::InvalidValue("audit request id"))
        );
    }

    #[test]
    fn placement_is_typed_and_unknown_observations_fail_closed() {
        let requirements =
            PlacementRequirements::new(vec![ProcessManager::Docker], vec!["console".into()])
                .unwrap();
        let observation = NodeCapabilityObservation::new(
            "node-a",
            ProcessManager::Docker,
            Some("25".into()),
            vec!["console".into()],
            &"a".repeat(64),
            10,
        )
        .unwrap();
        assert!(requirements.accepts(&observation));
        let unknown = NodeCapabilityObservation::new(
            "node-a",
            ProcessManager::Unknown,
            None,
            vec!["console".into()],
            &"b".repeat(64),
            11,
        )
        .unwrap();
        assert!(!requirements.accepts(&unknown));
        assert!(PlacementRequirements::new(vec![ProcessManager::Unknown], vec![]).is_err());

        let revision = ClusterRevision::new(
            1,
            RuntimeProfileId::new(),
            "1.21",
            ArtifactSetId::new(),
            ConfigBaselineId::new(),
        )
        .unwrap()
        .with_placement_requirements(requirements.clone())
        .unwrap();
        assert_eq!(revision.placement_requirements, requirements);
        assert_eq!(
            revision.typed_placement_requirements().unwrap(),
            requirements
        );
    }

    #[test]
    fn sftp_scan_is_metadata_only_and_protects_unknown_state_removals() {
        let service = ServiceId::new();
        let binding_id = BindingId::new();
        let endpoint =
            SftpEndpointMetadata::new(service, binding_id, "sftp.example", 22, "/srv/game")
                .unwrap();
        let session = ChangeSession {
            id: ChangeSessionId::new(),
            target_cluster: ClusterId::new(),
            state: ChangeSessionState::Editing,
            version: 1,
        };
        let binding = GameAPBinding {
            execution_unit_id: "opaque-unit".into(),
            node_id: "opaque-node".into(),
            target: GameAPBindingTarget::Cluster(session.target_cluster),
        };
        let changed = SftpChangedPath::new(
            "secrets/token",
            SftpChangeKind::Modified,
            Some(&"a".repeat(64)),
            Some(&"b".repeat(64)),
            FileClassification::Secret,
        )
        .unwrap();
        let scan = SftpScan::new(
            &endpoint,
            &binding,
            &session,
            &"c".repeat(64),
            &"d".repeat(64),
            vec![changed],
            20,
            SftpScanSource::OutOfBand,
            "scan-1",
            &"e".repeat(64),
        )
        .unwrap();
        let encoded = serde_json::to_string(&scan).unwrap();
        assert!(!encoded.contains("secret-content"));
        assert!(
            SftpChangedPath::new(
                "state/world",
                SftpChangeKind::Removed,
                Some(&"a".repeat(64)),
                None,
                FileClassification::State,
            )
            .is_err()
        );
        assert!(
            SftpChangedPath::new(
                "unknown",
                SftpChangeKind::Removed,
                Some(&"a".repeat(64)),
                None,
                FileClassification::Unknown,
            )
            .is_err()
        );
        let mut closed = session;
        closed.state = ChangeSessionState::Accepted;
        assert!(
            SftpScan::new(
                &endpoint,
                &binding,
                &closed,
                &"c".repeat(64),
                &"d".repeat(64),
                vec![],
                20,
                SftpScanSource::OutOfBand,
                "scan-2",
                &"e".repeat(64),
            )
            .is_err()
        );
    }

    #[test]
    fn tcp_shield_provider_network_is_not_domain_network() {
        let pool = ProxyPoolId::new();
        let provider = TcpShieldBackendSet::new(pool, 42, "backend-set").unwrap();
        assert_eq!(provider.provider_network_id, 42);
        assert_eq!(provider.domain_network_id, None);
        let mapped = provider.with_domain_network(NetworkId::new());
        assert!(mapped.domain_network_id.is_some());
        assert!(TcpShieldBackendSet::new(pool, 0, "backend-set").is_err());
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum GameAPBindingTarget {
    Service(ServiceId),
    Cluster(ClusterId),
    ExecutionUnit(String),
    World(WorldId),
    ProxyInstance(ProxyInstanceId),
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GameAPBinding {
    pub execution_unit_id: String,
    pub node_id: String,
    pub target: GameAPBindingTarget,
}
impl GameAPBinding {
    /// Stable digest of the persisted provider binding. The digest is used in
    /// a plan as a re-resolution guard; provider identifiers remain opaque to
    /// the domain and are never accepted as plan input.
    pub fn fingerprint(&self) -> String {
        fn field(out: &mut Vec<u8>, value: &str) {
            let length = u64::try_from(value.len()).unwrap_or(u64::MAX);
            out.extend_from_slice(&length.to_be_bytes());
            out.extend_from_slice(value.as_bytes());
        }
        let target = match &self.target {
            GameAPBindingTarget::Service(id) => format!("service:{}", id.as_uuid()),
            GameAPBindingTarget::Cluster(id) => format!("cluster:{}", id.as_uuid()),
            GameAPBindingTarget::ExecutionUnit(id) => format!("execution_unit:{id}"),
            GameAPBindingTarget::World(id) => format!("world:{}", id.as_uuid()),
            GameAPBindingTarget::ProxyInstance(id) => format!("proxy_instance:{}", id.as_uuid()),
        };
        let mut bytes = Vec::new();
        field(&mut bytes, &self.execution_unit_id);
        field(&mut bytes, &self.node_id);
        field(&mut bytes, &target);
        let mut hash = Sha256::new();
        hash.update(bytes);
        format!("{:x}", hash.finalize())
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum FileClassification {
    Managed,
    MutableConfig,
    Artifact,
    Generated,
    State,
    Secret,
    Unknown,
}

impl FileClassification {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Managed => "managed",
            Self::MutableConfig => "mutable_config",
            Self::Artifact => "artifact",
            Self::Generated => "generated",
            Self::State => "state",
            Self::Secret => "secret",
            Self::Unknown => "unknown",
        }
    }
}

/// One content-addressed entry in a configuration baseline. The baseline
/// deliberately contains metadata only: file contents, especially secrets,
/// are never part of this manifest.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConfigBaselineEntry {
    pub path: String,
    pub digest: String,
    pub classification: FileClassification,
}
impl ConfigBaselineEntry {
    pub fn new(
        path: &str,
        digest: &str,
        classification: FileClassification,
    ) -> Result<Self, DomainError> {
        let entry = Self {
            path: normalize_relative_path(path)?,
            digest: normalize_sha256_digest(digest)?,
            classification,
        };
        entry.validate()?;
        Ok(entry)
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        if normalize_relative_path(&self.path)? != self.path {
            return Err(DomainError::InvalidValue(
                "config baseline path is not normalized",
            ));
        }
        if normalize_sha256_digest(&self.digest)? != self.digest {
            return Err(DomainError::InvalidValue(
                "config baseline digest is not normalized",
            ));
        }
        Ok(())
    }
}

fn normalize_relative_path(path: &str) -> Result<String, DomainError> {
    let path = path.trim().replace('\\', "/");
    if path.is_empty()
        || path.starts_with('/')
        || path.as_bytes().get(1).is_some_and(|value| *value == b':')
    {
        return Err(DomainError::InvalidValue("config baseline path"));
    }
    let mut components = Vec::new();
    for component in path.split('/') {
        match component {
            "" | "." => {}
            ".." => return Err(DomainError::InvalidValue("config baseline path")),
            value if value.contains('\0') => {
                return Err(DomainError::InvalidValue("config baseline path"));
            }
            value => components.push(value),
        }
    }
    if components.is_empty() {
        return Err(DomainError::InvalidValue("config baseline path"));
    }
    Ok(components.join("/"))
}

fn normalize_sha256_digest(digest: &str) -> Result<String, DomainError> {
    let digest = digest.trim();
    if digest.len() != 64 || !digest.bytes().all(|value| value.is_ascii_hexdigit()) {
        return Err(DomainError::InvalidValue("config baseline sha256 digest"));
    }
    Ok(digest.to_ascii_lowercase())
}

fn baseline_digest(entries: &[ConfigBaselineEntry]) -> String {
    let mut entries = entries.to_vec();
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    let mut bytes = Vec::new();
    for entry in entries {
        for value in [
            entry.path,
            entry.digest,
            entry.classification.as_str().to_owned(),
        ] {
            bytes.extend_from_slice(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
            bytes.extend_from_slice(value.as_bytes());
        }
    }
    format!("{:x}", Sha256::digest(bytes))
}

/// Typed ownership and execution context for an audit event. A service is
/// always required so an audit row can be made visible through the same
/// service-scoped authorization path as the resource it describes. The
/// remaining dimensions are optional because not every event refers to a
/// cluster, world, execution unit, or durable operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuditScope {
    pub service_id: ServiceId,
    pub cluster_id: Option<ClusterId>,
    pub world_id: Option<WorldId>,
    pub execution_unit_ref: Option<String>,
    pub operation_id: Option<OperationId>,
}
impl AuditScope {
    pub fn for_service(service_id: ServiceId) -> Self {
        Self {
            service_id,
            cluster_id: None,
            world_id: None,
            execution_unit_ref: None,
            operation_id: None,
        }
    }

    pub fn for_cluster(service_id: ServiceId, cluster_id: ClusterId) -> Self {
        Self {
            cluster_id: Some(cluster_id),
            ..Self::for_service(service_id)
        }
    }

    pub fn for_world(service_id: ServiceId, world_id: WorldId) -> Self {
        Self {
            world_id: Some(world_id),
            ..Self::for_service(service_id)
        }
    }

    pub fn for_execution_unit(
        service_id: ServiceId,
        execution_unit_ref: impl Into<String>,
    ) -> Result<Self, DomainError> {
        let scope = Self {
            execution_unit_ref: Some(execution_unit_ref.into()),
            ..Self::for_service(service_id)
        };
        scope.validate()?;
        Ok(scope)
    }

    pub fn for_operation(service_id: ServiceId, operation_id: OperationId) -> Self {
        Self {
            operation_id: Some(operation_id),
            ..Self::for_service(service_id)
        }
    }

    pub fn with_cluster(mut self, cluster_id: ClusterId) -> Self {
        self.cluster_id = Some(cluster_id);
        self
    }

    pub fn with_world(mut self, world_id: WorldId) -> Self {
        self.world_id = Some(world_id);
        self
    }

    pub fn with_execution_unit(
        mut self,
        execution_unit_ref: impl Into<String>,
    ) -> Result<Self, DomainError> {
        self.execution_unit_ref = Some(execution_unit_ref.into());
        self.validate()?;
        Ok(self)
    }

    pub fn with_operation(mut self, operation_id: OperationId) -> Self {
        self.operation_id = Some(operation_id);
        self
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        if self
            .execution_unit_ref
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(DomainError::InvalidValue("audit execution unit ref"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditSource {
    Application,
    Api,
    Cli,
    System,
}
impl AuditSource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Application => "application",
            Self::Api => "api",
            Self::Cli => "cli",
            Self::System => "system",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditResult {
    Accepted,
    Success,
    Failure,
    Rejected,
}
impl AuditResult {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub actor: ActorId,
    pub action: String,
    pub target: String,
    pub classification: FileClassification,
    pub scope: AuditScope,
    pub source: AuditSource,
    pub result: AuditResult,
    pub before_revision: Option<u64>,
    pub after_revision: Option<u64>,
    pub plan_hash: Option<String>,
    pub request_id: Option<String>,
    pub evidence: Vec<String>,
}
impl AuditEvent {
    pub fn validate(&self) -> Result<(), DomainError> {
        self.scope.validate()?;
        if self.action.trim().is_empty() {
            return Err(DomainError::InvalidValue("audit action"));
        }
        if self.target.trim().is_empty() {
            return Err(DomainError::InvalidValue("audit target"));
        }
        if self
            .plan_hash
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(DomainError::InvalidValue("audit plan hash"));
        }
        if self
            .request_id
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err(DomainError::InvalidValue("audit request id"));
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    pub key: String,
    pub value_hash: String,
}
/// Content-addressed data staged outside the plan database. Plans carry only
/// its digest and size, never the bytes (including secret bytes).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StagedContentRef {
    pub digest: String,
    pub size: u64,
}
impl StagedContentRef {
    pub fn new(digest: &str, size: u64) -> Result<Self, DomainError> {
        let value = Self {
            digest: normalize_sha256_digest(digest)?,
            size,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        normalize_sha256_digest(&self.digest)?;
        Ok(())
    }
}

/// Session-scoped authorization for a content-addressed blob. The blob bytes
/// stay in CAS; this record is the only durable permission to reference them
/// from a plan.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StagedContentOwnership {
    pub id: StagedContentId,
    pub session_id: ChangeSessionId,
    pub actor: ActorId,
    pub content: StagedContentRef,
    pub classification: FileClassification,
    /// Actor/session scoped idempotency identity for the staging request.
    pub idempotency_key: String,
    /// Hash of the complete staging request (key is intentionally excluded).
    pub request_hash: String,
    pub expires_at: u64,
}
impl StagedContentOwnership {
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.id.as_uuid().is_nil()
            || self.session_id.as_uuid().is_nil()
            || self.actor.as_uuid().is_nil()
        {
            return Err(DomainError::InvalidValue("staged content owner"));
        }
        self.content.validate()?;
        required(&self.idempotency_key, "staged content idempotency key")?;
        if self.request_hash.len() != 64
            || !self
                .request_hash
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || self.request_hash != self.request_hash.to_ascii_lowercase()
        {
            return Err(DomainError::InvalidValue("staged content request hash"));
        }
        if matches!(
            self.classification,
            FileClassification::Unknown | FileClassification::State | FileClassification::Secret
        ) {
            return Err(DomainError::InvalidValue("staged content classification"));
        }
        if self.expires_at == 0 {
            return Err(DomainError::InvalidValue("staged content expiry"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionLifecycleAction {
    Start,
    Stop,
    Restart,
}
impl ExecutionLifecycleAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Start => "start",
            Self::Stop => "stop",
            Self::Restart => "restart",
        }
    }
}

/// Closed, typed management actions. Every mutation carries the stable
/// domain identity and the compare-and-set material needed by the application
/// to revalidate it immediately before an external call.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum PlanStepAction {
    ExecutionProvision {
        binding_id: BindingId,
        expected_binding_hash: String,
        domain_revision: u64,
    },
    ExecutionDelete {
        binding_id: BindingId,
        expected_binding_hash: String,
        expected_state_hash: String,
        domain_revision: u64,
        expected_version: u64,
    },
    ServiceLifecycleTransition {
        service_id: ServiceId,
        expected_state: ServiceLifecycle,
        next_state: ServiceLifecycle,
        expected_version: u64,
        reason: String,
    },
    ClusterRevisionCreate {
        cluster_id: ClusterId,
        revision: ClusterRevision,
        /// The complete set of endpoint bindings created with this revision.
        /// Their ids must exactly equal `revision.endpoint_bindings`.
        new_endpoint_bindings: Vec<EndpointBinding>,
        expected_current_number: Option<u64>,
    },
    ExecutionLifecycle {
        binding_id: BindingId,
        action: ExecutionLifecycleAction,
        expected_binding_hash: String,
        expected_state_hash: String,
        domain_revision: u64,
    },
    FileWrite {
        binding_id: BindingId,
        path: String,
        expected_binding_hash: String,
        domain_revision: u64,
        expected_before_digest: Option<String>,
        content: StagedContentRef,
        classification: FileClassification,
    },
    FileMove {
        binding_id: BindingId,
        from: String,
        to: String,
        expected_binding_hash: String,
        domain_revision: u64,
        expected_before_digest: Option<String>,
        expected_target_digest: Option<String>,
        classification: FileClassification,
    },
    FileQuarantine {
        binding_id: BindingId,
        path: String,
        expected_binding_hash: String,
        domain_revision: u64,
        expected_before_digest: Option<String>,
        classification: FileClassification,
    },
    FileBatch {
        binding_id: BindingId,
        expected_binding_hash: String,
        domain_revision: u64,
        operations: Vec<FileBatchOperation>,
    },
    ArtifactStage {
        artifact_id: ArtifactId,
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
        artifact_id: ArtifactId,
        artifact_set_id: ArtifactSetId,
        binding_id: BindingId,
        expected_binding_hash: String,
        cluster_id: ClusterId,
        expected_revision: RevisionId,
        target_revision: RevisionId,
        expected_digest: String,
        expected_version: u64,
        destination_path: String,
        expected_before_digest: Option<String>,
    },
    ProxyRollout {
        pool_id: ProxyPoolId,
        expected_instance_id: ProxyInstanceId,
        target_instance_id: ProxyInstanceId,
        expected_instance_version: u64,
        target_instance_version: u64,
        expected_instance_state: ProxyState,
        target_instance_state: ProxyState,
        target_binding_id: BindingId,
        target_binding_hash: String,
        domain_revision: u64,
        desired_state: ProxyState,
        /// Configuration writes that must be applied to the target execution
        /// after creation and before it is started or health-checked.
        configuration: Vec<FileBatchOperation>,
    },
    WorldWriterCutover {
        world_id: WorldId,
        expected_version: u64,
        expected_writer: Option<ClusterId>,
        next_writer: ClusterId,
        expected_writer_binding_id: Option<BindingId>,
        target_writer_binding_id: BindingId,
        expected_writer_binding_hash: Option<String>,
        target_writer_binding_hash: String,
        domain_revision: u64,
    },
    EndpointRollout {
        expected_binding_id: BindingId,
        target_binding_id: BindingId,
        cluster_id: ClusterId,
        expected_revision: RevisionId,
        target_revision: RevisionId,
        expected_version: u64,
        /// Explicit execution units whose live endpoint connections may be
        /// reconnected.  The controller may only restart units whose
        /// observation says they were running before the rollout.
        runtime_binding_ids: Vec<BindingId>,
        /// Fingerprints for `runtime_binding_ids`, in the same order.
        runtime_binding_hashes: Vec<String>,
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
    BackupCreate {
        kind: BackupKind,
        target: BackupTarget,
        request_hash: String,
    },
    BackupRestore {
        reference_id: BackupReferenceId,
        target: BackupTarget,
        expected_manifest_digest: String,
        /// Verified snapshot to use if this restore is compensated.
        rollback_reference_id: BackupReferenceId,
        expected_rollback_manifest_digest: String,
        expected_version: u64,
    },
    ServiceArchive {
        service_id: ServiceId,
        expected_version: u64,
        sunsetting_evidence_hash: String,
    },
    ServicePurge {
        service_id: ServiceId,
        expected_version: u64,
        archive_evidence_hash: String,
        verified_backup_id: BackupReferenceId,
        archived_at: u64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum FileBatchOperation {
    Write {
        path: String,
        expected_before_digest: Option<String>,
        content: StagedContentRef,
        classification: FileClassification,
    },
    Move {
        from: String,
        to: String,
        expected_before_digest: Option<String>,
        expected_target_digest: Option<String>,
        classification: FileClassification,
    },
    Quarantine {
        path: String,
        expected_before_digest: Option<String>,
        classification: FileClassification,
    },
}

impl PlanStepAction {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ExecutionProvision { .. } => "execution_provision",
            Self::ExecutionDelete { .. } => "execution_delete",
            Self::ServiceLifecycleTransition { .. } => "service_lifecycle_transition",
            Self::ClusterRevisionCreate { .. } => "cluster_revision_create",
            Self::ExecutionLifecycle { .. } => "execution_lifecycle",
            Self::FileWrite { .. } => "file_write",
            Self::FileMove { .. } => "file_move",
            Self::FileQuarantine { .. } => "file_quarantine",
            Self::FileBatch { .. } => "file_batch",
            Self::ArtifactStage { .. } => "artifact_stage",
            Self::ArtifactRegister { .. } => "artifact_register",
            Self::ArtifactActivate { .. } => "artifact_activate",
            Self::ProxyRollout { .. } => "proxy_rollout",
            Self::WorldWriterCutover { .. } => "world_writer_cutover",
            Self::EndpointRollout { .. } => "endpoint_rollout",
            Self::AccessPolicyUpdate { .. } => "access_policy_update",
            Self::RoutePolicyUpdate { .. } => "route_policy_update",
            Self::BackupCreate { .. } => "backup_create",
            Self::BackupRestore { .. } => "backup_restore",
            Self::ServiceArchive { .. } => "service_archive",
            Self::ServicePurge { .. } => "service_purge",
        }
    }

    pub fn binding_id(&self) -> Option<BindingId> {
        match self {
            Self::ExecutionProvision { binding_id, .. }
            | Self::ExecutionDelete { binding_id, .. }
            | Self::ExecutionLifecycle { binding_id, .. }
            | Self::FileWrite { binding_id, .. }
            | Self::FileMove { binding_id, .. }
            | Self::FileQuarantine { binding_id, .. }
            | Self::FileBatch { binding_id, .. }
            | Self::ArtifactActivate { binding_id, .. } => Some(*binding_id),
            Self::ProxyRollout {
                target_binding_id, ..
            }
            | Self::WorldWriterCutover {
                target_writer_binding_id: target_binding_id,
                ..
            }
            | Self::EndpointRollout {
                target_binding_id, ..
            } => Some(*target_binding_id),
            _ => None,
        }
    }

    pub fn expected_binding_hash(&self) -> Option<&str> {
        match self {
            Self::ExecutionProvision {
                expected_binding_hash,
                ..
            }
            | Self::ExecutionDelete {
                expected_binding_hash,
                ..
            }
            | Self::ExecutionLifecycle {
                expected_binding_hash,
                ..
            }
            | Self::FileWrite {
                expected_binding_hash,
                ..
            }
            | Self::FileMove {
                expected_binding_hash,
                ..
            }
            | Self::FileQuarantine {
                expected_binding_hash,
                ..
            }
            | Self::FileBatch {
                expected_binding_hash,
                ..
            }
            | Self::ArtifactActivate {
                expected_binding_hash,
                ..
            } => Some(expected_binding_hash),
            Self::ProxyRollout {
                target_binding_hash,
                ..
            } => Some(target_binding_hash),
            Self::WorldWriterCutover {
                target_writer_binding_hash,
                ..
            } => Some(target_writer_binding_hash),
            _ => None,
        }
    }

    pub fn with_binding_hash(self, expected_binding_hash: String) -> Self {
        match self {
            Self::ExecutionProvision {
                binding_id,
                domain_revision,
                ..
            } => Self::ExecutionProvision {
                binding_id,
                expected_binding_hash,
                domain_revision,
            },
            Self::ExecutionDelete {
                binding_id,
                expected_binding_hash: _,
                expected_state_hash,
                domain_revision,
                expected_version,
            } => Self::ExecutionDelete {
                binding_id,
                expected_binding_hash,
                expected_state_hash,
                domain_revision,
                expected_version,
            },
            Self::ServiceLifecycleTransition {
                service_id,
                expected_state,
                next_state,
                expected_version,
                reason,
            } => Self::ServiceLifecycleTransition {
                service_id,
                expected_state,
                next_state,
                expected_version,
                reason,
            },
            Self::ExecutionLifecycle {
                binding_id,
                action,
                expected_state_hash,
                domain_revision,
                ..
            } => Self::ExecutionLifecycle {
                binding_id,
                action,
                expected_binding_hash,
                expected_state_hash,
                domain_revision,
            },
            Self::FileWrite {
                binding_id,
                path,
                domain_revision,
                expected_before_digest,
                content,
                classification,
                ..
            } => Self::FileWrite {
                binding_id,
                path,
                expected_binding_hash,
                domain_revision,
                expected_before_digest,
                content,
                classification,
            },
            Self::FileMove {
                binding_id,
                from,
                to,
                domain_revision,
                expected_before_digest,
                expected_target_digest,
                classification,
                ..
            } => Self::FileMove {
                binding_id,
                from,
                to,
                expected_binding_hash,
                domain_revision,
                expected_before_digest,
                expected_target_digest,
                classification,
            },
            Self::FileQuarantine {
                binding_id,
                path,
                domain_revision,
                expected_before_digest,
                classification,
                ..
            } => Self::FileQuarantine {
                binding_id,
                path,
                expected_binding_hash,
                domain_revision,
                expected_before_digest,
                classification,
            },
            Self::FileBatch {
                binding_id,
                domain_revision,
                operations,
                ..
            } => Self::FileBatch {
                binding_id,
                expected_binding_hash,
                domain_revision,
                operations,
            },
            Self::ProxyRollout {
                pool_id,
                expected_instance_id,
                target_instance_id,
                expected_instance_version,
                target_instance_version,
                expected_instance_state,
                target_instance_state,
                target_binding_id,
                domain_revision,
                desired_state,
                configuration,
                ..
            } => Self::ProxyRollout {
                pool_id,
                expected_instance_id,
                target_instance_id,
                expected_instance_version,
                target_instance_version,
                expected_instance_state,
                target_instance_state,
                target_binding_id,
                target_binding_hash: expected_binding_hash,
                domain_revision,
                desired_state,
                configuration,
            },
            Self::ArtifactActivate {
                artifact_id,
                artifact_set_id,
                binding_id,
                cluster_id,
                expected_revision,
                target_revision,
                expected_digest,
                expected_version,
                destination_path,
                expected_before_digest,
                ..
            } => Self::ArtifactActivate {
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
            },
            action => action,
        }
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        fn hash(value: &str, what: &'static str) -> Result<(), DomainError> {
            if normalize_sha256_digest(value)? != value {
                return Err(DomainError::InvalidValue(what));
            }
            Ok(())
        }
        fn optional_hash(value: Option<&String>, what: &'static str) -> Result<(), DomainError> {
            if let Some(value) = value {
                hash(value, what)?;
            }
            Ok(())
        }
        fn version(value: u64, what: &'static str) -> Result<(), DomainError> {
            if value == 0 {
                return Err(DomainError::InvalidValue(what));
            }
            Ok(())
        }
        fn writable(classification: &FileClassification) -> Result<(), DomainError> {
            if matches!(
                classification,
                FileClassification::Unknown
                    | FileClassification::State
                    | FileClassification::Secret
            ) {
                return Err(DomainError::InvalidValue("plan file classification"));
            }
            Ok(())
        }
        fn path(value: &str) -> Result<(), DomainError> {
            normalize_relative_path(value).map(|_| ())
        }
        match self {
            Self::ExecutionProvision {
                expected_binding_hash,
                ..
            } => {
                hash(expected_binding_hash, "plan binding hash")?;
            }
            Self::ExecutionDelete {
                expected_binding_hash,
                expected_state_hash,
                expected_version,
                ..
            } => {
                hash(expected_binding_hash, "plan binding hash")?;
                hash(expected_state_hash, "plan state hash")?;
                version(*expected_version, "plan execution version")?;
            }
            Self::ServiceLifecycleTransition {
                service_id,
                expected_state,
                next_state,
                expected_version,
                reason,
            } => {
                if service_id.as_uuid().is_nil() || expected_state == next_state {
                    return Err(DomainError::InvalidValue("plan lifecycle transition"));
                }
                version(*expected_version, "plan lifecycle version")?;
                required(reason, "plan lifecycle reason")?;
                let mut service = Service {
                    id: *service_id,
                    key: "plan".into(),
                    display_name: "plan".into(),
                    ownership: Ownership::FirstParty,
                    audience: Audience::Public,
                    operator_model: OperatorModel::Central,
                    trust_profile: TrustProfile::Trusted,
                    lifecycle: expected_state.clone(),
                    availability: Availability::AlwaysOn,
                    current_cluster: None,
                    access_policy: None,
                    backup_policy: None,
                    metadata: String::new(),
                };
                service.transition(next_state.clone())?;
            }
            Self::ExecutionLifecycle {
                expected_binding_hash,
                expected_state_hash,
                ..
            } => {
                hash(expected_binding_hash, "plan binding hash")?;
                hash(expected_state_hash, "plan state hash")?;
            }
            Self::FileWrite {
                path: file_path,
                expected_binding_hash,
                expected_before_digest,
                content,
                classification,
                ..
            } => {
                path(file_path)?;
                hash(expected_binding_hash, "plan binding hash")?;
                optional_hash(expected_before_digest.as_ref(), "plan before digest")?;
                content.validate()?;
                writable(classification)?;
            }
            Self::FileMove {
                from,
                to,
                expected_binding_hash,
                expected_before_digest,
                expected_target_digest,
                classification,
                ..
            } => {
                path(from)?;
                path(to)?;
                hash(expected_binding_hash, "plan binding hash")?;
                optional_hash(expected_before_digest.as_ref(), "plan before digest")?;
                optional_hash(expected_target_digest.as_ref(), "plan target digest")?;
                writable(classification)?;
            }
            Self::FileQuarantine {
                path: file_path,
                expected_binding_hash,
                expected_before_digest,
                classification,
                ..
            } => {
                path(file_path)?;
                hash(expected_binding_hash, "plan binding hash")?;
                optional_hash(expected_before_digest.as_ref(), "plan before digest")?;
                writable(classification)?;
            }
            Self::FileBatch {
                expected_binding_hash,
                operations,
                ..
            } => {
                hash(expected_binding_hash, "plan binding hash")?;
                if operations.is_empty() {
                    return Err(DomainError::InvalidValue("empty file batch"));
                }
                let mut paths = std::collections::BTreeSet::new();
                for operation in operations {
                    let (path_a, path_b, before, target, content, classification) = match operation
                    {
                        FileBatchOperation::Write {
                            path,
                            expected_before_digest,
                            content,
                            classification,
                        } => (
                            path,
                            None,
                            expected_before_digest,
                            None,
                            Some(content),
                            classification,
                        ),
                        FileBatchOperation::Move {
                            from,
                            to,
                            expected_before_digest,
                            expected_target_digest,
                            classification,
                        } => (
                            from,
                            Some(to),
                            expected_before_digest,
                            expected_target_digest.as_ref(),
                            None,
                            classification,
                        ),
                        FileBatchOperation::Quarantine {
                            path,
                            expected_before_digest,
                            classification,
                        } => (
                            path,
                            None,
                            expected_before_digest,
                            None,
                            None,
                            classification,
                        ),
                    };
                    path(path_a)?;
                    if let Some(path_b) = path_b {
                        path(path_b)?;
                        if !paths.insert(path_b) {
                            return Err(DomainError::InvalidValue("duplicate file batch path"));
                        }
                    }
                    if !paths.insert(path_a) {
                        return Err(DomainError::InvalidValue("duplicate file batch path"));
                    }
                    optional_hash(before.as_ref(), "plan before digest")?;
                    optional_hash(target, "plan target digest")?;
                    if let Some(content) = content {
                        content.validate()?;
                    }
                    writable(classification)?;
                }
            }
            Self::ArtifactStage {
                expected_digest,
                expected_version,
                ..
            } => {
                hash(expected_digest, "plan artifact digest")?;
                version(*expected_version, "plan artifact version")?;
            }
            Self::ArtifactRegister {
                artifact,
                content,
                expected_version,
                ..
            } => {
                hash(&artifact.digest, "registered artifact digest")?;
                content.validate()?;
                if content.digest != artifact.digest {
                    return Err(DomainError::InvalidValue("registered artifact content"));
                }
                version(*expected_version, "registered artifact version")?;
            }
            Self::ClusterRevisionCreate {
                cluster_id,
                revision,
                new_endpoint_bindings,
                expected_current_number,
                ..
            } => {
                if cluster_id.as_uuid().is_nil()
                    || revision.id.as_uuid().is_nil()
                    || revision.number == 0
                {
                    return Err(DomainError::InvalidValue("cluster revision"));
                }
                if *expected_current_number == Some(0) {
                    return Err(DomainError::InvalidValue("current revision number"));
                }
                let mut binding_ids = std::collections::BTreeSet::new();
                let mut binding_keys = std::collections::BTreeSet::new();
                for binding in new_endpoint_bindings {
                    binding.validate()?;
                    if binding.revision_id != revision.id
                        || binding.cluster_id != *cluster_id
                        || !binding_ids.insert(binding.id)
                        || !binding_keys.insert(&binding.binding_key)
                    {
                        return Err(DomainError::InvalidValue(
                            "cluster revision endpoint bindings",
                        ));
                    }
                }
                let revision_binding_ids = revision
                    .endpoint_bindings
                    .iter()
                    .copied()
                    .collect::<std::collections::BTreeSet<_>>();
                if revision_binding_ids.len() != revision.endpoint_bindings.len()
                    || revision_binding_ids != binding_ids
                {
                    return Err(DomainError::InvalidValue(
                        "cluster revision endpoint binding set",
                    ));
                }
            }
            Self::ArtifactActivate {
                expected_digest,
                expected_binding_hash,
                destination_path,
                expected_before_digest,
                expected_revision,
                target_revision,
                expected_version,
                ..
            } => {
                hash(expected_digest, "plan artifact digest")?;
                hash(expected_binding_hash, "plan binding hash")?;
                normalize_relative_path(destination_path)?;
                optional_hash(expected_before_digest.as_ref(), "plan before digest")?;
                version(*expected_version, "plan artifact version")?;
                if expected_revision == target_revision {
                    return Err(DomainError::InvalidValue("artifact target revision"));
                }
            }
            Self::ProxyRollout {
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
            } => {
                if pool_id.as_uuid().is_nil()
                    || expected_instance_id.as_uuid().is_nil()
                    || target_instance_id.as_uuid().is_nil()
                    || expected_instance_id == target_instance_id
                    || target_binding_id.as_uuid().is_nil()
                {
                    return Err(DomainError::InvalidValue("plan proxy binding"));
                }
                version(*expected_instance_version, "plan proxy expected version")?;
                version(*target_instance_version, "plan proxy target version")?;
                if *expected_instance_state != ProxyState::Accepting
                    || !matches!(
                        target_instance_state,
                        ProxyState::Preparing | ProxyState::Ready
                    )
                    || *desired_state != ProxyState::Accepting
                {
                    return Err(DomainError::InvalidValue("plan proxy state"));
                }
                hash(target_binding_hash, "plan target binding hash")?;
                version(*domain_revision, "plan proxy domain revision")?;
                if configuration.is_empty() || configuration.len() > 1024 {
                    return Err(DomainError::InvalidValue("plan proxy configuration"));
                }
                let mut paths = std::collections::BTreeSet::new();
                for operation in configuration {
                    let FileBatchOperation::Write {
                        path: file_path,
                        expected_before_digest,
                        content,
                        classification,
                    } = operation
                    else {
                        return Err(DomainError::InvalidValue(
                            "proxy configuration must contain writes",
                        ));
                    };
                    normalize_relative_path(file_path)?;
                    if !paths.insert(file_path)
                        || *classification != FileClassification::MutableConfig
                    {
                        return Err(DomainError::InvalidValue("plan proxy configuration"));
                    }
                    optional_hash(expected_before_digest.as_ref(), "plan before digest")?;
                    content.validate()?;
                }
            }
            Self::WorldWriterCutover {
                expected_version,
                next_writer,
                expected_writer,
                expected_writer_binding_id,
                target_writer_binding_id,
                expected_writer_binding_hash,
                target_writer_binding_hash,
                domain_revision,
                world_id,
            } => {
                version(*expected_version, "plan world version")?;
                if world_id.as_uuid().is_nil()
                    || next_writer.as_uuid().is_nil()
                    || target_writer_binding_id.as_uuid().is_nil()
                    || expected_writer.as_ref() == Some(next_writer)
                    || expected_writer.is_none() != expected_writer_binding_id.is_none()
                    || expected_writer.is_none() != expected_writer_binding_hash.is_none()
                {
                    return Err(DomainError::InvalidValue("plan world writer"));
                }
                optional_hash(
                    expected_writer_binding_hash.as_ref(),
                    "plan expected writer binding hash",
                )?;
                hash(
                    target_writer_binding_hash,
                    "plan target writer binding hash",
                )?;
                version(*domain_revision, "plan world domain revision")?;
            }
            Self::EndpointRollout {
                expected_binding_id,
                target_binding_id,
                cluster_id,
                expected_revision,
                target_revision,
                expected_version,
                runtime_binding_ids,
                runtime_binding_hashes,
            } => {
                if expected_binding_id.as_uuid().is_nil()
                    || target_binding_id.as_uuid().is_nil()
                    || expected_binding_id == target_binding_id
                    || cluster_id.as_uuid().is_nil()
                {
                    return Err(DomainError::InvalidValue("plan endpoint binding"));
                }
                version(*expected_version, "plan endpoint version")?;
                if expected_revision == target_revision {
                    return Err(DomainError::InvalidValue("endpoint target revision"));
                }
                if runtime_binding_ids.is_empty()
                    || runtime_binding_ids.len() != runtime_binding_hashes.len()
                    || runtime_binding_ids.len() > 128
                {
                    return Err(DomainError::InvalidValue("endpoint runtime bindings"));
                }
                let mut runtime_ids = std::collections::BTreeSet::new();
                for (binding_id, binding_hash) in
                    runtime_binding_ids.iter().zip(runtime_binding_hashes)
                {
                    if binding_id.as_uuid().is_nil() || !runtime_ids.insert(binding_id) {
                        return Err(DomainError::InvalidValue(
                            "endpoint runtime binding identities",
                        ));
                    }
                    hash(binding_hash, "endpoint runtime binding hash")?;
                }
            }
            Self::AccessPolicyUpdate {
                desired_policy_hash,
                expected_version,
                service_id,
                desired_grants,
                ..
            } => {
                hash(desired_policy_hash, "plan access policy hash")?;
                version(*expected_version, "plan access policy version")?;
                if service_id.as_uuid().is_nil()
                    || desired_grants
                        .iter()
                        .any(|grant| grant.service_scope != Some(*service_id))
                {
                    return Err(DomainError::InvalidValue(
                        "plan access grants must target the plan service",
                    ));
                }
            }
            Self::RoutePolicyUpdate {
                expected_cluster,
                target_cluster,
                expected_version,
                ..
            } => {
                version(*expected_version, "plan route policy version")?;
                if expected_cluster == target_cluster {
                    return Err(DomainError::InvalidValue("plan route target"));
                }
            }
            Self::BackupCreate { request_hash, .. } => {
                hash(request_hash, "plan backup request hash")?
            }
            Self::BackupRestore {
                reference_id,
                expected_manifest_digest,
                rollback_reference_id,
                expected_rollback_manifest_digest,
                expected_version,
                ..
            } => {
                if reference_id.as_uuid().is_nil()
                    || rollback_reference_id.as_uuid().is_nil()
                    || reference_id == rollback_reference_id
                {
                    return Err(DomainError::InvalidValue("plan backup restore references"));
                }
                hash(expected_manifest_digest, "plan backup manifest digest")?;
                hash(
                    expected_rollback_manifest_digest,
                    "plan rollback backup manifest digest",
                )?;
                version(*expected_version, "plan backup version")?;
            }
            Self::ServiceArchive {
                sunsetting_evidence_hash,
                expected_version,
                ..
            } => {
                hash(sunsetting_evidence_hash, "plan sunsetting evidence hash")?;
                version(*expected_version, "plan archive version")?;
            }
            Self::ServicePurge {
                archive_evidence_hash,
                expected_version,
                archived_at,
                ..
            } => {
                hash(archive_evidence_hash, "plan archive evidence hash")?;
                version(*expected_version, "plan purge version")?;
                if *archived_at == 0 {
                    return Err(DomainError::InvalidValue("plan archive timestamp"));
                }
            }
        }
        Ok(())
    }

    /// Canonical bytes for this action. All fields are length-prefixed and
    /// explicit; changing any typed field changes the plan hash.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        fn field(out: &mut Vec<u8>, value: impl AsRef<[u8]>) {
            let value = value.as_ref();
            out.extend_from_slice(&(value.len() as u64).to_be_bytes());
            out.extend_from_slice(value);
        }
        fn opt_field(out: &mut Vec<u8>, value: Option<&str>) {
            match value {
                Some(value) => {
                    field(out, b"some");
                    field(out, value);
                }
                None => field(out, b"none"),
            }
        }
        fn id(out: &mut Vec<u8>, value: Uuid) {
            field(out, value.hyphenated().to_string());
        }
        fn class(value: &FileClassification) -> &'static str {
            value.as_str()
        }
        fn proxy_state(value: &ProxyState) -> &'static str {
            match value {
                ProxyState::Preparing => "preparing",
                ProxyState::Ready => "ready",
                ProxyState::Accepting => "accepting",
                ProxyState::Draining => "draining",
                ProxyState::Stopped => "stopped",
                ProxyState::Failed => "failed",
            }
        }
        fn role(value: Role) -> &'static str {
            match value {
                Role::PlatformAdmin => "platform_admin",
                Role::Operator => "operator",
                Role::ServiceMaintainer => "service_maintainer",
                Role::Auditor => "auditor",
            }
        }
        fn permission(value: Permission) -> &'static str {
            value.as_str()
        }
        fn grant_fields(out: &mut Vec<u8>, value: &AccessGrant) {
            id(out, value.actor.as_uuid());
            field(out, role(value.role));
            match value.service_scope {
                Some(service) => id(out, service.as_uuid()),
                None => field(out, b"none"),
            }
            field(out, value.permissions.len().to_string());
            for permission_value in &value.permissions {
                field(out, permission(*permission_value));
            }
        }
        fn backup_target(out: &mut Vec<u8>, value: &BackupTarget) {
            match value {
                BackupTarget::Service(value) => {
                    field(out, b"service");
                    id(out, value.as_uuid());
                }
                BackupTarget::Cluster(value) => {
                    field(out, b"cluster");
                    id(out, value.as_uuid());
                }
                BackupTarget::World(value) => {
                    field(out, b"world");
                    id(out, value.as_uuid());
                }
                BackupTarget::ExecutionUnit(value) => {
                    field(out, b"execution_unit");
                    id(out, value.as_uuid());
                }
            }
        }
        fn staged(out: &mut Vec<u8>, value: &StagedContentRef) {
            field(out, value.digest.as_bytes());
            field(out, value.size.to_string());
        }
        fn endpoint_binding(out: &mut Vec<u8>, value: &EndpointBinding) {
            id(out, value.id.as_uuid());
            id(out, value.endpoint_id.as_uuid());
            id(out, value.cluster_id.as_uuid());
            id(out, value.revision_id.as_uuid());
            field(out, value.binding_key.as_bytes());
            field(out, value.metadata.as_bytes());
        }
        fn digest_opt(out: &mut Vec<u8>, value: &Option<String>) {
            opt_field(out, value.as_deref());
        }
        fn batch(out: &mut Vec<u8>, value: &FileBatchOperation) {
            match value {
                FileBatchOperation::Write {
                    path,
                    expected_before_digest,
                    content,
                    classification,
                } => {
                    field(out, b"write");
                    field(out, path.as_bytes());
                    digest_opt(out, expected_before_digest);
                    staged(out, content);
                    field(out, class(classification));
                }
                FileBatchOperation::Move {
                    from,
                    to,
                    expected_before_digest,
                    expected_target_digest,
                    classification,
                } => {
                    field(out, b"move");
                    field(out, from.as_bytes());
                    field(out, to.as_bytes());
                    digest_opt(out, expected_before_digest);
                    digest_opt(out, expected_target_digest);
                    field(out, class(classification));
                }
                FileBatchOperation::Quarantine {
                    path,
                    expected_before_digest,
                    classification,
                } => {
                    field(out, b"quarantine");
                    field(out, path.as_bytes());
                    digest_opt(out, expected_before_digest);
                    field(out, class(classification));
                }
            }
        }
        let mut out = Vec::new();
        field(&mut out, self.as_str());
        match self {
            Self::ExecutionProvision {
                binding_id,
                expected_binding_hash,
                domain_revision,
            } => {
                id(&mut out, binding_id.as_uuid());
                field(&mut out, expected_binding_hash.as_bytes());
                field(&mut out, domain_revision.to_string());
            }
            Self::ExecutionDelete {
                binding_id,
                expected_binding_hash,
                expected_state_hash,
                domain_revision,
                expected_version,
            } => {
                id(&mut out, binding_id.as_uuid());
                field(&mut out, expected_binding_hash.as_bytes());
                field(&mut out, expected_state_hash.as_bytes());
                field(&mut out, domain_revision.to_string());
                field(&mut out, expected_version.to_string());
            }
            Self::ServiceLifecycleTransition {
                service_id,
                expected_state,
                next_state,
                expected_version,
                reason,
            } => {
                id(&mut out, service_id.as_uuid());
                field(&mut out, format!("{expected_state:?}"));
                field(&mut out, format!("{next_state:?}"));
                field(&mut out, expected_version.to_string());
                field(&mut out, reason.as_bytes());
            }
            Self::ExecutionLifecycle {
                binding_id,
                action,
                expected_binding_hash,
                expected_state_hash,
                domain_revision,
            } => {
                id(&mut out, binding_id.as_uuid());
                field(&mut out, action.as_str());
                field(&mut out, expected_binding_hash.as_bytes());
                field(&mut out, expected_state_hash.as_bytes());
                field(&mut out, domain_revision.to_string());
            }
            Self::FileWrite {
                binding_id,
                path,
                expected_binding_hash,
                domain_revision,
                expected_before_digest,
                content,
                classification,
            } => {
                id(&mut out, binding_id.as_uuid());
                field(&mut out, path.as_bytes());
                field(&mut out, expected_binding_hash.as_bytes());
                field(&mut out, domain_revision.to_string());
                digest_opt(&mut out, expected_before_digest);
                staged(&mut out, content);
                field(&mut out, class(classification));
            }
            Self::FileMove {
                binding_id,
                from,
                to,
                expected_binding_hash,
                domain_revision,
                expected_before_digest,
                expected_target_digest,
                classification,
            } => {
                id(&mut out, binding_id.as_uuid());
                field(&mut out, from.as_bytes());
                field(&mut out, to.as_bytes());
                field(&mut out, expected_binding_hash.as_bytes());
                field(&mut out, domain_revision.to_string());
                digest_opt(&mut out, expected_before_digest);
                digest_opt(&mut out, expected_target_digest);
                field(&mut out, class(classification));
            }
            Self::FileQuarantine {
                binding_id,
                path,
                expected_binding_hash,
                domain_revision,
                expected_before_digest,
                classification,
            } => {
                id(&mut out, binding_id.as_uuid());
                field(&mut out, path.as_bytes());
                field(&mut out, expected_binding_hash.as_bytes());
                field(&mut out, domain_revision.to_string());
                digest_opt(&mut out, expected_before_digest);
                field(&mut out, class(classification));
            }
            Self::FileBatch {
                binding_id,
                expected_binding_hash,
                domain_revision,
                operations,
            } => {
                id(&mut out, binding_id.as_uuid());
                field(&mut out, expected_binding_hash.as_bytes());
                field(&mut out, domain_revision.to_string());
                field(&mut out, operations.len().to_string());
                for operation in operations {
                    batch(&mut out, operation);
                }
            }
            Self::ArtifactStage {
                artifact_id,
                expected_digest,
                expected_version,
                domain_revision,
            } => {
                id(&mut out, artifact_id.as_uuid());
                field(&mut out, expected_digest.as_bytes());
                field(&mut out, expected_version.to_string());
                field(&mut out, domain_revision.to_string());
            }
            Self::ArtifactRegister {
                artifact,
                content,
                expected_version,
                domain_revision,
            } => {
                id(&mut out, artifact.id.as_uuid());
                field(&mut out, artifact.kind.as_bytes());
                field(&mut out, artifact.name.as_bytes());
                field(&mut out, artifact.version.as_bytes());
                field(&mut out, artifact.source.as_bytes());
                field(&mut out, artifact.source_id.as_bytes());
                field(&mut out, artifact.digest.as_bytes());
                field(&mut out, artifact.filename.as_bytes());
                field(&mut out, artifact.compatibility.as_bytes());
                field(&mut out, artifact.metadata.as_bytes());
                staged(&mut out, content);
                field(&mut out, expected_version.to_string());
                field(&mut out, domain_revision.to_string());
            }
            Self::ClusterRevisionCreate {
                cluster_id,
                revision,
                new_endpoint_bindings,
                expected_current_number,
            } => {
                id(&mut out, cluster_id.as_uuid());
                id(&mut out, revision.id.as_uuid());
                field(&mut out, revision.number.to_string());
                id(&mut out, revision.runtime_profile.as_uuid());
                field(&mut out, revision.minecraft_version.as_bytes());
                field(&mut out, revision.java_requirement.as_bytes());
                id(&mut out, revision.artifact_set.as_uuid());
                id(&mut out, revision.config_baseline.as_uuid());
                field(&mut out, new_endpoint_bindings.len().to_string());
                for binding in new_endpoint_bindings {
                    endpoint_binding(&mut out, binding);
                }
                field(&mut out, format!("{expected_current_number:?}"));
            }
            Self::ArtifactActivate {
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
            } => {
                id(&mut out, artifact_id.as_uuid());
                id(&mut out, artifact_set_id.as_uuid());
                id(&mut out, binding_id.as_uuid());
                field(&mut out, expected_binding_hash.as_bytes());
                id(&mut out, cluster_id.as_uuid());
                id(&mut out, expected_revision.as_uuid());
                id(&mut out, target_revision.as_uuid());
                field(&mut out, expected_digest.as_bytes());
                field(&mut out, expected_version.to_string());
                field(&mut out, destination_path.as_bytes());
                field(&mut out, expected_before_digest.as_deref().unwrap_or(""));
            }
            Self::ProxyRollout {
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
            } => {
                id(&mut out, pool_id.as_uuid());
                id(&mut out, expected_instance_id.as_uuid());
                id(&mut out, target_instance_id.as_uuid());
                field(&mut out, expected_instance_version.to_string());
                field(&mut out, target_instance_version.to_string());
                field(&mut out, proxy_state(expected_instance_state));
                field(&mut out, proxy_state(target_instance_state));
                id(&mut out, target_binding_id.as_uuid());
                field(&mut out, target_binding_hash.as_bytes());
                field(&mut out, domain_revision.to_string());
                field(&mut out, proxy_state(desired_state));
                field(&mut out, configuration.len().to_string());
                for operation in configuration {
                    batch(&mut out, operation);
                }
            }
            Self::WorldWriterCutover {
                world_id,
                expected_version,
                expected_writer,
                next_writer,
                expected_writer_binding_id,
                target_writer_binding_id,
                expected_writer_binding_hash,
                target_writer_binding_hash,
                domain_revision,
            } => {
                id(&mut out, world_id.as_uuid());
                field(&mut out, expected_version.to_string());
                match expected_writer {
                    Some(value) => id(&mut out, value.as_uuid()),
                    None => field(&mut out, b"none"),
                }
                id(&mut out, next_writer.as_uuid());
                match expected_writer_binding_id {
                    Some(value) => id(&mut out, value.as_uuid()),
                    None => field(&mut out, b"none"),
                }
                id(&mut out, target_writer_binding_id.as_uuid());
                opt_field(&mut out, expected_writer_binding_hash.as_deref());
                field(&mut out, target_writer_binding_hash.as_bytes());
                field(&mut out, domain_revision.to_string());
            }
            Self::EndpointRollout {
                expected_binding_id,
                target_binding_id,
                cluster_id,
                expected_revision,
                target_revision,
                expected_version,
                runtime_binding_ids,
                runtime_binding_hashes,
            } => {
                id(&mut out, expected_binding_id.as_uuid());
                id(&mut out, target_binding_id.as_uuid());
                id(&mut out, cluster_id.as_uuid());
                id(&mut out, expected_revision.as_uuid());
                id(&mut out, target_revision.as_uuid());
                field(&mut out, expected_version.to_string());
                field(&mut out, runtime_binding_ids.len().to_string());
                for binding_id in runtime_binding_ids {
                    id(&mut out, binding_id.as_uuid());
                }
                for binding_hash in runtime_binding_hashes {
                    field(&mut out, binding_hash.as_bytes());
                }
            }
            Self::AccessPolicyUpdate {
                policy_id,
                service_id,
                expected_version,
                desired_grants,
                desired_policy_hash,
            } => {
                id(&mut out, policy_id.as_uuid());
                id(&mut out, service_id.as_uuid());
                field(&mut out, expected_version.to_string());
                field(&mut out, desired_policy_hash.as_bytes());
                field(&mut out, desired_grants.len().to_string());
                for grant_value in desired_grants {
                    grant_fields(&mut out, grant_value);
                }
            }
            Self::RoutePolicyUpdate {
                route_id,
                pool_id,
                service_id,
                expected_cluster,
                target_cluster,
                expected_priority,
                target_priority,
                expected_version,
                disabled,
            } => {
                id(&mut out, route_id.as_uuid());
                id(&mut out, pool_id.as_uuid());
                id(&mut out, service_id.as_uuid());
                id(&mut out, expected_cluster.as_uuid());
                id(&mut out, target_cluster.as_uuid());
                field(&mut out, expected_priority.to_string());
                field(&mut out, target_priority.to_string());
                field(&mut out, expected_version.to_string());
                field(&mut out, disabled.to_string());
            }
            Self::BackupCreate {
                kind,
                target,
                request_hash,
            } => {
                field(&mut out, kind.as_str());
                backup_target(&mut out, target);
                field(&mut out, request_hash.as_bytes());
            }
            Self::BackupRestore {
                reference_id,
                target,
                expected_manifest_digest,
                rollback_reference_id,
                expected_rollback_manifest_digest,
                expected_version,
            } => {
                id(&mut out, reference_id.as_uuid());
                backup_target(&mut out, target);
                field(&mut out, expected_manifest_digest.as_bytes());
                id(&mut out, rollback_reference_id.as_uuid());
                field(&mut out, expected_rollback_manifest_digest.as_bytes());
                field(&mut out, expected_version.to_string());
            }
            Self::ServiceArchive {
                service_id,
                expected_version,
                sunsetting_evidence_hash,
            } => {
                id(&mut out, service_id.as_uuid());
                field(&mut out, expected_version.to_string());
                field(&mut out, sunsetting_evidence_hash.as_bytes());
            }
            Self::ServicePurge {
                service_id,
                expected_version,
                archive_evidence_hash,
                verified_backup_id,
                archived_at,
            } => {
                id(&mut out, service_id.as_uuid());
                field(&mut out, expected_version.to_string());
                field(&mut out, archive_evidence_hash.as_bytes());
                id(&mut out, verified_backup_id.as_uuid());
                field(&mut out, archived_at.to_string());
            }
        }
        out
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PlanStep {
    pub action: PlanStepAction,
}
impl PlanStep {
    pub fn new(action: PlanStepAction) -> Result<Self, DomainError> {
        action.validate()?;
        Ok(Self { action })
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        self.action.validate()
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        self.action.canonical_bytes()
    }
}

/// The durable object a plan owns. A plan target is never a provider string;
/// all variants identify a domain object by its stable typed id.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum PlanTarget {
    Service(ServiceId),
    Cluster(ClusterId),
    World(WorldId),
    ProxyPool(ProxyPoolId),
    ProxyInstance(ProxyInstanceId),
    Artifact(ArtifactId),
    ArtifactSet(ArtifactSetId),
    Endpoint(EndpointId),
    EndpointBinding(BindingId),
    AccessPolicy(PolicyId),
    Backup(BackupReferenceId),
    ExecutionUnit(BindingId),
}
impl PlanTarget {
    pub fn stable_string(self) -> String {
        let (kind, id) = match self {
            Self::Service(id) => ("service", id.as_uuid()),
            Self::Cluster(id) => ("cluster", id.as_uuid()),
            Self::World(id) => ("world", id.as_uuid()),
            Self::ProxyPool(id) => ("proxy_pool", id.as_uuid()),
            Self::ProxyInstance(id) => ("proxy_instance", id.as_uuid()),
            Self::Artifact(id) => ("artifact", id.as_uuid()),
            Self::ArtifactSet(id) => ("artifact_set", id.as_uuid()),
            Self::Endpoint(id) => ("endpoint", id.as_uuid()),
            Self::EndpointBinding(id) => ("endpoint_binding", id.as_uuid()),
            Self::AccessPolicy(id) => ("access_policy", id.as_uuid()),
            Self::Backup(id) => ("backup", id.as_uuid()),
            Self::ExecutionUnit(id) => ("execution_unit", id.as_uuid()),
        };
        format!("{kind}:{id}")
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PlanDescriptor {
    pub id: PlanId,
    pub actor: ActorId,
    pub target: PlanTarget,
    pub domain_revision: u64,
    pub observed_state_hashes: Vec<String>,
    pub expected_file_hashes: Vec<String>,
    pub expected_artifact_hashes: Vec<String>,
    pub steps: Vec<PlanStep>,
    pub backup_requirements: BackupRequirements,
    pub rollback_instructions: Vec<String>,
    pub expiry: u64,
    pub plan_hash: String,
}
impl PlanDescriptor {
    pub fn new(
        actor: ActorId,
        target: PlanTarget,
        domain_revision: u64,
        expiry: u64,
        steps: Vec<PlanStep>,
    ) -> Result<Self, DomainError> {
        for step in &steps {
            step.validate()?;
        }
        let mut p = Self {
            id: PlanId::new(),
            actor,
            target,
            domain_revision,
            observed_state_hashes: vec![],
            expected_file_hashes: vec![],
            expected_artifact_hashes: vec![],
            steps,
            backup_requirements: BackupRequirements {
                required: false,
                references: vec![],
            },
            rollback_instructions: vec![],
            expiry,
            plan_hash: String::new(),
        };
        p.plan_hash = p.compute_hash();
        Ok(p)
    }
    pub fn canonical_bytes(&self) -> Vec<u8> {
        // Length-prefixing prevents delimiter ambiguity and keeps the encoding independent
        // of Rust's Debug formatting or map iteration order.
        fn field(out: &mut String, value: &str) {
            out.push_str(&value.len().to_string());
            out.push(':');
            out.push_str(value);
        }
        fn fields(out: &mut String, values: &[String]) {
            out.push('[');
            for value in values {
                field(out, value);
            }
            out.push(']');
        }
        let mut out = String::new();
        field(&mut out, &self.id.as_uuid().to_string());
        field(&mut out, &self.actor.as_uuid().to_string());
        let target = self.target.stable_string();
        field(&mut out, &target);
        field(&mut out, &self.domain_revision.to_string());
        fields(&mut out, &self.observed_state_hashes);
        fields(&mut out, &self.expected_file_hashes);
        fields(&mut out, &self.expected_artifact_hashes);
        out.push('[');
        for step in &self.steps {
            let action = step
                .canonical_bytes()
                .into_iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>();
            field(&mut out, &action);
        }
        out.push(']');
        field(&mut out, &self.backup_requirements.required.to_string());
        fields(
            &mut out,
            &self
                .backup_requirements
                .references
                .iter()
                .map(|v| v.as_uuid().to_string())
                .collect::<Vec<_>>(),
        );
        fields(&mut out, &self.rollback_instructions);
        field(&mut out, &self.expiry.to_string());
        out.into_bytes()
    }
    pub fn compute_hash(&self) -> String {
        let mut h = Sha256::new();
        h.update(self.canonical_bytes());
        format!("{:x}", h.finalize())
    }

    pub fn validate(&self) -> Result<(), DomainError> {
        for step in &self.steps {
            step.validate()?;
        }
        if self.plan_hash.len() != 64
            || !self
                .plan_hash
                .bytes()
                .all(|value| value.is_ascii_hexdigit())
            || self.plan_hash != self.plan_hash.to_ascii_lowercase()
        {
            return Err(DomainError::InvalidValue("plan hash"));
        }
        if self.plan_hash != self.compute_hash() {
            return Err(DomainError::InvalidValue("plan hash does not match plan"));
        }
        let mut references = std::collections::BTreeSet::new();
        for reference in &self.backup_requirements.references {
            if !references.insert(*reference) {
                return Err(DomainError::InvalidValue("duplicate backup requirement"));
            }
        }
        Ok(())
    }
    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.expiry
    }
}
