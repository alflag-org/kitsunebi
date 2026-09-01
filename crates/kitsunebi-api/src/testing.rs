//! Small deterministic test doubles for route-contract tests.
use crate::{
    auth::VerifiedClaims,
    dto::{
        ArtifactCandidateDto, ArtifactDiscoverPayload, ChangeApprovalDto, ChangeBeginPayload,
        ChangePlanResultDto, ChangeSessionDto, FileClassification, FileDiffDto, FileEntryDto,
        FileReadDto, MutationRequest, OperationDto, OperationEvent, ResourceDto, SftpEndpointDto,
        SftpScanDto, SftpScanPayload, StagedContentDto,
    },
    error::ApiError,
    ports::{
        AccessDecision, ActorKind, Authorization, ConsoleAuditEvent, ConsoleFrame, ConsoleSession,
        FilePort, IdentityMapper, ManagementApi, MutationContext, OperationStreamPort, Permission,
        Role, StageContentRequest, VerifiedActor,
    },
};
use async_trait::async_trait;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::Arc,
};
use tokio::sync::Mutex;
use uuid::Uuid;

type PlanIdempotencyKey = (String, String, String, String);
type StoredPlan = (String, ChangePlanResultDto);
type StagedContentRecord = (String, StagedContentDto, FileClassification, String);

/// In-memory implementation used to exercise every route without a database or network.
pub struct InMemoryManagementApi {
    resources: Mutex<BTreeMap<(String, String), ResourceDto>>,
    idempotency: Mutex<BTreeMap<(String, String, String, String), OperationDto>>,
    plan_idempotency: Mutex<BTreeMap<PlanIdempotencyKey, StoredPlan>>,
    begin_idempotency: Mutex<BTreeMap<(String, String), ChangeSessionDto>>,
    staged_idempotency: Mutex<BTreeMap<(String, String, String), StagedContentRecord>>,
    files: InMemoryFiles,
}
impl Default for InMemoryManagementApi {
    fn default() -> Self {
        Self {
            resources: Mutex::new(BTreeMap::new()),
            idempotency: Mutex::new(BTreeMap::new()),
            plan_idempotency: Mutex::new(BTreeMap::new()),
            begin_idempotency: Mutex::new(BTreeMap::new()),
            staged_idempotency: Mutex::new(BTreeMap::new()),
            files: InMemoryFiles::default(),
        }
    }
}
impl InMemoryManagementApi {
    pub async fn insert(&self, resource: &str, id: &str, fields: Value) {
        self.resources.lock().await.insert(
            (resource.to_owned(), id.to_owned()),
            ResourceDto {
                id: id.to_owned(),
                fields,
            },
        );
    }
    pub fn actor() -> VerifiedActor {
        let permissions = Permission::all().into_iter().collect();
        VerifiedActor {
            subject: "test-subject".into(),
            email: Some("test@example.invalid".into()),
            common_name: Some("test".into()),
            kind: ActorKind::Browser,
            authorization: Authorization {
                role: Role::PlatformAdmin,
                permissions,
                service_scopes: BTreeSet::from(["*".into()]),
            },
        }
    }
}
#[async_trait]
impl ManagementApi for InMemoryManagementApi {
    async fn list(
        &self,
        resource: &str,
        actor: &VerifiedActor,
    ) -> Result<Vec<ResourceDto>, ApiError> {
        let map = self.resources.lock().await;
        Ok(map
            .iter()
            .filter(|((kind, _), item)| kind == resource && in_scope(item, actor))
            .map(|(_, item)| item.clone())
            .collect())
    }
    async fn get(
        &self,
        resource: &str,
        id: &str,
        actor: &VerifiedActor,
    ) -> Result<ResourceDto, ApiError> {
        let item = self
            .resources
            .lock()
            .await
            .get(&(resource.to_owned(), id.to_owned()))
            .cloned()
            .ok_or(ApiError::NotFound)?;
        if in_scope(&item, actor) {
            Ok(item)
        } else {
            Err(ApiError::NotFound)
        }
    }

    async fn list_sftp_endpoints(
        &self,
        _actor: &VerifiedActor,
    ) -> Result<Vec<SftpEndpointDto>, ApiError> {
        Ok(Vec::new())
    }

    async fn get_sftp_endpoint(
        &self,
        _actor: &VerifiedActor,
        _id: &str,
    ) -> Result<SftpEndpointDto, ApiError> {
        Err(ApiError::NotFound)
    }

    async fn scan_sftp(
        &self,
        _actor: &VerifiedActor,
        endpoint_id: &str,
        payload: SftpScanPayload,
        context: MutationContext,
    ) -> Result<SftpScanDto, ApiError> {
        Ok(SftpScanDto {
            id: Uuid::new_v4().to_string(),
            endpoint_id: endpoint_id.to_owned(),
            service_id: payload.service_id,
            execution_binding_id: payload.execution_binding_id,
            session_id: payload.change_session_id,
            before_manifest_hash: payload.before_manifest_hash,
            after_manifest_hash: payload.after_manifest_hash,
            changed_paths: payload.changed_paths,
            observed_at: payload.observed_at,
            source: payload.source,
            request_hash: context.request_hash,
        })
    }
    async fn authorize(
        &self,
        actor: &VerifiedActor,
        resource: &str,
        id: Option<&str>,
        permission: Permission,
    ) -> Result<AccessDecision, ApiError> {
        if !actor.authorization.permissions.contains(&permission) {
            return Err(ApiError::Forbidden);
        }
        if let Some(id) = id {
            let item = self
                .resources
                .lock()
                .await
                .get(&(resource.to_owned(), id.to_owned()))
                .cloned()
                .ok_or(ApiError::NotFound)?;
            if !in_scope(&item, actor) {
                return Err(ApiError::NotFound);
            }
        }
        Ok(AccessDecision { service_key: None })
    }
    async fn mutate(
        &self,
        resource: &str,
        id: Option<&str>,
        request: MutationRequest,
        context: MutationContext,
    ) -> Result<OperationDto, ApiError> {
        if context.request_hash != request.request_hash || context.expires_at != request.expires_at
        {
            return Err(ApiError::Conflict);
        }
        let key = (
            context.actor.subject.clone(),
            context.idempotency_key.clone(),
            resource.to_owned(),
            id.unwrap_or_default().to_owned(),
        );
        if let Some(existing) = self.idempotency.lock().await.get(&key).cloned() {
            if existing.plan_hash == context.if_match.trim_matches('"') {
                return Ok(existing);
            }
            return Err(ApiError::Conflict);
        }
        let operation = OperationDto {
            id: Uuid::new_v4().to_string(),
            status: request.command.as_str().to_owned(),
            plan_hash: context.if_match.trim_matches('"').to_owned(),
            request_id: context.request_id,
        };
        self.idempotency.lock().await.insert(key, operation.clone());
        Ok(operation)
    }
    async fn plan_change(
        &self,
        actor: &VerifiedActor,
        resource: &str,
        id: &str,
        request: MutationRequest,
        context: MutationContext,
    ) -> Result<ChangePlanResultDto, ApiError> {
        if !actor
            .authorization
            .permissions
            .contains(&Permission::ChangePlan)
        {
            return Err(ApiError::Forbidden);
        }
        request.validate_for(
            resource,
            crate::dto::MutationCommand::Plan,
            crate::dto::MutationAction::Change,
        )?;
        let crate::dto::MutationPayload::ChangePlan(payload) = request.payload.clone() else {
            return Err(ApiError::InvalidRequest("change plan payload is required"));
        };
        if resource != "change-sessions"
            || id.trim().is_empty()
            || context.idempotency_key.trim().is_empty()
            || context.actor.subject != actor.subject
            || context.request_hash != request.request_hash
            || context.expires_at != request.expires_at
            || payload.session_id != id
        {
            return Err(ApiError::Conflict);
        }
        if context.session_version != Some(1) || context.if_match != "\"1\"" {
            return Err(ApiError::Conflict);
        }
        if !actor.authorization.service_scopes.contains("*")
            && !actor
                .authorization
                .service_scopes
                .contains(&payload.service_id)
        {
            return Err(ApiError::NotFound);
        }
        let key = (
            actor.subject.clone(),
            context.idempotency_key.clone(),
            resource.to_owned(),
            id.to_owned(),
        );
        let mut plans = self.plan_idempotency.lock().await;
        if let Some((existing_hash, existing)) = plans.get(&key) {
            if existing_hash == &request.request_hash {
                return Ok(existing.clone());
            }
            return Err(ApiError::Conflict);
        }
        let result = ChangePlanResultDto {
            plan_id: Uuid::new_v4().to_string(),
            plan_hash: request.request_hash,
            session_id: payload.session_id,
            state: "planned".into(),
        };
        plans.insert(key, (result.plan_hash.clone(), result.clone()));
        Ok(result)
    }
    async fn approve_change(
        &self,
        actor: &VerifiedActor,
        resource: &str,
        id: &str,
        request: MutationRequest,
        context: MutationContext,
    ) -> Result<ChangeApprovalDto, ApiError> {
        if !actor
            .authorization
            .permissions
            .contains(&Permission::ChangeApprove)
        {
            return Err(ApiError::Forbidden);
        }
        request.validate_for(
            resource,
            crate::dto::MutationCommand::Approve,
            crate::dto::MutationAction::Change,
        )?;
        let crate::dto::MutationPayload::ChangeApprove(payload) = request.payload.clone() else {
            return Err(ApiError::InvalidRequest("change plan payload is required"));
        };
        if resource != "change-sessions"
            || payload.session_id != id
            || context.actor.subject != actor.subject
            || context.request_hash != request.request_hash
        {
            return Err(ApiError::Conflict);
        }
        if payload.plan_hash != context.if_match.trim_matches('"') {
            return Err(ApiError::Conflict);
        }
        Ok(ChangeApprovalDto {
            plan_id: payload.plan_id,
            plan_hash: payload.plan_hash,
            session_id: payload.session_id,
            state: "approved".into(),
        })
    }
    async fn stage_content(
        &self,
        actor: &VerifiedActor,
        request: StageContentRequest,
    ) -> Result<crate::dto::StagedContentDto, ApiError> {
        request.validate()?;
        if !actor
            .authorization
            .permissions
            .contains(&Permission::ChangePlan)
            || request.session_version != 1
        {
            return Err(ApiError::Forbidden);
        }
        let digest = crate::plan_hash(&request.bytes);
        let key = (
            actor.subject.clone(),
            request.session_id.clone(),
            request.idempotency_key.clone(),
        );
        let mut staged = self.staged_idempotency.lock().await;
        if let Some((existing_digest, existing, existing_classification, existing_request_hash)) =
            staged.get(&key)
        {
            if existing_digest != &digest
                || existing.size != request.bytes.len() as u64
                || existing_classification != &request.classification
                || existing_request_hash != &request.request_hash
            {
                return Err(ApiError::Conflict);
            }
            return Ok(existing.clone());
        }
        let result = crate::dto::StagedContentDto {
            digest,
            size: request.bytes.len() as u64,
        };
        staged.insert(
            key,
            (
                result.digest.clone(),
                result.clone(),
                request.classification,
                request.request_hash,
            ),
        );
        Ok(result)
    }
    async fn discover_artifacts(
        &self,
        actor: &VerifiedActor,
        _payload: ArtifactDiscoverPayload,
    ) -> Result<Vec<ArtifactCandidateDto>, ApiError> {
        if !actor
            .authorization
            .permissions
            .contains(&Permission::ArtifactDiscover)
        {
            return Err(ApiError::Forbidden);
        }
        Ok(Vec::new())
    }
    async fn begin_change_session(
        &self,
        actor: &VerifiedActor,
        payload: ChangeBeginPayload,
        idempotency_key: &str,
        _request_id: &str,
    ) -> Result<ChangeSessionDto, ApiError> {
        if !actor
            .authorization
            .permissions
            .contains(&Permission::ChangePlan)
        {
            return Err(ApiError::Forbidden);
        }
        if payload.service_id.trim().is_empty() || payload.cluster_id.trim().is_empty() {
            return Err(ApiError::InvalidRequest(
                "service_id and cluster_id are required",
            ));
        }
        if !actor.authorization.service_scopes.contains("*")
            && !actor
                .authorization
                .service_scopes
                .contains(&payload.service_id)
        {
            return Err(ApiError::NotFound);
        }
        let key = (actor.subject.clone(), idempotency_key.to_owned());
        if let Some(existing) = self.begin_idempotency.lock().await.get(&key).cloned() {
            return Ok(existing);
        }
        let session = ChangeSessionDto {
            id: Uuid::new_v4().to_string(),
            service_id: payload.service_id.clone(),
            cluster_id: payload.cluster_id.clone(),
            state: "editing".into(),
            version: 1,
        };
        self.resources.lock().await.insert(
            ("change-sessions".into(), session.id.clone()),
            ResourceDto {
                id: session.id.clone(),
                fields: json!({
                    "service_id": session.service_id,
                    "cluster_id": session.cluster_id,
                    "state": session.state,
                    "version": session.version,
                }),
            },
        );
        self.begin_idempotency
            .lock()
            .await
            .insert(key, session.clone());
        Ok(session)
    }
    async fn open_console(
        &self,
        _actor: &VerifiedActor,
        _unit_id: &str,
    ) -> Result<Box<dyn ConsoleSession>, ApiError> {
        Ok(Box::new(InMemoryConsole::default()))
    }
    async fn open_operation_stream(
        &self,
        _actor: &VerifiedActor,
        operation_id: &str,
    ) -> Result<Box<dyn OperationStreamPort>, ApiError> {
        Ok(Box::new(InMemoryOperationStream {
            events: VecDeque::from([OperationEvent {
                operation_id: operation_id.to_owned(),
                sequence: 1,
                status: "queued".into(),
                message: None,
                progress: Some(0),
            }]),
        }))
    }
    async fn health(&self) -> Result<Value, ApiError> {
        Ok(json!({"status":"healthy","backend":"in-memory"}))
    }
    fn files(&self) -> &dyn FilePort {
        &self.files
    }
}
fn in_scope(item: &ResourceDto, actor: &VerifiedActor) -> bool {
    let has_global_scope = actor.authorization.service_scopes.contains("*");
    match item.fields.get("service_key").and_then(Value::as_str) {
        Some(service) => has_global_scope || actor.authorization.service_scopes.contains(service),
        // A scoped actor cannot use an object with missing metadata as an
        // implicit global object. Only an explicitly global policy may see it.
        None => has_global_scope,
    }
}

#[derive(Default)]
struct InMemoryFiles {
    files: Mutex<BTreeMap<String, Vec<u8>>>,
}
#[async_trait]
impl FilePort for InMemoryFiles {
    async fn browse(
        &self,
        _: &VerifiedActor,
        _: &str,
        path: &str,
    ) -> Result<Vec<FileEntryDto>, ApiError> {
        let files = self.files.lock().await;
        Ok(files
            .keys()
            .filter(|p| p.starts_with(path) || path == ".")
            .map(|p| FileEntryDto {
                path: p.clone(),
                size: files[p].len() as u64,
                digest: crate::plan_hash(&files[p]),
                classification: "mutable_config".into(),
            })
            .collect())
    }
    async fn read(&self, _: &VerifiedActor, _: &str, path: &str) -> Result<FileReadDto, ApiError> {
        let bytes = self
            .files
            .lock()
            .await
            .get(path)
            .cloned()
            .ok_or(ApiError::NotFound)?;
        Ok(FileReadDto {
            path: path.into(),
            content_type: "application/octet-stream".into(),
            content: bytes,
        })
    }
    async fn download(
        &self,
        actor: &VerifiedActor,
        unit: &str,
        path: &str,
    ) -> Result<FileReadDto, ApiError> {
        self.read(actor, unit, path).await
    }
    async fn diff(&self, _: &VerifiedActor, _: &str, path: &str) -> Result<FileDiffDto, ApiError> {
        let bytes = self.files.lock().await.get(path).cloned();
        Ok(FileDiffDto {
            path: path.into(),
            before_digest: None,
            after_digest: bytes.as_deref().map(crate::plan_hash),
            changed: bytes.is_some(),
        })
    }
}
#[derive(Default)]
pub struct InMemoryConsole {
    inbound: VecDeque<ConsoleFrame>,
    sent: Vec<ConsoleFrame>,
}
impl InMemoryConsole {
    pub fn sent_frames(&self) -> &[ConsoleFrame] {
        &self.sent
    }
}
#[async_trait]
impl ConsoleSession for InMemoryConsole {
    async fn receive(&mut self) -> Result<Option<ConsoleFrame>, ApiError> {
        Ok(self.inbound.pop_front())
    }
    async fn send(&mut self, frame: ConsoleFrame) -> Result<(), ApiError> {
        self.sent.push(frame);
        Ok(())
    }
    async fn record(&mut self, _: ConsoleAuditEvent) -> Result<(), ApiError> {
        Ok(())
    }
    async fn close(&mut self) {}
}
struct InMemoryOperationStream {
    events: VecDeque<OperationEvent>,
}
#[async_trait]
impl OperationStreamPort for InMemoryOperationStream {
    async fn next(&mut self) -> Result<Option<OperationEvent>, ApiError> {
        Ok(self.events.pop_front())
    }
}
/// Test mapper proving that role/scope values come from the policy mapping, not JWT claims.
pub struct InMemoryIdentityMapper {
    pub actor_kind: ActorKind,
    pub role: Role,
    pub service_scopes: BTreeSet<String>,
    pub permissions: BTreeSet<Permission>,
}
#[async_trait]
impl IdentityMapper for InMemoryIdentityMapper {
    async fn map(&self, claims: &VerifiedClaims) -> Result<VerifiedActor, ApiError> {
        Ok(VerifiedActor {
            subject: claims.subject.clone(),
            email: claims.email.clone(),
            common_name: claims.common_name.clone(),
            kind: self.actor_kind,
            authorization: Authorization {
                role: self.role,
                permissions: self.permissions.clone(),
                service_scopes: self.service_scopes.clone(),
            },
        })
    }
}
/// A mapper granting all domain permissions for focused route-contract tests.
pub fn allow_all_mapper() -> Arc<InMemoryIdentityMapper> {
    Arc::new(InMemoryIdentityMapper {
        actor_kind: ActorKind::Browser,
        role: Role::PlatformAdmin,
        service_scopes: BTreeSet::from(["*".into()]),
        permissions: Permission::all().into_iter().collect(),
    })
}
