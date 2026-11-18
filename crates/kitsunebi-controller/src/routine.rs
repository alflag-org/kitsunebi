//! Routine lifecycle operations use the same persisted plans and evidence as
//! advanced changes. Preparation is separate so execution cannot change the
//! conditions the operator has confirmed.
use super::*;
use kitsunebi_api::dto::{LifecycleConfirmation, LifecyclePreview, LifecycleRequest};
use kitsunebi_domain::{ExecutionLifecycleAction, PlanStepAction};

fn lifecycle_action(
    action: kitsunebi_api::ExecutionLifecycleAction,
) -> (ExecutionLifecycleAction, ApiPermission, &'static str) {
    match action {
        kitsunebi_api::ExecutionLifecycleAction::Start => (
            ExecutionLifecycleAction::Start,
            ApiPermission::LifecycleStart,
            "Start the execution unit.",
        ),
        kitsunebi_api::ExecutionLifecycleAction::Stop => (
            ExecutionLifecycleAction::Stop,
            ApiPermission::LifecycleStop,
            "Stop the execution unit. Connected players will be disconnected.",
        ),
        kitsunebi_api::ExecutionLifecycleAction::Restart => (
            ExecutionLifecycleAction::Restart,
            ApiPermission::LifecycleRestart,
            "Restart the execution unit. Connected players will be disconnected.",
        ),
    }
}

impl MysqlManagement {
    async fn authorize_routine(
        &self,
        actor: &VerifiedActor,
        unit: &str,
        permission: ApiPermission,
    ) -> Result<ResolvedExecution, ApiError> {
        let resolved = self
            .files
            .resolve_execution(actor, unit, permission)
            .await?;
        for permission in [
            ApiPermission::ChangePlan,
            ApiPermission::ChangeApprove,
            ApiPermission::ChangeApply,
            ApiPermission::ChangeVerify,
            ApiPermission::ChangeAccept,
        ] {
            self.checker
                .authorize(actor, "execution-units", Some(unit), permission)
                .await?;
        }
        Ok(resolved)
    }

    pub(super) async fn prepare_routine(
        &self,
        actor: &VerifiedActor,
        unit: &str,
        input: LifecycleRequest,
        key: &str,
    ) -> Result<LifecyclePreview, ApiError> {
        let (action, permission, impact) = lifecycle_action(input.action);
        let resolved = self.authorize_routine(actor, unit, permission).await?;
        self.execution
            .require_capability(kitsunebi_gameap::Capability::Lifecycle)
            .map_err(application_error)?;
        let cluster = self
            .app
            .repository
            .cluster(resolved.cluster)
            .await
            .map_err(application_error)?;
        let revision_id = cluster.current_revision.ok_or(ApiError::Conflict)?;
        let revision = self
            .storage
            .get_revision(revision_id)
            .await
            .map_err(|_| ApiError::Backend)?
            .ok_or(ApiError::Conflict)?;
        let service = self
            .app
            .repository
            .service(resolved.service)
            .await
            .map_err(application_error)?;
        if service.current_cluster != Some(cluster.id) {
            return Err(ApiError::Conflict);
        }
        let status = self
            .execution
            .status(&resolved.binding)
            .await
            .map_err(application_error)?;
        let binding_id = self
            .app
            .steps
            .binding_id_for(&resolved.binding)
            .await
            .map_err(application_error)?;
        let request = ChangeRequest {
            actor: actor_id(actor)?,
            service: resolved.service,
            cluster: resolved.cluster,
            domain_revision: revision.number,
            idempotency_key: key.into(),
            steps: vec![
                PlanStep::new(PlanStepAction::ExecutionLifecycle {
                    binding_id,
                    action,
                    expected_binding_hash: resolved.binding.fingerprint(),
                    expected_state_hash: status.state_hash.clone(),
                    domain_revision: revision.number,
                })
                .map_err(|_| ApiError::Conflict)?,
            ],
            observed_state_hashes: vec![status.state_hash],
            expiry: now() + 300,
        };
        let coordinator = self.coordinator();
        let session = coordinator
            .begin(&request)
            .await
            .map_err(application_error)?;
        let plan = coordinator
            .plan_for_session(&request, session.id, session.version)
            .await
            .map_err(application_error)?;
        Ok(LifecyclePreview {
            session_id: session.id.as_uuid().to_string(),
            plan_id: plan.id.as_uuid().to_string(),
            plan_hash: plan.plan_hash,
            expires_at: plan.expiry,
            action: input.action,
            target_name: self.execution_label(&resolved).await?,
            running: status.running,
            impact: impact.into(),
        })
    }

    pub(super) async fn execution_label(
        &self,
        resolved: &ResolvedExecution,
    ) -> Result<String, ApiError> {
        let cluster = self
            .app
            .repository
            .cluster(resolved.cluster)
            .await
            .map_err(application_error)?;
        let service = self
            .app
            .repository
            .service(resolved.service)
            .await
            .map_err(application_error)?;
        let target = match resolved.binding.target {
            kitsunebi_domain::GameAPBindingTarget::World(id) => self
                .storage
                .get_world(id)
                .await
                .map_err(|_| ApiError::Backend)?
                .map(|v| v.display_name),
            kitsunebi_domain::GameAPBindingTarget::ProxyInstance(id) => self
                .storage
                .get_proxy_instance(id)
                .await
                .map_err(|_| ApiError::Backend)?
                .map(|v| v.key),
            _ => None,
        };
        Ok(format!(
            "{} / {}{}",
            service.display_name,
            cluster.key,
            target.map(|v| format!(" / {v}")).unwrap_or_default()
        ))
    }

    pub(super) async fn execute_routine(
        &self,
        actor: &VerifiedActor,
        session_id: &str,
        input: LifecycleConfirmation,
        key: &str,
        request_id: &str,
    ) -> Result<OperationDto, ApiError> {
        let session_id = Self::session_id(session_id)?;
        let actor_id = actor_id(actor)?;
        let session = self
            .app
            .repository
            .change_session_for_actor(session_id, actor_id)
            .await
            .map_err(application_error)?;
        let plan = self
            .plan_for_session(session_id, Self::plan_id(&input.plan_id)?)
            .await?;
        if plan.actor != actor_id
            || plan.plan_hash != input.plan_hash
            || plan.backup_requirements.required
        {
            return Err(ApiError::Conflict);
        }
        let [
            PlanStep {
                action:
                    PlanStepAction::ExecutionLifecycle {
                        binding_id,
                        action,
                        expected_binding_hash,
                        domain_revision,
                        ..
                    },
            },
        ] = plan.steps.as_slice()
        else {
            return Err(ApiError::InvalidRequest(
                "routine execution requires one lifecycle step",
            ));
        };
        let permission = match action {
            ExecutionLifecycleAction::Start => ApiPermission::LifecycleStart,
            ExecutionLifecycleAction::Stop => ApiPermission::LifecycleStop,
            ExecutionLifecycleAction::Restart => ApiPermission::LifecycleRestart,
        };
        let service = self.session_service(&session).await?;
        let binding = self
            .app
            .repository
            .gameap_binding(*binding_id, service, session.target_cluster)
            .await
            .map_err(application_error)?;
        let resolved = self
            .authorize_routine(actor, &binding.execution_unit_id, permission)
            .await?;
        if resolved.service != service
            || resolved.cluster != session.target_cluster
            || binding.fingerprint() != *expected_binding_hash
        {
            return Err(ApiError::Conflict);
        }
        let request = OperationRequest {
            key: key.into(),
            actor: actor_id,
            service,
            session_id,
            target: plan.target.stable_string(),
            request_hash: kitsunebi_api::plan_hash(
                format!("{}:{}", input.plan_id, input.plan_hash).as_bytes(),
            ),
        };
        // Check key reuse even when the plan already has a terminal operation.
        let same_request = self
            .app
            .operations
            .find_idempotent(&request)
            .await
            .map_err(application_error)?;
        let existing = match same_request {
            Some(value) => Some(value),
            None => self
                .app
                .operations
                .operation_for_plan(plan.id)
                .await
                .map_err(application_error)?,
        };
        let mut operation = if let Some(operation) = existing {
            operation
        } else {
            if plan.is_expired(now()) {
                return Err(ApiError::Conflict);
            }
            let cluster = self
                .app
                .repository
                .cluster(resolved.cluster)
                .await
                .map_err(application_error)?;
            let service_record = self
                .app
                .repository
                .service(service)
                .await
                .map_err(application_error)?;
            if service_record.current_cluster != Some(cluster.id) {
                return Err(ApiError::Conflict);
            }
            let revision = self
                .storage
                .get_revision(cluster.current_revision.ok_or(ApiError::Conflict)?)
                .await
                .map_err(|_| ApiError::Backend)?
                .ok_or(ApiError::Conflict)?;
            if revision.number != *domain_revision {
                return Err(ApiError::Conflict);
            }
            let coordinator = self.coordinator();
            if session.state == ChangeSessionState::Editing {
                coordinator
                    .ready(session_id, actor_id, service)
                    .await
                    .map_err(application_error)?;
            } else if session.state != ChangeSessionState::Ready {
                return Err(ApiError::Conflict);
            }
            self.app
                .execute_plan(&request, plan.id, now(), request_id)
                .await
                .map_err(application_error)?
        };
        if operation.state == OperationState::Verifying {
            operation = self
                .execution_workflow()
                .verify(operation.id, session_id, &plan, service, now(), request_id)
                .await
                .map_err(application_error)?;
        }
        if operation.state == OperationState::Verified {
            operation = self
                .execution_workflow()
                .accept(operation.id, session_id, now(), request_id)
                .await
                .map_err(application_error)?;
        }
        self.operation_dto(operation, request_id).await
    }
}
