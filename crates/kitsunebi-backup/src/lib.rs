#![forbid(unsafe_code)]

//! Small, fail-closed HTTP adapter for an explicitly configured backup service.
//!
//! This crate does not store backup data. The provider owns backup creation,
//! verification, and restore semantics behind the contract documented in the
//! request/response types below.

use async_trait::async_trait;
use kitsunebi_application::{
    ApplicationError, BackupComponent, BackupProvider, BackupRequest, BackupRestoreInvocation,
    BackupRestoreRequest,
};
use kitsunebi_domain::{BackupObservation, BackupReference, BackupReferenceId, BackupTarget};
use reqwest::{Client, ClientBuilder, Method, Url};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;

const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_TEXT_BYTES: usize = 4096;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BackupError {
    #[error("backup provider configuration is invalid")]
    InvalidConfiguration,
    #[error("backup request value is invalid")]
    InvalidRequest,
    #[error("backup provider response is invalid")]
    InvalidResponse,
    #[error("backup provider response is too large")]
    ResponseTooLarge,
    #[error("backup provider returned HTTP status {0}")]
    HttpStatus(u16),
    #[error("backup provider transport failed")]
    Transport,
    #[error("backup provider verification failed")]
    VerificationFailed,
    #[error("backup provider idempotency key conflicts with an earlier request")]
    IdempotencyConflict,
    #[error("backup restore plan has expired")]
    PlanExpired,
    #[error("backup manifest digest does not match the restore plan")]
    DigestMismatch,
}

#[derive(Clone)]
pub struct BackupHttpProvider {
    client: Client,
    base_url: Url,
    bearer: String,
}

impl fmt::Debug for BackupHttpProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BackupHttpProvider")
            .field("base_url", &self.base_url)
            .field("bearer", &"[REDACTED]")
            .finish()
    }
}

impl BackupHttpProvider {
    /// Construct the production adapter. Only HTTPS deployment endpoints are
    /// accepted; redirects and credentials embedded in the URL are rejected.
    pub fn new(base_url: &str, bearer: impl Into<String>) -> Result<Self, BackupError> {
        Self::build(base_url, bearer.into(), false)
    }

    /// Construct an adapter for a task-owned localhost fixture. This is the
    /// only constructor that permits HTTP.
    pub fn new_localhost_for_tests(
        base_url: &str,
        bearer: impl Into<String>,
    ) -> Result<Self, BackupError> {
        Self::build(base_url, bearer.into(), true)
    }

    fn build(
        base_url: &str,
        bearer: String,
        allow_localhost_http: bool,
    ) -> Result<Self, BackupError> {
        if bearer.is_empty()
            || bearer.len() > MAX_TEXT_BYTES
            || bearer.chars().any(|character| character.is_control())
        {
            return Err(BackupError::InvalidConfiguration);
        }
        let url = Url::parse(base_url).map_err(|_| BackupError::InvalidConfiguration)?;
        let localhost = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1"));
        if !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || url.query().is_some()
            || url.host_str().is_none()
            || (!allow_localhost_http && url.scheme() != "https")
            || (allow_localhost_http && url.scheme() == "http" && !localhost)
            || (allow_localhost_http && !matches!(url.scheme(), "http" | "https"))
        {
            return Err(BackupError::InvalidConfiguration);
        }
        let client = ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|_| BackupError::InvalidConfiguration)?;
        Ok(Self {
            client,
            base_url: url,
            bearer,
        })
    }

    async fn request<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        method: Method,
        path: &str,
        body: &T,
    ) -> Result<R, BackupError> {
        self.request_with_idempotency(method, path, body, None)
            .await
    }

    async fn request_with_idempotency<T: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        method: Method,
        path: &str,
        body: &T,
        idempotency_key: Option<&str>,
    ) -> Result<R, BackupError> {
        let url = self
            .base_url
            .join(path)
            .map_err(|_| BackupError::InvalidConfiguration)?;
        let mut request = self
            .client
            .request(method, url)
            .bearer_auth(&self.bearer)
            .json(body);
        if let Some(key) = idempotency_key {
            request = request.header("Idempotency-Key", key);
        }
        let response = request.send().await.map_err(|_| BackupError::Transport)?;
        let status = response.status();
        let bytes = read_limited(response).await?;
        if !status.is_success() {
            return Err(if status.as_u16() == 409 && idempotency_key.is_some() {
                BackupError::IdempotencyConflict
            } else {
                BackupError::HttpStatus(status.as_u16())
            });
        }
        serde_json::from_slice(&bytes).map_err(|_| BackupError::InvalidResponse)
    }

    async fn create_provider(
        &self,
        request: &BackupRequest,
    ) -> Result<BackupReference, BackupError> {
        validate_text(request.kind.as_str())?;
        let target = target_wire(request.target);
        validate_text(&target)?;
        validate_idempotency_key(&request.idempotency_key)?;
        validate_text(&request.request_hash)?;
        validate_components(request.kind, request.target, &request.components)?;
        let response: CreateResponse = self
            .request_with_idempotency(
                Method::POST,
                "v1/backups",
                &CreateRequest {
                    kind: request.kind.as_str(),
                    target: &target,
                    components: &request.components,
                },
                Some(&request.idempotency_key),
            )
            .await?;
        validate_response_text(&response.provider)?;
        validate_response_text(&response.reference)?;
        validate_digest(&response.manifest_digest)?;
        if !response.verified {
            return Err(BackupError::VerificationFailed);
        }
        Ok(BackupReference {
            id: BackupReferenceId::new(),
            session_id: request.session_id,
            kind: request.kind,
            target: request.target,
            provider: response.provider,
            provider_reference: response.reference,
            manifest_digest: response.manifest_digest,
            verified_at: None,
            required: true,
        })
    }

    async fn verify_provider(
        &self,
        reference: &BackupReference,
    ) -> Result<BackupObservation, BackupError> {
        validate_text(&reference.provider_reference)?;
        validate_digest(&reference.manifest_digest)?;
        let response: VerifyResponse = self
            .request(
                Method::POST,
                "v1/backups/verify",
                &VerifyRequest {
                    reference: &reference.provider_reference,
                },
            )
            .await?;
        validate_digest(&response.manifest_digest)?;
        if !response.verified {
            return Err(BackupError::VerificationFailed);
        }
        BackupObservation::new(&response.manifest_digest, response.observed_at)
            .map_err(|_| BackupError::InvalidResponse)
    }

    async fn restore_provider(
        &self,
        request: &BackupRestoreRequest,
    ) -> Result<BackupRestoreInvocation, BackupError> {
        let reference = &request.reference;
        validate_text(&reference.provider_reference)?;
        validate_digest(&reference.manifest_digest)?;
        if request.plan_expiry <= now_unix() {
            return Err(BackupError::PlanExpired);
        }
        let plan_ref = request.plan_id;
        let target = target_wire(request.target);
        validate_text(&target)?;
        validate_idempotency_key(&request.idempotency_key)?;
        let response: RestoreApplyResponse = self
            .request_with_idempotency(
                Method::POST,
                "v1/restores/apply",
                &RestoreApplyRequest {
                    plan_ref: plan_ref.as_uuid().to_string(),
                    reference: &reference.provider_reference,
                    target: &target,
                    expected_manifest_digest: &reference.manifest_digest,
                    expires_at: request.plan_expiry,
                },
                Some(&request.idempotency_key),
            )
            .await?;
        validate_response_text(&response.invocation_ref)?;
        if !response.accepted {
            return Err(BackupError::VerificationFailed);
        }
        let provider_invocation = response.invocation_ref;
        Ok(BackupRestoreInvocation {
            plan_id: request.plan_id,
            reference_id: reference.id,
            target: request.target,
            expected_manifest_digest: reference.manifest_digest.clone(),
            rollback_reference_id: request.rollback_reference.id,
            expected_rollback_manifest_digest: request.rollback_reference.manifest_digest.clone(),
            provider_invocation,
        })
    }

    async fn verify_restore_provider(
        &self,
        invocation: &BackupRestoreInvocation,
        expected_manifest_digest: &str,
    ) -> Result<BackupObservation, BackupError> {
        if invocation.plan_id.as_uuid().is_nil() || invocation.reference_id.as_uuid().is_nil() {
            return Err(BackupError::InvalidRequest);
        }
        validate_text(&invocation.provider_invocation)?;
        validate_digest(expected_manifest_digest)?;
        let response: RestoreVerifyResponse = self
            .request(
                Method::POST,
                "v1/restores/verify",
                &RestoreVerifyRequest {
                    invocation_ref: &invocation.provider_invocation,
                },
            )
            .await?;
        validate_digest(&response.observed_manifest_digest)?;
        if !response.verified || response.observed_manifest_digest != expected_manifest_digest {
            return Err(BackupError::DigestMismatch);
        }
        BackupObservation::new(expected_manifest_digest, response.observed_at)
            .map_err(|_| BackupError::InvalidResponse)
    }
}

#[async_trait]
impl BackupProvider for BackupHttpProvider {
    async fn create(&self, request: &BackupRequest) -> Result<BackupReference, ApplicationError> {
        self.create_provider(request)
            .await
            .map_err(to_application_error)
    }

    async fn verify(
        &self,
        reference: &BackupReference,
    ) -> Result<BackupObservation, ApplicationError> {
        self.verify_provider(reference)
            .await
            .map_err(to_application_error)
    }

    async fn restore(
        &self,
        request: &BackupRestoreRequest,
    ) -> Result<BackupRestoreInvocation, ApplicationError> {
        if request.reference.session_id != request.session_id
            || request.reference.target != request.target
        {
            return Err(ApplicationError::Conflict("backup restore scope"));
        }
        self.restore_provider(request)
            .await
            .map_err(to_application_error)
    }

    async fn verify_restore(
        &self,
        invocation: &BackupRestoreInvocation,
    ) -> Result<BackupObservation, ApplicationError> {
        // The manifest is not accepted from a client-side invocation. The
        // application must compare this observation to its persisted plan
        // expectation before accepting the change session.
        self.verify_restore_provider(invocation, &invocation.expected_manifest_digest)
            .await
            .map_err(to_application_error)
    }
}

fn to_application_error(error: BackupError) -> ApplicationError {
    match error {
        BackupError::VerificationFailed => {
            ApplicationError::VerificationFailed("backup provider verification failed".into())
        }
        BackupError::DigestMismatch => {
            ApplicationError::VerificationFailed("backup manifest digest mismatch".into())
        }
        BackupError::PlanExpired => ApplicationError::ExpiredPlan,
        BackupError::IdempotencyConflict => ApplicationError::Conflict("backup idempotency key"),
        other => ApplicationError::Port(other.to_string()),
    }
}

fn target_wire(target: BackupTarget) -> String {
    match target {
        BackupTarget::Service(id) => format!("service:{}", id.as_uuid()),
        BackupTarget::Cluster(id) => format!("cluster:{}", id.as_uuid()),
        BackupTarget::World(id) => format!("world:{}", id.as_uuid()),
        BackupTarget::ExecutionUnit(id) => format!("execution-unit:{}", id.as_uuid()),
    }
}

fn validate_components(
    kind: kitsunebi_domain::BackupKind,
    target: BackupTarget,
    components: &[BackupComponent],
) -> Result<(), BackupError> {
    if kind != kitsunebi_domain::BackupKind::ServiceConsistent {
        if components.is_empty() {
            return Ok(());
        }
        return Err(BackupError::InvalidRequest);
    }
    if !matches!(target, BackupTarget::Service(_)) || components.is_empty() {
        return Err(BackupError::InvalidRequest);
    }
    let mut ids = std::collections::BTreeSet::new();
    let mut world_ids = std::collections::BTreeSet::new();
    let mut worlds = 0_u8;
    let mut databases = 0_u8;
    for component in components {
        if component.reference_id.as_uuid().is_nil()
            || !ids.insert(component.reference_id)
            || component.kind == kitsunebi_domain::BackupKind::ServiceConsistent
            || component.kind == kitsunebi_domain::BackupKind::ChangeSnapshot
        {
            return Err(BackupError::InvalidRequest);
        }
        validate_text(&component.provider_reference)?;
        validate_digest(&component.manifest_digest)?;
        match component.kind {
            kitsunebi_domain::BackupKind::World => {
                let BackupTarget::World(world_id) = component.target else {
                    return Err(BackupError::InvalidRequest);
                };
                if !world_ids.insert(world_id) {
                    return Err(BackupError::InvalidRequest);
                }
                worlds = worlds.saturating_add(1);
            }
            kitsunebi_domain::BackupKind::ExternalDatabaseReference => {
                if component.target != target {
                    return Err(BackupError::InvalidRequest);
                }
                databases = databases.saturating_add(1);
            }
            kitsunebi_domain::BackupKind::ServiceConsistent
            | kitsunebi_domain::BackupKind::ChangeSnapshot => unreachable!(),
        }
    }
    if worlds == 0 || databases != 1 {
        return Err(BackupError::InvalidRequest);
    }
    Ok(())
}

async fn read_limited(mut response: reqwest::Response) -> Result<Vec<u8>, BackupError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(BackupError::ResponseTooLarge);
    }
    let mut bytes = Vec::with_capacity(response.content_length().unwrap_or(0) as usize);
    while let Some(chunk) = response.chunk().await.map_err(|_| BackupError::Transport)? {
        if bytes.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(BackupError::ResponseTooLarge);
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn validate_text(value: &str) -> Result<(), BackupError> {
    if value.is_empty()
        || value.len() > MAX_TEXT_BYTES
        || value.chars().any(|character| character.is_control())
    {
        Err(BackupError::InvalidRequest)
    } else {
        Ok(())
    }
}

fn validate_idempotency_key(value: &str) -> Result<(), BackupError> {
    if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        Err(BackupError::InvalidRequest)
    } else {
        Ok(())
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn validate_response_text(value: &str) -> Result<(), BackupError> {
    validate_text(value).map_err(|_| BackupError::InvalidResponse)
}

fn validate_digest(value: &str) -> Result<(), BackupError> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(BackupError::InvalidResponse)
    }
}

#[derive(Serialize)]
struct CreateRequest<'a> {
    kind: &'a str,
    target: &'a str,
    components: &'a [BackupComponent],
}
#[derive(Deserialize)]
struct CreateResponse {
    provider: String,
    reference: String,
    manifest_digest: String,
    verified: bool,
}
#[derive(Serialize)]
struct VerifyRequest<'a> {
    reference: &'a str,
}
#[derive(Serialize)]
struct RestoreApplyRequest<'a> {
    plan_ref: String,
    reference: &'a str,
    target: &'a str,
    expected_manifest_digest: &'a str,
    expires_at: u64,
}
#[derive(Deserialize)]
struct RestoreApplyResponse {
    invocation_ref: String,
    accepted: bool,
}
#[derive(Serialize)]
struct RestoreVerifyRequest<'a> {
    invocation_ref: &'a str,
}
#[derive(Deserialize)]
struct RestoreVerifyResponse {
    observed_manifest_digest: String,
    observed_at: u64,
    verified: bool,
}
#[derive(Deserialize)]
struct VerifyResponse {
    manifest_digest: String,
    observed_at: u64,
    verified: bool,
}

#[cfg(test)]
mod contract_tests {
    use super::*;
    use kitsunebi_domain::{BackupKind, ChangeSessionId, PlanId, ServiceId, WorldId};
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::mpsc,
        thread,
    };

    fn server_sequence(
        responses: Vec<(&'static str, &'static str)>,
    ) -> (String, mpsc::Receiver<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let mut requests = Vec::new();
            for (body, status) in responses {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = vec![0_u8; 64 * 1024];
                let length = stream.read(&mut request).unwrap();
                requests.push(String::from_utf8_lossy(&request[..length]).into_owned());
                write!(
                    stream,
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .unwrap();
                stream.write_all(body.as_bytes()).unwrap();
            }
            sender.send(requests).unwrap();
        });
        (format!("http://{address}/"), receiver)
    }

    fn request() -> BackupRequest {
        BackupRequest {
            session_id: ChangeSessionId::new(),
            kind: BackupKind::World,
            target: BackupTarget::World(WorldId::new()),
            idempotency_key: "create-1".into(),
            request_hash: "a".repeat(64),
            components: vec![],
        }
    }

    fn service_request() -> BackupRequest {
        let session_id = ChangeSessionId::new();
        let service = BackupTarget::Service(ServiceId::new());
        BackupRequest {
            session_id,
            kind: BackupKind::ServiceConsistent,
            target: service,
            idempotency_key: "service-create-1".into(),
            request_hash: "b".repeat(64),
            components: vec![
                BackupComponent {
                    reference_id: BackupReferenceId::new(),
                    kind: BackupKind::World,
                    target: BackupTarget::World(WorldId::new()),
                    provider_reference: "world-ref".into(),
                    manifest_digest: "c".repeat(64),
                },
                BackupComponent {
                    reference_id: BackupReferenceId::new(),
                    kind: BackupKind::ExternalDatabaseReference,
                    target: service,
                    provider_reference: "db-ref".into(),
                    manifest_digest: "d".repeat(64),
                },
            ],
        }
    }

    fn reference(request: &BackupRequest) -> BackupReference {
        BackupReference {
            id: BackupReferenceId::new(),
            session_id: request.session_id,
            kind: request.kind,
            target: request.target,
            provider: "vault".into(),
            provider_reference: "ref-1".into(),
            manifest_digest: "a".repeat(64),
            verified_at: Some(now_unix()),
            required: true,
        }
    }

    #[test]
    fn production_url_and_secret_rules_are_fail_closed() {
        assert!(BackupHttpProvider::new("http://127.0.0.1:1", "secret").is_err());
        assert!(BackupHttpProvider::new("https://user@example.invalid", "secret").is_err());
        assert!(BackupHttpProvider::new("https://example.invalid/#x", "secret").is_err());
        assert!(
            BackupHttpProvider::new_localhost_for_tests("http://example.invalid", "secret")
                .is_err()
        );
        assert!(
            BackupHttpProvider::new_localhost_for_tests("http://127.0.0.1:1", "secret").is_ok()
        );
    }

    #[test]
    fn debug_redacts_bearer_secret() {
        let provider = BackupHttpProvider::new("https://example.invalid", "very-secret").unwrap();
        assert!(!format!("{provider:?}").contains("very-secret"));
        assert!(
            !BackupError::HttpStatus(500)
                .to_string()
                .contains("very-secret")
        );
    }

    #[tokio::test]
    async fn application_create_and_verify_use_typed_domain_values() {
        let request = request();
        let (base, _requests) = server_sequence(vec![(
            r#"{"provider":"vault","reference":"ref-1","manifest_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","verified":true}"#,
            "201 Created",
        )]);
        let provider =
            BackupHttpProvider::new_localhost_for_tests(&base, "provider-secret").unwrap();
        let backup = BackupProvider::create(&provider, &request).await.unwrap();
        assert_eq!(backup.session_id, request.session_id);
        assert_eq!(backup.kind, request.kind);
        assert_eq!(backup.target, request.target);
        assert_eq!(backup.provider_reference, "ref-1");
        assert!(backup.verified_at.is_none());
        let observed = r#"{"manifest_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","observed_at":42,"verified":true}"#;
        let (base, requests) = server_sequence(vec![(observed, "200 OK")]);
        let provider = BackupHttpProvider::new_localhost_for_tests(&base, "secret").unwrap();
        let observation = BackupProvider::verify(&provider, &backup).await.unwrap();
        assert_eq!(observation.manifest_digest, backup.manifest_digest);
        assert_eq!(observation.observed_at, 42);
        let request_dump = requests.recv().unwrap().pop().unwrap();
        assert!(request_dump.contains("POST /v1/backups/verify HTTP/1.1"));
    }

    #[tokio::test]
    async fn service_consistent_create_carries_exact_component_references() {
        let request = service_request();
        let (base, requests) = server_sequence(vec![(
            r#"{"provider":"vault","reference":"manifest-ref","manifest_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","verified":true}"#,
            "201 Created",
        )]);
        let provider = BackupHttpProvider::new_localhost_for_tests(&base, "secret").unwrap();
        BackupProvider::create(&provider, &request).await.unwrap();
        let request_dump = requests.recv().unwrap().pop().unwrap();
        assert!(request_dump.contains("service-consistent"));
        assert!(request_dump.contains("world-ref"));
        assert!(request_dump.contains("db-ref"));
        assert!(request_dump.contains(&"c".repeat(64)));
        assert!(request_dump.contains(&"d".repeat(64)));
    }

    #[tokio::test]
    async fn service_consistent_create_rejects_missing_components() {
        let mut request = service_request();
        request.components.clear();
        let provider =
            BackupHttpProvider::new_localhost_for_tests("http://127.0.0.1:1/", "secret").unwrap();
        assert!(matches!(
            BackupProvider::create(&provider, &request).await,
            Err(ApplicationError::Port(_))
        ));
    }

    #[tokio::test]
    async fn restore_apply_returns_invocation_for_later_verify() {
        let request = request();
        let primary_reference = reference(&request);
        let rollback_reference = reference(&request);
        let rollback_reference_id = rollback_reference.id;
        let rollback_manifest_digest = rollback_reference.manifest_digest.clone();
        let (base, requests) = server_sequence(vec![(
            r#"{"invocation_ref":"inv-1","accepted":true}"#,
            "200 OK",
        )]);
        let provider = BackupHttpProvider::new_localhost_for_tests(&base, "secret").unwrap();
        let invocation = BackupProvider::restore(
            &provider,
            &BackupRestoreRequest {
                session_id: request.session_id,
                plan_id: PlanId::new(),
                plan_expiry: now_unix() + 900,
                idempotency_key: "restore-1".into(),
                reference: primary_reference,
                rollback_reference,
                target: request.target,
            },
        )
        .await
        .unwrap();
        assert_eq!(invocation.rollback_reference_id, rollback_reference_id);
        assert_eq!(
            invocation.expected_rollback_manifest_digest,
            rollback_manifest_digest
        );
        let requests = requests.recv().unwrap();
        assert!(requests[0].contains("POST /v1/restores/apply HTTP/1.1"));
        assert!(
            requests[0]
                .to_ascii_lowercase()
                .contains("idempotency-key: restore-1")
        );
    }

    #[tokio::test]
    async fn restore_invocation_survives_crash_and_reobserves() {
        let request = request();
        let rollback_reference = reference(&request);
        let (base, _) = server_sequence(vec![(
            r#"{"invocation_ref":"inv-crash-safe","accepted":true}"#,
            "200 OK",
        )]);
        let provider = BackupHttpProvider::new_localhost_for_tests(&base, "secret").unwrap();
        let invocation = BackupProvider::restore(
            &provider,
            &BackupRestoreRequest {
                session_id: request.session_id,
                plan_id: PlanId::new(),
                plan_expiry: now_unix() + 900,
                idempotency_key: "restore-crash-safe".into(),
                reference: reference(&request),
                rollback_reference,
                target: request.target,
            },
        )
        .await
        .unwrap();

        // Recovery reconstructs the typed invocation from durable operation
        // evidence; verification is a separate provider observation.
        let recovered = BackupRestoreInvocation {
            plan_id: invocation.plan_id,
            reference_id: invocation.reference_id,
            target: invocation.target,
            expected_manifest_digest: invocation.expected_manifest_digest,
            rollback_reference_id: invocation.rollback_reference_id,
            expected_rollback_manifest_digest: invocation.expected_rollback_manifest_digest,
            provider_invocation: invocation.provider_invocation,
        };
        let (base, _) = server_sequence(vec![(
            r#"{"observed_manifest_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","observed_at":42,"verified":true}"#,
            "200 OK",
        )]);
        let provider = BackupHttpProvider::new_localhost_for_tests(&base, "secret").unwrap();
        let observation = BackupProvider::verify_restore(&provider, &recovered)
            .await
            .unwrap();
        assert_eq!(
            observation.manifest_digest,
            recovered.expected_manifest_digest
        );
        assert_eq!(observation.observed_at, 42);
    }

    #[tokio::test]
    async fn falsified_restore_observation_is_rejected() {
        let request = request();
        let rollback_reference = reference(&request);
        let (base, _) = server_sequence(vec![
            (r#"{"invocation_ref":"inv-1","accepted":true}"#, "200 OK"),
            (
                r#"{"observed_manifest_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","observed_at":42,"verified":true}"#,
                "200 OK",
            ),
        ]);
        let provider = BackupHttpProvider::new_localhost_for_tests(&base, "secret").unwrap();
        let result = BackupProvider::restore(
            &provider,
            &BackupRestoreRequest {
                session_id: request.session_id,
                plan_id: PlanId::new(),
                plan_expiry: now_unix() + 900,
                idempotency_key: "restore-2".into(),
                reference: reference(&request),
                rollback_reference,
                target: request.target,
            },
        )
        .await
        .unwrap();
        let result = BackupProvider::verify_restore(&provider, &result).await;
        assert!(matches!(
            result,
            Err(ApplicationError::VerificationFailed(_))
        ));
    }

    #[tokio::test]
    async fn unverified_create_and_conflict_are_fail_closed() {
        let request = request();
        let (base, _) = server_sequence(vec![(
            r#"{"provider":"vault","reference":"ref-1","manifest_digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","verified":false}"#,
            "200 OK",
        )]);
        let provider = BackupHttpProvider::new_localhost_for_tests(&base, "secret").unwrap();
        assert!(matches!(
            BackupProvider::create(&provider, &request).await,
            Err(ApplicationError::VerificationFailed(_))
        ));
        let (base, _) = server_sequence(vec![("{}", "409 Conflict")]);
        let provider = BackupHttpProvider::new_localhost_for_tests(&base, "secret").unwrap();
        assert!(matches!(
            BackupProvider::create(&provider, &request).await,
            Err(ApplicationError::Conflict(_))
        ));
    }
}
