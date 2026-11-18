use super::*;
use axum::{
    Json, Router,
    http::{StatusCode, Uri},
    routing::any,
};
use std::sync::Mutex;

struct Fixture {
    backend: GameApExecutionBackend,
    requests: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn fixture(failure: bool) -> Fixture {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let captured = requests.clone();
    let router = Router::new().fallback(any(move |uri: Uri| {
        let captured = captured.clone();
        async move {
            captured.lock().unwrap().push(uri.to_string());
            let (status, value) = if uri.path().contains("/plugins/") {
                (StatusCode::NOT_FOUND, json!({"error": "plugin absent"}))
            } else if uri.path().ends_with("/content") {
                if uri.query().is_some_and(|v| v.contains("selected.conf")) {
                    (
                        StatusCode::OK,
                        json!({"type":"file", "content":"selected=true\n"}),
                    )
                } else {
                    (
                        StatusCode::OK,
                        json!({"type":"directory", "items":[
                            {"name":"selected.conf", "type":"file", "size":14},
                            {"name":"large.jar", "type":"file", "size":5000000000u64},
                            {"name":"world", "type":"directory", "size":0}
                        ]}),
                    )
                }
            } else if failure {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json!({"error":"provider failed"}),
                )
            } else {
                (
                    StatusCode::OK,
                    json!({"status":"success", "processActive":true}),
                )
            };
            (status, Json(value))
        }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    let capabilities = Capabilities::with_operator_lifecycle_attestation(
        TrustedDeploymentAssertion {
            api_version: kitsunebi_gameap::SUPPORTED_VERSION.into(),
            allow_creation: false,
            allow_placement: false,
        },
        kitsunebi_gameap::OFFICIAL_SCHEMA_SHA256,
        LifecycleContractAttestation::Verified,
    );
    let client = GameApClient::new(
        &base,
        GameApSecret::new("fixture"),
        GameApHttpTransport::new(&base, GameApClientConfig::default()).unwrap(),
    )
    .unwrap()
    .with_capabilities(capabilities);
    Fixture {
        backend: GameApExecutionBackend::new(Arc::new(client)),
        requests,
        task,
    }
}
fn binding() -> GameAPBinding {
    GameAPBinding {
        execution_unit_id: "6".into(),
        node_id: "1".into(),
        target: GameAPBindingTarget::ExecutionUnit("6".into()),
    }
}

#[tokio::test]
async fn lifecycle_reaches_public_api_without_process_manager_plugin() {
    let fixture = fixture(false).await;
    fixture.backend.start(&binding()).await.unwrap();
    fixture.backend.stop(&binding()).await.unwrap();
    fixture.backend.restart(&binding()).await.unwrap();
    assert_eq!(
        *fixture.requests.lock().unwrap(),
        [
            "/api/servers/6/start",
            "/api/servers/6/stop",
            "/api/servers/6/restart"
        ]
    );
    assert!(
        fixture
            .backend
            .observe_node_capability(&binding())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn lifecycle_provider_failure_is_not_success() {
    let fixture = fixture(true).await;
    assert!(fixture.backend.start(&binding()).await.is_err());
    assert!(fixture.backend.stop(&binding()).await.is_err());
    assert!(fixture.backend.restart(&binding()).await.is_err());
}

#[tokio::test]
async fn listing_uses_metadata_and_read_fetches_only_selected_file() {
    let fixture = fixture(false).await;
    let entries = fixture.backend.files(&binding(), ".").await.unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[1].size, 5_000_000_000);
    assert!(entries[2].is_directory);
    assert_eq!(fixture.requests.lock().unwrap().len(), 1);
    assert_eq!(
        fixture
            .backend
            .read_file(&binding(), "selected.conf")
            .await
            .unwrap(),
        b"selected=true\n"
    );
    let requests = fixture.requests.lock().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests[1].contains("selected.conf"));
    assert!(requests.iter().all(|path| !path.contains("download")));
}

struct Deny;
#[async_trait]
impl Authorizer for Deny {
    async fn authorize(&self, _: &application::Authorization) -> Result<(), ApplicationError> {
        Err(ApplicationError::Forbidden)
    }
}
struct Audit;
#[async_trait]
impl AuditSink for Audit {
    async fn record(&self, _: kitsunebi_domain::AuditEvent) -> Result<(), ApplicationError> {
        Ok(())
    }
}

#[tokio::test]
async fn denied_lifecycle_never_reaches_gameap() {
    let fixture = fixture(false).await;
    let service = application::ExecutionService {
        backend: fixture.backend.clone(),
        authorizer: Deny,
        audit: Audit,
    };
    assert!(matches!(
        service
            .lifecycle(
                &binding(),
                kitsunebi_domain::LifecycleDecision::Start,
                ActorId::new(),
                ServiceId::new()
            )
            .await,
        Err(ApplicationError::Forbidden)
    ));
    assert!(fixture.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn missing_connection_observer_cannot_prove_drained() {
    assert!(
        ConfiguredConnectionObserver::Unavailable
            .observe("127.0.0.1:25565")
            .await
            .is_err()
    );
}

struct Allow;
#[async_trait]
impl Authorizer for Allow {
    async fn authorize(&self, _: &application::Authorization) -> Result<(), ApplicationError> {
        Ok(())
    }
}

#[tokio::test]
async fn stale_file_write_reads_only_target_and_never_mutates() {
    let fixture = fixture(false).await;
    let service = application::ExecutionService {
        backend: fixture.backend.clone(),
        authorizer: Allow,
        audit: Audit,
    };
    let bytes = b"replacement=true\n".to_vec();
    let result = service
        .write(
            &binding(),
            &application::FileMutation {
                change: FileChange {
                    path: "selected.conf".into(),
                    content_digest: kitsunebi_gameap::sha256_hex(&bytes),
                    classification: FileClassification::MutableConfig,
                },
                bytes,
                expected_before: Some("f".repeat(64)),
                mode: application::FileMutationMode::Text,
            },
            ActorId::new(),
            ServiceId::new(),
        )
        .await;
    assert!(matches!(result, Err(ApplicationError::StalePlan)));
    let requests = fixture.requests.lock().unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].contains("selected.conf"));
}
