use std::{
    collections::VecDeque,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};

use kitsunebi_gameap::{
    Cancellation, Capabilities, Capability, CapabilityDiagnostic, CapabilityState, Client,
    ConsoleMessage, ConsoleSocket, CreateExecutionRequest, GameApError, HttpRequest, HttpResponse,
    HttpTransport, Lifecycle, MetricsReconnectPolicy, PROCESS_MANAGER_PLUGIN_ID, ProcessManager,
    Secret, TransportError, WebSocketTransport, reconnect_metrics,
};
use serde_json::json;

#[derive(Clone)]
struct MockHttp {
    requests: Arc<Mutex<Vec<HttpRequest>>>,
    responses: Arc<Mutex<VecDeque<Result<HttpResponse, TransportError>>>>,
}

impl MockHttp {
    fn new(responses: impl IntoIterator<Item = Result<HttpResponse, TransportError>>) -> Self {
        Self {
            requests: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(responses.into_iter().collect())),
        }
    }
    fn requests(&self) -> Vec<HttpRequest> {
        self.requests.lock().expect("request lock").clone()
    }
}

impl HttpTransport for MockHttp {
    fn send(
        &self,
        request: HttpRequest,
    ) -> Pin<Box<dyn Future<Output = Result<HttpResponse, TransportError>> + Send + '_>> {
        self.requests.lock().expect("request lock").push(request);
        let response = self
            .responses
            .lock()
            .expect("response lock")
            .pop_front()
            .expect("response");
        Box::pin(async move { response })
    }
}

fn response(body: impl Into<Vec<u8>>) -> Result<HttpResponse, TransportError> {
    Ok(HttpResponse {
        status: 200,
        body: body.into(),
        request_id: Some("req-test".into()),
    })
}

fn http_response(status: u16, body: impl Into<Vec<u8>>) -> Result<HttpResponse, TransportError> {
    Ok(HttpResponse {
        status,
        body: body.into(),
        request_id: Some("req-test".into()),
    })
}

fn enabled_capabilities() -> Capabilities {
    Capabilities {
        version: Some("4.4.2".into()),
        diagnostics: vec![
            CapabilityDiagnostic {
                capability: Capability::ExecutionCreate,
                state: CapabilityState::Supported,
                code: "endpoint_probe_ok".into(),
                reason: "mock deployment assertion".into(),
                endpoint: Some("/api/servers".into()),
            },
            CapabilityDiagnostic {
                capability: Capability::ExecutionDelete,
                state: CapabilityState::Supported,
                code: "endpoint_probe_ok".into(),
                reason: "mock deployment assertion".into(),
                endpoint: Some("/api/servers/{id}".into()),
            },
            CapabilityDiagnostic {
                capability: Capability::Lifecycle,
                state: CapabilityState::Supported,
                code: "endpoint_probe_ok".into(),
                reason: "mock deployment assertion".into(),
                endpoint: Some("/api/servers/{server}/restart".into()),
            },
            CapabilityDiagnostic {
                capability: Capability::ProcessManager,
                state: CapabilityState::Unknown,
                code: "process_manager_not_public".into(),
                reason: "not in public schema".into(),
                endpoint: None,
            },
            CapabilityDiagnostic {
                capability: Capability::PlacementMutation,
                state: CapabilityState::Unknown,
                code: "placement_not_public".into(),
                reason: "not in public schema".into(),
                endpoint: None,
            },
        ],
    }
}

fn client(mock: MockHttp) -> Client<MockHttp> {
    Client::new(
        "https://panel.example.test",
        Secret::new("pat_secret"),
        mock,
    )
    .expect("valid client")
    .with_capabilities(enabled_capabilities())
}

#[tokio::test]
async fn server_lifecycle_uses_official_operations() {
    let mock = MockHttp::new([
        response(r#"{"message":"created","result":{"taskId":7,"serverId":6}}"#),
        response(r#"{"task_id":8}"#),
        response(r#"{"processActive":true}"#),
        response(Vec::<u8>::new()),
    ]);
    let client = client(mock.clone());
    let created = client
        .create_execution(&CreateExecutionRequest {
            name: "test".into(),
            ds_id: json!(1),
            game_id: "minecraft".into(),
            game_mod_id: json!(1),
            server_ip: "127.0.0.1".into(),
            server_port: json!(25565),
            query_port: None,
            rcon_port: None,
            rcon: None,
            dir: None,
            start_command: None,
            su_user: None,
            install: None,
        })
        .await
        .expect("create");
    assert_eq!(created.result.server_id, 6);
    client
        .lifecycle("6", Lifecycle::Restart)
        .await
        .expect("restart");
    assert!(client.status("6").await.expect("status").process_active);
    client.delete_execution("6").await.expect("delete");
    let requests = mock.requests();
    assert_eq!(requests[0].method, "POST");
    assert_eq!(requests[0].path, "/api/servers");
    assert_eq!(requests[1].path, "/api/servers/6/restart");
    assert!(requests[1].body.is_empty());
    assert_eq!(requests[2].path, "/api/servers/6/status");
    assert!(requests[2].body.is_empty());
    assert_eq!(requests[3].method, "DELETE");
    assert_eq!(requests[3].path, "/api/servers/6");
}

#[tokio::test]
async fn file_operations_use_file_manager_and_short_token_query() {
    let mock = MockHttp::new([
        response(r#"{"type":"file","content":"hello"}"#),
        response(r#"{"status":"ok"}"#),
        response(r#"{"status":"ok"}"#),
        response(r#"{"token":"glst_file_token","expires_in":10}"#),
        response(b"payload".to_vec()),
    ]);
    let client = client(mock.clone());
    assert_eq!(
        client
            .read_file("6", "config/server.properties")
            .await
            .expect("read"),
        "hello"
    );
    client
        .write_file("6", "config/server.properties", "new")
        .await
        .expect("write");
    client
        .move_file("6", "old.cfg", "new.cfg", "file")
        .await
        .expect("move");
    assert_eq!(
        client
            .download_file("6", "config/server.properties")
            .await
            .expect("download"),
        b"payload"
    );
    let requests = mock.requests();
    assert_eq!(
        requests[0].path,
        "/api/file-manager/6/content?path=config%2Fserver.properties"
    );
    assert_eq!(requests[0].method, "GET");
    assert!(requests[0].body.is_empty());
    assert_eq!(requests[1].path, "/api/file-manager/6/update-file");
    assert_eq!(requests[2].path, "/api/file-manager/6/rename");
    assert_eq!(requests[3].path, "/api/auth/short-lived-token");
    assert!(requests[3].body.is_empty());
    assert_eq!(
        requests[4].path,
        "/api/file-manager/6/download?path=config%2Fserver.properties&token=glst_file_token"
    );
    assert!(requests[4].authorization.is_empty());
}

#[tokio::test]
async fn quarantine_labels_are_mapped_to_the_public_file_rename_kind() {
    let mock = MockHttp::new([
        response(r#"{"status":"ok"}"#),
        response(r#"{"status":"ok"}"#),
    ]);
    let client = client(mock.clone());
    client
        .move_file(
            "6",
            "config/server.properties",
            ".kitsunebi-quarantine/a",
            "quarantine",
        )
        .await
        .expect("quarantine move");
    client
        .move_file(
            "6",
            ".kitsunebi-quarantine/a",
            "config/server.properties",
            "quarantine-restore",
        )
        .await
        .expect("quarantine restore");

    let requests = mock.requests();
    for request in requests {
        let body: serde_json::Value = serde_json::from_slice(&request.body).expect("rename JSON");
        assert_eq!(body["type"], "file");
        assert_ne!(body["type"], "quarantine");
    }
}

#[tokio::test]
async fn checked_move_uses_digest_cas_and_post_move_observations() {
    let mock = MockHttp::new([
        response(r#"{"type":"file","content":"hello"}"#),
        response(r#"{"token":"glst_source","expires_in":10}"#),
        response(b"hello".to_vec()),
        http_response(404, r#"{"error":"file not found"}"#),
        response(r#"{"status":"renamed"}"#),
        http_response(404, r#"{"error":"file not found"}"#),
        response(r#"{"type":"file","content":"hello"}"#),
        response(r#"{"token":"glst_destination","expires_in":10}"#),
        response(b"hello".to_vec()),
    ]);
    let client = client(mock.clone());
    let digest = kitsunebi_gameap::sha256_hex(b"hello");
    let destination = ".kitsunebi-quarantine/abc";
    let observation = client
        .move_file_checked("6", "config/server.properties", destination, &digest, None)
        .await
        .expect("checked move");

    assert_eq!(observation.moved_digest, digest);
    assert_eq!(observation.source_before.path, "config/server.properties");
    assert_eq!(
        observation.source_before.digest.as_deref(),
        Some(digest.as_str())
    );
    assert_eq!(observation.destination_before.path, destination);
    assert_eq!(observation.destination_before.digest, None);
    assert_eq!(observation.source.path, "config/server.properties");
    assert_eq!(observation.source.digest, None);
    assert_eq!(observation.destination.path, destination);
    assert_eq!(
        observation.destination.digest.as_deref(),
        Some(digest.as_str())
    );
    let requests = mock.requests();
    let rename: serde_json::Value = serde_json::from_slice(&requests[4].body).expect("rename JSON");
    assert_eq!(rename["type"], "file");
    assert_eq!(rename["oldName"], "config/server.properties");
    assert_eq!(rename["newName"], destination);
}

#[tokio::test]
async fn quarantine_file_moves_to_the_controller_owned_path_and_verifies_it() {
    let path = "config/server.properties";
    let quarantine = Client::<MockHttp>::quarantine_path(path).expect("quarantine path");
    let mock = MockHttp::new([
        response(r#"{"type":"file","content":"hello"}"#),
        response(r#"{"token":"glst_source_initial","expires_in":10}"#),
        response(b"hello".to_vec()),
        response(r#"{"type":"file","content":"hello"}"#),
        response(r#"{"token":"glst_source_cas","expires_in":10}"#),
        response(b"hello".to_vec()),
        http_response(404, r#"{"error":"file not found"}"#),
        response(r#"{"status":"renamed"}"#),
        http_response(404, r#"{"error":"file not found"}"#),
        response(r#"{"type":"file","content":"hello"}"#),
        response(r#"{"token":"glst_destination","expires_in":10}"#),
        response(b"hello".to_vec()),
    ]);
    let client = client(mock.clone());
    let result = client.quarantine_file("6", path).await.expect("quarantine");
    assert_eq!(result.source_before.path, path);
    assert_eq!(result.destination_before.path, quarantine);
    assert_eq!(result.destination.path, quarantine);
    assert_eq!(
        result.destination.digest.as_deref(),
        Some("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
    );
    let requests = mock.requests();
    let rename: serde_json::Value = serde_json::from_slice(&requests[7].body).expect("rename JSON");
    assert_eq!(rename["type"], "file");
    assert_eq!(rename["newName"], quarantine);
}

#[tokio::test]
async fn quarantine_path_and_reverse_move_are_deterministic() {
    let path = "config/server.properties";
    let quarantine = Client::<MockHttp>::quarantine_path(path).expect("quarantine path");
    assert_eq!(
        quarantine,
        format!(
            ".kitsunebi-quarantine/{}",
            kitsunebi_gameap::sha256_hex(path.as_bytes())
        )
    );
    assert!(Client::<MockHttp>::quarantine_path("../escape").is_err());

    let mock = MockHttp::new([
        response(r#"{"type":"file","content":"hello"}"#),
        response(r#"{"token":"glst_source","expires_in":10}"#),
        response(b"hello".to_vec()),
        http_response(404, r#"{"error":"file not found"}"#),
        response(r#"{"status":"renamed"}"#),
        http_response(404, r#"{"error":"file not found"}"#),
        response(r#"{"type":"file","content":"hello"}"#),
        response(r#"{"token":"glst_destination","expires_in":10}"#),
        response(b"hello".to_vec()),
    ]);
    let client = client(mock);
    let digest = kitsunebi_gameap::sha256_hex(b"hello");
    let observation = client
        .reverse_move_file_checked("6", &quarantine, path, &digest)
        .await
        .expect("reverse move");
    assert_eq!(observation.source_before.path, quarantine);
    assert_eq!(
        observation.source_before.digest.as_deref(),
        Some(digest.as_str())
    );
    assert_eq!(observation.destination_before.path, path);
    assert_eq!(observation.destination.path, path);
    assert_eq!(
        observation.destination.digest.as_deref(),
        Some(digest.as_str())
    );
}

#[tokio::test]
async fn upload_and_delete_use_official_file_manager_contract() {
    let mock = MockHttp::new([
        response(r#"{"status":"ok"}"#),
        response(r#"{"status":"ok"}"#),
    ]);
    let client = client(mock.clone());
    client
        .upload_file("6", "mods/a.jar", b"bytes")
        .await
        .expect("upload");
    client.delete_file("6", "mods/a.jar").await.expect("delete");

    let requests = mock.requests();
    assert_eq!(requests[0].method, "POST");
    assert_eq!(requests[0].path, "/api/file-manager/6/upload");
    assert_eq!(requests[0].authorization, "Bearer pat_secret");
    assert_eq!(
        requests[0].content_type.as_deref(),
        Some("multipart/form-data; boundary=kitsunebi-gameap")
    );
    let body = String::from_utf8_lossy(&requests[0].body);
    assert!(body.contains("name=\"file\""));
    assert!(body.contains("name=\"path\""));
    assert!(body.contains("mods/a.jar"));
    assert!(body.contains("bytes"));

    assert_eq!(requests[1].method, "POST");
    assert_eq!(requests[1].path, "/api/file-manager/6/delete");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&requests[1].body).expect("delete JSON"),
        json!({"items":["mods/a.jar"]})
    );
}

#[tokio::test]
async fn capability_probe_reports_read_operations_and_keeps_mutation_unknown() {
    let mock = MockHttp::new([
        response(r#"{"processActive":false}"#),
        response(r#"{"id":1,"name":"node","connection_type":"http","version":null}"#),
        response(r#"{"path":"/srv/game"}"#),
        response(
            r#"{"node_id":1,"process_manager":"systemd","evidence_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","version":"1","timestamp":1720000000}"#,
        ),
    ]);
    let client = client(mock);
    let capabilities = client.discover_capabilities("6", "1").await.expect("probe");
    assert_eq!(capabilities.version, None);
    assert_eq!(
        capabilities.state(Capability::StatusRead),
        CapabilityState::Supported
    );
    assert_eq!(
        capabilities.state(Capability::NodeStatusRead),
        CapabilityState::Supported
    );
    assert_eq!(
        capabilities.state(Capability::FileList),
        CapabilityState::Supported
    );
    assert_eq!(
        capabilities.state(Capability::ExecutionCreate),
        CapabilityState::Unknown
    );
    assert_eq!(
        capabilities.state(Capability::PlacementMutation),
        CapabilityState::Unknown
    );
    assert_eq!(
        capabilities.state(Capability::ProcessManager),
        CapabilityState::Supported
    );
}

#[tokio::test]
async fn process_manager_plugin_observation_is_typed_and_authenticated() {
    let mock = MockHttp::new([response(
        r#"{"node_id":42,"process_manager":"unknown","evidence_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","version":"1","timestamp":1720000000}"#,
    )]);
    let client = Client::new(
        "http://127.0.0.1:18080",
        Secret::new("pat_secret"),
        mock.clone(),
    )
    .expect("valid client");
    let observation = client
        .observe_process_manager(PROCESS_MANAGER_PLUGIN_ID, 42)
        .await
        .expect("observation");
    assert_eq!(observation.plugin_id, PROCESS_MANAGER_PLUGIN_ID);
    assert_eq!(observation.node_id, 42);
    assert_eq!(observation.process_manager, ProcessManager::Unknown);
    let requests = mock.requests();
    assert_eq!(requests[0].method, "POST");
    assert_eq!(requests[0].path, "/api/plugins/pmobserve2j7d/observe");
    assert_eq!(requests[0].authorization, "Bearer pat_secret");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&requests[0].body).expect("request JSON"),
        serde_json::json!({"node_id": 42})
    );
}

#[tokio::test]
async fn process_manager_plugin_response_is_strict_and_https_is_required() {
    let malformed = MockHttp::new([response(
        r#"{"node_id":42,"process_manager":"systemd","evidence_hash":"bad","version":"1","timestamp":1720000000,"secret":"leak"}"#,
    )]);
    let client = Client::new("https://panel.example.test", Secret::new("pat"), malformed)
        .expect("valid client");
    assert!(matches!(
        client
            .observe_process_manager(PROCESS_MANAGER_PLUGIN_ID, 42)
            .await,
        Err(GameApError::Decode(_))
    ));

    let local_only = Client::new(
        "http://panel.example.test",
        Secret::new("pat"),
        MockHttp::new([]),
    )
    .expect("valid client");
    assert!(matches!(
        local_only
            .observe_process_manager(PROCESS_MANAGER_PLUGIN_ID, 42)
            .await,
        Err(GameApError::Decode(_))
    ));
}

#[tokio::test]
async fn unknown_process_manager_observation_does_not_enable_mutation() {
    let mock = MockHttp::new([
        response(r#"{"processActive":false}"#),
        response(r#"{"id":1,"name":"node","connection_type":"http","version":null}"#),
        response(r#"{"path":"/srv/game"}"#),
        response(
            r#"{"node_id":1,"process_manager":"unknown","evidence_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","version":"1","timestamp":1720000000}"#,
        ),
    ]);
    let client =
        Client::new("https://panel.example.test", Secret::new("pat"), mock).expect("valid client");
    let capabilities = client.discover_capabilities("6", "1").await.expect("probe");
    assert_eq!(
        capabilities.state(Capability::ProcessManager),
        CapabilityState::Unknown
    );
    assert!(!capabilities.allows_mutation(Capability::ProcessManager));
}

#[tokio::test]
async fn capability_probe_rejects_an_overflowing_node_id() {
    let client = Client::new(
        "https://panel.example.test",
        Secret::new("pat"),
        MockHttp::new([]),
    )
    .expect("valid client");
    assert_eq!(
        client
            .discover_capabilities("6", "18446744073709551616")
            .await,
        Err(GameApError::InvalidPath)
    );
}

#[tokio::test]
async fn public_unknown_capabilities_fail_closed() {
    let mock = MockHttp::new([]);
    let client =
        Client::new("https://panel.example.test", Secret::new("pat"), mock).expect("valid client");
    let error = client
        .create_execution(&CreateExecutionRequest {
            name: "x".into(),
            ds_id: json!(1),
            game_id: "x".into(),
            game_mod_id: json!(1),
            server_ip: "127.0.0.1".into(),
            server_port: json!(1),
            query_port: None,
            rcon_port: None,
            rcon: None,
            dir: None,
            start_command: None,
            su_user: None,
            install: None,
        })
        .await
        .expect_err("unknown creation must fail");
    assert_eq!(error, GameApError::Unsupported(Capability::ExecutionCreate));
}

#[tokio::test]
async fn errors_are_mapped_without_secret_body() {
    let mock = MockHttp::new([Ok(HttpResponse {
        status: 429,
        body: b"{\"token\":\"glst_secret\"}".to_vec(),
        request_id: Some("r-429".into()),
    })]);
    let error = Client::new("https://panel.example.test", Secret::new("pat"), mock)
        .expect("valid client")
        .status("6")
        .await
        .expect_err("429");
    let GameApError::Http {
        status,
        body,
        request_id,
        ..
    } = error
    else {
        panic!("wrong error")
    };
    assert_eq!(status, 429);
    assert_eq!(request_id.as_deref(), Some("r-429"));
    assert!(!body.contains("glst_secret"));
}

#[derive(Clone, Default)]
struct MockWs {
    calls: Arc<Mutex<Vec<(String, String)>>>,
}
struct MockSocket {
    sent: Arc<Mutex<Vec<String>>>,
    next: Option<ConsoleMessage>,
}
impl ConsoleSocket for MockSocket {
    fn send_command(
        &mut self,
        command: String,
    ) -> Pin<Box<dyn Future<Output = Result<(), GameApError>> + Send + '_>> {
        let sent = self.sent.clone();
        Box::pin(async move {
            sent.lock().expect("sent lock").push(command);
            Ok(())
        })
    }
    fn next(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<ConsoleMessage>, GameApError>> + Send + '_>>
    {
        let next = self.next.take();
        Box::pin(async move { Ok(next) })
    }
}
impl WebSocketTransport for MockWs {
    fn connect(
        &self,
        url: String,
        token: Secret,
    ) -> Pin<Box<dyn Future<Output = Result<Box<dyn ConsoleSocket>, TransportError>> + Send + '_>>
    {
        self.calls
            .lock()
            .expect("calls lock")
            .push((url, token.expose().into()));
        Box::pin(async {
            Ok(Box::new(MockSocket {
                sent: Arc::new(Mutex::new(Vec::new())),
                next: Some(ConsoleMessage {
                    kind: "console.output".into(),
                    payload: json!({"chunk":"ok"}),
                    ts: None,
                }),
            }) as Box<dyn ConsoleSocket>)
        })
    }
}

#[tokio::test]
async fn console_uses_server_side_short_token_and_bidirectional_socket() {
    let http = MockHttp::new([response(r#"{"token":"glst_console","expires_in":10}"#)]);
    let client = client(http);
    let ws = MockWs::default();
    let mut socket = client.connect_console(&ws, "6").await.expect("console");
    socket.send_command("list".into()).await.expect("command");
    assert_eq!(
        socket.next().await.expect("stream").expect("message").kind,
        "console.output"
    );
    let calls = ws.calls.lock().expect("calls lock");
    assert_eq!(
        calls[0].0,
        "wss://panel.example.test/api/ws/servers/6/console"
    );
    assert_eq!(calls[0].1, "glst_console");
}

#[tokio::test]
async fn metrics_uses_official_server_socket_path() {
    let http = MockHttp::new([response(r#"{"token":"glst_metrics","expires_in":10}"#)]);
    let client = client(http);
    let ws = MockWs::default();
    let _socket = client.connect_metrics(&ws, "6").await.expect("metrics");
    let calls = ws.calls.lock().expect("calls lock");
    assert_eq!(
        calls[0].0,
        "wss://panel.example.test/api/ws/servers/6/metrics"
    );
    assert_eq!(calls[0].1, "glst_metrics");
}

#[derive(Clone)]
struct FlakyWs {
    calls: Arc<Mutex<Vec<(String, String)>>>,
    failures: Arc<Mutex<usize>>,
}

impl FlakyWs {
    fn new(failures: usize) -> Self {
        Self {
            calls: Arc::new(Mutex::new(Vec::new())),
            failures: Arc::new(Mutex::new(failures)),
        }
    }
}

impl WebSocketTransport for FlakyWs {
    fn connect(
        &self,
        url: String,
        token: Secret,
    ) -> Pin<Box<dyn Future<Output = Result<Box<dyn ConsoleSocket>, TransportError>> + Send + '_>>
    {
        self.calls
            .lock()
            .expect("calls lock")
            .push((url, token.expose().into()));
        let failures = self.failures.clone();
        Box::pin(async move {
            let mut remaining = failures.lock().expect("failure lock");
            if *remaining > 0 {
                *remaining -= 1;
                Err(TransportError::Unavailable)
            } else {
                Ok(Box::new(MockSocket {
                    sent: Arc::new(Mutex::new(Vec::new())),
                    next: None,
                }) as Box<dyn ConsoleSocket>)
            }
        })
    }
}

#[tokio::test]
async fn metrics_reconnect_mints_a_fresh_token_after_outage() {
    let http = MockHttp::new([
        response(r#"{"token":"glst_first","expires_in":10}"#),
        response(r#"{"token":"glst_second","expires_in":10}"#),
    ]);
    let client = client(http);
    let ws = FlakyWs::new(1);
    let cancellation = Cancellation::default();
    let socket = reconnect_metrics(
        &ws,
        client.base_url(),
        "6",
        &client,
        MetricsReconnectPolicy {
            initial_backoff: Duration::ZERO,
            max_backoff: Duration::ZERO,
            max_attempts: 2,
        },
        &cancellation,
    )
    .await
    .expect("reconnected metrics");
    drop(socket);
    let calls = ws.calls.lock().expect("calls lock");
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0].1, "glst_first");
    assert_eq!(calls[1].1, "glst_second");
    assert!(
        calls
            .iter()
            .all(|call| call.0.ends_with("/api/ws/servers/6/metrics"))
    );
}
