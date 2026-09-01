use crate::{
    auth::{AccessClaims, AccessConfig, Authenticator, StaticJwks},
    dto::safe_content_disposition,
    error::ApiError,
    openapi::openapi_document,
    ports::{ActorKind, ConsoleSession, ManagementApi, Role, StageContentRequest},
    router,
    security::{
        DangerRateLimiter, HmacCsrfValidator, LocalAuthConfig, RuntimeEnvironment, SecurityConfig,
        StaticCsrfValidator, check_state_change, validate_archive_entries, validate_content_type,
        validate_local_auth, validate_relative_path,
    },
    testing::{InMemoryConsole, InMemoryManagementApi},
};
use axum::{
    body::Body,
    http::{HeaderMap, HeaderValue, Request},
    response::IntoResponse,
};
use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::json;
use std::{
    collections::BTreeSet,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;
use tower::ServiceExt;

const TEST_PRIVATE_KEY: &[u8] = include_bytes!("test_rsa_private.pem");
const TEST_MODULUS: &str = concat!(
    "yRE6rHuNR0QbHO3H3Kt2pOKGVhQqGZXInOduQNxXzuKlvQTLUTv4l4sggh5_CYYi_cvI-SXVT9kPWSKX",
    "xJXBXd_4LkvcPuUakBoAkfh-eiFVMh2VrUyWyj3MFl0HTVF9KwRXLAcwkREiS3npThHRyIxuy0ZMeZfx",
    "VL5arMhw1SRELB8HoGfG_AtH89BIE9jDBHZ9dLelK9a184zAf8LwoPLxvJb3Il5nncqPcSfKDDodMFBI",
    "Mc4lQzDKL5gvmiXLXB1AGLm8KBjfE8s3L5xqi-yUod-j8MtvIj812dkS4QMiRVN_by2h3ZY8LYVGrqZX",
    "ZTcgn2ujn8uKjXLZVD5TdQ"
);

fn jwk() -> Jwk {
    jwk_with_kid("rsa01")
}
fn jwk_with_kid(kid: &str) -> Jwk {
    serde_json::from_value(
        json!({"kty":"RSA","n":TEST_MODULUS,"e":"AQAB","kid":kid,"alg":"RS256","use":"sig"}),
    )
    .unwrap()
}
fn config() -> AccessConfig {
    AccessConfig::for_team_domain("https://team.cloudflareaccess.com", "test-aud").unwrap()
}
fn mapper() -> Arc<crate::testing::InMemoryIdentityMapper> {
    crate::testing::allow_all_mapper()
}
fn security_with_limits(body_limit: usize, upload_limit: usize) -> Arc<SecurityConfig> {
    Arc::new(SecurityConfig {
        allowed_origins: BTreeSet::from(["https://panel.example".into()]),
        csrf: Arc::new(StaticCsrfValidator::new("csrf")),
        body_limit,
        upload_limit,
        dangerous_rate_limit: 10,
        dangerous_rate_window: Duration::from_secs(60),
        environment: RuntimeEnvironment::Development,
        local_auth: LocalAuthConfig::default(),
    })
}
fn security() -> Arc<SecurityConfig> {
    security_with_limits(1024 * 1024, 1024 * 1024)
}
fn authenticator() -> Arc<Authenticator> {
    Arc::new(
        Authenticator::new(
            config(),
            Arc::new(StaticJwks::new(JwkSet { keys: vec![jwk()] })),
            mapper(),
        )
        .unwrap(),
    )
}

#[cfg(feature = "local-auth")]
#[tokio::test]
async fn local_auth_maps_only_canonical_subject() {
    let auth = Authenticator::local(mapper());
    let subject = "123e4567-e89b-12d3-a456-426614174000";
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-kitsunebi-local-subject",
        HeaderValue::from_static(subject),
    );
    headers.insert(
        "x-kitsunebi-local-role",
        HeaderValue::from_static("platform-admin"),
    );
    let actor = auth.authenticate(&headers).await.unwrap();
    assert_eq!(actor.subject, subject);
    assert_eq!(
        auth.authenticate(&HeaderMap::new()).await,
        Err(ApiError::Unauthorized)
    );

    for value in [
        "123E4567-e89b-12d3-a456-426614174000",
        "123e4567-e89b-12d3-a456-42661417400",
        "not-a-uuid",
        " 123e4567-e89b-12d3-a456-426614174000",
        "123e4567-e89b-12d3-a456-426614174000-extra",
    ] {
        let mut invalid = HeaderMap::new();
        invalid.insert("x-kitsunebi-local-subject", value.parse().unwrap());
        assert_eq!(
            auth.authenticate(&invalid).await,
            Err(ApiError::Unauthorized)
        );
    }
}

#[cfg(feature = "local-auth")]
#[tokio::test]
async fn local_auth_rejects_ambiguous_and_access_headers() {
    let auth = Authenticator::local(mapper());
    let subject = HeaderValue::from_static("123e4567-e89b-12d3-a456-426614174000");
    let mut duplicate = HeaderMap::new();
    duplicate.append("x-kitsunebi-local-subject", subject.clone());
    duplicate.append("x-kitsunebi-local-subject", subject.clone());
    assert_eq!(
        auth.authenticate(&duplicate).await,
        Err(ApiError::Unauthorized)
    );

    let mut mixed = HeaderMap::new();
    mixed.insert("x-kitsunebi-local-subject", subject);
    mixed.insert("cf-access-jwt-assertion", HeaderValue::from_static("token"));
    assert_eq!(auth.authenticate(&mixed).await, Err(ApiError::Unauthorized));

    let access = authenticator();
    let mut local_on_access = HeaderMap::new();
    local_on_access.insert(
        "x-kitsunebi-local-subject",
        HeaderValue::from_static("123e4567-e89b-12d3-a456-426614174000"),
    );
    assert_eq!(
        access.authenticate(&local_on_access).await,
        Err(ApiError::Unauthorized)
    );
}
fn signed(claims: AccessClaims, algorithm: Algorithm) -> String {
    signed_with_kid(claims, algorithm, "rsa01")
}
fn signed_with_kid(claims: AccessClaims, algorithm: Algorithm, kid: &str) -> String {
    let mut header = Header::new(algorithm);
    header.kid = Some(kid.into());
    let key = if algorithm == Algorithm::RS256 {
        EncodingKey::from_rsa_pem(TEST_PRIVATE_KEY).unwrap()
    } else {
        EncodingKey::from_secret(b"test-only-secret")
    };
    encode(&header, &claims, &key).unwrap()
}
fn claims(audience: serde_json::Value) -> AccessClaims {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    AccessClaims {
        iss: "https://team.cloudflareaccess.com".into(),
        aud: audience,
        sub: "actor-1".into(),
        exp: now + 3600,
        nbf: None,
        iat: Some(now),
        email: Some("actor@example.invalid".into()),
        common_name: Some("actor".into()),
    }
}

#[derive(Clone)]
struct RefreshOnlyJwks {
    calls: Arc<Mutex<Vec<bool>>>,
    key: Jwk,
    fail_refresh: bool,
}

#[async_trait::async_trait]
impl crate::JwksProvider for RefreshOnlyJwks {
    async fn key(&self, _kid: &str, force_refresh: bool) -> Result<Option<Jwk>, ApiError> {
        self.calls.lock().await.push(force_refresh);
        if force_refresh && self.fail_refresh {
            return Err(ApiError::Unauthorized);
        }
        if force_refresh {
            Ok(Some(self.key.clone()))
        } else {
            Ok(None)
        }
    }
}

#[tokio::test]
async fn access_accepts_valid_rs256_and_maps_identity() {
    let token = signed(claims(json!(["test-aud"])), Algorithm::RS256);
    let auth = Authenticator::new(
        config(),
        Arc::new(StaticJwks::new(JwkSet { keys: vec![jwk()] })),
        mapper(),
    )
    .unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(
        "cf-access-jwt-assertion",
        HeaderValue::from_str(&token).unwrap(),
    );
    let actor = auth.authenticate(&headers).await.unwrap();
    assert_eq!(actor.subject, "actor-1");
    assert_eq!(actor.authorization.role, Role::PlatformAdmin);
}
#[tokio::test]
async fn access_accepts_a_rotated_kid_without_trusting_jwt_authorization_claims() {
    let keys = Arc::new(StaticJwks::new(JwkSet { keys: vec![jwk()] }));
    let auth = Authenticator::new(config(), keys.clone(), mapper()).unwrap();
    let first = signed(claims(json!("test-aud")), Algorithm::RS256);
    auth.authenticate(&one_header(first)).await.unwrap();

    keys.replace(JwkSet {
        keys: vec![jwk_with_kid("rsa02")],
    })
    .await;
    let rotated = signed_with_kid(claims(json!("test-aud")), Algorithm::RS256, "rsa02");
    let actor = auth.authenticate(&one_header(rotated)).await.unwrap();
    assert_eq!(actor.authorization.role, Role::PlatformAdmin);
    assert!(actor.authorization.service_scopes.contains("*"));
}
#[tokio::test]
async fn access_rejects_wrong_issuer_audience_algorithm_kid_expiry_and_nbf() {
    let auth = Authenticator::new(
        config(),
        Arc::new(StaticJwks::new(JwkSet { keys: vec![jwk()] })),
        mapper(),
    )
    .unwrap();
    for (c, alg) in [
        (claims(json!(["other"])), Algorithm::RS256),
        (claims(json!(["test-aud"])), Algorithm::HS256),
    ] {
        assert!(matches!(
            auth.authenticate(&one_header(signed(c, alg))).await,
            Err(ApiError::Unauthorized)
        ));
    }
    let mut c = claims(json!(["test-aud"]));
    c.iss = "https://other.example".into();
    assert!(
        auth.authenticate(&one_header(signed(c, Algorithm::RS256)))
            .await
            .is_err()
    );
    let mut c = claims(json!(["test-aud"]));
    c.exp = 1;
    assert!(
        auth.authenticate(&one_header(signed(c, Algorithm::RS256)))
            .await
            .is_err()
    );
    let mut c = claims(json!(["test-aud"]));
    c.nbf = Some(u64::MAX);
    assert!(
        auth.authenticate(&one_header(signed(c, Algorithm::RS256)))
            .await
            .is_err()
    );
    let mut c = claims(json!(["test-aud"]));
    c.iat = None;
    assert!(
        auth.authenticate(&one_header(signed(c, Algorithm::RS256)))
            .await
            .is_err()
    );
    let mut h = one_header(signed(claims(json!(["test-aud"])), Algorithm::RS256));
    h.insert(
        "cf-access-jwt-assertion",
        HeaderValue::from_static("eyJhbGciOiJSUzI1NiIsImtpZCI6Im1pc3NpbmcifQ.e30.invalid"),
    );
    assert!(auth.authenticate(&h).await.is_err());
}

#[tokio::test]
async fn unknown_kid_gets_one_forced_refresh_without_expired_fallback() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let auth = Authenticator::new(
        config(),
        Arc::new(RefreshOnlyJwks {
            calls: calls.clone(),
            key: jwk(),
            fail_refresh: false,
        }),
        mapper(),
    )
    .unwrap();
    let token = signed(claims(json!(["test-aud"])), Algorithm::RS256);
    auth.authenticate(&one_header(token)).await.unwrap();
    assert_eq!(*calls.lock().await, vec![false, true]);

    let failed = Authenticator::new(
        config(),
        Arc::new(RefreshOnlyJwks {
            calls: Arc::new(Mutex::new(Vec::new())),
            key: jwk(),
            fail_refresh: true,
        }),
        mapper(),
    )
    .unwrap();
    assert!(matches!(
        failed
            .authenticate(&one_header(signed(
                claims(json!(["test-aud"])),
                Algorithm::RS256
            )))
            .await,
        Err(ApiError::Unauthorized)
    ));
}
fn one_header(token: String) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(
        "cf-access-jwt-assertion",
        HeaderValue::from_str(&token).unwrap(),
    );
    h
}
#[test]
fn path_and_filename_validation_rejects_traversal() {
    for path in [
        "../secret",
        "a/../../secret",
        "%252e%252e/secret",
        "a\\b",
        "a\0b",
        "/absolute",
    ] {
        assert!(validate_relative_path(path).is_err(), "{path:?}");
    }
    assert!(safe_content_disposition("a\r\nX-Evil: yes").is_err());
    assert!(safe_content_disposition("../../safe.txt").is_ok());
    assert!(validate_archive_entries([("configs/server.properties", false)]).is_ok());
    assert!(validate_archive_entries([("configs/link", true)]).is_err());
    assert!(validate_archive_entries([("%252e%252e/secrets", false)]).is_err());
    assert!(validate_content_type("application/json").is_ok());
    assert!(validate_content_type("text/plain\r\nX-Leak: yes").is_err());
}
#[tokio::test]
async fn origin_csrf_and_actor_rate_limit_are_enforced() {
    let security = SecurityConfig {
        allowed_origins: BTreeSet::from(["https://panel.example".into()]),
        csrf: Arc::new(StaticCsrfValidator::new("csrf")),
        body_limit: 1024,
        upload_limit: 1024,
        dangerous_rate_limit: 1,
        dangerous_rate_window: Duration::from_secs(60),
        environment: RuntimeEnvironment::Development,
        local_auth: LocalAuthConfig::default(),
    };
    let mut actor = crate::testing::InMemoryManagementApi::actor();
    actor.kind = ActorKind::Browser;
    let mut headers = HeaderMap::new();
    headers.insert("origin", HeaderValue::from_static("https://panel.example"));
    headers.insert("x-csrf-token", HeaderValue::from_static("csrf"));
    check_state_change(&security, &headers, &actor)
        .await
        .unwrap();
    headers.insert("origin", HeaderValue::from_static("https://evil.example"));
    assert!(
        check_state_change(&security, &headers, &actor)
            .await
            .is_err()
    );
    actor.kind = ActorKind::Service;
    headers.remove("origin");
    headers.remove("x-csrf-token");
    assert!(
        check_state_change(&security, &headers, &actor)
            .await
            .is_ok()
    );
    headers.insert("origin", HeaderValue::from_static("https://panel.example"));
    assert!(
        check_state_change(&security, &headers, &actor)
            .await
            .is_err()
    );
    headers.remove("origin");
    let limiter = DangerRateLimiter::default();
    limiter
        .check(&actor, 1, Duration::from_secs(60))
        .await
        .unwrap();
    assert!(
        limiter
            .check(&actor, 1, Duration::from_secs(60))
            .await
            .is_err()
    );
}

#[test]
fn hmac_csrf_tokens_are_actor_bound_and_expire() {
    let provider = HmacCsrfValidator::new([7_u8; 32], Duration::from_secs(60)).unwrap();
    let actor = InMemoryManagementApi::actor();
    let mut other = actor.clone();
    other.subject = "actor-2".into();
    let token = provider.issue_at(&actor, 1_000).unwrap();

    assert!(provider.verify_at(&actor, &token, 1_000));
    assert!(provider.verify_at(&actor, &token, 1_059));
    assert!(!provider.verify_at(&actor, &token, 1_060));
    assert!(!provider.verify_at(&other, &token, 1_000));
    for malformed in [
        "",
        "v2.1060.0000000000000000000000000000000000000000000000000000000000000000",
        "v1.1060.not-hex",
        "v1.01060.0000000000000000000000000000000000000000000000000000000000000000",
        "v1.1060.0000000000000000000000000000000000000000000000000000000000000000.extra",
    ] {
        assert!(!provider.verify_at(&actor, malformed, 1_000), "{malformed}");
    }
    assert!(HmacCsrfValidator::new([7_u8; 31], Duration::from_secs(60)).is_err());
    assert!(HmacCsrfValidator::new([7_u8; 32], Duration::ZERO).is_err());
}

#[tokio::test]
async fn session_route_issues_csrf_only_to_browser_with_allowed_origin() {
    let api = Arc::new(InMemoryManagementApi::default());
    let app = router(api, authenticator(), security()).unwrap();
    let token = signed(claims(json!("test-aud")), Algorithm::RS256);
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/session")
                .header("cf-access-jwt-assertion", token)
                .header("origin", "https://panel.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let session: crate::SessionDto = serde_json::from_slice(&body).unwrap();
    assert_eq!(session.csrf_token, "csrf");
}

#[tokio::test]
async fn metrics_route_and_openapi_use_get() {
    let app = router(
        Arc::new(InMemoryManagementApi::default()),
        authenticator(),
        security(),
    )
    .unwrap();
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    assert_eq!(
        response.headers()["content-type"],
        "text/plain; version=0.0.4"
    );
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&body).contains("kitsunebi_api_up 1"));

    let metrics = &openapi_document()["paths"]["/metrics"];
    assert!(metrics["get"].is_object());
    assert!(metrics.get("post").is_none());
}

#[tokio::test]
async fn session_route_denies_service_actor_and_wrong_origin() {
    let service_mapper = Arc::new(crate::testing::InMemoryIdentityMapper {
        actor_kind: ActorKind::Service,
        role: crate::Role::PlatformAdmin,
        service_scopes: BTreeSet::from(["*".into()]),
        permissions: crate::Permission::all().into_iter().collect(),
    });
    let service_auth = Arc::new(
        Authenticator::new(
            config(),
            Arc::new(StaticJwks::new(JwkSet { keys: vec![jwk()] })),
            service_mapper,
        )
        .unwrap(),
    );
    let service_response = router(
        Arc::new(InMemoryManagementApi::default()),
        service_auth,
        security(),
    )
    .unwrap()
    .oneshot(
        Request::builder()
            .method("POST")
            .uri("/api/v1/session")
            .header(
                "cf-access-jwt-assertion",
                signed(claims(json!("test-aud")), Algorithm::RS256),
            )
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(service_response.status(), axum::http::StatusCode::FORBIDDEN);

    let browser_response = router(
        Arc::new(InMemoryManagementApi::default()),
        authenticator(),
        security(),
    )
    .unwrap()
    .oneshot(
        Request::builder()
            .method("POST")
            .uri("/api/v1/session")
            .header(
                "cf-access-jwt-assertion",
                signed(claims(json!("test-aud")), Algorithm::RS256),
            )
            .header("origin", "https://evil.example")
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(browser_response.status(), axum::http::StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn session_get_does_not_issue_csrf_tokens() {
    let app = router(
        Arc::new(InMemoryManagementApi::default()),
        authenticator(),
        security(),
    )
    .unwrap();
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/v1/session")
                .header(
                    "cf-access-jwt-assertion",
                    signed(claims(json!("test-aud")), Algorithm::RS256),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        axum::http::StatusCode::METHOD_NOT_ALLOWED
    );
}

#[tokio::test]
async fn service_scope_is_resolved_from_object_metadata_and_replay_is_idempotent() {
    let api = InMemoryManagementApi::default();
    api.insert("services", "allowed", json!({"service_key":"alpha"}))
        .await;
    api.insert("services", "hidden", json!({"service_key":"beta"}))
        .await;
    let mut actor = InMemoryManagementApi::actor();
    actor.authorization.service_scopes = BTreeSet::from(["alpha".to_owned()]);
    let visible = api.list("services", &actor).await.unwrap();
    assert_eq!(
        visible
            .iter()
            .map(|item| item.id.as_str())
            .collect::<Vec<_>>(),
        ["allowed"]
    );
    assert!(matches!(
        api.get("services", "hidden", &actor).await,
        Err(ApiError::NotFound)
    ));
    assert!(matches!(
        api.authorize(
            &actor,
            "services",
            Some("hidden"),
            crate::Permission::ServiceRead
        )
        .await,
        Err(ApiError::NotFound)
    ));

    let payload = crate::MutationPayload::ChangeApply(crate::ChangeApplyPayload {
        session_id: "session-1".into(),
        plan_id: "plan-1".into(),
    });
    let request = crate::MutationRequest {
        command: crate::MutationCommand::Apply,
        action: crate::MutationAction::Change,
        request_hash: crate::plan_hash(&serde_json::to_vec(&payload).unwrap()),
        expires_at: unix_now_for_test() + 300,
        target_revision: None,
        payload,
    };
    let context = crate::MutationContext {
        actor: actor.clone(),
        idempotency_key: "same-request".into(),
        if_match: request.request_hash.clone(),
        session_version: None,
        request_hash: request.request_hash.clone(),
        expires_at: request.expires_at,
        request_id: "req-1".into(),
    };
    let first = api
        .mutate(
            "services",
            Some("allowed"),
            request.clone(),
            context.clone(),
        )
        .await
        .unwrap();
    let replay = api
        .mutate("services", Some("allowed"), request.clone(), context)
        .await
        .unwrap();
    assert_eq!(first, replay);
    let mut changed = request;
    changed.request_hash = crate::plan_hash(b"different");
    let changed_request_hash = changed.request_hash.clone();
    let changed_expires_at = changed.expires_at;
    assert!(matches!(
        api.mutate(
            "services",
            Some("allowed"),
            changed,
            crate::MutationContext {
                actor,
                idempotency_key: "same-request".into(),
                if_match: changed_request_hash.clone(),
                session_version: None,
                request_hash: changed_request_hash,
                expires_at: changed_expires_at,
                request_id: "req-2".into(),
            },
        )
        .await,
        Err(ApiError::Conflict)
    ));
    let stale_payload = crate::MutationPayload::ChangeApply(crate::ChangeApplyPayload {
        session_id: "session-2".into(),
        plan_id: "plan-2".into(),
    });
    let stale_plan_hash = crate::plan_hash(&serde_json::to_vec(&stale_payload).unwrap());
    assert!(matches!(
        api.mutate(
            "services",
            Some("allowed"),
            crate::MutationRequest {
                command: crate::MutationCommand::Apply,
                action: crate::MutationAction::Change,
                request_hash: stale_plan_hash.clone(),
                expires_at: unix_now_for_test() + 300,
                target_revision: None,
                payload: stale_payload,
            },
            crate::MutationContext {
                actor: InMemoryManagementApi::actor(),
                idempotency_key: "new-request".into(),
                if_match: "stale-etag".into(),
                session_version: None,
                request_hash: crate::plan_hash(b"different-request"),
                expires_at: unix_now_for_test() + 300,
                request_id: "req-3".into(),
            },
        )
        .await,
        Err(ApiError::Conflict)
    ));
}
#[tokio::test]
async fn console_port_keeps_backend_frames_separate_from_client_input() {
    let mut console = InMemoryConsole::default();
    console
        .send(crate::ConsoleFrame::Text("command".into()))
        .await
        .unwrap();
    assert_eq!(console.sent_frames().len(), 1);
    assert!(console.receive().await.unwrap().is_none());
}
fn unix_now_for_test() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[tokio::test]
async fn begin_change_session_is_typed_and_idempotent() {
    let api = InMemoryManagementApi::default();
    let actor = InMemoryManagementApi::actor();
    let payload = crate::ChangeBeginPayload {
        service_id: "00000000-0000-0000-0000-000000000001".into(),
        cluster_id: "00000000-0000-0000-0000-000000000002".into(),
    };
    let first = api
        .begin_change_session(&actor, payload.clone(), "begin-1", "request-1")
        .await
        .unwrap();
    let replay = api
        .begin_change_session(&actor, payload, "begin-1", "request-2")
        .await
        .unwrap();
    assert_eq!(first, replay);
    assert_eq!(first.state, "editing");
}

#[tokio::test]
async fn begin_change_session_route_returns_editable_session() {
    let api = Arc::new(InMemoryManagementApi::default());
    let app = router(api, authenticator(), security()).unwrap();
    let token = signed(claims(json!("test-aud")), Algorithm::RS256);
    let body = serde_json::to_vec(&json!({
        "service_id": "00000000-0000-0000-0000-000000000001",
        "cluster_id": "00000000-0000-0000-0000-000000000002"
    }))
    .unwrap();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/change-sessions")
                .header("cf-access-jwt-assertion", token)
                .header("content-type", "application/json")
                .header("origin", "https://panel.example")
                .header("x-csrf-token", "csrf")
                .header("idempotency-key", "begin-route-1")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let session: crate::ChangeSessionDto = serde_json::from_slice(&body).unwrap();
    assert_eq!(session.service_id, "00000000-0000-0000-0000-000000000001");
    assert_eq!(session.cluster_id, "00000000-0000-0000-0000-000000000002");
    assert_eq!(session.state, "editing");
    assert_eq!(session.version, 1);
}

#[tokio::test]
async fn plan_route_port_returns_typed_result_without_operation_shape() {
    let api = InMemoryManagementApi::default();
    let actor = InMemoryManagementApi::actor();
    let session_id = "00000000-0000-0000-0000-000000000003";
    let payload = crate::MutationPayload::ChangePlan(crate::ChangePlanPayload {
        session_id: session_id.into(),
        service_id: "00000000-0000-0000-0000-000000000001".into(),
        target: crate::PlanTarget::Cluster("00000000-0000-0000-0000-000000000002".into()),
        domain_revision: 1,
        observed_state_hashes: vec!["a".repeat(64)],
        expected_file_hashes: vec![],
        expected_artifact_hashes: vec![],
        steps: vec![crate::PlanStepDto {
            action: crate::PlanStepAction::ExecutionLifecycle(crate::ExecutionLifecycleStep {
                binding_id: "00000000-0000-0000-0000-000000000004".into(),
                action: crate::ExecutionLifecycleAction::Restart,
                expected_binding_hash: "b".repeat(64),
                expected_state_hash: "c".repeat(64),
                domain_revision: 1,
            }),
        }],
        backup_required: false,
        backup_references: vec![],
        rollback_instructions: vec!["restore snapshot".into()],
        expires_at: unix_now_for_test() + 300,
    });
    let request = crate::MutationRequest {
        command: crate::MutationCommand::Plan,
        action: crate::MutationAction::Change,
        request_hash: crate::plan_hash(&serde_json::to_vec(&payload).unwrap()),
        expires_at: unix_now_for_test() + 300,
        target_revision: None,
        payload,
    };
    let context = crate::MutationContext {
        actor: actor.clone(),
        idempotency_key: "typed-plan-1".into(),
        if_match: "\"1\"".into(),
        session_version: Some(1),
        request_hash: request.request_hash.clone(),
        expires_at: request.expires_at,
        request_id: "request-1".into(),
    };
    let result = api
        .plan_change(
            &actor,
            "change-sessions",
            session_id,
            request.clone(),
            context.clone(),
        )
        .await
        .unwrap();
    assert_eq!(result.session_id, session_id);
    assert_eq!(result.state, "planned");
    assert_eq!(result.plan_hash, request.request_hash);
    let replay = api
        .plan_change(&actor, "change-sessions", session_id, request, context)
        .await
        .unwrap();
    assert_eq!(result, replay);
}

#[tokio::test]
async fn approval_separates_request_hash_from_persisted_plan_hash() {
    let api = InMemoryManagementApi::default();
    let actor = InMemoryManagementApi::actor();
    let persisted_plan_hash = "a".repeat(64);
    let payload = crate::MutationPayload::ChangeApprove(crate::ChangeApprovePayload {
        session_id: "00000000-0000-0000-0000-000000000003".into(),
        plan_id: "00000000-0000-0000-0000-000000000004".into(),
        plan_hash: persisted_plan_hash.clone(),
    });
    let request_hash = crate::plan_hash(&serde_json::to_vec(&payload).unwrap());
    assert_ne!(request_hash, persisted_plan_hash);
    let request = crate::MutationRequest {
        command: crate::MutationCommand::Approve,
        action: crate::MutationAction::Change,
        request_hash: request_hash.clone(),
        expires_at: unix_now_for_test() + 300,
        target_revision: None,
        payload,
    };
    let context = crate::MutationContext {
        actor: actor.clone(),
        idempotency_key: "approval-1".into(),
        if_match: persisted_plan_hash.clone(),
        session_version: None,
        request_hash,
        expires_at: request.expires_at,
        request_id: "request-approval-1".into(),
    };
    let approved = api
        .approve_change(
            &actor,
            "change-sessions",
            "00000000-0000-0000-0000-000000000003",
            request.clone(),
            context.clone(),
        )
        .await
        .unwrap();
    assert_eq!(approved.plan_hash, persisted_plan_hash);

    let mut stale_context = context;
    stale_context.if_match = "b".repeat(64);
    assert!(matches!(
        api.approve_change(
            &actor,
            "change-sessions",
            "00000000-0000-0000-0000-000000000003",
            request,
            stale_context,
        )
        .await,
        Err(ApiError::Conflict)
    ));
}

#[test]
fn unsupported_error_has_a_stable_machine_code() {
    let response = ApiError::Unsupported.into_response();
    assert_eq!(
        response.status(),
        axum::http::StatusCode::UNPROCESSABLE_ENTITY
    );
}

#[tokio::test]
async fn router_requires_assertion_and_dispatches_mutation_contract() {
    let api = Arc::new(InMemoryManagementApi::default());
    api.insert("services", "svc-1", json!({"service_key":"survival"}))
        .await;
    api.insert(
        "change-sessions",
        "00000000-0000-0000-0000-000000000003",
        json!({"service_key":"survival"}),
    )
    .await;
    let app = router(api, authenticator(), security()).unwrap();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/v1/services")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);

    let token = signed(claims(json!(["test-aud"])), Algorithm::RS256);
    let payload = crate::MutationPayload::ChangePlan(crate::ChangePlanPayload {
        session_id: "00000000-0000-0000-0000-000000000003".into(),
        service_id: "00000000-0000-0000-0000-000000000001".into(),
        target: crate::PlanTarget::Cluster("00000000-0000-0000-0000-000000000002".into()),
        domain_revision: 1,
        observed_state_hashes: vec!["a".repeat(64)],
        expected_file_hashes: vec![],
        expected_artifact_hashes: vec![],
        steps: vec![crate::PlanStepDto {
            action: crate::PlanStepAction::ExecutionLifecycle(crate::ExecutionLifecycleStep {
                binding_id: "00000000-0000-0000-0000-000000000001".into(),
                action: crate::ExecutionLifecycleAction::Restart,
                expected_binding_hash: "b".repeat(64),
                expected_state_hash: "c".repeat(64),
                domain_revision: 1,
            }),
        }],
        backup_required: false,
        backup_references: vec![],
        rollback_instructions: vec![],
        expires_at: unix_now_for_test() + 300,
    });
    let request = json!({
        "command": "plan",
        "action": "change",
        "request_hash": crate::plan_hash(&serde_json::to_vec(&payload).unwrap()),
        "expires_at": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 300,
        "payload": payload
    });
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/change-sessions/00000000-0000-0000-0000-000000000003/plan")
                .header("cf-access-jwt-assertion", token)
                .header("content-type", "application/json")
                .header("origin", "https://panel.example")
                .header("x-csrf-token", "csrf")
                .header("idempotency-key", "route-test-1")
                .header(
                    "x-request-hash",
                    crate::plan_hash(&serde_json::to_vec(&payload).unwrap()),
                )
                .header("if-match", "\"1\"")
                .body(Body::from(serde_json::to_vec(&request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response
            .headers()
            .get("x-content-type-options")
            .and_then(|value| value.to_str().ok()),
        Some("nosniff")
    );
    assert!(
        response
            .headers()
            .get("content-security-policy")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.contains("default-src 'self'"))
    );
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    assert_eq!(
        status,
        axum::http::StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&body)
    );
}
#[test]
fn local_auth_cannot_be_enabled_in_production() {
    let config = LocalAuthConfig { enabled: true };
    assert!(validate_local_auth(&config, RuntimeEnvironment::Production).is_err());
    #[cfg(not(feature = "local-auth"))]
    assert!(validate_local_auth(&config, RuntimeEnvironment::Development).is_err());
    #[cfg(feature = "local-auth")]
    assert!(validate_local_auth(&config, RuntimeEnvironment::Development).is_ok());
}

#[test]
fn typed_plan_steps_round_trip_with_explicit_action_wrapper() {
    let plan = crate::ChangePlanPayload {
        session_id: "00000000-0000-0000-0000-000000000001".into(),
        service_id: "00000000-0000-0000-0000-000000000002".into(),
        target: crate::PlanTarget::Cluster("00000000-0000-0000-0000-000000000003".into()),
        domain_revision: 4,
        observed_state_hashes: vec!["a".repeat(64), "b".repeat(64)],
        expected_file_hashes: vec![],
        expected_artifact_hashes: vec![],
        steps: vec![
            crate::PlanStepDto {
                action: crate::PlanStepAction::ExecutionProvision(crate::ExecutionProvisionStep {
                    binding_id: "00000000-0000-0000-0000-000000000004".into(),
                    expected_binding_hash: "c".repeat(64),
                    domain_revision: 4,
                }),
            },
            crate::PlanStepDto {
                action: crate::PlanStepAction::RoutePolicyUpdate(crate::RoutePolicyUpdateStep {
                    route_id: "00000000-0000-0000-0000-000000000005".into(),
                    pool_id: "00000000-0000-0000-0000-000000000006".into(),
                    service_id: "00000000-0000-0000-0000-000000000002".into(),
                    expected_cluster: "00000000-0000-0000-0000-000000000003".into(),
                    target_cluster: "00000000-0000-0000-0000-000000000007".into(),
                    expected_priority: 10,
                    target_priority: 20,
                    expected_version: 2,
                    disabled: true,
                }),
            },
        ],
        backup_required: false,
        backup_references: vec![],
        rollback_instructions: vec![],
        expires_at: unix_now_for_test() + 300,
    };
    let encoded = serde_json::to_value(&plan).unwrap();
    assert_eq!(encoded["steps"][0]["action"]["kind"], "execution_provision");
    assert_eq!(encoded["steps"][1]["action"]["value"]["disabled"], true);
    let decoded: crate::ChangePlanPayload = serde_json::from_value(encoded).unwrap();
    assert_eq!(decoded, plan);
    assert!(
        crate::MutationPayload::ChangePlan(decoded)
            .validate()
            .is_ok()
    );
}

#[tokio::test]
async fn staged_content_idempotency_binds_the_uploaded_bytes() {
    let api = InMemoryManagementApi::default();
    let actor = InMemoryManagementApi::actor();
    let first = api
        .stage_content(
            &actor,
            StageContentRequest {
                session_id: "00000000-0000-0000-0000-000000000001".into(),
                bytes: b"one".to_vec(),
                classification: crate::FileClassification::Managed,
                session_version: 1,
                idempotency_key: "stage-1".into(),
                request_hash: crate::plan_hash(b"one"),
            },
        )
        .await
        .unwrap();
    assert_eq!(first.size, 3);
    assert_eq!(
        api.stage_content(
            &actor,
            StageContentRequest {
                session_id: "00000000-0000-0000-0000-000000000001".into(),
                bytes: b"one".to_vec(),
                classification: crate::FileClassification::Managed,
                session_version: 1,
                idempotency_key: "stage-1".into(),
                request_hash: crate::plan_hash(b"one"),
            },
        )
        .await
        .unwrap(),
        first
    );
    assert!(matches!(
        api.stage_content(
            &actor,
            StageContentRequest {
                session_id: "00000000-0000-0000-0000-000000000001".into(),
                bytes: b"two".to_vec(),
                classification: crate::FileClassification::Managed,
                session_version: 1,
                idempotency_key: "stage-1".into(),
                request_hash: crate::plan_hash(b"two"),
            },
        )
        .await,
        Err(ApiError::Conflict)
    ));
}

#[test]
fn openapi_is_nonempty_and_has_all_management_resources() {
    let document = openapi_document();
    let snapshot: serde_json::Value =
        serde_json::from_str(include_str!("../../../openapi/openapi.json")).unwrap();
    assert_eq!(document, snapshot);
    assert_eq!(document["openapi"], "3.1.0");
    let paths = document["paths"].as_object().unwrap();
    assert_eq!(
        paths["/api/v1/session"]["post"]["responses"]["200"]["content"]["application/json"]["schema"]
            ["$ref"],
        "#/components/schemas/Session"
    );
    for resource in crate::dto::ResourceKind::ALL {
        assert!(paths.contains_key(&format!("/api/v1/{}", resource.as_str())));
        assert!(
            paths[&format!("/api/v1/{}", resource.as_str())]
                .as_object()
                .is_some_and(|v| !v.is_empty())
        );
    }
    assert!(paths.contains_key("/api/v1/proxy-instances"));
    assert!(paths.contains_key("/api/v1/proxy-instances/{id}"));
    for action in [
        "/api/v1/change-sessions/{id}/plan",
        "/api/v1/change-sessions/{id}/approve",
        "/api/v1/change-sessions/{id}/apply",
        "/api/v1/change-sessions/{id}/verify",
        "/api/v1/change-sessions/{id}/accept",
        "/api/v1/change-sessions/{id}/rollback",
        "/api/v1/sftp-endpoints/{id}/scan",
    ] {
        let operation = &paths[action]["post"];
        assert_eq!(operation["security"][0]["cloudflareAccess"], json!([]));
        assert!(operation["requestBody"]["content"]["application/json"]["schema"].is_object());
        let expected_parameters = if action.contains("sftp-endpoints") {
            2
        } else {
            3
        };
        assert_eq!(
            operation["parameters"].as_array().unwrap().len(),
            expected_parameters
        );
    }
    let mut operation_ids = BTreeSet::new();
    for path in paths.values() {
        if let Some(operation) = path.as_object() {
            for operation in operation.values() {
                if let Some(id) = operation.get("operationId").and_then(|id| id.as_str()) {
                    assert!(operation_ids.insert(id.to_owned()), "duplicate {id}");
                }
            }
        }
    }
    assert_eq!(
        document["components"]["securitySchemes"]["cloudflareAccess"]["name"],
        "Cf-Access-Jwt-Assertion"
    );
    assert!(
        document["components"]["schemas"]["MutationRequest"]["additionalProperties"]
            .as_bool()
            .is_some_and(|value| !value)
    );
    assert_eq!(
        paths["/api/v1/change-sessions"]["post"]["requestBody"]["content"]["application/json"]["schema"]
            ["$ref"],
        "#/components/schemas/ChangeBeginPayload"
    );
    assert_eq!(
        paths["/api/v1/change-sessions"]["post"]["responses"]["200"]["content"]["application/json"]
            ["schema"]["$ref"],
        "#/components/schemas/ChangeSession"
    );
    assert_eq!(
        paths["/api/v1/change-sessions/{id}/plan"]["post"]["responses"]["200"]["content"]["application/json"]
            ["schema"]["$ref"],
        "#/components/schemas/ChangePlanResult"
    );
    assert!(document["components"]["schemas"]["PlanStep"]["oneOf"].is_array());
    let plan_variants = document["components"]["schemas"]["PlanStep"]["oneOf"]
        .as_array()
        .expect("typed plan variants");
    for kind in [
        "execution_provision",
        "execution_delete",
        "service_lifecycle_transition",
        "cluster_revision_create",
        "artifact_register",
        "route_policy_update",
    ] {
        assert!(
            plan_variants.iter().any(|variant| {
                variant["properties"]["action"]["properties"]["kind"]["const"] == kind
            }),
            "missing plan step {kind}"
        );
    }
    assert!(paths.contains_key("/api/v1/change-sessions/{id}/staged-content"));
    assert!(paths["/api/v1/operations/{id}/events"]["get"]["responses"]["200"].is_object());
    assert_eq!(
        paths["/api/v1/health/providers"]["get"]["security"][0]["cloudflareAccess"],
        json!([])
    );
    assert_eq!(
        paths["/health"]["get"]["summary"],
        "Controller health status"
    );
    assert_eq!(
        paths["/ready"]["get"]["summary"],
        "Controller database readiness"
    );
}

#[test]
fn access_policy_plan_requires_each_grant_to_name_the_target_service() {
    let service = uuid::Uuid::new_v4().to_string();
    let cluster = uuid::Uuid::new_v4().to_string();
    let session = uuid::Uuid::new_v4().to_string();
    let policy = uuid::Uuid::new_v4().to_string();
    let actor = uuid::Uuid::new_v4().to_string();
    let payload = |service_scope: Option<String>| {
        crate::MutationPayload::ChangePlan(crate::ChangePlanPayload {
            session_id: session.clone(),
            service_id: service.clone(),
            target: crate::PlanTarget::Cluster(cluster.clone()),
            domain_revision: 1,
            observed_state_hashes: vec!["a".repeat(64)],
            expected_file_hashes: vec![],
            expected_artifact_hashes: vec![],
            steps: vec![crate::PlanStepDto {
                action: crate::PlanStepAction::AccessPolicyUpdate(crate::AccessPolicyUpdateStep {
                    policy_id: policy.clone(),
                    service_id: service.clone(),
                    expected_version: 1,
                    desired_grants: vec![crate::PolicyGrantPayload {
                        actor_id: actor.clone(),
                        role: crate::PolicyRole::Operator,
                        service_scope,
                        permissions: vec![crate::PolicyPermission::ServiceRead],
                    }],
                    desired_policy_hash: "b".repeat(64),
                }),
            }],
            backup_required: false,
            backup_references: vec![],
            rollback_instructions: vec![],
            expires_at: 1,
        })
    };

    assert!(payload(Some(service.clone())).validate().is_ok());
    assert!(matches!(
        payload(None).validate(),
        Err(crate::ApiError::InvalidRequest(
            "step.desired_grants.service_scope must target service_id"
        ))
    ));
    assert!(matches!(
        payload(Some(uuid::Uuid::new_v4().to_string())).validate(),
        Err(crate::ApiError::InvalidRequest(
            "step.desired_grants.service_scope must target service_id"
        ))
    ));
}
