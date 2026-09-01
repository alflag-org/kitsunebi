//! Request security policy independent of authentication and application state.
use crate::{
    auth::VerifiedClaims,
    error::ApiError,
    ports::{ActorKind, VerifiedActor},
};
use axum::http::{HeaderMap, header};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::{
    collections::{BTreeSet, HashMap, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

/// Deployment mode used by the local-auth gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeEnvironment {
    Development,
    Production,
}
/// Local auth is enabled only when both the cargo feature and development mode are active.
#[derive(Clone, Debug, Default)]
pub struct LocalAuthConfig {
    pub enabled: bool,
}
/// Validate local-auth configuration before constructing a server.
pub fn validate_local_auth(
    config: &LocalAuthConfig,
    environment: RuntimeEnvironment,
) -> Result<(), ApiError> {
    if !config.enabled {
        return Ok(());
    }
    if environment == RuntimeEnvironment::Production {
        Err(ApiError::SecurityMisconfigured)
    } else {
        #[cfg(not(feature = "local-auth"))]
        {
            Err(ApiError::SecurityMisconfigured)
        }
        #[cfg(feature = "local-auth")]
        {
            Ok(())
        }
    }
}
/// CSRF token issuer and validator for browser state-changing requests.
///
/// Service actors never call this contract: their originless mutation path is
/// enforced by [`check_state_change`]. Implementations must not expose their
/// signing material through this trait.
pub trait CsrfTokenProvider: Send + Sync {
    fn issue(&self, actor: &VerifiedActor) -> Result<String, ApiError>;
    fn verify(&self, actor: &VerifiedActor, token: &str) -> bool;
}

/// A deterministic development/test provider. The configured token is never
/// derived from request data and is returned only to an authenticated browser.
pub struct StaticCsrfValidator {
    token: String,
}
impl StaticCsrfValidator {
    pub fn new(token: impl Into<String>) -> Self {
        Self {
            token: token.into(),
        }
    }
}
impl CsrfTokenProvider for StaticCsrfValidator {
    fn issue(&self, _: &VerifiedActor) -> Result<String, ApiError> {
        if self.token.is_empty() || !valid_static_token(&self.token) {
            return Err(ApiError::SecurityMisconfigured);
        }
        Ok(self.token.clone())
    }

    fn verify(&self, _: &VerifiedActor, token: &str) -> bool {
        valid_static_token(&self.token)
            && valid_static_token(token)
            && subtle::ConstantTimeEq::ct_eq(self.token.as_bytes(), token.as_bytes()).into()
    }
}

fn valid_static_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= 4096
        && token.chars().all(|character| !character.is_control())
}

const HMAC_TOKEN_VERSION: &str = "v1";
const HMAC_DIGEST_BYTES: usize = 32;
const HMAC_MIN_SECRET_BYTES: usize = 32;
const HMAC_MAX_TTL: Duration = Duration::from_secs(60 * 60);
type HmacSha256 = Hmac<Sha256>;

/// Production synchronizer-token provider.
///
/// Tokens contain only a version, a decimal expiry, and a hexadecimal HMAC.
/// The HMAC covers the expiry and verified actor subject, so a token cannot be
/// transferred between actors. No token state or signing secret is persisted by
/// this type.
pub struct HmacCsrfValidator {
    secret: Vec<u8>,
    ttl: Duration,
}

impl HmacCsrfValidator {
    /// Construct a provider with a secret of at least 256 bits and a lifetime
    /// no longer than one hour.
    pub fn new(secret: impl AsRef<[u8]>, ttl: Duration) -> Result<Self, ApiError> {
        if secret.as_ref().len() < HMAC_MIN_SECRET_BYTES
            || ttl.is_zero()
            || ttl > HMAC_MAX_TTL
            || ttl.as_secs() == 0
        {
            return Err(ApiError::SecurityMisconfigured);
        }
        Ok(Self {
            secret: secret.as_ref().to_vec(),
            ttl,
        })
    }

    /// Issue a token using an explicit Unix timestamp. This is public to make
    /// deterministic expiry tests possible without a clock dependency.
    pub fn issue_at(&self, actor: &VerifiedActor, now: u64) -> Result<String, ApiError> {
        let expiry = now
            .checked_add(self.ttl.as_secs())
            .ok_or(ApiError::SecurityMisconfigured)?;
        let digest = self.digest(actor, expiry)?;
        Ok(format!(
            "{HMAC_TOKEN_VERSION}.{expiry}.{}",
            encode_hex(&digest)
        ))
    }

    /// Validate a token using an explicit Unix timestamp.
    pub fn verify_at(&self, actor: &VerifiedActor, token: &str, now: u64) -> bool {
        let Some((expiry, encoded_digest)) = parse_hmac_token(token) else {
            return false;
        };
        let Some(max_expiry) = now.checked_add(self.ttl.as_secs()) else {
            return false;
        };
        if expiry <= now || expiry > max_expiry {
            return false;
        }
        let Ok(expected) = self.digest(actor, expiry) else {
            return false;
        };
        let Ok(actual) = decode_hex(encoded_digest) else {
            return false;
        };
        // The fixed-size equality check is constant-time. The expected value
        // was produced by HMAC-SHA256 above, without exposing the secret.
        subtle::ConstantTimeEq::ct_eq(expected.as_slice(), actual.as_slice()).into()
    }

    fn digest(
        &self,
        actor: &VerifiedActor,
        expiry: u64,
    ) -> Result<[u8; HMAC_DIGEST_BYTES], ApiError> {
        if actor.subject.is_empty()
            || actor.subject.len() > 256
            || actor
                .subject
                .chars()
                .any(|character| character.is_control())
        {
            return Err(ApiError::SecurityMisconfigured);
        }
        let mut mac = HmacSha256::new_from_slice(&self.secret)
            .map_err(|_| ApiError::SecurityMisconfigured)?;
        mac.update(HMAC_TOKEN_VERSION.as_bytes());
        mac.update(&[0]);
        mac.update(expiry.to_string().as_bytes());
        mac.update(&[0]);
        mac.update(actor.subject.as_bytes());
        let bytes = mac.finalize().into_bytes();
        let mut digest = [0_u8; HMAC_DIGEST_BYTES];
        digest.copy_from_slice(&bytes);
        Ok(digest)
    }
}

impl CsrfTokenProvider for HmacCsrfValidator {
    fn issue(&self, actor: &VerifiedActor) -> Result<String, ApiError> {
        let now = unix_now();
        self.issue_at(actor, now)
    }

    fn verify(&self, actor: &VerifiedActor, token: &str) -> bool {
        self.verify_at(actor, token, unix_now())
    }
}

fn parse_hmac_token(token: &str) -> Option<(u64, &str)> {
    if token.len() > 128 || !token.is_ascii() {
        return None;
    }
    let mut fields = token.split('.');
    if fields.next() != Some(HMAC_TOKEN_VERSION) {
        return None;
    }
    let expiry = fields.next()?;
    let digest = fields.next()?;
    if fields.next().is_some()
        || expiry.is_empty()
        || expiry.len() > 20
        || (expiry.len() > 1 && expiry.starts_with('0'))
        || !expiry.bytes().all(|byte| byte.is_ascii_digit())
        || digest.len() != HMAC_DIGEST_BYTES * 2
        || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return None;
    }
    Some((expiry.parse().ok()?, digest))
}

fn decode_hex(value: &str) -> Result<[u8; HMAC_DIGEST_BYTES], ()> {
    let mut output = [0_u8; HMAC_DIGEST_BYTES];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_value(chunk[0]).ok_or(())? << 4) | hex_value(chunk[1]).ok_or(())?;
    }
    Ok(output)
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn encode_hex(value: &[u8; HMAC_DIGEST_BYTES]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(HMAC_DIGEST_BYTES * 2);
    for byte in value {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
/// Exact-origin and request-limit settings.
pub struct SecurityConfig {
    pub allowed_origins: BTreeSet<String>,
    pub csrf: Arc<dyn CsrfTokenProvider>,
    pub body_limit: usize,
    pub upload_limit: usize,
    pub dangerous_rate_limit: usize,
    pub dangerous_rate_window: Duration,
    pub environment: RuntimeEnvironment,
    pub local_auth: LocalAuthConfig,
}
impl SecurityConfig {
    pub fn validate(&self) -> Result<(), ApiError> {
        if self.allowed_origins.is_empty()
            || self.body_limit == 0
            || self.body_limit > crate::JSON_BODY_LIMIT
            || self.upload_limit == 0
            || self.upload_limit > crate::UPLOAD_LIMIT
            || self.dangerous_rate_limit == 0
            || self.dangerous_rate_window.is_zero()
        {
            return Err(ApiError::SecurityMisconfigured);
        }
        for origin in &self.allowed_origins {
            let parsed = reqwest::Url::parse(origin).ok();
            if origin == "*"
                || origin.len() > 2048
                || parsed.as_ref().is_none_or(|url| {
                    !matches!(url.scheme(), "http" | "https")
                        || url.host_str().is_none()
                        || !url.username().is_empty()
                        || url.password().is_some()
                        // `url::Url` represents an origin without a path as `/`.
                        || url.path() != "/"
                        || url.query().is_some()
                        || url.fragment().is_some()
                })
                || (self.environment == RuntimeEnvironment::Production
                    && parsed.as_ref().is_none_or(|url| url.scheme() != "https"))
            {
                return Err(ApiError::SecurityMisconfigured);
            }
        }
        validate_local_auth(&self.local_auth, self.environment)
    }
    pub fn origin_allowed(&self, headers: &HeaderMap) -> bool {
        headers
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|origin| self.allowed_origins.contains(origin))
    }
}
/// Require one exact origin for browser-originated interactive channels.
pub fn check_origin(config: &SecurityConfig, headers: &HeaderMap) -> Result<(), ApiError> {
    if headers.get_all(header::ORIGIN).iter().count() == 1 && config.origin_allowed(headers) {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}
/// Enforce browser CSRF/origin policy, while permitting originless calls only for a
/// cryptographically authenticated service actor.
pub async fn check_state_change(
    config: &SecurityConfig,
    headers: &HeaderMap,
    actor: &VerifiedActor,
) -> Result<(), ApiError> {
    match actor.kind {
        ActorKind::Service => {
            // Service credentials are the explicit originless API path. An
            // Origin header would make the request ambiguous with a browser
            // flow, so reject it instead of silently bypassing CSRF policy.
            if headers.contains_key(header::ORIGIN) || headers.contains_key("x-csrf-token") {
                Err(ApiError::Forbidden)
            } else {
                Ok(())
            }
        }
        ActorKind::Browser => {
            check_origin(config, headers)?;
            let token = headers
                .get("x-csrf-token")
                .and_then(|v| v.to_str().ok())
                .filter(|v| {
                    !v.is_empty()
                        && v.len() <= 4096
                        && v.chars().all(|character| !character.is_control())
                })
                .ok_or(ApiError::Forbidden)?;
            if config.csrf.verify(actor, token) {
                Ok(())
            } else {
                Err(ApiError::Forbidden)
            }
        }
    }
}
/// Validate paths after URL decoding. A literal `%` is rejected so a second decode
/// cannot turn a previously safe path into traversal.
pub fn validate_relative_path(input: &str) -> Result<String, ApiError> {
    if input.is_empty()
        || input.len() > 4096
        || input.starts_with('/')
        || input.contains('\0')
        || input.contains('\\')
        || input.contains('%')
    {
        return Err(ApiError::Forbidden);
    }
    let mut components = Vec::new();
    for component in input.split('/') {
        if component.is_empty() || component == "." {
            continue;
        }
        if component == ".." {
            return Err(ApiError::Forbidden);
        }
        components.push(component)
    }
    if components.is_empty() {
        return Err(ApiError::Forbidden);
    }
    Ok(components.join("/"))
}

/// Validate every archive member before extraction. Archive readers must call this
/// before creating any destination path and must reject symlink-like entries.
pub fn validate_archive_entries<'a, I>(entries: I) -> Result<(), ApiError>
where
    I: IntoIterator<Item = (&'a str, bool)>,
{
    for (path, is_link) in entries {
        if is_link || validate_relative_path(path).is_err() {
            return Err(ApiError::Forbidden);
        }
    }
    Ok(())
}

/// Validate a user-provided media type before putting it in a response or audit record.
pub fn validate_content_type(value: &str) -> Result<&str, ApiError> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 128
        || value.chars().any(|character| character.is_control())
        || value.split('/').count() != 2
        || value.starts_with('/')
        || value.ends_with('/')
        || value.chars().any(|character| {
            !character.is_ascii_alphanumeric() && !matches!(character, '/' | '.' | '+' | '-' | '_')
        })
    {
        return Err(ApiError::InvalidRequest("invalid content type"));
    }
    Ok(value)
}
/// Per-verified-actor limiter for dangerous mutations.
#[derive(Default)]
pub struct DangerRateLimiter {
    entries: Mutex<HashMap<String, VecDeque<Instant>>>,
}
impl DangerRateLimiter {
    pub async fn check(
        &self,
        actor: &VerifiedActor,
        limit: usize,
        window: Duration,
    ) -> Result<(), ApiError> {
        let now = Instant::now();
        let mut map = self.entries.lock().await;
        let queue = map.entry(actor.subject.clone()).or_default();
        while queue
            .front()
            .is_some_and(|t| now.duration_since(*t) >= window)
        {
            queue.pop_front();
        }
        if queue.len() >= limit {
            return Err(ApiError::RateLimited);
        }
        queue.push_back(now);
        Ok(())
    }
}
/// JWT mapper input helper kept here to make the no-self-asserted-role rule explicit.
pub fn verified_subject(claims: &VerifiedClaims) -> &str {
    &claims.subject
}
