//! Cloudflare Access assertion verification and identity mapping.
use crate::{
    error::ApiError,
    ports::{IdentityMapper, VerifiedActor},
};
use async_trait::async_trait;
use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Request},
    middleware::Next,
    response::{IntoResponse, Response},
};
use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, decode, decode_header,
    jwk::{AlgorithmParameters, Jwk, JwkSet},
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::RwLock;

const ASSERTION_HEADER: &str = "cf-access-jwt-assertion";
const MAX_DEFAULT_JWKS_BYTES: usize = 256 * 1024;
const MAX_CACHE_TTL: Duration = Duration::from_secs(24 * 60 * 60);
const MAX_CLOCK_SKEW: Duration = Duration::from_secs(5 * 60);
const MAX_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Runtime configuration for Cloudflare Access validation.
#[derive(Clone, Debug)]
pub struct AccessConfig {
    pub issuer: String,
    pub audience: String,
    pub jwks_url: String,
    pub clock_skew: Duration,
    pub cache_ttl: Duration,
    pub request_timeout: Duration,
    pub max_jwks_bytes: usize,
}
impl AccessConfig {
    /// Build a configuration from a team domain and Access application audience.
    pub fn for_team_domain(team_domain: &str, audience: &str) -> Result<Self, ApiError> {
        let base = team_domain.trim_end_matches('/');
        let parsed = reqwest::Url::parse(base).map_err(|_| ApiError::SecurityMisconfigured)?;
        if parsed.scheme() != "https"
            || parsed.host_str().is_none()
            || (parsed.path() != "" && parsed.path() != "/")
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(ApiError::SecurityMisconfigured);
        }
        let url = format!("{base}/cdn-cgi/access/certs");
        if audience.trim().is_empty()
            || audience == "*"
            || audience.len() > 512
            || audience
                .chars()
                .any(|character| character.is_control() || character.is_whitespace())
        {
            return Err(ApiError::SecurityMisconfigured);
        }
        Ok(Self {
            issuer: base.to_owned(),
            audience: audience.to_owned(),
            jwks_url: url,
            clock_skew: Duration::from_secs(60),
            cache_ttl: Duration::from_secs(3600),
            request_timeout: Duration::from_secs(5),
            max_jwks_bytes: MAX_DEFAULT_JWKS_BYTES,
        })
    }
    /// Validate production-safe configuration before serving requests.
    pub fn validate(&self) -> Result<(), ApiError> {
        let issuer = reqwest::Url::parse(&self.issuer).ok();
        let jwks = reqwest::Url::parse(&self.jwks_url).ok();
        if issuer.as_ref().is_none_or(|url| {
            url.scheme() != "https"
                || url.host_str().is_none()
                || (url.path() != "" && url.path() != "/")
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
        }) || jwks.as_ref().is_none_or(|url| {
            url.scheme() != "https"
                || url.host_str().is_none()
                || url.path() != "/cdn-cgi/access/certs"
                || !url.username().is_empty()
                || url.password().is_some()
                || url.query().is_some()
                || url.fragment().is_some()
        }) || issuer.as_ref().map(reqwest::Url::origin)
            != jwks.as_ref().map(reqwest::Url::origin)
            || self.audience.trim().is_empty()
            || self.audience == "*"
            || self.audience.len() > 512
            || self
                .audience
                .chars()
                .any(|character| character.is_control() || character.is_whitespace())
            || self.cache_ttl.is_zero()
            || self.cache_ttl > MAX_CACHE_TTL
            || self.clock_skew > MAX_CLOCK_SKEW
            || self.request_timeout.is_zero()
            || self.request_timeout > MAX_REQUEST_TIMEOUT
            || self.max_jwks_bytes == 0
            || self.max_jwks_bytes > MAX_DEFAULT_JWKS_BYTES
        {
            Err(ApiError::SecurityMisconfigured)
        } else {
            Ok(())
        }
    }
}
/// Claims selected from a verified Access assertion. Role and scopes are deliberately absent.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct AccessClaims {
    pub iss: String,
    pub aud: Value,
    pub sub: String,
    pub exp: u64,
    pub nbf: Option<u64>,
    pub iat: Option<u64>,
    pub email: Option<String>,
    pub common_name: Option<String>,
}
/// Claims after cryptographic and temporal validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedClaims {
    pub subject: String,
    pub email: Option<String>,
    pub common_name: Option<String>,
    pub issuer: String,
    pub audience: String,
    pub expires_at: u64,
}

/// A bounded source of public signing keys.
#[async_trait]
pub trait JwksProvider: Send + Sync {
    async fn key(&self, kid: &str, force_refresh: bool) -> Result<Option<Jwk>, ApiError>;
}
#[derive(Clone)]
struct CachedKeys {
    set: JwkSet,
    fetched_at: Instant,
}
/// HTTPS remote JWKS cache. Expired keys are never used as a fallback.
pub struct RemoteJwks {
    client: Client,
    url: String,
    ttl: Duration,
    max_bytes: usize,
    cache: Arc<RwLock<Option<CachedKeys>>>,
}
impl RemoteJwks {
    /// Construct a cache for Cloudflare's `.../cdn-cgi/access/certs` endpoint.
    pub fn new(config: &AccessConfig) -> Result<Self, ApiError> {
        config.validate()?;
        let client = Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(config.request_timeout)
            .build()
            .map_err(|_| ApiError::SecurityMisconfigured)?;
        Ok(Self {
            client,
            url: config.jwks_url.clone(),
            ttl: config.cache_ttl,
            max_bytes: config.max_jwks_bytes,
            cache: Arc::new(RwLock::new(None)),
        })
    }
    async fn refresh(&self) -> Result<JwkSet, ApiError> {
        let response = self
            .client
            .get(&self.url)
            .send()
            .await
            .map_err(|_| ApiError::Unauthorized)?;
        if !response.status().is_success() {
            return Err(ApiError::Unauthorized);
        }
        if response
            .content_length()
            .is_some_and(|n| n > self.max_bytes as u64)
        {
            return Err(ApiError::Unauthorized);
        }
        let mut bytes = Vec::new();
        let mut response = response;
        while let Some(chunk) = response.chunk().await.map_err(|_| ApiError::Unauthorized)? {
            if bytes.len().saturating_add(chunk.len()) > self.max_bytes {
                return Err(ApiError::Unauthorized);
            }
            bytes.extend_from_slice(&chunk);
        }
        let set: JwkSet = serde_json::from_slice(&bytes).map_err(|_| ApiError::Unauthorized)?;
        if set.keys.is_empty() {
            return Err(ApiError::Unauthorized);
        }
        *self.cache.write().await = Some(CachedKeys {
            set: set.clone(),
            fetched_at: Instant::now(),
        });
        Ok(set)
    }
}
#[async_trait]
impl JwksProvider for RemoteJwks {
    async fn key(&self, kid: &str, force_refresh: bool) -> Result<Option<Jwk>, ApiError> {
        if !force_refresh {
            let cache = self.cache.read().await;
            if let Some(cache) = cache.as_ref()
                && cache.fetched_at.elapsed() < self.ttl
            {
                return Ok(cache.set.find(kid).cloned());
            }
            return Ok(None);
        }
        let set = self.refresh().await?;
        Ok(set.find(kid).cloned())
    }
}

/// Identity mapping is an application/database decision, never a JWT self-claim.
/// Request authenticator with separate production Access and feature-gated local backends.
pub struct Authenticator {
    backend: AuthBackend,
    mapper: Arc<dyn IdentityMapper>,
}
enum AuthBackend {
    Access {
        config: AccessConfig,
        keys: Arc<dyn JwksProvider>,
    },
    #[cfg(feature = "local-auth")]
    Local,
}
impl Authenticator {
    pub fn new(
        config: AccessConfig,
        keys: Arc<dyn JwksProvider>,
        mapper: Arc<dyn IdentityMapper>,
    ) -> Result<Self, ApiError> {
        config.validate()?;
        Ok(Self {
            backend: AuthBackend::Access { config, keys },
            mapper,
        })
    }
    pub async fn authenticate(&self, headers: &HeaderMap) -> Result<VerifiedActor, ApiError> {
        if headers.get_all("x-kitsunebi-local-subject").iter().count() > 0 {
            #[cfg(feature = "local-auth")]
            if matches!(&self.backend, AuthBackend::Access { .. }) {
                return Err(ApiError::Unauthorized);
            }
            #[cfg(not(feature = "local-auth"))]
            return Err(ApiError::Unauthorized);
        }
        #[cfg(feature = "local-auth")]
        if matches!(&self.backend, AuthBackend::Local) {
            return self.authenticate_local(headers).await;
        }
        if headers.get_all(ASSERTION_HEADER).iter().count() != 1 {
            return Err(ApiError::Unauthorized);
        }
        let token = headers
            .get(ASSERTION_HEADER)
            .and_then(|v| v.to_str().ok())
            .filter(|v| {
                !v.is_empty()
                    && v.len() <= 16 * 1024
                    && !v.chars().any(|character| character.is_whitespace())
            })
            .ok_or(ApiError::Unauthorized)?;
        let header = decode_header(token).map_err(|_| ApiError::Unauthorized)?;
        if header.alg != Algorithm::RS256 {
            return Err(ApiError::Unauthorized);
        }
        let kid = header.kid.ok_or(ApiError::Unauthorized)?;
        if kid.trim().is_empty()
            || kid.len() > 256
            || kid.chars().any(|character| character.is_control())
        {
            return Err(ApiError::Unauthorized);
        }
        // A missing or expired cache entry gets one forced refresh. There is no
        // expired-key fallback, and a single request cannot create a refresh loop.
        let (config, keys) = match &self.backend {
            AuthBackend::Access { config, keys } => (config, keys),
            #[cfg(feature = "local-auth")]
            AuthBackend::Local => return Err(ApiError::Unauthorized),
        };
        let key = match keys
            .key(&kid, false)
            .await
            .map_err(|_| ApiError::Unauthorized)?
        {
            Some(key) => key,
            None => keys
                .key(&kid, true)
                .await
                .map_err(|_| ApiError::Unauthorized)?
                .ok_or(ApiError::Unauthorized)?,
        };
        if key.common.key_id.as_deref() != Some(kid.as_str())
            || key.common.key_algorithm != Some(jsonwebtoken::jwk::KeyAlgorithm::RS256)
            || !matches!(&key.algorithm, AlgorithmParameters::RSA(_))
        {
            return Err(ApiError::Unauthorized);
        }
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(std::slice::from_ref(&config.issuer));
        validation.set_audience(std::slice::from_ref(&config.audience));
        validation.leeway = config.clock_skew.as_secs();
        validation.validate_nbf = true;
        validation.required_spec_claims.extend([
            "iss".to_owned(),
            "aud".to_owned(),
            "sub".to_owned(),
            "exp".to_owned(),
            "iat".to_owned(),
        ]);
        let data = decode::<AccessClaims>(
            token,
            &DecodingKey::from_jwk(&key).map_err(|_| ApiError::Unauthorized)?,
            &validation,
        )
        .map_err(|_| ApiError::Unauthorized)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if data.claims.sub.trim().is_empty()
            || data.claims.sub.len() > 256
            || data
                .claims
                .sub
                .chars()
                .any(|character| character.is_control())
            || data.claims.iat.is_none()
            || data
                .claims
                .iat
                .is_some_and(|iat| iat > now.saturating_add(config.clock_skew.as_secs()))
        {
            return Err(ApiError::Unauthorized);
        }
        let claims = VerifiedClaims {
            subject: data.claims.sub,
            email: data.claims.email,
            common_name: data.claims.common_name,
            issuer: data.claims.iss,
            audience: config.audience.clone(),
            expires_at: data.claims.exp,
        };
        self.mapper.map(&claims).await
    }

    #[cfg(feature = "local-auth")]
    pub fn local(mapper: Arc<dyn IdentityMapper>) -> Self {
        Self {
            backend: AuthBackend::Local,
            mapper,
        }
    }

    #[cfg(feature = "local-auth")]
    async fn authenticate_local(&self, headers: &HeaderMap) -> Result<VerifiedActor, ApiError> {
        if headers.get_all(ASSERTION_HEADER).iter().count() != 0
            || headers.get_all("x-kitsunebi-local-subject").iter().count() != 1
        {
            return Err(ApiError::Unauthorized);
        }
        let raw = headers
            .get("x-kitsunebi-local-subject")
            .and_then(|value| value.to_str().ok())
            .filter(|value| value.len() == 36)
            .filter(|value| {
                !value
                    .chars()
                    .any(|character| character.is_whitespace() || character.is_control())
            })
            .ok_or(ApiError::Unauthorized)?;
        let subject = uuid::Uuid::parse_str(raw)
            .ok()
            .filter(|value| value.hyphenated().to_string() == raw)
            .map(|value| value.hyphenated().to_string())
            .ok_or(ApiError::Unauthorized)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.mapper
            .map(&VerifiedClaims {
                subject,
                email: None,
                common_name: None,
                issuer: "local".into(),
                audience: "local".into(),
                expires_at: now.saturating_add(60),
            })
            .await
    }
}
/// Axum request middleware. It inserts only the verified, internally mapped actor.
pub async fn middleware(
    State(auth): State<Arc<Authenticator>>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    match auth.authenticate(request.headers()).await {
        Ok(actor) => {
            request.extensions_mut().insert(actor);
            next.run(request).await
        }
        Err(error) => error.into_response(),
    }
}

/// In-memory key source useful for deterministic tests without external network access.
#[derive(Clone)]
pub struct StaticJwks {
    set: Arc<RwLock<JwkSet>>,
}
impl StaticJwks {
    pub fn new(set: JwkSet) -> Self {
        Self {
            set: Arc::new(RwLock::new(set)),
        }
    }
    pub async fn replace(&self, set: JwkSet) {
        *self.set.write().await = set
    }
}
#[async_trait]
impl JwksProvider for StaticJwks {
    async fn key(&self, kid: &str, _force_refresh: bool) -> Result<Option<Jwk>, ApiError> {
        Ok(self.set.read().await.find(kid).cloned())
    }
}
