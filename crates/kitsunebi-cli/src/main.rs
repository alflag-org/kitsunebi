#![forbid(unsafe_code)]

//! A thin command-line client for the Kitsunebi management API.
//!
//! The CLI deliberately contains no lifecycle, rollout, or GameAP logic.  It builds
//! the same DTOs as the HTTP boundary, sends them to the versioned API, and renders
//! the API response.
use kitsunebi_api::{
    ArtifactCandidateDto, ArtifactDiscoverPayload, ChangeApprovalDto, ChangeBeginPayload,
    ChangeSessionDto, FileClassification, FileDiffDto, FileEntryDto, FileReadDto, MutationAction,
    MutationCommand, MutationPayload, MutationRequest, OperationDto, OperationEvent, ResourceDto,
    StagedContentDto, plan_hash, validate_file_path,
};
use reqwest::{
    Method, StatusCode, Url,
    blocking::{Client as HttpClient, Response},
    header::{HeaderMap, HeaderValue},
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, from_slice, to_value, to_vec};
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fmt,
    fs::File,
    io::{self, BufRead, BufReader, IsTerminal, Read, Write},
    path::Path,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const MAX_JSON_BYTES: usize = 1_048_576;
const MAX_FILE_BYTES: usize = 50 * 1024 * 1024;
const MAX_ERROR_BYTES: usize = 64 * 1024;
const MAX_IDEMPOTENCY_KEY: usize = 128;
const MAX_IF_MATCH: usize = 256;
const MAX_PLAN_AGE: u64 = 24 * 60 * 60;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const SSE_TIMEOUT: Duration = Duration::from_secs(2 * 60 * 60);

#[derive(Debug)]
enum CliError {
    Usage(&'static str),
    UsageOwned(String),
    Config(&'static str),
    Transport(&'static str),
    Api {
        status: StatusCode,
        code: String,
        request_id: Option<String>,
    },
    Unsupported(&'static str),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(message) | Self::Config(message) | Self::Transport(message) => {
                f.write_str(message)
            }
            Self::UsageOwned(message) => f.write_str(message),
            Self::Unsupported(message) => write!(f, "unsupported: {message}"),
            Self::Api {
                status,
                code,
                request_id,
            } => write!(
                f,
                "API error {status} ({code}){}",
                request_id
                    .as_deref()
                    .map(|id| format!(", request id {id}"))
                    .unwrap_or_default()
            ),
        }
    }
}
impl std::error::Error for CliError {}

/// Authentication material is kept private to the request builder.  In particular,
/// it does not implement `Debug` and is never included in a `CliError`.
enum Auth {
    ServiceToken {
        client_id: String,
        client_secret: String,
    },
    JwtAssertion(String),
}
impl Auth {
    fn from_environment() -> Result<Self, CliError> {
        let id = env::var("CF_ACCESS_CLIENT_ID").ok();
        let secret = env::var("CF_ACCESS_CLIENT_SECRET").ok();
        let assertion = env::var("CF_ACCESS_JWT_ASSERTION").ok();
        match (id, secret, assertion) {
            (Some(client_id), Some(client_secret), None)
                if !client_id.is_empty() && !client_secret.is_empty() =>
            {
                Ok(Self::ServiceToken {
                    client_id,
                    client_secret,
                })
            }
            (None, None, Some(assertion)) if !assertion.is_empty() => {
                Ok(Self::JwtAssertion(assertion))
            }
            (Some(_), Some(_), Some(_)) => Err(CliError::Config(
                "configure either CF_ACCESS_CLIENT_ID/CF_ACCESS_CLIENT_SECRET or CF_ACCESS_JWT_ASSERTION, not both",
            )),
            _ => Err(CliError::Config(
                "Cloudflare Access credentials are required (CF_ACCESS_CLIENT_ID and CF_ACCESS_CLIENT_SECRET, or CF_ACCESS_JWT_ASSERTION)",
            )),
        }
    }
    fn apply(
        &self,
        request: reqwest::blocking::RequestBuilder,
    ) -> reqwest::blocking::RequestBuilder {
        match self {
            Self::ServiceToken {
                client_id,
                client_secret,
            } => request
                .header("CF-Access-Client-Id", client_id)
                .header("CF-Access-Client-Secret", client_secret),
            Self::JwtAssertion(assertion) => request.header("Cf-Access-Jwt-Assertion", assertion),
        }
    }
    fn is_jwt(&self) -> bool {
        matches!(self, Self::JwtAssertion(_))
    }
}

struct ApiClient {
    http: HttpClient,
    base: Url,
    auth: Auth,
    json: bool,
}
impl ApiClient {
    fn from_environment(json: bool) -> Result<Self, CliError> {
        let raw = env::var("KITSUNEBI_API_URL")
            .map_err(|_| CliError::Config("KITSUNEBI_API_URL is required"))?;
        let allow_local_http = env::var("KITSUNEBI_ALLOW_INSECURE_LOCALHOST")
            .ok()
            .as_deref()
            == Some("1");
        let base = parse_base_url(&raw, allow_local_http)?;
        let http = HttpClient::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .user_agent("kitsunebi-cli/0.3")
            .build()
            .map_err(|_| CliError::Config("could not initialize HTTPS client"))?;
        Ok(Self {
            http,
            base,
            auth: Auth::from_environment()?,
            json,
        })
    }

    fn endpoint(&self, segments: &[&str]) -> Result<Url, CliError> {
        let mut url = self.base.clone();
        for segment in segments {
            if segment.is_empty() || segment.chars().any(char::is_control) {
                return Err(CliError::Usage("path segment is invalid"));
            }
            url.path_segments_mut()
                .map_err(|_| CliError::Config("API URL cannot be used as a base"))?
                .push(segment);
        }
        Ok(url)
    }
    fn resource_url(&self, resource: &str, id: Option<&str>) -> Result<Url, CliError> {
        let mut segments = vec!["api", "v1", resource];
        if let Some(id) = id {
            segments.push(id);
        }
        self.endpoint(&segments)
    }
    fn send<T: Serialize>(
        &self,
        method: Method,
        url: Url,
        body: Option<&T>,
        mutation_headers: Option<&HeaderMap>,
        stream: bool,
    ) -> Result<Response, CliError> {
        let mut request = self
            .http
            .request(method, url)
            .header("Accept", "application/json");
        if stream {
            request = request.timeout(SSE_TIMEOUT);
        }
        request = self.auth.apply(request);
        if let Some(body) = body {
            request = request.json(body);
        }
        if let Some(headers) = mutation_headers {
            request = request.headers(headers.clone());
        }
        request
            .send()
            .map_err(|_| CliError::Transport("request failed"))
    }
    fn get_json<T: DeserializeOwned>(&self, url: Url) -> Result<T, CliError> {
        for attempt in 0..=1 {
            let response = self.send::<Value>(Method::GET, url.clone(), None, None, false)?;
            if attempt == 0 && retryable(response.status()) {
                drop(response);
                thread::sleep(Duration::from_millis(100));
                continue;
            }
            return decode_json(response, MAX_JSON_BYTES);
        }
        Err(CliError::Transport("request retry failed"))
    }
    fn get_bytes(&self, url: Url, limit: usize) -> Result<Vec<u8>, CliError> {
        for attempt in 0..=1 {
            let response = self.send::<Value>(Method::GET, url.clone(), None, None, false)?;
            if attempt == 0 && retryable(response.status()) {
                drop(response);
                thread::sleep(Duration::from_millis(100));
                continue;
            }
            return decode_bytes(response, limit);
        }
        Err(CliError::Transport("request retry failed"))
    }
    fn list(&self, resource: &str) -> Result<Vec<ResourceDto>, CliError> {
        self.get_json(self.resource_url(resource, None)?)
    }
    fn show(&self, resource: &str, id: &str) -> Result<ResourceDto, CliError> {
        self.get_json(self.resource_url(resource, Some(id))?)
    }
    fn operation(&self, id: &str) -> Result<OperationDto, CliError> {
        self.get_json(self.resource_url("operations", Some(id))?)
    }
    fn mutation(
        &self,
        resource: &str,
        id: &str,
        action: MutationAction,
        command: MutationCommand,
        payload: MutationPayload,
        options: &MutationOptions,
    ) -> Result<OperationDto, CliError> {
        if payload.action() != action || payload.command() != command {
            return Err(CliError::Usage("payload kind does not match the command"));
        }
        let encoded = to_vec(&payload).map_err(|_| CliError::Usage("payload cannot be encoded"))?;
        if plan_hash(&encoded) != options.request_hash {
            return Err(CliError::Usage("request hash does not match payload"));
        }
        let request = MutationRequest {
            command,
            action,
            request_hash: options.request_hash.clone(),
            expires_at: options.expires_at,
            target_revision: options.target_revision.clone(),
            payload,
        };
        let url = mutation_url(self, resource, id, action, command)?;
        let headers = options.headers(&self.auth)?;
        let response = self.send(Method::POST, url, Some(&request), Some(&headers), false)?;
        decode_json(response, MAX_JSON_BYTES)
    }
    fn approve_change(
        &self,
        id: &str,
        payload: MutationPayload,
        options: &MutationOptions,
    ) -> Result<ChangeApprovalDto, CliError> {
        if payload.action() != MutationAction::Change
            || payload.command() != MutationCommand::Approve
        {
            return Err(CliError::Usage("approval payload kind is invalid"));
        }
        let encoded = to_vec(&payload).map_err(|_| CliError::Usage("payload cannot be encoded"))?;
        if plan_hash(&encoded) != options.request_hash {
            return Err(CliError::Usage("request hash does not match payload"));
        }
        let request = MutationRequest {
            command: MutationCommand::Approve,
            action: MutationAction::Change,
            request_hash: options.request_hash.clone(),
            expires_at: options.expires_at,
            target_revision: options.target_revision.clone(),
            payload,
        };
        let url = self.endpoint(&["api", "v1", "change-sessions", id, "approve"])?;
        let headers = options.headers(&self.auth)?;
        decode_json(
            self.send(Method::POST, url, Some(&request), Some(&headers), false)?,
            MAX_JSON_BYTES,
        )
    }
    fn discover_artifacts(
        &self,
        payload: &ArtifactDiscoverPayload,
    ) -> Result<Vec<ArtifactCandidateDto>, CliError> {
        let url = self.endpoint(&["api", "v1", "artifacts", "discover"])?;
        decode_json(
            self.send(Method::POST, url, Some(payload), None, false)?,
            MAX_JSON_BYTES,
        )
    }
    fn begin_change(
        &self,
        payload: &ChangeBeginPayload,
        idempotency_key: &str,
    ) -> Result<ChangeSessionDto, CliError> {
        let mut headers = HeaderMap::new();
        insert_header(&mut headers, "Idempotency-Key", idempotency_key)?;
        if self.auth.is_jwt() {
            insert_header(
                &mut headers,
                "Origin",
                &env::var("KITSUNEBI_ORIGIN")
                    .map_err(|_| CliError::Config("KITSUNEBI_ORIGIN is required"))?,
            )?;
            insert_header(
                &mut headers,
                "X-CSRF-Token",
                &env::var("KITSUNEBI_CSRF_TOKEN")
                    .map_err(|_| CliError::Config("KITSUNEBI_CSRF_TOKEN is required"))?,
            )?;
        }
        decode_json(
            self.send(
                Method::POST,
                self.endpoint(&["api", "v1", "change-sessions"])?,
                Some(payload),
                Some(&headers),
                false,
            )?,
            MAX_JSON_BYTES,
        )
    }
    fn stage_content(
        &self,
        session_id: &str,
        bytes: Vec<u8>,
        classification: FileClassification,
        if_match: &str,
        idempotency_key: &str,
    ) -> Result<StagedContentDto, CliError> {
        uuid::Uuid::parse_str(session_id)
            .map_err(|_| CliError::Usage("change session id must be a UUID"))?;
        if idempotency_key.is_empty() || idempotency_key.len() > MAX_IDEMPOTENCY_KEY {
            return Err(CliError::Usage("idempotency key is invalid"));
        }
        parse_strong_version(if_match)?;
        let mut headers = HeaderMap::new();
        insert_header(&mut headers, "Idempotency-Key", idempotency_key)?;
        insert_header(&mut headers, "If-Match", if_match)?;
        insert_header(
            &mut headers,
            "x-kitsunebi-classification",
            stage_classification_name(classification),
        )?;
        if self.auth.is_jwt() {
            insert_header(
                &mut headers,
                "Origin",
                &env::var("KITSUNEBI_ORIGIN")
                    .map_err(|_| CliError::Config("KITSUNEBI_ORIGIN is required"))?,
            )?;
            insert_header(
                &mut headers,
                "X-CSRF-Token",
                &env::var("KITSUNEBI_CSRF_TOKEN")
                    .map_err(|_| CliError::Config("KITSUNEBI_CSRF_TOKEN is required"))?,
            )?;
        }
        let url = self.endpoint(&["api", "v1", "change-sessions", session_id, "staged-content"])?;
        let request = self
            .http
            .post(url)
            .header("Accept", "application/json")
            .header("Content-Type", "application/octet-stream")
            .headers(headers)
            .body(bytes);
        let response = self
            .auth
            .apply(request)
            .send()
            .map_err(|_| CliError::Transport("request failed"))?;
        decode_json(response, MAX_JSON_BYTES)
    }
    fn file_list(&self, id: &str, path: Option<&str>) -> Result<Vec<FileEntryDto>, CliError> {
        let url = self.file_url(id, "files", path, false)?;
        self.get_json(url)
    }
    fn file_read(&self, id: &str, path: &str) -> Result<FileReadDto, CliError> {
        let url = self.file_url(id, "files/read", Some(path), true)?;
        self.get_json(url)
    }
    fn file_diff(&self, id: &str, path: &str) -> Result<FileDiffDto, CliError> {
        let url = self.file_url(id, "files/diff", Some(path), true)?;
        self.get_json(url)
    }
    fn file_download(&self, id: &str, path: &str) -> Result<Vec<u8>, CliError> {
        self.get_bytes(
            self.file_url(id, "files/download", Some(path), true)?,
            MAX_FILE_BYTES,
        )
    }
    fn file_url(
        &self,
        id: &str,
        suffix: &str,
        path: Option<&str>,
        required: bool,
    ) -> Result<Url, CliError> {
        if required && path.is_none() {
            return Err(CliError::Usage("--path is required"));
        }
        if let Some(path) = path {
            validate_cli_path(path)?;
        }
        let mut segments = vec!["api", "v1", "execution-units", id];
        segments.extend(suffix.split('/'));
        let mut url = self.endpoint(&segments)?;
        if let Some(path) = path {
            url.query_pairs_mut().append_pair("path", path);
        }
        Ok(url)
    }
    fn watch_operation(&self, id: &str) -> Result<(), CliError> {
        let url = self.endpoint(&["api", "v1", "operations", id, "events"])?;
        let response = self.send::<Value>(Method::GET, url, None, None, true)?;
        let mut reader = BufReader::new(success_response(response)?);
        let mut line = String::new();
        let mut data = String::new();
        loop {
            line.clear();
            if reader
                .read_line(&mut line)
                .map_err(|_| CliError::Transport("SSE read failed"))?
                == 0
            {
                break;
            }
            if let Some(value) = line.strip_prefix("data:") {
                data.push_str(value.trim_start());
            }
            if line.trim().is_empty() && !data.is_empty() {
                let event: OperationEvent = serde_json::from_str(&data)
                    .map_err(|_| CliError::Transport("invalid operation event"))?;
                print_output(&event, self.json)?;
                data.clear();
            }
        }
        Ok(())
    }
}

fn parse_base_url(raw: &str, allow_local_http: bool) -> Result<Url, CliError> {
    let url =
        Url::parse(raw).map_err(|_| CliError::Config("KITSUNEBI_API_URL must be a valid URL"))?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(CliError::Config(
            "KITSUNEBI_API_URL must not contain credentials, query, or fragment",
        ));
    }
    let host = url
        .host_str()
        .ok_or(CliError::Config("KITSUNEBI_API_URL must include a host"))?;
    let local = matches!(host, "localhost" | "127.0.0.1" | "::1");
    match url.scheme() {
        "https" => Ok(url),
        "http" if local && allow_local_http => Ok(url),
        "http" if local => Err(CliError::Config(
            "HTTP is only allowed for localhost with KITSUNEBI_ALLOW_INSECURE_LOCALHOST=1",
        )),
        _ => Err(CliError::Config("KITSUNEBI_API_URL must use HTTPS")),
    }
}

fn parse_strong_version(value: &str) -> Result<u64, CliError> {
    let value = value.trim();
    if value.len() < 3
        || !value.starts_with('"')
        || !value.ends_with('"')
        || value[1..value.len() - 1].contains('"')
        || value.contains(',')
    {
        return Err(CliError::Usage(
            "--if-match must be a single quoted session version, such as \"1\"",
        ));
    }
    let version = value[1..value.len() - 1]
        .parse::<u64>()
        .map_err(|_| CliError::Usage("--if-match must be a single quoted session version"))?;
    if version == 0 {
        return Err(CliError::Usage(
            "--if-match session version must be positive",
        ));
    }
    Ok(version)
}

fn parse_stage_classification(value: &str) -> Result<FileClassification, CliError> {
    match value.trim() {
        "managed" => Ok(FileClassification::Managed),
        "mutable_config" => Ok(FileClassification::MutableConfig),
        "artifact" => Ok(FileClassification::Artifact),
        "generated" => Ok(FileClassification::Generated),
        _ => Err(CliError::Usage(
            "--classification must be managed, mutable_config, artifact, or generated",
        )),
    }
}

fn stage_classification_name(value: FileClassification) -> &'static str {
    match value {
        FileClassification::Managed => "managed",
        FileClassification::MutableConfig => "mutable_config",
        FileClassification::Artifact => "artifact",
        FileClassification::Generated => "generated",
        FileClassification::State => "state",
        FileClassification::Secret => "secret",
        FileClassification::Unknown => "unknown",
    }
}

fn mutation_url(
    client: &ApiClient,
    resource: &str,
    id: &str,
    action: MutationAction,
    command: MutationCommand,
) -> Result<Url, CliError> {
    let suffix = match (resource, action, command) {
        ("change-sessions", MutationAction::Change, command) => command.as_str(),
        _ => return Err(CliError::Usage("unsupported mutation route")),
    };
    let mut segments = vec!["api", "v1", resource];
    if id.is_empty() {
        if !matches!(
            (resource, action),
            ("change-sessions", MutationAction::Change)
        ) {
            return Err(CliError::Usage("an id is required for this mutation route"));
        }
    } else {
        segments.push(id);
    }
    segments.extend(suffix.split('/'));
    client.endpoint(&segments)
}

struct MutationOptions {
    idempotency_key: String,
    if_match: String,
    request_hash: String,
    expires_at: u64,
    target_revision: Option<String>,
    yes: bool,
    origin: Option<String>,
    csrf_token: Option<String>,
}
impl MutationOptions {
    fn from_args(args: &ParsedArgs, auth: &Auth) -> Result<Self, CliError> {
        let idempotency_key = args.required_value("idempotency-key")?;
        let if_match = args.required_value("if-match")?;
        let request_hash = args.required_value("request-hash")?;
        let expires_at = args
            .required_value("expires-at")?
            .parse::<u64>()
            .map_err(|_| CliError::Usage("--expires-at must be a Unix timestamp"))?;
        let now = unix_now();
        if request_hash.len() != 64 || !request_hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(CliError::Usage(
                "--request-hash must be a 64-character hexadecimal digest",
            ));
        }
        if idempotency_key.is_empty()
            || idempotency_key.len() > MAX_IDEMPOTENCY_KEY
            || idempotency_key.chars().any(char::is_control)
        {
            return Err(CliError::Usage("--idempotency-key is invalid"));
        }
        if if_match.is_empty()
            || if_match.len() > MAX_IF_MATCH
            || if_match.chars().any(char::is_control)
        {
            return Err(CliError::Usage("--if-match is invalid"));
        }
        if expires_at <= now || expires_at > now.saturating_add(MAX_PLAN_AGE) {
            return Err(CliError::Usage(
                "--expires-at must be within the next 24 hours",
            ));
        }
        let origin = env::var("KITSUNEBI_ORIGIN").ok();
        let csrf_token = env::var("KITSUNEBI_CSRF_TOKEN").ok();
        if auth.is_jwt() && (origin.is_none() || csrf_token.as_deref().is_none_or(str::is_empty)) {
            return Err(CliError::Config(
                "JWT mutations require KITSUNEBI_ORIGIN and KITSUNEBI_CSRF_TOKEN",
            ));
        }
        if !auth.is_jwt() && (origin.is_some() || csrf_token.is_some()) {
            return Err(CliError::Config(
                "service-token mutations must not send Origin or CSRF headers",
            ));
        }
        Ok(Self {
            idempotency_key,
            if_match,
            request_hash,
            expires_at,
            target_revision: args.value("target-revision"),
            yes: args.flag("yes"),
            origin,
            csrf_token,
        })
    }
    fn headers(&self, auth: &Auth) -> Result<HeaderMap, CliError> {
        let mut headers = HeaderMap::new();
        insert_header(&mut headers, "Idempotency-Key", &self.idempotency_key)?;
        insert_header(&mut headers, "If-Match", &self.if_match)?;
        insert_header(&mut headers, "X-Request-Hash", &self.request_hash)?;
        if auth.is_jwt() {
            insert_header(
                &mut headers,
                "Origin",
                self.origin
                    .as_deref()
                    .ok_or(CliError::Config("KITSUNEBI_ORIGIN is required"))?,
            )?;
            insert_header(
                &mut headers,
                "X-CSRF-Token",
                self.csrf_token
                    .as_deref()
                    .ok_or(CliError::Config("KITSUNEBI_CSRF_TOKEN is required"))?,
            )?;
        }
        Ok(headers)
    }
}

fn insert_header(headers: &mut HeaderMap, name: &'static str, value: &str) -> Result<(), CliError> {
    let value =
        HeaderValue::from_str(value).map_err(|_| CliError::Usage("mutation header is invalid"))?;
    headers.insert(name, value);
    Ok(())
}

fn decode_json<T: DeserializeOwned>(response: Response, limit: usize) -> Result<T, CliError> {
    let bytes = decode_bytes(response, limit)?;
    from_slice(&bytes).map_err(|_| CliError::Transport("invalid JSON response"))
}
fn decode_bytes(response: Response, limit: usize) -> Result<Vec<u8>, CliError> {
    let response = success_response(response)?;
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(CliError::Transport("response body exceeds limit"));
    }
    let mut bytes =
        Vec::with_capacity(response.content_length().unwrap_or(0).min(limit as u64) as usize);
    let mut chunk = response.take((limit + 1) as u64);
    chunk
        .read_to_end(&mut bytes)
        .map_err(|_| CliError::Transport("response body could not be read"))?;
    if bytes.len() > limit {
        return Err(CliError::Transport("response body exceeds limit"));
    }
    Ok(bytes)
}
fn success_response(response: Response) -> Result<Response, CliError> {
    if response.status().is_success() {
        return Ok(response);
    }
    let status = response.status();
    let request_id = response
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let mut body = Vec::new();
    let mut limited = response.take((MAX_ERROR_BYTES + 1) as u64);
    let _ = limited.read_to_end(&mut body);
    let candidate = serde_json::from_slice::<Value>(&body)
        .ok()
        .and_then(|value| {
            value
                .get("error")
                .and_then(Value::as_str)
                .map(str::to_owned)
        });
    let code = candidate
        .filter(|value| is_known_error_code(value))
        .unwrap_or_else(|| status_code(status).to_owned());
    // Deliberately discard the body. API errors are not trusted to be secret-free.
    Err(CliError::Api {
        status,
        code,
        request_id,
    })
}
fn status_code(status: StatusCode) -> &'static str {
    match status {
        StatusCode::BAD_REQUEST => "invalid_request",
        StatusCode::UNAUTHORIZED => "unauthorized",
        StatusCode::FORBIDDEN => "forbidden",
        StatusCode::NOT_FOUND => "not_found",
        StatusCode::CONFLICT => "conflict",
        StatusCode::PAYLOAD_TOO_LARGE => "payload_too_large",
        StatusCode::TOO_MANY_REQUESTS => "rate_limited",
        StatusCode::UNPROCESSABLE_ENTITY => "unsupported",
        _ => "request_failed",
    }
}
fn is_known_error_code(code: &str) -> bool {
    matches!(
        code,
        "invalid_request"
            | "unauthorized"
            | "forbidden"
            | "not_found"
            | "conflict"
            | "payload_too_large"
            | "rate_limited"
            | "security_misconfigured"
            | "backend_unavailable"
            | "unsupported"
            | "relay_closed"
    )
}
fn retryable(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::REQUEST_TIMEOUT | StatusCode::TOO_MANY_REQUESTS
    ) || status.is_server_error()
}
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn validate_cli_path(path: &str) -> Result<(), CliError> {
    if path == "." {
        return Ok(());
    }
    validate_file_path(path)
        .map(|_| ())
        .map_err(|_| CliError::Usage("file path is invalid"))
}
fn read_local_file(path: &str, limit: usize) -> Result<Vec<u8>, CliError> {
    if path == "-" {
        let mut data = Vec::new();
        io::stdin()
            .take((limit + 1) as u64)
            .read_to_end(&mut data)
            .map_err(|_| CliError::Usage("standard input cannot be read"))?;
        if data.len() > limit {
            return Err(CliError::Usage(
                "standard input exceeds the configured limit",
            ));
        }
        return Ok(data);
    }
    let mut file =
        File::open(Path::new(path)).map_err(|_| CliError::Usage("input file cannot be opened"))?;
    let mut data = Vec::new();
    Read::by_ref(&mut file)
        .take((limit + 1) as u64)
        .read_to_end(&mut data)
        .map_err(|_| CliError::Usage("input file cannot be read"))?;
    if data.len() > limit {
        return Err(CliError::Usage("input file exceeds the configured limit"));
    }
    Ok(data)
}
fn read_payload(path: &str) -> Result<MutationPayload, CliError> {
    let bytes = read_local_file(path, MAX_JSON_BYTES)?;
    let payload: MutationPayload = serde_json::from_slice(&bytes)
        .map_err(|_| CliError::Usage("payload file is not a valid typed mutation payload"))?;
    payload
        .validate()
        .map_err(|_| CliError::Usage("payload contains invalid or unsafe fields"))?;
    Ok(payload)
}

#[derive(Default)]
struct ParsedArgs {
    values: BTreeMap<String, String>,
    flags: BTreeSet<String>,
    positional: Vec<String>,
}
impl ParsedArgs {
    fn parse(tokens: &[String]) -> Result<Self, CliError> {
        let mut args = Self::default();
        let mut index = 0;
        while index < tokens.len() {
            let token = &tokens[index];
            if let Some(option) = token.strip_prefix("--") {
                if option.is_empty() {
                    return Err(CliError::Usage("invalid option"));
                }
                let (name, inline) = option
                    .split_once('=')
                    .map_or((option, None), |(name, value)| (name, Some(value)));
                if matches!(name, "yes" | "follow" | "help") {
                    if inline.is_some() {
                        return Err(CliError::Usage("flag does not take a value"));
                    }
                    args.flags.insert(name.to_owned());
                } else {
                    let value = match inline {
                        Some(value) => value.to_owned(),
                        None => {
                            index += 1;
                            tokens
                                .get(index)
                                .cloned()
                                .ok_or(CliError::Usage("option value is missing"))?
                        }
                    };
                    if value.starts_with("--") {
                        return Err(CliError::Usage("option value is missing"));
                    }
                    args.values.insert(name.to_owned(), value);
                }
            } else {
                args.positional.push(token.clone());
            }
            index += 1;
        }
        Ok(args)
    }
    fn value(&self, name: &str) -> Option<String> {
        self.values.get(name).cloned()
    }
    fn required_value(&self, name: &str) -> Result<String, CliError> {
        self.value(name)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| CliError::UsageOwned(format!("--{name} is required")))
    }
    fn flag(&self, name: &str) -> bool {
        self.flags.contains(name)
    }
    fn require_no_positionals(&self) -> Result<(), CliError> {
        if self.positional.is_empty() {
            Ok(())
        } else {
            Err(CliError::Usage("unexpected positional argument"))
        }
    }
}

fn print_output<T: Serialize>(value: &T, json: bool) -> Result<(), CliError> {
    if json {
        println!(
            "{}",
            serde_json::to_string(value)
                .map_err(|_| CliError::Transport("output encoding failed"))?
        );
        return Ok(());
    }
    let value = to_value(value).map_err(|_| CliError::Transport("output encoding failed"))?;
    print_human(&value);
    Ok(())
}
fn print_human(value: &Value) {
    match value {
        Value::Array(items) => {
            for item in items {
                print_row(item);
            }
        }
        Value::Object(object) => {
            let id = object.get("id").and_then(Value::as_str);
            if id.is_some() {
                print_row(value);
            } else {
                println!("{}", serde_json::to_string(value).unwrap_or_default());
            }
        }
        _ => println!("{}", serde_json::to_string(value).unwrap_or_default()),
    }
}
fn print_row(value: &Value) {
    let id = value.get("id").and_then(Value::as_str).unwrap_or("-");
    let name = value
        .get("name")
        .and_then(Value::as_str)
        .or_else(|| value.get("status").and_then(Value::as_str))
        .unwrap_or("-");
    let extra = value
        .get("classification")
        .and_then(Value::as_str)
        .or_else(|| value.get("size").and_then(Value::as_u64).map(|_| "file"));
    println!(
        "{}\t{}{}",
        id,
        name,
        extra.map(|value| format!("\t{value}")).unwrap_or_default()
    );
}
fn print_file_entries(entries: &[FileEntryDto], json: bool) -> Result<(), CliError> {
    if json {
        return print_output(&entries, true);
    }
    for entry in entries {
        println!(
            "{}\t{}\t{}\t{}",
            entry.path, entry.size, entry.digest, entry.classification
        );
    }
    Ok(())
}
fn print_operation(operation: &OperationDto, json: bool) -> Result<(), CliError> {
    if json {
        print_output(operation, true)
    } else {
        println!(
            "{}\t{}\t{}\t{}",
            operation.id, operation.status, operation.plan_hash, operation.request_id
        );
        Ok(())
    }
}

fn confirm_if_needed(
    action: MutationAction,
    command: MutationCommand,
    yes: bool,
) -> Result<(), CliError> {
    if matches!(
        (action, command),
        (MutationAction::Change, MutationCommand::Plan)
            | (MutationAction::Change, MutationCommand::Verify)
    ) || yes
    {
        return Ok(());
    }
    if !io::stdin().is_terminal() {
        return Err(CliError::Usage(
            "dangerous mutation requires a TTY confirmation or --yes",
        ));
    }
    eprint!("This operation changes managed state. Type 'yes' to continue: ");
    io::stderr()
        .flush()
        .map_err(|_| CliError::Transport("confirmation prompt failed"))?;
    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .map_err(|_| CliError::Usage("confirmation failed"))?;
    if answer.trim() == "yes" {
        Ok(())
    } else {
        Err(CliError::Usage("operation cancelled"))
    }
}

fn run_mutation(
    client: &ApiClient,
    resource: &str,
    id: &str,
    action: MutationAction,
    command: MutationCommand,
    args: &ParsedArgs,
) -> Result<(), CliError> {
    if action != MutationAction::Change {
        return Err(CliError::Usage(
            "high-impact changes must be submitted as a typed change plan; use `change plan` then `change apply`",
        ));
    }
    uuid::Uuid::parse_str(id).map_err(|_| CliError::Usage("mutation target id must be a UUID"))?;
    let options = MutationOptions::from_args(args, &client.auth)?;
    confirm_if_needed(action, command, options.yes)?;
    let payload = read_payload(
        &args
            .required_value("payload-file")
            .or_else(|_| args.required_value("payload"))?,
    )?;
    let operation = client.mutation(resource, id, action, command, payload, &options)?;
    print_operation(&operation, client.json)
}

fn read_command(
    client: &ApiClient,
    group: &str,
    action: &str,
    args: &ParsedArgs,
) -> Result<(), CliError> {
    let resource = match group {
        "service" => "services",
        "server" | "execution-unit" => "execution-units",
        "cluster" => "clusters",
        "world" => "worlds",
        "proxy" => "proxy-pools",
        "artifact" | "artifacts" => "artifacts",
        "endpoint" | "endpoints" => "endpoints",
        "audit" => "audit-events",
        "change" => "change-sessions",
        "backup" => "backups",
        _ => return Err(CliError::Usage("unknown read command")),
    };
    match action {
        "list" => {
            if !args.positional.is_empty() {
                return Err(CliError::Usage("list does not take an id"));
            }
            let values = client.list(resource)?;
            print_output(&values, client.json)
        }
        "show" => {
            let id = one_id(args)?;
            let value = client.show(resource, id)?;
            print_output(&value, client.json)
        }
        _ => Err(CliError::Usage("read command must be list or show")),
    }
}
fn one_id(args: &ParsedArgs) -> Result<&str, CliError> {
    if args.positional.len() == 1 {
        Ok(&args.positional[0])
    } else {
        Err(CliError::Usage("exactly one id is required"))
    }
}

fn run_files(client: &ApiClient, action: &str, args: &ParsedArgs) -> Result<(), CliError> {
    let id = one_id(args)?;
    match action {
        "list" => {
            let path = args.value("path");
            let entries = client.file_list(id, path.as_deref())?;
            print_file_entries(&entries, client.json)
        }
        "read" => {
            let path = args.required_value("path")?;
            let file = client.file_read(id, &path)?;
            print_output(&file, client.json)
        }
        "diff" => {
            let path = args.required_value("path")?;
            let diff = client.file_diff(id, &path)?;
            print_output(&diff, client.json)
        }
        "download" => {
            let path = args.required_value("path")?;
            let output = args.required_value("output")?;
            if output == "-" {
                return Err(CliError::Usage("binary download requires --output FILE"));
            }
            let data = client.file_download(id, &path)?;
            std::fs::write(Path::new(&output), data)
                .map_err(|_| CliError::Usage("download output cannot be written"))
        }
        "upload" | "write" => Err(CliError::Usage(
            "file changes must be staged as typed change-plan steps; direct file writes are unavailable",
        )),
        "batch" => Err(CliError::Usage(
            "file batches must be submitted as typed change-plan steps",
        )),
        _ => Err(CliError::Usage(
            "files command must be list, read, diff, upload, download, write, or batch",
        )),
    }
}
fn run_service_or_server(
    client: &ApiClient,
    group: &str,
    action: &str,
    args: &ParsedArgs,
) -> Result<(), CliError> {
    if matches!(action, "list" | "show") {
        return read_command(client, group, action, args);
    }
    let id = one_id(args)?;
    let _ = id;
    let _ = args;
    Err(CliError::Usage(
        "service and execution changes must be submitted as typed change-plan steps",
    ))
}

fn run_typed_resource(
    client: &ApiClient,
    group: &str,
    action: &str,
    args: &ParsedArgs,
) -> Result<(), CliError> {
    if matches!(action, "list" | "show") {
        return read_command(client, group, action, args);
    }
    let _ = one_id(args)?;
    Err(CliError::Usage(
        "world, endpoint, and access-policy changes must be submitted as typed change-plan steps",
    ))
}
fn run_artifact_or_proxy(
    client: &ApiClient,
    group: &str,
    action: &str,
    args: &ParsedArgs,
) -> Result<(), CliError> {
    if matches!(action, "list" | "show") {
        return read_command(client, group, action, args);
    }
    if matches!(group, "artifact" | "artifacts") && action == "discover" {
        args.require_no_positionals()?;
        let path = args
            .value("payload-file")
            .or_else(|| args.value("payload"))
            .ok_or(CliError::Usage("--payload-file is required"))?;
        let bytes = read_local_file(&path, MAX_JSON_BYTES)?;
        let payload: ArtifactDiscoverPayload = serde_json::from_slice(&bytes)
            .map_err(|_| CliError::Usage("invalid artifact discovery payload"))?;
        payload
            .validate()
            .map_err(|_| CliError::Usage("invalid artifact discovery payload"))?;
        return print_output(&client.discover_artifacts(&payload)?, client.json);
    }
    let _ = one_id(args)?;
    Err(CliError::Usage(
        "artifact and proxy changes must be submitted as typed change-plan steps",
    ))
}

fn run_backup(client: &ApiClient, action: &str, args: &ParsedArgs) -> Result<(), CliError> {
    if matches!(action, "list" | "show") {
        return read_command(client, "backup", action, args);
    }
    match action {
        "create" | "restore" => Err(CliError::Usage(
            "backup changes must be submitted as typed change-plan steps",
        )),
        _ => Err(CliError::Usage(
            "backup command must be list, show, create, or restore",
        )),
    }
}
fn run_change(client: &ApiClient, action: &str, args: &ParsedArgs) -> Result<(), CliError> {
    if matches!(action, "list" | "show") {
        return read_command(client, "change", action, args);
    }
    if action == "begin" {
        args.require_no_positionals()?;
        let key = args.required_value("idempotency-key")?;
        let path = args
            .value("payload-file")
            .or_else(|| args.value("payload"))
            .ok_or(CliError::Usage("--payload-file is required"))?;
        let payload: ChangeBeginPayload =
            serde_json::from_slice(&read_local_file(&path, MAX_JSON_BYTES)?)
                .map_err(|_| CliError::Usage("invalid change begin payload"))?;
        return print_output(&client.begin_change(&payload, &key)?, client.json);
    }
    if matches!(action, "stage" | "stage-content") {
        let session_id = one_id(args)?;
        let input = args
            .value("input")
            .or_else(|| args.value("payload-file"))
            .ok_or(CliError::Usage("--input is required"))?;
        let key = args.required_value("idempotency-key")?;
        let if_match = args.required_value("if-match")?;
        let classification = parse_stage_classification(&args.required_value("classification")?)?;
        return print_output(
            &client.stage_content(
                session_id,
                read_local_file(&input, MAX_FILE_BYTES)?,
                classification,
                &if_match,
                &key,
            )?,
            client.json,
        );
    }
    let command = match action {
        "plan" => MutationCommand::Plan,
        "approve" => MutationCommand::Approve,
        "apply" => MutationCommand::Apply,
        "verify" => MutationCommand::Verify,
        "accept" => MutationCommand::Accept,
        "rollback" => MutationCommand::Rollback,
        _ => {
            return Err(CliError::Usage(
                "change command must be list, show, begin, stage-content, plan, approve, apply, verify, accept, or rollback",
            ));
        }
    };
    let id = one_id(args)?;
    if command == MutationCommand::Approve {
        let options = MutationOptions::from_args(args, &client.auth)?;
        if command == MutationCommand::Plan {
            parse_strong_version(&options.if_match)?;
        }
        let payload = read_payload(
            &args
                .required_value("payload-file")
                .or_else(|_| args.required_value("payload"))?,
        )?;
        confirm_if_needed(MutationAction::Change, command, options.yes)?;
        return print_output(&client.approve_change(id, payload, &options)?, client.json);
    }
    run_mutation(
        client,
        "change-sessions",
        id,
        MutationAction::Change,
        command,
        args,
    )
}
fn run_operation(client: &ApiClient, action: &str, args: &ParsedArgs) -> Result<(), CliError> {
    if action == "list" {
        args.require_no_positionals()?;
        let values = client.list("operations")?;
        return print_output(&values, client.json);
    }
    let id = one_id(args)?;
    match action {
        "show" | "status" => print_operation(&client.operation(id)?, client.json),
        "watch" => client.watch_operation(id),
        _ => Err(CliError::Usage(
            "operation command must be list, status, show, or watch",
        )),
    }
}

fn run() -> Result<(), CliError> {
    let mut argv: Vec<String> = env::args().skip(1).collect();
    let json = argv.iter().any(|arg| arg == "--json");
    argv.retain(|arg| arg != "--json");
    if argv.len() < 2 {
        return Err(CliError::Usage(
            "usage: kitsunebi [--json] <resource> <command> [id] [options]",
        ));
    }
    let group = argv.remove(0);
    let action = argv.remove(0);
    let args = ParsedArgs::parse(&argv)?;
    if args.flag("help") {
        return Err(CliError::Usage(
            "see command groups: service, server, cluster, proxy, world, change, operation, files, artifact, backup, endpoint, audit",
        ));
    }
    if group == "console" {
        return Err(CliError::Unsupported(
            "console WebSocket relay is not implemented by this CLI",
        ));
    }
    let client = ApiClient::from_environment(json)?;
    match group.as_str() {
        "service" | "server" | "execution-unit" => {
            run_service_or_server(&client, &group, &action, &args)
        }
        "change" => run_change(&client, &action, &args),
        "operation" => run_operation(&client, &action, &args),
        "files" => run_files(&client, &action, &args),
        "cluster" | "audit" => read_command(&client, &group, &action, &args),
        "world" | "endpoint" | "endpoints" | "access-policy" | "access-policies" => {
            run_typed_resource(&client, &group, &action, &args)
        }
        "backup" => run_backup(&client, &action, &args),
        "proxy" | "artifact" | "artifacts" => {
            run_artifact_or_proxy(&client, &group, &action, &args)
        }
        _ => Err(CliError::Usage("unknown command group")),
    }
}
fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn remote_http_is_rejected() {
        assert!(parse_base_url("http://example.test", true).is_err());
    }
    #[test]
    fn localhost_http_requires_explicit_opt_in() {
        assert!(parse_base_url("http://localhost:8787", false).is_err());
        assert!(parse_base_url("http://localhost:8787", true).is_ok());
    }
    #[test]
    fn credentials_and_query_are_rejected_from_base_url() {
        assert!(parse_base_url("https://user@example.test", false).is_err());
        assert!(parse_base_url("https://example.test/?token=secret", false).is_err());
    }
    #[test]
    fn parser_does_not_echo_option_values() {
        let parsed = ParsedArgs::parse(&["--if-match".into(), "secret-value".into()]).unwrap();
        assert_eq!(
            parsed
                .required_value("request-hash")
                .unwrap_err()
                .to_string(),
            "--request-hash is required"
        );
    }
    #[test]
    fn error_display_does_not_contain_access_secret() {
        let error = CliError::Api {
            status: StatusCode::FORBIDDEN,
            code: "forbidden".into(),
            request_id: None,
        };
        assert!(!error.to_string().contains("secret"));
    }
    #[test]
    fn mutation_payload_hash_uses_api_representation() {
        let payload = MutationPayload::ChangeApply(kitsunebi_api::ChangeApplyPayload {
            session_id: "00000000-0000-0000-0000-000000000001".into(),
            plan_id: "00000000-0000-0000-0000-000000000002".into(),
        });
        let encoded = to_vec(&payload).unwrap();
        assert_eq!(plan_hash(&encoded).len(), 64);
    }
    #[test]
    fn specialized_mutation_routes_are_rejected() {
        let client = ApiClient {
            http: HttpClient::new(),
            base: Url::parse("https://example.test").unwrap(),
            auth: Auth::JwtAssertion("test-assertion".into()),
            json: true,
        };
        assert!(
            mutation_url(
                &client,
                "backups",
                "",
                MutationAction::Change,
                MutationCommand::Apply,
            )
            .is_err()
        );
        assert!(
            mutation_url(
                &client,
                "backups",
                "00000000-0000-0000-0000-000000000001",
                MutationAction::Change,
                MutationCommand::Apply,
            )
            .is_err()
        );
    }
    #[test]
    fn endpoint_encodes_each_path_segment() {
        let client = ApiClient {
            http: HttpClient::new(),
            base: Url::parse("https://example.test").unwrap(),
            auth: Auth::JwtAssertion("test-assertion".into()),
            json: true,
        };
        let url = client
            .endpoint(&["api", "v1", "services", "service/id"])
            .unwrap();
        assert_eq!(url.path(), "/api/v1/services/service%2Fid");
    }
    #[test]
    fn mock_http_list_uses_access_service_headers_and_current_route() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 8192];
            let length = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..length]).to_ascii_lowercase();
            assert!(request.contains("get /api/v1/services "));
            assert!(request.contains("cf-access-client-id: client-id"));
            assert!(request.contains("cf-access-client-secret: client-secret"));
            let body = r#"[{"id":"svc-1","name":"Demo"}]"#;
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
        });
        let client = ApiClient {
            http: HttpClient::new(),
            base: Url::parse(&format!("http://{address}")).unwrap(),
            auth: Auth::ServiceToken {
                client_id: "client-id".into(),
                client_secret: "client-secret".into(),
            },
            json: true,
        };
        let values = client.list("services").unwrap();
        assert_eq!(values[0].id, "svc-1");
        server.join().unwrap();
    }
    #[test]
    fn mock_http_show_and_file_query_are_typed_and_encoded() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 8192];
            let length = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..length]).to_ascii_lowercase();
            assert!(
                request
                    .contains("get /api/v1/execution-units/server-1/files?path=plugins%2fconfig ")
            );
            let body =
                r#"[{"path":"plugins/config","size":4,"digest":"abcd","classification":"text"}]"#;
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
        });
        let client = ApiClient {
            http: HttpClient::new(),
            base: Url::parse(&format!("http://{address}")).unwrap(),
            auth: Auth::JwtAssertion("test-assertion".into()),
            json: true,
        };
        let values = client
            .file_list("server-1", Some("plugins/config"))
            .unwrap();
        assert_eq!(values[0].path, "plugins/config");
        server.join().unwrap();
    }
    #[test]
    fn mock_http_mutation_sends_route_and_required_headers() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 16384];
            let length = stream.read(&mut request).unwrap();
            let request = String::from_utf8_lossy(&request[..length]).to_ascii_lowercase();
            assert!(request.contains(
                "post /api/v1/change-sessions/00000000-0000-0000-0000-000000000001/apply "
            ));
            assert!(request.contains("idempotency-key: mutation-1"));
            assert!(request.contains("if-match: \"etag-1\""));
            assert!(request.contains("x-request-hash: "));
            assert!(request.contains("\"action\":\"change\""));
            let body = r#"{"id":"op-1","status":"planned","plan_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","request_id":"req-1"}"#;
            write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
        });
        let payload = MutationPayload::ChangeApply(kitsunebi_api::ChangeApplyPayload {
            session_id: "00000000-0000-0000-0000-000000000001".into(),
            plan_id: "00000000-0000-0000-0000-000000000002".into(),
        });
        let hash = plan_hash(&to_vec(&payload).unwrap());
        let options = MutationOptions {
            idempotency_key: "mutation-1".into(),
            if_match: "\"etag-1\"".into(),
            request_hash: hash,
            expires_at: unix_now() + 3600,
            target_revision: None,
            yes: true,
            origin: None,
            csrf_token: None,
        };
        let client = ApiClient {
            http: HttpClient::new(),
            base: Url::parse(&format!("http://{address}")).unwrap(),
            auth: Auth::ServiceToken {
                client_id: "client-id".into(),
                client_secret: "client-secret".into(),
            },
            json: true,
        };
        let operation = client
            .mutation(
                "change-sessions",
                "00000000-0000-0000-0000-000000000001",
                MutationAction::Change,
                MutationCommand::Apply,
                payload,
                &options,
            )
            .unwrap();
        assert_eq!(operation.id, "op-1");
        server.join().unwrap();
    }
    #[test]
    fn mock_http_error_does_not_echo_secret_body() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request);
            let body = r#"{"error":"client-secret"}"#;
            write!(stream, "HTTP/1.1 403 Forbidden\r\nX-Request-ID: req-1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
        });
        let client = ApiClient {
            http: HttpClient::new(),
            base: Url::parse(&format!("http://{address}")).unwrap(),
            auth: Auth::ServiceToken {
                client_id: "client-id".into(),
                client_secret: "client-secret".into(),
            },
            json: true,
        };
        let error = client.list("services").unwrap_err().to_string();
        assert!(!error.contains("client-secret"));
        server.join().unwrap();
    }
}
