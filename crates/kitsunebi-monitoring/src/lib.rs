#![forbid(unsafe_code)]

//! Read-only adapter for an explicitly configured external connection observer.
use async_trait::async_trait;
use kitsunebi_application::{ApplicationError, ConnectionEvidence, ConnectionObserver};
use reqwest::{Client, ClientBuilder, Method, Url};
use serde::{Deserialize, Serialize};
use std::{fmt, time::Duration};
use thiserror::Error;
use tokio::time::{Instant, sleep};

const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_TEXT_BYTES: usize = 4096;
const MAX_POLL_INTERVAL: Duration = Duration::from_secs(60);
const MAX_DEADLINE: Duration = Duration::from_secs(300);

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MonitoringError {
    #[error("monitoring provider configuration is invalid")]
    InvalidConfiguration,
    #[error("monitoring target is invalid")]
    InvalidTarget,
    #[error("monitoring provider response is invalid")]
    InvalidResponse,
    #[error("monitoring provider response is too large")]
    ResponseTooLarge,
    #[error("monitoring provider returned HTTP status {0}")]
    HttpStatus(u16),
    #[error("monitoring provider transport failed")]
    Transport,
}

#[derive(Clone)]
pub struct MonitoringHttpObserver {
    client: Client,
    base_url: Url,
    bearer: String,
    interval: Duration,
    deadline: Duration,
}

impl fmt::Debug for MonitoringHttpObserver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MonitoringHttpObserver")
            .field("base_url", &self.base_url)
            .field("bearer", &"[REDACTED]")
            .field("interval", &self.interval)
            .field("deadline", &self.deadline)
            .finish()
    }
}

#[derive(Serialize)]
struct ObserveRequest<'a> {
    target: &'a str,
}

#[derive(Deserialize)]
struct ObserveResponse {
    active: u64,
    observed: bool,
    evidence_hash: String,
}

impl MonitoringHttpObserver {
    /// Construct the production adapter. Only HTTPS endpoints are accepted.
    pub fn new(
        base_url: &str,
        bearer: impl Into<String>,
        interval: Duration,
        deadline: Duration,
    ) -> Result<Self, MonitoringError> {
        Self::build(base_url, bearer.into(), interval, deadline, false)
    }

    /// Construct an adapter for a task-owned localhost fixture. This is the only constructor permitting HTTP.
    pub fn new_localhost_for_tests(
        base_url: &str,
        bearer: impl Into<String>,
        interval: Duration,
        deadline: Duration,
    ) -> Result<Self, MonitoringError> {
        Self::build(base_url, bearer.into(), interval, deadline, true)
    }

    fn build(
        base_url: &str,
        bearer: String,
        interval: Duration,
        deadline: Duration,
        allow_localhost_http: bool,
    ) -> Result<Self, MonitoringError> {
        if bearer.is_empty()
            || bearer.len() > MAX_TEXT_BYTES
            || bearer.chars().any(char::is_control)
            || interval.is_zero()
            || interval > MAX_POLL_INTERVAL
            || deadline.is_zero()
            || deadline > MAX_DEADLINE
            || interval > deadline
        {
            return Err(MonitoringError::InvalidConfiguration);
        }
        let url = Url::parse(base_url).map_err(|_| MonitoringError::InvalidConfiguration)?;
        let localhost = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1"));
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.host_str().is_none()
            || (!allow_localhost_http && url.scheme() != "https")
            || (allow_localhost_http && url.scheme() == "http" && !localhost)
            || (allow_localhost_http && !matches!(url.scheme(), "http" | "https"))
        {
            return Err(MonitoringError::InvalidConfiguration);
        }
        let client = ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|_| MonitoringError::InvalidConfiguration)?;
        Ok(Self {
            client,
            base_url: url,
            bearer,
            interval,
            deadline,
        })
    }

    async fn request(&self, target: &str) -> Result<ConnectionEvidence, MonitoringError> {
        validate_target(target)?;
        let url = self
            .base_url
            .join("v1/connections/observe")
            .map_err(|_| MonitoringError::InvalidConfiguration)?;
        let response = self
            .client
            .request(Method::POST, url)
            .bearer_auth(&self.bearer)
            .json(&ObserveRequest { target })
            .send()
            .await
            .map_err(|_| MonitoringError::Transport)?;
        let status = response.status();
        if !status.is_success() {
            return Err(MonitoringError::HttpStatus(status.as_u16()));
        }
        let body = read_bounded(response).await?;
        let value: ObserveResponse =
            serde_json::from_slice(&body).map_err(|_| MonitoringError::InvalidResponse)?;
        if !is_digest(&value.evidence_hash) {
            return Err(MonitoringError::InvalidResponse);
        }
        Ok(ConnectionEvidence {
            active: value.active,
            observed: value.observed,
            hash: value.evidence_hash,
        })
    }

    async fn observe_checked(&self, target: &str) -> Result<ConnectionEvidence, MonitoringError> {
        validate_target(target)?;
        let deadline = Instant::now() + self.deadline;
        let mut last = self.request(target).await?;
        if last.active == 0 && last.observed {
            return Ok(last);
        }
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Ok(last);
            }
            sleep(self.interval.min(deadline - now)).await;
            if Instant::now() >= deadline {
                return Ok(last);
            }
            last = self.request(target).await?;
            if last.active == 0 && last.observed {
                return Ok(last);
            }
        }
    }
}

#[async_trait]
impl ConnectionObserver for MonitoringHttpObserver {
    async fn observe(&self, target: &str) -> Result<ConnectionEvidence, ApplicationError> {
        self.observe_checked(target)
            .await
            .map_err(|_| ApplicationError::Port("monitoring observer unavailable".to_owned()))
    }
}

fn validate_target(target: &str) -> Result<(), MonitoringError> {
    if target.is_empty() || target.len() > MAX_TEXT_BYTES || target.chars().any(char::is_control) {
        return Err(MonitoringError::InvalidTarget);
    }
    Ok(())
}

fn is_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

async fn read_bounded(mut response: reqwest::Response) -> Result<Vec<u8>, MonitoringError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(MonitoringError::ResponseTooLarge);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| MonitoringError::Transport)?
    {
        if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(MonitoringError::ResponseTooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc;
    use std::thread;

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn body(active: u64, observed: bool, digest: &str) -> String {
        format!("{{\"active\":{active},\"observed\":{observed},\"evidence_hash\":\"{digest}\"}}")
    }

    fn server(responses: Vec<(u16, String)>) -> (String, mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture");
        let url = format!("http://{}", listener.local_addr().expect("address"));
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            for (status, body) in &responses {
                let Ok((mut stream, _)) = listener.accept() else {
                    break;
                };
                let request = read_request(&mut stream);
                let _ = sender.send(String::from_utf8_lossy(&request).into_owned());
                let reason = if *status == 200 { "OK" } else { "Error" };
                let headers = format!(
                    "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                if stream.write_all(headers.as_bytes()).is_err()
                    || stream.write_all(body.as_bytes()).is_err()
                {
                    break;
                }
            }
        });
        (url, receiver)
    }

    fn read_request(stream: &mut TcpStream) -> Vec<u8> {
        let mut data = Vec::new();
        let mut buffer = [0_u8; 4096];
        while let Ok(size) = stream.read(&mut buffer) {
            if size == 0 {
                break;
            }
            data.extend_from_slice(&buffer[..size]);
            let Some(end) = data.windows(4).position(|window| window == b"\r\n\r\n") else {
                continue;
            };
            let length = String::from_utf8_lossy(&data[..end])
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse().ok())
                        .flatten()
                })
                .unwrap_or(0);
            if data.len() >= end + 4 + length {
                break;
            }
        }
        data
    }

    fn observer(url: &str, interval: Duration, deadline: Duration) -> MonitoringHttpObserver {
        MonitoringHttpObserver::new_localhost_for_tests(url, "provider-secret", interval, deadline)
            .expect("fixture config")
    }

    #[tokio::test]
    async fn returns_zero_without_extra_poll() {
        let (url, requests) = server(vec![(200, body(0, true, A))]);
        let result = observer(&url, Duration::from_millis(1), Duration::from_millis(40))
            .observe_checked("proxy")
            .await
            .expect("evidence");
        assert_eq!(result.active, 0);
        assert!(
            requests
                .recv()
                .expect("request")
                .contains("POST /v1/connections/observe")
        );
        assert!(requests.try_recv().is_err());
    }

    #[tokio::test]
    async fn polls_decreasing_values_to_zero() {
        let (url, requests) = server(vec![
            (200, body(2, true, A)),
            (200, body(1, true, B)),
            (200, body(0, true, A)),
        ]);
        let result = observer(&url, Duration::from_millis(1), Duration::from_millis(100))
            .observe_checked("proxy")
            .await
            .expect("evidence");
        assert_eq!(result.active, 0);
        assert_eq!(requests.iter().count(), 3);
    }

    #[tokio::test]
    async fn deadline_returns_last_active_observation() {
        let (url, requests) = server(vec![(200, body(5, true, A)); 4]);
        let result = observer(&url, Duration::from_millis(5), Duration::from_millis(20))
            .observe_checked("proxy")
            .await
            .expect("evidence");
        assert_eq!(result.active, 5);
        assert!(requests.recv().is_ok());
        assert!(requests.recv().is_ok());
    }

    #[tokio::test]
    async fn rejects_bad_response_status_and_size() {
        let (url, _) = server(vec![(200, body(0, true, "bad"))]);
        assert_eq!(
            observer(&url, Duration::from_millis(1), Duration::from_millis(20))
                .observe_checked("x")
                .await,
            Err(MonitoringError::InvalidResponse)
        );
        let (url, _) = server(vec![(503, "provider details".into())]);
        assert_eq!(
            observer(&url, Duration::from_millis(1), Duration::from_millis(20))
                .observe_checked("x")
                .await,
            Err(MonitoringError::HttpStatus(503))
        );
        let large = format!("{{\"padding\":\"{}\"}}", "x".repeat(MAX_RESPONSE_BYTES));
        let (url, _) = server(vec![(200, large)]);
        assert_eq!(
            observer(&url, Duration::from_millis(1), Duration::from_millis(20))
                .observe_checked("x")
                .await,
            Err(MonitoringError::ResponseTooLarge)
        );
    }

    #[tokio::test]
    async fn authenticates_and_serializes_exact_query() {
        let (url, requests) = server(vec![(200, body(0, true, A))]);
        let adapter = observer(&url, Duration::from_millis(1), Duration::from_millis(20));
        assert!(!format!("{adapter:?}").contains("provider-secret"));
        adapter.observe_checked("target-1").await.expect("evidence");
        let request = requests.recv().expect("request");
        assert!(
            request
                .to_ascii_lowercase()
                .contains("authorization: bearer provider-secret")
        );
        assert!(request.contains("POST /v1/connections/observe HTTP/1.1"));
        assert!(request.ends_with("{\"target\":\"target-1\"}"));
    }

    #[test]
    fn enforces_url_timing_and_target_gates() {
        assert!(
            MonitoringHttpObserver::new(
                "http://127.0.0.1:1",
                "s",
                Duration::from_secs(1),
                Duration::from_secs(2)
            )
            .is_err()
        );
        assert!(
            MonitoringHttpObserver::new(
                "https://user@example.invalid",
                "s",
                Duration::from_secs(1),
                Duration::from_secs(2)
            )
            .is_err()
        );
        assert!(
            MonitoringHttpObserver::new(
                "https://example.invalid/?q=1",
                "s",
                Duration::from_secs(1),
                Duration::from_secs(2)
            )
            .is_err()
        );
        assert!(
            MonitoringHttpObserver::new_localhost_for_tests(
                "http://example.invalid",
                "s",
                Duration::from_secs(1),
                Duration::from_secs(2)
            )
            .is_err()
        );
        assert!(
            MonitoringHttpObserver::new_localhost_for_tests(
                "http://127.0.0.1:1",
                "s",
                Duration::from_secs(1),
                Duration::from_secs(2)
            )
            .is_ok()
        );
        assert!(validate_target("bad\n").is_err());
    }
}
