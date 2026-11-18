#![forbid(unsafe_code)]

//! A narrow GameAP capability extension for observing daemon process managers.
//!
//! GameAP's public node model does not expose the daemon's resolved
//! `process_manager.name`. The WASM route therefore invokes one fixed,
//! non-user-controlled command through `gameap-nodecmd`, reads only the
//! `process_manager.name` field from the default daemon configuration, and
//! never returns command output or configuration values.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[cfg(target_arch = "wasm32")]
const EVIDENCE_VERSION: &str = "1";
#[cfg(target_arch = "wasm32")]
const OBSERVE_COMMAND: &str = "cat /etc/gameap-daemon/gameap-daemon.yaml";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ObserveRequest {
    pub node_id: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessManagerEvidence {
    pub node_id: u64,
    pub process_manager: ProcessManager,
    pub evidence_hash: String,
    pub version: String,
    pub timestamp: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProcessManager {
    Systemd,
    Docker,
    Podman,
    Unknown,
}

impl ProcessManager {
    pub fn parse(value: &str) -> Self {
        match value.trim().trim_matches(['\'', '"']) {
            "systemd" => Self::Systemd,
            "docker" => Self::Docker,
            "podman" => Self::Podman,
            _ => Self::Unknown,
        }
    }
}

/// Parse only the process manager name from a daemon YAML document.
///
/// This intentionally supports the documented block form and inline scalar
/// form, but does not deserialize or expose the remainder of the config.
pub fn parse_process_manager(config: &str) -> ProcessManager {
    let mut in_process_manager = false;
    for line in config.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed == "process_manager:" {
            in_process_manager = true;
            continue;
        }
        if let Some(value) = trimmed.strip_prefix("process_manager:") {
            let value = value
                .split_once('#')
                .map_or(value, |(value, _)| value)
                .trim();
            if let Some(name) = value.strip_prefix("{name:") {
                return ProcessManager::parse(name.trim().trim_end_matches('}').trim());
            }
            if !value.is_empty() {
                return ProcessManager::parse(value);
            }
            continue;
        }
        if in_process_manager {
            if !line.starts_with([' ', '\t']) {
                in_process_manager = false;
                continue;
            }
            if let Some(value) = trimmed.strip_prefix("name:") {
                let value = value.split_once('#').map_or(value, |(value, _)| value);
                return ProcessManager::parse(value);
            }
        }
    }
    ProcessManager::Unknown
}

pub fn evidence_hash(node_id: u64, config: &str, manager: &ProcessManager) -> String {
    let mut digest = Sha256::new();
    digest.update(node_id.to_be_bytes());
    digest.update(config.as_bytes());
    digest.update(serde_json::to_string(manager).unwrap_or_else(|_| "unknown".to_owned()));
    format!("{:x}", digest.finalize())
}

#[cfg(target_arch = "wasm32")]
fn unknown_evidence(node_id: u64, config: &str, timestamp: u64) -> ProcessManagerEvidence {
    ProcessManagerEvidence {
        node_id,
        process_manager: ProcessManager::Unknown,
        evidence_hash: evidence_hash(node_id, config, &ProcessManager::Unknown),
        version: EVIDENCE_VERSION.to_owned(),
        timestamp,
    }
}

#[cfg(target_arch = "wasm32")]
mod plugin {
    use super::*;
    use gameap_plugin_sdk::host::nodecmd;
    use gameap_plugin_sdk::proto::gameap::plugin as pb;
    use gameap_plugin_sdk::{Plugin, PluginError, register_plugin};
    use std::time::{SystemTime, UNIX_EPOCH};

    #[derive(Default)]
    struct ProcessManagerPlugin;

    impl Plugin for ProcessManagerPlugin {
        fn get_info(&mut self, _req: pb::GetInfoRequest) -> Result<pb::PluginInfo, PluginError> {
            Ok(pb::PluginInfo {
                id: "pmobserve2j7d".into(),
                name: "Process Manager Observation".into(),
                version: env!("CARGO_PKG_VERSION").into(),
                description: "Reports an explicitly observed daemon process manager".into(),
                author: "Kitsunebi".into(),
                license: "MIT".into(),
                api_version: "1".into(),
                ..Default::default()
            })
        }

        fn get_http_routes(
            &mut self,
            _req: pb::GetHttpRoutesRequest,
        ) -> Result<pb::GetHttpRoutesResponse, PluginError> {
            Ok(pb::GetHttpRoutesResponse {
                routes: vec![pb::HttpRoute {
                    path: "/observe".into(),
                    methods: vec!["POST".into()],
                    requires_auth: true,
                    admin_only: true,
                    description: "Observe the daemon process manager for a node".into(),
                }],
            })
        }

        fn handle_http_request(
            &mut self,
            req: pb::HttpRequest,
        ) -> Result<pb::HttpResponse, PluginError> {
            if req.method != "POST" || req.path != "/observe" {
                return Ok(pb::HttpResponse {
                    status_code: 404,
                    ..Default::default()
                });
            }
            let parsed: ObserveRequest = match serde_json::from_slice::<ObserveRequest>(&req.body) {
                Ok(value) if value.node_id > 0 => value,
                _ => {
                    return Ok(json_response(
                        400,
                        br#"{"error":"invalid request"}"#.to_vec(),
                    ));
                }
            };
            let result = nodecmd::execute_command(
                &gameap_plugin_sdk::proto::gameap::plugin::sdk::nodecmd::ExecuteCommandRequest {
                    node_id: parsed.node_id,
                    command: OBSERVE_COMMAND.into(),
                    work_dir: None,
                },
            );
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|value| value.as_secs())
                .unwrap_or(0);
            let evidence = match result {
                Ok(response) if response.exit_code == 0 => {
                    let manager = parse_process_manager(&response.output);
                    ProcessManagerEvidence {
                        node_id: parsed.node_id,
                        process_manager: manager.clone(),
                        evidence_hash: evidence_hash(parsed.node_id, &response.output, &manager),
                        version: EVIDENCE_VERSION.into(),
                        timestamp,
                    }
                }
                _ => unknown_evidence(parsed.node_id, "", timestamp),
            };
            let body =
                serde_json::to_vec(&evidence).map_err(|_| PluginError::new("encoding failed"))?;
            Ok(json_response(200, body))
        }
    }

    fn json_response(status_code: i32, body: Vec<u8>) -> pb::HttpResponse {
        pb::HttpResponse {
            status_code,
            headers: [("Content-Type".into(), "application/json".into())]
                .into_iter()
                .collect(),
            body,
        }
    }

    register_plugin!(ProcessManagerPlugin);
}
