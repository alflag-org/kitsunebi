//! Deterministic OpenAPI 3.1 document for the HTTP surface.

use crate::{API_PREFIX, dto::ResourceKind};
use kitsunebi_domain::Permission;
use serde_json::{Map, Value, json};

/// Generate the OpenAPI document from the same resource/action tables used by
/// the router. The checked-in snapshot is produced from this function.
pub fn openapi_document() -> Value {
    let mut paths = Map::new();

    for resource in ResourceKind::ALL {
        let collection = format!("{API_PREFIX}/{}", resource.as_str());
        let item = format!("{collection}/{{id}}");
        let mut collection_methods = json!({
            "get": resource_operation("List resource", resource_read_permission(resource), "ResourceList")
        });
        collection_methods["get"]["operationId"] =
            Value::String(format!("list{}", operation_id_segment(resource.as_str())));
        if resource == ResourceKind::ChangeSessions {
            collection_methods["post"] = begin_change_operation();
            collection_methods["post"]["operationId"] =
                Value::String(operation_id_for_path(&collection));
        }
        paths.insert(collection, collection_methods);

        let mut item_methods = Map::new();
        item_methods.insert(
            "get".to_owned(),
            resource_operation(
                "Get resource",
                resource_read_permission(resource),
                "Resource",
            ),
        );
        item_methods["get"]["operationId"] =
            Value::String(format!("get{}", operation_id_segment(resource.as_str())));
        paths.insert(item, Value::Object(item_methods));
    }

    for (path, action, command, permission) in [
        (
            "/api/v1/change-sessions/{id}/plan",
            "change-plan",
            "plan",
            "change.plan",
        ),
        (
            "/api/v1/change-sessions/{id}/approve",
            "change-approve",
            "approve",
            "change.approve",
        ),
        (
            "/api/v1/change-sessions/{id}/apply",
            "change-apply",
            "apply",
            "change.apply",
        ),
        (
            "/api/v1/change-sessions/{id}/verify",
            "change-verify",
            "verify",
            "change.verify",
        ),
        (
            "/api/v1/change-sessions/{id}/accept",
            "change-accept",
            "accept",
            "change.accept",
        ),
        (
            "/api/v1/change-sessions/{id}/rollback",
            "change-rollback",
            "rollback",
            "change.rollback",
        ),
        // High-impact resource operations deliberately do not have direct
        // action routes. They are represented by typed ChangePlan steps and
        // can only execute through the persisted change-session lifecycle.
    ] {
        let mut operation = if path == "/api/v1/change-sessions/{id}/plan" {
            plan_mutation_operation(action, command, permission)
        } else if path == "/api/v1/change-sessions/{id}/approve" {
            approval_mutation_operation(action, command, permission)
        } else {
            action_mutation_operation(action, command, permission)
        };
        if path == "/api/v1/execution-units/{id}/lifecycle" {
            operation["x-permissions"] = json!([
                Permission::LifecycleStart.as_str(),
                Permission::LifecycleStop.as_str(),
                Permission::LifecycleRestart.as_str()
            ]);
        }
        operation["operationId"] = Value::String(operation_id_for_path(path));
        paths.insert(path.to_owned(), json!({"post": operation}));
    }
    paths.insert(
        "/api/v1/artifacts/discover".to_owned(),
        json!({
            "post": artifact_discover_operation()
        }),
    );
    paths.insert(
        "/api/v1/change-sessions/{id}/staged-content".to_owned(),
        json!({"post": staged_content_operation()}),
    );
    let mut sftp_scan = action_mutation_operation("sftp-scan", "apply", "change.plan");
    if let Some(parameters) = sftp_scan["parameters"].as_array_mut() {
        parameters.retain(|parameter| parameter["$ref"] != "#/components/parameters/RequestHash");
    }
    sftp_scan["operationId"] = Value::String("sftpScan".to_owned());
    paths.insert(
        "/api/v1/sftp-endpoints/{id}/scan".to_owned(),
        json!({"post": sftp_scan}),
    );

    paths.insert(
        "/health".to_owned(),
        public_operation("health", "Controller health status", "Health"),
    );
    paths.insert(
        "/live".to_owned(),
        public_operation("live", "Liveness status", "Live"),
    );
    paths.insert(
        "/ready".to_owned(),
        public_operation("ready", "Controller database readiness", "Ready"),
    );
    paths.insert(
        "/metrics".to_owned(),
        json!({
            "get": {
                "operationId": "metrics",
                "summary": "Prometheus metrics",
                "security": [],
                "responses": {
                    "200": {
                        "description": "Prometheus text exposition format",
                        "content": {"text/plain": {"schema": {"type": "string"}}}
                    }
                }
            }
        }),
    );
    paths.insert(
        "/api/v1/operations/{id}/events".to_owned(),
        json!({
            "get": {
                "operationId": "operationEvents",
                "summary": "Stream operation progress",
                "description": "Operation-specific server-sent events. The authenticated actor and service scope are checked before the stream opens; the stream expires after the bounded lifetime or idle period.",
                "x-permission": Permission::OperationRead.as_str(),
                "security": [{"cloudflareAccess": []}],
                "responses": {
                    "200": {
                        "description": "text/event-stream",
                        "content": {"text/event-stream": {"schema": {"$ref": "#/components/schemas/OperationEvent"}}}
                    },
                    "401": {"$ref": "#/components/responses/Unauthorized"},
                    "403": {"$ref": "#/components/responses/Forbidden"},
                    "404": {"$ref": "#/components/responses/NotFound"}
                }
            }
        }),
    );
    paths.insert(
        "/api/v1/execution-units/{id}/console".to_owned(),
        json!({
            "get": {
                "operationId": "consoleRelay",
                "summary": "Relay an authenticated console session",
                "description": "WebSocket relay to the server-side ConsoleSession port. The browser never receives GameAP credentials, frames are bounded, and audit records contain only direction, size, and digest.",
                "security": [{"cloudflareAccess": []}],
                "x-permission": Permission::ConsoleRead.as_str(),
                "x-permissions": [Permission::ConsoleRead.as_str(), Permission::ConsoleSend.as_str()],
                "responses": {
                    "101": {"description": "WebSocket upgrade"},
                    "401": {"$ref": "#/components/responses/Unauthorized"},
                    "403": {"$ref": "#/components/responses/Forbidden"}
                }
            }
        }),
    );
    paths.insert(
        "/api/v1/session".to_owned(),
        json!({
            "post": {
                "operationId": "session",
                "summary": "Issue a browser CSRF token",
                "description": "Returns a short-lived synchronizer token for the authenticated browser actor. Service actors are not eligible, and the request must carry one allowed Origin.",
                "security": [{"cloudflareAccess": []}],
                "responses": {
                    "200": {
                        "description": "browser session security material",
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Session"}}}
                    },
                    "401": {"$ref": "#/components/responses/Unauthorized"},
                    "403": {"$ref": "#/components/responses/Forbidden"}
                }
            }
        }),
    );
    paths.insert(
        "/api/v1/health/providers".to_owned(),
        json!({
            "get": {
                "operationId": "providerHealth",
                "summary": "Authenticated provider health",
                "description": "Detailed GameAP, backup, monitoring, DNS, and TCPShield dependency health. This endpoint is authenticated; public /health and /ready remain shallow probes.",
                "security": [{"cloudflareAccess": []}],
                "responses": {
                    "200": {"description": "success", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Health"}}}},
                    "401": {"$ref": "#/components/responses/Unauthorized"},
                    "403": {"$ref": "#/components/responses/Forbidden"}
                }
            }
        }),
    );

    insert_file_paths(&mut paths);

    json!({
        "openapi": "3.1.0",
        "jsonSchemaDialect": "https://json-schema.org/draft/2020-12/schema",
        "info": {
            "title": "Kitsunebi Management API",
            "version": "1.0.0"
        },
        "security": [{"cloudflareAccess": []}],
        "paths": paths,
        "components": {
            "securitySchemes": {
                "cloudflareAccess": {
                    "type": "apiKey",
                    "in": "header",
                    "name": "Cf-Access-Jwt-Assertion",
                    "description": "Cloudflare Access RS256 JWT assertion. Cookie and bearer fallbacks are not accepted. The origin validates issuer, audience, exp/nbf/iat, kid, and the rotated JWKS before mapping the subject through the persisted actor identity and access-policy port; roles and service scopes are never inferred from JWT claims."
                }
            },
            "parameters": {
                "IdempotencyKey": {
                    "name": "Idempotency-Key",
                    "in": "header",
                    "required": true,
                    "schema": {"type": "string", "minLength": 1, "maxLength": 128}
                },
                "RequestHash": {
                    "name": "X-Request-Hash",
                    "in": "header",
                    "required": true,
                    "schema": {"type": "string", "pattern": "^[0-9a-fA-F]{64}$"},
                    "description": "SHA-256 of the canonical serialized typed payload; it must exactly equal MutationRequest.request_hash."
                },
                "IfMatch": {
                    "name": "If-Match",
                    "in": "header",
                    "required": true,
                    "schema": {"type": "string", "minLength": 1, "maxLength": 256},
                    "description": "A single strong entity-tag. Plan and staged-content routes use the quoted session version (for example, \"1\"); later lifecycle routes use the persisted plan hash."
                },
                "StagedClassification": {
                    "name": "x-kitsunebi-classification",
                    "in": "header",
                    "required": true,
                    "schema": {"type": "string", "enum": ["managed", "mutable_config", "artifact", "generated"]},
                    "description": "Closed content classification. State, secret, and unknown content cannot be staged."
                },
                "FilePath": {
                    "name": "path",
                    "in": "query",
                    "required": false,
                    "schema": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 4096,
                        "description": "Normalized relative path; percent-encoded traversal, NUL, backslash, absolute, and parent components are rejected."
                    }
                },
                "RequiredFilePath": {
                    "name": "path",
                    "in": "query",
                    "required": true,
                    "schema": {
                        "type": "string",
                        "minLength": 1,
                        "maxLength": 4096,
                        "description": "Normalized relative path; percent-encoded traversal, NUL, backslash, absolute, and parent components are rejected."
                    }
                }
            },
            "responses": {
                "BadRequest": response("invalid request"),
                "Unauthorized": response("unauthorized"),
                "Forbidden": response("forbidden"),
                "NotFound": response("not found"),
                "Conflict": response("conflict"),
                "Unsupported": response("unsupported operation"),
                "PayloadTooLarge": response("payload too large"),
                "RateLimited": response("rate limited")
            },
            "schemas": schemas()
        }
    })
}

fn resource_operation(summary: &str, permission: &str, schema: &str) -> Value {
    json!({
        "summary": summary,
        "x-permission": permission,
        "security": [{"cloudflareAccess": []}],
        "responses": {
            "200": {
                "description": "success",
                "content": {"application/json": {"schema": {"$ref": format!("#/components/schemas/{schema}")}}}
            },
            "401": {"$ref": "#/components/responses/Unauthorized"},
            "403": {"$ref": "#/components/responses/Forbidden"},
            "404": {"$ref": "#/components/responses/NotFound"}
        }
    })
}

fn resource_read_permission(resource: ResourceKind) -> &'static str {
    match resource {
        ResourceKind::Artifacts => Permission::ArtifactDiscover.as_str(),
        ResourceKind::Worlds => Permission::WorldRead.as_str(),
        ResourceKind::Endpoints => Permission::EndpointRead.as_str(),
        ResourceKind::AccessPolicies => Permission::AccessRead.as_str(),
        ResourceKind::AuditEvents => Permission::AuditRead.as_str(),
        ResourceKind::Operations => Permission::OperationRead.as_str(),
        _ => Permission::ServiceRead.as_str(),
    }
}

fn public_operation(operation_id: &str, summary: &str, schema: &str) -> Value {
    json!({
        "get": {
            "operationId": operation_id,
            "summary": summary,
            "security": [],
            "responses": {
                "200": {
                    "description": "success",
                    "content": {"application/json": {"schema": {"$ref": format!("#/components/schemas/{schema}")}}}
                }
            }
        }
    })
}

fn approval_mutation_operation(action: &str, command: &str, permission: &str) -> Value {
    let mut operation = action_mutation_operation(action, command, permission);
    operation["responses"]["200"] = json!({
        "description": "change approval",
        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ChangeApproval"}}}
    });
    operation
}

fn artifact_discover_operation() -> Value {
    json!({
        "summary": "Discover artifact candidates",
        "operationId": "discoverArtifacts",
        "x-permission": Permission::ArtifactDiscover.as_str(),
        "security": [{"cloudflareAccess": []}],
        "requestBody": {"required": true, "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ArtifactDiscoverPayload"}}}},
        "responses": {
            "200": {"description": "artifact candidates", "content": {"application/json": {"schema": {"type": "array", "items": {"$ref": "#/components/schemas/ArtifactCandidate"}}}}},
            "400": {"$ref": "#/components/responses/BadRequest"},
            "401": {"$ref": "#/components/responses/Unauthorized"},
            "403": {"$ref": "#/components/responses/Forbidden"},
            "413": {"$ref": "#/components/responses/PayloadTooLarge"},
            "429": {"$ref": "#/components/responses/RateLimited"}
        },
        "x-action": "artifact-discover"
    })
}

fn staged_content_operation() -> Value {
    json!({
        "summary": "Stage content in a change session",
        "operationId": "stageChangeSessionContent",
        "x-permission": Permission::ChangePlan.as_str(),
        "security": [{"cloudflareAccess": []}],
        "parameters": [
            {"$ref": "#/components/parameters/IdempotencyKey"},
            {"$ref": "#/components/parameters/IfMatch"},
            {"$ref": "#/components/parameters/StagedClassification"}
        ],
        "requestBody": {"required": true, "content": {"application/octet-stream": {"schema": {"type": "string", "format": "binary"}}}},
        "responses": {
            "200": {"description": "content reference", "content": {"application/json": {"schema": {"$ref": "#/components/schemas/StagedContent"}}}},
            "400": {"$ref": "#/components/responses/BadRequest"},
            "401": {"$ref": "#/components/responses/Unauthorized"},
            "403": {"$ref": "#/components/responses/Forbidden"},
            "409": {"$ref": "#/components/responses/Conflict"},
            "413": {"$ref": "#/components/responses/PayloadTooLarge"}
        }
    })
}

fn operation_id_for_path(path: &str) -> String {
    path.trim_matches('/')
        .split('/')
        .map(operation_id_segment)
        .collect::<Vec<_>>()
        .join("")
}

fn operation_id_segment(segment: &str) -> String {
    segment
        .trim_matches('{')
        .trim_matches('}')
        .split('-')
        .map(|part| {
            let mut chars = part.chars();
            match chars.next() {
                Some(first) => first.to_uppercase().chain(chars).collect::<String>(),
                None => String::new(),
            }
        })
        .collect::<String>()
}

fn action_mutation_operation(action: &str, command: &str, permission: &str) -> Value {
    json!({
        "summary": format!("{action} operation"),
        "operationId": format!("{action}Mutation"),
        "x-permission": permission,
        "security": [{"cloudflareAccess": []}],
        "parameters": [
            {"$ref": "#/components/parameters/IdempotencyKey"},
            {"$ref": "#/components/parameters/RequestHash"},
            {"$ref": "#/components/parameters/IfMatch"}
        ],
        "requestBody": {
            "required": true,
            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/MutationRequest"}}}
        },
        "responses": {
            "200": {
                "description": "operation",
                "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Operation"}}}
            },
            "400": {"$ref": "#/components/responses/BadRequest"},
            "401": {"$ref": "#/components/responses/Unauthorized"},
            "403": {"$ref": "#/components/responses/Forbidden"},
            "409": {"$ref": "#/components/responses/Conflict"},
            "413": {"$ref": "#/components/responses/PayloadTooLarge"},
            "422": {"$ref": "#/components/responses/Unsupported"},
            "429": {"$ref": "#/components/responses/RateLimited"}
        },
        "x-command": command,
        "x-action": action
    })
}

fn plan_mutation_operation(action: &str, command: &str, permission: &str) -> Value {
    let mut operation = action_mutation_operation(action, command, permission);
    operation["responses"]["200"] = json!({
        "description": "persisted change plan",
        "content": {
            "application/json": {
                "schema": {"$ref": "#/components/schemas/ChangePlanResult"}
            }
        }
    });
    operation
}

fn begin_change_operation() -> Value {
    json!({
        "summary": "Begin a change session",
        "operationId": "beginChangeSession",
        "x-permission": Permission::ChangePlan.as_str(),
        "security": [{"cloudflareAccess": []}],
        "parameters": [{"$ref": "#/components/parameters/IdempotencyKey"}],
        "requestBody": {
            "required": true,
            "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ChangeBeginPayload"}}}
        },
        "responses": {
            "200": {
                "description": "editable change session",
                "content": {"application/json": {"schema": {"$ref": "#/components/schemas/ChangeSession"}}}
            },
            "400": {"$ref": "#/components/responses/BadRequest"},
            "401": {"$ref": "#/components/responses/Unauthorized"},
            "403": {"$ref": "#/components/responses/Forbidden"},
            "404": {"$ref": "#/components/responses/NotFound"},
            "409": {"$ref": "#/components/responses/Conflict"}
        },
        "x-command": "begin",
        "x-action": "change-session"
    })
}

fn insert_file_paths(paths: &mut Map<String, Value>) {
    for (suffix, method, permission, schema, summary) in [
        (
            "files",
            "get",
            "files.read",
            "FileEntryList",
            "Browse files",
        ),
        (
            "files/browse",
            "get",
            "files.read",
            "FileEntryList",
            "Browse files",
        ),
        ("files/read", "get", "files.read", "FileRead", "Read a file"),
        (
            "files/download",
            "get",
            "files.read",
            "BinaryFile",
            "Download a file",
        ),
        ("files/diff", "get", "files.read", "FileDiff", "Diff a file"),
    ] {
        let path = format!("/api/v1/execution-units/{{id}}/{suffix}");
        let mut operation = resource_operation(summary, permission, schema);
        operation["operationId"] = Value::String(format!("{}File", suffix.replace('/', "")));
        let path_parameter = if matches!(suffix, "files" | "files/browse") {
            "FilePath"
        } else {
            "RequiredFilePath"
        };
        operation["parameters"] =
            json!([{"$ref": format!("#/components/parameters/{path_parameter}")}]);
        let mut methods = Map::new();
        methods.insert(method.to_owned(), operation);
        paths.insert(path, Value::Object(methods));
    }
}

fn response(description: &str) -> Value {
    json!({
        "description": description,
        "content": {
            "application/json": {
                "schema": {"$ref": "#/components/schemas/Error"}
            }
        }
    })
}

fn schemas() -> Value {
    let plan_targets = [
        "service",
        "cluster",
        "world",
        "proxy_pool",
        "proxy_instance",
        "artifact",
        "artifact_set",
        "endpoint",
        "endpoint_binding",
        "access_policy",
        "backup",
        "execution_unit",
    ]
    .into_iter()
    .map(|kind| {
        json!({
            "type": "object", "additionalProperties": false,
            "required": ["kind", "value"],
            "properties": {"kind": {"const": kind}, "value": {"type": "string", "format": "uuid"}}
        })
    })
    .collect::<Vec<_>>();
    json!({
        "Permission": {
            "type": "string",
            "enum": Permission::all().iter().map(|permission| permission.as_str()).collect::<Vec<_>>(),
            "description": "Explicit action grant. Role labels do not grant an action without this value and an object/service scope."
        },
        "Resource": {
            "type": "object",
            "required": ["id"],
            "properties": {"id": {"type": "string"}},
            "additionalProperties": true
        },
        "ResourceList": {
            "type": "array",
            "items": {"$ref": "#/components/schemas/Resource"}
        },
        "Session": {
            "type": "object",
            "additionalProperties": false,
            "required": ["csrf_token"],
            "properties": {
                "csrf_token": {"type": "string", "minLength": 1, "maxLength": 4096}
            }
        },
        "BackupTarget": {
            "oneOf": [
                {"type": "object", "additionalProperties": false, "required": ["kind", "value"], "properties": {"kind": {"const": "service"}, "value": {"type": "string", "format": "uuid"}}},
                {"type": "object", "additionalProperties": false, "required": ["kind", "value"], "properties": {"kind": {"const": "cluster"}, "value": {"type": "string", "format": "uuid"}}},
                {"type": "object", "additionalProperties": false, "required": ["kind", "value"], "properties": {"kind": {"const": "world"}, "value": {"type": "string", "format": "uuid"}}},
                {"type": "object", "additionalProperties": false, "required": ["kind", "value"], "properties": {"kind": {"const": "execution_unit"}, "value": {"type": "string", "format": "uuid"}}}
            ]
        },
        "PlanTarget": {
            "oneOf": plan_targets
        },
        "StagedContent": {
            "type": "object",
            "additionalProperties": false,
            "required": ["digest", "size"],
            "properties": {
                "digest": {"type": "string", "pattern": "^[0-9a-fA-F]{64}$"},
                "size": {"type": "integer", "format": "uint64", "minimum": 0}
            }
        },
        "FileBatchOperation": {
            "oneOf": [
                {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["kind", "value"],
                    "properties": {
                        "kind": {"const": "write"},
                        "value": {
                            "type": "object",
                            "additionalProperties": false,
                            "required": ["path", "expected_before_digest", "content", "classification"],
                            "properties": {
                                "path": {"type": "string", "minLength": 1, "maxLength": 4096},
                                "expected_before_digest": {"type": ["string", "null"], "pattern": "^[0-9a-fA-F]{64}$"},
                                "content": {"$ref": "#/components/schemas/StagedContent"},
                                "classification": {"const": "mutable_config"}
                            }
                        }
                    }
                }
            ]
        },
        "EndpointBinding": {
            "type": "object",
            "additionalProperties": false,
            "required": ["id", "endpoint_id", "cluster_id", "revision_id", "binding_key", "metadata"],
            "properties": {
                "id": {"type": "string", "format": "uuid"},
                "endpoint_id": {"type": "string", "format": "uuid"},
                "cluster_id": {"type": "string", "format": "uuid"},
                "revision_id": {"type": "string", "format": "uuid"},
                "binding_key": {"type": "string", "minLength": 1, "maxLength": 256},
                "metadata": {"type": "string", "maxLength": 4096}
            }
        },
        "MutationRequest": {
            "type": "object",
            "additionalProperties": false,
            "required": ["command", "action", "request_hash", "expires_at", "payload"],
            "properties": {
                "command": {
                    "type": "string",
                    "enum": ["plan", "approve", "apply", "verify", "accept", "rollback"]
                },
                "action": {
                    "type": "string",
                    "enum": ["change"]
                },
                "request_hash": {
                    "type": "string",
                    "pattern": "^[0-9a-fA-F]{64}$"
                },
                "expires_at": {"type": "integer", "format": "uint64", "minimum": 1},
                "target_revision": {"type": ["string", "null"], "maxLength": 256},
                "payload": {"$ref": "#/components/schemas/MutationPayload"}
            }
        },
        "MutationPayload": {
            "oneOf": [
                {"$ref": "#/components/schemas/ChangePlanPayload"},
                {"$ref": "#/components/schemas/ChangeApprovePayload"},
                {"$ref": "#/components/schemas/ChangeApplyPayload"},
                {"$ref": "#/components/schemas/ChangeVerifyPayload"},
                {"$ref": "#/components/schemas/ChangeAcceptPayload"},
                {"$ref": "#/components/schemas/ChangeRollbackPayload"}
            ],
            "discriminator": {"propertyName": "kind"}
        },
        "ChangePlanPayload": {
            "type": "object",
            "additionalProperties": false,
            "required": ["kind", "value"],
            "properties": {
                "kind": {"const": "change-plan"},
                "value": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["session_id", "service_id", "target", "domain_revision", "observed_state_hashes", "steps", "expires_at"],
                    "properties": {
                        "session_id": {"type": "string", "format": "uuid"}, "service_id": {"type": "string", "format": "uuid"}, "target": {"$ref": "#/components/schemas/PlanTarget"},
                        "domain_revision": {"type": "integer", "minimum": 0}, "observed_state_hashes": {"type": "array", "minItems": 1, "maxItems": 1024, "items": {"type": "string", "pattern": "^[0-9a-fA-F]{64}$"}},
                        "expected_file_hashes": {"type": "array", "maxItems": 1024, "items": {"type": "string", "pattern": "^[0-9a-fA-F]{64}$"}},
                        "expected_artifact_hashes": {"type": "array", "maxItems": 1024, "items": {"type": "string", "pattern": "^[0-9a-fA-F]{64}$"}},
                        "steps": {"type": "array", "minItems": 1, "maxItems": 1024, "items": {"$ref": "#/components/schemas/PlanStep"}},
                        "backup_required": {"type": "boolean"},
                        "backup_references": {"type": "array", "maxItems": 1024, "items": {"type": "string", "format": "uuid"}},
                        "rollback_instructions": {"type": "array", "maxItems": 1024, "items": {"type": "string", "minLength": 1, "maxLength": 4096}},
                        "expires_at": {"type": "integer", "format": "uint64", "minimum": 1}
                    }
                }
            }
        },
        "ChangeBeginPayload": {
            "type": "object",
            "additionalProperties": false,
            "required": ["service_id", "cluster_id"],
            "properties": {
                "service_id": {"type": "string", "format": "uuid"},
                "cluster_id": {"type": "string", "format": "uuid"}
            }
        },
        "ChangeSession": {
            "type": "object",
            "additionalProperties": false,
            "required": ["id", "service_id", "cluster_id", "state", "version"],
            "properties": {
                "id": {"type": "string", "format": "uuid"},
                "service_id": {"type": "string", "format": "uuid"},
                "cluster_id": {"type": "string", "format": "uuid"},
                "state": {"type": "string"},
                "version": {"type": "integer", "format": "uint64", "minimum": 1}
            }
        },
        "ChangePlanResult": {
            "type": "object",
            "additionalProperties": false,
            "required": ["plan_id", "plan_hash", "session_id", "state"],
            "properties": {
                "plan_id": {"type": "string", "format": "uuid"},
                "plan_hash": {"type": "string", "pattern": "^[0-9a-fA-F]{64}$"},
                "session_id": {"type": "string", "format": "uuid"},
                "state": {"type": "string", "const": "planned"}
            }
        },
        "ChangeApproval": {
            "type": "object",
            "additionalProperties": false,
            "required": ["plan_id", "plan_hash", "session_id", "state"],
            "properties": {
                "plan_id": {"type": "string", "format": "uuid"},
                "plan_hash": {"type": "string", "pattern": "^[0-9a-fA-F]{64}$"},
                "session_id": {"type": "string", "format": "uuid"},
                "state": {"type": "string", "const": "approved"}
            }
        },
        "ChangeApprovePayload": typed_payload_schema("change-approve", &["session_id", "plan_id", "plan_hash"]),
        "ChangeApplyPayload": typed_payload_schema("change-apply", &["session_id", "plan_id"]),
        "ChangeVerifyPayload": typed_payload_schema("change-verify", &["session_id", "operation_id"]),
        "ChangeAcceptPayload": typed_payload_schema("change-accept", &["session_id", "operation_id"]),
        "ChangeRollbackPayload": typed_payload_schema("change-rollback", &["session_id", "operation_id", "reason"]),
        "ArtifactDiscoverPayload": {
            "type": "object",
            "additionalProperties": false,
            "required": ["provider", "query"],
            "properties": {
                "provider": {"type": "string", "enum": ["manual", "direct-url", "modrinth", "github-release", "paper", "hangar"]},
                "query": {"type": "object", "additionalProperties": false, "required": ["kind", "value"]}
            }
        },
        "ArtifactCandidate": {
            "type": "object",
            "additionalProperties": false,
            "required": ["id", "provider", "kind", "name", "version", "source", "source_id", "digest", "filename", "compatibility", "metadata", "size"],
            "properties": {
                "id": {"type": "string", "format": "uuid"},
                "provider": {"type": "string", "enum": ["manual", "direct-url", "modrinth", "github-release", "paper", "hangar"]},
                "kind": {"type": "string"}, "name": {"type": "string"}, "version": {"type": "string"},
                "source": {"type": "string"}, "source_id": {"type": "string"},
                "digest": {"type": "string", "pattern": "^[0-9a-fA-F]{64}$"}, "filename": {"type": "string"},
                "compatibility": {"type": "string"}, "metadata": {"type": "string"},
                "size": {"type": "integer", "minimum": 0}
            }
        },
        "Artifact": {
            "type": "object",
            "additionalProperties": false,
            "required": ["id", "kind", "name", "version", "source", "source_id", "digest", "filename", "compatibility", "metadata"],
            "properties": {
                "id": {"type": "string", "format": "uuid"}, "kind": {"type": "string"}, "name": {"type": "string"}, "version": {"type": "string"},
                "source": {"type": "string"}, "source_id": {"type": "string"}, "digest": {"type": "string", "pattern": "^[0-9a-fA-F]{64}$"},
                "filename": {"type": "string"}, "compatibility": {"type": "string"}, "metadata": {"type": "string"}
            }
        },
        "ClusterRevision": {
            "type": "object",
            "additionalProperties": false,
            "required": ["id", "number", "runtime_profile", "minecraft_version", "java_requirement", "artifact_set", "config_baseline", "world_bindings", "endpoint_bindings", "placement_requirements", "resource_requirements", "health_checks", "startup_parameters"],
            "properties": {
                "id": {"type": "string", "format": "uuid"}, "number": {"type": "integer", "format": "uint64", "minimum": 0},
                "runtime_profile": {"type": "string", "format": "uuid"}, "minecraft_version": {"type": "string"}, "java_requirement": {"type": "string"},
                "artifact_set": {"type": "string", "format": "uuid"}, "config_baseline": {"type": "string", "format": "uuid"},
                "world_bindings": {"type": "array", "items": {"type": "string", "format": "uuid"}}, "endpoint_bindings": {"type": "array", "items": {"type": "string", "format": "uuid"}},
                "placement_requirements": {"type": "object", "additionalProperties": false, "required": ["process_managers", "required_capabilities"], "properties": {"process_managers": {"type": "array", "items": {"type": "string"}}, "required_capabilities": {"type": "array", "items": {"type": "string"}}}},
                "resource_requirements": {"type": "string"}, "health_checks": {"type": "array", "items": {"type": "string"}}, "startup_parameters": {"type": "array", "items": {"type": "string"}}
            }
        },
        "PolicyGrant": {
            "type": "object",
            "additionalProperties": false,
            "required": ["actor_id", "role", "service_scope", "permissions"],
            "properties": {
                "actor_id": {"type": "string", "format": "uuid"},
                "role": {"type": "string", "enum": ["platform_admin", "operator", "service_maintainer", "auditor"]},
                "service_scope": {"type": "string", "format": "uuid"},
                "permissions": {"type": "array", "items": {"$ref": "#/components/schemas/Permission"}}
            }
        },
        "SftpScanPayload": sftp_scan_schema(),
        "PlanStep": plan_step_schema(),
        "Operation": {
            "type": "object",
            "required": ["id", "status", "plan_hash", "request_id"],
            "properties": {
                "id": {"type": "string"}, "status": {"type": "string"}, "plan_hash": {"type": "string"}, "request_id": {"type": "string"}
            }
        },
        "OperationEvent": {
            "type": "object",
            "required": ["operation_id", "sequence", "status"],
            "properties": {
                "operation_id": {"type": "string"}, "sequence": {"type": "integer", "minimum": 0}, "status": {"type": "string"},
                "message": {"type": ["string", "null"]}, "progress": {"type": ["integer", "null"], "minimum": 0, "maximum": 100}
            }
        },
        "FileEntryList": {"type": "array", "items": {"$ref": "#/components/schemas/FileEntry"}},
        "FileEntry": {
            "type": "object",
            "required": ["path", "size", "digest", "classification"],
            "properties": {"path": {"type": "string"}, "size": {"type": "integer"}, "digest": {"type": "string"}, "classification": {"type": "string"}}
        },
        "FileRead": {
            "type": "object",
            "required": ["path", "content_type", "content"],
            "properties": {"path": {"type": "string"}, "content_type": {"type": "string"}, "content": {"type": "array", "items": {"type": "integer", "minimum": 0, "maximum": 255}}}
        },
        "FileDiff": {
            "type": "object",
            "required": ["path", "changed"],
            "properties": {"path": {"type": "string"}, "before_digest": {"type": ["string", "null"]}, "after_digest": {"type": ["string", "null"]}, "changed": {"type": "boolean"}}
        },
        "BinaryFile": {"type": "string", "format": "binary"},
        "NoContent": {"type": "object"},
        "Health": {"type": "object", "additionalProperties": true},
        "Live": {"type": "object", "required": ["status"], "properties": {"status": {"const": "live"}}},
        "Ready": {
            "type": "object",
            "required": ["status"],
            "properties": {
                "status": {"const": "ready"},
                "checks": {"type": "object", "additionalProperties": true}
            },
            "additionalProperties": true
        },
        "Error": {
            "type": "object",
            "required": ["error"],
            "properties": {"error": {"type": "string"}}
        }
    })
}

fn typed_payload_schema(kind: &str, required: &[&str]) -> Value {
    let properties = required
        .iter()
        .map(|name| {
            let schema = match *name {
                "changed_paths" => json!({
                    "type": "array",
                    "maxItems": 4096,
                    "items": {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["path", "kind", "classification"],
                        "properties": {
                            "path": {"type": "string", "minLength": 1, "maxLength": 4096},
                            "kind": {"type": "string", "enum": ["added", "modified", "removed"]},
                            "before_digest": {"type": ["string", "null"], "pattern": "^[0-9a-fA-F]{64}$"},
                            "after_digest": {"type": ["string", "null"], "pattern": "^[0-9a-fA-F]{64}$"},
                            "classification": {"type": "string", "enum": ["managed", "mutable_config", "artifact", "generated", "state", "secret", "unknown"]}
                        }
                    }
                }),
                "candidate" => json!({"$ref": "#/components/schemas/ArtifactCandidate"}),
                "target" => json!({"$ref": "#/components/schemas/BackupTarget"}),
                "change_session_id" | "service_id" | "cluster_id" | "binding_id" | "endpoint_id" | "execution_binding_id" | "backup_id" | "plan_id" | "operation_id" => json!({"type": "string", "format": "uuid"}),
                "manual_content" => json!({"type": ["array", "null"], "items": {"type": "integer", "minimum": 0, "maximum": 255}}),
                "grants" => json!({"type": "array", "items": {"$ref": "#/components/schemas/PolicyGrant"}}),
                "expected_world_version" | "expected_version" => json!({"type": "integer", "format": "uint64", "minimum": 0}),
                "transition" => json!({
                    "type": "string",
                    "enum": ["planned", "testing", "active", "maintenance", "sunsetting", "archived"]
                }),
                "kind" => json!({
                    "type": "string",
                    "enum": ["change-snapshot", "world", "service-consistent", "external-database-reference"]
                }),
                "domain_revision" => json!({"type": "integer", "minimum": 0}),
                "observed_at" => json!({"type": "integer", "format": "uint64", "minimum": 1}),
                "source" => json!({"type": "string", "enum": ["out_of_band", "provisioning", "operator"]}),
                "plan_hash" | "digest" | "expected_digest" | "expected_manifest_digest" => {
                    json!({"type": "string", "pattern": "^[0-9a-fA-F]{64}$"})
                }
                _ => json!({"type": "string"}),
            };
            ((*name).to_owned(), schema)
        })
        .collect::<Map<String, Value>>();
    let mut value = json!({
        "type": "object",
        "additionalProperties": false,
        "required": required,
        "properties": properties
    });
    if kind == "purge"
        && let Some(confirmation) = value["properties"].get_mut("confirmation")
    {
        *confirmation = json!({"const": "PURGE"});
    }
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["kind", "value"],
        "properties": {
                "kind": {"const": kind},
            "value": value
        }
    })
}

fn step_variant(kind: &str, required: &[&str]) -> Value {
    let properties = required
        .iter()
        .map(|name| {
            let schema = match *name {
                "action" => json!({"type": "string", "enum": ["start", "stop", "restart"]}),
                "content" => json!({"$ref": "#/components/schemas/StagedContent"}),
                "artifact" => json!({"$ref": "#/components/schemas/Artifact"}),
                "revision" => json!({"$ref": "#/components/schemas/ClusterRevision"}),
                "expected_state" | "next_state" => json!({"type": "string", "enum": ["Planned", "Testing", "Active", "Maintenance", "Sunsetting", "Archived"]}),
                "expected_instance_state" | "target_instance_state" => json!({"type": "string", "enum": ["preparing", "ready", "accepting", "draining", "stopped", "failed"]}),
                "expected_before_digest" | "expected_target_digest" => json!({"type": ["string", "null"], "pattern": "^[0-9a-fA-F]{64}$"}),
                "new_endpoint_bindings" => json!({"type": "array", "minItems": 1, "maxItems": 128, "items": {"$ref": "#/components/schemas/EndpointBinding"}}),
                "domain_revision" | "expected_version" | "archived_at" => json!({"type": "integer", "format": "uint64", "minimum": 0}),
                "expected_instance_version" | "target_instance_version" => json!({"type": "integer", "format": "uint64", "minimum": 1}),
                "expected_current_number" | "expected_priority" | "target_priority" => json!({"type": ["integer", "null"], "minimum": 0}),
                "disabled" => json!({"type": "boolean"}),
                "operations" => json!({"type": "array", "minItems": 1, "maxItems": 1024}),
                "configuration" => json!({"type": "array", "minItems": 1, "maxItems": 1024, "items": {"$ref": "#/components/schemas/FileBatchOperation"}}),
                "desired_grants" => json!({"type": "array", "maxItems": 1024, "items": {"$ref": "#/components/schemas/PolicyGrant"}}),
                "expected_writer" | "expected_writer_binding_id" => json!({"type": ["string", "null"], "format": "uuid"}),
                "expected_writer_binding_hash" => json!({"type": ["string", "null"], "pattern": "^[0-9a-fA-F]{64}$"}),
                "runtime_binding_ids" => json!({"type": "array", "minItems": 1, "maxItems": 128, "items": {"type": "string", "format": "uuid"}}),
                "runtime_binding_hashes" => json!({"type": "array", "minItems": 1, "maxItems": 128, "items": {"type": "string", "pattern": "^[0-9a-fA-F]{64}$"}}),
                "target" => json!({"$ref": "#/components/schemas/BackupTarget"}),
                "binding_id" | "expected_binding_id" | "target_binding_id" | "target_writer_binding_id" | "artifact_id" | "artifact_set_id" | "cluster_id" | "pool_id" | "instance_id" | "expected_instance_id" | "target_instance_id" | "world_id" | "endpoint_binding_id" | "policy_id" | "service_id" | "reference_id" | "rollback_reference_id" | "verified_backup_id" => json!({"type": "string", "format": "uuid"}),
                "expected_revision" | "target_revision" => json!({"type": "string", "format": "uuid"}),
                "desired_state" => json!({"type": "string", "enum": ["preparing", "ready", "accepting", "draining", "stopped", "failed"]}),
                "classification" => json!({"type": "string", "enum": ["managed", "mutable_config", "artifact", "generated", "state", "secret", "unknown"]}),
                "path" | "from" | "to" => json!({"type": "string", "minLength": 1, "maxLength": 4096}),
                _ if name.starts_with("expected_") || name.ends_with("_hash") || name.ends_with("_digest") || *name == "request_hash" => json!({"type": "string", "pattern": "^[0-9a-fA-F]{64}$"}),
                _ => json!({"type": "string"}),
            };
            ((*name).to_owned(), schema)
        })
        .collect::<Map<String, Value>>();
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["action"],
        "properties": {
            "action": {
                "type": "object",
                "additionalProperties": false,
                "required": ["kind", "value"],
                "properties": {
                    "kind": {"const": kind},
                    "value": {"type": "object", "additionalProperties": false, "required": required, "properties": properties}
                }
            }
        }
    })
}

fn plan_step_schema() -> Value {
    let variants = [
        (
            "execution_provision",
            &["binding_id", "expected_binding_hash", "domain_revision"][..],
        ),
        (
            "execution_delete",
            &[
                "binding_id",
                "expected_binding_hash",
                "expected_state_hash",
                "domain_revision",
                "expected_version",
            ][..],
        ),
        (
            "service_lifecycle_transition",
            &[
                "service_id",
                "expected_state",
                "next_state",
                "expected_version",
                "reason",
            ][..],
        ),
        (
            "cluster_revision_create",
            &[
                "cluster_id",
                "revision",
                "new_endpoint_bindings",
                "expected_current_number",
            ][..],
        ),
        (
            "execution_lifecycle",
            &[
                "binding_id",
                "action",
                "expected_binding_hash",
                "expected_state_hash",
                "domain_revision",
            ][..],
        ),
        (
            "file_write",
            &[
                "binding_id",
                "path",
                "expected_binding_hash",
                "domain_revision",
                "content",
                "classification",
            ][..],
        ),
        (
            "file_move",
            &[
                "binding_id",
                "from",
                "to",
                "expected_binding_hash",
                "domain_revision",
                "classification",
            ][..],
        ),
        (
            "file_quarantine",
            &[
                "binding_id",
                "path",
                "expected_binding_hash",
                "domain_revision",
                "classification",
            ][..],
        ),
        (
            "file_batch",
            &[
                "binding_id",
                "expected_binding_hash",
                "domain_revision",
                "operations",
            ][..],
        ),
        (
            "artifact_stage",
            &[
                "artifact_id",
                "expected_digest",
                "expected_version",
                "domain_revision",
            ][..],
        ),
        (
            "artifact_register",
            &["artifact", "content", "expected_version", "domain_revision"][..],
        ),
        (
            "artifact_activate",
            &[
                "artifact_id",
                "artifact_set_id",
                "binding_id",
                "expected_binding_hash",
                "cluster_id",
                "expected_revision",
                "target_revision",
                "expected_digest",
                "expected_version",
                "destination_path",
                "expected_before_digest",
            ][..],
        ),
        (
            "proxy_rollout",
            &[
                "pool_id",
                "expected_instance_id",
                "target_instance_id",
                "expected_instance_version",
                "target_instance_version",
                "expected_instance_state",
                "target_instance_state",
                "target_binding_id",
                "target_binding_hash",
                "domain_revision",
                "desired_state",
                "configuration",
            ][..],
        ),
        (
            "world_writer_cutover",
            &[
                "world_id",
                "expected_version",
                "expected_writer",
                "next_writer",
                "expected_writer_binding_id",
                "target_writer_binding_id",
                "expected_writer_binding_hash",
                "target_writer_binding_hash",
                "domain_revision",
            ][..],
        ),
        (
            "endpoint_rollout",
            &[
                "expected_binding_id",
                "target_binding_id",
                "cluster_id",
                "expected_revision",
                "target_revision",
                "expected_version",
                "runtime_binding_ids",
                "runtime_binding_hashes",
            ][..],
        ),
        (
            "access_policy_update",
            &[
                "policy_id",
                "service_id",
                "expected_version",
                "desired_grants",
                "desired_policy_hash",
            ][..],
        ),
        (
            "route_policy_update",
            &[
                "route_id",
                "pool_id",
                "service_id",
                "expected_cluster",
                "target_cluster",
                "expected_priority",
                "target_priority",
                "expected_version",
                "disabled",
            ][..],
        ),
        ("backup_create", &["kind", "target", "request_hash"][..]),
        (
            "backup_restore",
            &[
                "reference_id",
                "target",
                "expected_manifest_digest",
                "rollback_reference_id",
                "expected_rollback_manifest_digest",
                "expected_version",
            ][..],
        ),
        (
            "service_archive",
            &["service_id", "expected_version", "sunsetting_evidence_hash"][..],
        ),
        (
            "service_purge",
            &[
                "service_id",
                "expected_version",
                "archive_evidence_hash",
                "verified_backup_id",
                "archived_at",
            ][..],
        ),
    ];
    json!({"oneOf": variants.into_iter().map(|(kind, required)| step_variant(kind, required)).collect::<Vec<_>>()})
}

fn sftp_scan_schema() -> Value {
    typed_payload_schema(
        "sftp-scan",
        &[
            "change_session_id",
            "service_id",
            "endpoint_id",
            "execution_binding_id",
            "before_manifest_hash",
            "after_manifest_hash",
            "changed_paths",
            "observed_at",
            "source",
        ],
    )
}
