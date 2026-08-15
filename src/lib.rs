//! `dev.mcpg.backend.elasticsearch` — Elasticsearch / OpenSearch backend
//! binding plugin.
//!
//! One binding == one ES operation (the `http`/`sql` envelope model): the
//! operator declares `backend: { kind: elasticsearch, operation, urls,
//! index_allowlist, ... }` and that binding becomes one MCP tool. Per call
//! the tool arguments are turned into one ES REST request (method + path +
//! body + content-type), dispatched via `reqwest` (rustls-tls) under a
//! per-call timeout, and the response is shaped into a stable envelope.
//!
//! v1 operations: `search`, `count`, `get`, `index`, `delete`, `bulk`,
//! `msearch`. The index travels as an allowlisted, path-injection-guarded
//! tool argument (or a binding `default_index`); write ops are gated by
//! `allow_writes`. The `expand_capabilities` index-per-tool catalog is a
//! deferred follow-up.

mod config;
mod dispatch;
mod surface;
pub mod watch;

#[cfg(any(feature = "cdylib-export", feature = "static-firstparty"))]
mod cdylib;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use mcpg_plugin_protocol::audit::{AuditEvent, AuditOutcome};
use mcpg_plugin_protocol::types::PluginIdentity;
use mcpg_plugin_protocol::{
    BackendError, BackendHost, BackendPlugin, BackendRequest, BackendResponse, PluginManifest,
    ResourcePage, firstparty_manifest,
};
use mcpg_plugin_sdk::HostHandle;
use serde_json::{Value, json};
use tracing::debug;

pub use config::{ElasticsearchBackendSpec, EsAuth, EsOperation, EsTlsConfig, SpecError};

/// Sentinel wrapper the gateway projects verbatim as a `CallToolResult`
/// (so we can return `isError: true` tool-level errors). Matches the host
/// + mock-backend constant.
const VERBATIM_RESULT_KEY: &str = "__mcpg_verbatim_result";

struct EsProfile {
    spec: ElasticsearchBackendSpec,
    client: reqwest::Client,
    urls: Vec<String>,
    /// `cred://`-bearing auth secret refs captured from the gateway's
    /// `__mcpg_secret_refs` injection (rotation / revocation bookkeeping).
    #[allow(dead_code)]
    secret_refs: Vec<String>,
}

/// `BackendPlugin` for `kind: "elasticsearch"`.
pub struct ElasticsearchBackendPlugin {
    manifest: PluginManifest,
    // std RwLock: guards are never held across `.await` (the client is
    // built before the write lock is taken; `execute` clones the Arc out
    // before awaiting). Lets the sync trait methods read it too.
    profiles: RwLock<BTreeMap<String, Arc<EsProfile>>>,
    /// Unified host surface for per-call observability. Installed once at
    /// boot by the gateway before any `execute()` traffic; `None` in test
    /// harnesses (the triad short-circuits to a no-op).
    host_handle: OnceLock<HostHandle>,
}

impl Default for ElasticsearchBackendPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl ElasticsearchBackendPlugin {
    #[must_use]
    pub fn new() -> Self {
        Self {
            manifest: firstparty_manifest! {
                id: "dev.mcpg.backend.elasticsearch",
                name: "Elasticsearch Binding",
                class: Backend,
            },
            profiles: RwLock::new(BTreeMap::new()),
            host_handle: OnceLock::new(),
        }
    }

    /// No plugin-level config — per-binding connection + operation details
    /// arrive via `register_profile`.
    pub fn from_config_json(_config_json: &str) -> Self {
        Self::new()
    }

    /// Install the unified [`HostHandle`]. Idempotent — a second call is a
    /// no-op. Returns whether the slot was filled.
    pub fn set_host_handle(&self, host: HostHandle) -> bool {
        self.host_handle.set(host).is_ok()
    }

    fn host_handle(&self) -> Option<&HostHandle> {
        self.host_handle.get()
    }

    fn profile(&self, name: &str) -> Option<Arc<EsProfile>> {
        self.profiles
            .read()
            .expect("profiles lock poisoned")
            .get(name)
            .cloned()
    }

    /// Emit the per-call observability triad (latency histogram + counter +
    /// optional audit event) through the installed [`HostHandle`].
    /// Short-circuits when no handle is installed (test paths).
    #[allow(clippy::too_many_arguments)]
    async fn emit_host_observability(
        &self,
        backend_name: &str,
        outcome_label: &'static str,
        status_code: Option<u16>,
        reason: Option<&str>,
        identity: Option<&PluginIdentity>,
        request_id: &str,
        duration: Duration,
    ) {
        let Some(host) = self.host_handle() else {
            return;
        };
        host.histogram(
            "mcpg_es_backend_latency_seconds",
            duration.as_secs_f64(),
            &[("outcome", outcome_label)],
        );
        host.counter(
            "mcpg_es_backend_calls_total",
            1,
            &[("outcome", outcome_label)],
        );

        if let Some(action) = audit_action_for_outcome(outcome_label) {
            let actor = identity.cloned().unwrap_or_else(synthetic_system_identity);
            let mut details = json!({
                "backend": backend_name,
                "duration_ms": duration.as_millis() as u64,
                "outcome": outcome_label,
                "alias": host.alias(),
            });
            if let Some(status) = status_code {
                details
                    .as_object_mut()
                    .expect("json object")
                    .insert("status_code".into(), Value::from(status));
            }
            if let Some(reason) = reason {
                details
                    .as_object_mut()
                    .expect("json object")
                    .insert("reason".into(), Value::String(reason.to_owned()));
            }
            let event = AuditEvent {
                event_id: format!("es-{}-{}", request_id, duration.as_nanos()),
                occurred_at: rfc3339_now(),
                actor,
                action: action.to_owned(),
                resource: Some(format!("es-binding://{backend_name}")),
                outcome: AuditOutcome::Failure,
                request_id: Some(request_id.to_owned()),
                node_id: None,
                details,
                prev_event_hash: None,
            };
            let host_for_audit = host.clone();
            if let Err(join_err) = tokio::task::spawn_blocking(move || {
                let _ = host_for_audit.audit_event(event);
            })
            .await
            {
                debug!(
                    target: "mcpg::elasticsearch::host_handle",
                    error = %join_err,
                    "host_handle.audit_event spawn_blocking failed"
                );
            }
        }
    }
}

impl std::fmt::Debug for ElasticsearchBackendPlugin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ElasticsearchBackendPlugin")
            .field("id", &self.manifest.id)
            .finish()
    }
}

/// Bounded outcome label for the unified host-handle metric pair. The set
/// MUST stay closed so the host metrics recorder doesn't blow up on
/// cardinality. 4xx/5xx are class-bucketed.
fn host_outcome_label_for_status(status: u16) -> &'static str {
    match status {
        200..=299 => "ok",
        400..=499 => "es_4xx",
        500..=599 => "es_5xx",
        _ => "ok",
    }
}

/// Bounded outcome label for the transport-error path (no HTTP status).
fn host_outcome_label_for_transport_error(message: &str) -> &'static str {
    let lower = message.to_ascii_lowercase();
    if lower.contains("timed out") || lower.contains("timeout") {
        "timeout"
    } else {
        "transport"
    }
}

/// Bounded set of dotted audit-event action names emitted on notable
/// failures. `None` for success + 4xx (normal traffic). Driver-class
/// failures (timeout / transport / 5xx) emit so operators can reconstruct
/// upstream outages.
fn audit_action_for_outcome(label: &str) -> Option<&'static str> {
    match label {
        "timeout" => Some("dev.mcpg.backend.elasticsearch.request_timeout"),
        "transport" => Some("dev.mcpg.backend.elasticsearch.request_failed"),
        "es_5xx" => Some("dev.mcpg.backend.elasticsearch.upstream_5xx"),
        _ => None,
    }
}

fn rfc3339_now() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// Synthetic identity for audit events on system-initiated calls (no
/// caller attribution).
fn synthetic_system_identity() -> PluginIdentity {
    PluginIdentity {
        kind: "system".into(),
        trust_level: "verified".into(),
        subject_id: Some("dev.mcpg.backend.elasticsearch".into()),
        auth_provider: None,
        issuer: None,
        roles: vec![],
        groups: vec![],
        scopes: vec![],
        attributes: Default::default(),
    }
}

fn verbatim_error(msg: &str) -> Vec<u8> {
    let envelope = json!({
        VERBATIM_RESULT_KEY: {
            "content": [ { "type": "text", "text": msg } ],
            "isError": true,
        }
    });
    serde_json::to_vec(&envelope).unwrap_or_else(|_| b"{}".to_vec())
}

#[async_trait]
impl BackendPlugin for ElasticsearchBackendPlugin {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn kind(&self) -> &str {
        "elasticsearch"
    }

    async fn register_profile(
        &self,
        profile_name: &str,
        spec: &Value,
        host: Arc<dyn BackendHost>,
    ) -> Result<(), BackendError> {
        let _ = &host; // cred:// resolution happens per-call via the cdylib-bridged host
        let parsed =
            ElasticsearchBackendSpec::parse(spec).map_err(|e| BackendError::InvalidSpec {
                message: e.to_string(),
            })?;

        if parsed.allow_any_index {
            tracing::warn!(
                target: "mcpg::elasticsearch",
                backend = %profile_name,
                "elasticsearch binding registered with allow_any_index — index allowlist bypassed"
            );
        }

        // The gateway injects `__mcpg_secret_refs` post-resolution so we can
        // track which cred:// refs touched the auth surface for rotation.
        let secret_refs: Vec<String> = spec
            .get("__mcpg_secret_refs")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default();

        let urls = parsed.trimmed_urls();
        let client = dispatch::build_client(&parsed).map_err(|e| BackendError::InvalidSpec {
            message: format!("elasticsearch client init: {e}"),
        })?;

        debug!(
            target: "mcpg::elasticsearch",
            backend = %profile_name,
            operation = %parsed.operation.as_str(),
            urls = ?urls,
            "registered elasticsearch binding profile"
        );

        let profile = Arc::new(EsProfile {
            spec: parsed,
            client,
            urls,
            secret_refs,
        });
        self.profiles
            .write()
            .expect("profiles lock poisoned")
            .insert(profile_name.to_owned(), profile);
        Ok(())
    }

    async fn execute(
        &self,
        profile_name: &str,
        request: BackendRequest,
    ) -> Result<BackendResponse, BackendError> {
        let t0 = Instant::now();
        let request_id = request.request_id.clone();
        let identity = request.identity.clone();

        let profile = match self.profile(profile_name) {
            Some(p) => p,
            None => {
                let err = BackendError::ProfileNotFound {
                    backend_name: profile_name.to_owned(),
                };
                return Err(err);
            }
        };

        // Parse tool arguments. Bad JSON is a tool-level error (the caller
        // sent garbage), NOT a backend transport failure.
        let args: Value = if request.payload.is_empty() {
            json!({})
        } else {
            match serde_json::from_slice(&request.payload) {
                Ok(v) => v,
                Err(e) => {
                    return Ok(BackendResponse {
                        payload: verbatim_error(&format!("invalid tool arguments JSON: {e}")),
                        truncated: false,
                    });
                }
            }
        };

        // Build the REST call (method + path + body + content-type). All
        // bad-argument paths (off-allowlist index, scripting guard,
        // missing required field) return a tool-level error.
        let call = match dispatch::build_call(&profile.spec, &args) {
            Ok(c) => c,
            Err(msg) => {
                return Ok(BackendResponse {
                    payload: verbatim_error(&msg),
                    truncated: false,
                });
            }
        };

        // Resolve the auth header value at dispatch time and issue the
        // request against the first healthy URL.
        let outcome =
            dispatch::issue_call(&profile.client, &profile.urls, &profile.spec, &call).await;

        let (label, status, reason, response) = match outcome {
            Ok(res) => {
                let label = host_outcome_label_for_status(res.status);
                let reason = if res.status >= 400 {
                    Some(format!("upstream status {}", res.status))
                } else {
                    None
                };
                (label, Some(res.status), reason, Ok(res))
            }
            Err(message) => {
                let label = host_outcome_label_for_transport_error(&message);
                (label, None, Some(message.clone()), Err(message))
            }
        };

        self.emit_host_observability(
            profile_name,
            label,
            status,
            reason.as_deref(),
            identity.as_ref(),
            request_id.as_str(),
            t0.elapsed(),
        )
        .await;

        match response {
            Ok(res) => {
                let envelope = dispatch::build_envelope(&profile.spec, &call, &res);
                // On the resource/prompt surfaces a successful (2xx) response is
                // reshaped into the surface-correct body the gateway decoder
                // requires; a non-2xx response keeps the tool envelope (carrying
                // `downstreamError` → gateway `is_error`) so the resource/prompt
                // decoder sees a clean error rather than an invalid `{contents}`.
                // The wrapped body is the upstream JSON response (or the envelope
                // when there is no JSON body).
                let is_success = (200..300).contains(&res.status);
                let body = if is_success && profile.spec.surface != surface::Surface::Tool {
                    let upstream = res.json.clone().unwrap_or_else(|| envelope.clone());
                    match profile.spec.surface {
                        surface::Surface::Tool => envelope,
                        surface::Surface::Resource => {
                            match surface::resolve_resource_uri(profile.spec.uri.as_deref(), &args)
                            {
                                Some(uri) => surface::resource_contents_body(uri, &upstream),
                                None => {
                                    return Ok(BackendResponse {
                                        payload: verbatim_error(
                                            "resource surface requires a `uri` (set a static `uri` on the binding or invoke via a resources/read request)",
                                        ),
                                        truncated: false,
                                    });
                                }
                            }
                        }
                        surface::Surface::Prompt => surface::prompt_messages_body(&upstream),
                    }
                } else {
                    envelope
                };
                let payload = serde_json::to_vec(&body).map_err(|e| BackendError::Transport {
                    message: format!("elasticsearch envelope serialization failed: {e}"),
                })?;
                let truncated = surface::surface_truncated(profile.spec.surface, res.truncated);
                Ok(BackendResponse { payload, truncated })
            }
            Err(message) => {
                if host_outcome_label_for_transport_error(&message) == "timeout" {
                    Err(BackendError::Timeout {
                        timeout_ms: profile.spec.operation_timeout_ms,
                    })
                } else {
                    Err(BackendError::Transport { message })
                }
            }
        }
    }

    fn input_schema(&self, profile_name: &str) -> Option<Value> {
        self.profile(profile_name)
            .map(|p| dispatch::op_input_schema(p.spec.operation))
    }

    /// JSON Schema for the response envelope this binding emits.
    fn output_schema(&self, _profile_name: &str) -> Option<Value> {
        Some(dispatch::result_envelope_schema())
    }

    fn audit_metadata(&self, profile_name: &str) -> serde_json::Map<String, Value> {
        let mut m = serde_json::Map::new();
        if let Some(p) = self.profile(profile_name) {
            m.insert(
                "es.operation".into(),
                Value::String(p.spec.operation.as_str().to_owned()),
            );
            m.insert(
                "es.index_mode".into(),
                Value::String(if p.spec.allow_any_index {
                    "any".to_owned()
                } else {
                    "allowlist".to_owned()
                }),
            );
        }
        m
    }

    /// Enumerate resources for `resources/list` via the operator-fixed
    /// `list_query` `_search`. The cursor is the integer offset (`from`).
    /// Bindings without a `list_query` inherit the empty page.
    async fn list_resources(
        &self,
        profile_name: &str,
        cursor: Option<&str>,
    ) -> Result<ResourcePage, BackendError> {
        let profile = self
            .profile(profile_name)
            .ok_or_else(|| BackendError::ProfileNotFound {
                backend_name: profile_name.to_owned(),
            })?;
        let Some(list) = profile.spec.list_query.clone() else {
            return Ok(ResourcePage::empty());
        };
        let from = match cursor {
            Some(c) => c.parse::<u64>().map_err(|_| BackendError::InvalidSpec {
                message: format!("list cursor '{c}' is not a non-negative integer"),
            })?,
            None => 0,
        };

        let call = dispatch::build_list_call(&profile.spec, &list, from)
            .map_err(|message| BackendError::InvalidSpec { message })?;
        let res = dispatch::issue_call(&profile.client, &profile.urls, &profile.spec, &call)
            .await
            .map_err(|message| BackendError::Transport { message })?;
        if res.status >= 400 {
            return Err(BackendError::Transport {
                message: format!("elasticsearch list_query returned status {}", res.status),
            });
        }
        let body = res.json.unwrap_or(Value::Null);
        let hits = dispatch::search_hits(&body);
        Ok(surface::hits_to_resource_page(
            &hits,
            &list.uri_field,
            list.name_field.as_deref(),
            list.description_field.as_deref(),
            from,
            list.page_size,
        ))
    }

    /// Return completion candidates for a resource-template variable via the
    /// operator-fixed `variable_completions[<variable_name>]` `_search`. The
    /// caller prefix is bound as a JSON string value in a `prefix` query —
    /// never raw query DSL. Unconfigured variables inherit the empty list.
    async fn complete_template_variable(
        &self,
        profile_name: &str,
        variable_name: &str,
        prefix: &str,
        _config: &Value,
        _context: &BTreeMap<String, String>,
    ) -> Result<Vec<String>, BackendError> {
        let profile = self
            .profile(profile_name)
            .ok_or_else(|| BackendError::ProfileNotFound {
                backend_name: profile_name.to_owned(),
            })?;
        let Some(cc) = profile
            .spec
            .variable_completions
            .get(variable_name)
            .cloned()
        else {
            return Ok(vec![]);
        };
        let max = cc.max_results.unwrap_or(100) as u64;

        let call = dispatch::build_completion_call(&profile.spec, &cc, prefix, max)
            .map_err(|message| BackendError::InvalidSpec { message })?;
        let res = dispatch::issue_call(&profile.client, &profile.urls, &profile.spec, &call)
            .await
            .map_err(|message| BackendError::Transport { message })?;
        if res.status >= 400 {
            return Err(BackendError::Transport {
                message: format!("elasticsearch completion returned status {}", res.status),
            });
        }
        let body = res.json.unwrap_or(Value::Null);
        let hits = dispatch::search_hits(&body);
        Ok(surface::hits_to_completion_values(
            &hits,
            &cc.field,
            max as usize,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
    }

    fn plugin_with(spec: Value) -> ElasticsearchBackendPlugin {
        let p = ElasticsearchBackendPlugin::new();
        rt().block_on(async {
            let host = mcpg_plugin_protocol::noop_backend_host();
            BackendPlugin::register_profile(&p, "t", &spec, host)
                .await
                .unwrap();
        });
        p
    }

    fn search_spec() -> Value {
        json!({
            "urls": ["https://es.example.com:9200"],
            "operation": "search",
            "index_allowlist": ["logs"],
            "default_index": "logs"
        })
    }

    fn req(args: Value) -> BackendRequest {
        BackendRequest {
            payload: serde_json::to_vec(&args).unwrap(),
            headers: vec![],
            request_id: "r".into(),
            session_id: None,
            identity: None,
            idempotency: None,
        }
    }

    #[test]
    fn kind_and_manifest() {
        let p = ElasticsearchBackendPlugin::new();
        assert_eq!(BackendPlugin::kind(&p), "elasticsearch");
        assert_eq!(p.manifest.id, "dev.mcpg.backend.elasticsearch");
    }

    #[test]
    fn register_rejects_bad_spec() {
        let p = ElasticsearchBackendPlugin::new();
        let err = rt().block_on(async {
            let host = mcpg_plugin_protocol::noop_backend_host();
            BackendPlugin::register_profile(&p, "t", &json!({ "urls": [] }), host).await
        });
        assert!(matches!(err, Err(BackendError::InvalidSpec { .. })));
    }

    #[test]
    fn execute_unknown_profile_is_profile_not_found() {
        let p = ElasticsearchBackendPlugin::new();
        let err =
            rt().block_on(async { BackendPlugin::execute(&p, "missing", req(json!({}))).await });
        assert!(matches!(err, Err(BackendError::ProfileNotFound { .. })));
    }

    #[test]
    fn list_resources_empty_when_unconfigured() {
        let p = plugin_with(search_spec());
        let page = rt()
            .block_on(async { BackendPlugin::list_resources(&p, "t", None).await })
            .expect("list");
        assert!(page.resources.is_empty());
        assert!(page.next_cursor.is_none());
    }

    #[test]
    fn complete_template_variable_empty_when_unconfigured() {
        let p = plugin_with(search_spec());
        let got = rt()
            .block_on(async {
                BackendPlugin::complete_template_variable(
                    &p,
                    "t",
                    "v",
                    "x",
                    &json!({}),
                    &BTreeMap::new(),
                )
                .await
            })
            .expect("complete");
        assert!(got.is_empty());
    }

    #[test]
    fn list_resources_unknown_profile_is_profile_not_found() {
        let p = ElasticsearchBackendPlugin::new();
        let err = rt().block_on(async { BackendPlugin::list_resources(&p, "missing", None).await });
        assert!(matches!(err, Err(BackendError::ProfileNotFound { .. })));
    }

    #[test]
    fn register_stores_list_query_and_completions() {
        let mut spec = search_spec();
        spec["surface"] = json!("resource");
        spec["list_query"] = json!({ "uri_field": "uri", "page_size": 25 });
        spec["variable_completions"] = json!({ "name": { "field": "name.keyword" } });
        let p = plugin_with(spec);
        let prof = p.profile("t").unwrap();
        assert!(prof.spec.list_query.is_some());
        assert!(prof.spec.variable_completions.contains_key("name"));
    }

    #[test]
    fn execute_non_json_payload_is_tool_error() {
        let p = plugin_with(search_spec());
        let resp = rt()
            .block_on(async {
                BackendPlugin::execute(
                    &p,
                    "t",
                    BackendRequest {
                        payload: b"{ not json".to_vec(),
                        headers: vec![],
                        request_id: "r".into(),
                        session_id: None,
                        identity: None,
                        idempotency: None,
                    },
                )
                .await
            })
            .unwrap();
        let v: Value = serde_json::from_slice(&resp.payload).unwrap();
        assert_eq!(v[VERBATIM_RESULT_KEY]["isError"], true);
    }

    #[test]
    fn execute_off_allowlist_index_is_tool_error() {
        let p = plugin_with(search_spec());
        let resp = rt()
            .block_on(async {
                BackendPlugin::execute(&p, "t", req(json!({ "index": "secrets" }))).await
            })
            .unwrap();
        let v: Value = serde_json::from_slice(&resp.payload).unwrap();
        assert_eq!(v[VERBATIM_RESULT_KEY]["isError"], true);
    }

    #[test]
    fn audit_metadata_carries_op_and_mode() {
        let p = plugin_with(search_spec());
        let m = BackendPlugin::audit_metadata(&p, "t");
        assert_eq!(m["es.operation"], "search");
        assert_eq!(m["es.index_mode"], "allowlist");
    }

    #[test]
    fn input_schema_search_has_query() {
        let p = plugin_with(search_spec());
        let schema = BackendPlugin::input_schema(&p, "t").unwrap();
        assert!(schema["properties"]["query"].is_object());
        assert!(schema["properties"]["size"].is_object());
    }

    #[test]
    fn input_schema_knn_has_query_vector() {
        let spec = json!({
            "urls": ["https://es.example.com:9200"],
            "operation": "knn",
            "index_allowlist": ["docs"],
            "default_index": "docs",
            "knn": { "field": "embedding", "k": 5 }
        });
        let p = plugin_with(spec);
        let schema = BackendPlugin::input_schema(&p, "t").unwrap();
        assert!(schema["properties"]["query_vector"].is_object());
        assert_eq!(schema["properties"]["query_vector"]["type"], "array");
        let m = BackendPlugin::audit_metadata(&p, "t");
        assert_eq!(m["es.operation"], "knn");
    }
}
