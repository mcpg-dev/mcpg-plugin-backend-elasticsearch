//! `watch_strategy` entity (`elasticsearch_poll`) — the POLLING change-watch
//! path.
//!
//! Elasticsearch has no native change-push channel for arbitrary indices, so
//! this strategy polls a cheap, sorted `_search` (the index's newest document
//! by a monotonic `cursor_field`) on a cadence and signals a change whenever
//! that top sort value advances. The poll thread, the cursor diff, the stop
//! signal and the opaque handle round-trip all live in the shared
//! [`mcpg_plugin_sdk::watch`] helper — this entity only supplies the per-tick
//! `poll` closure over the backend's own reqwest dispatch.
//!
//! The helper's loop is synchronous and [`dispatch::issue_call`] is async, so a
//! single current-thread tokio runtime is built once in [`watch`] and moved
//! into the closure; each tick `block_on`s one search (sequential ticks, so a
//! single-thread runtime is enough). Connect / search failures map to the
//! closure's `Err(String)` — the helper logs and retries on the next tick.

use std::sync::Arc;
use std::time::Duration;

use mcpg_plugin_protocol::backend::WatchError;
use mcpg_plugin_protocol::{PluginManifest, firstparty_manifest};
use mcpg_plugin_sdk::HostHandle;
use mcpg_plugin_sdk::ffi::{SyncWatchStrategyPlugin, WatchHandleBox};
use mcpg_plugin_sdk::watch::{cancel_polling_watch, spawn_polling_watch};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::config::{ElasticsearchBackendSpec, EsAuth, EsOperation, EsTlsConfig};
use crate::dispatch::{self, EsRestCall};

pub const PLUGIN_ID: &str = "dev.mcpg.backend.elasticsearch";

/// The strategy discriminator this entity handles.
pub const WATCH_KIND: &str = "elasticsearch_poll";

/// Default poll cadence when `interval_ms` is omitted (1 minute).
fn default_interval_ms() -> u64 {
    60_000
}

/// Default per-tick search budget when `timeout_ms` is omitted (10 seconds).
fn default_timeout_ms() -> u64 {
    10_000
}

/// Per-watch spec: the ES connection fields needed to build a client (reusing
/// the backend's connection shape verbatim) plus the index/alias to watch, the
/// monotonic `cursor_field` to sort on, and an optional scoping `query`. The
/// connection is carried per-watch (not at plugin level), so a watcher is
/// self-contained.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WatchSpec {
    /// Base URL(s) — same shape as the binding (first is primary, the rest are
    /// failover). Each must be `https://` (or `http://localhost` for tests).
    urls: Vec<String>,
    /// HTTP auth surface (ApiKey / Basic / Bearer), same shape as the binding.
    #[serde(default)]
    auth: EsAuth,
    /// TLS knobs (CA bundle / loopback-gated insecure-skip-verify), same shape
    /// as the binding.
    #[serde(default)]
    tls: EsTlsConfig,
    /// Index or alias to watch. REQUIRED.
    index: String,
    /// A monotonically-advancing field to sort on (e.g. `@timestamp` or
    /// `_seq_no`); its top (descending) value is the cursor. REQUIRED.
    cursor_field: String,
    /// Optional ES query DSL scoping the watch (e.g. only a tenant's docs).
    /// Defaults to `match_all`.
    #[serde(default)]
    query: Option<Value>,
    /// Allow private/loopback resolved addresses (test / in-cluster ES).
    #[serde(default)]
    allow_private_backends: bool,
    /// Poll cadence in milliseconds (default 60000; floored by the SDK helper).
    #[serde(default = "default_interval_ms")]
    interval_ms: u64,
    /// Per-tick connect + wall-clock search budget in milliseconds
    /// (default 10000).
    #[serde(default = "default_timeout_ms")]
    timeout_ms: u64,
}

/// `watch_strategy` entity. Stateless beyond its manifest — every watcher's
/// connection + index + cursor field arrive on the per-watch spec.
pub struct ElasticsearchWatchCdylib {
    manifest: PluginManifest,
}

impl ElasticsearchWatchCdylib {
    /// Infallible cdylib factory. `config_json` + host are ignored — the watch
    /// carries no plugin-level config (the connection + index + cursor field
    /// arrive via the per-watch spec).
    pub fn from_host_config(_config_json: &str, _host: HostHandle) -> Self {
        Self {
            manifest: firstparty_manifest! {
                id: "dev.mcpg.backend.elasticsearch",
                name: "Elasticsearch Poll Watch Strategy",
                class: WatchStrategy,
            },
        }
    }
}

/// Extract the cursor from the top hit of a sorted `_search` response: prefer
/// the hit's `sort` array (the value ES sorted on — present whenever the search
/// carried a `sort` clause), falling back to the `_source.<cursor_field>` leaf.
/// `None` when there are zero hits (no signal this tick) or no extractable
/// value. String values yield the bare string; everything else its JSON
/// rendering, so the cursor comparison is stable across ticks.
fn cursor_from_hit(body: &Value, cursor_field: &str) -> Option<String> {
    let hits = dispatch::search_hits(body);
    let top = hits.first()?;

    // The `sort` array carries the exact value ES sorted on (the most reliable
    // cursor); take its first element.
    if let Some(sort_val) = top
        .get("sort")
        .and_then(Value::as_array)
        .and_then(|a| a.first())
    {
        return stringify_scalar(sort_val);
    }

    // Fall back to the projected `_source.<cursor_field>` (dot-path) leaf.
    let leaf = dot_path(top.get("_source")?, cursor_field)?;
    stringify_scalar(leaf)
}

/// Stringify a JSON scalar for cursor comparison. `None` for `null`.
fn stringify_scalar(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Null => None,
        other => Some(other.to_string()),
    }
}

/// Resolve a dot-path (`a.b.c`) against a JSON object, returning the leaf.
fn dot_path<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = root;
    for seg in path.split('.') {
        cur = cur.get(seg)?;
    }
    Some(cur)
}

impl SyncWatchStrategyPlugin for ElasticsearchWatchCdylib {
    fn manifest(&self) -> &PluginManifest {
        &self.manifest
    }

    fn kind(&self) -> &str {
        WATCH_KIND
    }

    fn watch(
        &self,
        resource_uri: &str,
        spec: &Value,
        emit_event: Box<dyn Fn(&str) + Send + Sync + 'static>,
    ) -> Result<WatchHandleBox, WatchError> {
        let parsed: WatchSpec =
            serde_json::from_value(spec.clone()).map_err(|e| WatchError::InvalidSpec {
                message: format!("invalid elasticsearch_poll watch spec: {e}"),
            })?;

        let invalid = |m: String| WatchError::InvalidSpec { message: m };
        if parsed.index.trim().is_empty() {
            return Err(invalid("index must not be empty".into()));
        }
        if parsed.cursor_field.trim().is_empty() {
            return Err(invalid("cursor_field must not be empty".into()));
        }

        // Reuse the backend's spec validation + client builder by synthesising a
        // minimal read-only `search` binding spec: the watch index is the sole
        // allowlist entry, so the resolved search path is fenced the same way a
        // per-call search index is. A parse/validate failure (bad URL, unsafe
        // index token, …) surfaces as an InvalidSpec.
        let backend_spec_json = json!({
            "urls": parsed.urls,
            "operation": "search",
            "index_allowlist": [parsed.index],
            "default_index": parsed.index,
            "auth": serde_json::to_value(&parsed.auth).map_err(|e| invalid(e.to_string()))?,
            "tls": serde_json::to_value(&parsed.tls).map_err(|e| invalid(e.to_string()))?,
            "allow_private_backends": parsed.allow_private_backends,
            "operation_timeout_ms": parsed.timeout_ms.max(1),
            "connect_timeout_ms": parsed.timeout_ms.max(1),
        });
        let backend_spec = ElasticsearchBackendSpec::parse(&backend_spec_json)
            .map_err(|e| invalid(e.to_string()))?;

        // The verifying client (no socket opened here). A build failure (bad CA
        // PEM, …) is a Subscribe error.
        let client = dispatch::build_client(&backend_spec).map_err(|e| WatchError::Subscribe {
            message: format!("elasticsearch_poll: client init: {e}"),
        })?;

        // Pre-build the sorted, size-1, cursor-field-only search body once: the
        // body is operator-fixed and identical every tick.
        let query = parsed.query.unwrap_or_else(|| json!({ "match_all": {} }));
        let cursor_field = parsed.cursor_field;
        let index = backend_spec.default_index.clone().unwrap_or_default();
        let body = json!({
            "query": query,
            "size": 1,
            "sort": [ { &cursor_field: { "order": "desc" } } ],
            "_source": [ cursor_field.as_str() ],
        });
        let body_bytes = serde_json::to_vec(&body).map_err(|e| invalid(e.to_string()))?;
        let call = EsRestCall {
            method: reqwest::Method::POST,
            path: format!("/{index}/_search"),
            query: None,
            body: Some(body_bytes),
            content_type: "application/json",
            operation: EsOperation::Search,
            display_path: format!("/{index}/_search"),
        };

        // One current-thread runtime, moved into the closure: ticks are
        // sequential, so a single-thread runtime is enough to `block_on` each
        // async search.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| WatchError::Subscribe {
                message: format!("elasticsearch_poll: tokio runtime init failed: {e}"),
            })?;

        let client = Arc::new(client);
        let backend_spec = Arc::new(backend_spec);
        let urls = backend_spec.trimmed_urls();
        let call = Arc::new(call);

        let poll = move || -> Result<Option<String>, String> {
            let res = rt.block_on(dispatch::issue_call(&client, &urls, &backend_spec, &call))?;
            if res.status >= 400 {
                return Err(format!(
                    "elasticsearch _search returned status {}",
                    res.status
                ));
            }
            let body = res.json.unwrap_or(Value::Null);
            Ok(cursor_from_hit(&body, &cursor_field))
        };

        Ok(spawn_polling_watch(
            resource_uri,
            Duration::from_millis(parsed.interval_ms),
            emit_event,
            poll,
        ))
    }

    fn cancel(&self, watch_handle: WatchHandleBox) {
        cancel_polling_watch(watch_handle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn stub_host() -> HostHandle {
        // SAFETY: `stub_host_ref` returns a process-static no-op host ref; the
        // factory ignores the host entirely.
        #[allow(unsafe_code)]
        unsafe {
            HostHandle::from_ffi(mcpg_plugin_sdk::testing::stub_host_ref())
        }
    }

    fn plugin() -> ElasticsearchWatchCdylib {
        ElasticsearchWatchCdylib::from_host_config("", stub_host())
    }

    fn emit_noop() -> Box<dyn Fn(&str) + Send + Sync + 'static> {
        Box::new(|_| {})
    }

    #[test]
    fn manifest_and_kind_are_correct() {
        use mcpg_plugin_protocol::PluginClass;
        let p = plugin();
        let m = SyncWatchStrategyPlugin::manifest(&p);
        assert_eq!(m.id, PLUGIN_ID);
        assert_eq!(m.plugin_class, PluginClass::WatchStrategy);
        assert_eq!(p.kind(), WATCH_KIND);
    }

    #[test]
    fn spec_parses_with_defaults() {
        let parsed: WatchSpec = serde_json::from_value(json!({
            "urls": ["https://es.example.com:9200"],
            "index": "logs",
            "cursor_field": "@timestamp",
        }))
        .unwrap();
        assert_eq!(parsed.interval_ms, 60_000);
        assert_eq!(parsed.timeout_ms, 10_000);
        assert_eq!(parsed.index, "logs");
        assert_eq!(parsed.cursor_field, "@timestamp");
        assert!(parsed.query.is_none());
        assert!(matches!(parsed.auth, EsAuth::None));
        assert!(!parsed.allow_private_backends);
    }

    #[test]
    fn spec_parses_overrides() {
        let parsed: WatchSpec = serde_json::from_value(json!({
            "urls": ["https://es.example.com:9200"],
            "auth": { "kind": "bearer", "token": "tok" },
            "index": "events",
            "cursor_field": "_seq_no",
            "query": { "term": { "tenant": "acme" } },
            "interval_ms": 30_000,
            "timeout_ms": 5_000,
        }))
        .unwrap();
        assert_eq!(parsed.cursor_field, "_seq_no");
        assert_eq!(parsed.interval_ms, 30_000);
        assert_eq!(parsed.timeout_ms, 5_000);
        assert!(matches!(parsed.auth, EsAuth::Bearer { .. }));
        assert!(parsed.query.is_some());
    }

    #[test]
    fn unknown_field_is_invalid_spec() {
        let p = plugin();
        assert!(matches!(
            p.watch(
                "es://logs",
                &json!({
                    "urls": ["https://es:9200"],
                    "index": "logs",
                    "cursor_field": "@timestamp",
                    "bogus": true,
                }),
                emit_noop(),
            ),
            Err(WatchError::InvalidSpec { .. })
        ));
    }

    #[test]
    fn empty_index_is_invalid_spec() {
        let p = plugin();
        assert!(matches!(
            p.watch(
                "es://logs",
                &json!({
                    "urls": ["https://es:9200"],
                    "index": "   ",
                    "cursor_field": "@timestamp",
                }),
                emit_noop(),
            ),
            Err(WatchError::InvalidSpec { .. })
        ));
    }

    #[test]
    fn empty_cursor_field_is_invalid_spec() {
        let p = plugin();
        assert!(matches!(
            p.watch(
                "es://logs",
                &json!({
                    "urls": ["https://es:9200"],
                    "index": "logs",
                    "cursor_field": "  ",
                }),
                emit_noop(),
            ),
            Err(WatchError::InvalidSpec { .. })
        ));
    }

    #[test]
    fn bad_url_is_invalid_spec() {
        // A plain non-localhost http:// URL fails the backend's endpoint guard
        // → InvalidSpec at watch start.
        let p = plugin();
        assert!(matches!(
            p.watch(
                "es://logs",
                &json!({
                    "urls": ["http://es.evil.com:9200"],
                    "index": "logs",
                    "cursor_field": "@timestamp",
                }),
                emit_noop(),
            ),
            Err(WatchError::InvalidSpec { .. })
        ));
    }

    #[test]
    fn cursor_from_hit_prefers_sort_value() {
        // A real ES `_search` response: top hit carries the sort array.
        let body = json!({
            "hits": {
                "total": { "value": 5 },
                "hits": [
                    {
                        "_id": "abc",
                        "_source": { "@timestamp": "2026-06-23T10:00:00Z" },
                        "sort": [ 1750673000000_i64 ]
                    }
                ]
            }
        });
        assert_eq!(
            cursor_from_hit(&body, "@timestamp").as_deref(),
            Some("1750673000000")
        );
    }

    #[test]
    fn cursor_from_hit_falls_back_to_source_leaf() {
        // No `sort` array (e.g. a search without a sort clause): use the
        // projected _source leaf, dot-path resolved.
        let body = json!({
            "hits": {
                "hits": [
                    { "_source": { "meta": { "seq": 42 } } }
                ]
            }
        });
        assert_eq!(cursor_from_hit(&body, "meta.seq").as_deref(), Some("42"));

        // A string leaf yields the bare string.
        let body = json!({
            "hits": { "hits": [ { "_source": { "@timestamp": "2026-06-23T10:00:00Z" } } ] }
        });
        assert_eq!(
            cursor_from_hit(&body, "@timestamp").as_deref(),
            Some("2026-06-23T10:00:00Z")
        );
    }

    #[test]
    fn cursor_from_hit_none_on_zero_hits() {
        let body = json!({ "hits": { "total": { "value": 0 }, "hits": [] } });
        assert_eq!(cursor_from_hit(&body, "@timestamp"), None);

        // A null sort value is "no signal".
        let body = json!({
            "hits": { "hits": [ { "_source": {}, "sort": [ Value::Null ] } ] }
        });
        assert_eq!(cursor_from_hit(&body, "@timestamp"), None);
    }
}
