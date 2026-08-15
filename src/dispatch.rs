//! Request building + dispatch + response shaping for the Elasticsearch
//! backend.
//!
//! `build_call` turns the tool arguments into one REST call (method, path,
//! body, content-type) and applies the security guards: index resolution,
//! the scripting guard, and the size/from clamp.
//!
//! `issue_call` resolves the auth header at dispatch time and issues the
//! request against the first healthy URL, capping the response body at
//! `max_response_bytes`.
//!
//! `build_envelope` shapes the response into a stable JSON envelope and
//! never reflects the auth header.

use std::time::Duration;

use serde_json::{Map, Value, json};

use crate::config::{ElasticsearchBackendSpec, EsAuth, EsOperation};

/// Request content type for NDJSON bulk / msearch bodies.
const NDJSON_CT: &str = "application/x-ndjson";
/// Request content type for normal JSON bodies.
const JSON_CT: &str = "application/json";

/// A fully-built ES REST call, ready to issue. The auth header is NOT here
/// — it's resolved at dispatch time in `issue_call` so the resolved secret
/// never lingers in a struct that might be logged.
#[derive(Debug)]
pub(crate) struct EsRestCall {
    pub method: reqwest::Method,
    /// Path relative to the base URL, leading `/` included (e.g.
    /// `/logs/_search`). Already path-injection-validated.
    pub path: String,
    /// Optional query string (without the leading `?`).
    pub query: Option<String>,
    /// Request body bytes (JSON or NDJSON), or `None` for a bodyless GET.
    pub body: Option<Vec<u8>>,
    pub content_type: &'static str,
    /// Echoed into the envelope for observability.
    pub operation: EsOperation,
    pub display_path: String,
}

/// Outcome of issuing the REST call.
#[derive(Debug)]
pub(crate) struct EsResult {
    pub status: u16,
    /// Response body, parsed as JSON when possible (else `None` + raw kept
    /// in `raw_body`).
    pub json: Option<Value>,
    pub raw_body: String,
    pub truncated: bool,
}

/// Validate a caller-supplied document id destined for the final path
/// segment.
///
/// `.` is unreserved, so percent-encoding leaves `..` intact — and because
/// the id is the last segment, `/{index}/_doc/..` normalizes to `/{index}/`,
/// turning a single-document DELETE into a delete of the whole index.
/// Percent-encoding cannot fix this: URL parsing treats `%2e` as a dot for
/// segment removal, so a dot-only id has to be refused outright.
fn checked_doc_id(id: &str) -> Result<String, String> {
    if id.is_empty() || id.len() > 512 {
        return Err("`id` must be 1..=512 bytes".into());
    }
    if id.bytes().all(|b| b == b'.') {
        return Err("`id` must not consist only of dots".into());
    }
    Ok(encode_path_segment(id))
}

/// URL-path-segment percent-encoding for a document id. ES doc ids may
/// contain arbitrary characters; we MUST encode them so they cannot break
/// out of the path. Encodes everything outside the RFC 3986 unreserved set
/// (`A-Z a-z 0-9 - . _ ~`) — in particular `/`, `\`, `%`, `?`, `#`, and
/// spaces — so a doc id can never alter the request path.
fn encode_path_segment(seg: &str) -> String {
    let mut out = String::with_capacity(seg.len());
    for &b in seg.as_bytes() {
        let unreserved = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~');
        if unreserved {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(hex_upper(b >> 4));
            out.push(hex_upper(b & 0x0f));
        }
    }
    out
}

fn hex_upper(nibble: u8) -> char {
    match nibble {
        0..=9 => (b'0' + nibble) as char,
        _ => (b'A' + (nibble - 10)) as char,
    }
}

/// Build the per-op input schema (returned to the gateway so it validates
/// caller args before dispatch).
pub(crate) fn op_input_schema(op: EsOperation) -> Value {
    let index_prop = json!({
        "type": "string",
        "description": "Target index (must be in the binding allowlist; defaults to default_index)"
    });
    match op {
        EsOperation::Search => json!({
            "type": "object",
            "properties": {
                "index": index_prop,
                "query": { "type": "object", "description": "Elasticsearch query DSL" },
                "size": { "type": "integer", "minimum": 0 },
                "from": { "type": "integer", "minimum": 0 },
                "sort": { "type": "array" },
                "source": { "description": "_source filtering: array of fields or boolean" },
                "aggs": { "type": "object" }
            }
        }),
        EsOperation::Count => json!({
            "type": "object",
            "properties": {
                "index": index_prop,
                "query": { "type": "object", "description": "Elasticsearch query DSL" }
            }
        }),
        EsOperation::Get => json!({
            "type": "object",
            "properties": {
                "index": index_prop,
                "id": { "type": "string" },
                "source": { "description": "_source filtering: array of fields or boolean" }
            },
            "required": ["id"]
        }),
        EsOperation::Index => json!({
            "type": "object",
            "properties": {
                "index": index_prop,
                "id": { "type": "string" },
                "document": { "type": "object" },
                "refresh": { "type": "string", "enum": ["true", "false", "wait_for"] },
                "op_type": { "type": "string", "enum": ["index", "create"] }
            },
            "required": ["document"]
        }),
        EsOperation::Delete => json!({
            "type": "object",
            "properties": {
                "index": index_prop,
                "id": { "type": "string" },
                "refresh": { "type": "string", "enum": ["true", "false", "wait_for"] }
            },
            "required": ["id"]
        }),
        EsOperation::Bulk => json!({
            "type": "object",
            "properties": {
                "index": index_prop,
                "operations": {
                    "type": "array",
                    "description": "Sequence of bulk action/source objects (NDJSON lines)"
                },
                "refresh": { "type": "string", "enum": ["true", "false", "wait_for"] }
            },
            "required": ["operations"]
        }),
        EsOperation::Msearch => json!({
            "type": "object",
            "properties": {
                "searches": {
                    "type": "array",
                    "description": "Per-search { index?, query, size?, from? } objects",
                    "items": { "type": "object" }
                }
            },
            "required": ["searches"]
        }),
        EsOperation::Knn => json!({
            "type": "object",
            "properties": {
                "index": index_prop,
                "query_vector": {
                    "type": "array",
                    "items": { "type": "number" },
                    "description": "Query embedding (array of numbers) for the dense_vector kNN search; falls back to the binding's literal knn.query_vector when omitted"
                },
                "source": { "description": "_source filtering: array of fields or boolean" }
            }
        }),
    }
}

/// Recursive scan for server-side code-execution keys in a query body.
/// Returns the first offending key found.
fn find_scripting_key(v: &Value) -> Option<String> {
    match v {
        Value::Object(map) => {
            for (k, val) in map {
                if is_scripting_key(k) {
                    return Some(k.clone());
                }
                if let Some(hit) = find_scripting_key(val) {
                    return Some(hit);
                }
            }
            None
        }
        Value::Array(items) => items.iter().find_map(find_scripting_key),
        _ => None,
    }
}

/// Whether a JSON key introduces server-side code execution.
///
/// Matched by shape rather than by an exact list: the `scripted_metric`
/// aggregation carries Painless under `init_script`, `map_script`,
/// `combine_script` and `reduce_script`, none of which are named `script`,
/// so an exact-name list let a caller-supplied `aggs` object walk straight
/// past a guard documented as default-deny.
fn is_scripting_key(key: &str) -> bool {
    matches!(
        key,
        "script" | "script_score" | "scripted_metric" | "runtime_mappings" | "script_fields"
    ) || key.ends_with("_script")
}

/// Apply the default-deny scripting guard to a query-bearing body unless
/// the binding opted in.
fn check_scripting(spec: &ElasticsearchBackendSpec, body: &Value) -> Result<(), String> {
    if spec.allow_scripting {
        return Ok(());
    }
    if let Some(key) = find_scripting_key(body) {
        return Err(format!(
            "query body contains `{key}` (scripting disabled; set allow_scripting to enable)"
        ));
    }
    Ok(())
}

/// Clamp a caller-supplied `size` / `from` to the binding ceiling.
fn clamp(value: u64, ceiling: u64) -> u64 {
    value.min(ceiling)
}

/// Build the search/count body `{query, size, from, sort, _source, aggs}`
/// from arguments, clamping size/from and running the scripting guard.
fn build_search_body(
    spec: &ElasticsearchBackendSpec,
    args: &Value,
    include_paging: bool,
) -> Result<Value, String> {
    check_scripting(spec, args)?;
    let mut body = Map::new();
    if let Some(q) = args.get("query") {
        body.insert("query".into(), q.clone());
    }
    if include_paging {
        if let Some(size) = args.get("size").and_then(Value::as_u64) {
            body.insert("size".into(), json!(clamp(size, spec.max_size)));
        }
        if let Some(from) = args.get("from").and_then(Value::as_u64) {
            body.insert("from".into(), json!(clamp(from, spec.max_from)));
        }
        if let Some(sort) = args.get("sort") {
            body.insert("sort".into(), sort.clone());
        }
        if let Some(source) = args.get("source") {
            body.insert("_source".into(), source.clone());
        }
        if let Some(aggs) = args.get("aggs") {
            body.insert("aggs".into(), aggs.clone());
        }
    }
    Ok(Value::Object(body))
}

/// Build the `_search` body for the kNN op: a top-level `knn` clause (the
/// modern ES kNN API) carrying `{field, query_vector, k, num_candidates?,
/// filter?}`, plus an optional caller `_source` projection. The query vector
/// is the per-call `query_vector` argument (an array of numbers) falling back
/// to the binding's literal `knn.query_vector`; a non-array / empty / non-
/// finite vector is a tool-level error. The optional operator `filter` is run
/// through the scripting guard.
fn build_knn_body(
    spec: &ElasticsearchBackendSpec,
    knn: &crate::config::KnnConfig,
    args: &Value,
) -> Result<Value, String> {
    let query_vector = resolve_query_vector(knn, args)?;

    let mut clause = Map::new();
    clause.insert("field".into(), json!(knn.field));
    clause.insert("query_vector".into(), Value::Array(query_vector));
    clause.insert("k".into(), json!(knn.k));
    if let Some(nc) = knn.num_candidates {
        // ES requires num_candidates >= k; clamp up so a misconfig can't be
        // rejected upstream.
        clause.insert("num_candidates".into(), json!(nc.max(knn.k)));
    }
    if let Some(filter) = &knn.filter {
        check_scripting(spec, filter)?;
        clause.insert("filter".into(), filter.clone());
    }

    let mut body = Map::new();
    body.insert("knn".into(), Value::Object(clause));
    if let Some(source) = args.get("source") {
        body.insert("_source".into(), source.clone());
    }
    Ok(Value::Object(body))
}

/// Resolve the kNN query vector: prefer the per-call `query_vector` argument,
/// fall back to the binding's literal. Validates that it is a non-empty array
/// of finite numbers and lowers each element to a JSON number.
fn resolve_query_vector(
    knn: &crate::config::KnnConfig,
    args: &Value,
) -> Result<Vec<Value>, String> {
    match args.get("query_vector") {
        Some(Value::Array(items)) => {
            if items.is_empty() {
                return Err("`query_vector` must be a non-empty array of numbers".into());
            }
            let mut out = Vec::with_capacity(items.len());
            for (i, el) in items.iter().enumerate() {
                let n = el
                    .as_f64()
                    .filter(|x| x.is_finite())
                    .ok_or_else(|| format!("`query_vector[{i}]` must be a finite number"))?;
                out.push(json!(n));
            }
            Ok(out)
        }
        Some(_) => Err("`query_vector` must be an array of numbers".into()),
        None => match &knn.query_vector {
            Some(lit) if !lit.is_empty() => Ok(lit.iter().map(|x| json!(x)).collect()),
            _ => Err(
                "missing required `query_vector` argument (no literal knn.query_vector configured)"
                    .into(),
            ),
        },
    }
}

/// Assemble an NDJSON bulk body. Each entry is one JSON object serialized
/// on its own line. ES `_bulk` requires a trailing newline.
/// The four bulk action verbs. `delete` carries no source line; the other
/// three are followed by one.
const BULK_ACTIONS: [&str; 4] = ["index", "create", "update", "delete"];

/// Assemble a bulk NDJSON body.
///
/// Bulk is the one operation whose body re-declares its own target: each
/// action line may carry `_index`, which Elasticsearch honours over the
/// index in the URL. Every action's target is therefore resolved through
/// `spec.resolve_index`, the same allowlist gate the URL went through and
/// the one `assemble_msearch_ndjson` already applies per search. Source
/// lines are held to the scripting guard for the same reason: an `update`
/// action's `script` is a query body by another name.
pub(crate) fn assemble_bulk_ndjson(
    spec: &ElasticsearchBackendSpec,
    operations: &[Value],
) -> Result<Vec<u8>, String> {
    let mut out = String::new();
    // Bulk NDJSON alternates: an action line, then a source line for every
    // verb except `delete`. Tracking that here is what tells an attacker's
    // `{"_index": …}` inside a *source* body apart from a real action.
    let mut expect_source = false;
    for (i, op) in operations.iter().enumerate() {
        if !op.is_object() && !op.is_null() {
            return Err(format!("bulk operations[{i}] must be a JSON object"));
        }
        let mut op = op.clone();
        if expect_source {
            check_scripting(spec, &op).map_err(|e| format!("bulk operations[{i}]: {e}"))?;
            expect_source = false;
        } else {
            let obj = op
                .as_object_mut()
                .ok_or_else(|| format!("bulk operations[{i}] must be an action object"))?;
            if obj.len() != 1 {
                return Err(format!(
                    "bulk operations[{i}] must name exactly one action ({})",
                    BULK_ACTIONS.join(", ")
                ));
            }
            let action = obj
                .keys()
                .next()
                .cloned()
                .unwrap_or_else(|| "<none>".to_owned());
            if !BULK_ACTIONS.contains(&action.as_str()) {
                return Err(format!(
                    "bulk operations[{i}] action `{action}` is not one of {}",
                    BULK_ACTIONS.join(", ")
                ));
            }
            if let Some(meta) = obj.get_mut(&action).and_then(Value::as_object_mut) {
                let declared = meta.get("_index").and_then(Value::as_str);
                let resolved = spec
                    .resolve_index(declared)
                    .map_err(|e| format!("bulk operations[{i}]: {e}"))?;
                meta.insert("_index".to_owned(), Value::String(resolved));
            }
            expect_source = action != "delete";
        }
        out.push_str(&serde_json::to_string(&op).map_err(|e| format!("bulk line {i}: {e}"))?);
        out.push('\n');
    }
    if expect_source {
        return Err("bulk operations end with an action that has no source line".into());
    }
    Ok(out.into_bytes())
}

/// Assemble an NDJSON msearch body: a `{index}` header line followed by the
/// search body line, per search. Each search's index is validated +
/// allowlist-checked before assembly.
pub(crate) fn assemble_msearch_ndjson(
    spec: &ElasticsearchBackendSpec,
    searches: &[Value],
) -> Result<Vec<u8>, String> {
    let mut out = String::new();
    for (i, s) in searches.iter().enumerate() {
        let arg_index = s.get("index").and_then(Value::as_str);
        let index = spec
            .resolve_index(arg_index)
            .map_err(|e| format!("searches[{i}]: {e}"))?;
        let header = json!({ "index": index });
        out.push_str(
            &serde_json::to_string(&header).map_err(|e| format!("msearch header {i}: {e}"))?,
        );
        out.push('\n');
        let body = build_search_body(spec, s, true)?;
        out.push_str(&serde_json::to_string(&body).map_err(|e| format!("msearch body {i}: {e}"))?);
        out.push('\n');
    }
    Ok(out.into_bytes())
}

/// Build the REST call for an operation from the tool arguments. All
/// bad-argument paths return `Err(message)` (the caller maps these to a
/// tool-level `isError` envelope).
pub(crate) fn build_call(
    spec: &ElasticsearchBackendSpec,
    args: &Value,
) -> Result<EsRestCall, String> {
    use reqwest::Method;
    let op = spec.operation;

    let arg_index = args.get("index").and_then(Value::as_str);

    let call = match op {
        EsOperation::Search => {
            let index = spec.resolve_index(arg_index)?;
            let body = build_search_body(spec, args, true)?;
            EsRestCall {
                method: Method::POST,
                path: format!("/{index}/_search"),
                query: None,
                body: Some(serde_json::to_vec(&body).map_err(|e| e.to_string())?),
                content_type: JSON_CT,
                operation: op,
                display_path: format!("/{index}/_search"),
            }
        }
        EsOperation::Count => {
            let index = spec.resolve_index(arg_index)?;
            let body = build_search_body(spec, args, false)?;
            EsRestCall {
                method: Method::POST,
                path: format!("/{index}/_count"),
                query: None,
                body: Some(serde_json::to_vec(&body).map_err(|e| e.to_string())?),
                content_type: JSON_CT,
                operation: op,
                display_path: format!("/{index}/_count"),
            }
        }
        EsOperation::Get => {
            let index = spec.resolve_index(arg_index)?;
            let id = args
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| "missing required `id` argument".to_string())?;
            let enc_id = checked_doc_id(id)?;
            let query = source_query(args);
            EsRestCall {
                method: Method::GET,
                path: format!("/{index}/_doc/{enc_id}"),
                query,
                body: None,
                content_type: JSON_CT,
                operation: op,
                display_path: format!("/{index}/_doc/{id}"),
            }
        }
        EsOperation::Index => {
            let index = spec.resolve_index(arg_index)?;
            let document = args
                .get("document")
                .filter(|d| d.is_object())
                .ok_or_else(|| "missing required `document` object argument".to_string())?;
            let mut query_parts: Vec<String> = Vec::new();
            if let Some(rf) = refresh_param(args)? {
                query_parts.push(format!("refresh={rf}"));
            }
            if let Some(ot) = args.get("op_type").and_then(Value::as_str) {
                if !matches!(ot, "index" | "create") {
                    return Err("`op_type` must be `index` or `create`".into());
                }
                query_parts.push(format!("op_type={ot}"));
            }
            let (method, path, display) = match args.get("id").and_then(Value::as_str) {
                Some(id) => {
                    let enc = checked_doc_id(id)?;
                    (
                        Method::PUT,
                        format!("/{index}/_doc/{enc}"),
                        format!("/{index}/_doc/{id}"),
                    )
                }
                None => (
                    Method::POST,
                    format!("/{index}/_doc"),
                    format!("/{index}/_doc"),
                ),
            };
            EsRestCall {
                method,
                path,
                query: if query_parts.is_empty() {
                    None
                } else {
                    Some(query_parts.join("&"))
                },
                body: Some(serde_json::to_vec(document).map_err(|e| e.to_string())?),
                content_type: JSON_CT,
                operation: op,
                display_path: display,
            }
        }
        EsOperation::Delete => {
            let index = spec.resolve_index(arg_index)?;
            let id = args
                .get("id")
                .and_then(Value::as_str)
                .ok_or_else(|| "missing required `id` argument".to_string())?;
            let enc_id = checked_doc_id(id)?;
            let query = refresh_param(args)?.map(|rf| format!("refresh={rf}"));
            EsRestCall {
                method: Method::DELETE,
                path: format!("/{index}/_doc/{enc_id}"),
                query,
                body: None,
                content_type: JSON_CT,
                operation: op,
                display_path: format!("/{index}/_doc/{id}"),
            }
        }
        EsOperation::Bulk => {
            let index = spec.resolve_index(arg_index)?;
            let operations = args
                .get("operations")
                .and_then(Value::as_array)
                .ok_or_else(|| "missing required `operations` array argument".to_string())?;
            let body = assemble_bulk_ndjson(spec, operations)?;
            let query = refresh_param(args)?.map(|rf| format!("refresh={rf}"));
            EsRestCall {
                method: Method::POST,
                path: format!("/{index}/_bulk"),
                query,
                body: Some(body),
                content_type: NDJSON_CT,
                operation: op,
                display_path: format!("/{index}/_bulk"),
            }
        }
        EsOperation::Knn => {
            let index = spec.resolve_index(arg_index)?;
            let knn = spec
                .knn
                .as_ref()
                .ok_or_else(|| "knn operation requires a `knn` config block".to_string())?;
            let body = build_knn_body(spec, knn, args)?;
            EsRestCall {
                method: Method::POST,
                path: format!("/{index}/_search"),
                query: None,
                body: Some(serde_json::to_vec(&body).map_err(|e| e.to_string())?),
                content_type: JSON_CT,
                operation: op,
                display_path: format!("/{index}/_search"),
            }
        }
        EsOperation::Msearch => {
            let searches = args
                .get("searches")
                .and_then(Value::as_array)
                .ok_or_else(|| "missing required `searches` array argument".to_string())?;
            if searches.is_empty() {
                return Err("`searches` must not be empty".into());
            }
            let body = assemble_msearch_ndjson(spec, searches)?;
            EsRestCall {
                method: Method::POST,
                path: "/_msearch".into(),
                query: None,
                body: Some(body),
                content_type: NDJSON_CT,
                operation: op,
                display_path: "/_msearch".into(),
            }
        }
    };

    // Enforce the request-body byte cap.
    if let Some(b) = &call.body
        && b.len() > spec.max_request_bytes
    {
        return Err(format!(
            "request body {} bytes exceeds max_request_bytes {}",
            b.len(),
            spec.max_request_bytes
        ));
    }
    Ok(call)
}

/// `_source` query-string for `get` (`true`/`false` or a CSV of fields).
fn source_query(args: &Value) -> Option<String> {
    match args.get("source") {
        Some(Value::Bool(b)) => Some(format!("_source={b}")),
        Some(Value::Array(fields)) => {
            let csv: Vec<String> = fields
                .iter()
                .filter_map(|f| f.as_str().map(encode_path_segment))
                .collect();
            if csv.is_empty() {
                None
            } else {
                Some(format!("_source={}", csv.join(",")))
            }
        }
        _ => None,
    }
}

/// Validate + extract the `refresh` query parameter.
fn refresh_param(args: &Value) -> Result<Option<&str>, String> {
    match args.get("refresh") {
        None => Ok(None),
        Some(Value::String(s)) => {
            if matches!(s.as_str(), "true" | "false" | "wait_for") {
                Ok(Some(s.as_str()))
            } else {
                Err("`refresh` must be \"true\", \"false\", or \"wait_for\"".into())
            }
        }
        Some(_) => Err("`refresh` must be a string".into()),
    }
}

/// Build the auth header `(name, value)` from the resolved spec auth. The
/// secret is read from the (already `${env}`-resolved, per-call
/// `cred://`-resolved) spec fields. `None` for `kind: none`.
///
/// NOTE: at v1 the per-caller `cred://` resolution is handled by the
/// gateway/host substitution pipeline before the value lands in the spec
/// field (config-load `${env.X}`), matching the static-cred posture of
/// vault-dynamic-db. The resolved value is never logged.
fn auth_header(spec: &ElasticsearchBackendSpec) -> Option<(&'static str, String)> {
    use base64_lite::b64;
    match &spec.auth {
        EsAuth::None => None,
        EsAuth::ApiKey { api_key } => Some(("Authorization", format!("ApiKey {api_key}"))),
        EsAuth::Basic { username, password } => {
            let token = b64(format!("{username}:{password}").as_bytes());
            Some(("Authorization", format!("Basic {token}")))
        }
        EsAuth::Bearer { token } => Some(("Authorization", format!("Bearer {token}"))),
    }
}

/// Minimal standard-base64 encoder (avoids adding the `base64` crate for a
/// single Basic-auth header). RFC 4648 alphabet, padded.
mod base64_lite {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    pub fn b64(input: &[u8]) -> String {
        let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
        for chunk in input.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = *chunk.get(1).unwrap_or(&0) as u32;
            let b2 = *chunk.get(2).unwrap_or(&0) as u32;
            let n = (b0 << 16) | (b1 << 8) | b2;
            out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
            out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
            if chunk.len() > 1 {
                out.push(ALPHABET[((n >> 6) & 63) as usize] as char);
            } else {
                out.push('=');
            }
            if chunk.len() > 2 {
                out.push(ALPHABET[(n & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
        out
    }
}

/// Build the operator-fixed listing `_search` call: `{query, from, size,
/// _source}` against the resolved index. No caller input reaches the body —
/// `from` / `size` are the paginator's offset / page bound.
pub(crate) fn build_list_call(
    spec: &ElasticsearchBackendSpec,
    list: &crate::config::ListQueryConfig,
    from: u64,
) -> Result<EsRestCall, String> {
    use reqwest::Method;
    let index = spec.resolve_index(list.index.as_deref())?;
    let query = list
        .query
        .clone()
        .unwrap_or_else(|| json!({ "match_all": {} }));
    let mut source: Vec<&str> = vec![list.uri_field.as_str()];
    if let Some(f) = &list.name_field {
        source.push(f);
    }
    if let Some(f) = &list.description_field {
        source.push(f);
    }
    let body = json!({
        "query": query,
        "from": from,
        "size": list.page_size,
        "_source": source,
    });
    // Re-run the scripting guard over the operator body — it stays subject to
    // the same server-side-code-execution fence as a per-call search body.
    check_scripting(spec, &body)?;
    Ok(EsRestCall {
        method: Method::POST,
        path: format!("/{index}/_search"),
        query: None,
        body: Some(serde_json::to_vec(&body).map_err(|e| e.to_string())?),
        content_type: JSON_CT,
        operation: EsOperation::Search,
        display_path: format!("/{index}/_search"),
    })
}

/// Build the operator-fixed completion `_search`: a `prefix` query on the
/// declared field carrying the caller prefix as a JSON string VALUE (never raw
/// DSL), ANDed with the operator's optional fixed filter.
pub(crate) fn build_completion_call(
    spec: &ElasticsearchBackendSpec,
    cc: &crate::config::EsCompletionConfig,
    prefix: &str,
    size: u64,
) -> Result<EsRestCall, String> {
    use reqwest::Method;
    let index = spec.resolve_index(cc.index.as_deref())?;
    let mut bool_query = serde_json::Map::new();
    bool_query.insert("must".into(), json!([{ "prefix": { &cc.field: prefix } }]));
    if let Some(filter) = &cc.filter {
        bool_query.insert("filter".into(), filter.clone());
    }
    let body = json!({
        "query": { "bool": Value::Object(bool_query) },
        "size": size,
        "_source": [cc.field.as_str()],
    });
    check_scripting(spec, &body)?;
    Ok(EsRestCall {
        method: Method::POST,
        path: format!("/{index}/_search"),
        query: None,
        body: Some(serde_json::to_vec(&body).map_err(|e| e.to_string())?),
        content_type: JSON_CT,
        operation: EsOperation::Search,
        display_path: format!("/{index}/_search"),
    })
}

/// Pull the `hits.hits[]` array out of a `_search` response body.
pub(crate) fn search_hits(body: &Value) -> Vec<Value> {
    body.get("hits")
        .and_then(|h| h.get("hits"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// Resolve a dot-path against a hit's `_source` object, returning the string
/// leaf value. `None` when the path is absent or not a string.
pub(crate) fn source_string(hit: &Value, path: &str) -> Option<String> {
    let mut cur = hit.get("_source")?;
    for seg in path.split('.') {
        cur = cur.get(seg)?;
    }
    cur.as_str().map(str::to_owned)
}

/// Build the per-profile `reqwest::Client` (rustls, timeouts, optional CA,
/// optional loopback-gated insecure-skip-verify). DNS-rebinding is enforced
/// per-call in `issue_call`, not pinned here (the failover URL list makes a
/// single pinned resolution insufficient).
pub(crate) fn build_client(spec: &ElasticsearchBackendSpec) -> Result<reqwest::Client, String> {
    let mut builder = reqwest::Client::builder()
        .connect_timeout(Duration::from_millis(spec.connect_timeout_ms))
        .timeout(Duration::from_millis(spec.operation_timeout_ms))
        .redirect(reqwest::redirect::Policy::none());

    if let Some(pem) = &spec.tls.ca_cert_pem {
        let cert = reqwest::Certificate::from_pem(pem.as_bytes())
            .map_err(|e| format!("tls.ca_cert_pem parse: {e}"))?;
        builder = builder.add_root_certificate(cert);
    }
    if spec.tls.insecure_skip_verify {
        // Loopback-gated at validate() — honored only for dev self-signed.
        builder = builder.danger_accept_invalid_certs(true);
    }
    builder.build().map_err(|e| format!("reqwest build: {e}"))
}

/// Issue the call against the first healthy URL, failing over on transport
/// error. Returns `Err(message)` on transport/timeout failure (mapped to
/// `BackendError` by the caller); a 4xx/5xx is an `Ok(EsResult)` with the
/// status carried in the envelope.
pub(crate) async fn issue_call(
    client: &reqwest::Client,
    urls: &[String],
    spec: &ElasticsearchBackendSpec,
    call: &EsRestCall,
) -> Result<EsResult, String> {
    let header = auth_header(spec);
    let mut last_err: Option<String> = None;

    for base in urls {
        // SSRF / DNS-rebinding guard: resolve the host and reject private
        // addresses unless opted in. Done per attempt so a failover URL is
        // independently validated.
        if let Err(e) = guard_host(base, spec.allow_private_backends).await {
            last_err = Some(e);
            continue;
        }

        let mut full = format!("{base}{}", call.path);
        if let Some(q) = &call.query {
            full.push('?');
            full.push_str(q);
        }

        let mut rb = client
            .request(call.method.clone(), &full)
            .header(reqwest::header::CONTENT_TYPE, call.content_type)
            .header(reqwest::header::ACCEPT, JSON_CT);
        if let Some((name, value)) = &header {
            rb = rb.header(*name, value);
        }
        if let Some(body) = &call.body {
            rb = rb.body(body.clone());
        }

        match rb.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                let bytes = match resp.bytes().await {
                    Ok(b) => b,
                    Err(e) => {
                        last_err = Some(redact(format!("response body read failed: {e}")));
                        continue;
                    }
                };
                let truncated = bytes.len() > spec.max_response_bytes;
                let capped = if truncated {
                    &bytes[..spec.max_response_bytes]
                } else {
                    &bytes[..]
                };
                let raw_body = String::from_utf8_lossy(capped).into_owned();
                // Only attempt JSON parse on a non-truncated body (a cut
                // body is not valid JSON).
                let json = if truncated {
                    None
                } else {
                    serde_json::from_slice::<Value>(capped).ok()
                };
                return Ok(EsResult {
                    status,
                    json,
                    raw_body,
                    truncated,
                });
            }
            Err(e) => {
                last_err = Some(redact(e.to_string()));
            }
        }
    }
    Err(last_err.unwrap_or_else(|| "no reachable elasticsearch URL".into()))
}

/// Strip any credential userinfo from an error string before it surfaces.
fn redact(s: String) -> String {
    mcpg_plugin_protocol::redact::redact_in_text(&s)
}

/// DNS-rebinding / SSRF guard: resolve the base URL's host and reject if it
/// resolves only to private/loopback addresses (unless opted in).
async fn guard_host(base: &str, allow_private: bool) -> Result<(), String> {
    if allow_private {
        return Ok(());
    }
    let url = url::Url::parse(base).map_err(|_| "base URL failed to parse".to_string())?;
    let host = url
        .host_str()
        .ok_or_else(|| "base URL has no host".to_string())?
        .to_owned();
    let port = url
        .port_or_known_default()
        .ok_or_else(|| "base URL has no port".to_string())?;
    let pairs: Vec<std::net::SocketAddr> = tokio::net::lookup_host(format!("{host}:{port}"))
        .await
        .map_err(|e| format!("DNS resolution failed for {host}: {e}"))?
        .collect();
    if pairs.is_empty() {
        return Err(format!("DNS resolution returned no addresses for {host}"));
    }
    if pairs
        .iter()
        .all(|a| mcpg_plugin_protocol::security::is_private_address(&a.ip()))
    {
        return Err(format!(
            "DNS rebinding guard: host '{host}' resolved only to private addresses"
        ));
    }
    Ok(())
}

/// JSON Schema (draft 2020-12) for the envelope wrapper [`build_envelope`]
/// produces. Describes the stable top-level shape (`operation`/`method`/
/// `path`/`statusCode`/`ok`/`truncated` plus `response` XOR `responseText`,
/// an optional `downstreamError`, and the gateway verbatim-result wrapper
/// for tool-level failures). The `response` body mirrors the upstream
/// Elasticsearch JSON verbatim, so it is intentionally left untyped and the
/// object stays open (`additionalProperties: true`) — no real envelope ever
/// fails validation.
pub(crate) fn result_envelope_schema() -> Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "operation": { "type": "string" },
            "method": { "type": "string" },
            "path": { "type": "string" },
            "statusCode": { "type": "integer" },
            "ok": { "type": "boolean" },
            "truncated": { "type": "boolean" },
            "response": {},
            "responseText": { "type": "string" },
            "downstreamError": { "type": ["object", "null"] },
            "__mcpg_verbatim_result": { "type": "object" }
        },
        "additionalProperties": true
    })
}

/// Shape the response into a stable envelope. Passes the ES JSON through
/// under `response`, plus status + operation + truncation + request path.
/// NEVER reflects the auth header.
pub(crate) fn build_envelope(
    spec: &ElasticsearchBackendSpec,
    call: &EsRestCall,
    res: &EsResult,
) -> Value {
    let _ = spec;
    let mut env = Map::new();
    env.insert("operation".into(), json!(call.operation.as_str()));
    env.insert("method".into(), json!(call.method.as_str()));
    env.insert("path".into(), json!(call.display_path));
    env.insert("statusCode".into(), json!(res.status));
    env.insert("ok".into(), json!((200..300).contains(&res.status)));
    env.insert("truncated".into(), json!(res.truncated));
    if let Some(j) = &res.json {
        env.insert("response".into(), j.clone());
    } else {
        env.insert("responseText".into(), json!(res.raw_body));
    }
    if res.status >= 400 {
        env.insert(
            "downstreamError".into(),
            json!({
                "statusCode": res.status,
                "body": res.json.clone().unwrap_or_else(|| json!(res.raw_body)),
            }),
        );
    }
    Value::Object(env)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ElasticsearchBackendSpec;
    use serde_json::json;

    fn spec(op: &str, extra: Value) -> ElasticsearchBackendSpec {
        let mut v = json!({
            "urls": ["https://es:9200"],
            "operation": op,
            "index_allowlist": ["logs-*", "events"],
            "default_index": "events",
            "allow_writes": true
        });
        if let Value::Object(e) = extra {
            for (k, val) in e {
                v[k] = val;
            }
        }
        ElasticsearchBackendSpec::parse(&v).unwrap()
    }

    #[test]
    fn build_list_call_targets_search_with_pagination() {
        let s = spec("search", json!({}));
        let list = crate::config::ListQueryConfig {
            index: Some("events".into()),
            query: Some(json!({ "term": { "kind": "doc" } })),
            uri_field: "uri".into(),
            name_field: Some("title".into()),
            description_field: None,
            page_size: 25,
        };
        let call = build_list_call(&s, &list, 50).unwrap();
        assert_eq!(call.path, "/events/_search");
        let body: Value = serde_json::from_slice(call.body.as_deref().unwrap()).unwrap();
        assert_eq!(body["from"], json!(50));
        assert_eq!(body["size"], json!(25));
        assert_eq!(body["query"], json!({ "term": { "kind": "doc" } }));
        assert_eq!(body["_source"], json!(["uri", "title"]));
    }

    #[test]
    fn build_completion_call_binds_prefix_as_value() {
        let s = spec("search", json!({}));
        let cc = crate::config::EsCompletionConfig {
            index: Some("events".into()),
            field: "name.keyword".into(),
            filter: Some(json!([{ "term": { "owner": "acme" } }])),
            max_results: Some(10),
        };
        // A prefix that would be dangerous if interpolated as raw DSL — it must
        // land as a JSON string VALUE inside the prefix query, not as structure.
        let call = build_completion_call(&s, &cc, "ab\"}}],\"x\":1", 10).unwrap();
        assert_eq!(call.path, "/events/_search");
        let body: Value = serde_json::from_slice(call.body.as_deref().unwrap()).unwrap();
        let must = &body["query"]["bool"]["must"];
        assert_eq!(must[0]["prefix"]["name.keyword"], json!("ab\"}}],\"x\":1"));
        assert_eq!(
            body["query"]["bool"]["filter"],
            json!([{ "term": { "owner": "acme" } }])
        );
        assert_eq!(body["_source"], json!(["name.keyword"]));
        assert_eq!(body["size"], json!(10));
    }

    #[test]
    fn search_hits_and_source_string_extract() {
        let body = json!({
            "hits": { "hits": [
                { "_source": { "uri": "es://a", "meta": { "title": "A" } } },
                { "_source": { "uri": "es://b" } },
            ]}
        });
        let hits = search_hits(&body);
        assert_eq!(hits.len(), 2);
        assert_eq!(source_string(&hits[0], "uri").as_deref(), Some("es://a"));
        assert_eq!(source_string(&hits[0], "meta.title").as_deref(), Some("A"));
        assert!(source_string(&hits[1], "meta.title").is_none());
    }

    #[test]
    fn output_schema_covers_envelope_keys() {
        let schema = result_envelope_schema();
        assert_eq!(schema["type"], json!("object"));
        let s = spec("search", json!({}));
        let call = build_call(
            &s,
            &json!({ "index": "events", "query": { "match_all": {} } }),
        )
        .unwrap();
        let res = EsResult {
            status: 200,
            json: Some(json!({ "hits": { "total": { "value": 0 } } })),
            raw_body: String::new(),
            truncated: false,
        };
        let env = build_envelope(&s, &call, &res);
        let props = schema["properties"].as_object().expect("properties object");
        for key in env.as_object().expect("envelope object").keys() {
            assert!(props.contains_key(key), "schema missing key `{key}`");
        }
        // The upstream JSON body is passed through untyped.
        assert_eq!(schema["properties"]["response"], json!({}));
    }

    #[test]
    fn base64_basic_auth_matches_reference() {
        // base64("elastic:changeme") == ZWxhc3RpYzpjaGFuZ2VtZQ==
        assert_eq!(
            base64_lite::b64(b"elastic:changeme"),
            "ZWxhc3RpYzpjaGFuZ2VtZQ=="
        );
        // Standard RFC 4648 vectors.
        assert_eq!(base64_lite::b64(b"f"), "Zg==");
        assert_eq!(base64_lite::b64(b"fo"), "Zm8=");
        assert_eq!(base64_lite::b64(b"foo"), "Zm9v");
        assert_eq!(base64_lite::b64(b"foob"), "Zm9vYg==");
    }

    #[test]
    fn auth_header_formats() {
        let s = spec(
            "search",
            json!({ "auth": { "kind": "api_key", "api_key": "AbC123" } }),
        );
        assert_eq!(
            auth_header(&s),
            Some(("Authorization", "ApiKey AbC123".into()))
        );
        let s = spec(
            "search",
            json!({ "auth": { "kind": "bearer", "token": "tok" } }),
        );
        assert_eq!(
            auth_header(&s),
            Some(("Authorization", "Bearer tok".into()))
        );
        let s = spec(
            "search",
            json!({ "auth": { "kind": "basic", "username": "u", "password": "p" } }),
        );
        assert_eq!(
            auth_header(&s),
            Some((
                "Authorization",
                format!("Basic {}", base64_lite::b64(b"u:p"))
            ))
        );
        let s = spec("search", json!({}));
        assert_eq!(auth_header(&s), None);
    }

    #[test]
    fn search_clamps_size_and_from() {
        let s = spec("search", json!({ "max_size": 50, "max_from": 100 }));
        let call = build_call(
            &s,
            &json!({ "index": "events", "query": { "match_all": {} }, "size": 99999, "from": 500 }),
        )
        .unwrap();
        let body: Value = serde_json::from_slice(call.body.as_ref().unwrap()).unwrap();
        assert_eq!(body["size"], 50);
        assert_eq!(body["from"], 100);
        assert_eq!(call.path, "/events/_search");
        assert_eq!(call.method, reqwest::Method::POST);
    }

    #[test]
    fn scripting_guard_rejects_script_by_default() {
        let s = spec("search", json!({}));
        let err = build_call(
            &s,
            &json!({ "index": "events", "query": { "script": { "source": "1" } } }),
        )
        .unwrap_err();
        assert!(err.contains("script"), "{err}");
    }

    /// `scripted_metric` carries Painless under `init_script` / `map_script`
    /// / `combine_script` / `reduce_script`, so an exact-name ban on
    /// "script" let a caller-supplied `aggs` object past a guard documented
    /// as default-deny.
    #[test]
    fn scripting_guard_catches_scripted_metric_aggregation() {
        let s = spec("search", json!({}));
        let err = build_call(
            &s,
            &json!({
                "index": "events",
                "aggs": {
                    "profit": {
                        "scripted_metric": {
                            "init_script": "state.t = []",
                            "map_script": "state.t.add(1)",
                            "combine_script": "return 1",
                            "reduce_script": "return 1"
                        }
                    }
                }
            }),
        )
        .unwrap_err();
        assert!(err.contains("scripting"), "got: {err}");
    }

    #[test]
    fn scripting_key_predicate_covers_the_shapes() {
        for bad in [
            "script",
            "script_score",
            "scripted_metric",
            "runtime_mappings",
            "script_fields",
            "init_script",
            "map_script",
            "combine_script",
            "reduce_script",
        ] {
            assert!(is_scripting_key(bad), "{bad} must be refused");
        }
        for ok in ["query", "aggs", "description", "scripts", "transcript"] {
            assert!(!is_scripting_key(ok), "{ok} must be allowed");
        }
    }

    #[test]
    fn scripting_guard_detects_nested_runtime_mappings() {
        let s = spec("search", json!({}));
        let err = build_call(
            &s,
            &json!({ "index": "events", "query": { "bool": { "must": [ { "runtime_mappings": {} } ] } } }),
        )
        .unwrap_err();
        assert!(err.contains("runtime_mappings"), "{err}");
    }

    #[test]
    fn scripting_allowed_when_opted_in() {
        let s = spec("search", json!({ "allow_scripting": true }));
        let call = build_call(
            &s,
            &json!({ "index": "events", "query": { "script_score": { "script": "x" } } }),
        );
        assert!(call.is_ok());
    }

    #[test]
    fn get_encodes_doc_id_path() {
        let s = spec("get", json!({}));
        let call = build_call(&s, &json!({ "index": "events", "id": "a b/c" })).unwrap();
        assert_eq!(call.method, reqwest::Method::GET);
        assert!(call.path.starts_with("/events/_doc/"));
        // The space + slash must be percent-encoded — no raw `/` after _doc.
        let suffix = call.path.strip_prefix("/events/_doc/").unwrap();
        assert!(!suffix.contains('/'), "doc id slash not encoded: {suffix}");
        assert!(!suffix.contains(' '));
    }

    #[test]
    fn index_with_id_is_put_without_is_post() {
        let s = spec("index", json!({}));
        let with_id = build_call(
            &s,
            &json!({ "index": "events", "id": "1", "document": { "a": 1 } }),
        )
        .unwrap();
        assert_eq!(with_id.method, reqwest::Method::PUT);
        assert_eq!(with_id.path, "/events/_doc/1");
        let no_id = build_call(&s, &json!({ "index": "events", "document": { "a": 1 } })).unwrap();
        assert_eq!(no_id.method, reqwest::Method::POST);
        assert_eq!(no_id.path, "/events/_doc");
    }

    #[test]
    fn index_refresh_in_query() {
        let s = spec("index", json!({}));
        let call = build_call(
            &s,
            &json!({ "index": "events", "document": { "a": 1 }, "refresh": "wait_for" }),
        )
        .unwrap();
        assert_eq!(call.query.as_deref(), Some("refresh=wait_for"));
    }

    #[test]
    fn index_rejects_bad_refresh() {
        let s = spec("index", json!({}));
        let err = build_call(
            &s,
            &json!({ "index": "events", "document": {}, "refresh": "soon" }),
        )
        .unwrap_err();
        assert!(err.contains("refresh"), "{err}");
    }

    #[test]
    fn delete_builds_delete_method() {
        let s = spec("delete", json!({}));
        let call = build_call(&s, &json!({ "index": "events", "id": "42" })).unwrap();
        assert_eq!(call.method, reqwest::Method::DELETE);
        assert_eq!(call.path, "/events/_doc/42");
    }

    #[test]
    fn bulk_assembles_ndjson_with_trailing_newline() {
        let s = spec("bulk", json!({}));
        let call = build_call(
            &s,
            &json!({
                "index": "events",
                "operations": [
                    { "index": { "_id": "1" } },
                    { "field": "value" }
                ]
            }),
        )
        .unwrap();
        assert_eq!(call.content_type, NDJSON_CT);
        let body = String::from_utf8(call.body.unwrap()).unwrap();
        assert_eq!(body.lines().count(), 2);
        assert!(body.ends_with('\n'));
        assert!(body.contains("\"_id\":\"1\""));
        // The URL-scoped index is stamped onto the action line.
        assert!(body.contains("\"_index\":\"events\""));
    }

    /// `/{index}/_doc/..` normalizes to `/{index}/`, so a dot-only id turns
    /// a one-document delete into a delete of the whole index.
    #[test]
    fn dot_only_doc_id_is_refused() {
        for op in ["delete", "get"] {
            let s = spec(op, json!({}));
            for id in ["..", ".", "..."] {
                let err = build_call(&s, &json!({ "index": "events", "id": id })).unwrap_err();
                assert!(err.contains("dots"), "{op}/{id}: {err}");
            }
        }
        // A normal id containing dots is still fine.
        let s = spec("get", json!({}));
        let call = build_call(&s, &json!({ "index": "events", "id": "a.b.c" })).unwrap();
        assert_eq!(call.path, "/events/_doc/a.b.c");
    }

    /// A bulk action line may re-declare `_index`, which Elasticsearch
    /// honours over the URL — so it must clear the same allowlist.
    #[test]
    fn bulk_action_index_is_allowlist_checked() {
        let s = spec("bulk", json!({}));
        let err = build_call(
            &s,
            &json!({
                "index": "events",
                "operations": [
                    { "index": { "_index": "secrets", "_id": "1" } },
                    { "field": "value" }
                ]
            }),
        )
        .unwrap_err();
        assert!(err.contains("allowlist"), "got: {err}");

        // An allowlisted override is accepted and preserved.
        let call = build_call(
            &s,
            &json!({
                "index": "events",
                "operations": [
                    { "index": { "_index": "logs-2026", "_id": "1" } },
                    { "field": "value" }
                ]
            }),
        )
        .unwrap();
        let body = String::from_utf8(call.body.unwrap()).unwrap();
        assert!(body.contains("\"_index\":\"logs-2026\""), "got: {body}");
    }

    /// An `update` action's source line carries a `script`, which is a query
    /// body by another name and must hit the same scripting guard.
    #[test]
    fn bulk_source_line_hits_the_scripting_guard() {
        let s = spec("bulk", json!({}));
        let err = build_call(
            &s,
            &json!({
                "index": "events",
                "operations": [
                    { "update": { "_id": "1" } },
                    { "script": { "source": "ctx._source.x = 1" } }
                ]
            }),
        )
        .unwrap_err();
        assert!(err.contains("scripting"), "got: {err}");
    }

    /// An unknown verb on an action line would be passed through to ES.
    #[test]
    fn bulk_rejects_unknown_action_verb() {
        let s = spec("bulk", json!({}));
        let err = build_call(
            &s,
            &json!({ "index": "events", "operations": [ { "drop_index": {} } ] }),
        )
        .unwrap_err();
        assert!(err.contains("not one of"), "got: {err}");
    }

    #[test]
    fn msearch_assembles_header_and_body_lines() {
        let s = spec("msearch", json!({}));
        let call = build_call(
            &s,
            &json!({
                "searches": [
                    { "index": "events", "query": { "match_all": {} }, "size": 5 },
                    { "index": "logs-app", "query": { "term": { "x": 1 } } }
                ]
            }),
        )
        .unwrap();
        assert_eq!(call.content_type, NDJSON_CT);
        assert_eq!(call.path, "/_msearch");
        let body = String::from_utf8(call.body.unwrap()).unwrap();
        // 2 searches * 2 lines each = 4 lines.
        assert_eq!(body.lines().count(), 4);
        let first: Value = serde_json::from_str(body.lines().next().unwrap()).unwrap();
        assert_eq!(first["index"], "events");
    }

    #[test]
    fn msearch_validates_each_search_index_against_allowlist() {
        let s = spec("msearch", json!({}));
        let err = build_call(
            &s,
            &json!({ "searches": [ { "index": "secrets", "query": {} } ] }),
        )
        .unwrap_err();
        assert!(
            err.contains("allowlist") || err.contains("secrets"),
            "{err}"
        );
    }

    #[test]
    fn missing_required_arg_is_error() {
        let s = spec("get", json!({}));
        assert!(build_call(&s, &json!({ "index": "events" })).is_err());
        let s = spec("index", json!({}));
        assert!(build_call(&s, &json!({ "index": "events" })).is_err());
        let s = spec("bulk", json!({}));
        assert!(build_call(&s, &json!({ "index": "events" })).is_err());
    }

    #[test]
    fn request_body_byte_cap_enforced() {
        let s = spec("index", json!({ "max_request_bytes": 8 }));
        let err = build_call(
            &s,
            &json!({ "index": "events", "document": { "big": "xxxxxxxxxxxxxxxx" } }),
        )
        .unwrap_err();
        assert!(err.contains("max_request_bytes"), "{err}");
    }

    #[test]
    fn envelope_shape_on_synthetic_search_response() {
        let s = spec("search", json!({}));
        let call = build_call(
            &s,
            &json!({ "index": "events", "query": { "match_all": {} } }),
        )
        .unwrap();
        let res = EsResult {
            status: 200,
            json: Some(json!({
                "took": 3,
                "timed_out": false,
                "hits": { "total": { "value": 1 }, "hits": [ { "_id": "1", "_source": { "a": 1 } } ] }
            })),
            raw_body: String::new(),
            truncated: false,
        };
        let env = build_envelope(&s, &call, &res);
        assert_eq!(env["operation"], "search");
        assert_eq!(env["statusCode"], 200);
        assert_eq!(env["ok"], true);
        assert_eq!(env["response"]["hits"]["total"]["value"], 1);
        assert!(env["downstreamError"].is_null());
    }

    #[test]
    fn envelope_marks_4xx_as_downstream_error() {
        let s = spec("get", json!({}));
        let call = build_call(&s, &json!({ "index": "events", "id": "missing" })).unwrap();
        let res = EsResult {
            status: 404,
            json: Some(json!({ "found": false })),
            raw_body: String::new(),
            truncated: false,
        };
        let env = build_envelope(&s, &call, &res);
        assert_eq!(env["statusCode"], 404);
        assert_eq!(env["ok"], false);
        assert_eq!(env["downstreamError"]["statusCode"], 404);
    }

    fn knn_spec(extra: Value) -> ElasticsearchBackendSpec {
        let mut knn = json!({ "field": "embedding", "k": 5, "num_candidates": 100 });
        if let Value::Object(e) = extra {
            for (k, val) in e {
                knn[k] = val;
            }
        }
        spec("knn", json!({ "knn": knn }))
    }

    #[test]
    fn knn_builds_search_with_knn_clause() {
        let s = knn_spec(json!({}));
        let call = build_call(
            &s,
            &json!({ "index": "events", "query_vector": [0.1, 0.2, 0.3] }),
        )
        .unwrap();
        assert_eq!(call.method, reqwest::Method::POST);
        assert_eq!(call.path, "/events/_search");
        let body: Value = serde_json::from_slice(call.body.as_deref().unwrap()).unwrap();
        let knn = &body["knn"];
        assert_eq!(knn["field"], "embedding");
        assert_eq!(knn["k"], 5);
        assert_eq!(knn["num_candidates"], 100);
        assert_eq!(knn["query_vector"], json!([0.1, 0.2, 0.3]));
        assert!(knn.get("filter").is_none());
    }

    #[test]
    fn knn_clamps_num_candidates_up_to_k() {
        let s = knn_spec(json!({ "k": 50, "num_candidates": 10 }));
        let call = build_call(&s, &json!({ "index": "events", "query_vector": [1.0] })).unwrap();
        let body: Value = serde_json::from_slice(call.body.as_deref().unwrap()).unwrap();
        assert_eq!(body["knn"]["k"], 50);
        // num_candidates < k is clamped up to k.
        assert_eq!(body["knn"]["num_candidates"], 50);
    }

    #[test]
    fn knn_includes_filter_clause() {
        let s = knn_spec(json!({ "filter": { "term": { "tenant": "acme" } } }));
        let call = build_call(
            &s,
            &json!({ "index": "events", "query_vector": [1.0, 2.0] }),
        )
        .unwrap();
        let body: Value = serde_json::from_slice(call.body.as_deref().unwrap()).unwrap();
        assert_eq!(
            body["knn"]["filter"],
            json!({ "term": { "tenant": "acme" } })
        );
    }

    #[test]
    fn knn_falls_back_to_literal_vector() {
        let s = knn_spec(json!({ "query_vector": [9.0, 8.0, 7.0] }));
        // No call-arg query_vector → the literal is used.
        let call = build_call(&s, &json!({ "index": "events" })).unwrap();
        let body: Value = serde_json::from_slice(call.body.as_deref().unwrap()).unwrap();
        assert_eq!(body["knn"]["query_vector"], json!([9.0, 8.0, 7.0]));
    }

    #[test]
    fn knn_call_arg_overrides_literal() {
        let s = knn_spec(json!({ "query_vector": [9.0] }));
        let call = build_call(
            &s,
            &json!({ "index": "events", "query_vector": [1.0, 1.0] }),
        )
        .unwrap();
        let body: Value = serde_json::from_slice(call.body.as_deref().unwrap()).unwrap();
        assert_eq!(body["knn"]["query_vector"], json!([1.0, 1.0]));
    }

    #[test]
    fn knn_rejects_non_array_query_vector() {
        let s = knn_spec(json!({}));
        let err = build_call(
            &s,
            &json!({ "index": "events", "query_vector": "not-an-array" }),
        )
        .unwrap_err();
        assert!(err.contains("query_vector"), "{err}");
    }

    #[test]
    fn knn_rejects_non_numeric_vector_element() {
        let s = knn_spec(json!({}));
        let err = build_call(
            &s,
            &json!({ "index": "events", "query_vector": [1.0, "x"] }),
        )
        .unwrap_err();
        assert!(err.contains("query_vector[1]"), "{err}");
    }

    #[test]
    fn knn_rejects_empty_query_vector() {
        let s = knn_spec(json!({}));
        let err = build_call(&s, &json!({ "index": "events", "query_vector": [] })).unwrap_err();
        assert!(err.contains("query_vector"), "{err}");
    }

    #[test]
    fn knn_missing_vector_with_no_literal_is_error() {
        let s = knn_spec(json!({}));
        let err = build_call(&s, &json!({ "index": "events" })).unwrap_err();
        assert!(err.contains("query_vector"), "{err}");
    }

    #[test]
    fn knn_filter_subject_to_scripting_guard() {
        let s = knn_spec(json!({ "filter": { "script": { "source": "1" } } }));
        let err = build_call(&s, &json!({ "index": "events", "query_vector": [1.0] })).unwrap_err();
        assert!(err.contains("script"), "{err}");
    }

    #[test]
    fn knn_off_allowlist_index_is_error() {
        let s = knn_spec(json!({}));
        let err =
            build_call(&s, &json!({ "index": "secrets", "query_vector": [1.0] })).unwrap_err();
        assert!(
            err.contains("allowlist") || err.contains("secrets"),
            "{err}"
        );
    }

    #[test]
    fn count_omits_paging_fields() {
        let s = spec("count", json!({}));
        let call = build_call(
            &s,
            &json!({ "index": "events", "query": { "match_all": {} }, "size": 99 }),
        )
        .unwrap();
        assert_eq!(call.path, "/events/_count");
        let body: Value = serde_json::from_slice(call.body.as_ref().unwrap()).unwrap();
        assert!(body.get("size").is_none(), "count must not carry size");
        assert!(body.get("query").is_some());
    }
}
