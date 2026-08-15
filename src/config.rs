//! Per-binding spec for `dev.mcpg.backend.elasticsearch`.
//!
//! One binding == one Elasticsearch / OpenSearch operation against an
//! operator-configured base URL + index allowlist (the `http`/`sql`
//! envelope model). The gateway serialises its typed binding config to
//! this spec for `register_profile`.
//!
//! No `deny_unknown_fields` on the TOP-LEVEL spec struct — the gateway
//! injects `__mcpg_secret_refs` (and possibly `__mcpg_id_sig`) attributes
//! before registration; the nested sub-structs (`EsAuth`, `EsTlsConfig`)
//! DO carry `deny_unknown_fields` so a typo in those is caught.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Per-binding Elasticsearch spec.
#[derive(Clone, Deserialize, Serialize)]
pub struct ElasticsearchBackendSpec {
    /// Base URL(s). First is primary; the rest are failover (tried in
    /// order on transport error). Each must be `https://` (or
    /// `http://localhost` for the security-disabled test container).
    /// Trailing slash trimmed at register.
    pub urls: Vec<String>,

    /// Which ES operation this binding exposes as a tool.
    pub operation: EsOperation,

    /// Default index used when the `index` argument is absent. MUST be a
    /// valid index token AND (unless `allow_any_index`) be covered by the
    /// allowlist. Optional — when absent, the `index` arg is required
    /// (except for `msearch`, whose indices ride per-search).
    #[serde(default)]
    pub default_index: Option<String>,

    /// Index allowlist. Empty => NO index reachable (fail-closed) unless
    /// `allow_any_index` is explicitly true. Each entry is validated as a
    /// safe index token; a single trailing `*` (e.g. `logs-*`) is a
    /// prefix wildcard.
    #[serde(default)]
    pub index_allowlist: Vec<String>,

    /// Escape hatch — when true the allowlist is bypassed (the resolved
    /// index is still subject to the path-injection token validator).
    #[serde(default)]
    pub allow_any_index: bool,

    /// Required true for write operations (`index` / `delete` / `bulk`).
    /// Read-only by default.
    #[serde(default)]
    pub allow_writes: bool,

    /// Allow `script` / `script_score` / `runtime_mappings` keys in a
    /// query body. Default deny (server-side code-execution surface).
    #[serde(default)]
    pub allow_scripting: bool,

    /// Auth surface. Exactly one variant.
    #[serde(default)]
    pub auth: EsAuth,

    /// TLS knobs.
    #[serde(default)]
    pub tls: EsTlsConfig,

    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_operation_timeout_ms")]
    pub operation_timeout_ms: u64,
    #[serde(default = "default_max_response_bytes")]
    pub max_response_bytes: usize,
    #[serde(default = "default_max_request_bytes")]
    pub max_request_bytes: usize,
    #[serde(default = "default_max_size")]
    pub max_size: u64,
    #[serde(default = "default_max_from")]
    pub max_from: u64,

    /// Allow private/loopback resolved addresses (test / in-cluster ES).
    /// Default false => the DNS-rebinding guard rejects private IPs.
    #[serde(default)]
    pub allow_private_backends: bool,

    /// MCP surface this binding serves. `tool` (default) emits the unchanged
    /// REST envelope; `resource` reshapes a successful (2xx) response body into
    /// the `resources/read` `{contents:[…]}` body; `prompt` reshapes it into the
    /// `prompts/get` `{messages:[…]}` body. Non-2xx responses keep the tool
    /// envelope (carrying `downstreamError`) on every surface. Set to match the
    /// capability list the binding is placed under (`resources[]` / `prompts[]`).
    #[serde(default)]
    pub surface: crate::surface::Surface,

    /// Optional static resource URI for `surface: resource`. When set it is used
    /// verbatim as the emitted content `uri`; when omitted the binding uses the
    /// requested URI the gateway passes in the call arguments (`uri`). Ignored
    /// for `tool` / `prompt` surfaces.
    #[serde(default)]
    pub uri: Option<String>,

    /// Optional listing config for `resources/list`. On a `surface: resource`
    /// binding this runs an operator-fixed `_search` to enumerate concrete
    /// resource URIs. The query body and index are operator-fixed; the only
    /// caller-derived value is the opaque pagination cursor (an offset). Empty →
    /// the binding returns no dynamic listing (the trait default).
    #[serde(default)]
    pub list_query: Option<ListQueryConfig>,

    /// Optional per-template-variable completion config for
    /// `completion/complete`. Keyed by the URI template variable name; each
    /// entry runs an operator-fixed `_search` whose `prefix` query on the
    /// declared `field` carries the caller-typed prefix as a JSON string VALUE
    /// (never raw query DSL — injection-safe). Empty → no completion candidates
    /// (the trait default).
    #[serde(default)]
    pub variable_completions: std::collections::BTreeMap<String, EsCompletionConfig>,

    /// Vector kNN config for `operation: knn`. Operator-fixed `field` / `k` /
    /// `num_candidates` / `filter`, plus an optional literal fallback query
    /// vector. The query vector itself rides as the per-call `query_vector`
    /// argument (an array of numbers) when present, falling back to the
    /// literal. Required (and only meaningful) for the `knn` op.
    #[serde(default)]
    pub knn: Option<KnnConfig>,
}

/// Operator-fixed kNN parameters for `operation: knn`. The query body issued
/// is a `_search` carrying a top-level `knn: { field, query_vector, k,
/// num_candidates, filter? }` clause (the modern ES kNN API).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct KnnConfig {
    /// The `dense_vector` field to search. Required. Must be a safe field token.
    pub field: String,
    /// Number of nearest neighbours to return. Required, must be > 0.
    pub k: usize,
    /// Candidate pool size per shard (`num_candidates`). Optional — ES defaults
    /// when omitted. When set it is clamped to `>= k` at build time.
    #[serde(default)]
    pub num_candidates: Option<usize>,
    /// Optional operator-fixed `filter` query ANDed with the kNN search. Caller
    /// input never reaches it; subject to the same scripting guard as a search
    /// body.
    #[serde(default)]
    pub filter: Option<serde_json::Value>,
    /// Optional literal query vector used when the call provides no
    /// `query_vector` argument. Each element must be a finite number.
    #[serde(default)]
    pub query_vector: Option<Vec<f64>>,
}

/// Operator-fixed `_search` that enumerates resources for `resources/list`.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct ListQueryConfig {
    /// Index to search. Resolved + allowlist-checked the same way the per-call
    /// `index` argument is; falls back to `default_index` when absent.
    #[serde(default)]
    pub index: Option<String>,
    /// Operator-fixed query DSL body (e.g. `{"match_all":{}}`). Caller input
    /// never reaches it. Defaults to `match_all` when omitted.
    #[serde(default)]
    pub query: Option<serde_json::Value>,
    /// `_source` dot-path whose string value is the resource URI. Required.
    pub uri_field: String,
    /// Optional `_source` path for the resource display name.
    #[serde(default)]
    pub name_field: Option<String>,
    /// Optional `_source` path for the resource description.
    #[serde(default)]
    pub description_field: Option<String>,
    /// Rows per page (1..=1000). Defaults to 100.
    #[serde(default = "default_list_page_size")]
    pub page_size: u64,
}

/// Operator-fixed `_search` producing completion candidates for one template
/// variable via a `prefix` query that binds the caller prefix as a value.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct EsCompletionConfig {
    /// Index to search (resolved + allowlist-checked); falls back to
    /// `default_index`.
    #[serde(default)]
    pub index: Option<String>,
    /// The field the `prefix` query matches AND whose `_source` value is
    /// returned as a candidate. Required. Must be a safe field token.
    pub field: String,
    /// Optional operator-fixed `filter` clauses ANDed with the prefix query
    /// (e.g. an owner term). Caller input never reaches these.
    #[serde(default)]
    pub filter: Option<serde_json::Value>,
    /// Optional cap on returned candidates; defaults to 100.
    #[serde(default)]
    pub max_results: Option<u32>,
}

fn default_list_page_size() -> u64 {
    100
}

/// A safe ES field token for the prefix-query path / `_source` projection —
/// `[A-Za-z0-9_.]`, non-empty. Fences the operator-declared `field`, which is
/// used as a JSON object key in the constructed query body.
pub fn is_safe_field_token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.'))
}

fn default_connect_timeout_ms() -> u64 {
    5_000
}
fn default_operation_timeout_ms() -> u64 {
    30_000
}
fn default_max_response_bytes() -> usize {
    4 * 1024 * 1024
}
fn default_max_request_bytes() -> usize {
    4 * 1024 * 1024
}
fn default_max_size() -> u64 {
    1_000
}
fn default_max_from() -> u64 {
    10_000
}

/// Redacting `Debug` so `{:?}` of a spec never prints the auth secret.
impl std::fmt::Debug for ElasticsearchBackendSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ElasticsearchBackendSpec")
            .field("urls", &self.urls)
            .field("operation", &self.operation)
            .field("default_index", &self.default_index)
            .field("index_allowlist", &self.index_allowlist)
            .field("allow_any_index", &self.allow_any_index)
            .field("allow_writes", &self.allow_writes)
            .field("allow_scripting", &self.allow_scripting)
            .field("auth", &self.auth)
            .field("tls", &self.tls)
            .field("connect_timeout_ms", &self.connect_timeout_ms)
            .field("operation_timeout_ms", &self.operation_timeout_ms)
            .field("max_response_bytes", &self.max_response_bytes)
            .field("max_request_bytes", &self.max_request_bytes)
            .field("max_size", &self.max_size)
            .field("max_from", &self.max_from)
            .field("allow_private_backends", &self.allow_private_backends)
            .field("knn", &self.knn)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EsOperation {
    Search,
    Count,
    Get,
    Index,
    Delete,
    Bulk,
    Msearch,
    Knn,
}

impl EsOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            EsOperation::Search => "search",
            EsOperation::Count => "count",
            EsOperation::Get => "get",
            EsOperation::Index => "index",
            EsOperation::Delete => "delete",
            EsOperation::Bulk => "bulk",
            EsOperation::Msearch => "msearch",
            EsOperation::Knn => "knn",
        }
    }

    /// Whether this op mutates the index (gated by `allow_writes`).
    pub fn is_write(self) -> bool {
        matches!(
            self,
            EsOperation::Index | EsOperation::Delete | EsOperation::Bulk
        )
    }

    /// Whether this op resolves a single per-call index (vs `msearch`,
    /// which carries indices per search line).
    pub fn needs_index(self) -> bool {
        !matches!(self, EsOperation::Msearch)
    }
}

/// Auth surface. The secret-bearing fields carry `cred://<plugin>/<target>`
/// (resolved per-caller at dispatch) and/or `${env.X}` (resolved at config
/// load). `kind: none` is the security-disabled / fronting-proxy case.
#[derive(Clone, Deserialize, Serialize, Default)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EsAuth {
    #[default]
    None,
    /// ES `Authorization: ApiKey <base64(id:api_key)>`.
    ApiKey { api_key: String },
    /// HTTP Basic. `username` is plain; `password` carries the secret.
    Basic { username: String, password: String },
    /// Raw Bearer token (OpenSearch / proxied ES).
    Bearer { token: String },
}

// Redacting `Debug` — the secret-bearing fields never reach a `{:?}`.
impl std::fmt::Debug for EsAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EsAuth::None => f.write_str("None"),
            EsAuth::ApiKey { .. } => f.debug_struct("ApiKey").field("api_key", &"***").finish(),
            EsAuth::Basic { username, .. } => f
                .debug_struct("Basic")
                .field("username", username)
                .field("password", &"***")
                .finish(),
            EsAuth::Bearer { .. } => f.debug_struct("Bearer").field("token", &"***").finish(),
        }
    }
}

#[derive(Clone, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct EsTlsConfig {
    /// Inline PEM CA bundle (or a PEM path) for a private / self-signed CA.
    #[serde(default)]
    pub ca_cert_pem: Option<String>,
    /// Skip server cert verification. DANGEROUS — only honored when ALL
    /// base URLs are loopback; register fails otherwise. Dev self-signed
    /// ES only.
    #[serde(default)]
    pub insecure_skip_verify: bool,
}

impl std::fmt::Debug for EsTlsConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EsTlsConfig")
            .field("ca_cert_pem", &self.ca_cert_pem.as_ref().map(|_| "<pem>"))
            .field("insecure_skip_verify", &self.insecure_skip_verify)
            .finish()
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SpecError {
    #[error("elasticsearch spec JSON: {0}")]
    Json(String),
    #[error("elasticsearch: urls must not be empty")]
    EmptyUrls,
    #[error("elasticsearch: url `{0}` must be https:// (or http://localhost for tests)")]
    InvalidUrl(String),
    #[error("elasticsearch: index token `{0}` is invalid")]
    InvalidIndexToken(String),
    #[error(
        "elasticsearch: no reachable index — set index_allowlist, default_index, or allow_any_index"
    )]
    NoReachableIndex,
    #[error("elasticsearch: default_index `{0}` is not covered by index_allowlist")]
    DefaultIndexNotAllowed(String),
    #[error("elasticsearch: operation `{0}` is a write; set allow_writes: true")]
    WritesNotAllowed(&'static str),
    #[error("elasticsearch: tls.insecure_skip_verify requires all urls to be loopback")]
    InsecureSkipVerifyNonLoopback,
    #[error("elasticsearch: tls.ca_cert_pem and tls.insecure_skip_verify are contradictory")]
    TlsContradiction,
    #[error("elasticsearch: auth secret must not be empty")]
    EmptyAuthSecret,
    #[error("elasticsearch: operation_timeout_ms must be > 0")]
    InvalidOperationTimeout,
    #[error("elasticsearch: connect_timeout_ms must be > 0")]
    InvalidConnectTimeout,
    #[error("elasticsearch: max_response_bytes must be > 0")]
    InvalidResponseBytes,
    #[error("elasticsearch: max_request_bytes must be > 0")]
    InvalidRequestBytes,
    #[error("elasticsearch: max_size must be > 0")]
    InvalidMaxSize,
    #[error("elasticsearch: `uri` is only valid with `surface: resource`")]
    UriRequiresResourceSurface,
    #[error("elasticsearch: `uri` must not be empty")]
    EmptyUri,
    #[error("elasticsearch: list_query.uri_field must not be empty")]
    EmptyListUriField,
    #[error("elasticsearch: list_query.page_size must be 1..=1000")]
    InvalidListPageSize,
    #[error("elasticsearch: list_query.index — {0}")]
    InvalidListIndex(String),
    #[error("elasticsearch: variable_completions.{0}.field `{1}` is not a safe field token")]
    InvalidCompletionField(String, String),
    #[error("elasticsearch: variable_completions.{0}.index — {1}")]
    InvalidCompletionIndex(String, String),
    #[error("elasticsearch: operation `knn` requires a `knn` config block")]
    KnnConfigMissing,
    #[error("elasticsearch: `knn` config is only valid with operation `knn`")]
    KnnConfigUnused,
    #[error("elasticsearch: knn.field must not be empty / must be a safe field token")]
    InvalidKnnField,
    #[error("elasticsearch: knn.k must be > 0")]
    InvalidKnnK,
    #[error("elasticsearch: knn.query_vector literal must be a non-empty array of finite numbers")]
    InvalidKnnLiteralVector,
}

/// An endpoint override is config-origin, but constrain it: `https://`
/// anywhere, or `http://` only to an exact localhost host (the
/// test/emulator carve-out). Plain `http://` to any other host is an
/// operator footgun (cleartext credentials) — reject it.
pub(crate) fn is_allowed_endpoint(url: &str) -> bool {
    if let Some(rest) = url.strip_prefix("https://") {
        return !rest.is_empty();
    }
    if let Some(rest) = url.strip_prefix("http://") {
        let host = rest.split(['/', ':']).next().unwrap_or("");
        return matches!(host, "localhost" | "127.0.0.1" | "[::1]");
    }
    false
}

/// Whether the URL's host is a loopback literal (gates
/// `insecure_skip_verify`).
pub(crate) fn is_loopback_url(url: &str) -> bool {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"));
    let Some(rest) = rest else {
        return false;
    };
    let host = rest.split(['/', ':']).next().unwrap_or("");
    matches!(host, "localhost" | "127.0.0.1" | "[::1]")
}

/// Safe ES index token for inline use in a URL path segment.
///
/// ES index naming rules + path-injection defense: lowercase only; no
/// `/`, `\`, `?`, `"`, `<`, `>`, `|`, ` `, `,`, `#`, `:`, `*` (except a
/// single TRAILING `*` for an allowlist wildcard — never in a resolved
/// request index); no leading `-`, `_`, `+`; not `.` or `..`; ≤255 bytes;
/// no `%` (percent-encoding breakout). `allow_wildcard` permits the single
/// trailing `*` (used only when validating allowlist entries, never a
/// resolved request index).
pub(crate) fn is_safe_index_token_inner(s: &str, allow_wildcard: bool) -> bool {
    if s.is_empty() || s.len() > 255 {
        return false;
    }
    if s == "." || s == ".." {
        return false;
    }
    // Reserved single-index aliases that would widen the request scope.
    if s == "_all" {
        return false;
    }
    // A single trailing `*` may be stripped for the wildcard form; any
    // OTHER `*` (or a `*` when wildcards are disallowed) is rejected.
    let core = if allow_wildcard && s.ends_with('*') {
        &s[..s.len() - 1]
    } else {
        s
    };
    if core.is_empty() {
        // A bare `*` (or trailing `*` with no prefix) widens to all
        // indices — reject.
        return false;
    }
    let first = core.as_bytes()[0];
    if matches!(first, b'-' | b'_' | b'+') {
        return false;
    }
    for &b in core.as_bytes() {
        // Lowercase ASCII letters, digits, and a small punctuation set ES
        // permits in index names. Everything else (including '/', '\',
        // '%', '*', uppercase, control, whitespace) is rejected.
        let ok =
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_' | b'+');
        if !ok {
            return false;
        }
    }
    true
}

/// A resolved request index — no wildcards permitted.
pub fn is_safe_index_token(s: &str) -> bool {
    is_safe_index_token_inner(s, false)
}

/// An allowlist entry — a single trailing `*` is permitted as a prefix
/// wildcard.
pub(crate) fn is_safe_allowlist_token(s: &str) -> bool {
    is_safe_index_token_inner(s, true)
}

/// Whether a resolved (wildcard-free) index is covered by one allowlist
/// entry. A trailing-`*` entry matches as a prefix; a plain entry matches
/// exactly.
pub(crate) fn allowlist_covers(allowlist: &[String], index: &str) -> bool {
    allowlist.iter().any(|entry| {
        if let Some(prefix) = entry.strip_suffix('*') {
            index.starts_with(prefix)
        } else {
            entry == index
        }
    })
}

impl ElasticsearchBackendSpec {
    pub fn parse(spec: &serde_json::Value) -> Result<Self, SpecError> {
        let parsed: Self =
            serde_json::from_value(spec.clone()).map_err(|e| SpecError::Json(e.to_string()))?;
        parsed.validate()?;
        Ok(parsed)
    }

    fn validate(&self) -> Result<(), SpecError> {
        if self.urls.is_empty() {
            return Err(SpecError::EmptyUrls);
        }
        for u in &self.urls {
            if !is_allowed_endpoint(u.trim()) {
                return Err(SpecError::InvalidUrl(u.clone()));
            }
        }

        for entry in &self.index_allowlist {
            if !is_safe_allowlist_token(entry) {
                return Err(SpecError::InvalidIndexToken(entry.clone()));
            }
        }
        if let Some(di) = &self.default_index {
            if !is_safe_index_token(di) {
                return Err(SpecError::InvalidIndexToken(di.clone()));
            }
            if !self.allow_any_index && !allowlist_covers(&self.index_allowlist, di) {
                return Err(SpecError::DefaultIndexNotAllowed(di.clone()));
            }
        }

        // Fail-closed: an index-resolving op with no reachable index is a
        // config error. `msearch` carries indices per-search so it is
        // exempt from the default-index requirement, but still needs a
        // way to validate them (allowlist or allow_any_index).
        if self.operation.needs_index() {
            if self.index_allowlist.is_empty()
                && !self.allow_any_index
                && self.default_index.is_none()
            {
                return Err(SpecError::NoReachableIndex);
            }
        } else if self.index_allowlist.is_empty() && !self.allow_any_index {
            return Err(SpecError::NoReachableIndex);
        }

        if self.operation.is_write() && !self.allow_writes {
            return Err(SpecError::WritesNotAllowed(self.operation.as_str()));
        }

        if self.tls.insecure_skip_verify {
            if self.tls.ca_cert_pem.is_some() {
                return Err(SpecError::TlsContradiction);
            }
            if !self.urls.iter().all(|u| is_loopback_url(u.trim())) {
                return Err(SpecError::InsecureSkipVerifyNonLoopback);
            }
        }

        // Reject only an EMPTY literal secret — real cred:// / ${env}
        // resolution happens later. A `${...}` placeholder or a bare
        // `cred://...` is a non-empty literal and passes here.
        match &self.auth {
            EsAuth::None => {}
            EsAuth::ApiKey { api_key } => {
                if api_key.trim().is_empty() {
                    return Err(SpecError::EmptyAuthSecret);
                }
            }
            EsAuth::Basic { password, .. } => {
                if password.trim().is_empty() {
                    return Err(SpecError::EmptyAuthSecret);
                }
            }
            EsAuth::Bearer { token } => {
                if token.trim().is_empty() {
                    return Err(SpecError::EmptyAuthSecret);
                }
            }
        }

        if self.operation_timeout_ms == 0 {
            return Err(SpecError::InvalidOperationTimeout);
        }
        if self.connect_timeout_ms == 0 {
            return Err(SpecError::InvalidConnectTimeout);
        }
        if self.max_response_bytes == 0 {
            return Err(SpecError::InvalidResponseBytes);
        }
        if self.max_request_bytes == 0 {
            return Err(SpecError::InvalidRequestBytes);
        }
        if self.max_size == 0 {
            return Err(SpecError::InvalidMaxSize);
        }
        // Surface coherence: `uri` is only meaningful on the resource surface; a
        // static `uri` on a tool/prompt binding is a config mistake worth a
        // fail-closed rejection rather than a silent no-op.
        if self.uri.is_some() && self.surface != crate::surface::Surface::Resource {
            return Err(SpecError::UriRequiresResourceSurface);
        }
        if let Some(u) = &self.uri
            && u.trim().is_empty()
        {
            return Err(SpecError::EmptyUri);
        }
        // Operator-fixed listing: non-empty uri field, bounded page size, and a
        // resolvable + allowlisted index — fail-closed so a misconfigured
        // listing never reaches a `resources/list` call.
        if let Some(lq) = &self.list_query {
            if lq.uri_field.trim().is_empty() {
                return Err(SpecError::EmptyListUriField);
            }
            if !(1..=1000).contains(&lq.page_size) {
                return Err(SpecError::InvalidListPageSize);
            }
            self.resolve_index(lq.index.as_deref())
                .map_err(SpecError::InvalidListIndex)?;
        }
        // Operator-fixed completion: safe field token + resolvable index.
        for (name, cc) in &self.variable_completions {
            if !is_safe_field_token(&cc.field) {
                return Err(SpecError::InvalidCompletionField(
                    name.clone(),
                    cc.field.clone(),
                ));
            }
            self.resolve_index(cc.index.as_deref())
                .map_err(|e| SpecError::InvalidCompletionIndex(name.clone(), e))?;
        }
        // kNN config coherence: present iff the op is `knn`, safe field token,
        // positive k, and a finite literal vector when one is supplied. The
        // scripting guard over the optional filter runs at build time.
        match (self.operation, &self.knn) {
            (EsOperation::Knn, None) => return Err(SpecError::KnnConfigMissing),
            (op, Some(_)) if op != EsOperation::Knn => return Err(SpecError::KnnConfigUnused),
            (_, None) => {}
            (_, Some(knn)) => {
                if !is_safe_field_token(&knn.field) {
                    return Err(SpecError::InvalidKnnField);
                }
                if knn.k == 0 {
                    return Err(SpecError::InvalidKnnK);
                }
                if let Some(v) = &knn.query_vector
                    && (v.is_empty() || v.iter().any(|x| !x.is_finite()))
                {
                    return Err(SpecError::InvalidKnnLiteralVector);
                }
            }
        }
        Ok(())
    }

    /// Base URLs with trailing slashes trimmed.
    pub fn trimmed_urls(&self) -> Vec<String> {
        self.urls
            .iter()
            .map(|u| u.trim().trim_end_matches('/').to_owned())
            .collect()
    }

    /// Resolve a per-call index: prefer the argument, fall back to
    /// `default_index`. Validates the token and (unless `allow_any_index`)
    /// allowlist membership. Returns a tool-level error message on a bad
    /// index (so the caller gets `isError: true`, not a 5xx).
    pub fn resolve_index(&self, arg_index: Option<&str>) -> Result<String, String> {
        let index = match (arg_index, &self.default_index) {
            (Some(i), _) => i.to_owned(),
            (None, Some(d)) => d.clone(),
            (None, None) => {
                return Err(
                    "missing required `index` argument (no default_index configured)".into(),
                );
            }
        };
        if !is_safe_index_token(&index) {
            return Err(format!("index `{index}` is not a valid index name"));
        }
        if !self.allow_any_index && !allowlist_covers(&self.index_allowlist, &index) {
            return Err(format!(
                "index `{index}` is not in the configured allowlist"
            ));
        }
        Ok(index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn minimal_search() -> serde_json::Value {
        json!({
            "urls": ["https://es.example.com:9200"],
            "operation": "search",
            "index_allowlist": ["logs"]
        })
    }

    #[test]
    fn surface_defaults_to_tool() {
        let s = ElasticsearchBackendSpec::parse(&minimal_search()).unwrap();
        assert_eq!(s.surface, crate::surface::Surface::Tool);
        assert!(s.uri.is_none());
    }

    #[test]
    fn parses_resource_surface_with_uri() {
        let mut v = minimal_search();
        v["surface"] = json!("resource");
        v["uri"] = json!("es://logs/all");
        let s = ElasticsearchBackendSpec::parse(&v).unwrap();
        assert_eq!(s.surface, crate::surface::Surface::Resource);
        assert_eq!(s.uri.as_deref(), Some("es://logs/all"));
    }

    #[test]
    fn rejects_uri_on_tool_surface() {
        let mut v = minimal_search();
        v["uri"] = json!("es://x");
        assert_eq!(
            ElasticsearchBackendSpec::parse(&v).unwrap_err(),
            SpecError::UriRequiresResourceSurface
        );
    }

    #[test]
    fn parses_list_query_and_completions() {
        let mut v = minimal_search();
        v["default_index"] = json!("logs");
        v["surface"] = json!("resource");
        v["list_query"] = json!({
            "uri_field": "uri",
            "name_field": "title",
            "query": { "term": { "kind": "doc" } },
            "page_size": 50,
        });
        v["variable_completions"] = json!({
            "name": { "field": "name.keyword", "filter": [{ "term": { "owner": "acme" } }] }
        });
        let s = ElasticsearchBackendSpec::parse(&v).unwrap();
        let lq = s.list_query.expect("list_query");
        assert_eq!(lq.uri_field, "uri");
        assert_eq!(lq.page_size, 50);
        assert!(s.variable_completions.contains_key("name"));
    }

    #[test]
    fn rejects_list_query_empty_uri_field() {
        let mut v = minimal_search();
        v["default_index"] = json!("logs");
        v["list_query"] = json!({ "uri_field": "  " });
        assert_eq!(
            ElasticsearchBackendSpec::parse(&v).unwrap_err(),
            SpecError::EmptyListUriField
        );
    }

    #[test]
    fn rejects_list_query_off_allowlist_index() {
        let mut v = minimal_search();
        v["list_query"] = json!({ "uri_field": "uri", "index": "secrets" });
        assert!(matches!(
            ElasticsearchBackendSpec::parse(&v).unwrap_err(),
            SpecError::InvalidListIndex(_)
        ));
    }

    #[test]
    fn rejects_completion_unsafe_field() {
        let mut v = minimal_search();
        v["default_index"] = json!("logs");
        v["variable_completions"] = json!({
            "x": { "field": "name\"};drop" }
        });
        assert!(matches!(
            ElasticsearchBackendSpec::parse(&v).unwrap_err(),
            SpecError::InvalidCompletionField(_, _)
        ));
    }

    #[test]
    fn safe_field_token_rules() {
        assert!(is_safe_field_token("name"));
        assert!(is_safe_field_token("name.keyword"));
        assert!(!is_safe_field_token(""));
        assert!(!is_safe_field_token("name\"x"));
        assert!(!is_safe_field_token("na me"));
    }

    #[test]
    fn parses_minimal_with_defaults() {
        let s = ElasticsearchBackendSpec::parse(&minimal_search()).unwrap();
        assert_eq!(s.operation, EsOperation::Search);
        assert_eq!(s.connect_timeout_ms, 5_000);
        assert_eq!(s.operation_timeout_ms, 30_000);
        assert_eq!(s.max_size, 1_000);
        assert_eq!(s.max_from, 10_000);
        assert_eq!(s.max_response_bytes, 4 * 1024 * 1024);
        assert!(!s.allow_writes);
        assert!(matches!(s.auth, EsAuth::None));
    }

    #[test]
    fn nested_auth_denies_unknown_field() {
        let mut v = minimal_search();
        v["auth"] = json!({ "kind": "api_key", "api_key": "x", "typo": 1 });
        assert!(matches!(
            ElasticsearchBackendSpec::parse(&v).unwrap_err(),
            SpecError::Json(_)
        ));
    }

    #[test]
    fn nested_tls_denies_unknown_field() {
        let mut v = minimal_search();
        v["tls"] = json!({ "insecure_skip_verify": false, "typo": true });
        assert!(matches!(
            ElasticsearchBackendSpec::parse(&v).unwrap_err(),
            SpecError::Json(_)
        ));
    }

    #[test]
    fn top_level_tolerates_injected_secret_refs() {
        // The gateway injects `__mcpg_secret_refs`; the top-level spec must
        // NOT reject it (no deny_unknown_fields there).
        let mut v = minimal_search();
        v["__mcpg_secret_refs"] = json!(["cred://es/key"]);
        v["__mcpg_id_sig"] = json!("deadbeef");
        assert!(ElasticsearchBackendSpec::parse(&v).is_ok());
    }

    #[test]
    fn endpoint_https_or_localhost_only() {
        assert!(is_allowed_endpoint("https://es:9200"));
        assert!(is_allowed_endpoint("http://localhost:9200"));
        assert!(is_allowed_endpoint("http://127.0.0.1:9200"));
        assert!(!is_allowed_endpoint("http://evil:9200"));
        assert!(!is_allowed_endpoint("ftp://es:9200"));
        assert!(!is_allowed_endpoint("https://"));
    }

    #[test]
    fn rejects_plain_http_nonlocal_url() {
        let mut v = minimal_search();
        v["urls"] = json!(["http://es.evil.com:9200"]);
        assert!(matches!(
            ElasticsearchBackendSpec::parse(&v).unwrap_err(),
            SpecError::InvalidUrl(_)
        ));
    }

    #[test]
    fn index_token_accepts_valid_names() {
        for ok in ["logs", "my-index-2024", "logs.2024.06", "a", "events_v2"] {
            assert!(is_safe_index_token(ok), "{ok} should be valid");
        }
    }

    #[test]
    fn index_token_rejects_path_breakout_and_specials() {
        for bad in [
            "../etc",
            "a/b",
            "..",
            ".",
            "%2e%2e",
            "_all",
            "*",
            "-leading",
            "_leading",
            "+leading",
            "UPPER",
            "has space",
            "a,b",
            "a:b",
            "a#b",
            "a?b",
            "a*b",
            "back\\slash",
            "a%2f",
        ] {
            assert!(!is_safe_index_token(bad), "{bad} should be rejected");
        }
        // > 255 bytes.
        let long = "a".repeat(256);
        assert!(!is_safe_index_token(&long));
    }

    #[test]
    fn allowlist_token_accepts_trailing_wildcard_only() {
        assert!(is_safe_allowlist_token("logs-*"));
        assert!(is_safe_allowlist_token("logs"));
        // Wildcard NOT at the end, or a bare `*`, is rejected.
        assert!(!is_safe_allowlist_token("lo*gs"));
        assert!(!is_safe_allowlist_token("*"));
        assert!(!is_safe_allowlist_token("*-logs"));
        // The resolved-index validator never accepts a wildcard.
        assert!(!is_safe_index_token("logs-*"));
    }

    #[test]
    fn allowlist_membership_with_prefix_and_exact() {
        let al = vec!["logs-*".to_string(), "metrics".to_string()];
        assert!(allowlist_covers(&al, "logs-app"));
        assert!(allowlist_covers(&al, "logs-"));
        assert!(allowlist_covers(&al, "metrics"));
        assert!(!allowlist_covers(&al, "secrets"));
        assert!(!allowlist_covers(&al, "metrics-2"));
    }

    #[test]
    fn resolve_index_uses_arg_then_default() {
        let mut v = minimal_search();
        v["default_index"] = json!("logs");
        let s = ElasticsearchBackendSpec::parse(&v).unwrap();
        assert_eq!(s.resolve_index(Some("logs")).unwrap(), "logs");
        assert_eq!(s.resolve_index(None).unwrap(), "logs");
    }

    #[test]
    fn resolve_index_rejects_off_allowlist() {
        let s = ElasticsearchBackendSpec::parse(&minimal_search()).unwrap();
        assert!(s.resolve_index(Some("secrets")).is_err());
    }

    #[test]
    fn resolve_index_rejects_injection_even_when_allow_any() {
        let mut v = minimal_search();
        v["index_allowlist"] = json!([]);
        v["allow_any_index"] = json!(true);
        let s = ElasticsearchBackendSpec::parse(&v).unwrap();
        // allow_any bypasses membership but NOT the token validator.
        assert!(s.resolve_index(Some("../etc")).is_err());
        assert!(s.resolve_index(Some("anything")).is_ok());
    }

    #[test]
    fn resolve_index_prefix_wildcard_accepts_member() {
        let mut v = minimal_search();
        v["index_allowlist"] = json!(["logs-*"]);
        let s = ElasticsearchBackendSpec::parse(&v).unwrap();
        assert_eq!(s.resolve_index(Some("logs-app")).unwrap(), "logs-app");
        assert!(s.resolve_index(Some("metrics")).is_err());
    }

    #[test]
    fn resolve_index_missing_arg_and_default_is_error() {
        let mut v = minimal_search();
        v["allow_any_index"] = json!(true);
        v["index_allowlist"] = json!([]);
        let s = ElasticsearchBackendSpec::parse(&v).unwrap();
        assert!(s.resolve_index(None).is_err());
    }

    #[test]
    fn fail_closed_empty_allowlist_no_default_no_any() {
        let mut v = minimal_search();
        v["index_allowlist"] = json!([]);
        assert_eq!(
            ElasticsearchBackendSpec::parse(&v).unwrap_err(),
            SpecError::NoReachableIndex
        );
    }

    #[test]
    fn default_index_must_be_in_allowlist() {
        let mut v = minimal_search();
        v["default_index"] = json!("other");
        assert!(matches!(
            ElasticsearchBackendSpec::parse(&v).unwrap_err(),
            SpecError::DefaultIndexNotAllowed(_)
        ));
    }

    #[test]
    fn tls_insecure_skip_verify_rejected_on_nonloopback() {
        let mut v = minimal_search();
        v["tls"] = json!({ "insecure_skip_verify": true });
        assert_eq!(
            ElasticsearchBackendSpec::parse(&v).unwrap_err(),
            SpecError::InsecureSkipVerifyNonLoopback
        );
    }

    #[test]
    fn tls_insecure_skip_verify_ok_on_loopback() {
        let v = json!({
            "urls": ["http://localhost:9200"],
            "operation": "search",
            "index_allowlist": ["logs"],
            "tls": { "insecure_skip_verify": true }
        });
        assert!(ElasticsearchBackendSpec::parse(&v).is_ok());
    }

    #[test]
    fn tls_ca_and_insecure_contradiction() {
        let v = json!({
            "urls": ["http://localhost:9200"],
            "operation": "search",
            "index_allowlist": ["logs"],
            "tls": { "insecure_skip_verify": true, "ca_cert_pem": "-----BEGIN CERTIFICATE-----" }
        });
        assert_eq!(
            ElasticsearchBackendSpec::parse(&v).unwrap_err(),
            SpecError::TlsContradiction
        );
    }

    #[test]
    fn write_op_requires_allow_writes() {
        let mut v = minimal_search();
        v["operation"] = json!("delete");
        assert_eq!(
            ElasticsearchBackendSpec::parse(&v).unwrap_err(),
            SpecError::WritesNotAllowed("delete")
        );
        v["allow_writes"] = json!(true);
        assert!(ElasticsearchBackendSpec::parse(&v).is_ok());
    }

    #[test]
    fn empty_auth_secret_rejected() {
        let mut v = minimal_search();
        v["auth"] = json!({ "kind": "api_key", "api_key": "  " });
        assert_eq!(
            ElasticsearchBackendSpec::parse(&v).unwrap_err(),
            SpecError::EmptyAuthSecret
        );
    }

    #[test]
    fn debug_redacts_auth_secret() {
        let mut v = minimal_search();
        v["auth"] = json!({ "kind": "basic", "username": "elastic", "password": "s3cr3t" });
        let s = ElasticsearchBackendSpec::parse(&v).unwrap();
        let dbg = format!("{s:?}");
        assert!(!dbg.contains("s3cr3t"), "debug leaked secret: {dbg}");
        assert!(dbg.contains("elastic"), "username should be visible: {dbg}");
        assert!(dbg.contains("***"));
    }

    fn minimal_knn(knn: serde_json::Value) -> serde_json::Value {
        json!({
            "urls": ["https://es.example.com:9200"],
            "operation": "knn",
            "index_allowlist": ["docs"],
            "default_index": "docs",
            "knn": knn,
        })
    }

    #[test]
    fn parses_knn_op_and_config() {
        let v = minimal_knn(json!({ "field": "embedding", "k": 10, "num_candidates": 200 }));
        let s = ElasticsearchBackendSpec::parse(&v).unwrap();
        assert_eq!(s.operation, EsOperation::Knn);
        assert!(!s.operation.is_write());
        assert!(s.operation.needs_index());
        let knn = s.knn.expect("knn config");
        assert_eq!(knn.field, "embedding");
        assert_eq!(knn.k, 10);
        assert_eq!(knn.num_candidates, Some(200));
    }

    #[test]
    fn knn_op_requires_knn_config() {
        let v = json!({
            "urls": ["https://es:9200"],
            "operation": "knn",
            "index_allowlist": ["docs"],
            "default_index": "docs",
        });
        assert_eq!(
            ElasticsearchBackendSpec::parse(&v).unwrap_err(),
            SpecError::KnnConfigMissing
        );
    }

    #[test]
    fn knn_config_only_valid_for_knn_op() {
        let mut v = minimal_search();
        v["knn"] = json!({ "field": "embedding", "k": 5 });
        assert_eq!(
            ElasticsearchBackendSpec::parse(&v).unwrap_err(),
            SpecError::KnnConfigUnused
        );
    }

    #[test]
    fn knn_rejects_empty_field() {
        let v = minimal_knn(json!({ "field": "", "k": 5 }));
        assert_eq!(
            ElasticsearchBackendSpec::parse(&v).unwrap_err(),
            SpecError::InvalidKnnField
        );
    }

    #[test]
    fn knn_rejects_unsafe_field() {
        let v = minimal_knn(json!({ "field": "emb\"}};drop", "k": 5 }));
        assert_eq!(
            ElasticsearchBackendSpec::parse(&v).unwrap_err(),
            SpecError::InvalidKnnField
        );
    }

    #[test]
    fn knn_rejects_zero_k() {
        let v = minimal_knn(json!({ "field": "embedding", "k": 0 }));
        assert_eq!(
            ElasticsearchBackendSpec::parse(&v).unwrap_err(),
            SpecError::InvalidKnnK
        );
    }

    #[test]
    fn knn_rejects_empty_literal_vector() {
        let v = minimal_knn(json!({ "field": "embedding", "k": 5, "query_vector": [] }));
        assert_eq!(
            ElasticsearchBackendSpec::parse(&v).unwrap_err(),
            SpecError::InvalidKnnLiteralVector
        );
    }

    #[test]
    fn knn_accepts_literal_vector() {
        let v = minimal_knn(json!({ "field": "embedding", "k": 5, "query_vector": [0.1, 0.2] }));
        let s = ElasticsearchBackendSpec::parse(&v).unwrap();
        assert_eq!(s.knn.unwrap().query_vector, Some(vec![0.1, 0.2]));
    }

    #[test]
    fn knn_config_denies_unknown_field() {
        let v = minimal_knn(json!({ "field": "embedding", "k": 5, "typo": true }));
        assert!(matches!(
            ElasticsearchBackendSpec::parse(&v).unwrap_err(),
            SpecError::Json(_)
        ));
    }

    #[test]
    fn msearch_exempt_from_default_index_requirement() {
        let v = json!({
            "urls": ["https://es:9200"],
            "operation": "msearch",
            "index_allowlist": ["logs-*"]
        });
        assert!(ElasticsearchBackendSpec::parse(&v).is_ok());
    }
}
