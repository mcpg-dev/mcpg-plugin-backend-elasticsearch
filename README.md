# Elasticsearch Binding (`dev.mcpg.backend.elasticsearch`)

A **backend (binding)** plugin that exposes Elasticsearch / OpenSearch REST
operations as MCP tools. Each binding declares **one operation** against an
operator-configured base URL + index allowlist, and that binding becomes one
tool (the `http`/`sql` envelope model). Dispatches over the ES REST API via
`reqwest` (rustls-tls).

## v1 operations

`search`, `count`, `get`, `index`, `delete`, `bulk`, `msearch`, `knn`. (An
`expand_capabilities` index-per-tool catalog is a deferred follow-up.)

| Operation | Required args | Optional args | REST call | Result envelope |
|---|---|---|---|---|
| `search` | — | `index`, `query`, `size`, `from`, `sort`, `source`, `aggs` | `POST /{index}/_search` | `{ operation, statusCode, ok, response: <ES hits>, ... }` |
| `count` | — | `index`, `query` | `POST /{index}/_count` | `{ response: { count, _shards }, ... }` |
| `get` | `id` | `index`, `source` | `GET /{index}/_doc/{id}` | `{ response: { _id, found, _source }, ... }` |
| `index` (write) | `document` | `index`, `id`, `refresh`, `op_type` | `PUT /{index}/_doc/{id}` or `POST /{index}/_doc` | `{ response: { _id, result }, ... }` |
| `delete` (write) | `id` | `index`, `refresh` | `DELETE /{index}/_doc/{id}` | `{ response: { _id, result }, ... }` |
| `bulk` (write) | `operations` | `index`, `refresh` | `POST /{index}/_bulk` (NDJSON) | `{ response: { took, errors, items }, ... }` |
| `msearch` | `searches` | — | `POST /_msearch` (NDJSON) | `{ response: { took, responses }, ... }` |
| `knn` | `query_vector` † | `index`, `source` | `POST /{index}/_search` (top-level `knn` clause) | `{ response: <ES hits>, ... }` |

† `query_vector` is required unless the binding configures a literal
`knn.query_vector` fallback.

- `size` / `from` are **clamped** to `max_size` / `max_from`.
- Write ops (`index` / `delete` / `bulk`) require `allow_writes: true`.
- `bulk` / `msearch` send `Content-Type: application/x-ndjson`; each
  `msearch` per-search index is allowlist-validated before NDJSON assembly.
- The index travels as an **allowlisted, path-injection-guarded** `index`
  argument (or the binding `default_index`).

## Binding config (`backend: { kind: elasticsearch, ... }`)

| Field | Type | Default | Description |
|---|---|---|---|
| `urls` | string[] | *(required)* | Base URL(s); first is primary, rest are transport-failover. `https://` (or `http://localhost`). |
| `operation` | enum | *(required)* | `search` \| `count` \| `get` \| `index` \| `delete` \| `bulk` \| `msearch`. |
| `default_index` | string | *(none)* | Index used when the `index` arg is absent; must be covered by the allowlist. |
| `index_allowlist` | string[] | `[]` | Allowed indices. Empty = fail-closed (no index reachable) unless `allow_any_index`. A single trailing `*` (e.g. `logs-*`) is a prefix wildcard. |
| `allow_any_index` | bool | `false` | Bypass the allowlist (still token-validated). Logged at warn on register. |
| `allow_writes` | bool | `false` | Required `true` for write operations. |
| `allow_scripting` | bool | `false` | Allow `script` / `script_score` / `runtime_mappings` in a query body. |
| `auth` | object | `{ kind: none }` | `{ kind: api_key, api_key }` \| `{ kind: basic, username, password }` \| `{ kind: bearer, token }` \| `{ kind: none }`. |
| `tls` | object | — | `{ ca_cert_pem?, insecure_skip_verify? }`. `insecure_skip_verify` is honored only when **all** URLs are loopback. |
| `connect_timeout_ms` | int | `5000` | |
| `operation_timeout_ms` | int | `30000` | |
| `max_response_bytes` | int | 4 MiB | Response body cap; over-cap bodies are truncated. |
| `max_request_bytes` | int | 4 MiB | Request body cap. |
| `max_size` | int | `1000` | `size` ceiling. |
| `max_from` | int | `10000` | `from` ceiling. |
| `allow_private_backends` | bool | `false` | Allow private/loopback resolved addresses (test / in-cluster ES). |

### Secret references

Auth secrets are never config literals — they ride config-origin secret
references:

- `${env.X}` — resolved at config load (bare `${env.…}` dot form).
- `cred://<plugin-id>/<target>` — resolved per caller. In an interpolated
  header position, use the wrapped `${cred://<plugin-id>/<target>}` token.

The resolved secret is never logged and is **never reflected** into the
response envelope (the `Authorization` header is excluded).

## Example

```yaml
# 1. Load the backend plugin artifact (top-level `plugins:` is a flat list).
plugins:
  - id: dev.mcpg.backend.elasticsearch
    class: backend
    source: { oci: "oci://ghcr.io/mcpg-dev/plugins/backend-elasticsearch:protocol-1" }

# 2. Declare each binding as a tool under `mcp.capabilities.tools[]`.
#    Each entry's `backend.kind: elasticsearch` routes to the plugin above.
mcp:
  capabilities:
    tools:
      - name: logs.search
        description: Full-text search over the application logs.
        backend:
          kind: elasticsearch
          urls: ["https://es.internal:9200"]
          operation: search
          index_allowlist: ["logs-*"]
          default_index: logs-app
          auth:
            kind: api_key
            api_key: "${env.ES_API_KEY}"
      - name: logs.index
        description: Index a structured log document.
        backend:
          kind: elasticsearch
          urls: ["https://es.internal:9200"]
          operation: index
          index_allowlist: ["logs-app"]
          default_index: logs-app
          allow_writes: true
          auth:
            kind: basic
            username: ingest
            password: "${cred://es-creds/ingest}"
```

## Vector kNN search (RAG / semantic search)

The `knn` operation issues a `_search` carrying the modern top-level `knn`
clause against a `dense_vector` field — the building block for
retrieval-augmented generation. The operator fixes the field, neighbour count,
candidate pool, and an optional pre-filter on the binding; the caller supplies
the query embedding as the `query_vector` argument (an array of numbers), which
typically comes from an embeddings step earlier in the same turn / pipeline. A
binding may also pin a literal `knn.query_vector` used when no argument is
given.

```jsonc
// Issued body for operation: knn
POST /{index}/_search
{
  "knn": {
    "field": "embedding",
    "query_vector": [0.12, -0.04, ...],
    "k": 5,
    "num_candidates": 100,
    "filter": { "term": { "tenant": "acme" } }   // optional, operator-fixed
  }
}
```

### `knn` config block (`backend.knn`)

| Field | Type | Default | Description |
|---|---|---|---|
| `field` | string | *(required)* | The `dense_vector` field to search. Safe field token (`[A-Za-z0-9_.]`). |
| `k` | int | *(required)* | Number of nearest neighbours to return (must be `> 0`). |
| `num_candidates` | int | *(ES default)* | Per-shard candidate pool; clamped up to `k` if smaller. |
| `filter` | object | *(none)* | Operator-fixed query ANDed with the kNN search (subject to the scripting guard). Caller input never reaches it. |
| `query_vector` | number[] | *(none)* | Literal fallback embedding used only when the call omits `query_vector`. |

- The `query_vector` argument must be a **non-empty array of finite numbers**;
  a non-array / empty / non-finite element is a tool-level error.
- The `index` resolves the same way as the other ops (the `index` argument or
  `default_index`, allowlist-checked, path-injection-guarded).

```yaml
# RAG: kNN over a dense_vector field, fed an embedding produced upstream.
mcp:
  capabilities:
    tools:
      # 1. Produce the query embedding (any embeddings backend).
      - name: docs.embed
        description: Embed the user query into a dense vector.
        backend:
          kind: openai_embeddings   # illustrative — any embeddings binding
          # ...

      # 2. kNN-retrieve the nearest documents for that embedding.
      - name: docs.semantic_search
        description: Semantic (vector) search over the knowledge base.
        backend:
          kind: elasticsearch
          urls: ["https://es.internal:9200"]
          operation: knn
          index_allowlist: ["kb-*"]
          default_index: kb-docs
          auth: { kind: api_key, api_key: "${env.ES_API_KEY}" }
          knn:
            field: embedding          # the dense_vector field
            k: 5
            num_candidates: 100
            filter: { term: { published: true } }
        # caller passes: { "query_vector": <array of floats from docs.embed> }
```

In a `kind: pipeline` binding the embedding step feeds the kNN step directly:

```yaml
      backend:
        kind: pipeline
        steps:
          - id: embed
            kind: openai_embeddings
            input_transform: "{ 'input': arguments.query }"
          - id: retrieve
            kind: elasticsearch
            operation: knn
            urls: ["https://es.internal:9200"]
            index_allowlist: ["kb-*"]
            default_index: kb-docs
            auth: { kind: api_key, api_key: "${env.ES_API_KEY}" }
            knn: { field: embedding, k: 5, num_candidates: 100 }
            input_transform: "{ 'query_vector': steps.embed.response.data[0].embedding }"
```

## MCP surfaces & composition

The same binding works on every MCP surface. The surface is selected by the
capability list the binding sits under plus a `surface:` knob; composition is via
`pipeline` steps and child tools.

### As a pipeline step

Inside a `kind: pipeline` binding, an Elasticsearch step uses the
`elasticsearch` step discriminator. The backend config fields are flattened next
to `id` / `kind`; `input_transform` shapes the step's arguments from prior steps.

```yaml
      backend:
        kind: pipeline
        pipeline_timeout_ms: 30000
        steps:
          - id: search
            kind: elasticsearch
            urls: ["https://es.internal:9200"]
            operation: search
            index_allowlist: ["logs-*"]
            default_index: logs-app
            auth: { kind: api_key, api_key: "${env.ES_API_KEY}" }
            input_transform: "${arguments}"
          - id: summarize
            kind: transform
            expression: "{ 'hits': steps.search.response }"
```

### As a resource

Place the binding under `mcp.capabilities.resources[]` with `surface: resource`.
Successful results are reshaped into the `resources/read` `{contents:[…]}` body.
Set a static `uri:` or let the binding use the requested URI from the read call.

```yaml
  capabilities:
    resources:
      - name: logs.recent
        uri: "es://logs/recent"
        backend:
          kind: elasticsearch
          urls: ["https://es.internal:9200"]
          operation: search
          index_allowlist: ["logs-app"]
          default_index: logs-app
          auth: { kind: api_key, api_key: "${env.ES_API_KEY}" }
          surface: resource
          uri: "es://logs/recent"
```

### As a prompt

Under `mcp.capabilities.prompts[]` with `surface: prompt`, results are reshaped
into the `prompts/get` `{messages:[…]}` body.

```yaml
  capabilities:
    prompts:
      - name: logs.context
        backend:
          kind: elasticsearch
          urls: ["https://es.internal:9200"]
          operation: search
          index_allowlist: ["logs-app"]
          default_index: logs-app
          auth: { kind: api_key, api_key: "${env.ES_API_KEY}" }
          surface: prompt
```

### As a child tool

An LLM / generator binding can list this binding in its child-tool set, letting
the model call it during a turn. Child dispatch is governed by
`governance.child_invoke.enforce_gates` (depth cap + self-call cycle refusal
apply). Use a read operation (`search` / `count` / `get`) as a child.

### Schemas & annotations

`output_schema` for the envelope wrapper is advertised in `tools/list`, and
`input_schema` is advertised too. Operators should mark read-operation bindings
explicitly so clients treat them as side-effect-free:

```yaml
        annotations: { read_only: true, open_world: false }
```

## Change-watching

A resource can subscribe to index changes through the plugin's second entity —
a **polling `watch_strategy`** (kind `elasticsearch_poll`). ES has no native
change-push channel for arbitrary indices, so the strategy runs a cheap, sorted,
size-1 `_search` (the index's newest document by a monotonic `cursor_field`) on
a cadence and emits `notifications/resources/updated` whenever that top sort
value advances. The first tick only records a baseline, so a watcher never fires
spuriously at startup.

Attach it under a resource's `watch:` block. The watch carries its own
connection (it is not tied to the binding's profile) plus the index + cursor
field:

```yaml
mcp.configurations[].resources[].watch:
  type: plugin
  kind: elasticsearch_poll
  urls: ["https://es.internal:9200"]
  auth: { kind: api_key, api_key: "${cred://es/key}" }
  index: "logs-app"
  cursor_field: "@timestamp"
  query: { term: { tenant: "acme" } }   # optional — defaults to match_all
  interval_ms: 30000
```

**Watch spec fields**

| Field | Type | Default | Description |
|---|---|---|---|
| `urls` | array | *(required)* | Base URL(s) — same shape as the binding (first primary, rest failover; `https://` or `http://localhost`). |
| `auth` | object | *(none)* | ApiKey / Basic / Bearer — same shape as the binding. |
| `tls` | object | *(verifying)* | CA bundle / loopback-gated insecure-skip-verify — same shape as the binding. |
| `index` | string | *(required)* | Index or alias to watch. |
| `cursor_field` | string | *(required)* | A monotonic field to sort on (e.g. `@timestamp`, `_seq_no`); its top descending value is the cursor. |
| `query` | object | `match_all` | Optional ES query DSL scoping the watch. |
| `allow_private_backends` | bool | `false` | Allow private/loopback resolved addresses (test / in-cluster ES). |
| `interval_ms` | int | `60000` | Poll cadence (floored at 250 ms). |
| `timeout_ms` | int | `10000` | Per-tick connect + wall-clock search budget. |

An empty `index` or `cursor_field` is rejected at watch start, as is a bad base
URL (the binding's HTTPS-or-localhost guard applies). A tick returning zero hits
(or a NULL cursor) is treated as "no change"; transient connect / search
failures are logged and retried on the next tick.

## Security

- **Index path-injection guard.** The index goes into the REST URL path
  (`POST /{index}/_search`), so every allowlist entry, `default_index`, and
  resolved per-call index is validated by `is_safe_index_token`: lowercase
  only, ≤255 bytes, no `/` `\` `%` `*` `:` `,` `#` `?` whitespace, no
  leading `-`/`_`/`+`, never `.`/`..`/`_all`. A resolved index must also be
  a member of the allowlist (trailing-`*` prefix match) unless
  `allow_any_index`. Document ids are percent-encoded into the path segment.
- **Fail-closed indexing.** An empty allowlist with no `default_index` and
  `allow_any_index: false` is a config error at register.
- **HTTPS-or-localhost base URL** + a **DNS-rebinding / SSRF guard**: the
  resolved host must not be private/loopback unless `allow_private_backends`.
- **Scripting guard.** `script` / `script_score` / `runtime_mappings` keys
  in a query body are refused by default (recursive scan); set
  `allow_scripting` to opt in.
- **Write gate.** `index` / `delete` / `bulk` require `allow_writes: true`.
- **Size/from clamp** to `max_size` / `max_from`; request + response body
  byte caps.
- **Secret handling.** Auth secrets resolve from config-origin `${env.X}` /
  `cred://` references; the resolved `Authorization` header is never logged
  and never reflected into the envelope. The spec struct has a redacting
  `Debug`.
- `network_outbound` capability.

## Testing

Unit tests (`cargo test -p mcpg-plugin-backend-elasticsearch --lib`, ~50)
cover config validation, the index path-injection guard + allowlist
matching, the TLS gates, the write gate, size clamping, the scripting guard,
NDJSON assembly for `bulk`/`msearch`, and the response-envelope shape — all
offline. An offline `wiremock` contract suite
(`cargo test -p mcpg-plugin-backend-elasticsearch --test wiremock_smoke`,
~11) asserts method/path/body/Content-Type, auth-header format + non-
reflection, 4xx/5xx mapping, and body truncation. A real-ES testcontainer
suite drives an index → search round-trip:

```bash
cargo test -p mcpg-plugin-backend-elasticsearch \
    --features integration-tests --test integration -- --test-threads 1
```

(needs Docker; runs in the `--config=integration` CI lane. The bundled
ES 7.16 image has security disabled, so it exercises the `auth: none` HTTP
path; the ES-8 https+auth contract is covered by the wiremock suite.)

## Notes

- rustls-only: `reqwest` uses `default-features = false, features = ["json",
  "rustls-tls"]`. The `openssl` / `native-tls` Rust wrappers are banned by
  `deny.toml`.
- Wired into the gateway via the closed `BackendImpl` enum (`kind:
  elasticsearch`) like the other envelope backends.
```
