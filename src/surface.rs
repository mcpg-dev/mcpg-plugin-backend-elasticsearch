//! MCP surface shaping for resource / prompt bindings.
//!
//! A binding is a tool by default; the operator may instead place it under
//! `mcp.capabilities.resources[]` / `resource_templates[]` / `prompts[]`. The
//! gateway routes those reads to the same `execute()` path but applies a strict
//! decoder over the response body — `{contents:[…]}` for `resources/read` and
//! `{messages:[…]}` for `prompts/get`. The tool surface keeps the raw op result.
//!
//! Elasticsearch's primary result body is the upstream JSON response (search
//! hits / a document / a write ack), so the surface helpers wrap that whole
//! value into one content entry. Only successful (2xx) responses are reshaped;
//! non-2xx responses keep the tool envelope (carrying `downstreamError`) on
//! every surface. On the resource surface the requested URI arrives in the call
//! arguments as a top-level `uri` field (the gateway materializes it from the
//! resource read request); an operator may also pin a static `uri` on the
//! binding. The prompt surface carries no URI.

use mcpg_plugin_protocol::{ListedResource, ResourcePage};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::dispatch::source_string;

/// Map `_search` hits into a [`ResourcePage`].
///
/// Each hit's `uri_field` (`_source` dot-path) is the resource URI (required);
/// optional `name_field` / `description_field` fill the display fields. Hits
/// without a string URI value are skipped. `next_cursor` is the offset for the
/// next page, present only when the page was full.
pub fn hits_to_resource_page(
    hits: &[Value],
    uri_field: &str,
    name_field: Option<&str>,
    description_field: Option<&str>,
    from: u64,
    page_size: u64,
) -> ResourcePage {
    let full_page = hits.len() as u64 >= page_size;
    let mut resources: Vec<ListedResource> = Vec::with_capacity(hits.len());
    for hit in hits {
        let Some(uri) = source_string(hit, uri_field) else {
            continue;
        };
        resources.push(ListedResource {
            uri,
            name: name_field.and_then(|f| source_string(hit, f)),
            description: description_field.and_then(|f| source_string(hit, f)),
            mime_type: None,
        });
    }
    let next_cursor = if full_page {
        Some((from + hits.len() as u64).to_string())
    } else {
        None
    };
    ResourcePage {
        resources,
        next_cursor,
    }
}

/// Extract completion candidates from `_search` hits: each hit's `field`
/// `_source` string value, capped at `max`.
pub fn hits_to_completion_values(hits: &[Value], field: &str, max: usize) -> Vec<String> {
    hits.iter()
        .take(max)
        .filter_map(|hit| source_string(hit, field))
        .collect()
}

/// Which MCP surface a binding serves. `Tool` (default) keeps the historical
/// tool result body byte-for-byte; `Resource` / `Prompt` reshape the successful
/// op result into the surface-correct body the gateway decoder requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Surface {
    /// Tool surface — unchanged op result body.
    #[default]
    Tool,
    /// `resources/read` surface — `{contents:[{uri,text,mimeType}]}`.
    Resource,
    /// `prompts/get` surface — `{messages:[{role,content}]}`.
    Prompt,
}

impl Surface {
    /// Stable label for diagnostics.
    #[allow(dead_code)]
    pub fn as_str(self) -> &'static str {
        match self {
            Surface::Tool => "tool",
            Surface::Resource => "resource",
            Surface::Prompt => "prompt",
        }
    }
}

/// Whether a serialized response body should carry the transport
/// `truncated` flag. Only the tool surface may propagate upstream
/// truncation: its body is opaque text the gateway is free to suffix with
/// `[response truncated]`. The resource / prompt bodies are complete JSON
/// documents the gateway decodes strictly, so a truncation suffix would
/// corrupt the decode — they are never marked truncated.
pub fn surface_truncated(surface: Surface, upstream_truncated: bool) -> bool {
    surface == Surface::Tool && upstream_truncated
}

/// Resolve the resource URI for a `resources/read`: a static binding `uri`
/// wins, otherwise the gateway-supplied `uri` argument. Returns `None` when
/// neither is available so the caller can surface a clean error envelope
/// instead of emitting a decoder-invalid `{contents}` body.
pub fn resolve_resource_uri<'a>(
    static_uri: Option<&'a str>,
    arguments: &'a Value,
) -> Option<&'a str> {
    if let Some(u) = static_uri
        && !u.trim().is_empty()
    {
        return Some(u);
    }
    arguments
        .get("uri")
        .and_then(Value::as_str)
        .filter(|u| !u.trim().is_empty())
}

/// Wrap the op result body into the `resources/read` contract body —
/// `{contents:[{uri, text, mimeType:"application/json"}]}` — a single content
/// entry whose `text` is the JSON-serialized op result.
pub fn resource_contents_body(uri: &str, body: &Value) -> Value {
    let text = serde_json::to_string(body).unwrap_or_else(|_| "null".to_owned());
    json!({
        "contents": [
            {
                "uri": uri,
                "text": text,
                "mimeType": "application/json",
            }
        ]
    })
}

/// Wrap the op result body into the `prompts/get` contract body —
/// `{messages:[{role:"user", content:{type:"text", text:<body-as-json>}}]}`.
pub fn prompt_messages_body(body: &Value) -> Value {
    let text = serde_json::to_string(body).unwrap_or_else(|_| "null".to_owned());
    json!({
        "messages": [
            {
                "role": "user",
                "content": { "type": "text", "text": text }
            }
        ]
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn surface_default_is_tool() {
        assert_eq!(Surface::default(), Surface::Tool);
    }

    #[test]
    fn surface_parses_snake_case() {
        let s: Surface = serde_json::from_value(json!("resource")).unwrap();
        assert_eq!(s, Surface::Resource);
        let s: Surface = serde_json::from_value(json!("prompt")).unwrap();
        assert_eq!(s, Surface::Prompt);
    }

    #[test]
    fn static_uri_wins_over_argument() {
        let args = json!({ "uri": "es://from-arg" });
        assert_eq!(
            resolve_resource_uri(Some("es://static"), &args),
            Some("es://static")
        );
    }

    #[test]
    fn falls_back_to_argument_uri() {
        let args = json!({ "uri": "es://orders/42" });
        assert_eq!(resolve_resource_uri(None, &args), Some("es://orders/42"));
    }

    #[test]
    fn no_uri_available_returns_none() {
        assert_eq!(resolve_resource_uri(None, &json!({})), None);
        assert_eq!(resolve_resource_uri(Some("  "), &json!({})), None);
    }

    #[test]
    fn resource_body_satisfies_decoder_shape() {
        let result = json!({ "item": { "order_id": { "S": "42" } } });
        let body = resource_contents_body("es://orders/42", &result);
        let contents = body["contents"].as_array().expect("contents array");
        assert_eq!(contents.len(), 1);
        assert_eq!(contents[0]["uri"], json!("es://orders/42"));
        assert!(contents[0]["text"].is_string());
        assert!(contents[0].get("blob").is_none());
        assert_eq!(contents[0]["mimeType"], json!("application/json"));
        let decoded: Value = serde_json::from_str(contents[0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(decoded, result);
    }

    #[test]
    fn prompt_body_satisfies_decoder_shape() {
        let result = json!({ "items": [] });
        let body = prompt_messages_body(&result);
        let messages = body["messages"].as_array().expect("messages array");
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0]["role"], json!("user"));
        assert_eq!(messages[0]["content"]["type"], json!("text"));
        assert!(messages[0]["content"]["text"].is_string());
    }

    #[test]
    fn hits_map_to_resource_page_with_cursor() {
        let hits: Vec<Value> = (0..3)
            .map(|i| json!({ "_source": { "uri": format!("es://item/{i}"), "title": format!("T{i}") } }))
            .collect();
        // Full page (3 hits, page_size 3) → next cursor = from + 3.
        let page = hits_to_resource_page(&hits, "uri", Some("title"), None, 6, 3);
        assert_eq!(page.resources.len(), 3);
        assert_eq!(page.resources[0].uri, "es://item/0");
        assert_eq!(page.resources[0].name.as_deref(), Some("T0"));
        assert_eq!(page.next_cursor.as_deref(), Some("9"));

        // Short page → exhausted.
        let short = hits_to_resource_page(&hits, "uri", None, None, 0, 10);
        assert!(short.next_cursor.is_none());
    }

    #[test]
    fn hits_without_uri_field_are_skipped() {
        let hits = vec![
            json!({ "_source": { "other": "x" } }),
            json!({ "_source": { "uri": "es://ok" } }),
        ];
        let page = hits_to_resource_page(&hits, "uri", None, None, 0, 10);
        assert_eq!(page.resources.len(), 1);
        assert_eq!(page.resources[0].uri, "es://ok");
    }

    #[test]
    fn hits_map_to_completion_values() {
        let hits = vec![
            json!({ "_source": { "name": "alpha" } }),
            json!({ "_source": { "name": "alphabet" } }),
            json!({ "_source": { "name": 99 } }),
        ];
        let got = hits_to_completion_values(&hits, "name", 10);
        assert_eq!(got, vec!["alpha".to_owned(), "alphabet".to_owned()]);
        assert_eq!(
            hits_to_completion_values(&hits, "name", 1),
            vec!["alpha".to_owned()]
        );
    }

    #[test]
    fn resource_and_prompt_surfaces_never_truncate() {
        // Even when the upstream response was truncated, the resource/prompt
        // surfaces must NOT propagate the flag — the gateway decodes those
        // bodies strictly and a `[response truncated]` suffix would corrupt
        // them.
        assert!(!surface_truncated(Surface::Resource, true));
        assert!(!surface_truncated(Surface::Prompt, true));
        // The tool surface still propagates upstream truncation.
        assert!(surface_truncated(Surface::Tool, true));
        assert!(!surface_truncated(Surface::Tool, false));
    }
}
