//! ZCode request body transformation
//!
//! Applies ZCode-specific body mutations before forwarding to upstream.
//! - Anthropic format: adds `cache_control: { type: "ephemeral" }` to the last
//!   non-system message block (mirrors ZCode's `HLr` algorithm).
//! - OpenAI format: `stream_options.include_usage` is already handled by the
//!   existing `inject_openai_stream_include_usage` in transform.rs.
//!
//! All transformations are no-ops on malformed input — the original body is
//! returned unchanged.

use crate::proxy::error::ProxyError;
use serde_json::Value;

/// Apply ZCode-specific transformations to the Anthropic-format request body
/// BEFORE it gets converted to OpenAI Chat format.
///
/// Currently this adds `cache_control: { type: "ephemeral" }` to the last
/// content block of the last non-system message.
///
/// Returns the modified body, or the original on failure/unchanged.
pub fn apply_zcode_anthropic_transforms(body: Value) -> Result<Value, ProxyError> {
    let mut body = body;
    apply_anthropic_cache_control(&mut body);
    Ok(body)
}

/// Anthropic: add `cache_control: { type: "ephemeral" }` to the last content
/// block of the last non-system message. Mirrors ZCode's `HLr` algorithm.
///
/// ZCode clients set `applyCacheControl: true` by default. Anthropic's API
/// silently ignores `cache_control` below the per-model token floor, so
/// unconditional add is safe.
///
/// Idempotent — skips if any block on that message already carries cache_control.
fn apply_anthropic_cache_control(body: &mut Value) -> bool {
    let messages = match body.get_mut("messages").and_then(|m| m.as_array_mut()) {
        Some(messages) if !messages.is_empty() => messages,
        _ => return false,
    };

    for i in (0..messages.len()).rev() {
        let msg = &messages[i];
        if msg.get("role").and_then(|r| r.as_str()) == Some("system") {
            continue;
        }

        let msg = &mut messages[i];
        match msg.get("content") {
            // String content → convert to content block array with cache_control
            Some(c) if c.is_string() => {
                let text = c.as_str().unwrap_or("").to_string();
                msg["content"] = serde_json::json!([{
                    "type": "text",
                    "text": text,
                    "cache_control": { "type": "ephemeral" }
                }]);
                return true;
            }
            // Array content → add cache_control to the last block
            Some(c) if c.is_array() => {
                let arr = msg["content"].as_array_mut().unwrap();
                if arr.is_empty() {
                    return false;
                }
                let last_idx = arr.len() - 1;
                let last = &mut arr[last_idx];
                if last.get("cache_control").is_none() {
                    last["cache_control"] = serde_json::json!({ "type": "ephemeral" });
                    return true;
                }
                return false;
            }
            _ => {}
        }
        return false;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_apply_anthropic_cache_control_on_last_message() {
        let mut body = json!({
            "model": "glm-4.6",
            "messages": [
                {"role": "user", "content": "hello"},
                {"role": "assistant", "content": "hi there"}
            ],
            "max_tokens": 1024
        });

        let changed = apply_anthropic_cache_control(&mut body);
        assert!(changed);

        let last_content = &body["messages"][1]["content"];
        assert!(last_content.is_array());
        let arr = last_content.as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["type"], "text");
        assert_eq!(arr[0]["text"], "hi there");
        assert_eq!(arr[0]["cache_control"]["type"], "ephemeral");
    }

    #[test]
    fn test_skip_system_messages() {
        let mut body = json!({
            "model": "glm-4.6",
            "messages": [
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": "hello"}
            ],
            "max_tokens": 1024
        });

        let changed = apply_anthropic_cache_control(&mut body);
        assert!(changed);

        // Should apply to the user message (index 1), not the system message
        let last_content = &body["messages"][1]["content"];
        assert!(last_content.is_array());
    }

    #[test]
    fn test_idempotent() {
        let mut body = json!({
            "model": "glm-4.6",
            "messages": [
                {"role": "user", "content": [{"type": "text", "text": "hello", "cache_control": {"type": "ephemeral"}}]}
            ],
            "max_tokens": 1024
        });

        let changed = apply_anthropic_cache_control(&mut body);
        assert!(!changed, "should be idempotent when cache_control already present");
    }

    #[test]
    fn test_apply_zcode_anthropic_transforms_passthrough() {
        let body = json!({"model": "glm-4.6", "messages": [{"role": "user", "content": "test"}], "max_tokens": 100});
        let result = apply_zcode_anthropic_transforms(body).unwrap();
        // Should have cache_control applied
        let last_content = &result["messages"][0]["content"];
        assert!(last_content.is_array());
    }
}
