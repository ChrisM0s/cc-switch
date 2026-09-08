//! CodeBuddy 请求转换模块
//!
//! CodeBuddy（腾讯云 AI 编程助手）的 `/v2/chat/completions` 接口在协议层面
//! 与 OpenAI Chat Completions 兼容，因此响应侧直接复用现有的
//! `streaming::create_anthropic_sse_stream`（流式）与 `transform::openai_to_anthropic`
//! （非流式，仅作保险，CodeBuddy 实际只返回流式）。
//!
//! 本模块只负责请求侧的 CodeBuddy 特有规则：
//! - 消息数组长度必须 ≥2（CodeBuddy 后端硬性限制），单条 user 消息需自动补一条 system
//! - 强制注入 `stream: true`（CodeBuddy 不支持非流式）
//!
//! 工具调用的角色与 ID 格式经 `transform::anthropic_to_openai_with_reasoning_content`
//! 转换后已是 OpenAI Chat 形态（`role: tool` + `tool_call_id`），CodeBuddy 接受这种
//! 形态，无需额外的 `toolu_`/`call_` 前缀转换。

use crate::proxy::error::ProxyError;
use serde_json::{json, Value};

use super::transform::anthropic_to_openai_with_reasoning_content;

/// Anthropic 请求 → CodeBuddy Chat Completions 请求
///
/// 在调用此函数之前，Anthropic Messages API 本身要求 messages 非空，
/// 因此正常路径不会出现空数组。作为防御性边界：若 messages 为空，返回错误。
pub fn anthropic_to_codebuddy(body: Value) -> Result<Value, ProxyError> {
    let mut result = anthropic_to_openai_with_reasoning_content(body, false)?;

    // 防御性校验：messages 不能为空
    let msg_count = result
        .get("messages")
        .and_then(|m| m.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    if msg_count == 0 {
        return Err(ProxyError::ConfigError(
            "CodeBuddy 请求需要至少一条消息".to_string(),
        ));
    }

    ensure_min_two_messages(&mut result);
    result["stream"] = json!(true);

    // 脱敏：对客户端注入的合规模板（system prompt 品牌词、运行时上下文、
    // 工具描述中的安全术语）做零宽脱敏与 harness 压缩，缓解 CodeBuddy
    // 后端内容审核误伤（移植自 codebuddy2api desensitize 模块，默认开启）
    super::codebuddy_desensitize::apply_desensitize(&mut result);

    Ok(result)
}

/// CodeBuddy 后端要求 messages 数组长度至少为 2。
/// 单条消息时在前面插入一条占位 system 消息。
fn ensure_min_two_messages(result: &mut Value) {
    let len = result
        .get("messages")
        .and_then(|m| m.as_array())
        .map(|a| a.len())
        .unwrap_or(0);

    if len >= 2 {
        return;
    }

    // Exactly 1 message: prepend a system placeholder
    if len == 1 {
        if let Some(messages) = result
            .get_mut("messages")
            .and_then(|m| m.as_array_mut())
        {
            messages.insert(0, json!({"role": "system", "content": "You are a helpful assistant."}));
        }
    }
    // len == 0 is already rejected by the caller (anthropic_to_codebuddy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn pads_single_message_with_system() {
        let body = json!({
            "model": "auto-chat",
            "messages": [
                {"role": "user", "content": "hello"}
            ]
        });

        let result = anthropic_to_codebuddy(body).expect("should convert");
        let messages = result["messages"].as_array().expect("messages array");
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0]["role"], "system");
        assert_eq!(messages[1]["role"], "user");
    }

    #[test]
    fn leaves_multi_message_untouched_count() {
        let body = json!({
            "model": "auto-chat",
            "system": "You are CodeBuddy.",
            "messages": [
                {"role": "user", "content": "hello"}
            ]
        });

        // system 字段会被转换为一条 system message，因此加上 user 消息共 2 条，
        // 不需要额外补全。
        let result = anthropic_to_codebuddy(body).expect("should convert");
        let messages = result["messages"].as_array().expect("messages array");
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0]["role"], "system");
        assert_eq!(messages[0]["content"], "You are CodeBuddy.");
    }

    #[test]
    fn forces_stream_true() {
        let body = json!({
            "model": "auto-chat",
            "messages": [
                {"role": "user", "content": "hello"}
            ],
            "stream": false
        });

        let result = anthropic_to_codebuddy(body).expect("should convert");
        assert_eq!(result["stream"], true);
    }

    #[test]
    fn empty_messages_returns_error() {
        let body = json!({
            "model": "auto-chat",
            "messages": []
        });

        let result = anthropic_to_codebuddy(body);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        // ConfigError wraps the message in a specific format
        assert!(
            err.contains("至少需要一条消息") || err.contains("message") || err.contains("CodeBuddy"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn pads_single_message_with_system_after_rejecting_empty() {
        // 单条消息应该正常补全为两条
        let body = json!({
            "model": "auto-chat",
            "messages": [
                {"role": "user", "content": "hello"}
            ]
        });

        let result = anthropic_to_codebuddy(body).expect("should convert");
        let messages = result["messages"].as_array().expect("messages array");
        assert_eq!(messages.len(), 2);
    }
}
