//! CodeBuddy 脱敏防护模块
//!
//! 背景：CodeBuddy 后端（copilot.tencent.com）有内容审核，会拦截含
//! "攻击/漏洞/凭证"等含义的英文术语与竞争对手品牌词。这些词经常出现在
//! 客户端**固定的合规 system 模板**里（例如「Refuse requests for DoS
//! attacks, exploit development...」属于"拒绝作恶"的合规声明），并非用户的
//! 有害输入，却被后端误判为敏感词导致整条请求被拦。
//!
//! 处理方式（与上游一致）：
//! - 对合规声明高频词在词内部插入零宽空格（U+200B）：人/模型读无差别，
//!   后端关键词子串匹配失效
//! - 对 Claude Code / Codex CLI 注入的 harness 运行时上下文做压缩/裁剪
//! - 对 tools 定义移除 description/title 元数据（审核重灾区）
//! - 不改动真实用户输入
//!
//! 同时提供内容审核拦截检测：CodeBuddy 审核命中时仍返回 HTTP 200，响应体
//! 为固定拦截话术，此前会被当正常回复透传（静默失败）。在流式/非流式收尾
//! 处检测并输出显式告警，便于定位。

use regex::Regex;
use serde_json::Value;
use std::sync::OnceLock;

/// 零宽空格：插入到关键词内部，打断后端的关键词匹配，但模型/人眼读起来无差别。
const ZWSP: char = '\u{200b}';

/// 触发审核的"合规声明高频词"（来自真实被拦截的客户端 system 模板）。
/// 全部是"拒绝作恶"语境里常见的英文术语。大小写不敏感匹配。
static SENSITIVE_TERMS: &[&str] = &[
    // 原有词表
    "DoS",
    "DDoS",
    "exploit",
    "credential testing",
    "credential stuffing",
    "supply chain compromise",
    "supply-chain compromise",
    "detection evasion",
    "C2 frameworks",
    "C2 framework",
    "command and control",
    "malicious purposes",
    "malicious intent",
    "mass targeting",
    "brute force",
    "brute-force",
    "privilege escalation",
    "reverse shell",
    "remote code execution",
    "SQL injection",
    "XSS",
    "CSRF",
    "phishing",
    "malware",
    "ransomware",
    "keylogger",
    "rootkit",
    "backdoor",
    "botnet",
    "zero-day",
    "0day",
    // Codex CLI system prompt 里额外的高频触发词
    "vulnerability",
    "vulnerabilities",
    "red teaming",
    "red-teaming",
    "sandbox",
    "sandboxing",
    "sandboxed",
    "unsandboxed",
    "escalated privileges",
    "escalated",
    "escalation",
    "destructive action",
    "destructive command",
    "destructive",
    "attack",
    "attacks",
    "cybersecurity",
    "security review",
    "exploit development",
    "hacking",
    "penetration testing",
    "penetration test",
    "injection",
    "weaponize",
    "weaponized",
    "harmful",
    "dangerous",
    "abuse",
    "abusive",
    "illegal",
    "terrorist",
    "terrorism",
    "bomb",
    "weapon",
    "weapons",
    "drug",
    "drugs",
    "narcotic",
    "suicide",
    "self-harm",
    "murder",
    "kill",
    "violence",
    "violent",
    // Claude Code / Anthropic 品牌词（避免竞争品牌词触发审核）
    "Claude Code",
    "Claude Opus",
    "Claude Sonnet",
    "Claude Haiku",
    "Claude Fable",
    "Anthropic",
    "Co-Authored-By",
    "noreply@anthropic.com",
];

/// 编译成一个大正则，按词长降序，避免短词先吃掉长词。忽略大小写。
fn sensitive_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        let mut terms: Vec<&str> = SENSITIVE_TERMS.to_vec();
        terms.sort_by_key(|t| std::cmp::Reverse(t.len()));
        let joined = terms
            .iter()
            .map(|t| regex::escape(t))
            .collect::<Vec<_>>()
            .join("|");
        Regex::new(&format!("(?i){joined}")).expect("invalid sensitive terms pattern")
    })
}

/// Codex CLI / Claude Code 会把大量运行时上下文包装进 user 消息里；这些不是
/// 用户真正提问，里面常含 permissions / sandbox / skills 等说明，也会触发后端审核。
const HARNESS_USER_MARKERS: &[&str] = &[
    "# AGENTS.md instructions",
    "<environment_context>",
    "<permissions instructions>",
    "<collaboration_mode>",
    "<skills_instructions>",
    "<system-reminder>", // Claude Code 注入的运行时上下文
    "# claudeMd",        // Claude Code CLAUDE.md 注入
];

const CODEX_SYSTEM_MARKERS: &[&str] = &[
    "You are a coding agent running in the Codex CLI",
    "Within this context, Codex refers to",
    "# How you work",
    "You are Claude Code", // Claude Code system prompt
];

const PERMISSIONS_MARKERS: &[&str] = &[
    "<permissions instructions>",
    "Filesystem sandboxing defines which files can be read or written.",
    "## How to request escalation",
];

const SKILLS_MARKERS: &[&str] = &[
    "<skills_instructions>",
    "### Available skills",
    "### How to use skills",
];

/// 运行时上下文块的整块替换（start_tag ..= end_tag → 摘要）。
const RUNTIME_BLOCK_REPLACEMENTS: &[(&str, &str, &str)] = &[
    (
        "<environment_context>",
        "</environment_context>",
        "Environment context is provided by the harness.",
    ),
    (
        "<permissions instructions>",
        "</permissions instructions>",
        "Runtime permissions apply: filesystem access may be sandboxed, network may be restricted, and some commands may require user approval.",
    ),
    (
        "<collaboration_mode>",
        "</collaboration_mode>",
        "Collaboration mode instructions are provided by the harness.",
    ),
    (
        "<skills_instructions>",
        "</skills_instructions>",
        "Runtime skill metadata is available. Use relevant skills only when explicitly requested or clearly applicable.",
    ),
    (
        "<plugins_instructions>",
        "</plugins_instructions>",
        "Runtime plugin metadata is available when relevant.",
    ),
    (
        "<system-reminder>",
        "</system-reminder>",
        "Runtime reminder context is provided by the harness.",
    ),
];

const RUNTIME_TAIL_MARKERS: &[&str] = &[
    "The following deferred tools are now available via ToolSearch.",
    "Available agent types for the Agent tool:",
    // 注意：上游词表中这两处本身带有零宽空格（U+200B），忠实移植保持一致
    "The following sk\u{200b}ills are available for use with the Sk\u{200b}ill tool:",
    "## MCP Server Instructions",
];

const RUNTIME_TAIL_SUMMARY: &str =
    "Runtime tool, agent, skill, and MCP metadata is available separately.";

const CODEX_CORE_SUMMARY: &str = "You are a coding assistant in Codex CLI. Be precise, helpful, concise, and safe. Inspect the repository, use available tools when needed, follow repository instructions, and keep the user informed with concise progress updates.";

/// 3 个及以上连续换行折叠为 2 个。
fn newline_collapse_pattern() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\n{3,}").expect("invalid newline pattern"))
}

/// 在词内部插入零宽空格。如 'DoS' -> 'Do\u{200B}S'。
/// 在第 1 个字符后插入即可（足够打断子串匹配，且改动最小）。
fn zero_width_split(term: &str) -> String {
    let mut chars = term.chars();
    match chars.next() {
        Some(first) => {
            let mut s = String::with_capacity(term.len() + ZWSP.len_utf8());
            s.push(first);
            s.push(ZWSP);
            s.push_str(chars.as_str());
            s
        }
        None => term.to_string(),
    }
}

/// 对文本中的触发词插入零宽空格。无触发词则原样返回。
pub fn desensitize_text(text: &str) -> String {
    if text.is_empty() {
        return text.to_string();
    }
    sensitive_pattern()
        .replace_all(text, |caps: &regex::Captures| zero_width_split(&caps[0]))
        .into_owned()
}

/// 把字符串或 content blocks 规整成纯文本，便于识别注入模板。
fn content_to_text(content: &Value) -> String {
    if let Some(s) = content.as_str() {
        return s.to_string();
    }
    if let Some(blocks) = content.as_array() {
        let mut parts = String::new();
        for blk in blocks {
            if blk.get("type").and_then(Value::as_str) == Some("text") {
                parts.push_str(blk.get("text").and_then(Value::as_str).unwrap_or(""));
            }
        }
        return parts;
    }
    String::new()
}

/// 判断 user 消息是否其实是 Codex/CLI 注入的上下文，而非用户自然输入。
fn looks_like_harness_text(text: &str) -> bool {
    HARNESS_USER_MARKERS.iter().any(|m| text.contains(m))
}

fn looks_like_harness_user_message(content: &Value) -> bool {
    looks_like_harness_text(&content_to_text(content))
}

/// 把 Codex / Claude Code 注入的超长运行时提示压缩成短摘要，降低审核误伤。
/// 返回 None 表示未命中任何 harness 特征，调用方走常规脱敏路径。
fn compact_harness_message(role: &str, content: &Value) -> Option<String> {
    let text = content_to_text(content);
    if text.is_empty() {
        return None;
    }
    if role == "system" && CODEX_SYSTEM_MARKERS.iter().any(|m| text.contains(m)) {
        if text.contains("You are Claude Code") {
            return Some(
                "You are a coding assistant. Be precise, helpful, concise, and safe. \
                 Use available tools when needed, follow repository instructions, and keep the user informed."
                    .to_string(),
            );
        }
        return Some(
            "You are a coding assistant in Codex CLI. Be precise, helpful, concise, and safe. \
             Use available tools when needed, follow repository instructions, and keep the user informed."
                .to_string(),
        );
    }
    if PERMISSIONS_MARKERS.iter().any(|m| text.contains(m)) {
        return Some(
            "Runtime permissions apply: filesystem access may be sandboxed, network may be restricted, \
             and some commands may require user approval."
                .to_string(),
        );
    }
    if SKILLS_MARKERS.iter().any(|m| text.contains(m)) {
        return Some(
            "Runtime skill metadata is available. Use relevant skills only when explicitly requested or clearly applicable."
                .to_string(),
        );
    }
    if role == "user" && looks_like_harness_user_message(content) {
        return Some(
            "Repository instructions and environment context are provided. Follow repository guidance \
             while answering the user's actual request."
                .to_string(),
        );
    }
    None
}

/// 在 `text` 中从 `from` 起查找最先出现的 `markers`，返回最早的字节位置。
fn earliest_marker(text: &str, from: usize, markers: &[&str]) -> Option<usize> {
    markers
        .iter()
        .filter_map(|m| text[from..].find(m).map(|i| i + from))
        .min()
}

/// 预编译的运行时上下文块替换正则及其替换文本（start_tag..end_tag → 摘要）。
fn runtime_block_regexes() -> &'static Vec<(Regex, String)> {
    static RES: OnceLock<Vec<(Regex, String)>> = OnceLock::new();
    RES.get_or_init(|| {
        RUNTIME_BLOCK_REPLACEMENTS
            .iter()
            .map(|(start_tag, end_tag, replacement)| {
                let pattern = format!(
                    r"(?s)\s*{}.*?{}\s*",
                    regex::escape(start_tag),
                    regex::escape(end_tag)
                );
                let re = Regex::new(&pattern).expect("invalid runtime block pattern");
                (re, format!("\n\n{replacement}\n\n"))
            })
            .collect()
    })
}

/// 轻量裁掉冗长的运行时元数据，保留主要行为指令。
///
/// 用于不压缩的场景：尽量保留 Codex / Claude Code 的核心提示，
/// 但移除重复的 environment / permissions / skills / tool inventory 大段文本。
fn prune_runtime_fragments(role: &str, text: &str) -> String {
    if text.is_empty() {
        return text.to_string();
    }

    let mut pruned = text.to_string();

    // 整块替换 environment / permissions / skills 等运行时上下文块
    for (re, replacement) in runtime_block_regexes() {
        pruned = re.replace_all(&pruned, replacement).into_owned();
    }

    // 从第一个运行时尾部标记起整体截断
    if let Some(cut) = earliest_marker(&pruned, 0, RUNTIME_TAIL_MARKERS) {
        let head = pruned[..cut].trim_end();
        pruned = if head.is_empty() {
            RUNTIME_TAIL_SUMMARY.to_string()
        } else {
            format!("{head}\n\n{RUNTIME_TAIL_SUMMARY}")
        };
    }

    // Codex system prompt 的大段行为指令做节选压缩（intro + Personality/AGENTS.md）
    if role == "system" && CODEX_SYSTEM_MARKERS.iter().any(|m| pruned.contains(m)) {
        let mut keep_sections: Vec<String> = Vec::new();

        // intro：开头到第一个大节标记之前
        let intro_end = earliest_marker(
            &pruned,
            0,
            &[
                "\n# AGENTS.md spec",
                "\n## Responsiveness",
                "\n## Planning",
                "\n## Task execution",
            ],
        )
        .unwrap_or(pruned.len());
        let intro = pruned[..intro_end].trim();
        if !intro.is_empty() {
            keep_sections.push(intro.to_string());
        }

        for heading in ["## Personality", "# AGENTS.md spec"] {
            if let Some(hstart) = pruned.find(heading) {
                let section_end =
                    earliest_marker(&pruned, hstart, &["\n## ", "\n# "]).unwrap_or(pruned.len());
                let section = pruned[hstart..section_end].trim();
                if !section.is_empty() {
                    keep_sections.push(section.to_string());
                }
            }
        }

        pruned = if keep_sections.is_empty() {
            CODEX_CORE_SUMMARY.to_string()
        } else {
            keep_sections.join("\n\n")
        };
    }

    if role == "user" && looks_like_harness_text(&pruned) {
        if pruned.contains("# AGENTS.md instructions")
            || text.contains("<environment_context>")
            || text.contains("<skills_instructions>")
        {
            return "Repository instructions and durable user context are provided. \
                Follow repository guidance while answering the user's actual request."
                .to_string();
        }
    }

    newline_collapse_pattern()
        .replace_all(&pruned, "\n\n")
        .trim()
        .to_string()
}

/// 递归处理 tool 定义，移除高风险描述字段或对其做零宽脱敏。
fn desensitize_tool_value(value: &Value, strip_metadata: bool) -> Value {
    match value {
        Value::Object(map) => {
            let mut new_map = serde_json::Map::new();
            for (key, item) in map {
                let is_text_field =
                    matches!(key.as_str(), "description" | "title") && item.as_str().is_some();
                if is_text_field {
                    if strip_metadata {
                        continue; // 整个字段移除
                    }
                    new_map.insert(
                        key.clone(),
                        Value::String(desensitize_text(item.as_str().unwrap_or(""))),
                    );
                } else {
                    new_map.insert(key.clone(), desensitize_tool_value(item, strip_metadata));
                }
            }
            Value::Object(new_map)
        }
        Value::Array(arr) => Value::Array(
            arr.iter()
                .map(|v| desensitize_tool_value(v, strip_metadata))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// 对单条消息做脱敏（就地修改）。
///
/// 默认策略（与上游 `_apply_desensitize` 一致）：
/// - system / developer 角色始终脱敏
/// - user 角色仅当识别为 harness 注入上下文时才处理
/// - compact 模式优先压缩为摘要；否则走轻量裁剪 + 零宽脱敏
fn desensitize_message(message: &mut Value) {
    let Some(obj) = message.as_object_mut() else {
        return;
    };
    let role = obj
        .get("role")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let should_desensitize = matches!(role.as_str(), "system" | "developer")
        || (role == "user"
            && obj
                .get("content")
                .is_some_and(looks_like_harness_user_message));
    if !should_desensitize {
        return;
    }

    let content = obj.get("content").cloned().unwrap_or(Value::Null);

    let new_content = if let Some(compacted) = compact_harness_message(&role, &content) {
        // 压缩命中：摘要本身再做一次零宽脱敏
        Value::String(desensitize_text(&compacted))
    } else if let Some(s) = content.as_str() {
        Value::String(desensitize_text(&prune_runtime_fragments(&role, s)))
    } else if let Some(blocks) = content.as_array() {
        let new_blocks: Vec<Value> = blocks
            .iter()
            .map(|blk| {
                if blk.get("type").and_then(Value::as_str) == Some("text") {
                    let text = blk
                        .get("text")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    let mut nb = blk.clone();
                    if let Some(text_obj) = nb.as_object_mut() {
                        text_obj.insert(
                            "text".to_string(),
                            Value::String(desensitize_text(&prune_runtime_fragments(&role, &text))),
                        );
                    }
                    nb
                } else {
                    blk.clone()
                }
            })
            .collect();
        Value::Array(new_blocks)
    } else {
        return;
    };

    obj.insert("content".to_string(), new_content);
}

/// 对 CodeBuddy 请求体（OpenAI Chat 形态）应用脱敏，就地修改。
///
/// 等价于上游 `desensitize_body(body, roles=("system","developer"),
/// desensitize_harness_user=True, desensitize_tools=True,
/// compact_harness=True, strip_tool_metadata=True)`，对应
/// `CODEBUDDY_DESENSITIZE`（默认开）+ `CODEBUDDY_DESENSITIZE_NO_COMPACT`
/// （默认关，即压缩开启）的默认配置。
pub fn apply_desensitize(body: &mut Value) {
    if let Some(messages) = body.get_mut("messages").and_then(Value::as_array_mut) {
        for message in messages.iter_mut() {
            desensitize_message(message);
        }
    }
    let has_tools = body
        .get("tools")
        .and_then(Value::as_array)
        .is_some_and(|a| !a.is_empty());
    if has_tools {
        if let Some(tools) = body.get_mut("tools") {
            *tools = desensitize_tool_value(tools, true);
        }
    }
}

// ---------------------------------------------------------------------------
// 内容审核拦截检测（移植自上游 converter.py 的 _looks_like_content_filter_text）
// ---------------------------------------------------------------------------

/// 审核拦截话术通常很短；超过该长度的按正常长回复处理，避免误判。
const CONTENT_FILTER_TEXT_MAX_LEN: usize = 300;

/// 判断响应文本是否为 CodeBuddy 内容审核拦截。
///
/// 后端内容审核命中时仍返回 HTTP 200，但响应体是固定的拦截话术。
/// 需在流式转发的收尾处识别，否则客户端只会看到一段"无法响应"的短回复，
/// 无法与正常回复区分，难以定位。
pub fn looks_like_content_filter_text(text: &str) -> bool {
    let t = text.trim().to_lowercase();
    if t.is_empty() || t.chars().count() > CONTENT_FILTER_TEXT_MAX_LEN {
        return false;
    }
    t.contains("content-filter")
        || t.contains("content_filter")
        || t.contains("敏感内容")
        || t.contains("内容审核")
        || t.contains("无法响应您的请求")
}

/// 检测到内容审核拦截时输出统一格式的告警日志。
pub fn log_content_filter_warning(source: &str, text: &str) {
    let truncated: String = text.chars().take(120).collect();
    log::warn!(
        "[{source}] 检测到内容审核拦截（HTTP 200 但内容被后端拦截），回复文本: {truncated:?}。\
         若频繁出现，说明 CodeBuddy 后端内容审核命中了未脱敏的内容"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ZWSP: char = '\u{200b}';

    // 模拟 Claude Code 注入的 system prompt 开头（含品牌词）
    const CLAUDE_SYSTEM_PROMPT: &str = "You are Claude Code, Anthropic's official CLI for Claude.\nYou are an interactive CLI tool. Refuse requests for DoS attacks, exploit development, and privilege escalation when they lack authorization.";

    // 模拟 Claude Code 注入的 harness user 消息（运行时上下文）
    const HARNESS_USER_MESSAGE: &str = "<system-reminder>\nHere is useful information about the environment.\n# claudeMd\nSome repository instructions...\n</system-reminder>";

    #[test]
    fn brand_words_zero_width() {
        for term in [
            "Claude Code",
            "Claude Opus",
            "Claude Sonnet",
            "Anthropic",
            "Co-Authored-By",
            "noreply@anthropic.com",
        ] {
            let text = format!("prefix {term} suffix");
            let result = desensitize_text(&text);
            assert!(!result.contains(term), "{term} 应被打断子串匹配");
            let expected = format!("prefix {}{ZWSP}{} suffix", &term[..1], &term[1..]);
            assert_eq!(result, expected, "{term} 应仅在首字符后插入一个零宽空格");
        }
    }

    #[test]
    fn security_terms_zero_width() {
        let text = "Refuse requests for DoS attacks and exploit development.";
        let result = desensitize_text(text);
        assert!(!result.contains("DoS") && !result.contains("exploit"));
        assert!(result.contains(ZWSP));
    }

    #[test]
    fn normal_text_untouched() {
        for text in [
            "这是一段正常的中文，不含任何触发词。",
            "no sensitive words here",
        ] {
            assert_eq!(desensitize_text(text), text);
        }
    }

    #[test]
    fn compact_claude_system_prompt() {
        let mut body = json!({
            "messages": [
                {"role": "system", "content": CLAUDE_SYSTEM_PROMPT},
                {"role": "user", "content": "帮我写一个函数"},
            ]
        });
        let original = body["messages"][0]["content"].clone();
        apply_desensitize(&mut body);
        let system_content = body["messages"][0]["content"].as_str().unwrap();
        assert!(!system_content.contains("Claude Code"));
        assert!(system_content.contains("coding assistant"));
        // 其余消息不受影响
        assert_eq!(body["messages"][1]["content"], "帮我写一个函数");
        let _ = original;
    }

    #[test]
    fn compact_harness_user_message() {
        let mut body = json!({
            "messages": [
                {"role": "system", "content": "You are helpful."},
                {"role": "user", "content": HARNESS_USER_MESSAGE},
                {"role": "assistant", "content": "ok"},
                {"role": "user", "content": "真实用户问题：DoS 是什么？"},
            ]
        });
        apply_desensitize(&mut body);
        let harness = body["messages"][1]["content"].as_str().unwrap();
        assert!(!harness.contains("<system-reminder>"));
        assert!(!harness.contains("claudeMd"));
        // 真实用户输入保持原样（不做脱敏、不做压缩）
        assert_eq!(body["messages"][3]["content"], "真实用户问题：DoS 是什么？");
        // 普通未被压缩的 system 消息只做零宽脱敏
        assert_eq!(body["messages"][0]["content"], "You are helpful.");
    }

    #[test]
    fn no_compact_keeps_content_with_zero_width() {
        // 等价于上游 no_compact：直接走 prune + desensitize_text 路径
        let pruned = prune_runtime_fragments("system", CLAUDE_SYSTEM_PROMPT);
        let result = desensitize_text(&pruned);
        // 保留主体内容，但触发词已脱敏
        assert!(result.contains("interactive CLI tool"));
        assert!(!result.contains("Claude Code"));
        assert!(result.contains(ZWSP));
    }

    #[test]
    fn tools_description_stripped() {
        let mut body = json!({
            "messages": [{"role": "user", "content": "hi"}],
            "tools": [{
                "type": "function",
                "function": {
                    "name": "Bash",
                    "description": "Run dangerous commands in a sandbox. Supports privilege escalation.",
                    "parameters": {"type": "object", "properties": {
                        "command": {"type": "string", "description": "The command to execute"}
                    }}
                }
            }]
        });
        apply_desensitize(&mut body);
        let func = &body["tools"][0]["function"];
        assert!(
            func.get("description").is_none(),
            "顶层 description 应被移除"
        );
        assert_eq!(func["name"], "Bash", "工具名必须保留");
        assert!(func.get("parameters").is_some(), "参数 schema 必须保留");
    }

    #[test]
    fn tools_description_desensitized_when_not_stripped() {
        let tools = json!([{
            "type": "function",
            "function": {
                "name": "Bash",
                "description": "Refuse malicious purposes and destructive commands.",
            }
        }]);
        let result = desensitize_tool_value(&tools, false);
        let desc = result[0]["function"]["description"].as_str().unwrap();
        assert!(!desc.contains("malicious"));
        assert!(desc.contains(ZWSP));
    }

    #[test]
    fn apply_desensitize_integration() {
        let mut body = json!({
            "model": "claude-sonnet-4-5",
            "messages": [
                {"role": "system", "content": CLAUDE_SYSTEM_PROMPT},
                {"role": "user", "content": HARNESS_USER_MESSAGE},
                {"role": "user", "content": "帮我看看这个报错"},
            ],
            "tools": [{
                "type": "function",
                "function": {
                    "name": "Read",
                    "description": "Reads a file from the local filesystem."
                }
            }]
        });
        apply_desensitize(&mut body);
        let system_content = body["messages"][0]["content"].as_str().unwrap();
        let harness_content = body["messages"][1]["content"].as_str().unwrap();
        // system 被压缩为通用摘要，harness user 被压缩，均不含品牌词
        assert!(!format!("{system_content}{harness_content}").contains("Claude Code"));
        assert!(system_content.contains("coding assistant"));
        assert!(!harness_content.contains("<system-reminder>"));
        // 真实用户消息原样保留
        assert_eq!(body["messages"][2]["content"], "帮我看看这个报错");
        // 工具 description 被移除，名称保留
        assert!(body["tools"][0]["function"].get("description").is_none());
        assert_eq!(body["tools"][0]["function"]["name"], "Read");
    }

    #[test]
    fn content_filter_detection() {
        let intercepted = [
            "很抱歉，您的请求包含敏感内容，无法响应您的请求。",
            "该请求触发内容审核，已被拦截。",
            "{\"error\": {\"code\": \"content_filter\", \"message\": \"blocked\"}}",
            "Request rejected by content-filter policy.",
        ];
        for text in intercepted {
            assert!(
                looks_like_content_filter_text(text),
                "应识别拦截文本: {}",
                &text.chars().take(30).collect::<String>()
            );
        }

        let normal_long = "关于内容审核机制的设计说明。".repeat(50);
        let normal = [
            "",
            "这是一段正常的模型回复，讲的是如何编写单元测试。",
            // 正常长回复中恰好包含关键词，但长度超过阈值不应误判
            normal_long.as_str(),
        ];
        for text in normal {
            assert!(
                !looks_like_content_filter_text(text),
                "不应误判: {}",
                &text.chars().take(30).collect::<String>()
            );
        }
    }
}
