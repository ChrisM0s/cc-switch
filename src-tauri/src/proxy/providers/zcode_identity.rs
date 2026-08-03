//! ZCode identity header builder
//!
//! Injects the ZCode desktop client's companion headers on every upstream request,
//! making the proxy indistinguishable from the official ZCode client at the
//! fingerprinting layer. Mirrors `pio()` in the ZCode bundle (the
//! `buildProviderIdentityHeaders` helper).

use crate::proxy::error::ProxyError;
use crate::provider::Provider;

const ZCODE_REFERER_ORIGIN: &str = "https://zcode.z.ai";
const ZCODE_APP_VERSION: &str = "3.3.3";
const ZCODE_SOURCE_TITLE: &str = "cli";
const ZCODE_AGENT: &str = "glm";

/// Check whether a provider should use ZCode identity headers.
///
/// Returns true when:
/// - The provider's meta.provider_type is "zcode", OR
/// - The provider's base_url contains a Z.AI or Bigmodel domain
pub fn is_zcode_provider(provider: &Provider) -> bool {
    if let Some(meta) = provider.meta.as_ref() {
        if meta.provider_type.as_deref() == Some("zcode") {
            return true;
        }
    }

    // Detect by base_url patterns
    let base_url = provider
        .settings_config
        .get("env")
        .and_then(|env| env.get("ANTHROPIC_BASE_URL"))
        .and_then(|v| v.as_str())
        .or_else(|| {
            provider
                .settings_config
                .get("base_url")
                .and_then(|v| v.as_str())
        })
        .or_else(|| {
            provider
                .settings_config
                .get("baseURL")
                .and_then(|v| v.as_str())
        })
        .or_else(|| {
            provider
                .settings_config
                .get("apiEndpoint")
                .and_then(|v| v.as_str())
        });

    match base_url {
        Some(url) => url.contains("api.z.ai") || url.contains("bigmodel.cn"),
        None => false,
    }
}

/// Build ZCode identity headers for upstream requests.
///
/// Returns a list of (name, value) header pairs in the exact order the official
/// ZCode client would send them.
pub fn build_zcode_identity_headers() -> Result<Vec<(&'static str, String)>, ProxyError> {
    let platform = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    let os_category = match platform {
        "macos" => "macos",
        "windows" => "windows",
        _ => "linux",
    };

    let mut headers: Vec<(&'static str, String)> = Vec::new();

    // 1. HTTP-Referer — always present
    headers.push(("HTTP-Referer", ZCODE_REFERER_ORIGIN.to_string()));

    // 2. User-Agent — ZCode/{version}
    headers.push(("User-Agent", format!("ZCode/{ZCODE_APP_VERSION}")));

    // 3. X-ZCode-App-Version — only when version is valid printable ASCII
    headers.push(("X-ZCode-App-Version", ZCODE_APP_VERSION.to_string()));

    // 4. X-Title — Z Code@{sourceTitle}
    headers.push(("X-Title", format!("Z Code@{ZCODE_SOURCE_TITLE}")));

    // 5. X-ZCode-Agent — hardcoded to "glm"
    headers.push(("X-ZCode-Agent", ZCODE_AGENT.to_string()));

    // 6. X-Platform — {platform}-{arch}
    headers.push(("X-Platform", format!("{platform}-{arch}")));

    // 7. X-Os-Category — windows|macos|linux
    headers.push(("X-Os-Category", os_category.to_string()));

    Ok(headers)
}

/// Build a trace ID header pair for ZCode upstream requests.
/// Only injects x-request-id and x-zcode-trace-id (not x-query-id and
/// x-session-id which are client-provided in strict mode).
pub fn build_zcode_trace_headers() -> Vec<(&'static str, String)> {
    let request_id = uuid::Uuid::new_v4().simple().to_string();
    let trace_id = uuid::Uuid::new_v4().simple().to_string();
    vec![
        ("x-request-id", request_id),
        ("x-zcode-trace-id", trace_id),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn create_provider_with_url(base_url: &str) -> Provider {
        Provider {
            id: "test".to_string(),
            name: "Test ZCode".to_string(),
            settings_config: json!({
                "env": {
                    "ANTHROPIC_BASE_URL": base_url,
                    "ANTHROPIC_AUTH_TOKEN": "test-key.test-secret"
                }
            }),
            website_url: None,
            category: None,
            created_at: None,
            sort_index: None,
            notes: None,
            meta: None,
            icon: None,
            icon_color: None,
            in_failover_queue: false,
        }
    }

    #[test]
    fn test_is_zcode_provider_by_url() {
        assert!(is_zcode_provider(&create_provider_with_url("https://api.z.ai/api/anthropic")));
        assert!(is_zcode_provider(&create_provider_with_url(
            "https://open.bigmodel.cn/api/paas/v4"
        )));
        assert!(!is_zcode_provider(&create_provider_with_url("https://api.anthropic.com")));
        assert!(!is_zcode_provider(&create_provider_with_url(
            "https://api.openai.com"
        )));
    }

    #[test]
    fn test_build_zcode_identity_headers() {
        let headers = build_zcode_identity_headers().unwrap();
        let map: std::collections::HashMap<&str, &str> =
            headers.iter().map(|(k, v)| (*k, v.as_str())).collect();

        assert_eq!(map.get("HTTP-Referer"), Some(&"https://zcode.z.ai"));
        assert_eq!(map.get("X-ZCode-Agent"), Some(&"glm"));
        assert!(map.get("User-Agent").unwrap().starts_with("ZCode/"));
        assert!(map.get("X-Title").unwrap().starts_with("Z Code@"));
    }
}
