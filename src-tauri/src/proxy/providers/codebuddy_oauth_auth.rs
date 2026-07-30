//! CodeBuddy OAuth Authentication Module
//!
//! 实现腾讯云 CodeBuddy 官方账号的登录流程（本地配置 → state 轮询，非标准 OAuth2 redirect）。
//! 支持三种站点类型：
//! - **国际站**: https://www.codebuddy.ai
//! - **中国站**: https://www.codebuddy.cn
//! - **企业版**: 自定义 API 端点 + 企业标识 + 可选 User-Agent
//!
//! 每个账号绑定独立的站点配置（CodeBuddyAuthProfile），认证和后续对话请求均使用
//! 对应站点的端点与请求头。
//!
//! ## 认证流程（两阶段）
//! 1. **本地配置阶段**: cc-switch 在 127.0.0.1 随机端口启动一次性配置页，用户在浏览器
//!    选择站点类型，企业版需填写 API 端点、企业标识和可选 User-Agent。
//! 2. **上游登录阶段**: 提交配置后调用对应站点的 `/v2/plugin/auth/state` 获取 authUrl，
//!    浏览器自动跳转到 CodeBuddy 登录页完成授权；前端轮询 `/v2/plugin/auth/token`。
//!
//! ## 多账号支持
//! - 每个 CodeBuddy 账号独立存储 access_token（JWT）、user_id 和 profile
//! - Provider 通过 meta.authBinding 关联账号（auth_provider = "codebuddy_oauth"）
//! - 账号唯一标识来自 JWT payload 中的 email 或 sub

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::copilot_auth::{GitHubAccount, GitHubDeviceCodeResponse};

// ============================================================================
// Constants
// ============================================================================

/// 国际站默认端点
pub const CODEBUDDY_INTERNATIONAL_BASE_URL: &str = "https://www.codebuddy.ai";

/// 中国站默认端点
pub const CODEBUDDY_CHINA_BASE_URL: &str = "https://www.codebuddy.cn";

/// 生成登录 state 的接口路径
pub const AUTH_STATE_PATH: &str = "/v2/plugin/auth/state";

/// 轮询登录状态的接口路径
pub const AUTH_TOKEN_PATH: &str = "/v2/plugin/auth/token";

/// 对话接口路径
pub const CHAT_COMPLETIONS_PATH: &str = "/v2/chat/completions";

/// 登录状态尚未完成时后端返回的业务 code
const AUTH_PENDING_CODE: i64 = 11217;

/// flow 默认有效时长（秒）
pub const AUTH_STATE_DEFAULT_EXPIRES_IN: u64 = 1800;

/// 轮询间隔安全余量（秒）
const POLLING_SAFETY_MARGIN_SECS: u64 = 3;

/// 默认 SaaS User-Agent
const DEFAULT_SAAS_USER_AGENT: &str = "CLI/1.0.8 CodeBuddy/1.0.8";

/// 默认企业版 User-Agent
const DEFAULT_ENTERPRISE_USER_AGENT: &str = "CodeBuddyIDE/4.2.22590715";

/// 最大 User-Agent 长度（防止注入攻击）
const MAX_USER_AGENT_LEN: usize = 512;

/// 最大企业标识长度
const MAX_ENTERPRISE_ID_LEN: usize = 256;

/// 最大端点 URL 长度
const MAX_ENDPOINT_URL_LEN: usize = 512;

/// 本地配置页表单最大 POST 体大小
pub const MAX_FORM_BODY_BYTES: usize = 4_096;

/// 本地配置页服务器超时（秒）
pub const CONFIG_SERVER_TIMEOUT_SECS: u64 = 300;

// ============================================================================
// Site Type & Auth Profile
// ============================================================================

/// 站点类型
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeBuddySiteType {
    /// 国际站（SaaS）
    International,
    /// 中国站
    China,
    /// 企业版（自定义端点 + 企业标识）
    Enterprise,
}

impl fmt::Display for CodeBuddySiteType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CodeBuddySiteType::International => write!(f, "international"),
            CodeBuddySiteType::China => write!(f, "china"),
            CodeBuddySiteType::Enterprise => write!(f, "enterprise"),
        }
    }
}

impl std::str::FromStr for CodeBuddySiteType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "international" => Ok(CodeBuddySiteType::International),
            "china" => Ok(CodeBuddySiteType::China),
            "enterprise" => Ok(CodeBuddySiteType::Enterprise),
            _ => Err(format!("无效的站点类型: {s}")),
        }
    }
}

/// 认证关系判断（是否是 SaaS 产品）
impl CodeBuddySiteType {
    pub fn is_enterprise(&self) -> bool {
        matches!(self, CodeBuddySiteType::Enterprise)
    }

    /// 对应的产品请求头值
    pub fn product_header(&self) -> &'static str {
        match self {
            CodeBuddySiteType::International | CodeBuddySiteType::China => "SaaS",
            CodeBuddySiteType::Enterprise => "Cloud-Hosted",
        }
    }
}

/// 站点配置档案，绑定到每个账号
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeBuddyAuthProfile {
    /// 站点类型
    pub site_type: CodeBuddySiteType,

    /// API 端点（国际站/中国站自动填充，企业版由用户提供）
    pub api_endpoint: String,

    /// 企业标识（仅企业版有效）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enterprise_id: Option<String>,

    /// 自定义 User-Agent（仅企业版有效，为空则使用默认）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
}

impl CodeBuddyAuthProfile {
    /// 创建国际站 profile
    pub fn international() -> Self {
        Self {
            site_type: CodeBuddySiteType::International,
            api_endpoint: CODEBUDDY_INTERNATIONAL_BASE_URL.to_string(),
            enterprise_id: None,
            user_agent: None,
        }
    }

    /// 创建中国站 profile
    pub fn china() -> Self {
        Self {
            site_type: CodeBuddySiteType::China,
            api_endpoint: CODEBUDDY_CHINA_BASE_URL.to_string(),
            enterprise_id: None,
            user_agent: None,
        }
    }

    /// 创建企业版 profile，校验参数
    pub fn enterprise(
        api_endpoint: String,
        enterprise_id: String,
        user_agent: Option<String>,
    ) -> Result<Self, CodeBuddyOAuthError> {
        // 校验端点
        let normalized = normalize_endpoint_url(&api_endpoint)?;

        // 校验企业标识
        if enterprise_id.is_empty() || enterprise_id.len() > MAX_ENTERPRISE_ID_LEN {
            return Err(CodeBuddyOAuthError::InvalidConfig(
                "企业标识不能为空且长度不能超过 256 字符".to_string(),
            ));
        }
        // 防御 HTTP header 注入
        if enterprise_id.contains('\n') || enterprise_id.contains('\r') {
            return Err(CodeBuddyOAuthError::InvalidConfig(
                "企业标识不能包含换行符".to_string(),
            ));
        }

        // 校验 User-Agent（可选）
        if let Some(ref ua) = user_agent {
            validate_user_agent(ua)?;
        }

        Ok(Self {
            site_type: CodeBuddySiteType::Enterprise,
            api_endpoint: normalized,
            enterprise_id: Some(enterprise_id),
            user_agent,
        })
    }

    /// 获取用于请求头的 Host 部分
    pub fn host(&self) -> &str {
        extract_host_from_url(&self.api_endpoint)
    }

    /// 获取用于请求头的 User-Agent
    pub fn effective_user_agent(&self) -> &str {
        if self.site_type.is_enterprise() {
            self.user_agent
                .as_deref()
                .unwrap_or(DEFAULT_ENTERPRISE_USER_AGENT)
        } else {
            DEFAULT_SAAS_USER_AGENT
        }
    }

    /// 获取用于请求头的产品标识
    pub fn product_header(&self) -> &'static str {
        self.site_type.product_header()
    }

    /// 获取用于 X-User-Id 的默认值（SaaS 默认使用匿名 UUID）
    pub fn default_user_id() -> &'static str {
        "b5be3a67-237e-4ee6-9b9a-0b9ecd7b454b"
    }
}

impl Default for CodeBuddyAuthProfile {
    fn default() -> Self {
        Self::international()
    }
}

/// 规范化端点 URL：必须是 HTTPS，移除尾部斜杠、查询参数和片段，拒绝 IP 地址和凭证
fn normalize_endpoint_url(url: &str) -> Result<String, CodeBuddyOAuthError> {
    let trimmed = url.trim();

    if trimmed.is_empty() || trimmed.len() > MAX_ENDPOINT_URL_LEN {
        return Err(CodeBuddyOAuthError::InvalidConfig(format!(
            "端点 URL 长度必须在 1-{MAX_ENDPOINT_URL_LEN} 字符之间"
        )));
    }

    // 解析 URL
    let parsed = url::Url::parse(trimmed).map_err(|e| {
        CodeBuddyOAuthError::InvalidConfig(format!("无效的端点 URL: {e}"))
    })?;

    // 必须是 HTTPS（本地开发允许 http for localhost 但生产拒绝）
    if parsed.scheme() != "https" {
        return Err(CodeBuddyOAuthError::InvalidConfig(
            "端点必须使用 HTTPS 协议".to_string(),
        ));
    }

    // 不允许用户名/密码
    if parsed.username() != "" || parsed.password().is_some() {
        return Err(CodeBuddyOAuthError::InvalidConfig(
            "端点 URL 不能包含用户名或密码".to_string(),
        ));
    }

    // 不允许 query 参数
    if parsed.query().is_some() {
        return Err(CodeBuddyOAuthError::InvalidConfig(
            "端点 URL 不能包含查询参数".to_string(),
        ));
    }

    // 不允许 fragment
    if parsed.fragment().is_some() {
        return Err(CodeBuddyOAuthError::InvalidConfig(
            "端点 URL 不能包含片段".to_string(),
        ));
    }

    // 构建规范化 URL：scheme + host + port（无路径尾斜杠）
    let host = parsed.host_str().ok_or_else(|| {
        CodeBuddyOAuthError::InvalidConfig("端点 URL 缺少主机名".to_string())
    })?;

    // 不允许裸 IP（安全策略）
    if host.parse::<std::net::IpAddr>().is_ok() {
        return Err(CodeBuddyOAuthError::InvalidConfig(
            "端点 URL 不能使用裸 IP 地址，请使用域名".to_string(),
        ));
    }

    // 不允许 localhost（安全策略）
    if host.eq_ignore_ascii_case("localhost") {
        return Err(CodeBuddyOAuthError::InvalidConfig(
            "端点 URL 不能使用 localhost".to_string(),
        ));
    }

    if let Some(port) = parsed.port() {
        Ok(format!("{}://{}:{}/", parsed.scheme(), host, port))
    } else {
        Ok(format!("{}://{}/", parsed.scheme(), host))
    }
}

/// 从 URL 提取 host（不含端口），用于 Host header
fn extract_host_from_url(url: &str) -> &str {
    // 简单提取：去掉 scheme 后取 host
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    // 去掉端口和路径
    without_scheme
        .split('/')
        .next()
        .unwrap_or(without_scheme)
        .split(':')
        .next()
        .unwrap_or(without_scheme)
}

/// 校验 User-Agent 字符串
fn validate_user_agent(ua: &str) -> Result<(), CodeBuddyOAuthError> {
    if ua.is_empty() {
        return Err(CodeBuddyOAuthError::InvalidConfig(
            "User-Agent 不能为空".to_string(),
        ));
    }
    if ua.len() > MAX_USER_AGENT_LEN {
        return Err(CodeBuddyOAuthError::InvalidConfig(format!(
            "User-Agent 长度不能超过 {MAX_USER_AGENT_LEN} 字符"
        )));
    }
    // 拒绝含换行符的输入（防止 HTTP header 注入）
    if ua.contains('\n') || ua.contains('\r') {
        return Err(CodeBuddyOAuthError::InvalidConfig(
            "User-Agent 不能包含换行符".to_string(),
        ));
    }
    Ok(())
}

// ============================================================================
// Auth Header Builders（profile-aware，对齐 codebuddy2api）
// ============================================================================

/// 构建 /auth/state 请求头（启动认证）
pub fn build_auth_start_headers(profile: &CodeBuddyAuthProfile) -> Vec<(&'static str, String)> {
    let host = profile.host();
    let request_id = uuid::Uuid::new_v4().simple().to_string();
    let is_enterprise = profile.site_type.is_enterprise();

    let mut headers: Vec<(&'static str, String)> = vec![
        ("Host", host.to_string()),
        ("Accept", "application/json, text/plain, */*".to_string()),
        ("Content-Type", "application/json".to_string()),
        ("Cache-Control", "no-cache".to_string()),
        ("Pragma", "no-cache".to_string()),
        ("Connection", "close".to_string()),
        ("X-Requested-With", "XMLHttpRequest".to_string()),
        ("X-Domain", host.to_string()),
        (
            "User-Agent",
            profile.effective_user_agent().to_string(),
        ),
        ("X-Product", profile.product_header().to_string()),
        ("X-Request-ID", request_id),
    ];

    if is_enterprise {
        let ent_id = profile
            .enterprise_id
            .as_deref()
            .unwrap_or("")
            .to_string();
        headers.push(("X-Enterprise-Id", ent_id.clone()));
        headers.push(("X-Tenant-Id", ent_id));
        headers.push(("X-Env-ID", "production".to_string()));
        headers.push(("X-IDE-Type", "VSCode".to_string()));
        headers.push(("X-IDE-Name", "VSCode".to_string()));
        headers.push(("X-IDE-Version", "1.115.0".to_string()));
        headers.push(("X-Product-Version", "4.2.22590715".to_string()));
    } else {
        headers.push(("X-No-Authorization", "true".to_string()));
        headers.push(("X-No-User-Id", "true".to_string()));
        headers.push(("X-No-Enterprise-Id", "true".to_string()));
        headers.push(("X-No-Department-Info", "true".to_string()));
    }

    headers
}

/// 构建 /auth/token 轮询请求头
pub fn build_auth_poll_headers(profile: &CodeBuddyAuthProfile) -> Vec<(&'static str, String)> {
    let host = profile.host();
    let request_id = uuid::Uuid::new_v4().simple().to_string();
    let span_id = uuid::Uuid::new_v4().simple().to_string()[..16].to_string();
    let is_enterprise = profile.site_type.is_enterprise();

    let mut headers: Vec<(&'static str, String)> = vec![
        ("Host", host.to_string()),
        ("Accept", "application/json, text/plain, */*".to_string()),
        ("Cache-Control", "no-cache".to_string()),
        ("Pragma", "no-cache".to_string()),
        ("Connection", "close".to_string()),
        ("X-Requested-With", "XMLHttpRequest".to_string()),
        ("X-Request-ID", request_id.clone()),
        ("b3", format!("{request_id}-{span_id}-1-")),
        ("X-B3-TraceId", request_id.clone()),
        ("X-B3-ParentSpanId", String::new()),
        ("X-B3-SpanId", span_id),
        ("X-B3-Sampled", "1".to_string()),
        ("X-Domain", host.to_string()),
        (
            "User-Agent",
            profile.effective_user_agent().to_string(),
        ),
        ("X-Product", profile.product_header().to_string()),
    ];

    if is_enterprise {
        let ent_id = profile
            .enterprise_id
            .as_deref()
            .unwrap_or("")
            .to_string();
        headers.push(("X-Enterprise-Id", ent_id.clone()));
        headers.push(("X-Tenant-Id", ent_id));
        headers.push(("X-Env-ID", "production".to_string()));
        headers.push(("X-IDE-Type", "VSCode".to_string()));
        headers.push(("X-IDE-Name", "VSCode".to_string()));
        headers.push(("X-IDE-Version", "1.115.0".to_string()));
        headers.push(("X-Product-Version", "4.2.22590715".to_string()));
    } else {
        headers.push(("X-No-Authorization", "true".to_string()));
        headers.push(("X-No-User-Id", "true".to_string()));
        headers.push(("X-No-Enterprise-Id", "true".to_string()));
        headers.push(("X-No-Department-Info", "true".to_string()));
    }

    headers
}

/// 运行时认证凭证（一次读取，避免 forwarder 多次读锁产生不一致快照）
#[derive(Debug, Clone)]
pub struct CodeBuddyRuntimeAuth {
    pub access_token: String,
    pub user_id: String,
    pub profile: CodeBuddyAuthProfile,
}

/// 构建 CodeBuddy 对话请求头（chat/completions）
///
/// 对齐 codebuddy2api 的 `generate_codebuddy_headers`，根据 profile 区分 SaaS/企业版。
pub fn build_chat_headers(
    bearer_token: &str,
    user_id: &str,
    profile: &CodeBuddyAuthProfile,
) -> Vec<(&'static str, String)> {
    let host = profile.host();
    let request_id = uuid::Uuid::new_v4().simple().to_string();
    let conversation_id = uuid::Uuid::new_v4().to_string();
    let conversation_request_id = uuid::Uuid::new_v4().simple().to_string()[..16].to_string();
    let conversation_message_id = uuid::Uuid::new_v4().to_string().replace('-', "");

    let mut headers: Vec<(&'static str, String)> = vec![
        ("Host", host.to_string()),
        ("Accept", "application/json".to_string()),
        (
            "Authorization",
            format!("Bearer {bearer_token}"),
        ),
        ("X-Domain", host.to_string()),
        ("X-Product", profile.product_header().to_string()),
        ("X-Request-ID", request_id.clone()),
        ("X-Conversation-ID", conversation_id),
        (
            "X-Conversation-Request-ID",
            conversation_request_id,
        ),
        (
            "X-Conversation-Message-ID",
            conversation_message_id,
        ),
        ("X-User-Id", user_id.to_string()),
        ("X-Agent-Intent", "craft".to_string()),
    ];

    if profile.site_type.is_enterprise() {
        let ent_id = profile
            .enterprise_id
            .as_deref()
            .unwrap_or("")
            .to_string();
        headers.push(("Content-Type", "application/json;charset=UTF-8".to_string()));
        headers.push(("X-Enterprise-Id", ent_id.clone()));
        headers.push(("X-Tenant-Id", ent_id));
        headers.push(("X-IDE-Type", "VSCode".to_string()));
        headers.push(("X-IDE-Name", "VSCode".to_string()));
        headers.push(("X-IDE-Version", "1.115.0".to_string()));
        headers.push(("X-Product-Version", "4.2.22590715".to_string()));
        headers.push(("X-Env-ID", "production".to_string()));
        headers.push((
            "User-Agent",
            profile.effective_user_agent().to_string(),
        ));
        headers.push((
            "X-Request-Trace-Id",
            request_id,
        ));
    } else {
        headers.push(("Content-Type", "application/json".to_string()));
        headers.push(("X-Requested-With", "XMLHttpRequest".to_string()));
        headers.push(("x-stainless-arch", "x64".to_string()));
        headers.push(("x-stainless-lang", "js".to_string()));
        headers.push(("x-stainless-os", "Windows".to_string()));
        headers.push(("x-stainless-package-version", "5.10.1".to_string()));
        headers.push(("x-stainless-retry-count", "0".to_string()));
        headers.push(("x-stainless-runtime", "node".to_string()));
        headers.push(("x-stainless-runtime-version", "v22.13.1".to_string()));
        headers.push(("X-IDE-Type", "CLI".to_string()));
        headers.push(("X-IDE-Name", "CLI".to_string()));
        headers.push(("X-IDE-Version", "1.0.7".to_string()));
        headers.push((
            "User-Agent",
            profile.effective_user_agent().to_string(),
        ));
    }

    headers
}

/// 构造 CodeBuddy 对话的完整 URL
pub fn build_chat_url(profile: &CodeBuddyAuthProfile) -> String {
    let base = profile.api_endpoint.trim_end_matches('/');
    format!("{base}{CHAT_COMPLETIONS_PATH}")
}

// ============================================================================
// OAuth Error
// ============================================================================

/// CodeBuddy OAuth 错误
#[derive(Debug, thiserror::Error)]
pub enum CodeBuddyOAuthError {
    #[error("等待用户授权中")]
    AuthorizationPending,

    #[error("登录 state 已过期")]
    ExpiredToken,

    #[error("Token 获取失败: {0}")]
    TokenFetchFailed(String),

    #[error("access_token 已过期，请重新登录")]
    TokenExpired,

    #[error("无效的配置: {0}")]
    InvalidConfig(String),

    #[error("网络错误: {0}")]
    NetworkError(String),

    #[error("解析错误: {0}")]
    ParseError(String),

    #[error("IO 错误: {0}")]
    IoError(String),

    #[error("账号不存在: {0}")]
    AccountNotFound(String),
}

impl From<reqwest::Error> for CodeBuddyOAuthError {
    fn from(err: reqwest::Error) -> Self {
        CodeBuddyOAuthError::NetworkError(err.to_string())
    }
}

impl From<std::io::Error> for CodeBuddyOAuthError {
    fn from(err: std::io::Error) -> Self {
        CodeBuddyOAuthError::IoError(err.to_string())
    }
}

// ============================================================================
// API Response Types
// ============================================================================

/// `/v2/plugin/auth/state` 响应
#[derive(Debug, Clone, Deserialize)]
struct AuthStateResponse {
    code: i64,
    #[serde(default)]
    data: Option<AuthStateData>,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
struct AuthStateData {
    state: String,
    #[serde(rename = "authUrl")]
    auth_url: String,
}

/// `/v2/plugin/auth/token` 响应
#[derive(Debug, Clone, Deserialize)]
struct AuthTokenResponse {
    code: i64,
    #[serde(default)]
    data: Option<AuthTokenData>,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
struct AuthTokenData {
    #[serde(rename = "accessToken")]
    access_token: String,
}

/// 解析后的 JWT claims
#[derive(Debug, Clone, Default, Deserialize)]
struct AccessTokenClaims {
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    sub: Option<String>,
    #[serde(default)]
    exp: Option<i64>,
}

// ============================================================================
// Internal Types
// ============================================================================

/// 缓存的 access_token（含过期时间）
#[derive(Debug, Clone)]
struct CachedAccessToken {
    token: String,
    /// 过期时间戳（毫秒）
    expires_at_ms: i64,
}

impl CachedAccessToken {
    fn is_expired(&self) -> bool {
        let now = chrono::Utc::now().timestamp_millis();
        self.expires_at_ms <= now
    }
}

/// 进行中的登录流程
#[derive(Debug, Clone)]
pub enum PendingFlow {
    /// 等待用户在本地配置页选择站点并提交
    AwaitingConfiguration {
        expires_at_ms: i64,
        csrf_token: String,
    },
    /// 已提交配置，等待用户在 CodeBuddy 登录页完成授权
    AwaitingAuthorization {
        expires_at_ms: i64,
        upstream_state: String,
        profile: CodeBuddyAuthProfile,
    },
}

impl PendingFlow {
    fn expires_at_ms(&self) -> i64 {
        match self {
            PendingFlow::AwaitingConfiguration { expires_at_ms, .. } => *expires_at_ms,
            PendingFlow::AwaitingAuthorization { expires_at_ms, .. } => *expires_at_ms,
        }
    }
}

// ============================================================================
// Account Data (v2)
// ============================================================================

/// 持久化的账号数据（v2）
#[derive(Debug, Clone, Serialize, Deserialize)]
struct CodeBuddyAccountData {
    /// 账号唯一标识（email 或 sub）
    pub account_id: String,
    /// 账号邮箱（如果可获取）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// access_token（JWT，直接持久化——CodeBuddy 无 refresh 机制）
    pub access_token: String,
    /// access_token 过期时间戳（毫秒）
    pub expires_at_ms: i64,
    /// 认证时间戳（秒）
    pub authenticated_at: i64,
    /// 用户 ID（优先 JWT sub，用于 X-User-Id）
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    /// 站点配置档案
    #[serde(default)]
    pub profile: CodeBuddyAuthProfile,
}

impl From<&CodeBuddyAccountData> for GitHubAccount {
    fn from(data: &CodeBuddyAccountData) -> Self {
        let profile_label = match data.profile.site_type {
            CodeBuddySiteType::International => "国际站".to_string(),
            CodeBuddySiteType::China => "中国站".to_string(),
            CodeBuddySiteType::Enterprise => data
                .profile
                .enterprise_id
                .as_deref()
                .map(|id| format!("企业: {id}"))
                .unwrap_or_else(|| "企业版".to_string()),
        };
        GitHubAccount {
            id: data.account_id.clone(),
            login: data.email.clone().unwrap_or_else(|| {
                format!("CodeBuddy {profile_label} ({})", &data.account_id)
            }),
            avatar_url: None,
            authenticated_at: data.authenticated_at,
            github_domain: format!(
                "{} ({})",
                data.profile.api_endpoint,
                profile_label
            ),
        }
    }
}

/// 持久化存储结构（v2，向后兼容 v1）
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct CodeBuddyOAuthStore {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    accounts: HashMap<String, CodeBuddyAccountData>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    default_account_id: Option<String>,
}

// ============================================================================
// Manager
// ============================================================================

/// CodeBuddy OAuth 认证管理器（多账号）
pub struct CodeBuddyOAuthManager {
    accounts: Arc<RwLock<HashMap<String, CodeBuddyAccountData>>>,
    default_account_id: Arc<RwLock<Option<String>>>,
    /// 内存缓存的 access_token
    access_tokens: Arc<RwLock<HashMap<String, CachedAccessToken>>>,
    /// 进行中的登录流程：flow_id → PendingFlow
    pending_flows: Arc<RwLock<HashMap<String, PendingFlow>>>,
    storage_path: PathBuf,
}

impl CodeBuddyOAuthManager {
    pub fn new(data_dir: PathBuf) -> Self {
        let storage_path = data_dir.join("codebuddy_oauth_auth.json");

        let manager = Self {
            accounts: Arc::new(RwLock::new(HashMap::new())),
            default_account_id: Arc::new(RwLock::new(None)),
            access_tokens: Arc::new(RwLock::new(HashMap::new())),
            pending_flows: Arc::new(RwLock::new(HashMap::new())),
            storage_path,
        };

        if let Err(e) = manager.load_from_disk_sync() {
            log::warn!("[CodeBuddyOAuth] 加载存储失败: {e}");
        }

        manager
    }

    /// 获取 pending_flows Arc 引用（供本地配置页服务器使用）
    pub fn pending_flows_arc(&self) -> Arc<RwLock<HashMap<String, PendingFlow>>> {
        self.pending_flows.clone()
    }

    // ==================== 登录流程 ====================

    /// 启动登录流程（两阶段：本地配置 → 上游登录）
    ///
    /// 在 127.0.0.1:0 启动一次性配置页服务器，返回 flow_id 作为 device_code，
    /// verification_uri 指向本地配置页。
    pub async fn start_device_flow(
        &self,
    ) -> Result<GitHubDeviceCodeResponse, CodeBuddyOAuthError> {
        log::info!("[CodeBuddyOAuth] 启动登录流程（本地配置模式）");

        // 生成 flow ID 和 CSRF token
        let flow_id = uuid::Uuid::new_v4().simple().to_string();
        let csrf_token = uuid::Uuid::new_v4().simple().to_string();
        let expires_in = CONFIG_SERVER_TIMEOUT_SECS;
        let expires_at_ms =
            chrono::Utc::now().timestamp_millis() + (expires_in as i64) * 1000;

        // 清理过期 flow
        {
            let mut flows = self.pending_flows.write().await;
            let now_ms = chrono::Utc::now().timestamp_millis();
            flows.retain(|_, flow| flow.expires_at_ms() > now_ms);
            flows.insert(
                flow_id.clone(),
                PendingFlow::AwaitingConfiguration {
                    expires_at_ms,
                    csrf_token: csrf_token.clone(),
                },
            );
        }

        // 启动本地配置页服务器
        let port = crate::proxy::providers::codebuddy_auth_form::start_config_server(
            flow_id.clone(),
            csrf_token,
            self.pending_flows.clone(),
            expires_at_ms,
        )
        .await
        .map_err(|e| {
            CodeBuddyOAuthError::NetworkError(format!("无法启动本地配置服务器: {e}"))
        })?;

        let verification_uri = format!("http://127.0.0.1:{port}/?flow={flow_id}");

        log::info!(
            "[CodeBuddyOAuth] 本地配置页已启动: {verification_uri}"
        );

        Ok(GitHubDeviceCodeResponse {
            device_code: flow_id.clone(),
            user_code: flow_id,
            verification_uri,
            expires_in,
            interval: 5 + POLLING_SAFETY_MARGIN_SECS,
        })
    }

    /// 轮询登录状态（以 flow_id 为 key）
    ///
    /// 在配置阶段返回 AuthorizationPending；完成配置后使用 upstream state 轮询 token。
    pub async fn poll_for_token(
        &self,
        device_code: &str,
    ) -> Result<Option<GitHubAccount>, CodeBuddyOAuthError> {
        // 检查 flow 是否存在及状态
        let flow = {
            let flows = self.pending_flows.read().await;
            flows.get(device_code).cloned()
        };

        let flow = flow.ok_or_else(|| {
            CodeBuddyOAuthError::TokenFetchFailed(
                "未找到对应的登录流程，请重新启动登录".to_string(),
            )
        })?;

        let now_ms = chrono::Utc::now().timestamp_millis();
        if flow.expires_at_ms() <= now_ms {
            let mut flows = self.pending_flows.write().await;
            flows.remove(device_code);
            return Err(CodeBuddyOAuthError::ExpiredToken);
        }

        match &flow {
            PendingFlow::AwaitingConfiguration { .. } => {
                // 用户尚未完成本地配置
                Err(CodeBuddyOAuthError::AuthorizationPending)
            }
            PendingFlow::AwaitingAuthorization {
                upstream_state,
                profile,
                ..
            } => {
                // 使用 profile 对应的端点轮询 token
                self.poll_upstream_token(device_code, upstream_state, profile)
                    .await
            }
        }
    }

    /// 向 profile 指定的站点轮询 token
    async fn poll_upstream_token(
        &self,
        flow_id: &str,
        upstream_state: &str,
        profile: &CodeBuddyAuthProfile,
    ) -> Result<Option<GitHubAccount>, CodeBuddyOAuthError> {
        let url = format!(
            "{}v2/plugin/auth/token?state={upstream_state}",
            profile.api_endpoint
        );

        log::debug!(
            "[CodeBuddyOAuth] 轮询登录状态: {}",
            url.split('?').next().unwrap_or(&url)
        );

        let mut req = crate::proxy::http_client::get().get(&url);

        for (key, value) in build_auth_poll_headers(profile) {
            req = req.header(key, &value);
        }

        let poll_response = req.send().await?;

        if !poll_response.status().is_success() {
            let status = poll_response.status();
            let text = poll_response.text().await.unwrap_or_default();
            return Err(CodeBuddyOAuthError::TokenFetchFailed(format!(
                "{status} - {text}"
            )));
        }

        let parsed: AuthTokenResponse = poll_response
            .json()
            .await
            .map_err(|e| CodeBuddyOAuthError::ParseError(e.to_string()))?;

        if parsed.code == AUTH_PENDING_CODE {
            return Err(CodeBuddyOAuthError::AuthorizationPending);
        }

        if parsed.code != 0 {
            return Err(CodeBuddyOAuthError::TokenFetchFailed(format!(
                "登录轮询返回错误码: {}",
                parsed.code
            )));
        }

        let data = parsed.data.ok_or_else(|| {
            CodeBuddyOAuthError::ParseError("响应缺少 data 字段".to_string())
        })?;

        log::info!("[CodeBuddyOAuth] 用户已完成登录");

        // 清理 pending flow
        {
            let mut flows = self.pending_flows.write().await;
            flows.remove(flow_id);
        }

        let claims = parse_jwt_claims(&data.access_token).ok_or_else(|| {
            CodeBuddyOAuthError::ParseError(
                "无法解析 access_token 中的账号信息".to_string(),
            )
        })?;

        let account_id = claims
            .email
            .clone()
            .or_else(|| claims.sub.clone())
            .ok_or_else(|| {
                CodeBuddyOAuthError::ParseError(
                    "access_token 缺少 email/sub 字段".to_string(),
                )
            })?;

        let expires_at_ms = claims
            .exp
            .map(|exp| exp * 1000)
            .unwrap_or_else(|| chrono::Utc::now().timestamp_millis() + 3_600_000);

        let user_id = claims
            .sub
            .clone()
            .or_else(|| claims.email.clone())
            .unwrap_or_else(|| CodeBuddyAuthProfile::default_user_id().to_string());

        let account = self
            .add_account_internal(
                account_id,
                data.access_token,
                claims.email,
                expires_at_ms,
                Some(user_id),
                profile.clone(),
            )
            .await?;

        Ok(Some(account))
    }

    // ==================== Runtime Auth ====================

    /// 获取指定账号的完整运行时凭证（token + user_id + profile）
    ///
    /// 一次读取返回所有请求所需字段，避免 forwarder 多次读取产生不一致快照。
    pub async fn get_runtime_auth_for_account(
        &self,
        account_id: &str,
    ) -> Result<CodeBuddyRuntimeAuth, CodeBuddyOAuthError> {
        let tokens = self.access_tokens.read().await;
        let cached = tokens
            .get(account_id)
            .ok_or_else(|| CodeBuddyOAuthError::AccountNotFound(account_id.to_string()))?;

        if cached.is_expired() {
            return Err(CodeBuddyOAuthError::TokenExpired);
        }

        let accounts = self.accounts.read().await;
        let account = accounts
            .get(account_id)
            .ok_or_else(|| CodeBuddyOAuthError::AccountNotFound(account_id.to_string()))?;

        Ok(CodeBuddyRuntimeAuth {
            access_token: cached.token.clone(),
            user_id: account
                .user_id
                .clone()
                .unwrap_or_else(|| CodeBuddyAuthProfile::default_user_id().to_string()),
            profile: account.profile.clone(),
        })
    }

    /// 获取默认账号的完整运行时凭证
    pub async fn get_runtime_auth(
        &self,
    ) -> Result<CodeBuddyRuntimeAuth, CodeBuddyOAuthError> {
        match self.resolve_default_account_id().await {
            Some(id) => self.get_runtime_auth_for_account(&id).await,
            None => Err(CodeBuddyOAuthError::AccountNotFound(
                "无可用的 CodeBuddy 账号".to_string(),
            )),
        }
    }

    // ==================== Token 获取（兼容旧签名） ====================

    pub async fn get_valid_token_for_account(
        &self,
        account_id: &str,
    ) -> Result<String, CodeBuddyOAuthError> {
        self.get_runtime_auth_for_account(account_id)
            .await
            .map(|a| a.access_token)
    }

    pub async fn get_valid_token(&self) -> Result<String, CodeBuddyOAuthError> {
        self.get_runtime_auth().await.map(|a| a.access_token)
    }

    /// 获取默认账号 ID
    pub async fn default_account_id(&self) -> Option<String> {
        self.resolve_default_account_id().await
    }

    // ==================== 多账号管理 ====================

    pub async fn list_accounts(&self) -> Vec<GitHubAccount> {
        let accounts = self.accounts.read().await.clone();
        let default_id = self.resolve_default_account_id().await;
        Self::sorted_accounts(&accounts, default_id.as_deref())
    }

    pub async fn remove_account(
        &self,
        account_id: &str,
    ) -> Result<(), CodeBuddyOAuthError> {
        log::info!("[CodeBuddyOAuth] 移除账号: {account_id}");

        {
            let mut accounts = self.accounts.write().await;
            if accounts.remove(account_id).is_none() {
                return Err(CodeBuddyOAuthError::AccountNotFound(
                    account_id.to_string(),
                ));
            }
        }

        {
            let mut tokens = self.access_tokens.write().await;
            tokens.remove(account_id);
        }

        {
            let accounts = self.accounts.read().await;
            let mut default = self.default_account_id.write().await;
            if default.as_deref() == Some(account_id) {
                *default = Self::fallback_default_account_id(&accounts);
            }
        }

        self.save_to_disk().await?;
        Ok(())
    }

    pub async fn set_default_account(
        &self,
        account_id: &str,
    ) -> Result<(), CodeBuddyOAuthError> {
        {
            let accounts = self.accounts.read().await;
            if !accounts.contains_key(account_id) {
                return Err(CodeBuddyOAuthError::AccountNotFound(
                    account_id.to_string(),
                ));
            }
        }

        {
            let mut default = self.default_account_id.write().await;
            *default = Some(account_id.to_string());
        }

        self.save_to_disk().await?;
        Ok(())
    }

    pub async fn clear_auth(&self) -> Result<(), CodeBuddyOAuthError> {
        log::info!("[CodeBuddyOAuth] 清除所有认证");

        {
            let mut accounts = self.accounts.write().await;
            accounts.clear();
        }
        {
            let mut default = self.default_account_id.write().await;
            *default = None;
        }
        {
            let mut tokens = self.access_tokens.write().await;
            tokens.clear();
        }
        {
            let mut flows = self.pending_flows.write().await;
            flows.clear();
        }

        if self.storage_path.exists() {
            std::fs::remove_file(&self.storage_path)?;
        }

        Ok(())
    }

    pub async fn is_authenticated(&self) -> bool {
        let accounts = self.accounts.read().await;
        !accounts.is_empty()
    }

    pub async fn get_status(&self) -> CodeBuddyOAuthStatus {
        let accounts_map = self.accounts.read().await.clone();
        let default_id = self.resolve_default_account_id().await;
        let account_list =
            Self::sorted_accounts(&accounts_map, default_id.as_deref());
        let authenticated = !account_list.is_empty();
        let username = default_id
            .as_ref()
            .and_then(|id| accounts_map.get(id))
            .and_then(|a| a.email.clone())
            .or_else(|| account_list.first().map(|a| a.login.clone()));

        CodeBuddyOAuthStatus {
            accounts: account_list,
            default_account_id: default_id,
            authenticated,
            username,
        }
    }

    // ==================== 内部方法 ====================

    async fn add_account_internal(
        &self,
        account_id: String,
        access_token: String,
        email: Option<String>,
        expires_at_ms: i64,
        user_id: Option<String>,
        profile: CodeBuddyAuthProfile,
    ) -> Result<GitHubAccount, CodeBuddyOAuthError> {
        let now = chrono::Utc::now().timestamp();

        let data = CodeBuddyAccountData {
            account_id: account_id.clone(),
            email,
            access_token: access_token.clone(),
            expires_at_ms,
            authenticated_at: now,
            user_id,
            profile,
        };

        let account = GitHubAccount::from(&data);

        {
            let mut accounts = self.accounts.write().await;
            accounts.insert(account_id.clone(), data);
        }

        {
            let mut tokens = self.access_tokens.write().await;
            tokens.insert(
                account_id.clone(),
                CachedAccessToken {
                    token: access_token,
                    expires_at_ms,
                },
            );
        }

        {
            let mut default = self.default_account_id.write().await;
            if default.is_none() {
                *default = Some(account_id);
            }
        }

        self.save_to_disk().await?;
        Ok(account)
    }

    fn fallback_default_account_id(
        accounts: &HashMap<String, CodeBuddyAccountData>,
    ) -> Option<String> {
        accounts
            .iter()
            .max_by(|(id_a, a), (id_b, b)| {
                a.authenticated_at
                    .cmp(&b.authenticated_at)
                    .then_with(|| id_b.cmp(id_a))
            })
            .map(|(id, _)| id.clone())
    }

    fn sorted_accounts(
        accounts: &HashMap<String, CodeBuddyAccountData>,
        default_account_id: Option<&str>,
    ) -> Vec<GitHubAccount> {
        let mut list: Vec<GitHubAccount> =
            accounts.values().map(GitHubAccount::from).collect();
        list.sort_by(|a, b| {
            let a_default = default_account_id == Some(a.id.as_str());
            let b_default = default_account_id == Some(b.id.as_str());
            b_default
                .cmp(&a_default)
                .then_with(|| b.authenticated_at.cmp(&a.authenticated_at))
                .then_with(|| a.login.cmp(&b.login))
        });
        list
    }

    async fn resolve_default_account_id(&self) -> Option<String> {
        let stored = self.default_account_id.read().await.clone();
        let accounts = self.accounts.read().await;

        if let Some(id) = stored {
            if accounts.contains_key(&id) {
                return Some(id);
            }
        }

        Self::fallback_default_account_id(&accounts)
    }

    fn write_store_atomic(&self, content: &str) -> Result<(), CodeBuddyOAuthError> {
        if let Some(parent) = self.storage_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let parent = self
            .storage_path
            .parent()
            .ok_or_else(|| CodeBuddyOAuthError::IoError("无效的存储路径".to_string()))?;
        let file_name = self
            .storage_path
            .file_name()
            .ok_or_else(|| {
                CodeBuddyOAuthError::IoError("无效的存储文件名".to_string())
            })?
            .to_string_lossy()
            .to_string();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let tmp_path = parent.join(format!("{file_name}.tmp.{ts}"));

        #[cfg(unix)]
        {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

            let mut file = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&tmp_path)?;
            file.write_all(content.as_bytes())?;
            file.flush()?;

            fs::rename(&tmp_path, &self.storage_path)?;
            fs::set_permissions(
                &self.storage_path,
                fs::Permissions::from_mode(0o600),
            )?;
        }

        #[cfg(windows)]
        {
            let mut file = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&tmp_path)?;
            file.write_all(content.as_bytes())?;
            file.flush()?;

            if self.storage_path.exists() {
                let _ = fs::remove_file(&self.storage_path);
            }
            fs::rename(&tmp_path, &self.storage_path)?;
        }

        Ok(())
    }

    fn load_from_disk_sync(&self) -> Result<(), CodeBuddyOAuthError> {
        if !self.storage_path.exists() {
            return Ok(());
        }

        let content = std::fs::read_to_string(&self.storage_path)?;

        // 先尝试解析为通用 JSON Value，按 version 字段决定反序列化路径
        let raw: serde_json::Value = serde_json::from_str(&content)
            .map_err(|e| CodeBuddyOAuthError::ParseError(e.to_string()))?;

        let version = raw
            .get("version")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;

        let store: CodeBuddyOAuthStore = match version {
            0 | 1 => {
                // v1 格式：无 profile/user_id 字段，按国际站默认填充
                let store_v1: CodeBuddyOAuthStoreV1 = serde_json::from_str(&content)
                    .map_err(|e| CodeBuddyOAuthError::ParseError(e.to_string()))?;
                store_v1.migrate_to_v2()
            }
            _ => serde_json::from_str(&content)
                .map_err(|e| CodeBuddyOAuthError::ParseError(e.to_string()))?,
        };

        if let Ok(mut accounts) = self.accounts.try_write() {
            *accounts = store.accounts;
            log::info!(
                "[CodeBuddyOAuth] 从磁盘加载 {} 个账号 (v{})",
                accounts.len(),
                if version < 2 { 2 } else { version }
            );
        }
        if let Ok(mut default) = self.default_account_id.try_write() {
            *default = store.default_account_id;
            if default.is_none() {
                if let Ok(accounts) = self.accounts.try_read() {
                    *default = Self::fallback_default_account_id(&accounts);
                }
            }
        }
        if let Ok(accounts) = self.accounts.try_read() {
            if let Ok(mut tokens) = self.access_tokens.try_write() {
                for (id, data) in accounts.iter() {
                    tokens.insert(
                        id.clone(),
                        CachedAccessToken {
                            token: data.access_token.clone(),
                            expires_at_ms: data.expires_at_ms,
                        },
                    );
                }
            }
        }

        // 如果是从 v1 迁移的，自动写回 v2 格式
        if version < 2 {
            let accounts = self.accounts.try_read();
            let default_id = self.default_account_id.try_read();
            if let (Ok(accounts), Ok(default)) = (accounts, default_id) {
                let store = CodeBuddyOAuthStore {
                    version: 2,
                    accounts: accounts.clone(),
                    default_account_id: default.clone(),
                };
                if let Ok(content) =
                    serde_json::to_string_pretty(&store)
                {
                    let _ = self.write_store_atomic(&content);
                }
            }
        }

        Ok(())
    }

    async fn save_to_disk(&self) -> Result<(), CodeBuddyOAuthError> {
        let accounts = self.accounts.read().await.clone();
        let default = self.resolve_default_account_id().await;

        let store = CodeBuddyOAuthStore {
            version: 2,
            accounts,
            default_account_id: default,
        };

        let content = serde_json::to_string_pretty(&store)
            .map_err(|e| CodeBuddyOAuthError::ParseError(e.to_string()))?;

        self.write_store_atomic(&content)?;

        log::info!(
            "[CodeBuddyOAuth] 保存到磁盘成功（{} 个账号）",
            store.accounts.len()
        );

        Ok(())
    }
}

// ============================================================================
// V1 Migration Types
// ============================================================================

/// v1 持久化存储（向后兼容读取）
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct CodeBuddyOAuthStoreV1 {
    #[serde(default)]
    version: u32,
    #[serde(default)]
    accounts: HashMap<String, CodeBuddyAccountDataV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    default_account_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CodeBuddyAccountDataV1 {
    pub account_id: String,
    #[serde(default)]
    pub email: Option<String>,
    pub access_token: String,
    pub expires_at_ms: i64,
    pub authenticated_at: i64,
}

impl CodeBuddyOAuthStoreV1 {
    fn migrate_to_v2(self) -> CodeBuddyOAuthStore {
        let accounts = self
            .accounts
            .into_iter()
            .map(|(id, v1_data)| {
                // 从 access_token 解析 user_id
                let user_id = parse_jwt_claims(&v1_data.access_token)
                    .and_then(|claims| claims.sub.or(claims.email))
                    .or_else(|| v1_data.email.clone());

                let v2_data = CodeBuddyAccountData {
                    account_id: v1_data.account_id,
                    email: v1_data.email,
                    access_token: v1_data.access_token,
                    expires_at_ms: v1_data.expires_at_ms,
                    authenticated_at: v1_data.authenticated_at,
                    user_id,
                    profile: CodeBuddyAuthProfile::international(),
                };
                (id, v2_data)
            })
            .collect();

        CodeBuddyOAuthStore {
            version: 2,
            accounts,
            default_account_id: self.default_account_id,
        }
    }
}

// ============================================================================
// Status
// ============================================================================

/// CodeBuddy OAuth 状态摘要
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeBuddyOAuthStatus {
    pub accounts: Vec<GitHubAccount>,
    pub default_account_id: Option<String>,
    pub authenticated: bool,
    pub username: Option<String>,
}

// ============================================================================
// Utility Functions
// ============================================================================

/// 生成 32 字符十六进制 nonce
fn generate_nonce_hex() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

/// 解析 JWT 中的 claims
fn parse_jwt_claims(token: &str) -> Option<AccessTokenClaims> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let decoded = URL_SAFE_NO_PAD.decode(parts[1]).ok()?;
    serde_json::from_slice(&decoded).ok()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_jwt(payload_json: &str) -> String {
        let header = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"none\"}");
        let payload = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
        format!("{header}.{payload}.sig")
    }

    // ---- Profile / Site Config ----

    #[test]
    fn profile_international_has_correct_defaults() {
        let p = CodeBuddyAuthProfile::international();
        assert_eq!(p.site_type, CodeBuddySiteType::International);
        assert!(p.api_endpoint.starts_with("https://www.codebuddy.ai"));
        assert_eq!(p.product_header(), "SaaS");
        assert!(p.enterprise_id.is_none());
    }

    #[test]
    fn profile_china_has_correct_defaults() {
        let p = CodeBuddyAuthProfile::china();
        assert_eq!(p.site_type, CodeBuddySiteType::China);
        assert!(p.api_endpoint.starts_with("https://www.codebuddy.cn"));
        assert_eq!(p.product_header(), "SaaS");
    }

    #[test]
    fn profile_enterprise_rejects_empty_endpoint() {
        let r = CodeBuddyAuthProfile::enterprise(
            "".to_string(),
            "ent-1".to_string(),
            None,
        );
        assert!(r.is_err());
    }

    #[test]
    fn profile_enterprise_rejects_http() {
        let r = CodeBuddyAuthProfile::enterprise(
            "http://evil.com".to_string(),
            "ent-1".to_string(),
            None,
        );
        assert!(r.is_err());
        assert!(
            r.unwrap_err()
                .to_string()
                .contains("HTTPS")
        );
    }

    #[test]
    fn profile_enterprise_rejects_url_with_credentials() {
        let r = CodeBuddyAuthProfile::enterprise(
            "https://user:pass@example.com".to_string(),
            "ent-1".to_string(),
            None,
        );
        assert!(r.is_err());
    }

    #[test]
    fn profile_enterprise_rejects_url_with_query() {
        let r = CodeBuddyAuthProfile::enterprise(
            "https://example.com?foo=bar".to_string(),
            "ent-1".to_string(),
            None,
        );
        assert!(r.is_err());
    }

    #[test]
    fn profile_enterprise_rejects_url_with_fragment() {
        let r = CodeBuddyAuthProfile::enterprise(
            "https://example.com#section".to_string(),
            "ent-1".to_string(),
            None,
        );
        assert!(r.is_err());
    }

    #[test]
    fn profile_enterprise_rejects_bare_ip() {
        let r = CodeBuddyAuthProfile::enterprise(
            "https://10.0.0.1".to_string(),
            "ent-1".to_string(),
            None,
        );
        assert!(r.is_err());
    }

    #[test]
    fn profile_enterprise_rejects_empty_enterprise_id() {
        let r = CodeBuddyAuthProfile::enterprise(
            "https://example.com".to_string(),
            "".to_string(),
            None,
        );
        assert!(r.is_err());
    }

    #[test]
    fn profile_enterprise_normalizes_trailing_slash() {
        let p = CodeBuddyAuthProfile::enterprise(
            "https://example.com".to_string(),
            "ent-1".to_string(),
            None,
        )
        .expect("valid");
        assert_eq!(p.api_endpoint, "https://example.com/");
    }

    #[test]
    fn profile_enterprise_rejects_ua_with_newline() {
        let r = CodeBuddyAuthProfile::enterprise(
            "https://example.com".to_string(),
            "ent-1".to_string(),
            Some("Evil\nHeader: injected".to_string()),
        );
        assert!(r.is_err());
    }

    #[test]
    fn profile_enterprise_accepts_valid_ua() {
        let p = CodeBuddyAuthProfile::enterprise(
            "https://example.com".to_string(),
            "ent-1".to_string(),
            Some("CodeBuddyIDE/5.0".to_string()),
        )
        .expect("valid");
        assert_eq!(p.effective_user_agent(), "CodeBuddyIDE/5.0");
    }

    #[test]
    fn profile_enterprise_defaults_ua_when_none() {
        let p = CodeBuddyAuthProfile::enterprise(
            "https://example.com".to_string(),
            "ent-1".to_string(),
            None,
        )
        .expect("valid");
        assert_eq!(p.effective_user_agent(), DEFAULT_ENTERPRISE_USER_AGENT);
    }

    #[test]
    fn profile_accepts_enterprise_internal_domain() {
        // 企业内部域名是合法使用场景
        let p = CodeBuddyAuthProfile::enterprise(
            "https://codebuddy.internal.corp.example.com".to_string(),
            "ent-1".to_string(),
            None,
        )
        .expect("internal domain should be valid");
        assert_eq!(
            p.api_endpoint,
            "https://codebuddy.internal.corp.example.com/"
        );
    }

    #[test]
    fn normalize_endpoint_preserves_nondefault_port() {
        let p = CodeBuddyAuthProfile::enterprise(
            "https://codebuddy.internal.corp.example.com:8443".to_string(),
            "ent-1".to_string(),
            None,
        )
        .expect("port should be valid");
        assert_eq!(
            p.api_endpoint,
            "https://codebuddy.internal.corp.example.com:8443/"
        );
    }

    #[test]
    fn host_extraction_works() {
        assert_eq!(
            extract_host_from_url("https://www.codebuddy.ai/"),
            "www.codebuddy.ai"
        );
        assert_eq!(
            extract_host_from_url("https://codebuddy.cn/v2/chat/completions"),
            "codebuddy.cn"
        );
        assert_eq!(
            extract_host_from_url("https://example.com:8443/"),
            "example.com"
        );
    }

    // ---- Auth Headers ----

    #[test]
    fn auth_start_headers_saas() {
        let profile = CodeBuddyAuthProfile::international();
        let headers = build_auth_start_headers(&profile);
        let keys: Vec<&str> = headers.iter().map(|(k, _)| *k).collect();

        assert!(keys.contains(&"X-Product"));
        // find SaaS value
        let product = headers
            .iter()
            .find(|(k, _)| *k == "X-Product")
            .map(|(_, v)| v.as_str());
        assert_eq!(product, Some("SaaS"));
        assert!(keys.contains(&"X-No-Authorization"));
        assert!(!keys.contains(&"X-Enterprise-Id"));
        assert!(!keys.contains(&"X-Tenant-Id"));
    }

    #[test]
    fn auth_start_headers_enterprise() {
        let profile = CodeBuddyAuthProfile::enterprise(
            "https://enterprise.example.com".to_string(),
            "my-ent-id".to_string(),
            Some("TestUA/1.0".to_string()),
        )
        .expect("valid");
        let headers = build_auth_start_headers(&profile);

        let product = headers
            .iter()
            .find(|(k, _)| *k == "X-Product")
            .map(|(_, v)| v.as_str());
        assert_eq!(product, Some("Cloud-Hosted"));

        let ent_id = headers
            .iter()
            .find(|(k, _)| *k == "X-Enterprise-Id")
            .map(|(_, v)| v.as_str());
        assert_eq!(ent_id, Some("my-ent-id"));

        let tenant = headers
            .iter()
            .find(|(k, _)| *k == "X-Tenant-Id")
            .map(|(_, v)| v.as_str());
        assert_eq!(tenant, Some("my-ent-id"));

        let ua = headers
            .iter()
            .find(|(k, _)| *k == "User-Agent")
            .map(|(_, v)| v.as_str());
        assert_eq!(ua, Some("TestUA/1.0"));
    }

    #[test]
    fn auth_poll_headers_has_trace_fields() {
        let profile = CodeBuddyAuthProfile::international();
        let headers = build_auth_poll_headers(&profile);
        let keys: Vec<&str> = headers.iter().map(|(k, _)| *k).collect();
        assert!(keys.contains(&"b3"));
        assert!(keys.contains(&"X-B3-TraceId"));
        assert!(keys.contains(&"X-B3-SpanId"));
    }

    #[test]
    fn chat_headers_saas() {
        let profile = CodeBuddyAuthProfile::international();
        let headers = build_chat_headers("token123", "user-1", &profile);
        let product = headers
            .iter()
            .find(|(k, _)| *k == "X-Product")
            .map(|(_, v)| v.as_str());
        assert_eq!(product, Some("SaaS"));

        // SaaS should not have enterprise headers
        let has_enterprise = headers.iter().any(|(k, _)| *k == "X-Enterprise-Id");
        assert!(!has_enterprise);

        // SaaS should have stainless headers
        let has_stainless = headers
            .iter()
            .any(|(k, _)| k.starts_with("x-stainless-"));
        assert!(has_stainless);
    }

    #[test]
    fn chat_headers_enterprise() {
        let profile = CodeBuddyAuthProfile::enterprise(
            "https://enterprise.example.com".to_string(),
            "my-ent-id".to_string(),
            None,
        )
        .expect("valid");
        let headers = build_chat_headers("token123", "user-1", &profile);
        let product = headers
            .iter()
            .find(|(k, _)| *k == "X-Product")
            .map(|(_, v)| v.as_str());
        assert_eq!(product, Some("Cloud-Hosted"));

        let ent_id = headers
            .iter()
            .find(|(k, _)| *k == "X-Enterprise-Id")
            .map(|(_, v)| v.as_str());
        assert_eq!(ent_id, Some("my-ent-id"));

        let user_id = headers
            .iter()
            .find(|(k, _)| *k == "X-User-Id")
            .map(|(_, v)| v.as_str());
        assert_eq!(user_id, Some("user-1"));
    }

    #[test]
    fn chat_url_construction() {
        let p = CodeBuddyAuthProfile::international();
        assert_eq!(
            build_chat_url(&p),
            "https://www.codebuddy.ai/v2/chat/completions"
        );

        let p = CodeBuddyAuthProfile::enterprise(
            "https://enterprise.example.com".to_string(),
            "ent-1".to_string(),
            None,
        )
        .expect("valid");
        assert_eq!(
            build_chat_url(&p),
            "https://enterprise.example.com/v2/chat/completions"
        );
    }

    // ---- Store Migration ----

    #[test]
    fn v1_to_v2_migration_preserves_account_ids() {
        let v1_data = CodeBuddyAccountDataV1 {
            account_id: "test@example.com".to_string(),
            email: Some("test@example.com".to_string()),
            access_token: make_jwt(
                r#"{"email":"test@example.com","sub":"abc123","exp":1999999999}"#,
            ),
            expires_at_ms: 1999999999000,
            authenticated_at: 1000,
        };

        let mut accounts = HashMap::new();
        accounts.insert("test@example.com".to_string(), v1_data);

        let store_v1 = CodeBuddyOAuthStoreV1 {
            version: 1,
            accounts,
            default_account_id: Some("test@example.com".to_string()),
        };

        let store_v2 = store_v1.migrate_to_v2();
        assert_eq!(store_v2.version, 2);
        let migrated = store_v2
            .accounts
            .get("test@example.com")
            .expect("account should exist");
        assert_eq!(migrated.account_id, "test@example.com");
        assert_eq!(migrated.profile.site_type, CodeBuddySiteType::International);
        assert_eq!(migrated.user_id, Some("abc123".to_string()));
        assert_eq!(
            store_v2.default_account_id,
            Some("test@example.com".to_string())
        );
    }

    #[test]
    fn v1_migration_without_sub_uses_email_as_user_id() {
        let v1_data = CodeBuddyAccountDataV1 {
            account_id: "test@example.com".to_string(),
            email: Some("test@example.com".to_string()),
            access_token: make_jwt(
                r#"{"email":"test@example.com","exp":1999999999}"#,
            ),
            expires_at_ms: 1999999999000,
            authenticated_at: 1000,
        };

        let mut accounts = HashMap::new();
        accounts.insert("test@example.com".to_string(), v1_data);

        let store_v1 = CodeBuddyOAuthStoreV1 {
            version: 1,
            accounts,
            default_account_id: None,
        };

        let store_v2 = store_v1.migrate_to_v2();
        let migrated =
            store_v2.accounts.get("test@example.com").expect("should exist");
        assert_eq!(migrated.user_id, Some("test@example.com".to_string()));
    }

    // ---- JWT Parsing ----

    #[test]
    fn parse_jwt_claims_extracts_email_and_exp() {
        let token =
            make_jwt(r#"{"email":"user@example.com","sub":"abc123","exp":1999999999}"#);
        let claims = parse_jwt_claims(&token).expect("claims should parse");
        assert_eq!(claims.email.as_deref(), Some("user@example.com"));
        assert_eq!(claims.sub.as_deref(), Some("abc123"));
        assert_eq!(claims.exp, Some(1999999999));
    }

    #[test]
    fn parse_jwt_claims_rejects_malformed_token() {
        assert!(parse_jwt_claims("not-a-jwt").is_none());
        assert!(parse_jwt_claims("a.b").is_none());
    }

    // ---- Cache ----

    #[test]
    fn cached_access_token_expiry() {
        let expired = CachedAccessToken {
            token: "t".to_string(),
            expires_at_ms: chrono::Utc::now().timestamp_millis() - 1000,
        };
        assert!(expired.is_expired());

        let valid = CachedAccessToken {
            token: "t".to_string(),
            expires_at_ms: chrono::Utc::now().timestamp_millis() + 60_000,
        };
        assert!(!valid.is_expired());
    }

    #[test]
    fn generate_nonce_hex_is_32_hex_chars() {
        let nonce = generate_nonce_hex();
        assert_eq!(nonce.len(), 32);
        assert!(nonce.chars().all(|c| c.is_ascii_hexdigit()));
    }

    // ---- Token ----

    #[tokio::test]
    async fn get_valid_token_for_account_not_found() {
        let dir = std::env::temp_dir().join(format!(
            "cc-switch-codebuddy-test-{}",
            chrono::Utc::now()
                .timestamp_nanos_opt()
                .unwrap_or_default()
        ));
        let manager = CodeBuddyOAuthManager::new(dir);
        let result = manager.get_valid_token_for_account("nonexistent").await;
        assert!(matches!(
            result,
            Err(CodeBuddyOAuthError::AccountNotFound(_))
        ));
    }

    #[tokio::test]
    async fn get_valid_token_for_account_expired() {
        let dir = std::env::temp_dir().join(format!(
            "cc-switch-codebuddy-test-{}",
            chrono::Utc::now()
                .timestamp_nanos_opt()
                .unwrap_or_default()
        ));
        let manager = CodeBuddyOAuthManager::new(dir);
        manager
            .add_account_internal(
                "user@example.com".to_string(),
                "expired-token".to_string(),
                Some("user@example.com".to_string()),
                chrono::Utc::now().timestamp_millis() - 1000,
                Some("uid".to_string()),
                CodeBuddyAuthProfile::international(),
            )
            .await
            .expect("add account should succeed");

        let result = manager
            .get_valid_token_for_account("user@example.com")
            .await;
        assert!(matches!(result, Err(CodeBuddyOAuthError::TokenExpired)));
    }

    #[tokio::test]
    async fn get_valid_token_for_account_valid() {
        let dir = std::env::temp_dir().join(format!(
            "cc-switch-codebuddy-test-{}",
            chrono::Utc::now()
                .timestamp_nanos_opt()
                .unwrap_or_default()
        ));
        let manager = CodeBuddyOAuthManager::new(dir);
        manager
            .add_account_internal(
                "user@example.com".to_string(),
                "valid-token".to_string(),
                Some("user@example.com".to_string()),
                chrono::Utc::now().timestamp_millis() + 60_000,
                Some("uid".to_string()),
                CodeBuddyAuthProfile::international(),
            )
            .await
            .expect("add account should succeed");

        let token = manager
            .get_valid_token_for_account("user@example.com")
            .await
            .expect("token should be valid");
        assert_eq!(token, "valid-token");
    }
}
