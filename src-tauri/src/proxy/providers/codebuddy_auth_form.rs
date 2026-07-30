//! CodeBuddy 本地认证配置页服务器
//!
//! 在 `127.0.0.1:0` 绑定一次性 Axum HTTP 服务，提供站点选择表单。
//! 用户提交配置后，服务向对应 CodeBuddy 站点请求上游 authUrl 并 303 跳转。
//!
//! ## 安全边界
//! - 严格绑定 loopback（127.0.0.1），不监听 LAN/公网地址
//! - 单次 POST（一次提交后服务关闭）
//! - CSRF 双向校验（flow 参数 + 独立 csrf_token）
//! - Host / Origin 校验
//! - 请求体大小限制
//! - 超时自动关闭

use axum::{
    body::Body,
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, Response},
    routing::{get, post},
    Router,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::RwLock;

use super::codebuddy_oauth_auth::{
    build_auth_start_headers, CodeBuddyAuthProfile, PendingFlow,
    AUTH_STATE_DEFAULT_EXPIRES_IN, CONFIG_SERVER_TIMEOUT_SECS, MAX_FORM_BODY_BYTES,
};

/// 本地配置页服务器绑定地址
const BIND_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);

/// 表单 POST 请求体
#[derive(Debug, Deserialize)]
struct FormSubmit {
    site_type: String,
    csrf_token: String,
    #[serde(default)]
    endpoint: Option<String>,
    #[serde(default)]
    enterprise_id: Option<String>,
    #[serde(default)]
    user_agent: Option<String>,
}

/// GET 查询参数（仅用于 flow 标识）
#[derive(Debug, Deserialize)]
struct FlowQuery {
    flow: Option<String>,
}

/// 服务器共享状态
#[derive(Clone)]
struct AppState {
    flow_id: String,
    csrf_token: String,
    pending_flows: Arc<RwLock<HashMap<String, PendingFlow>>>,
    expires_at_ms: i64,
    submitted: Arc<AtomicBool>,
}

/// 站点选择表单 HTML
fn form_html(csrf_token: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CodeBuddy 认证配置</title>
<style>
:root {{
  --bg: #f8f9fa;
  --card-bg: #fff;
  --text: #1a1a2e;
  --muted: #6b7280;
  --border: #e5e7eb;
  --primary: #2563eb;
  --primary-hover: #1d4ed8;
  --danger: #ef4444;
  --radius: 10px;
  --shadow: 0 1px 3px rgba(0,0,0,.08), 0 1px 2px rgba(0,0,0,.06);
}}
@media (prefers-color-scheme:dark) {{
  :root {{
    --bg: #111827;
    --card-bg: #1f2937;
    --text: #f3f4f6;
    --muted: #9ca3af;
    --border: #374151;
  }}
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  background: var(--bg); color: var(--text);
  display: flex; align-items: center; justify-content: center;
  min-height: 100vh; padding: 1rem;
}}
.card {{
  background: var(--card-bg);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  box-shadow: var(--shadow);
  padding: 2rem; max-width: 480px; width: 100%;
}}
h1 {{
  font-size: 1.25rem; font-weight: 600; margin-bottom: .5rem;
  display: flex; align-items: center; gap: .5rem;
}}
.subtitle {{ color: var(--muted); font-size: .875rem; margin-bottom: 1.5rem; }}
.field {{ margin-bottom: 1rem; }}
label {{
  display: block; font-size: .875rem; font-weight: 500;
  margin-bottom: .25rem; color: var(--text);
}}
label .required {{ color: var(--danger); }}
input[type=text], input[type=url], select {{
  width: 100%; padding: .625rem .75rem;
  border: 1px solid var(--border); border-radius: .5rem;
  font-size: .875rem; background: var(--bg); color: var(--text);
  transition: border-color .15s;
}}
input:focus, select:focus {{ outline: none; border-color: var(--primary); }}
.radio-group {{ display: flex; gap: .5rem; }}
.radio-group label {{
  flex: 1; display: flex; align-items: center; gap: .375rem;
  padding: .625rem .75rem; border: 2px solid var(--border);
  border-radius: .5rem; cursor: pointer; font-size: .875rem;
  transition: all .15s; justify-content: center; background: var(--bg);
}}
.radio-group label:hover {{ border-color: var(--primary); }}
.radio-group label.active {{ border-color: var(--primary); background: rgba(37,99,235,.08); }}
.radio-group input[type=radio] {{ display: none; }}
.hidden {{ display: none !important; }}
.buttons {{ display: flex; gap: .5rem; margin-top: 1.5rem; }}
.btn {{
  flex: 1; padding: .625rem; border: none; border-radius: .5rem;
  font-size: .875rem; font-weight: 500; cursor: pointer; transition: opacity .15s;
}}
.btn-primary {{ background: var(--primary); color: #fff; }}
.btn-primary:hover {{ background: var(--primary-hover); }}
.btn-secondary {{ background: var(--bg); color: var(--text); border: 1px solid var(--border); }}
.btn:disabled {{ opacity: .5; cursor: not-allowed; }}
.error-msg {{ color: var(--danger); font-size: .875rem; margin-top: .75rem; display: none; }}
.error-msg.visible {{ display: block; }}
.spinner {{
  display: inline-block; width: 1rem; height: 1rem; border: 2px solid transparent;
  border-top-color: #fff; border-radius: 50%; animation: spin .6s linear infinite;
  vertical-align: middle; margin-right: .375rem;
}}
@keyframes spin {{ to {{ transform: rotate(360deg); }} }}
</style>
</head>
<body>
<div class="card">
  <h1>CodeBuddy 认证</h1>
  <p class="subtitle">选择站点类型。企业版需填写 API 端点、企业标识和可选 User-Agent。</p>
  <div class="field">
    <label>站点类型</label>
    <div class="radio-group" id="siteTypeGroup">
      <label class="active" data-value="international">
        <input type="radio" name="siteType" value="international" checked> 国际站
      </label>
      <label data-value="china">
        <input type="radio" name="siteType" value="china"> 中国站
      </label>
      <label data-value="enterprise">
        <input type="radio" name="siteType" value="enterprise"> 企业版
      </label>
    </div>
  </div>
  <div id="enterpriseFields" class="hidden">
    <div class="field">
      <label for="endpoint">API 端点 <span class="required">*</span></label>
      <input type="url" id="endpoint" placeholder="https://your-enterprise.example.com" autocomplete="off">
    </div>
    <div class="field">
      <label for="enterpriseId">企业标识 <span class="required">*</span></label>
      <input type="text" id="enterpriseId" placeholder="如: your-company-id" autocomplete="off">
    </div>
    <div class="field">
      <label for="userAgent">User-Agent (可选)</label>
      <input type="text" id="userAgent" placeholder="如: CodeBuddyIDE/1.115.0" autocomplete="off">
    </div>
  </div>
  <div class="buttons">
    <button class="btn btn-primary" id="submitBtn" type="button">开始认证</button>
    <button class="btn btn-secondary" id="cancelBtn" type="button">取消</button>
  </div>
  <div class="error-msg" id="errorMsg"></div>
</div>
<script>
var siteTypeLabels = document.querySelectorAll('#siteTypeGroup label');
var enterpriseFields = document.getElementById('enterpriseFields');
var submitBtn = document.getElementById('submitBtn');
var cancelBtn = document.getElementById('cancelBtn');
var errorMsg = document.getElementById('errorMsg');
var endpoint = document.getElementById('endpoint');
var enterpriseId = document.getElementById('enterpriseId');
var userAgent = document.getElementById('userAgent');
var siteType = 'international';
siteTypeLabels.forEach(function(l) {{
  l.addEventListener('click', function() {{
    siteTypeLabels.forEach(function(x) {{ x.classList.remove('active'); }});
    l.classList.add('active');
    siteType = l.dataset.value;
    enterpriseFields.classList.toggle('hidden', siteType !== 'enterprise');
    errorMsg.classList.remove('visible');
  }});
}});
function showError(msg) {{
  errorMsg.textContent = msg;
  errorMsg.classList.add('visible');
}}
submitBtn.addEventListener('click', function() {{
  var body = {{ site_type: siteType, csrf_token: "{csrf_token}" }};
  if (siteType === 'enterprise') {{
    var ep = endpoint.value.trim();
    var eid = enterpriseId.value.trim();
    var ua = userAgent.value.trim();
    if (!ep) {{ showError('请填写 API 端点'); return; }}
    if (!eid) {{ showError('请填写企业标识'); return; }}
    body.endpoint = ep;
    body.enterprise_id = eid;
    if (ua) body.user_agent = ua;
  }}
  submitBtn.disabled = true;
  submitBtn.innerHTML = '<span class="spinner"></span> 提交中...';
  errorMsg.classList.remove('visible');
  fetch('/', {{
    method: 'POST',
    headers: {{ 'Content-Type': 'application/json', 'X-CSRF-Token': "{csrf_token}" }},
    body: JSON.stringify(body)
  }})
  .then(function(r) {{
    if (r.redirected) {{
      window.location.href = r.url;
    }} else {{
      return r.json().then(function(data) {{
        showError(data.error || '提交失败');
        submitBtn.disabled = false;
        submitBtn.textContent = '开始认证';
      }});
    }}
  }})
  .catch(function(e) {{
    showError('网络错误: ' + e.message);
    submitBtn.disabled = false;
    submitBtn.textContent = '开始认证';
  }});
}});
cancelBtn.addEventListener('click', function() {{
  fetch('/cancel', {{ method: 'POST' }}).then(function() {{
    document.body.innerHTML = '<div class="card"><h1>已取消</h1><p class="subtitle">此页面可以关闭。</p></div>';
  }});
}});
</script>
</body>
</html>"#
    )
}

/// 校验 Origin 和 Host 均为 loopback
fn validate_loopback_headers(headers: &HeaderMap) -> Result<(), (StatusCode, String)> {
    if let Some(host) = headers.get("host") {
        let host_str = host.to_str().unwrap_or("");
        let host_part = host_str.split(':').next().unwrap_or(host_str);
        if host_part != "127.0.0.1" && host_part != "localhost" {
            return Err((
                StatusCode::FORBIDDEN,
                "Invalid Host header".to_string(),
            ));
        }
    }

    if let Some(origin) = headers.get("origin") {
        let origin_str = origin.to_str().unwrap_or("");
        if !origin_str.starts_with("http://127.0.0.1:")
            && !origin_str.starts_with("http://localhost:")
        {
            return Err((
                StatusCode::FORBIDDEN,
                "Invalid Origin header".to_string(),
            ));
        }
    }

    Ok(())
}

/// 启动一次性配置页 HTTP 服务器，返回实际监听的端口
pub async fn start_config_server(
    flow_id: String,
    csrf_token: String,
    pending_flows: Arc<RwLock<HashMap<String, PendingFlow>>>,
    expires_at_ms: i64,
) -> Result<u16, Box<dyn std::error::Error + Send + Sync>> {
    let submitted = Arc::new(AtomicBool::new(false));

    let state = AppState {
        flow_id,
        csrf_token,
        pending_flows,
        expires_at_ms,
        submitted,
    };

    let app = Router::new()
        .route("/", get(serve_form).post(handle_submit))
        .route("/cancel", post(handle_cancel))
        .layer(
            tower_http::cors::CorsLayer::new()
                .allow_origin(tower_http::cors::AllowOrigin::predicate(
                    |origin, _| {
                        if let Ok(origin_str) = std::str::from_utf8(origin.as_bytes()) {
                            origin_str.starts_with("http://127.0.0.1:")
                                || origin_str.starts_with("http://localhost:")
                        } else {
                            false
                        }
                    },
                ))
                .allow_headers([
                    axum::http::header::CONTENT_TYPE,
                    axum::http::HeaderName::from_static("x-csrf-token"),
                ])
                .allow_methods([
                    axum::http::Method::GET,
                    axum::http::Method::POST,
                    axum::http::Method::OPTIONS,
                ]),
        )
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(BIND_ADDR).await?;
    let local_port = listener.local_addr()?.port();

    tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                tokio::time::sleep(std::time::Duration::from_secs(
                    CONFIG_SERVER_TIMEOUT_SECS,
                ))
                .await;
            })
            .await;
    });

    Ok(local_port)
}

/// GET / — 返回配置表单 HTML
async fn serve_form(
    State(state): State<AppState>,
    Query(query): Query<FlowQuery>,
) -> Result<Html<String>, (StatusCode, String)> {
    let flow = query.flow.unwrap_or_default();
    if flow != state.flow_id {
        return Err((StatusCode::FORBIDDEN, "无效的 flow 参数".to_string()));
    }

    let now_ms = chrono::Utc::now().timestamp_millis();
    if now_ms > state.expires_at_ms {
        return Err((
            StatusCode::GONE,
            "登录流程已过期，请重新启动".to_string(),
        ));
    }

    let html = form_html(&state.csrf_token);
    Ok(Html(html))
}

/// POST / — 处理站点配置提交
async fn handle_submit(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> Result<Response<Body>, (StatusCode, String)> {
    // 只允许一次提交
    if state.submitted.swap(true, Ordering::SeqCst) {
        return Err((
            StatusCode::GONE,
            "此配置页已提交，请关闭页面".to_string(),
        ));
    }

    // 校验 loopback headers
    validate_loopback_headers(&headers)?;

    // 大小限制
    if body.len() > MAX_FORM_BODY_BYTES {
        return Err((StatusCode::PAYLOAD_TOO_LARGE, "请求体过大".to_string()));
    }

    // Content-Type
    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !content_type.starts_with("application/json") {
        return Err((
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "Content-Type 必须为 application/json".to_string(),
        ));
    }

    // 解析 JSON
    let form: FormSubmit =
        serde_json::from_str(&body).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    // 校验 CSRF
    let csrf_header = headers
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if csrf_header != state.csrf_token || form.csrf_token != state.csrf_token {
        return Err((StatusCode::FORBIDDEN, "CSRF 校验失败".to_string()));
    }

    // 校验超时
    let now_ms = chrono::Utc::now().timestamp_millis();
    if now_ms > state.expires_at_ms {
        return Err((
            StatusCode::GONE,
            "登录流程已过期，请重新启动".to_string(),
        ));
    }

    // 根据站点类型构建 profile
    let profile = match form.site_type.as_str() {
        "international" => CodeBuddyAuthProfile::international(),
        "china" => CodeBuddyAuthProfile::china(),
        "enterprise" => {
            let endpoint = form.endpoint.ok_or_else(|| {
                (StatusCode::BAD_REQUEST, "企业版缺少 API 端点".to_string())
            })?;
            let enterprise_id = form.enterprise_id.ok_or_else(|| {
                (
                    StatusCode::BAD_REQUEST,
                    "企业版缺少企业标识".to_string(),
                )
            })?;
            CodeBuddyAuthProfile::enterprise(
                endpoint,
                enterprise_id,
                form.user_agent.filter(|s| !s.is_empty()),
            )
            .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?
        }
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("无效的站点类型: {}", form.site_type),
            ))
        }
    };

    log::info!(
        "[CodeBuddyOAuth] 本地配置提交: site_type={}, endpoint={}",
        form.site_type,
        profile.api_endpoint
    );

    // 调用上游 /auth/state 获取真正的 authUrl
    match call_upstream_auth_state(&profile).await {
        Ok((upstream_state, auth_url)) => {
            // 校验 auth_url 与 profile 同源（企业版防御恶意重定向）
            if let Err(e) = validate_auth_url_origin(&auth_url, &profile) {
                log::error!(
                    "[CodeBuddyOAuth] authUrl 与配置端点不同源: {e}"
                );
                return Err((
                    StatusCode::BAD_GATEWAY,
                    "CodeBuddy 站点返回的登录链接与端点不同源".to_string(),
                ));
            }

            // 更新 pending flow
            {
                let mut flows = state.pending_flows.write().await;
                flows.insert(
                    state.flow_id,
                    PendingFlow::AwaitingAuthorization {
                        expires_at_ms: chrono::Utc::now().timestamp_millis()
                            + (AUTH_STATE_DEFAULT_EXPIRES_IN as i64) * 1000,
                        upstream_state,
                        profile,
                    },
                );
            }

            log::info!(
                "[CodeBuddyOAuth] 上游 state 获取成功，跳转到 CodeBuddy 登录页"
            );

            // 303 重定向到上游登录页
            Ok(Response::builder()
                .status(StatusCode::SEE_OTHER)
                .header("Location", auth_url)
                .body(Body::empty())
                .unwrap())
        }
        Err(e) => {
            log::error!("[CodeBuddyOAuth] 上游 state 请求失败: {e}");
            Err((
                StatusCode::BAD_GATEWAY,
                format!("无法连接到 CodeBuddy 站点: {e}"),
            ))
        }
    }
}

/// POST /cancel — 处理取消
async fn handle_cancel(
    State(state): State<AppState>,
) -> Result<(), (StatusCode, String)> {
    state.submitted.store(true, Ordering::SeqCst);
    {
        let mut flows = state.pending_flows.write().await;
        flows.remove(&state.flow_id);
    }
    Ok(())
}

/// 调用 CodeBuddy 站点的 /auth/state 获取上游 state + authUrl
pub async fn call_upstream_auth_state(
    profile: &CodeBuddyAuthProfile,
) -> Result<(String, String), String> {
    let nonce = uuid::Uuid::new_v4().simple().to_string();
    let url = format!(
        "{}v2/plugin/auth/state?platform=VSCode&nonce={nonce}",
        profile.api_endpoint
    );

    let mut req = crate::proxy::http_client::get()
        .post(&url)
        .header("Content-Type", "application/json")
        .json(&serde_json::json!({ "nonce": nonce }));

    for (key, value) in build_auth_start_headers(profile) {
        req = req.header(key, &value);
    }

    log::info!(
        "[CodeBuddyOAuth] 正在请求上游 /auth/state: POST {url}",
    );
    log::debug!(
        "[CodeBuddyOAuth] /auth/state 请求头: {:?}",
        build_auth_start_headers(profile)
    );

    let response = req.send().await.map_err(|e| {
        log::error!("[CodeBuddyOAuth] /auth/state 网络错误: {e}");
        e.to_string()
    })?;

    let status = response.status();
    log::info!(
        "[CodeBuddyOAuth] /auth/state 响应: HTTP {status}",
    );

    if !status.is_success() {
        let text = response.text().await.unwrap_or_default();
        log::error!("[CodeBuddyOAuth] /auth/state HTTP 错误: {status} body={text}");
        return Err(format!("HTTP {status}: {text}"));
    }

    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| {
            log::error!("[CodeBuddyOAuth] /auth/state JSON 解析失败: {e}");
            format!("JSON 解析失败: {e}")
        })?;

    log::debug!(
        "[CodeBuddyOAuth] /auth/state 响应体: {}",
        serde_json::to_string_pretty(&body).unwrap_or_default()
    );

    let code = body.get("code").and_then(|v| v.as_i64()).unwrap_or(-1);
    if code != 0 {
        let msg = body
            .get("msg")
            .and_then(|v| v.as_str())
            .unwrap_or("未知错误");
        return Err(format!("API 返回错误码 {code}: {msg}"));
    }

    let data = body.get("data").ok_or("响应缺少 data 字段")?;
    let state = data
        .get("state")
        .and_then(|v| v.as_str())
        .ok_or("响应缺少 state")?
        .to_string();
    let auth_url = data
        .get("authUrl")
        .and_then(|v| v.as_str())
        .ok_or("响应缺少 authUrl")?
        .to_string();

    Ok((state, auth_url))
}

/// 校验上游返回的 authUrl 与 profile 配置的端点同源
fn validate_auth_url_origin(
    auth_url: &str,
    profile: &CodeBuddyAuthProfile,
) -> Result<(), String> {
    let auth_parsed = url::Url::parse(auth_url).map_err(|e| format!("authUrl 解析失败: {e}"))?;
    let endpoint_parsed =
        url::Url::parse(&profile.api_endpoint).map_err(|e| format!("端点解析失败: {e}"))?;

    if auth_parsed.scheme() != endpoint_parsed.scheme() {
        return Err(format!(
            "authUrl scheme mismatch: {} vs {}",
            auth_parsed.scheme(),
            endpoint_parsed.scheme()
        ));
    }
    if auth_parsed.host_str() != endpoint_parsed.host_str() {
        return Err(format!(
            "authUrl host mismatch: {} vs {}",
            auth_parsed.host_str().unwrap_or("none"),
            endpoint_parsed.host_str().unwrap_or("none")
        ));
    }
    if auth_parsed.port() != endpoint_parsed.port() {
        return Err("authUrl port mismatch".to_string());
    }

    Ok(())
}
