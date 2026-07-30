//! CodeBuddy OAuth state.
//!
//! CodeBuddy 没有公开的额度/模型查询接口，因此这里只需要暴露
//! `CodeBuddyOAuthState`（供 `commands::auth` 的通用 auth_* 命令使用）。

use crate::proxy::providers::codebuddy_oauth_auth::CodeBuddyOAuthManager;
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct CodeBuddyOAuthState(pub Arc<RwLock<CodeBuddyOAuthManager>>);
