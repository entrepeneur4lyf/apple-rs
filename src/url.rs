use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fmt;
use url::Url;

#[non_exhaustive]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub enum ResponseMode {
    Query,
    Fragment,
    #[default]
    FormPost,
}

impl fmt::Display for ResponseMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResponseMode::Query => write!(f, "query"),
            ResponseMode::Fragment => write!(f, "fragment"),
            ResponseMode::FormPost => write!(f, "form_post"),
        }
    }
}

#[non_exhaustive]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub enum ResponseType {
    Code,
    #[default]
    CodeId,
}

impl fmt::Display for ResponseType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResponseType::Code => write!(f, "code"),
            ResponseType::CodeId => write!(f, "code id_token"),
        }
    }
}

/// Result of building an authorize URL — includes the URL and the
/// generated CSRF state token that must be stored in the session
/// and verified in the callback.
#[derive(Debug, Clone)]
pub struct AuthorizeResult {
    pub url: String,
    pub state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizeURLConfig {
    pub client_id: String,
    pub redirect_uri: String,
    pub scope: Option<Vec<String>>,
    pub nonce: Option<String>,
    pub response_mode: Option<ResponseMode>,
    pub response_type: Option<ResponseType>,
}

/// Generate a cryptographically random 32-byte state token (base64url-encoded).
fn generate_state() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(&bytes)
}

/// Constant-time comparison of state tokens to prevent timing attacks.
pub fn verify_state(
    stored_state: &str,
    received_state: &str,
) -> Result<(), crate::error::AppleError> {
    if stored_state.is_empty() || received_state.is_empty() {
        return Err(crate::error::AppleError::StateMismatchError);
    }
    if constant_time_eq(stored_state.as_bytes(), received_state.as_bytes()) {
        Ok(())
    } else {
        Err(crate::error::AppleError::StateMismatchError)
    }
}

/// Constant-time byte comparison. Processes all bytes regardless of match
/// to prevent timing side-channels. Uses black_box to prevent the compiler
/// from short-circuiting the loop.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    let result = std::hint::black_box(result);
    result == 0
}

pub fn authorize_url(cfg: AuthorizeURLConfig) -> AuthorizeResult {
    let state = generate_state();
    let mut url = Url::parse("https://appleid.apple.com/auth/authorize")
        .expect("hardcoded Apple authorize URL must parse");
    let mut query = url.query_pairs_mut();

    query.append_pair(
        "response_type",
        &cfg.response_type.unwrap_or_default().to_string(),
    );
    query.append_pair(
        "response_mode",
        &cfg.response_mode.unwrap_or_default().to_string(),
    );
    query.append_pair("client_id", &cfg.client_id);
    query.append_pair("redirect_uri", &cfg.redirect_uri);
    query.append_pair("state", &state);

    if let Some(nonce) = cfg.nonce {
        query.append_pair("nonce", &nonce);
    }
    if let Some(scope) = cfg.scope {
        query.append_pair("scope", &scope.join(" "));
    }

    drop(query);
    AuthorizeResult {
        url: url.to_string(),
        state,
    }
}
