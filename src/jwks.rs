use crate::error::AppleError;
use crate::user::Claims;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use reqwest::Client;
use serde::Deserialize;
use std::sync::RwLock;
use std::time::{Duration, Instant};

const JWKS_URL: &str = "https://appleid.apple.com/auth/keys";
const APPLE_ISSUER: &str = "https://appleid.apple.com";
const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(3600); // 1 hour

/// A single JSON Web Key from Apple's JWKS.
#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    pub kty: String,
    pub kid: String,
    pub alg: String,
    #[serde(rename = "use")]
    pub use_: String,
    pub crv: String,
    pub x: String,
    pub y: String,
}

/// JWKS response from Apple.
#[derive(Debug, Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

/// Cache entry with fetch timestamp.
struct JwksCache {
    keys: Vec<Jwk>,
    fetched_at: Instant,
}

/// Client for fetching and caching Apple's public keys (JWKS).
pub struct AppleJwksClient {
    http_client: Client,
    cache: RwLock<JwksCache>,
    cache_ttl: Duration,
}

impl AppleJwksClient {
    /// Create a new JWKS client with default 1-hour cache TTL.
    pub fn new() -> Result<Self, AppleError> {
        Self::with_cache_ttl(DEFAULT_CACHE_TTL)
    }

    /// Create a new JWKS client with a custom cache TTL.
    pub fn with_cache_ttl(ttl: Duration) -> Result<Self, AppleError> {
        let http_client = Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| AppleError::HttpError(e.to_string()))?;

        Ok(AppleJwksClient {
            http_client,
            cache: RwLock::new(JwksCache {
                keys: Vec::new(),
                fetched_at: Instant::now() - Duration::from_secs(86400), // expired
            }),
            cache_ttl: ttl,
        })
    }

    /// Fetch JWKS from Apple and update the cache.
    async fn fetch_jwks(&self) -> Result<(), AppleError> {
        let response = self
            .http_client
            .get(JWKS_URL)
            .send()
            .await
            .map_err(|e| AppleError::JwksError(format!("JWKS fetch failed: {e}")))?;

        if response.status() != reqwest::StatusCode::OK {
            return Err(AppleError::JwksError(format!(
                "JWKS endpoint returned {}",
                response.status()
            )));
        }

        let jwks: JwkSet = response
            .json()
            .await
            .map_err(|e| AppleError::JwksError(format!("JWKS parse failed: {e}")))?;

        let mut cache = self
            .cache
            .write()
            .map_err(|e| AppleError::JwksError(format!("cache lock poisoned: {e}")))?;
        cache.keys = jwks.keys;
        cache.fetched_at = Instant::now();
        Ok(())
    }

    /// Check if cache is stale.
    fn cache_is_stale(&self) -> bool {
        let cache = match self.cache.read() {
            Ok(c) => c,
            Err(_) => return true,
        };
        cache.keys.is_empty() || cache.fetched_at.elapsed() > self.cache_ttl
    }

    /// Get the JWK matching the given key ID.
    /// Forces a cache refresh if the kid is not found.
    pub async fn get_key(&self, kid: &str) -> Result<Jwk, AppleError> {
        // Check cache first
        {
            let cache = self
                .cache
                .read()
                .map_err(|e| AppleError::JwksError(format!("cache lock poisoned: {e}")))?;
            if !self.cache_is_stale()
                && let Some(jwk) = cache.keys.iter().find(|k| k.kid == kid)
            {
                return Ok(jwk.clone());
            }
        }

        // Cache is stale or kid not found — re-fetch
        self.fetch_jwks().await?;

        // Try again from fresh cache
        let cache = self
            .cache
            .read()
            .map_err(|e| AppleError::JwksError(format!("cache lock poisoned: {e}")))?;
        cache
            .keys
            .iter()
            .find(|k| k.kid == kid)
            .cloned()
            .ok_or_else(|| AppleError::JwksError(format!("key ID '{kid}' not found in JWKS")))
    }

    /// Verify an Apple ID token and return the decoded claims.
    ///
    /// # Security
    /// This function verifies the JWT signature using Apple's public keys,
    /// validates issuer, audience, expiry, and nonce. It will NEVER decode
    /// a JWT without signature verification.
    pub async fn verify_token(
        &self,
        token: &str,
        expected_audience: &str,
        expected_nonce: Option<&str>,
    ) -> Result<Claims, AppleError> {
        // First, decode the header to get the kid
        let header = jsonwebtoken::decode_header(token)
            .map_err(|e| AppleError::TokenValidationError(format!("invalid JWT header: {e}")))?;

        let kid = header
            .kid
            .ok_or_else(|| AppleError::TokenValidationError("missing kid in JWT header".into()))?;

        // Get the matching JWK
        let jwk = self.get_key(&kid).await?;

        // Convert JWK x/y coordinates to a decoding key for verification
        // from_ec_components takes base64url-encoded strings directly
        let decoding_key = DecodingKey::from_ec_components(&jwk.x, &jwk.y).map_err(|e| {
            AppleError::JwksError(format!("failed to build decoding key from JWK: {e}"))
        })?;

        // Configure validation
        let mut validation = Validation::new(Algorithm::ES256);
        validation.set_issuer(&[APPLE_ISSUER]);
        validation.set_audience(&[expected_audience]);
        validation.validate_exp = true;

        let token_data = decode::<Claims>(token, &decoding_key, &validation).map_err(|e| {
            AppleError::TokenValidationError(format!("JWT verification failed: {e}"))
        })?;

        // Verify nonce if provided
        if let Some(expected) = expected_nonce {
            let actual =
                token_data.claims.nonce.as_deref().ok_or_else(|| {
                    AppleError::TokenValidationError("nonce missing in token".into())
                })?;
            if actual != expected {
                return Err(AppleError::TokenValidationError("nonce mismatch".into()));
            }
        }

        Ok(token_data.claims)
    }
}
