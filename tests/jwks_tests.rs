use apple::jwks::{AppleJwksClient, Jwk};
use std::time::Duration;

#[test]
fn test_jwk_deserialization() {
    let json = r#"{
        "kty": "EC",
        "kid": "86D7KFB",
        "alg": "ES256",
        "use": "sig",
        "crv": "P-256",
        "x": "WKn-ZIGu0cUuZq4Xc6Sm5p6Dgk9p8T7g4vBk9lqO3Xw",
        "y": "VYn-ZIGu0cUuZq4Xc6Sm5p6Dgk9p8T7g4vBk9lqO3Xw"
    }"#;
    let jwk: Jwk = serde_json::from_str(json).unwrap();
    assert_eq!(jwk.kty, "EC");
    assert_eq!(jwk.kid, "86D7KFB");
    assert_eq!(jwk.alg, "ES256");
    assert_eq!(jwk.crv.as_deref(), Some("P-256"));
    assert_eq!(
        jwk.x.as_deref(),
        Some("WKn-ZIGu0cUuZq4Xc6Sm5p6Dgk9p8T7g4vBk9lqO3Xw")
    );
    assert!(jwk.n.is_none());
}

#[test]
fn test_rsa_jwk_deserialization() {
    // Sign in with Apple id_token keys are RSA (n/e), not EC.
    let json = r#"{
        "kty": "RSA",
        "kid": "1E6VioIaNI",
        "use": "sig",
        "alg": "RS256",
        "n": "ttL4HNkWLS_Oh0GADZqA4lTM8Y8UyaCR2NfIcvxby6quhwIISI9",
        "e": "AQAB"
    }"#;
    let jwk: Jwk = serde_json::from_str(json).unwrap();
    assert_eq!(jwk.kty, "RSA");
    assert_eq!(jwk.alg, "RS256");
    assert_eq!(
        jwk.n.as_deref(),
        Some("ttL4HNkWLS_Oh0GADZqA4lTM8Y8UyaCR2NfIcvxby6quhwIISI9")
    );
    assert_eq!(jwk.e.as_deref(), Some("AQAB"));
    assert!(jwk.crv.is_none());
}

#[test]
fn test_jwks_client_creation() {
    let client = AppleJwksClient::new().unwrap();
    let _ = client;
}

#[test]
fn test_jwks_client_custom_ttl() {
    let client = AppleJwksClient::with_cache_ttl(Duration::from_secs(300)).unwrap();
    let _ = client;
}
