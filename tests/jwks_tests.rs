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
    assert_eq!(jwk.crv, "P-256");
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
