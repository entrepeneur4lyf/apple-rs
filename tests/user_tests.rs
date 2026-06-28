use apple::error::AppleError;
use apple::jwks::AppleJwksClient;
use apple::user::parse_bool;

/// A forged JWT signed with a random key (not Apple's) must be rejected.
/// This is the critical negative test — it catches the original vulnerability
/// where get_user_info_from_id_token decoded with an empty secret.
#[tokio::test]
async fn test_forged_token_is_rejected() {
    let jwks_client = AppleJwksClient::new().unwrap();

    // Create a JWT signed with a test key (not Apple's real key)
    use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::EncodePrivateKey;

    // Deterministic test key — not in Apple's JWKS
    let test_key_bytes: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];
    let signing_key = SigningKey::from_slice(&test_key_bytes).unwrap();
    let der = signing_key.to_pkcs8_der().unwrap();

    let claims = serde_json::json!({
        "iss": "https://appleid.apple.com",
        "aud": "com.test.app",
        "sub": "001234.abc.def.123",
        "iat": 1700000000,
        "exp": 2000000000,
        "email": "test@example.com",
        "email_verified": "true",
        "is_private_email": "false",
        "real_user_status": 2,
    });

    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some("FAKEKID".to_string());
    let forged_token = encode(&header, &claims, &EncodingKey::from_ec_der(der.as_bytes())).unwrap();

    let result =
        apple::user::get_user_info_from_id_token(&forged_token, "com.test.app", None, &jwks_client)
            .await;

    assert!(result.is_err(), "forged token must be rejected");
    match result.unwrap_err() {
        AppleError::TokenValidationError(_) => {
            // Expected — the signature won't verify against Apple's keys
        }
        AppleError::JwksError(_) => {
            // Also acceptable in test — can't reach Apple's JWKS endpoint in test env
        }
        e => panic!("expected TokenValidationError or JwksError, got {e:?}"),
    }
}

#[test]
fn test_parse_bool_from_string() {
    // Apple serializes email_verified as a string "true"/"false", not a bool.
    assert!(parse_bool(&Some(serde_json::Value::String(
        "true".to_string()
    ))));
    assert!(!parse_bool(&Some(serde_json::Value::String(
        "false".to_string()
    ))));
    assert!(parse_bool(&Some(serde_json::Value::Bool(true))));
    assert!(!parse_bool(&Some(serde_json::Value::Bool(false))));
    assert!(!parse_bool(&None));
}
