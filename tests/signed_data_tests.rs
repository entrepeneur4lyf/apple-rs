#![cfg(feature = "appstore")]

use apple::appstore::signed_data::SignedDataVerifier;
use apple::appstore::types::AppStoreEnvironment;
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

#[test]
fn test_reject_empty_x5c() {
    let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"ES256","x5c":[]}"#);
    let payload = URL_SAFE_NO_PAD.encode(r#"{"bundleId":"com.test","environment":"Production"}"#);
    let signature = URL_SAFE_NO_PAD.encode([0u8; 64].as_slice());

    let jws = format!("{header}.{payload}.{signature}");

    let verifier =
        SignedDataVerifier::new(vec![], "com.test", AppStoreEnvironment::Production, None);

    let result = verifier.verify_and_decode_transaction(&jws);
    assert!(result.is_err(), "JWS with empty x5c must be rejected");
}

#[test]
fn test_reject_chain_too_short() {
    // A cert chain with only 1 cert must be rejected.
    let (_, _, leaf_der) = generate_test_cert_chain();
    let leaf_b64 = STANDARD.encode(&leaf_der);

    let header = URL_SAFE_NO_PAD.encode(format!(r#"{{"alg":"ES256","x5c":["{leaf_b64}"]}}"#));
    let payload = URL_SAFE_NO_PAD.encode(r#"{"bundleId":"com.test","environment":"Production"}"#);
    let signature = URL_SAFE_NO_PAD.encode([0u8; 64].as_slice());

    let jws = format!("{header}.{payload}.{signature}");
    let verifier =
        SignedDataVerifier::new(vec![], "com.test", AppStoreEnvironment::Production, None);
    let result = verifier.verify_and_decode_transaction(&jws);
    assert!(result.is_err(), "chain with < 2 certs must be rejected");
}

#[test]
fn test_reject_untrusted_root() {
    let (root_der, intermediate_der, leaf_der) = generate_test_cert_chain();

    // Verifier trusts no roots (empty = always rejects non-empty chain root)
    let verifier =
        SignedDataVerifier::new(vec![], "com.test", AppStoreEnvironment::Production, None);

    let root_b64 = STANDARD.encode(&root_der);
    let intermediate_b64 = STANDARD.encode(&intermediate_der);
    let leaf_b64 = STANDARD.encode(&leaf_der);

    let header = URL_SAFE_NO_PAD.encode(format!(
        r#"{{"alg":"ES256","x5c":["{leaf_b64}","{intermediate_b64}","{root_b64}"]}}"#
    ));
    let payload = URL_SAFE_NO_PAD.encode(r#"{"bundleId":"com.test","environment":"Production"}"#);
    let signature = URL_SAFE_NO_PAD.encode([0u8; 64].as_slice());

    let jws = format!("{header}.{payload}.{signature}");
    let result = verifier.verify_and_decode_transaction(&jws);
    assert!(result.is_err(), "untrusted root must be rejected");
}

fn generate_test_cert_chain() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};

    // Root CA (self-signed)
    let root_key = KeyPair::generate().unwrap();
    let mut root_params = CertificateParams::new(vec![]).unwrap();
    root_params.distinguished_name = DistinguishedName::new();
    root_params
        .distinguished_name
        .push(DnType::CommonName, "Test Root CA");
    root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let root_cert = root_params.self_signed(&root_key).unwrap();

    // Intermediate CA (signed by root)
    let intermediate_key = KeyPair::generate().unwrap();
    let mut intermediate_params = CertificateParams::new(vec![]).unwrap();
    intermediate_params.distinguished_name = DistinguishedName::new();
    intermediate_params
        .distinguished_name
        .push(DnType::CommonName, "Test Intermediate CA");
    intermediate_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let intermediate_cert = intermediate_params
        .signed_by(&intermediate_key, &root_cert, &root_key)
        .unwrap();

    // Leaf cert (signed by intermediate)
    let leaf_key = KeyPair::generate().unwrap();
    let mut leaf_params = CertificateParams::new(vec![]).unwrap();
    leaf_params.distinguished_name = DistinguishedName::new();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "Test Leaf");
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &intermediate_cert, &intermediate_key)
        .unwrap();

    (
        root_cert.der().to_vec(),
        intermediate_cert.der().to_vec(),
        leaf_cert.der().to_vec(),
    )
}
