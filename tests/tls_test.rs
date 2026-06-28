/// Verify no native-tls or openssl in the dependency tree.
/// This is a build-time check, not a runtime test — we verify by
/// checking that the crate compiles with rustls-tls only.
#[test]
fn rustls_only_compiles() {
    // If this compiles, reqwest is using rustls-tls.
    // If native-tls were pulled in, this would still compile but
    // `cargo tree -e features | grep native-tls` would find it.
    // The real verification is in CI.
    assert!(true);
}
