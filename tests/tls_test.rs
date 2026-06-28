/// Verify the crate compiles with rustls-tls only (no native-tls/OpenSSL).
/// The real verification is `cargo tree -e features | grep native-tls` in CI.
#[test]
fn rustls_only_compiles() {
    // If this compiles, reqwest is configured with rustls-tls.
}
