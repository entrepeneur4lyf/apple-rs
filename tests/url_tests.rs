#[cfg(feature = "auth")]
mod auth_url_tests {
    use apple::url::*;

    #[test]
    fn test_response_mode_display() {
        assert_eq!(ResponseMode::Query.to_string(), "query");
        assert_eq!(ResponseMode::Fragment.to_string(), "fragment");
        assert_eq!(ResponseMode::FormPost.to_string(), "form_post");
    }

    #[test]
    fn test_response_type_display() {
        assert_eq!(ResponseType::Code.to_string(), "code");
        assert_eq!(ResponseType::CodeId.to_string(), "code id_token");
    }

    #[test]
    fn test_response_mode_default() {
        let mode: ResponseMode = Default::default();
        assert_eq!(mode.to_string(), "form_post");
    }

    #[test]
    fn test_response_type_default() {
        let rt: ResponseType = Default::default();
        assert_eq!(rt.to_string(), "code id_token");
    }

    #[test]
    fn test_authorize_url_defaults() {
        let cfg = AuthorizeURLConfig {
            client_id: "com.example.app".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            scope: None,
            nonce: None,
            response_mode: None,
            response_type: None,
        };

        let result = authorize_url(cfg);
        assert!(result
            .url
            .starts_with("https://appleid.apple.com/auth/authorize?"));
        assert!(result.url.contains("client_id=com.example.app"));
        assert!(result
            .url
            .contains("redirect_uri=https%3A%2F%2Fexample.com%2Fcallback"));
        assert!(result.url.contains("response_type=code+id_token"));
        assert!(result.url.contains("response_mode=form_post"));
        assert!(!result.state.is_empty());
        assert!(result.url.contains("state="));
    }

    #[test]
    fn test_authorize_url_with_all_params() {
        let cfg = AuthorizeURLConfig {
            client_id: "com.example.app".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            scope: Some(vec!["email".to_string(), "name".to_string()]),
            nonce: Some("nonce123".to_string()),
            response_mode: Some(ResponseMode::FormPost),
            response_type: Some(ResponseType::CodeId),
        };

        let result = authorize_url(cfg);
        assert!(result.url.contains("scope=email+name"));
        assert!(result.url.contains("nonce=nonce123"));
        assert!(!result.state.is_empty());
    }

    #[test]
    fn test_authorize_url_with_fragment_mode() {
        let cfg = AuthorizeURLConfig {
            client_id: "com.example.app".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            scope: None,
            nonce: None,
            response_mode: Some(ResponseMode::Fragment),
            response_type: Some(ResponseType::Code),
        };

        let result = authorize_url(cfg);
        assert!(result.url.contains("response_mode=fragment"));
        assert!(result.url.contains("response_type=code"));
    }

    #[test]
    fn test_authorize_url_generates_state() {
        let cfg = AuthorizeURLConfig {
            client_id: "com.example.app".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            scope: Some(vec!["email".to_string(), "name".to_string()]),
            nonce: Some("nonce123".to_string()),
            response_mode: None,
            response_type: None,
        };

        let result = authorize_url(cfg);
        assert!(!result.state.is_empty());
        assert!(result.state.len() >= 32);
        assert!(result.url.contains("state="));
        assert!(result.url.contains(&result.state));
    }

    #[test]
    fn test_verify_state_accepts_match() {
        let state = "abc123";
        assert!(verify_state(state, state).is_ok());
    }

    #[test]
    fn test_verify_state_rejects_mismatch() {
        assert!(verify_state("abc123", "xyz789").is_err());
    }

    #[test]
    fn test_verify_state_rejects_empty() {
        assert!(verify_state("", "").is_err());
    }

    #[test]
    fn test_two_authorize_urls_generate_different_states() {
        let cfg = AuthorizeURLConfig {
            client_id: "com.example.app".to_string(),
            redirect_uri: "https://example.com/callback".to_string(),
            scope: None,
            nonce: None,
            response_mode: None,
            response_type: None,
        };
        let result1 = authorize_url(cfg.clone());
        let result2 = authorize_url(cfg);
        assert_ne!(result1.state, result2.state);
    }
}
