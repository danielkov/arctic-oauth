mod common;

#[cfg(feature = "google")]
mod google_extra {
    use arctic_oauth::Google;

    #[test]
    fn authorization_url_requires_pkce() {
        let google = Google::new("cid", "secret", "http://localhost/callback");
        let _url = google.authorization_url("state", &["openid"], "verifier");
    }

    #[test]
    fn authorization_url_includes_scope_and_redirect() {
        let google = Google::new("cid", "secret", "http://localhost/callback");
        let url = google.authorization_url("state123", &["openid", "email", "profile"], "verifier");

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("scope".into(), "openid email profile".into())));
        assert!(pairs.contains(&("redirect_uri".into(), "http://localhost/callback".into())));
        assert!(pairs.contains(&("code_challenge_method".into(), "S256".into())));
    }

    #[tokio::test]
    async fn revocation_via_mock_server() {
        use super::common::mock_server::MockOAuth2Server;

        let server = MockOAuth2Server::start().await;
        let mock_url = server.url();
        let google = Google::with_endpoints(
            "cid",
            "secret",
            "http://localhost/callback",
            &format!("{mock_url}/authorize"),
            &format!("{mock_url}/token"),
            Some(&format!("{mock_url}/revoke")),
        );

        server.mock_revocation_success().await;

        let http = arctic_oauth::ReqwestClient::new();
        google
            .revoke_token(&http, "token-to-revoke")
            .await
            .expect("revocation should succeed");
    }
}
