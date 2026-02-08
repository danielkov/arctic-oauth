mod common;

#[cfg(feature = "discord")]
mod discord_extra {
    use arctic_oauth::{Discord, generate_code_verifier};

    #[tokio::test]
    async fn flow_without_pkce() {
        use super::common::mock_server::MockOAuth2Server;

        let server = MockOAuth2Server::start().await;
        let mock_url = server.url();
        let discord = Discord::with_endpoints(
            "client-id",
            Some("client-secret".into()),
            "http://localhost/callback",
            &format!("{mock_url}/authorize"),
            &format!("{mock_url}/token"),
            Some(&format!("{mock_url}/revoke")),
        );

        // Authorization URL without PKCE
        let url = discord
            .authorization_url("state123", &["identify", "email"], None)
            .unwrap();

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.contains(&("client_id".into(), "client-id".into())));
        assert!(pairs.contains(&("state".into(), "state123".into())));
        assert!(
            !pairs.iter().any(|(k, _)| k == "code_challenge"),
            "should not have code_challenge without PKCE"
        );
        assert!(
            !pairs.iter().any(|(k, _)| k == "code_challenge_method"),
            "should not have code_challenge_method without PKCE"
        );

        // Token exchange without PKCE
        let token_response = serde_json::json!({
            "access_token": "discord-tok",
            "token_type": "Bearer",
            "expires_in": 604800
        });
        server.mock_token_success(token_response).await;

        let http = arctic_oauth::ReqwestClient::new();
        let tokens = discord
            .validate_authorization_code(&http, "auth-code", None)
            .await
            .expect("token exchange should succeed without PKCE");

        assert_eq!(tokens.access_token().unwrap(), "discord-tok");
    }

    #[test]
    fn authorization_url_with_pkce() {
        let discord = Discord::new("cid", Some("secret".into()), "http://localhost/callback");
        let verifier = generate_code_verifier();
        let url = discord
            .authorization_url("state123", &["identify"], Some(&verifier))
            .unwrap();

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.iter().any(|(k, _)| k == "code_challenge"));
        assert!(pairs.contains(&("code_challenge_method".into(), "S256".into())));
    }

    #[test]
    fn authorization_url_without_pkce() {
        let discord = Discord::new("cid", Some("secret".into()), "http://localhost/callback");
        let url = discord
            .authorization_url("state123", &["identify"], None)
            .unwrap();

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(!pairs.iter().any(|(k, _)| k == "code_challenge"));
        assert!(!pairs.iter().any(|(k, _)| k == "code_challenge_method"));
    }

    #[tokio::test]
    async fn refresh_via_mock_server() {
        use super::common::mock_server::MockOAuth2Server;

        let server = MockOAuth2Server::start().await;
        let mock_url = server.url();
        let discord = Discord::with_endpoints(
            "cid",
            Some("secret".into()),
            "http://localhost/callback",
            &format!("{mock_url}/authorize"),
            &format!("{mock_url}/token"),
            None,
        );

        let refresh_response = serde_json::json!({
            "access_token": "refreshed-tok",
            "token_type": "Bearer",
            "expires_in": 604800
        });
        server.mock_token_success(refresh_response).await;

        let http = arctic_oauth::ReqwestClient::new();
        let tokens = discord
            .refresh_access_token(&http, "my-refresh-token")
            .await
            .expect("refresh should succeed");

        assert_eq!(tokens.access_token().unwrap(), "refreshed-tok");

        server
            .verify_token_request(&[
                ("grant_type", "refresh_token"),
                ("refresh_token", "my-refresh-token"),
            ])
            .await;
    }

    #[tokio::test]
    async fn revocation_via_mock_server() {
        use super::common::mock_server::MockOAuth2Server;

        let server = MockOAuth2Server::start().await;
        let mock_url = server.url();
        let discord = Discord::with_endpoints(
            "cid",
            Some("secret".into()),
            "http://localhost/callback",
            &format!("{mock_url}/authorize"),
            &format!("{mock_url}/token"),
            Some(&format!("{mock_url}/revoke")),
        );

        server.mock_revocation_success().await;

        let http = arctic_oauth::ReqwestClient::new();
        discord
            .revoke_token(&http, "token-to-revoke")
            .await
            .expect("revocation should succeed");
    }
}
