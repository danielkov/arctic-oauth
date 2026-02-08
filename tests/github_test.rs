mod common;

#[cfg(feature = "github")]
mod github_extra {
    use arctic_oauth::{Error, GitHub};

    /// GitHub-specific: error responses returned with HTTP 200 status.
    #[tokio::test]
    async fn error_as_200() {
        use super::common::mock_server::MockOAuth2Server;

        let server = MockOAuth2Server::start().await;
        let mock_url = server.url();
        let github = GitHub::with_endpoints(
            "client-id",
            "client-secret",
            Some("http://localhost/callback".into()),
            &format!("{mock_url}/authorize"),
            &format!("{mock_url}/token"),
        );

        server
            .mock_token_error_as_200(
                "bad_verification_code",
                "The code passed is incorrect or expired.",
            )
            .await;

        let http = arctic_oauth::ReqwestClient::new();
        let err = github
            .validate_authorization_code(&http, "expired-code")
            .await
            .expect_err("should return error for error-as-200");

        match err {
            Error::OAuthRequest {
                code, description, ..
            } => {
                assert_eq!(code, "bad_verification_code");
                assert_eq!(
                    description.as_deref(),
                    Some("The code passed is incorrect or expired.")
                );
            }
            other => panic!("Expected OAuthRequest, got: {other:?}"),
        }
    }

    #[test]
    fn rejects_code_verifier() {
        let github = GitHub::new("cid", "secret", None);
        let url = github.authorization_url("state", &["repo"]);
        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(!pairs.iter().any(|(k, _)| k == "code_challenge"));
    }

    #[test]
    fn authorization_url_with_scopes() {
        let github = GitHub::new("cid", "secret", Some("http://localhost/callback".into()));
        let url = github.authorization_url("state123", &["repo", "user:email"]);

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("scope".into(), "repo user:email".into())));
        assert!(pairs.contains(&("redirect_uri".into(), "http://localhost/callback".into())));
        assert!(!pairs.iter().any(|(k, _)| k == "code_challenge"));
    }
}
