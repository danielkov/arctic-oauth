/// Generic flow test harness implemented as a macro.
///
/// The `OAuthProvider` trait is not dyn-compatible (it uses `impl HttpClient`
/// generics and `impl Future` returns), so we use a macro that generates
/// concrete test functions for each provider.
///
/// Usage:
/// ```ignore
/// provider_flow_tests! {
///     provider_name: "Google",
///     make_provider: |mock_url| { Google::with_endpoints(...) },
///     pkce: Required,
///     supports_refresh: true,
///     supports_revocation: true,
/// }
/// ```
#[macro_export]
macro_rules! provider_flow_tests {
    (
        provider_name: $name:expr,
        make_provider: |$mock_url:ident| $make_provider:expr,
        pkce: $pkce:ident,
        supports_refresh: $supports_refresh:tt,
        supports_revocation: $supports_revocation:tt,
    ) => {
        #[tokio::test]
        async fn flow_authorization_url_construction() {
            use arctic_oauth::{
                generate_code_verifier, generate_state, OAuthProvider, PkceRequirement,
            };

            let provider = {
                let $mock_url = "https://mock.example.com".to_string();
                $make_provider
            };
            let state = generate_state();

            let code_verifier =
                match PkceRequirement::$pkce {
                    PkceRequirement::Required | PkceRequirement::Optional => {
                        Some(generate_code_verifier())
                    }
                    PkceRequirement::None => None,
                };

            let url = provider
                .authorization_url(&state, &["openid", "email"], code_verifier.as_deref())
                .expect("authorization_url should succeed");

            let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();

            assert!(
                pairs.contains(&("response_type".into(), "code".into())),
                "{}: missing response_type=code",
                $name
            );
            assert!(
                pairs.iter().any(|(k, _)| k == "client_id"),
                "{}: missing client_id",
                $name
            );
            assert!(
                pairs.iter().any(|(k, v)| k == "state" && v == &state),
                "{}: missing or wrong state",
                $name
            );

            match PkceRequirement::$pkce {
                PkceRequirement::Required | PkceRequirement::Optional => {
                    assert!(
                        pairs.iter().any(|(k, _)| k == "code_challenge"),
                        "{}: missing code_challenge",
                        $name
                    );
                    assert!(
                        pairs.iter().any(|(k, _)| k == "code_challenge_method"),
                        "{}: missing code_challenge_method",
                        $name
                    );
                }
                PkceRequirement::None => {
                    assert!(
                        !pairs.iter().any(|(k, _)| k == "code_challenge"),
                        "{}: unexpected code_challenge",
                        $name
                    );
                }
            }
        }

        #[tokio::test]
        async fn flow_successful_token_exchange() {
            use arctic_oauth::{generate_code_verifier, OAuthProvider, PkceRequirement};
            use super::common::mock_server::MockOAuth2Server;

            let server = MockOAuth2Server::start().await;
            let $mock_url = server.url();
            let provider = $make_provider;

            let token_response = serde_json::json!({
                "access_token": "test-access-token",
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "test-refresh-token",
                "scope": "openid email"
            });
            server.mock_token_success(token_response).await;

            let code_verifier = match PkceRequirement::$pkce {
                PkceRequirement::Required | PkceRequirement::Optional => {
                    Some(generate_code_verifier())
                }
                PkceRequirement::None => None,
            };

            let http = arctic_oauth::ReqwestClient::new();
            let tokens = provider
                .validate_authorization_code(&http, "test-auth-code", code_verifier.as_deref())
                .await
                .unwrap_or_else(|e| panic!("{}: token exchange failed: {e}", $name));

            assert_eq!(
                tokens.access_token().unwrap(),
                "test-access-token",
                "{}: wrong access_token",
                $name
            );
            assert_eq!(
                tokens.token_type().unwrap(),
                "Bearer",
                "{}: wrong token_type",
                $name
            );
            assert_eq!(
                tokens.access_token_expires_in_seconds().unwrap(),
                3600,
                "{}: wrong expires_in",
                $name
            );

            server
                .verify_token_request(&[
                    ("grant_type", "authorization_code"),
                    ("code", "test-auth-code"),
                ])
                .await;
        }

        #[tokio::test]
        async fn flow_token_exchange_oauth_error() {
            use arctic_oauth::{generate_code_verifier, Error, OAuthProvider, PkceRequirement};
            use super::common::mock_server::MockOAuth2Server;

            let server = MockOAuth2Server::start().await;
            let $mock_url = server.url();
            let provider = $make_provider;

            server
                .mock_token_error("invalid_grant", "The authorization code has expired")
                .await;

            let code_verifier = match PkceRequirement::$pkce {
                PkceRequirement::Required | PkceRequirement::Optional => {
                    Some(generate_code_verifier())
                }
                PkceRequirement::None => None,
            };

            let http = arctic_oauth::ReqwestClient::new();
            let err = provider
                .validate_authorization_code(&http, "bad-code", code_verifier.as_deref())
                .await
                .expect_err(&format!("{}: expected OAuth error", $name));

            match err {
                Error::OAuthRequest {
                    code, description, ..
                } => {
                    assert_eq!(code, "invalid_grant", "{}: wrong error code", $name);
                    assert_eq!(
                        description.as_deref(),
                        Some("The authorization code has expired"),
                        "{}: wrong error description",
                        $name
                    );
                }
                other => panic!("{}: expected OAuthRequest, got: {other:?}", $name),
            }
        }

        #[tokio::test]
        async fn flow_token_exchange_unexpected_status() {
            use arctic_oauth::{generate_code_verifier, Error, OAuthProvider, PkceRequirement};
            use super::common::mock_server::MockOAuth2Server;

            let server = MockOAuth2Server::start().await;
            let $mock_url = server.url();
            let provider = $make_provider;

            server.mock_unexpected_status(500).await;

            let code_verifier = match PkceRequirement::$pkce {
                PkceRequirement::Required | PkceRequirement::Optional => {
                    Some(generate_code_verifier())
                }
                PkceRequirement::None => None,
            };

            let http = arctic_oauth::ReqwestClient::new();
            let err = provider
                .validate_authorization_code(&http, "code", code_verifier.as_deref())
                .await
                .expect_err(&format!("{}: expected error for 500", $name));

            assert!(
                matches!(err, Error::UnexpectedResponse { status: 500 }),
                "{}: expected UnexpectedResponse(500), got: {err:?}",
                $name
            );
        }

        #[tokio::test]
        async fn flow_token_exchange_malformed_body() {
            use arctic_oauth::{generate_code_verifier, Error, OAuthProvider, PkceRequirement};
            use super::common::mock_server::MockOAuth2Server;

            let server = MockOAuth2Server::start().await;
            let $mock_url = server.url();
            let provider = $make_provider;

            // 400 with empty body (not valid JSON)
            server.mock_unexpected_status(400).await;

            let code_verifier = match PkceRequirement::$pkce {
                PkceRequirement::Required | PkceRequirement::Optional => {
                    Some(generate_code_verifier())
                }
                PkceRequirement::None => None,
            };

            let http = arctic_oauth::ReqwestClient::new();
            let err = provider
                .validate_authorization_code(&http, "code", code_verifier.as_deref())
                .await
                .expect_err(&format!("{}: expected error for malformed body", $name));

            assert!(
                matches!(err, Error::UnexpectedErrorBody { status: 400, .. }),
                "{}: expected UnexpectedErrorBody(400), got: {err:?}",
                $name
            );
        }

        provider_flow_tests!(@refresh $name, |$mock_url| $make_provider, $supports_refresh);
        provider_flow_tests!(@revocation $name, |$mock_url| $make_provider, $supports_revocation);
    };

    // Refresh: supported
    (@refresh $name:expr, |$mock_url:ident| $make_provider:expr, true) => {
        #[tokio::test]
        async fn flow_token_refresh() {
            use arctic_oauth::OAuthProvider;
            use super::common::mock_server::MockOAuth2Server;

            let server = MockOAuth2Server::start().await;
            let $mock_url = server.url();
            let provider = $make_provider;

            let refresh_response = serde_json::json!({
                "access_token": "new-access-token",
                "token_type": "Bearer",
                "expires_in": 3600
            });
            server.mock_token_success(refresh_response).await;

            let http = arctic_oauth::ReqwestClient::new();
            let tokens = provider
                .refresh_access_token(&http, "test-refresh-token")
                .await
                .unwrap_or_else(|e| panic!("{}: refresh failed: {e}", $name));

            assert_eq!(
                tokens.access_token().unwrap(),
                "new-access-token",
                "{}: wrong refreshed access_token",
                $name
            );

            server
                .verify_token_request(&[
                    ("grant_type", "refresh_token"),
                    ("refresh_token", "test-refresh-token"),
                ])
                .await;
        }
    };

    // Refresh: not supported
    (@refresh $name:expr, |$mock_url:ident| $make_provider:expr, false) => {};

    // Revocation: supported
    (@revocation $name:expr, |$mock_url:ident| $make_provider:expr, true) => {
        #[tokio::test]
        async fn flow_token_revocation() {
            use arctic_oauth::OAuthProvider;
            use super::common::mock_server::MockOAuth2Server;

            let server = MockOAuth2Server::start().await;
            let $mock_url = server.url();
            let provider = $make_provider;

            server.mock_revocation_success().await;

            let http = arctic_oauth::ReqwestClient::new();
            provider
                .revoke_token(&http, "token-to-revoke")
                .await
                .unwrap_or_else(|e| panic!("{}: revocation failed: {e}", $name));
        }
    };

    // Revocation: not supported
    (@revocation $name:expr, |$mock_url:ident| $make_provider:expr, false) => {};
}
