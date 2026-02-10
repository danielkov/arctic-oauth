use crate::client::OAuth2Client;
use crate::error::Error;
use crate::http::HttpClient;
use crate::pkce::CodeChallengeMethod;
use crate::tokens::OAuth2Tokens;

const AUTHORIZATION_ENDPOINT: &str = "https://apis.roblox.com/oauth/v1/authorize";
const TOKEN_ENDPOINT: &str = "https://apis.roblox.com/oauth/v1/token";
const REVOCATION_ENDPOINT: &str = "https://apis.roblox.com/oauth/v1/token/revoke";

/// OAuth 2.0 client for [Roblox](https://create.roblox.com/docs/cloud/reference/oauth2).
///
/// Roblox requires PKCE (Proof Key for Code Exchange) with the S256 challenge method
/// for all authorization requests. The client supports the authorization code flow,
/// token refresh, and token revocation.
///
/// # Setup
///
/// 1. Create an OAuth 2.0 application in the [Creator Dashboard](https://create.roblox.com/credentials).
/// 2. Configure your OAuth 2.0 credentials and obtain the client ID and client secret.
/// 3. Add your redirect URI to the allowed redirect URIs list in your app settings.
///
/// # Scopes
///
/// Roblox uses space-separated scopes. Common scopes include:
///
/// | Scope | Description |
/// |-------|-------------|
/// | `openid` | Access to user identity information |
/// | `profile` | Access to user profile data |
/// | `email` | Access to user email address |
/// | `universe.read` | Read access to universe data |
/// | `asset.read` | Read access to asset data |
///
/// See the full list at <https://create.roblox.com/docs/cloud/reference/oauth2#scopes>.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{Roblox, ReqwestClient, generate_state, generate_code_verifier};
///
/// # async fn example() -> Result<(), arctic_oauth::Error> {
/// let provider = Roblox::new(
///     "your-client-id",
///     Some("your-client-secret".to_string()),
///     "https://example.com/callback",
/// );
///
/// // Step 1: Generate PKCE verifier and CSRF state, then redirect the user.
/// let state = generate_state();
/// let code_verifier = generate_code_verifier();
/// let url = provider.authorization_url(&state, &["openid", "profile"], &code_verifier);
///
/// // Step 2: Exchange the authorization code for tokens.
/// let http = ReqwestClient::new();
/// let tokens = provider
///     .validate_authorization_code(&http, "authorization-code", &code_verifier)
///     .await?;
/// println!("Access token: {}", tokens.access_token()?);
///
/// // Step 3 (optional): Refresh an expired access token.
/// let refreshed = provider
///     .refresh_access_token(&http, tokens.refresh_token()?)
///     .await?;
///
/// // Step 4 (optional): Revoke a token.
/// provider.revoke_token(&http, tokens.access_token()?).await?;
/// # Ok(())
/// # }
/// ```
pub struct Roblox {
    client: OAuth2Client,
    authorization_endpoint: String,
    token_endpoint: String,
    revocation_endpoint: String,
}

impl Roblox {
    /// Creates a new Roblox OAuth 2.0 client configured with production endpoints.
    ///
    /// # Arguments
    ///
    /// * `client_id` - The OAuth 2.0 client ID from Roblox's Creator Dashboard.
    /// * `client_secret` - The OAuth 2.0 client secret from Roblox's Creator Dashboard (optional).
    /// * `redirect_uri` - The URI Roblox will redirect to after authorization.
    ///   Must match one configured in your app settings.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::Roblox;
    ///
    /// let provider = Roblox::new(
    ///     "your-client-id",
    ///     Some("your-client-secret".to_string()),
    ///     "https://example.com/callback",
    /// );
    /// ```
    pub fn new(
        client_id: impl Into<String>,
        client_secret: Option<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        Self {
            client: OAuth2Client::new(client_id, client_secret, Some(redirect_uri.into())),
            authorization_endpoint: AUTHORIZATION_ENDPOINT.to_string(),
            token_endpoint: TOKEN_ENDPOINT.to_string(),
            revocation_endpoint: REVOCATION_ENDPOINT.to_string(),
        }
    }
}

#[cfg(any(test, feature = "testing"))]
impl Roblox {
    /// Creates a Roblox client with custom endpoint URLs.
    ///
    /// This is useful for integration testing with mock servers (e.g.
    /// [`wiremock`](https://docs.rs/wiremock)). Only available when the `testing` feature
    /// is enabled or in `#[cfg(test)]` builds.
    ///
    /// # Example
    ///
    /// ```rust
    /// # #[cfg(feature = "testing")]
    /// # {
    /// use arctic_oauth::Roblox;
    ///
    /// let provider = Roblox::with_endpoints(
    ///     "test-client-id",
    ///     Some("test-secret".to_string()),
    ///     "http://localhost/callback",
    ///     "http://localhost:8080/authorize",
    ///     "http://localhost:8080/token",
    ///     Some("http://localhost:8080/revoke"),
    /// );
    /// # }
    /// ```
    pub fn with_endpoints(
        client_id: impl Into<String>,
        client_secret: Option<String>,
        redirect_uri: impl Into<String>,
        authorization_endpoint: &str,
        token_endpoint: &str,
        revocation_endpoint: Option<&str>,
    ) -> Self {
        Self {
            client: OAuth2Client::new(client_id, client_secret, Some(redirect_uri.into())),
            authorization_endpoint: authorization_endpoint.to_string(),
            token_endpoint: token_endpoint.to_string(),
            revocation_endpoint: revocation_endpoint
                .unwrap_or(REVOCATION_ENDPOINT)
                .to_string(),
        }
    }
}

impl Roblox {
    /// Returns the provider name (`"Roblox"`).
    pub fn name(&self) -> &'static str {
        "Roblox"
    }

    /// Builds the Roblox authorization URL that the user should be redirected to.
    ///
    /// The returned URL includes all required OAuth 2.0 parameters and PKCE parameters.
    /// Your application should store `state` and `code_verifier` in the user's session
    /// before redirecting, as they are needed to complete the flow.
    ///
    /// # Arguments
    ///
    /// * `state` - A CSRF token. Use [`generate_state`](crate::generate_state) to create one.
    /// * `scopes` - The OAuth 2.0 scopes to request (e.g. `&["openid", "profile"]`).
    /// * `code_verifier` - The PKCE code verifier. Use
    ///   [`generate_code_verifier`](crate::generate_code_verifier) to create one.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{Roblox, generate_state, generate_code_verifier};
    ///
    /// let provider = Roblox::new("client-id", Some("secret".to_string()), "https://example.com/cb");
    /// let state = generate_state();
    /// let verifier = generate_code_verifier();
    ///
    /// let url = provider.authorization_url(&state, &["openid", "profile"], &verifier);
    /// ```
    pub fn authorization_url(
        &self,
        state: &str,
        scopes: &[&str],
        code_verifier: &str,
    ) -> url::Url {
        self.client.create_authorization_url_with_pkce(
            &self.authorization_endpoint,
            state,
            CodeChallengeMethod::S256,
            code_verifier,
            scopes,
        )
    }

    /// Exchanges an authorization code for access and refresh tokens.
    ///
    /// Call this in your redirect URI handler after Roblox redirects back with a `code`
    /// query parameter. The `code_verifier` must be the same value used to generate the
    /// authorization URL.
    ///
    /// # Arguments
    ///
    /// * `http_client` - An [`HttpClient`](crate::HttpClient) implementation (e.g.
    ///   [`ReqwestClient`](crate::ReqwestClient)).
    /// * `code` - The authorization code from the `code` query parameter.
    /// * `code_verifier` - The PKCE code verifier used when creating the authorization URL.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OAuthRequest`] if Roblox rejects the code, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::{Roblox, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let provider = Roblox::new("client-id", Some("secret".to_string()), "https://example.com/cb");
    /// let http = ReqwestClient::new();
    ///
    /// let tokens = provider
    ///     .validate_authorization_code(&http, "the-auth-code", "the-verifier")
    ///     .await?;
    ///
    /// println!("Access token: {}", tokens.access_token()?);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn validate_authorization_code(
        &self,
        http_client: &(impl HttpClient + ?Sized),
        code: &str,
        code_verifier: &str,
    ) -> Result<OAuth2Tokens, Error> {
        self.client
            .validate_authorization_code(
                http_client,
                &self.token_endpoint,
                code,
                Some(code_verifier),
            )
            .await
    }

    /// Refreshes an expired access token using a refresh token.
    ///
    /// Roblox access tokens typically expire after 15 minutes. Use this method to
    /// obtain a new access token without requiring the user to re-authenticate.
    ///
    /// # Arguments
    ///
    /// * `http_client` - An [`HttpClient`](crate::HttpClient) implementation.
    /// * `refresh_token` - The refresh token from a previous token response.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OAuthRequest`] if the refresh token is invalid or revoked, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::{Roblox, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let provider = Roblox::new("client-id", Some("secret".to_string()), "https://example.com/cb");
    /// let http = ReqwestClient::new();
    ///
    /// let new_tokens = provider
    ///     .refresh_access_token(&http, "stored-refresh-token")
    ///     .await?;
    ///
    /// println!("New access token: {}", new_tokens.access_token()?);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn refresh_access_token(
        &self,
        http_client: &(impl HttpClient + ?Sized),
        refresh_token: &str,
    ) -> Result<OAuth2Tokens, Error> {
        self.client
            .refresh_access_token(http_client, &self.token_endpoint, refresh_token, &[])
            .await
    }

    /// Revokes an access token or refresh token.
    ///
    /// This invalidates the token immediately, preventing further use. Use this when
    /// the user signs out of your application.
    ///
    /// # Arguments
    ///
    /// * `http_client` - An [`HttpClient`](crate::HttpClient) implementation.
    /// * `token` - The access token or refresh token to revoke.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedResponse`] if Roblox returns a non-200 status, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::{Roblox, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let provider = Roblox::new("client-id", Some("secret".to_string()), "https://example.com/cb");
    /// let http = ReqwestClient::new();
    ///
    /// provider.revoke_token(&http, "token-to-revoke").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn revoke_token(
        &self,
        http_client: &(impl HttpClient + ?Sized),
        token: &str,
    ) -> Result<(), Error> {
        self.client
            .revoke_token(http_client, &self.revocation_endpoint, token)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{HttpRequest, HttpResponse};
    use std::sync::Mutex;

    struct MockHttpClient {
        responses: Mutex<Vec<HttpResponse>>,
        recorded: Mutex<Vec<HttpRequest>>,
    }

    impl MockHttpClient {
        fn new(responses: Vec<HttpResponse>) -> Self {
            Self {
                responses: Mutex::new(responses),
                recorded: Mutex::new(Vec::new()),
            }
        }

        fn take_requests(&self) -> Vec<HttpRequest> {
            std::mem::take(&mut self.recorded.lock().unwrap())
        }
    }

    impl HttpClient for MockHttpClient {
        async fn send(
            &self,
            request: HttpRequest,
        ) -> Result<HttpResponse, Box<dyn std::error::Error + Send + Sync>> {
            self.recorded.lock().unwrap().push(request);
            let response = self.responses.lock().unwrap().remove(0);
            Ok(response)
        }
    }

    fn parse_form_body(request: &HttpRequest) -> Vec<(String, String)> {
        url::form_urlencoded::parse(&request.body)
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect()
    }

    #[test]
    fn new_sets_production_endpoints() {
        let roblox = Roblox::new("cid", Some("secret".into()), "https://app/cb");
        assert_eq!(roblox.authorization_endpoint, AUTHORIZATION_ENDPOINT);
        assert_eq!(roblox.token_endpoint, TOKEN_ENDPOINT);
        assert_eq!(roblox.revocation_endpoint, REVOCATION_ENDPOINT);
    }

    #[test]
    fn name_returns_roblox() {
        let roblox = Roblox::new("cid", Some("secret".into()), "https://app/cb");
        assert_eq!(roblox.name(), "Roblox");
    }

    #[test]
    fn authorization_url_includes_pkce() {
        let roblox = Roblox::new("cid", Some("secret".into()), "https://app/cb");
        let url = roblox.authorization_url("state123", &["openid", "profile"], "my-verifier");

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.contains(&("client_id".into(), "cid".into())));
        assert!(pairs.contains(&("state".into(), "state123".into())));
        assert!(pairs.contains(&("scope".into(), "openid profile".into())));
        assert!(pairs.iter().any(|(k, _)| k == "code_challenge"));
        assert!(pairs.contains(&("code_challenge_method".into(), "S256".into())));
    }

    #[tokio::test]
    async fn validate_authorization_code_delegates_to_client() {
        let roblox = Roblox::with_endpoints(
            "cid",
            Some("secret".into()),
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
            None,
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "roblox-tok",
                "token_type": "Bearer",
                "expires_in": 900
            }))
            .unwrap(),
        }]);

        let tokens = roblox
            .validate_authorization_code(&mock, "auth-code", "verifier")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "roblox-tok");

        let requests = mock.take_requests();
        assert_eq!(requests[0].url, "https://mock/token");
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("code_verifier".into(), "verifier".into())));
    }

    #[tokio::test]
    async fn refresh_access_token_delegates_to_client() {
        let roblox = Roblox::with_endpoints(
            "cid",
            Some("secret".into()),
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
            None,
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "new-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);

        let tokens = roblox
            .refresh_access_token(&mock, "refresh-tok")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "new-tok");
    }

    #[tokio::test]
    async fn revoke_token_delegates_to_client() {
        let roblox = Roblox::with_endpoints(
            "cid",
            Some("secret".into()),
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
            Some("https://mock/revoke"),
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: vec![],
        }]);

        let result = roblox.revoke_token(&mock, "tok-to-revoke").await;
        assert!(result.is_ok());

        let requests = mock.take_requests();
        assert_eq!(requests[0].url, "https://mock/revoke");
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("token".into(), "tok-to-revoke".into())));
    }
}
