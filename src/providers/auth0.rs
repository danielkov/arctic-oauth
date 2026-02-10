use crate::client::OAuth2Client;
use crate::error::Error;
use crate::http::HttpClient;
use crate::pkce::CodeChallengeMethod;
use crate::tokens::OAuth2Tokens;

/// OAuth 2.0 client for [Auth0](https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow).
///
/// Auth0 optionally supports PKCE with the S256 challenge method. This client supports
/// the full authorization code flow with and without PKCE, including token refresh and
/// revocation. The client secret is optional for public clients.
///
/// # Setup
///
/// 1. Create an application in the [Auth0 Dashboard](https://manage.auth0.com/).
/// 2. Go to **Applications > Applications** and create a new application.
/// 3. Copy your domain, client ID, and client secret from the application settings.
/// 4. Add your redirect URI under **Application URIs > Allowed Callback URLs**.
///
/// # Scopes
///
/// Auth0 uses space-separated scopes. Common scopes include:
///
/// | Scope | Description |
/// |-------|-------------|
/// | `openid` | OpenID Connect authentication |
/// | `profile` | User's profile information |
/// | `email` | User's email address |
/// | `offline_access` | Request a refresh token |
///
/// See the full list at <https://auth0.com/docs/get-started/apis/scopes>.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{Auth0, ReqwestClient, generate_state, generate_code_verifier};
///
/// # async fn example() -> Result<(), arctic_oauth::Error> {
/// let auth0 = Auth0::new(
///     "myapp.us.auth0.com",
///     "your-client-id",
///     Some("your-client-secret".into()),
///     "https://example.com/callback",
/// );
///
/// // Step 1: Generate PKCE verifier and CSRF state, then redirect the user.
/// let state = generate_state();
/// let code_verifier = generate_code_verifier();
/// let url = auth0.authorization_url(&state, &["openid", "profile"], Some(&code_verifier));
/// // Store `state` and `code_verifier` in the user's session, then redirect to `url`.
///
/// // Step 2: In your callback handler, exchange the authorization code for tokens.
/// let http = ReqwestClient::new();
/// let tokens = auth0
///     .validate_authorization_code(&http, "authorization-code", Some(&code_verifier))
///     .await?;
/// println!("Access token: {}", tokens.access_token()?);
///
/// // Step 3 (optional): Refresh an expired access token.
/// let refreshed = auth0
///     .refresh_access_token(&http, tokens.refresh_token()?)
///     .await?;
///
/// // Step 4 (optional): Revoke a token.
/// auth0.revoke_token(&http, tokens.access_token()?).await?;
/// # Ok(())
/// # }
/// ```
pub struct Auth0 {
    client: OAuth2Client,
    authorization_endpoint: String,
    token_endpoint: String,
    revocation_endpoint: String,
}

impl Auth0 {
    /// Creates a new Auth0 OAuth 2.0 client.
    ///
    /// The endpoints are automatically constructed from your Auth0 domain.
    ///
    /// # Arguments
    ///
    /// * `domain` - Your Auth0 tenant domain (e.g., `myapp.us.auth0.com`).
    /// * `client_id` - The client ID from your Auth0 application.
    /// * `client_secret` - The client secret (optional for public clients).
    /// * `redirect_uri` - The URI Auth0 will redirect to after authorization. Must match
    ///   one of the allowed callback URLs configured in your Auth0 application.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::Auth0;
    ///
    /// let auth0 = Auth0::new(
    ///     "myapp.us.auth0.com",
    ///     "your-client-id",
    ///     Some("your-client-secret".into()),
    ///     "https://example.com/callback",
    /// );
    /// ```
    pub fn new(
        domain: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: Option<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        let domain = domain.into();
        Self {
            client: OAuth2Client::new(client_id, client_secret, Some(redirect_uri.into())),
            authorization_endpoint: format!("https://{domain}/authorize"),
            token_endpoint: format!("https://{domain}/oauth/token"),
            revocation_endpoint: format!("https://{domain}/oauth/revoke"),
        }
    }
}

impl Auth0 {
    /// Returns the provider name (`"Auth0"`).
    pub fn name(&self) -> &'static str {
        "Auth0"
    }

    /// Builds the Auth0 authorization URL that the user should be redirected to.
    ///
    /// The returned URL includes all required OAuth 2.0 parameters, and optionally PKCE
    /// parameters if `code_verifier` is provided. Your application should store `state`
    /// (and `code_verifier` if using PKCE) in the user's session before redirecting.
    ///
    /// # Arguments
    ///
    /// * `state` - A CSRF token to prevent cross-site request forgery. Use
    ///   [`generate_state`](crate::generate_state) to create one.
    /// * `scopes` - The OAuth 2.0 scopes to request (e.g. `&["openid", "profile"]`).
    /// * `code_verifier` - Optional PKCE code verifier. Use
    ///   [`generate_code_verifier`](crate::generate_code_verifier) to create one, or pass
    ///   `None` to skip PKCE.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{Auth0, generate_state, generate_code_verifier};
    ///
    /// let auth0 = Auth0::new("myapp.us.auth0.com", "client-id", Some("secret".into()), "https://example.com/cb");
    /// let state = generate_state();
    /// let verifier = generate_code_verifier();
    ///
    /// // With PKCE:
    /// let url = auth0.authorization_url(&state, &["openid", "profile"], Some(&verifier));
    /// assert!(url.as_str().starts_with("https://"));
    ///
    /// // Without PKCE:
    /// let url_no_pkce = auth0.authorization_url(&state, &["openid", "profile"], None);
    /// ```
    pub fn authorization_url(
        &self,
        state: &str,
        scopes: &[&str],
        code_verifier: Option<&str>,
    ) -> url::Url {
        match code_verifier {
            Some(verifier) => self.client.create_authorization_url_with_pkce(
                &self.authorization_endpoint,
                state,
                CodeChallengeMethod::S256,
                verifier,
                scopes,
            ),
            None => self
                .client
                .create_authorization_url(&self.authorization_endpoint, state, scopes),
        }
    }

    /// Exchanges an authorization code for access and refresh tokens.
    ///
    /// Call this in your redirect URI handler after Auth0 redirects back with a `code`
    /// query parameter. If you used PKCE in the authorization URL, you must pass the
    /// same `code_verifier` here.
    ///
    /// # Arguments
    ///
    /// * `http_client` - An [`HttpClient`](crate::HttpClient) implementation (e.g.
    ///   [`ReqwestClient`](crate::ReqwestClient)).
    /// * `code` - The authorization code from the `code` query parameter.
    /// * `code_verifier` - Optional PKCE code verifier stored during the authorization step.
    ///   Pass `None` if you did not use PKCE.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OAuthRequest`] if Auth0 rejects the code, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::{Auth0, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let auth0 = Auth0::new("myapp.us.auth0.com", "client-id", Some("secret".into()), "https://example.com/cb");
    /// let http = ReqwestClient::new();
    ///
    /// // With PKCE:
    /// let tokens = auth0
    ///     .validate_authorization_code(&http, "the-auth-code", Some("the-code-verifier"))
    ///     .await?;
    ///
    /// // Without PKCE:
    /// let tokens_no_pkce = auth0
    ///     .validate_authorization_code(&http, "the-auth-code", None)
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
        code_verifier: Option<&str>,
    ) -> Result<OAuth2Tokens, Error> {
        self.client
            .validate_authorization_code(http_client, &self.token_endpoint, code, code_verifier)
            .await
    }

    /// Refreshes an expired access token using a refresh token.
    ///
    /// Auth0 access tokens expire after a set period. If your initial token response
    /// included a refresh token (requires the `offline_access` scope), you can use it
    /// to obtain a new access token without user interaction.
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
    /// # use arctic_oauth::{Auth0, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let auth0 = Auth0::new("myapp.us.auth0.com", "client-id", Some("secret".into()), "https://example.com/cb");
    /// let http = ReqwestClient::new();
    ///
    /// let new_tokens = auth0
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
    /// Use this when a user signs out or disconnects your application. Revoking a
    /// refresh token will invalidate all access tokens issued from it.
    ///
    /// # Arguments
    ///
    /// * `http_client` - An [`HttpClient`](crate::HttpClient) implementation.
    /// * `token` - The access token or refresh token to revoke.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedResponse`] if Auth0 returns a non-200 status, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::{Auth0, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let auth0 = Auth0::new("myapp.us.auth0.com", "client-id", Some("secret".into()), "https://example.com/cb");
    /// let http = ReqwestClient::new();
    ///
    /// auth0.revoke_token(&http, "token-to-revoke").await?;
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
    fn new_builds_endpoints_from_domain() {
        let auth0 = Auth0::new(
            "myapp.us.auth0.com",
            "cid",
            Some("secret".into()),
            "https://app/cb",
        );
        assert_eq!(
            auth0.authorization_endpoint,
            "https://myapp.us.auth0.com/authorize"
        );
        assert_eq!(
            auth0.token_endpoint,
            "https://myapp.us.auth0.com/oauth/token"
        );
        assert_eq!(
            auth0.revocation_endpoint,
            "https://myapp.us.auth0.com/oauth/revoke"
        );
    }

    #[test]
    fn name_returns_auth0() {
        let auth0 = Auth0::new("example.auth0.com", "cid", None, "https://app/cb");
        assert_eq!(auth0.name(), "Auth0");
    }

    #[test]
    fn authorization_url_without_pkce() {
        let auth0 = Auth0::new("example.auth0.com", "cid", Some("secret".into()), "https://app/cb");
        let url = auth0.authorization_url("state123", &["openid"], None);

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(!pairs.iter().any(|(k, _)| k == "code_challenge"));
    }

    #[test]
    fn authorization_url_with_pkce() {
        let auth0 = Auth0::new("example.auth0.com", "cid", Some("secret".into()), "https://app/cb");
        let url = auth0.authorization_url("state123", &["openid"], Some("my-verifier"));

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.iter().any(|(k, _)| k == "code_challenge"));
        assert!(pairs.contains(&("code_challenge_method".into(), "S256".into())));
    }

    #[tokio::test]
    async fn validate_authorization_code_with_pkce() {
        let auth0 = Auth0::new("mock.auth0.com", "cid", Some("secret".into()), "https://app/cb");
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "auth0-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);

        let tokens = auth0
            .validate_authorization_code(&mock, "code", Some("verifier"))
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "auth0-tok");

        let requests = mock.take_requests();
        assert_eq!(requests[0].url, "https://mock.auth0.com/oauth/token");
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("code_verifier".into(), "verifier".into())));
    }

    #[tokio::test]
    async fn validate_authorization_code_without_pkce() {
        let auth0 = Auth0::new("mock.auth0.com", "cid", Some("secret".into()), "https://app/cb");
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "auth0-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);

        auth0
            .validate_authorization_code(&mock, "code", None)
            .await
            .unwrap();

        let requests = mock.take_requests();
        let body = parse_form_body(&requests[0]);
        assert!(!body.iter().any(|(k, _)| k == "code_verifier"));
    }

    #[tokio::test]
    async fn revoke_token_delegates_to_client() {
        let auth0 = Auth0::new("mock.auth0.com", "cid", Some("secret".into()), "https://app/cb");
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: vec![],
        }]);

        let result = auth0.revoke_token(&mock, "tok").await;
        assert!(result.is_ok());

        let requests = mock.take_requests();
        assert_eq!(requests[0].url, "https://mock.auth0.com/oauth/revoke");
    }
}
