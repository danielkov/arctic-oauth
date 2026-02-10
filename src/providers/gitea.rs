use crate::client::OAuth2Client;
use crate::error::Error;
use crate::http::HttpClient;
use crate::pkce::CodeChallengeMethod;
use crate::tokens::OAuth2Tokens;

/// OAuth 2.0 client for [Gitea](https://docs.gitea.com/development/oauth2-provider).
///
/// Gitea requires PKCE with the S256 challenge method on all authorization requests.
/// This client supports self-hosted Gitea instances by allowing you to specify a
/// custom base URL. The client supports the authorization code flow with token exchange
/// and refresh.
///
/// # Setup
///
/// 1. In your Gitea instance, go to **Settings > Applications** (in user or organization settings).
/// 2. Create a new OAuth2 application and note the **Client ID** and **Client Secret**.
/// 3. Set the **Redirect URI** to match the `redirect_uri` you pass to [`Gitea::new`].
///
/// # Scopes
///
/// Gitea uses space-separated scopes. Common scopes include:
///
/// | Scope | Description |
/// |-------|-------------|
/// | `user` | Full access to user profile |
/// | `repo` | Access to repositories |
/// | `write:repo` | Write access to repositories |
///
/// See your Gitea instance's OAuth documentation for the full list of available scopes.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{Gitea, ReqwestClient, generate_state, generate_code_verifier};
///
/// # async fn example() -> Result<(), arctic_oauth::Error> {
/// let gitea = Gitea::new(
///     "https://gitea.example.com",
///     "your-client-id",
///     Some("your-client-secret".into()),
///     "https://example.com/callback",
/// );
///
/// // Step 1: Generate PKCE verifier and CSRF state, then redirect the user.
/// let state = generate_state();
/// let code_verifier = generate_code_verifier();
/// let url = gitea.authorization_url(&state, &["user", "repo"], &code_verifier);
/// // Store `state` and `code_verifier` in the user's session, then redirect to `url`.
///
/// // Step 2: In your callback handler, exchange the authorization code for tokens.
/// let http = ReqwestClient::new();
/// let tokens = gitea
///     .validate_authorization_code(&http, "authorization-code", &code_verifier)
///     .await?;
/// println!("Access token: {}", tokens.access_token()?);
///
/// // Step 3 (optional): Refresh an expired access token.
/// let refreshed = gitea
///     .refresh_access_token(&http, tokens.refresh_token()?)
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct Gitea {
    client: OAuth2Client,
    authorization_endpoint: String,
    token_endpoint: String,
}

impl Gitea {
    /// Creates a new Gitea OAuth 2.0 client for a specific Gitea instance.
    ///
    /// # Arguments
    ///
    /// * `base_url` - The base URL of the Gitea instance (e.g. `"https://gitea.example.com"`).
    /// * `client_id` - The OAuth 2.0 application ID from Gitea.
    /// * `client_secret` - Optional client secret. Use `None` for public clients.
    /// * `redirect_uri` - The URI Gitea will redirect to after authorization.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::Gitea;
    ///
    /// let gitea = Gitea::new(
    ///     "https://gitea.example.com",
    ///     "your-client-id",
    ///     Some("your-client-secret".into()),
    ///     "https://example.com/callback",
    /// );
    /// ```
    pub fn new(
        base_url: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: Option<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        let base = base_url.into();
        Self {
            client: OAuth2Client::new(client_id, client_secret, Some(redirect_uri.into())),
            authorization_endpoint: format!("{base}/login/oauth/authorize"),
            token_endpoint: format!("{base}/login/oauth/access_token"),
        }
    }
}

impl Gitea {
    /// Returns the provider name (`"Gitea"`).
    pub fn name(&self) -> &'static str {
        "Gitea"
    }

    /// Builds the Gitea authorization URL that the user should be redirected to.
    ///
    /// The returned URL includes all required OAuth 2.0 and PKCE parameters. Your
    /// application should store `state` and `code_verifier` in the user's session
    /// before redirecting, as both are needed to complete the flow.
    ///
    /// # Arguments
    ///
    /// * `state` - A CSRF token to prevent cross-site request forgery. Use
    ///   [`generate_state`](crate::generate_state) to create one.
    /// * `scopes` - The OAuth 2.0 scopes to request (e.g. `&["user", "repo"]`).
    /// * `code_verifier` - The PKCE code verifier. Use
    ///   [`generate_code_verifier`](crate::generate_code_verifier) to create one.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{Gitea, generate_state, generate_code_verifier};
    ///
    /// let gitea = Gitea::new("https://gitea.example.com", "client-id", None, "https://example.com/cb");
    /// let state = generate_state();
    /// let verifier = generate_code_verifier();
    ///
    /// let url = gitea.authorization_url(&state, &["user"], &verifier);
    /// assert!(url.as_str().contains("/login/oauth/authorize"));
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
    /// Call this in your redirect URI handler after Gitea redirects back with a `code`
    /// query parameter. The `code_verifier` must be the same value used to generate the
    /// authorization URL.
    ///
    /// # Arguments
    ///
    /// * `http_client` - An [`HttpClient`](crate::HttpClient) implementation (e.g.
    ///   [`ReqwestClient`](crate::ReqwestClient)).
    /// * `code` - The authorization code from the `code` query parameter.
    /// * `code_verifier` - The PKCE code verifier stored during the authorization step.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OAuthRequest`] if Gitea rejects the code, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::{Gitea, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let gitea = Gitea::new("https://gitea.example.com", "client-id", Some("secret".into()), "https://example.com/cb");
    /// let http = ReqwestClient::new();
    ///
    /// let tokens = gitea
    ///     .validate_authorization_code(&http, "the-auth-code", "the-code-verifier")
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
    /// Gitea access tokens expire after a configurable period. If your initial token response
    /// included a refresh token, you can use it to obtain a new access token without user
    /// interaction.
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
    /// # use arctic_oauth::{Gitea, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let gitea = Gitea::new("https://gitea.example.com", "client-id", Some("secret".into()), "https://example.com/cb");
    /// let http = ReqwestClient::new();
    ///
    /// let new_tokens = gitea
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
    fn new_builds_endpoints_from_base_url() {
        let gitea = Gitea::new("https://gitea.example.com", "cid", None, "https://app/cb");
        assert_eq!(
            gitea.authorization_endpoint,
            "https://gitea.example.com/login/oauth/authorize"
        );
        assert_eq!(
            gitea.token_endpoint,
            "https://gitea.example.com/login/oauth/access_token"
        );
    }

    #[test]
    fn name_returns_gitea() {
        let gitea = Gitea::new("https://gitea.example.com", "cid", None, "https://app/cb");
        assert_eq!(gitea.name(), "Gitea");
    }

    #[test]
    fn authorization_url_includes_pkce() {
        let gitea = Gitea::new("https://gitea.example.com", "cid", None, "https://app/cb");
        let url = gitea.authorization_url("state123", &["repo"], "my-verifier");

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.contains(&("client_id".into(), "cid".into())));
        assert!(pairs.iter().any(|(k, _)| k == "code_challenge"));
        assert!(pairs.contains(&("code_challenge_method".into(), "S256".into())));
    }

    #[tokio::test]
    async fn validate_authorization_code_sends_verifier() {
        let gitea = Gitea::new("https://mock", "cid", Some("secret".into()), "https://app/cb");
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "gitea-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);

        let tokens = gitea
            .validate_authorization_code(&mock, "code", "verifier")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "gitea-tok");

        let requests = mock.take_requests();
        assert_eq!(requests[0].url, "https://mock/login/oauth/access_token");
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("code_verifier".into(), "verifier".into())));
    }

    #[tokio::test]
    async fn refresh_access_token_delegates_to_client() {
        let gitea = Gitea::new("https://mock", "cid", Some("secret".into()), "https://app/cb");
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "new-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);

        let tokens = gitea.refresh_access_token(&mock, "rt").await.unwrap();
        assert_eq!(tokens.access_token().unwrap(), "new-tok");
    }
}
