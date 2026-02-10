use crate::client::OAuth2Client;
use crate::error::Error;
use crate::http::HttpClient;
use crate::tokens::OAuth2Tokens;

/// Configuration for creating a [`GitLab`] client with a custom HTTP client.
///
/// Use this when you need to provide your own [`HttpClient`] implementation
/// (e.g. a pre-configured `reqwest::Client` with custom timeouts or proxies).
/// For the common case, use [`GitLab::new`] which uses the built-in default client.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{GitLab, GitLabOptions, HttpClient};
///
/// let custom_client = reqwest::Client::builder()
///     .timeout(std::time::Duration::from_secs(10))
///     .build()
///     .unwrap();
///
/// let gitlab = GitLab::from_options(GitLabOptions {
///     base_url: "https://gitlab.com".into(),
///     client_id: "your-client-id".into(),
///     client_secret: Some("your-client-secret".into()),
///     redirect_uri: "https://example.com/callback".into(),
///     http_client: &custom_client,
/// });
/// ```
pub struct GitLabOptions<'a, H: HttpClient> {
    pub base_url: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_uri: String,
    pub http_client: &'a H,
}

/// OAuth 2.0 client for [GitLab](https://docs.gitlab.com/ee/api/oauth2.html).
///
/// GitLab follows the standard authorization code flow without requiring PKCE.
/// This client supports both GitLab.com and self-hosted GitLab instances by allowing
/// you to specify a custom base URL. The client supports token exchange, refresh,
/// and revocation.
///
/// # Setup
///
/// 1. Go to your GitLab instance's **User Settings > Applications** (or for groups: **Group Settings > Applications**).
/// 2. Create a new application and note the **Application ID** (client ID) and **Secret** (client secret).
/// 3. Set the **Redirect URI** to match the `redirect_uri` you pass to [`GitLab::new`].
///
/// # Scopes
///
/// GitLab uses space-separated scopes. Common scopes include:
///
/// | Scope | Description |
/// |-------|-------------|
/// | `read_user` | Read user profile |
/// | `openid` | OpenID Connect authentication |
/// | `profile` | User's profile information |
/// | `email` | User's email address |
/// | `api` | Complete API access |
///
/// See the full list at <https://docs.gitlab.com/ee/integration/oauth_provider.html#authorized-applications>.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{GitLab, generate_state};
///
/// # async fn example() -> Result<(), arctic_oauth::Error> {
/// // For GitLab.com:
/// let gitlab = GitLab::new(
///     "https://gitlab.com",
///     "your-client-id",
///     Some("your-client-secret".into()),
///     "https://example.com/callback",
/// );
///
/// // Step 1: Generate CSRF state and redirect the user.
/// let state = generate_state();
/// let url = gitlab.authorization_url(&state, &["read_user", "openid"]);
/// // Store `state` in the user's session, then redirect to `url`.
///
/// // Step 2: In your callback handler, exchange the authorization code for tokens.
/// let tokens = gitlab
///     .validate_authorization_code("authorization-code")
///     .await?;
/// println!("Access token: {}", tokens.access_token()?);
///
/// // Step 3 (optional): Refresh an expired access token.
/// let refreshed = gitlab
///     .refresh_access_token(tokens.refresh_token()?)
///     .await?;
///
/// // Step 4 (optional): Revoke a token.
/// gitlab.revoke_token(tokens.access_token()?).await?;
/// # Ok(())
/// # }
/// ```
pub struct GitLab<'a, H: HttpClient> {
    client: OAuth2Client,
    http_client: &'a H,
    authorization_endpoint: String,
    token_endpoint: String,
    revocation_endpoint: String,
}

impl<'a, H: HttpClient> GitLab<'a, H> {
    /// Creates a GitLab client from a [`GitLabOptions`] struct.
    ///
    /// Use this when you need a custom HTTP client. For the common case,
    /// use [`GitLab::new`] instead.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{GitLab, GitLabOptions};
    ///
    /// let custom_client = reqwest::Client::new();
    /// let gitlab = GitLab::from_options(GitLabOptions {
    ///     base_url: "https://gitlab.com".into(),
    ///     client_id: "your-client-id".into(),
    ///     client_secret: Some("your-client-secret".into()),
    ///     redirect_uri: "https://example.com/callback".into(),
    ///     http_client: &custom_client,
    /// });
    /// ```
    pub fn from_options(options: GitLabOptions<'a, H>) -> Self {
        let base = options.base_url;
        Self {
            http_client: options.http_client,
            client: OAuth2Client::new(
                options.client_id,
                options.client_secret,
                Some(options.redirect_uri),
            ),
            authorization_endpoint: format!("{base}/oauth/authorize"),
            token_endpoint: format!("{base}/oauth/token"),
            revocation_endpoint: format!("{base}/oauth/revoke"),
        }
    }
}

#[cfg(feature = "reqwest-client")]
impl GitLab<'static, reqwest::Client> {
    /// Creates a new GitLab OAuth 2.0 client for a specific GitLab instance.
    ///
    /// Uses the built-in `reqwest::Client` for HTTP requests. To provide a custom
    /// HTTP client, use [`GitLab::from_options`] instead.
    ///
    /// # Arguments
    ///
    /// * `base_url` - The base URL of the GitLab instance (e.g. `"https://gitlab.com"` for
    ///   GitLab.com or `"https://gitlab.example.com"` for self-hosted).
    /// * `client_id` - The OAuth 2.0 application ID from GitLab.
    /// * `client_secret` - Optional client secret. Use `None` for public clients.
    /// * `redirect_uri` - The URI GitLab will redirect to after authorization.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::GitLab;
    ///
    /// // GitLab.com
    /// let gitlab = GitLab::new(
    ///     "https://gitlab.com",
    ///     "your-client-id",
    ///     Some("your-client-secret".into()),
    ///     "https://example.com/callback",
    /// );
    ///
    /// // Self-hosted
    /// let gitlab_self = GitLab::new(
    ///     "https://gitlab.mycompany.com",
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
        Self::from_options(GitLabOptions {
            base_url: base_url.into(),
            client_id: client_id.into(),
            client_secret,
            redirect_uri: redirect_uri.into(),
            http_client: crate::http::default_client(),
        })
    }
}

impl<'a, H: HttpClient> GitLab<'a, H> {
    /// Returns the provider name (`"GitLab"`).
    pub fn name(&self) -> &'static str {
        "GitLab"
    }

    /// Builds the GitLab authorization URL that the user should be redirected to.
    ///
    /// The returned URL includes all required OAuth 2.0 parameters. Your application should
    /// store `state` in the user's session before redirecting.
    ///
    /// # Arguments
    ///
    /// * `state` - A CSRF token to prevent cross-site request forgery. Use
    ///   [`generate_state`](crate::generate_state) to create one.
    /// * `scopes` - The OAuth 2.0 scopes to request (e.g. `&["read_user", "openid"]`).
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{GitLab, generate_state};
    ///
    /// let gitlab = GitLab::new("https://gitlab.com", "client-id", Some("secret".into()), "https://example.com/cb");
    /// let state = generate_state();
    ///
    /// let url = gitlab.authorization_url(&state, &["read_user", "api"]);
    /// assert!(url.as_str().starts_with("https://gitlab.com/"));
    /// ```
    pub fn authorization_url(&self, state: &str, scopes: &[&str]) -> url::Url {
        self.client
            .create_authorization_url(&self.authorization_endpoint, state, scopes)
    }

    /// Exchanges an authorization code for access and refresh tokens.
    ///
    /// Call this in your redirect URI handler after GitLab redirects back with a `code`
    /// query parameter.
    ///
    /// # Arguments
    ///
    /// * `code` - The authorization code from the `code` query parameter.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OAuthRequest`] if GitLab rejects the code, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::GitLab;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let gitlab = GitLab::new("https://gitlab.com", "client-id", Some("secret".into()), "https://example.com/cb");
    ///
    /// let tokens = gitlab
    ///     .validate_authorization_code("the-auth-code")
    ///     .await?;
    ///
    /// println!("Access token: {}", tokens.access_token()?);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn validate_authorization_code(&self, code: &str) -> Result<OAuth2Tokens, Error> {
        self.client
            .validate_authorization_code(self.http_client, &self.token_endpoint, code, None)
            .await
    }

    /// Refreshes an expired access token using a refresh token.
    ///
    /// GitLab access tokens expire after a configurable period (typically 2 hours).
    /// If your initial token response included a refresh token, you can use it to
    /// obtain a new access token without user interaction.
    ///
    /// # Arguments
    ///
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
    /// # use arctic_oauth::GitLab;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let gitlab = GitLab::new("https://gitlab.com", "client-id", Some("secret".into()), "https://example.com/cb");
    ///
    /// let new_tokens = gitlab
    ///     .refresh_access_token("stored-refresh-token")
    ///     .await?;
    ///
    /// println!("New access token: {}", new_tokens.access_token()?);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn refresh_access_token(&self, refresh_token: &str) -> Result<OAuth2Tokens, Error> {
        self.client
            .refresh_access_token(self.http_client, &self.token_endpoint, refresh_token, &[])
            .await
    }

    /// Revokes an access token or refresh token.
    ///
    /// Use this when a user signs out or disconnects your application. GitLab will
    /// invalidate the token and prevent further use.
    ///
    /// # Arguments
    ///
    /// * `token` - The access token or refresh token to revoke.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedResponse`] if GitLab returns a non-200 status, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::GitLab;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let gitlab = GitLab::new("https://gitlab.com", "client-id", Some("secret".into()), "https://example.com/cb");
    ///
    /// gitlab.revoke_token("token-to-revoke").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn revoke_token(&self, token: &str) -> Result<(), Error> {
        self.client
            .revoke_token(self.http_client, &self.revocation_endpoint, token)
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

    fn get_header<'a>(request: &'a HttpRequest, name: &str) -> Option<&'a str> {
        request
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn make_gitlab(http_client: &MockHttpClient) -> GitLab<'_, MockHttpClient> {
        GitLab::from_options(GitLabOptions {
            base_url: "https://gitlab.example.com".into(),
            client_id: "cid".into(),
            client_secret: Some("secret".into()),
            redirect_uri: "https://app/cb".into(),
            http_client,
        })
    }

    #[test]
    fn new_builds_endpoints_from_base_url() {
        let mock = MockHttpClient::new(vec![]);
        let gitlab = make_gitlab(&mock);
        assert_eq!(
            gitlab.authorization_endpoint,
            "https://gitlab.example.com/oauth/authorize"
        );
        assert_eq!(
            gitlab.token_endpoint,
            "https://gitlab.example.com/oauth/token"
        );
        assert_eq!(
            gitlab.revocation_endpoint,
            "https://gitlab.example.com/oauth/revoke"
        );
    }

    #[test]
    fn name_returns_gitlab() {
        let mock = MockHttpClient::new(vec![]);
        let gitlab = GitLab::from_options(GitLabOptions {
            base_url: "https://gitlab.com".into(),
            client_id: "cid".into(),
            client_secret: Some("secret".into()),
            redirect_uri: "https://app/cb".into(),
            http_client: &mock,
        });
        assert_eq!(gitlab.name(), "GitLab");
    }

    #[test]
    fn authorization_url_includes_standard_params() {
        let mock = MockHttpClient::new(vec![]);
        let gitlab = GitLab::from_options(GitLabOptions {
            base_url: "https://gitlab.com".into(),
            client_id: "cid".into(),
            client_secret: Some("secret".into()),
            redirect_uri: "https://app/cb".into(),
            http_client: &mock,
        });
        let url = gitlab.authorization_url("state123", &["read_user", "api"]);

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.contains(&("client_id".into(), "cid".into())));
        assert!(pairs.contains(&("state".into(), "state123".into())));
        assert!(pairs.contains(&("scope".into(), "read_user api".into())));
        assert!(pairs.contains(&("redirect_uri".into(), "https://app/cb".into())));
        // No PKCE
        assert!(!pairs.iter().any(|(k, _)| k == "code_challenge"));
    }

    #[tokio::test]
    async fn validate_authorization_code_delegates_to_client() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "gitlab-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);
        let gitlab = make_gitlab(&mock);

        let tokens = gitlab
            .validate_authorization_code("auth-code")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "gitlab-tok");

        let requests = mock.take_requests();
        assert_eq!(requests[0].url, "https://gitlab.example.com/oauth/token");
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("grant_type".into(), "authorization_code".into())));
        assert!(body.contains(&("code".into(), "auth-code".into())));
        assert!(get_header(&requests[0], "Authorization").is_some());
    }

    #[tokio::test]
    async fn validate_authorization_code_public_client() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "gitlab-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);
        let gitlab = GitLab::from_options(GitLabOptions {
            base_url: "https://mock".into(),
            client_id: "cid".into(),
            client_secret: None,
            redirect_uri: "https://app/cb".into(),
            http_client: &mock,
        });

        gitlab
            .validate_authorization_code("auth-code")
            .await
            .unwrap();

        let requests = mock.take_requests();
        assert!(get_header(&requests[0], "Authorization").is_none());
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("client_id".into(), "cid".into())));
    }

    #[tokio::test]
    async fn refresh_access_token_delegates_to_client() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "new-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);
        let gitlab = make_gitlab(&mock);

        let tokens = gitlab.refresh_access_token("rt").await.unwrap();
        assert_eq!(tokens.access_token().unwrap(), "new-tok");

        let requests = mock.take_requests();
        assert_eq!(requests[0].url, "https://gitlab.example.com/oauth/token");
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("grant_type".into(), "refresh_token".into())));
    }

    #[tokio::test]
    async fn revoke_token_delegates_to_client() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: vec![],
        }]);
        let gitlab = make_gitlab(&mock);

        let result = gitlab.revoke_token("tok").await;
        assert!(result.is_ok());

        let requests = mock.take_requests();
        assert_eq!(requests[0].url, "https://gitlab.example.com/oauth/revoke");
    }
}
