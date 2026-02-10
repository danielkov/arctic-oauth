use crate::client::OAuth2Client;
use crate::error::Error;
use crate::http::HttpClient;
use crate::pkce::CodeChallengeMethod;
use crate::tokens::OAuth2Tokens;

const AUTHORIZATION_ENDPOINT: &str = "https://twitter.com/i/oauth2/authorize";
const TOKEN_ENDPOINT: &str = "https://api.twitter.com/2/oauth2/token";
const REVOCATION_ENDPOINT: &str = "https://api.twitter.com/2/oauth2/revoke";

/// Configuration for creating a [`Twitter`] client with a custom HTTP client.
///
/// Use this when you need to provide your own [`HttpClient`] implementation
/// (e.g. a pre-configured `reqwest::Client` with custom timeouts or proxies).
/// For the common case, use [`Twitter::new`] which uses the built-in default client.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{Twitter, TwitterOptions, HttpClient};
///
/// let custom_client = reqwest::Client::builder()
///     .timeout(std::time::Duration::from_secs(10))
///     .build()
///     .unwrap();
///
/// let twitter = Twitter::from_options(TwitterOptions {
///     client_id: "your-client-id".into(),
///     client_secret: Some("your-client-secret".into()),
///     redirect_uri: "https://example.com/callback".into(),
///     http_client: &custom_client,
/// });
/// ```
pub struct TwitterOptions<'a, H: HttpClient> {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_uri: String,
    pub http_client: &'a H,
}

/// OAuth 2.0 client for [X (formerly Twitter)](https://docs.x.com/fundamentals/authentication/oauth-2-0/overview).
///
/// X requires PKCE with the S256 challenge method for authorization requests.
/// This client supports the full authorization code flow including token refresh and
/// revocation. The client secret is optional for public clients.
///
/// # Setup
///
/// 1. Create a project and app in the [X Developer Portal](https://developer.x.com/en/portal/dashboard).
/// 2. Navigate to your app settings and enable **OAuth 2.0** authentication.
/// 3. Obtain your **Client ID** and **Client Secret** (if using a confidential client).
/// 4. Add your redirect URI to the **Callback URI / Redirect URL** list to match the
///    `redirect_uri` you pass to [`Twitter::new`].
///
/// # Scopes
///
/// X uses space-separated scopes. Common scopes include:
///
/// | Scope | Description |
/// |-------|-------------|
/// | `tweet.read` | Read tweets, including protected tweets |
/// | `tweet.write` | Create, delete, and manage tweets |
/// | `users.read` | Read user profile information |
/// | `follows.read` | Read follows and followers |
/// | `offline.access` | Enable refresh tokens |
///
/// See the full list at <https://docs.x.com/fundamentals/authentication/oauth-2-0/overview>.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{Twitter, generate_state, generate_code_verifier};
///
/// # async fn example() -> Result<(), arctic_oauth::Error> {
/// let twitter = Twitter::new(
///     "your-client-id",
///     Some("your-client-secret".into()),
///     "https://example.com/callback",
/// );
///
/// // Step 1: Generate PKCE verifier and CSRF state, then redirect the user.
/// let state = generate_state();
/// let code_verifier = generate_code_verifier();
/// let url = twitter.authorization_url(&state, &["tweet.read", "users.read"], &code_verifier);
/// // Store `state` and `code_verifier` in the user's session, then redirect to `url`.
///
/// // Step 2: In your callback handler, exchange the authorization code for tokens.
/// let tokens = twitter
///     .validate_authorization_code("authorization-code", &code_verifier)
///     .await?;
/// println!("Access token: {}", tokens.access_token()?);
///
/// // Step 3 (optional): Refresh an expired access token.
/// let refreshed = twitter
///     .refresh_access_token(tokens.refresh_token()?)
///     .await?;
///
/// // Step 4 (optional): Revoke a token.
/// twitter.revoke_token(tokens.access_token()?).await?;
/// # Ok(())
/// # }
/// ```
pub struct Twitter<'a, H: HttpClient> {
    client: OAuth2Client,
    http_client: &'a H,
    authorization_endpoint: String,
    token_endpoint: String,
    revocation_endpoint: String,
}

impl<'a, H: HttpClient> Twitter<'a, H> {
    /// Creates a Twitter client from a [`TwitterOptions`] struct.
    ///
    /// Use this when you need a custom HTTP client. For the common case,
    /// use [`Twitter::new`] instead.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{Twitter, TwitterOptions};
    ///
    /// let custom_client = reqwest::Client::new();
    /// let twitter = Twitter::from_options(TwitterOptions {
    ///     client_id: "your-client-id".into(),
    ///     client_secret: Some("your-client-secret".into()),
    ///     redirect_uri: "https://example.com/callback".into(),
    ///     http_client: &custom_client,
    /// });
    /// ```
    pub fn from_options(options: TwitterOptions<'a, H>) -> Self {
        Self {
            http_client: options.http_client,
            client: OAuth2Client::new(
                options.client_id,
                options.client_secret,
                Some(options.redirect_uri),
            ),
            authorization_endpoint: AUTHORIZATION_ENDPOINT.to_string(),
            token_endpoint: TOKEN_ENDPOINT.to_string(),
            revocation_endpoint: REVOCATION_ENDPOINT.to_string(),
        }
    }
}

#[cfg(feature = "reqwest-client")]
impl Twitter<'static, reqwest::Client> {
    /// Creates a new X (formerly Twitter) OAuth 2.0 client using the default HTTP client.
    ///
    /// The endpoints are automatically set to production values.
    /// Uses the built-in `reqwest::Client` for HTTP requests. To provide a custom
    /// HTTP client, use [`Twitter::from_options`] instead.
    ///
    /// # Arguments
    ///
    /// * `client_id` - The OAuth 2.0 Client ID from the X Developer Portal.
    /// * `client_secret` - The OAuth 2.0 Client Secret (optional for public clients).
    /// * `redirect_uri` - The URI X will redirect to after authorization. Must be listed
    ///   in your app's Callback URI / Redirect URL settings.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::Twitter;
    ///
    /// // With client secret (confidential client)
    /// let twitter = Twitter::new(
    ///     "your-client-id",
    ///     Some("your-client-secret".into()),
    ///     "https://example.com/callback",
    /// );
    ///
    /// // Without client secret (public client)
    /// let twitter_public = Twitter::new(
    ///     "your-client-id",
    ///     None,
    ///     "https://example.com/callback",
    /// );
    /// ```
    pub fn new(
        client_id: impl Into<String>,
        client_secret: Option<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        Self::from_options(TwitterOptions {
            client_id: client_id.into(),
            client_secret,
            redirect_uri: redirect_uri.into(),
            http_client: crate::http::default_client(),
        })
    }
}

impl<'a, H: HttpClient> Twitter<'a, H> {
    /// Returns the provider name (`"Twitter"`).
    pub fn name(&self) -> &'static str {
        "Twitter"
    }

    /// Builds the X authorization URL that the user should be redirected to.
    ///
    /// The returned URL includes all required OAuth 2.0 and PKCE parameters. Your
    /// application should store `state` and `code_verifier` in the user's session
    /// before redirecting, as both are needed to complete the flow.
    ///
    /// # Arguments
    ///
    /// * `state` - A CSRF token to prevent cross-site request forgery. Use
    ///   [`generate_state`](crate::generate_state) to create one.
    /// * `scopes` - The OAuth 2.0 scopes to request (e.g. `&["tweet.read", "users.read"]`).
    ///   Include `offline.access` if you need refresh tokens.
    /// * `code_verifier` - The PKCE code verifier. Use
    ///   [`generate_code_verifier`](crate::generate_code_verifier) to create one.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{Twitter, generate_state, generate_code_verifier};
    ///
    /// let twitter = Twitter::new("client-id", None, "https://example.com/cb");
    /// let state = generate_state();
    /// let verifier = generate_code_verifier();
    ///
    /// let url = twitter.authorization_url(&state, &["tweet.read", "users.read"], &verifier);
    /// assert!(url.as_str().starts_with("https://twitter.com/"));
    /// ```
    pub fn authorization_url(&self, state: &str, scopes: &[&str], code_verifier: &str) -> url::Url {
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
    /// Call this in your redirect URI handler after X redirects back with a `code`
    /// query parameter. The `code_verifier` must be the same value used to generate the
    /// authorization URL.
    ///
    /// # Arguments
    ///
    /// * `code` - The authorization code from the `code` query parameter.
    /// * `code_verifier` - The PKCE code verifier stored during the authorization step.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OAuthRequest`] if X rejects the code, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::Twitter;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let twitter = Twitter::new("client-id", Some("secret".into()), "https://example.com/cb");
    ///
    /// let tokens = twitter
    ///     .validate_authorization_code("the-auth-code", "the-code-verifier")
    ///     .await?;
    ///
    /// println!("Access token: {}", tokens.access_token()?);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn validate_authorization_code(
        &self,
        code: &str,
        code_verifier: &str,
    ) -> Result<OAuth2Tokens, Error> {
        self.client
            .validate_authorization_code(
                self.http_client,
                &self.token_endpoint,
                code,
                Some(code_verifier),
            )
            .await
    }

    /// Refreshes an expired access token using a refresh token.
    ///
    /// X access tokens typically expire after 2 hours. If you requested the
    /// `offline.access` scope and your initial token response included a refresh token,
    /// you can use it to obtain a new access token without user interaction.
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
    /// # use arctic_oauth::Twitter;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let twitter = Twitter::new("client-id", Some("secret".into()), "https://example.com/cb");
    ///
    /// let new_tokens = twitter
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
    /// Use this when a user signs out or disconnects your application. Revoking a token
    /// invalidates it immediately.
    ///
    /// # Arguments
    ///
    /// * `token` - The access token or refresh token to revoke.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OAuthRequest`] if X rejects the request, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::Twitter;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let twitter = Twitter::new("client-id", Some("secret".into()), "https://example.com/cb");
    ///
    /// twitter.revoke_token("token-to-revoke").await?;
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

    fn make_twitter(http_client: &MockHttpClient) -> Twitter<'_, MockHttpClient> {
        Twitter::from_options(TwitterOptions {
            client_id: "cid".into(),
            client_secret: Some("secret".into()),
            redirect_uri: "https://app/cb".into(),
            http_client,
        })
    }

    #[test]
    fn new_sets_production_endpoints() {
        let mock = MockHttpClient::new(vec![]);
        let twitter = make_twitter(&mock);
        assert_eq!(twitter.authorization_endpoint, AUTHORIZATION_ENDPOINT);
        assert_eq!(twitter.token_endpoint, TOKEN_ENDPOINT);
        assert_eq!(twitter.revocation_endpoint, REVOCATION_ENDPOINT);
    }

    #[test]
    fn name_returns_twitter() {
        let mock = MockHttpClient::new(vec![]);
        let twitter = make_twitter(&mock);
        assert_eq!(twitter.name(), "Twitter");
    }

    #[test]
    fn authorization_url_includes_pkce() {
        let mock = MockHttpClient::new(vec![]);
        let twitter = make_twitter(&mock);
        let url = twitter.authorization_url("state123", &["tweet.read"], "my-verifier");

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.iter().any(|(k, _)| k == "code_challenge"));
        assert!(pairs.contains(&("code_challenge_method".into(), "S256".into())));
    }

    #[tokio::test]
    async fn validate_authorization_code_sends_verifier() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "twitter-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);
        let twitter = make_twitter(&mock);

        let tokens = twitter
            .validate_authorization_code("code", "verifier")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "twitter-tok");

        let requests = mock.take_requests();
        assert_eq!(requests[0].url, TOKEN_ENDPOINT);
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("code_verifier".into(), "verifier".into())));
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
        let twitter = make_twitter(&mock);

        let tokens = twitter.refresh_access_token("rt").await.unwrap();
        assert_eq!(tokens.access_token().unwrap(), "new-tok");
    }

    #[tokio::test]
    async fn revoke_token_delegates_to_client() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: vec![],
        }]);
        let twitter = make_twitter(&mock);

        let result = twitter.revoke_token("tok").await;
        assert!(result.is_ok());

        let requests = mock.take_requests();
        assert_eq!(requests[0].url, REVOCATION_ENDPOINT);
    }
}
