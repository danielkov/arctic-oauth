use crate::client::OAuth2Client;
use crate::error::Error;
use crate::http::HttpClient;
use crate::pkce::CodeChallengeMethod;
use crate::tokens::OAuth2Tokens;

/// Configuration for creating a [`Mastodon`] client with a custom HTTP client.
///
/// Use this when you need to provide your own [`HttpClient`] implementation
/// (e.g. a pre-configured `reqwest::Client` with custom timeouts or proxies).
/// For the common case, use [`Mastodon::new`] which uses the built-in default client.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{Mastodon, MastodonOptions, HttpClient};
///
/// let custom_client = reqwest::Client::builder()
///     .timeout(std::time::Duration::from_secs(10))
///     .build()
///     .unwrap();
///
/// let mastodon = Mastodon::from_options(MastodonOptions {
///     base_url: "https://mastodon.social".into(),
///     client_id: "your-client-id".into(),
///     client_secret: "your-client-secret".into(),
///     redirect_uri: "https://example.com/callback".into(),
///     http_client: &custom_client,
/// });
/// ```
pub struct MastodonOptions<'a, H: HttpClient> {
    pub base_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub http_client: &'a H,
}

/// OAuth 2.0 client for [Mastodon](https://docs.joinmastodon.org/client/token/).
///
/// Mastodon requires PKCE with the S256 challenge method on all authorization requests.
/// This client supports the authorization code flow including token revocation. Note that
/// Mastodon is a federated platform, so you must specify the instance base URL.
///
/// # Setup
///
/// 1. Register your application on the target Mastodon instance via the API (`POST /api/v1/apps`) or web interface.
/// 2. Obtain the **client_id** and **client_secret** from the registration response.
/// 3. Set the **redirect_uri** to match the value you pass to [`Mastodon::new`].
///
/// # Scopes
///
/// Mastodon uses space-separated scopes. Common scopes include:
///
/// | Scope | Description |
/// |-------|-------------|
/// | `read` | Read access to all data |
/// | `write` | Write access to all data |
/// | `follow` | Modify account relationships |
/// | `push` | Receive push notifications |
///
/// See the full list at <https://docs.joinmastodon.org/api/oauth-scopes/>.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{Mastodon, generate_state, generate_code_verifier};
///
/// # async fn example() -> Result<(), arctic_oauth::Error> {
/// let mastodon = Mastodon::new(
///     "https://mastodon.social",
///     "your-client-id",
///     "your-client-secret",
///     "https://example.com/callback",
/// );
///
/// // Step 1: Generate PKCE verifier and CSRF state, then redirect the user.
/// let state = generate_state();
/// let code_verifier = generate_code_verifier();
/// let url = mastodon.authorization_url(&state, &["read", "write"], &code_verifier);
///
/// // Step 2: Exchange the authorization code for tokens.
/// let tokens = mastodon
///     .validate_authorization_code("authorization-code", &code_verifier)
///     .await?;
/// println!("Access token: {}", tokens.access_token()?);
///
/// // Step 3 (optional): Revoke a token.
/// mastodon.revoke_token(tokens.access_token()?).await?;
/// # Ok(())
/// # }
/// ```
pub struct Mastodon<'a, H: HttpClient> {
    client: OAuth2Client,
    http_client: &'a H,
    authorization_endpoint: String,
    token_endpoint: String,
    revocation_endpoint: String,
}

impl<'a, H: HttpClient> Mastodon<'a, H> {
    /// Creates a Mastodon client from a [`MastodonOptions`] struct.
    ///
    /// Use this when you need a custom HTTP client. For the common case,
    /// use [`Mastodon::new`] instead.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{Mastodon, MastodonOptions};
    ///
    /// let custom_client = reqwest::Client::new();
    /// let mastodon = Mastodon::from_options(MastodonOptions {
    ///     base_url: "https://mastodon.social".into(),
    ///     client_id: "your-client-id".into(),
    ///     client_secret: "your-client-secret".into(),
    ///     redirect_uri: "https://example.com/callback".into(),
    ///     http_client: &custom_client,
    /// });
    /// ```
    pub fn from_options(options: MastodonOptions<'a, H>) -> Self {
        let base = options.base_url;
        Self {
            http_client: options.http_client,
            client: OAuth2Client::new(
                options.client_id,
                Some(options.client_secret),
                Some(options.redirect_uri),
            ),
            authorization_endpoint: format!("{base}/api/v1/oauth/authorize"),
            token_endpoint: format!("{base}/api/v1/oauth/token"),
            revocation_endpoint: format!("{base}/api/v1/oauth/revoke"),
        }
    }
}

#[cfg(feature = "reqwest-client")]
impl Mastodon<'static, reqwest::Client> {
    /// Creates a new Mastodon OAuth 2.0 client configured for a specific instance using the default HTTP client.
    ///
    /// The endpoints are automatically constructed from the base URL.
    /// Uses the built-in `reqwest::Client` for HTTP requests. To provide a custom
    /// HTTP client, use [`Mastodon::from_options`] instead.
    ///
    /// # Arguments
    ///
    /// * `base_url` - The base URL of the Mastodon instance (e.g. `"https://mastodon.social"`).
    /// * `client_id` - The OAuth 2.0 client ID from app registration.
    /// * `client_secret` - The OAuth 2.0 client secret from app registration.
    /// * `redirect_uri` - The URI Mastodon will redirect to after authorization. Must match
    ///   the redirect URI configured during app registration.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::Mastodon;
    ///
    /// let mastodon = Mastodon::new(
    ///     "https://mastodon.social",
    ///     "your-client-id",
    ///     "your-client-secret",
    ///     "https://example.com/callback",
    /// );
    /// ```
    pub fn new(
        base_url: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        Self::from_options(MastodonOptions {
            base_url: base_url.into(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri: redirect_uri.into(),
            http_client: crate::http::default_client(),
        })
    }
}

impl<'a, H: HttpClient> Mastodon<'a, H> {
    /// Returns the provider name (`"Mastodon"`).
    pub fn name(&self) -> &'static str {
        "Mastodon"
    }

    /// Builds the Mastodon authorization URL that the user should be redirected to.
    ///
    /// The returned URL includes all required OAuth 2.0 and PKCE parameters. Your
    /// application should store `state` and `code_verifier` in the user's session
    /// before redirecting, as both are needed to complete the flow.
    ///
    /// # Arguments
    ///
    /// * `state` - A CSRF token to prevent cross-site request forgery. Use
    ///   [`generate_state`](crate::generate_state) to create one.
    /// * `scopes` - The OAuth 2.0 scopes to request (e.g. `&["read", "write"]`).
    /// * `code_verifier` - The PKCE code verifier. Use
    ///   [`generate_code_verifier`](crate::generate_code_verifier) to create one.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{Mastodon, generate_state, generate_code_verifier};
    ///
    /// let mastodon = Mastodon::new("https://mastodon.social", "client-id", "client-secret", "https://example.com/cb");
    /// let state = generate_state();
    /// let verifier = generate_code_verifier();
    ///
    /// let url = mastodon.authorization_url(&state, &["read"], &verifier);
    /// assert!(url.as_str().starts_with("https://mastodon.social/"));
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

    /// Exchanges an authorization code for access tokens.
    ///
    /// Call this in your redirect URI handler after Mastodon redirects back with a `code`
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
    /// Returns [`Error::OAuthRequest`] if Mastodon rejects the code, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::Mastodon;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let mastodon = Mastodon::new("https://mastodon.social", "client-id", "secret", "https://example.com/cb");
    ///
    /// let tokens = mastodon
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

    /// Revokes an access token.
    ///
    /// Use this when a user signs out or disconnects your application.
    ///
    /// # Arguments
    ///
    /// * `token` - The access token to revoke.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedResponse`] if Mastodon returns a non-200 status, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::Mastodon;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let mastodon = Mastodon::new("https://mastodon.social", "client-id", "secret", "https://example.com/cb");
    ///
    /// mastodon.revoke_token("token-to-revoke").await?;
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

    fn make_mastodon(http_client: &MockHttpClient) -> Mastodon<'_, MockHttpClient> {
        Mastodon::from_options(MastodonOptions {
            base_url: "https://mastodon.social".into(),
            client_id: "cid".into(),
            client_secret: "secret".into(),
            redirect_uri: "https://app/cb".into(),
            http_client,
        })
    }

    #[test]
    fn new_builds_endpoints_from_base_url() {
        let mock = MockHttpClient::new(vec![]);
        let mastodon = make_mastodon(&mock);
        assert_eq!(
            mastodon.authorization_endpoint,
            "https://mastodon.social/api/v1/oauth/authorize"
        );
        assert_eq!(
            mastodon.token_endpoint,
            "https://mastodon.social/api/v1/oauth/token"
        );
        assert_eq!(
            mastodon.revocation_endpoint,
            "https://mastodon.social/api/v1/oauth/revoke"
        );
    }

    #[test]
    fn name_returns_mastodon() {
        let mock = MockHttpClient::new(vec![]);
        let mastodon = Mastodon::from_options(MastodonOptions {
            base_url: "https://mastodon.social".into(),
            client_id: "cid".into(),
            client_secret: "secret".into(),
            redirect_uri: "https://app/cb".into(),
            http_client: &mock,
        });
        assert_eq!(mastodon.name(), "Mastodon");
    }

    #[test]
    fn authorization_url_includes_pkce() {
        let mock = MockHttpClient::new(vec![]);
        let mastodon = Mastodon::from_options(MastodonOptions {
            base_url: "https://mastodon.social".into(),
            client_id: "cid".into(),
            client_secret: "secret".into(),
            redirect_uri: "https://app/cb".into(),
            http_client: &mock,
        });
        let url = mastodon.authorization_url("state123", &["read"], "my-verifier");

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
                "access_token": "masto-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);
        let mastodon = make_mastodon(&mock);

        let tokens = mastodon
            .validate_authorization_code("code", "verifier")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "masto-tok");

        let requests = mock.take_requests();
        assert_eq!(
            requests[0].url,
            "https://mastodon.social/api/v1/oauth/token"
        );
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("code_verifier".into(), "verifier".into())));
    }

    #[tokio::test]
    async fn revoke_token_delegates_to_client() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: vec![],
        }]);
        let mastodon = make_mastodon(&mock);

        let result = mastodon.revoke_token("tok").await;
        assert!(result.is_ok());

        let requests = mock.take_requests();
        assert_eq!(
            requests[0].url,
            "https://mastodon.social/api/v1/oauth/revoke"
        );
    }
}
