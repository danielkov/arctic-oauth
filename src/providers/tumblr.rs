use crate::client::OAuth2Client;
use crate::error::Error;
use crate::http::HttpClient;
use crate::tokens::OAuth2Tokens;

const AUTHORIZATION_ENDPOINT: &str = "https://www.tumblr.com/oauth2/authorize";
const TOKEN_ENDPOINT: &str = "https://api.tumblr.com/v2/oauth2/token";

/// Configuration for creating a [`Tumblr`] client with a custom HTTP client.
///
/// Use this when you need to provide your own [`HttpClient`] implementation
/// (e.g. a pre-configured `reqwest::Client` with custom timeouts or proxies).
/// For the common case, use [`Tumblr::new`] which uses the built-in default client.
pub struct TumblrOptions<'a, H: HttpClient> {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub http_client: &'a H,
}

/// OAuth 2.0 client for [Tumblr](https://www.tumblr.com/docs/en/api/v2#oauth2-authorization).
///
/// Tumblr uses standard OAuth 2.0 authorization code flow without PKCE.
/// The client supports authorization, token exchange, and token refresh.
///
/// # Setup
///
/// 1. Register an application in the [Tumblr Application Management](https://www.tumblr.com/oauth/apps).
/// 2. Obtain your OAuth consumer key (client ID) and secret key (client secret).
/// 3. Configure the Default callback URL to match your application's redirect URI.
///
/// # Scopes
///
/// Tumblr uses space-separated scopes. Common scopes include:
///
/// | Scope | Description |
/// |-------|-------------|
/// | `basic` | Read basic user information and public posts |
/// | `write` | Create, edit, and delete posts |
/// | `offline_access` | Request refresh tokens for long-term access |
///
/// See the full list at <https://www.tumblr.com/docs/en/api/v2#oauth2-authorization>.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{Tumblr, generate_state};
///
/// # async fn example() -> Result<(), arctic_oauth::Error> {
/// let provider = Tumblr::new(
///     "your-client-id",
///     "your-client-secret",
///     "https://example.com/callback",
/// );
///
/// // Step 1: Generate CSRF state and redirect the user.
/// let state = generate_state();
/// let url = provider.authorization_url(&state, &["basic", "write"]);
///
/// // Step 2: Exchange the authorization code for tokens.
/// let tokens = provider
///     .validate_authorization_code("authorization-code")
///     .await?;
/// println!("Access token: {}", tokens.access_token()?);
///
/// // Step 3 (optional): Refresh an expired access token.
/// let refreshed = provider
///     .refresh_access_token(tokens.refresh_token()?)
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct Tumblr<'a, H: HttpClient> {
    client: OAuth2Client,
    http_client: &'a H,
    authorization_endpoint: String,
    token_endpoint: String,
}

impl<'a, H: HttpClient> Tumblr<'a, H> {
    /// Creates a Tumblr client from a [`TumblrOptions`] struct.
    ///
    /// Use this when you need a custom HTTP client. For the common case,
    /// use [`Tumblr::new`] instead.
    pub fn from_options(options: TumblrOptions<'a, H>) -> Self {
        Self {
            client: OAuth2Client::new(
                options.client_id,
                Some(options.client_secret),
                Some(options.redirect_uri),
            ),
            http_client: options.http_client,
            authorization_endpoint: AUTHORIZATION_ENDPOINT.to_string(),
            token_endpoint: TOKEN_ENDPOINT.to_string(),
        }
    }
}

#[cfg(feature = "reqwest-client")]
impl Tumblr<'static, reqwest::Client> {
    /// Creates a new Tumblr OAuth 2.0 client configured with production endpoints.
    ///
    /// Uses the built-in `reqwest::Client` for HTTP requests. To provide a custom
    /// HTTP client, use [`Tumblr::from_options`] instead.
    ///
    /// # Arguments
    ///
    /// * `client_id` - The OAuth 2.0 client ID (consumer key) from Tumblr's application management.
    /// * `client_secret` - The OAuth 2.0 client secret (secret key) from Tumblr's application management.
    /// * `redirect_uri` - The URI Tumblr will redirect to after authorization.
    ///   Must match the callback URL configured in your app settings.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::Tumblr;
    ///
    /// let provider = Tumblr::new(
    ///     "your-client-id",
    ///     "your-client-secret",
    ///     "https://example.com/callback",
    /// );
    /// ```
    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        Self::from_options(TumblrOptions {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri: redirect_uri.into(),
            http_client: crate::http::default_client(),
        })
    }
}

impl<'a, H: HttpClient> Tumblr<'a, H> {
    /// Returns the provider name (`"Tumblr"`).
    pub fn name(&self) -> &'static str {
        "Tumblr"
    }

    /// Builds the Tumblr authorization URL that the user should be redirected to.
    ///
    /// The returned URL includes all required OAuth 2.0 parameters. Your application
    /// should store `state` in the user's session before redirecting, as it is needed
    /// to complete the flow.
    ///
    /// # Arguments
    ///
    /// * `state` - A CSRF token. Use [`generate_state`](crate::generate_state) to create one.
    /// * `scopes` - The OAuth 2.0 scopes to request (e.g. `&["basic", "write"]`).
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{Tumblr, generate_state};
    ///
    /// let provider = Tumblr::new("client-id", "client-secret", "https://example.com/cb");
    /// let state = generate_state();
    ///
    /// let url = provider.authorization_url(&state, &["basic", "write"]);
    /// ```
    pub fn authorization_url(&self, state: &str, scopes: &[&str]) -> url::Url {
        self.client
            .create_authorization_url(&self.authorization_endpoint, state, scopes)
    }

    /// Exchanges an authorization code for access and refresh tokens.
    ///
    /// Call this in your redirect URI handler after Tumblr redirects back with a `code`
    /// query parameter.
    ///
    /// # Arguments
    ///
    /// * `code` - The authorization code from the `code` query parameter.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OAuthRequest`] if Tumblr rejects the code, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::Tumblr;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let provider = Tumblr::new("client-id", "client-secret", "https://example.com/cb");
    ///
    /// let tokens = provider
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
    /// Tumblr access tokens typically expire after 1 hour when using the `offline_access`
    /// scope. Use this method to obtain a new access token without requiring the user to
    /// re-authenticate.
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
    /// # use arctic_oauth::Tumblr;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let provider = Tumblr::new("client-id", "client-secret", "https://example.com/cb");
    ///
    /// let new_tokens = provider
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

    fn make_tumblr(http_client: &MockHttpClient) -> Tumblr<'_, MockHttpClient> {
        Tumblr::from_options(TumblrOptions {
            client_id: "cid".into(),
            client_secret: "secret".into(),
            redirect_uri: "https://app/cb".into(),
            http_client,
        })
    }

    #[test]
    fn new_sets_production_endpoints() {
        let mock = MockHttpClient::new(vec![]);
        let tumblr = make_tumblr(&mock);
        assert_eq!(tumblr.authorization_endpoint, AUTHORIZATION_ENDPOINT);
        assert_eq!(tumblr.token_endpoint, TOKEN_ENDPOINT);
    }

    #[test]
    fn name_returns_correct_name() {
        let mock = MockHttpClient::new(vec![]);
        let tumblr = make_tumblr(&mock);
        assert_eq!(tumblr.name(), "Tumblr");
    }

    #[test]
    fn authorization_url_builds_correct_params() {
        let mock = MockHttpClient::new(vec![]);
        let tumblr = make_tumblr(&mock);
        let url = tumblr.authorization_url("state123", &["basic"]);

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.contains(&("client_id".into(), "cid".into())));
        assert!(pairs.contains(&("state".into(), "state123".into())));
        assert!(pairs.contains(&("scope".into(), "basic".into())));
        assert!(pairs.contains(&("redirect_uri".into(), "https://app/cb".into())));
        assert!(!pairs.iter().any(|(k, _)| k == "code_challenge"));
    }

    #[tokio::test]
    async fn validate_authorization_code_delegates_to_client() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "tumblr-tok",
                "token_type": "Bearer",
                "expires_in": 3600
            }))
            .unwrap(),
        }]);
        let tumblr = make_tumblr(&mock);

        let tokens = tumblr
            .validate_authorization_code("auth-code")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "tumblr-tok");

        let requests = mock.take_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url, TOKEN_ENDPOINT);

        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("grant_type".into(), "authorization_code".into())));
        assert!(body.contains(&("code".into(), "auth-code".into())));
        assert!(!body.iter().any(|(k, _)| k == "code_verifier"));
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
        let tumblr = make_tumblr(&mock);

        let tokens = tumblr.refresh_access_token("refresh-tok").await.unwrap();

        assert_eq!(tokens.access_token().unwrap(), "new-tok");

        let requests = mock.take_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url, TOKEN_ENDPOINT);

        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("grant_type".into(), "refresh_token".into())));
        assert!(body.contains(&("refresh_token".into(), "refresh-tok".into())));
    }
}
