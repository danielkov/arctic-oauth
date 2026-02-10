use crate::client::OAuth2Client;
use crate::error::Error;
use crate::http::HttpClient;
use crate::tokens::OAuth2Tokens;

const AUTHORIZATION_ENDPOINT: &str = "https://www.figma.com/oauth";
const TOKEN_ENDPOINT: &str = "https://api.figma.com/v1/oauth/token";
const REFRESH_ENDPOINT: &str = "https://api.figma.com/v1/oauth/refresh";

/// Configuration for creating a [`Figma`] client with a custom HTTP client.
///
/// Use this when you need to provide your own [`HttpClient`] implementation
/// (e.g. a pre-configured `reqwest::Client` with custom timeouts or proxies).
/// For the common case, use [`Figma::new`] which uses the built-in default client.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{Figma, FigmaOptions, HttpClient};
///
/// let custom_client = reqwest::Client::builder()
///     .timeout(std::time::Duration::from_secs(10))
///     .build()
///     .unwrap();
///
/// let figma = Figma::from_options(FigmaOptions {
///     client_id: "your-client-id".into(),
///     client_secret: "your-client-secret".into(),
///     redirect_uri: "https://example.com/callback".into(),
///     http_client: &custom_client,
/// });
/// ```
pub struct FigmaOptions<'a, H: HttpClient> {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub http_client: &'a H,
}

/// OAuth 2.0 client for [Figma](https://www.figma.com/developers/api#oauth2).
///
/// Figma does not require PKCE. This client supports the full authorization code flow
/// including token refresh. Note that Figma uses a separate endpoint for token refresh.
///
/// # Setup
///
/// 1. Go to your [Figma account settings](https://www.figma.com/developers/apps).
/// 2. Click **Create a new app** and configure your OAuth application.
/// 3. Set the callback URL to match the `redirect_uri` you pass to [`Figma::new`].
/// 4. Note your Client ID and Client Secret.
///
/// # Scopes
///
/// Figma uses space-separated scopes. Common scopes include:
///
/// | Scope | Description |
/// |-------|-------------|
/// | `file_read` | Read files and comments |
/// | `file_write` | Edit files |
/// | `file_variables:read` | Read variables |
/// | `file_variables:write` | Write variables |
///
/// See the full list at <https://www.figma.com/developers/api#oauth2-scopes>.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{Figma, generate_state};
///
/// # async fn example() -> Result<(), arctic_oauth::Error> {
/// let figma = Figma::new(
///     "your-client-id",
///     "your-client-secret",
///     "https://example.com/callback",
/// );
///
/// // Step 1: Generate CSRF state, then redirect the user.
/// let state = generate_state();
/// let url = figma.authorization_url(&state, &["file_read"]);
/// // Store `state` in the user's session, then redirect to `url`.
///
/// // Step 2: In your callback handler, exchange the authorization code for tokens.
/// let tokens = figma
///     .validate_authorization_code("authorization-code")
///     .await?;
/// println!("Access token: {}", tokens.access_token()?);
///
/// // Step 3 (optional): Refresh an expired access token.
/// let refreshed = figma
///     .refresh_access_token(tokens.refresh_token()?)
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct Figma<'a, H: HttpClient> {
    client: OAuth2Client,
    http_client: &'a H,
    authorization_endpoint: String,
    token_endpoint: String,
    refresh_endpoint: String,
}

impl<'a, H: HttpClient> Figma<'a, H> {
    /// Creates a Figma client from a [`FigmaOptions`] struct.
    ///
    /// Use this when you need a custom HTTP client. For the common case,
    /// use [`Figma::new`] instead.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{Figma, FigmaOptions};
    ///
    /// let custom_client = reqwest::Client::new();
    /// let figma = Figma::from_options(FigmaOptions {
    ///     client_id: "your-client-id".into(),
    ///     client_secret: "your-client-secret".into(),
    ///     redirect_uri: "https://example.com/callback".into(),
    ///     http_client: &custom_client,
    /// });
    /// ```
    pub fn from_options(options: FigmaOptions<'a, H>) -> Self {
        Self {
            http_client: options.http_client,
            client: OAuth2Client::new(
                options.client_id,
                Some(options.client_secret),
                Some(options.redirect_uri),
            ),
            authorization_endpoint: AUTHORIZATION_ENDPOINT.to_string(),
            token_endpoint: TOKEN_ENDPOINT.to_string(),
            refresh_endpoint: REFRESH_ENDPOINT.to_string(),
        }
    }
}

#[cfg(feature = "reqwest-client")]
impl Figma<'static, reqwest::Client> {
    /// Creates a new Figma OAuth 2.0 client using the default HTTP client.
    ///
    /// The endpoints are automatically set to production values.
    /// Uses the built-in `reqwest::Client` for HTTP requests. To provide a custom
    /// HTTP client, use [`Figma::from_options`] instead.
    ///
    /// # Arguments
    ///
    /// * `client_id` - The OAuth 2.0 client ID from your Figma app settings.
    /// * `client_secret` - The OAuth 2.0 client secret from your Figma app settings.
    /// * `redirect_uri` - The URI Figma will redirect to after authorization. Must match
    ///   the callback URL configured in your Figma app.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::Figma;
    ///
    /// let figma = Figma::new(
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
        Self::from_options(FigmaOptions {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri: redirect_uri.into(),
            http_client: crate::http::default_client(),
        })
    }
}

impl<'a, H: HttpClient> Figma<'a, H> {
    /// Returns the provider name (`"Figma"`).
    pub fn name(&self) -> &'static str {
        "Figma"
    }

    /// Builds the Figma authorization URL that the user should be redirected to.
    ///
    /// The returned URL includes all required OAuth 2.0 parameters. Your application should
    /// store `state` in the user's session before redirecting.
    ///
    /// # Arguments
    ///
    /// * `state` - A CSRF token to prevent cross-site request forgery. Use
    ///   [`generate_state`](crate::generate_state) to create one.
    /// * `scopes` - The OAuth 2.0 scopes to request (e.g. `&["file_read"]`).
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{Figma, generate_state};
    ///
    /// let figma = Figma::new("client-id", "client-secret", "https://example.com/cb");
    /// let state = generate_state();
    ///
    /// let url = figma.authorization_url(&state, &["file_read"]);
    /// assert!(url.as_str().starts_with("https://www.figma.com/"));
    /// ```
    pub fn authorization_url(&self, state: &str, scopes: &[&str]) -> url::Url {
        self.client
            .create_authorization_url(&self.authorization_endpoint, state, scopes)
    }

    /// Exchanges an authorization code for access and refresh tokens.
    ///
    /// Call this in your redirect URI handler after Figma redirects back with a `code`
    /// query parameter.
    ///
    /// # Arguments
    ///
    /// * `code` - The authorization code from the `code` query parameter.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OAuthRequest`] if Figma rejects the code, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::Figma;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let figma = Figma::new("client-id", "secret", "https://example.com/cb");
    ///
    /// let tokens = figma
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
    /// Figma access tokens typically expire after 90 days. Use this method to obtain a new
    /// access token without user interaction. Note that Figma uses a separate endpoint
    /// for token refresh.
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
    /// # use arctic_oauth::Figma;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let figma = Figma::new("client-id", "secret", "https://example.com/cb");
    ///
    /// let new_tokens = figma
    ///     .refresh_access_token("stored-refresh-token")
    ///     .await?;
    ///
    /// println!("New access token: {}", new_tokens.access_token()?);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn refresh_access_token(&self, refresh_token: &str) -> Result<OAuth2Tokens, Error> {
        self.client
            .refresh_access_token(self.http_client, &self.refresh_endpoint, refresh_token, &[])
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

    fn make_figma(http_client: &MockHttpClient) -> Figma<'_, MockHttpClient> {
        Figma::from_options(FigmaOptions {
            client_id: "cid".into(),
            client_secret: "secret".into(),
            redirect_uri: "https://app/cb".into(),
            http_client,
        })
    }

    #[test]
    fn new_sets_production_endpoints() {
        let mock = MockHttpClient::new(vec![]);
        let figma = make_figma(&mock);
        assert_eq!(figma.authorization_endpoint, AUTHORIZATION_ENDPOINT);
        assert_eq!(figma.token_endpoint, TOKEN_ENDPOINT);
        assert_eq!(figma.refresh_endpoint, REFRESH_ENDPOINT);
    }

    #[test]
    fn name_returns_figma() {
        let mock = MockHttpClient::new(vec![]);
        let figma = make_figma(&mock);
        assert_eq!(figma.name(), "Figma");
    }

    #[test]
    fn authorization_url_builds_correct_params() {
        let mock = MockHttpClient::new(vec![]);
        let figma = make_figma(&mock);
        let url = figma.authorization_url("state123", &["file_read", "file_write"]);

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.contains(&("client_id".into(), "cid".into())));
        assert!(pairs.contains(&("state".into(), "state123".into())));
        assert!(pairs.contains(&("scope".into(), "file_read file_write".into())));
        assert!(pairs.contains(&("redirect_uri".into(), "https://app/cb".into())));
        assert!(!pairs.iter().any(|(k, _)| k == "code_challenge"));
    }

    #[test]
    fn authorization_url_without_scopes() {
        let mock = MockHttpClient::new(vec![]);
        let figma = make_figma(&mock);
        let url = figma.authorization_url("state123", &[]);

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(!pairs.iter().any(|(k, _)| k == "scope"));
    }

    #[tokio::test]
    async fn validate_authorization_code_sends_to_token_endpoint() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "figma-tok",
                "token_type": "Bearer",
                "expires_in": 7776000
            }))
            .unwrap(),
        }]);
        let figma = make_figma(&mock);

        let tokens = figma
            .validate_authorization_code("auth-code")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "figma-tok");

        let requests = mock.take_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url, TOKEN_ENDPOINT);

        assert!(get_header(&requests[0], "Authorization").is_some());

        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("grant_type".into(), "authorization_code".into())));
        assert!(body.contains(&("code".into(), "auth-code".into())));
    }

    #[tokio::test]
    async fn refresh_access_token_sends_to_refresh_endpoint() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "new-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);
        let figma = make_figma(&mock);

        let tokens = figma.refresh_access_token("refresh-tok").await.unwrap();

        assert_eq!(tokens.access_token().unwrap(), "new-tok");

        let requests = mock.take_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url, REFRESH_ENDPOINT);

        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("grant_type".into(), "refresh_token".into())));
        assert!(body.contains(&("refresh_token".into(), "refresh-tok".into())));
    }
}
