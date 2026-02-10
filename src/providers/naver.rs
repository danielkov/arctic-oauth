use crate::error::Error;
use crate::http::HttpClient;
use crate::request::{create_oauth2_request, send_token_request};
use crate::tokens::OAuth2Tokens;

const AUTHORIZATION_ENDPOINT: &str = "https://nid.naver.com/oauth2.0/authorize";
const TOKEN_ENDPOINT: &str = "https://nid.naver.com/oauth2.0/token";

/// Configuration for creating a [`Naver`] client with a custom HTTP client.
///
/// Use this when you need to provide your own [`HttpClient`] implementation
/// (e.g. a pre-configured `reqwest::Client` with custom timeouts or proxies).
/// For the common case, use [`Naver::new`] which uses the built-in default client.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{Naver, NaverOptions, HttpClient};
///
/// let custom_client = reqwest::Client::builder()
///     .timeout(std::time::Duration::from_secs(10))
///     .build()
///     .unwrap();
///
/// let naver = Naver::from_options(NaverOptions {
///     client_id: "your-client-id".into(),
///     client_secret: "your-client-secret".into(),
///     redirect_uri: "https://example.com/callback".into(),
///     http_client: &custom_client,
/// });
/// ```
pub struct NaverOptions<'a, H: HttpClient> {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub http_client: &'a H,
}

/// OAuth 2.0 client for [Naver](https://developers.naver.com/docs/login/api/).
///
/// Naver does not use state, scopes, or PKCE parameters in the authorization flow.
/// This client supports the authorization code flow including token refresh but not
/// token revocation.
///
/// # Setup
///
/// 1. Register your application at the [Naver Developers](https://developers.naver.com/apps/#/register) page.
/// 2. Obtain your Client ID and Client Secret from the application settings.
/// 3. Configure the callback URL to match the `redirect_uri` you pass to [`Naver::new`].
///
/// # Scopes
///
/// Naver does not use explicit scopes in the OAuth flow. Instead, permissions are configured
/// in the application settings on the Naver Developers portal. Available APIs include:
///
/// | API | Description |
/// |-----|-------------|
/// | Member Profile | Access user profile information |
/// | Cafe | Access user's cafe information |
/// | Blog | Access user's blog content |
///
/// See the full list at <https://developers.naver.com/docs/login/api/>.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::Naver;
///
/// # async fn example() -> Result<(), arctic_oauth::Error> {
/// let naver = Naver::new(
///     "your-client-id",
///     "your-client-secret",
///     "https://example.com/callback",
/// );
///
/// // Step 1: Redirect the user (no state or scopes required).
/// let url = naver.authorization_url();
/// // Redirect to `url`.
///
/// // Step 2: In your callback handler, exchange the authorization code for tokens.
/// let tokens = naver
///     .validate_authorization_code("authorization-code")
///     .await?;
/// println!("Access token: {}", tokens.access_token()?);
///
/// // Step 3 (optional): Refresh an expired access token.
/// let refreshed = naver
///     .refresh_access_token(tokens.refresh_token()?)
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct Naver<'a, H: HttpClient> {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    authorization_endpoint: String,
    token_endpoint: String,
    http_client: &'a H,
}

impl<'a, H: HttpClient> Naver<'a, H> {
    /// Creates a Naver client from a [`NaverOptions`] struct.
    ///
    /// Use this when you need a custom HTTP client. For the common case,
    /// use [`Naver::new`] instead.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{Naver, NaverOptions};
    ///
    /// let custom_client = reqwest::Client::new();
    /// let naver = Naver::from_options(NaverOptions {
    ///     client_id: "your-client-id".into(),
    ///     client_secret: "your-client-secret".into(),
    ///     redirect_uri: "https://example.com/callback".into(),
    ///     http_client: &custom_client,
    /// });
    /// ```
    pub fn from_options(options: NaverOptions<'a, H>) -> Self {
        Self {
            client_id: options.client_id,
            client_secret: options.client_secret,
            redirect_uri: options.redirect_uri,
            authorization_endpoint: AUTHORIZATION_ENDPOINT.to_string(),
            token_endpoint: TOKEN_ENDPOINT.to_string(),
            http_client: options.http_client,
        }
    }
}

#[cfg(feature = "reqwest-client")]
impl Naver<'static, reqwest::Client> {
    /// Creates a new Naver OAuth 2.0 client using the default HTTP client.
    ///
    /// Uses the built-in `reqwest::Client` for HTTP requests. To provide a custom
    /// HTTP client, use [`Naver::from_options`] instead.
    ///
    /// # Arguments
    ///
    /// * `client_id` - The OAuth 2.0 client ID from Naver Developers.
    /// * `client_secret` - The OAuth 2.0 client secret from Naver Developers.
    /// * `redirect_uri` - The URI Naver will redirect to after authorization. Must match
    ///   the callback URL configured in your Naver application.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::Naver;
    ///
    /// let naver = Naver::new(
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
        Self::from_options(NaverOptions {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri: redirect_uri.into(),
            http_client: crate::http::default_client(),
        })
    }
}

impl<'a, H: HttpClient> Naver<'a, H> {
    /// Returns the provider name (`"Naver"`).
    pub fn name(&self) -> &'static str {
        "Naver"
    }

    /// Builds the Naver authorization URL that the user should be redirected to.
    ///
    /// Naver does not use state, scopes, or PKCE parameters. The authorization URL only
    /// includes the response type, client ID, and redirect URI.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::Naver;
    ///
    /// let naver = Naver::new("client-id", "secret", "https://example.com/cb");
    /// let url = naver.authorization_url();
    /// assert!(url.as_str().starts_with("https://nid.naver.com/"));
    /// ```
    pub fn authorization_url(&self) -> url::Url {
        let mut url = url::Url::parse(&self.authorization_endpoint)
            .expect("invalid authorization endpoint URL");

        {
            let mut params = url.query_pairs_mut();
            params.append_pair("response_type", "code");
            params.append_pair("client_id", &self.client_id);
            params.append_pair("redirect_uri", &self.redirect_uri);
        }

        url
    }

    /// Exchanges an authorization code for access and refresh tokens.
    ///
    /// Call this in your redirect URI handler after Naver redirects back with a `code`
    /// query parameter. Credentials are sent in the POST body (not via Basic auth).
    ///
    /// # Arguments
    ///
    /// * `code` - The authorization code from the `code` query parameter.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OAuthRequest`] if Naver rejects the code, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::Naver;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let naver = Naver::new("client-id", "secret", "https://example.com/cb");
    ///
    /// let tokens = naver
    ///     .validate_authorization_code("the-auth-code")
    ///     .await?;
    ///
    /// println!("Access token: {}", tokens.access_token()?);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn validate_authorization_code(&self, code: &str) -> Result<OAuth2Tokens, Error> {
        let body = vec![
            ("grant_type".to_string(), "authorization_code".to_string()),
            ("code".to_string(), code.to_string()),
            ("redirect_uri".to_string(), self.redirect_uri.clone()),
            ("client_id".to_string(), self.client_id.clone()),
            ("client_secret".to_string(), self.client_secret.clone()),
        ];

        let request = create_oauth2_request(&self.token_endpoint, &body);
        send_token_request(self.http_client, request).await
    }

    /// Refreshes an expired access token using a refresh token.
    ///
    /// Naver uses the same token endpoint for both authorization code exchange and
    /// token refresh. Credentials are sent in the POST body (not via Basic auth).
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
    /// # use arctic_oauth::Naver;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let naver = Naver::new("client-id", "secret", "https://example.com/cb");
    ///
    /// let new_tokens = naver
    ///     .refresh_access_token("stored-refresh-token")
    ///     .await?;
    ///
    /// println!("New access token: {}", new_tokens.access_token()?);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn refresh_access_token(&self, refresh_token: &str) -> Result<OAuth2Tokens, Error> {
        let body = vec![
            ("grant_type".to_string(), "refresh_token".to_string()),
            ("refresh_token".to_string(), refresh_token.to_string()),
            ("client_id".to_string(), self.client_id.clone()),
            ("client_secret".to_string(), self.client_secret.clone()),
        ];

        let request = create_oauth2_request(&self.token_endpoint, &body);
        send_token_request(self.http_client, request).await
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

    fn make_naver(http_client: &MockHttpClient) -> Naver<'_, MockHttpClient> {
        Naver::from_options(NaverOptions {
            client_id: "cid".into(),
            client_secret: "secret".into(),
            redirect_uri: "https://app/cb".into(),
            http_client,
        })
    }

    #[test]
    fn new_sets_production_endpoints() {
        let mock = MockHttpClient::new(vec![]);
        let provider = make_naver(&mock);
        assert_eq!(provider.authorization_endpoint, AUTHORIZATION_ENDPOINT);
        assert_eq!(provider.token_endpoint, TOKEN_ENDPOINT);
    }

    #[test]
    fn name_returns_naver() {
        let mock = MockHttpClient::new(vec![]);
        let provider = make_naver(&mock);
        assert_eq!(provider.name(), "Naver");
    }

    #[test]
    fn authorization_url_has_no_state_and_no_scopes() {
        let mock = MockHttpClient::new(vec![]);
        let provider = make_naver(&mock);
        let url = provider.authorization_url();

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.contains(&("client_id".into(), "cid".into())));
        assert!(pairs.contains(&("redirect_uri".into(), "https://app/cb".into())));
        // No state, no scope
        assert!(!pairs.iter().any(|(k, _)| k == "state"));
        assert!(!pairs.iter().any(|(k, _)| k == "scope"));
    }

    #[tokio::test]
    async fn validate_authorization_code_sends_body_credentials() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "naver-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);
        let provider = make_naver(&mock);

        let tokens = provider
            .validate_authorization_code("auth-code")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "naver-tok");

        let requests = mock.take_requests();
        assert_eq!(requests[0].url, "https://nid.naver.com/oauth2.0/token");
        assert!(get_header(&requests[0], "Authorization").is_none());

        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("grant_type".into(), "authorization_code".into())));
        assert!(body.contains(&("code".into(), "auth-code".into())));
        assert!(body.contains(&("client_id".into(), "cid".into())));
        assert!(body.contains(&("client_secret".into(), "secret".into())));
        assert!(body.contains(&("redirect_uri".into(), "https://app/cb".into())));
    }

    #[tokio::test]
    async fn refresh_access_token_sends_body_credentials() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "new-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);
        let provider = make_naver(&mock);

        let tokens = provider.refresh_access_token("refresh-tok").await.unwrap();

        assert_eq!(tokens.access_token().unwrap(), "new-tok");

        let requests = mock.take_requests();
        assert!(get_header(&requests[0], "Authorization").is_none());
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("grant_type".into(), "refresh_token".into())));
        assert!(body.contains(&("refresh_token".into(), "refresh-tok".into())));
        assert!(body.contains(&("client_id".into(), "cid".into())));
        assert!(body.contains(&("client_secret".into(), "secret".into())));
    }
}
