use crate::client::OAuth2Client;
use crate::error::Error;
use crate::http::HttpClient;
use crate::tokens::OAuth2Tokens;

const AUTHORIZATION_ENDPOINT: &str = "https://appcenter.intuit.com/connect/oauth2";
const TOKEN_ENDPOINT: &str = "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer";
const REVOCATION_ENDPOINT: &str = "https://developer.api.intuit.com/v2/oauth2/tokens/revoke";

/// Configuration for creating an [`Intuit`] client with a custom HTTP client.
///
/// Use this when you need to provide your own [`HttpClient`] implementation
/// (e.g. a pre-configured `reqwest::Client` with custom timeouts or proxies).
/// For the common case, use [`Intuit::new`] which uses the built-in default client.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{Intuit, IntuitOptions, HttpClient};
///
/// let custom_client = reqwest::Client::builder()
///     .timeout(std::time::Duration::from_secs(10))
///     .build()
///     .unwrap();
///
/// let intuit = Intuit::from_options(IntuitOptions {
///     client_id: "your-client-id".into(),
///     client_secret: "your-client-secret".into(),
///     redirect_uri: "https://example.com/callback".into(),
///     http_client: &custom_client,
/// });
/// ```
pub struct IntuitOptions<'a, H: HttpClient> {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub http_client: &'a H,
}

/// OAuth 2.0 client for [Intuit](https://developer.intuit.com/app/developer/qbo/docs/develop/authentication-and-authorization/oauth-2.0).
///
/// Intuit does not require PKCE. This client supports the full authorization code flow
/// including token refresh and revocation for accessing QuickBooks Online and other
/// Intuit services.
///
/// # Setup
///
/// 1. Create an app in the [Intuit Developer Portal](https://developer.intuit.com/app/developer/myapps).
/// 2. Navigate to your app's **Keys & credentials** section to obtain your Client ID and Client Secret.
/// 3. Add the redirect URI under **Keys & credentials > Redirect URIs** to match the `redirect_uri` you pass to [`Intuit::new`].
///
/// # Scopes
///
/// Intuit uses space-separated scopes with a reverse domain notation. Common scopes include:
///
/// | Scope | Description |
/// |-------|-------------|
/// | `com.intuit.quickbooks.accounting` | Access QuickBooks Online accounting data |
/// | `com.intuit.quickbooks.payment` | Access QuickBooks payments |
/// | `openid` | OpenID Connect authentication |
/// | `profile` | User profile information |
/// | `email` | User email address |
///
/// See the full list at <https://developer.intuit.com/app/developer/qbo/docs/develop/authentication-and-authorization/oauth-2.0#scopes>.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{Intuit, generate_state};
///
/// # async fn example() -> Result<(), arctic_oauth::Error> {
/// let intuit = Intuit::new(
///     "your-client-id",
///     "your-client-secret",
///     "https://example.com/callback",
/// );
///
/// // Step 1: Generate CSRF state and redirect the user.
/// let state = generate_state();
/// let url = intuit.authorization_url(&state, &["com.intuit.quickbooks.accounting", "openid"]);
/// // Store `state` in the user's session, then redirect to `url`.
///
/// // Step 2: Exchange the authorization code for tokens.
/// let tokens = intuit
///     .validate_authorization_code("authorization-code")
///     .await?;
/// println!("Access token: {}", tokens.access_token()?);
///
/// // Step 3 (optional): Refresh an expired access token.
/// let refreshed = intuit
///     .refresh_access_token(tokens.refresh_token()?)
///     .await?;
///
/// // Step 4 (optional): Revoke a token.
/// intuit.revoke_token(tokens.access_token()?).await?;
/// # Ok(())
/// # }
/// ```
pub struct Intuit<'a, H: HttpClient> {
    client: OAuth2Client,
    http_client: &'a H,
    authorization_endpoint: String,
    token_endpoint: String,
    revocation_endpoint: String,
}

impl<'a, H: HttpClient> Intuit<'a, H> {
    /// Creates an Intuit client from an [`IntuitOptions`] struct.
    ///
    /// Use this when you need a custom HTTP client. For the common case,
    /// use [`Intuit::new`] instead.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{Intuit, IntuitOptions};
    ///
    /// let custom_client = reqwest::Client::new();
    /// let intuit = Intuit::from_options(IntuitOptions {
    ///     client_id: "your-client-id".into(),
    ///     client_secret: "your-client-secret".into(),
    ///     redirect_uri: "https://example.com/callback".into(),
    ///     http_client: &custom_client,
    /// });
    /// ```
    pub fn from_options(options: IntuitOptions<'a, H>) -> Self {
        Self {
            http_client: options.http_client,
            client: OAuth2Client::new(
                options.client_id,
                Some(options.client_secret),
                Some(options.redirect_uri),
            ),
            authorization_endpoint: AUTHORIZATION_ENDPOINT.to_string(),
            token_endpoint: TOKEN_ENDPOINT.to_string(),
            revocation_endpoint: REVOCATION_ENDPOINT.to_string(),
        }
    }
}

#[cfg(feature = "reqwest-client")]
impl Intuit<'static, reqwest::Client> {
    /// Creates a new Intuit OAuth 2.0 client configured with production endpoints using the default HTTP client.
    ///
    /// Uses the built-in `reqwest::Client` for HTTP requests. To provide a custom
    /// HTTP client, use [`Intuit::from_options`] instead.
    ///
    /// # Arguments
    ///
    /// * `client_id` - The OAuth 2.0 client ID from Intuit Developer Portal.
    /// * `client_secret` - The OAuth 2.0 client secret from Intuit Developer Portal.
    /// * `redirect_uri` - The URI Intuit will redirect to after authorization.
    ///   Must match one configured in your app settings.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::Intuit;
    ///
    /// let intuit = Intuit::new(
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
        Self::from_options(IntuitOptions {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri: redirect_uri.into(),
            http_client: crate::http::default_client(),
        })
    }
}

impl<'a, H: HttpClient> Intuit<'a, H> {
    /// Returns the provider name (`"Intuit"`).
    pub fn name(&self) -> &'static str {
        "Intuit"
    }

    /// Builds the Intuit authorization URL that the user should be redirected to.
    ///
    /// The returned URL includes all required OAuth 2.0 parameters. Your application
    /// should store `state` in the user's session before redirecting, as it is needed
    /// to prevent CSRF attacks.
    ///
    /// # Arguments
    ///
    /// * `state` - A CSRF token. Use [`generate_state`](crate::generate_state) to create one.
    /// * `scopes` - The OAuth 2.0 scopes to request (e.g. `&["com.intuit.quickbooks.accounting"]`).
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{Intuit, generate_state};
    ///
    /// let intuit = Intuit::new("client-id", "client-secret", "https://example.com/cb");
    /// let state = generate_state();
    ///
    /// let url = intuit.authorization_url(&state, &["com.intuit.quickbooks.accounting"]);
    /// assert!(url.as_str().starts_with("https://appcenter.intuit.com/"));
    /// ```
    pub fn authorization_url(&self, state: &str, scopes: &[&str]) -> url::Url {
        self.client
            .create_authorization_url(&self.authorization_endpoint, state, scopes)
    }

    /// Exchanges an authorization code for access and refresh tokens.
    ///
    /// Call this in your redirect URI handler after Intuit redirects back with a `code`
    /// query parameter.
    ///
    /// # Arguments
    ///
    /// * `code` - The authorization code from the `code` query parameter.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OAuthRequest`] if Intuit rejects the code, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::Intuit;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let intuit = Intuit::new("client-id", "secret", "https://example.com/cb");
    ///
    /// let tokens = intuit
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
    /// Intuit access tokens typically expire after 1 hour. Refresh tokens are valid
    /// for 100 days. Use this method to obtain a new access token without requiring
    /// the user to re-authenticate.
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
    /// # use arctic_oauth::Intuit;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let intuit = Intuit::new("client-id", "secret", "https://example.com/cb");
    ///
    /// let new_tokens = intuit
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
    /// Use this when a user signs out or disconnects your application from their
    /// Intuit account. Revoking a refresh token also invalidates the associated
    /// access token.
    ///
    /// # Arguments
    ///
    /// * `token` - The access token or refresh token to revoke.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedResponse`] if Intuit returns a non-200 status, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::Intuit;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let intuit = Intuit::new("client-id", "secret", "https://example.com/cb");
    ///
    /// intuit.revoke_token("token-to-revoke").await?;
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

    fn make_intuit(http_client: &MockHttpClient) -> Intuit<'_, MockHttpClient> {
        Intuit::from_options(IntuitOptions {
            client_id: "cid".into(),
            client_secret: "secret".into(),
            redirect_uri: "https://app/cb".into(),
            http_client,
        })
    }

    #[test]
    fn new_sets_production_endpoints() {
        let mock = MockHttpClient::new(vec![]);
        let intuit = make_intuit(&mock);
        assert_eq!(intuit.authorization_endpoint, AUTHORIZATION_ENDPOINT);
        assert_eq!(intuit.token_endpoint, TOKEN_ENDPOINT);
        assert_eq!(intuit.revocation_endpoint, REVOCATION_ENDPOINT);
    }

    #[test]
    fn name_returns_intuit() {
        let mock = MockHttpClient::new(vec![]);
        let intuit = make_intuit(&mock);
        assert_eq!(intuit.name(), "Intuit");
    }

    #[test]
    fn authorization_url_builds_correct_params() {
        let mock = MockHttpClient::new(vec![]);
        let intuit = make_intuit(&mock);
        let url = intuit.authorization_url("state123", &["com.intuit.quickbooks.accounting"]);

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.contains(&("client_id".into(), "cid".into())));
        assert!(pairs.contains(&("state".into(), "state123".into())));
        assert!(pairs.contains(&("scope".into(), "com.intuit.quickbooks.accounting".into())));
        assert!(pairs.contains(&("redirect_uri".into(), "https://app/cb".into())));
    }

    #[tokio::test]
    async fn validate_authorization_code_delegates_to_client() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "intuit-tok",
                "token_type": "Bearer",
                "expires_in": 3600
            }))
            .unwrap(),
        }]);
        let intuit = make_intuit(&mock);

        let tokens = intuit
            .validate_authorization_code("auth-code")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "intuit-tok");

        let requests = mock.take_requests();
        assert_eq!(
            requests[0].url,
            "https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer"
        );
        assert!(get_header(&requests[0], "Authorization").is_some());
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
        let intuit = make_intuit(&mock);

        let tokens = intuit.refresh_access_token("refresh-tok").await.unwrap();

        assert_eq!(tokens.access_token().unwrap(), "new-tok");
    }

    #[tokio::test]
    async fn revoke_token_delegates_to_client() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: vec![],
        }]);
        let intuit = make_intuit(&mock);

        let result = intuit.revoke_token("tok-to-revoke").await;
        assert!(result.is_ok());

        let requests = mock.take_requests();
        assert_eq!(
            requests[0].url,
            "https://developer.api.intuit.com/v2/oauth2/tokens/revoke"
        );
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("token".into(), "tok-to-revoke".into())));
    }
}
