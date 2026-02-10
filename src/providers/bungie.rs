use crate::client::OAuth2Client;
use crate::error::Error;
use crate::http::HttpClient;
use crate::tokens::OAuth2Tokens;

const AUTHORIZATION_ENDPOINT: &str = "https://www.bungie.net/en/oauth/authorize";
const TOKEN_ENDPOINT: &str = "https://www.bungie.net/platform/app/oauth/token";

/// Configuration for creating a [`Bungie`] client with a custom HTTP client.
///
/// Use this when you need to provide your own [`HttpClient`] implementation.
/// For the common case, use [`Bungie::new`] which uses the built-in default client.
pub struct BungieOptions<'a, H: HttpClient> {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_uri: String,
    pub http_client: &'a H,
}

/// OAuth 2.0 client for [Bungie](https://github.com/Bungie-net/api/wiki/OAuth-Documentation).
///
/// Bungie does not require PKCE for authorization requests. This client supports the
/// authorization code flow including token refresh but does not support token revocation.
/// The client secret is optional for public clients.
///
/// # Setup
///
/// 1. Create an application on the [Bungie Application Portal](https://www.bungie.net/en/Application).
/// 2. Obtain your **OAuth Client ID** and **OAuth Client Secret** (if using a confidential client).
/// 3. Set your redirect URL to match the `redirect_uri` you pass to [`Bungie::new`].
///
/// # Scopes
///
/// Bungie does not use traditional OAuth scopes. Access permissions are configured through
/// your application settings in the Bungie Application Portal.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{Bungie, generate_state};
///
/// # async fn example() -> Result<(), arctic_oauth::Error> {
/// let bungie = Bungie::new(
///     "your-client-id",
///     Some("your-client-secret".into()),
///     "https://example.com/callback",
/// );
///
/// // Step 1: Generate CSRF state, then redirect the user.
/// let state = generate_state();
/// let url = bungie.authorization_url(&state, &[]);
/// // Store `state` in the user's session, then redirect to `url`.
///
/// // Step 2: In your callback handler, exchange the authorization code for tokens.
/// let tokens = bungie
///     .validate_authorization_code("authorization-code")
///     .await?;
/// println!("Access token: {}", tokens.access_token()?);
///
/// // Step 3 (optional): Refresh an expired access token.
/// let refreshed = bungie
///     .refresh_access_token(tokens.refresh_token()?)
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct Bungie<'a, H: HttpClient> {
    client: OAuth2Client,
    http_client: &'a H,
    authorization_endpoint: String,
    token_endpoint: String,
}

impl<'a, H: HttpClient> Bungie<'a, H> {
    /// Creates a Bungie client from a [`BungieOptions`] struct.
    ///
    /// Use this when you need a custom HTTP client. For the common case,
    /// use [`Bungie::new`] instead.
    pub fn from_options(options: BungieOptions<'a, H>) -> Self {
        Self {
            http_client: options.http_client,
            client: OAuth2Client::new(
                options.client_id,
                options.client_secret,
                Some(options.redirect_uri),
            ),
            authorization_endpoint: AUTHORIZATION_ENDPOINT.to_string(),
            token_endpoint: TOKEN_ENDPOINT.to_string(),
        }
    }
}

#[cfg(feature = "reqwest-client")]
impl Bungie<'static, reqwest::Client> {
    /// Creates a new Bungie OAuth 2.0 client using the default HTTP client.
    ///
    /// # Arguments
    ///
    /// * `client_id` - The OAuth Client ID from the Bungie Application Portal.
    /// * `client_secret` - The OAuth Client Secret (optional for public clients).
    /// * `redirect_uri` - The URI Bungie will redirect to after authorization. Must match
    ///   the redirect URL configured in your application settings.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::Bungie;
    ///
    /// // With client secret (confidential client)
    /// let bungie = Bungie::new(
    ///     "your-client-id",
    ///     Some("your-client-secret".into()),
    ///     "https://example.com/callback",
    /// );
    ///
    /// // Without client secret (public client)
    /// let bungie_public = Bungie::new(
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
        Self::from_options(BungieOptions {
            client_id: client_id.into(),
            client_secret,
            redirect_uri: redirect_uri.into(),
            http_client: crate::http::default_client(),
        })
    }
}

impl<'a, H: HttpClient> Bungie<'a, H> {
    /// Returns the provider name (`"Bungie"`).
    pub fn name(&self) -> &'static str {
        "Bungie"
    }

    /// Builds the Bungie authorization URL that the user should be redirected to.
    ///
    /// The returned URL includes all required OAuth 2.0 parameters. Your application
    /// should store `state` in the user's session before redirecting to verify the
    /// callback request.
    ///
    /// # Arguments
    ///
    /// * `state` - A CSRF token to prevent cross-site request forgery. Use
    ///   [`generate_state`](crate::generate_state) to create one.
    /// * `scopes` - OAuth 2.0 scopes (typically empty for Bungie as permissions are
    ///   configured in the application portal).
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{Bungie, generate_state};
    ///
    /// let bungie = Bungie::new("client-id", None, "https://example.com/cb");
    /// let state = generate_state();
    ///
    /// let url = bungie.authorization_url(&state, &[]);
    /// assert!(url.as_str().starts_with("https://www.bungie.net/"));
    /// ```
    pub fn authorization_url(&self, state: &str, scopes: &[&str]) -> url::Url {
        self.client
            .create_authorization_url(&self.authorization_endpoint, state, scopes)
    }

    /// Exchanges an authorization code for access and refresh tokens.
    ///
    /// Call this in your redirect URI handler after Bungie redirects back with a `code`
    /// query parameter.
    ///
    /// # Arguments
    ///
    /// * `code` - The authorization code from the `code` query parameter.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OAuthRequest`] if Bungie rejects the code, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::Bungie;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let bungie = Bungie::new("client-id", Some("secret".into()), "https://example.com/cb");
    ///
    /// let tokens = bungie
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
    /// Bungie access tokens expire after a certain period. If your initial token response
    /// included a refresh token, you can use it to obtain a new access token without user
    /// interaction.
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
    /// # use arctic_oauth::Bungie;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let bungie = Bungie::new("client-id", Some("secret".into()), "https://example.com/cb");
    ///
    /// let new_tokens = bungie
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

    fn make_bungie(http_client: &MockHttpClient) -> Bungie<'_, MockHttpClient> {
        Bungie::from_options(BungieOptions {
            client_id: "cid".into(),
            client_secret: Some("secret".into()),
            redirect_uri: "https://app/cb".into(),
            http_client,
        })
    }

    #[test]
    fn new_sets_production_endpoints() {
        let mock = MockHttpClient::new(vec![]);
        let bungie = make_bungie(&mock);
        assert_eq!(bungie.authorization_endpoint, AUTHORIZATION_ENDPOINT);
        assert_eq!(bungie.token_endpoint, TOKEN_ENDPOINT);
    }

    #[test]
    fn name_returns_bungie() {
        let mock = MockHttpClient::new(vec![]);
        let bungie = make_bungie(&mock);
        assert_eq!(bungie.name(), "Bungie");
    }

    #[test]
    fn authorization_url_no_pkce() {
        let mock = MockHttpClient::new(vec![]);
        let bungie = make_bungie(&mock);
        let url = bungie.authorization_url("state123", &[]);

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.contains(&("client_id".into(), "cid".into())));
        assert!(!pairs.iter().any(|(k, _)| k == "code_challenge"));
    }

    #[tokio::test]
    async fn validate_authorization_code_delegates_to_client() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "bungie-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);
        let bungie = make_bungie(&mock);

        let tokens = bungie.validate_authorization_code("code").await.unwrap();

        assert_eq!(tokens.access_token().unwrap(), "bungie-tok");

        let requests = mock.take_requests();
        assert_eq!(requests[0].url, TOKEN_ENDPOINT);
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("grant_type".into(), "authorization_code".into())));
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
        let bungie = make_bungie(&mock);

        let tokens = bungie.refresh_access_token("rt").await.unwrap();
        assert_eq!(tokens.access_token().unwrap(), "new-tok");
    }
}
