use crate::client::OAuth2Client;
use crate::error::Error;
use crate::http::HttpClient;
use crate::tokens::OAuth2Tokens;

const AUTHORIZATION_ENDPOINT: &str = "https://bitbucket.org/site/oauth2/authorize";
const TOKEN_ENDPOINT: &str = "https://bitbucket.org/site/oauth2/access_token";

/// Configuration for creating a [`Bitbucket`] client with a custom HTTP client.
///
/// Use this when you need to provide your own [`HttpClient`] implementation.
/// For the common case, use [`Bitbucket::new`] which uses the built-in default client.
pub struct BitbucketOptions<'a, H: HttpClient> {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub http_client: &'a H,
}

/// OAuth 2.0 client for [Bitbucket](https://developer.atlassian.com/cloud/bitbucket/oauth-2/).
///
/// Bitbucket does not require PKCE and does not use OAuth scopes in the authorization
/// URL. This client supports the authorization code flow including token refresh. Note
/// that Bitbucket does not provide a token revocation endpoint.
///
/// # Setup
///
/// 1. Navigate to a workspace's settings on [Bitbucket](https://bitbucket.org/).
/// 2. Go to **OAuth consumers** under **Access Management** and click **Add consumer**.
/// 3. Copy your Client ID (Key) and Client Secret (Secret).
/// 4. Add the callback URL to match the `redirect_uri` you pass to [`Bitbucket::new`].
/// 5. Select the necessary permissions for your application.
///
/// # Scopes
///
/// Bitbucket uses granular permission scopes, but they are configured during app creation
/// in the Bitbucket settings rather than passed in the authorization URL. Common permissions
/// include:
///
/// | Permission | Description |
/// |------------|-------------|
/// | Account: Read | Read user account information |
/// | Repositories: Read | Access repository metadata and content |
/// | Pull requests: Read | View pull requests |
///
/// See the full list at <https://developer.atlassian.com/cloud/bitbucket/oauth-2/#scopes>.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{Bitbucket, generate_state};
///
/// # async fn example() -> Result<(), arctic_oauth::Error> {
/// let bitbucket = Bitbucket::new(
///     "your-client-id",
///     "your-client-secret",
///     "https://example.com/callback",
/// );
///
/// // Step 1: Generate CSRF state and redirect the user.
/// let state = generate_state();
/// let url = bitbucket.authorization_url(&state);
/// // Store `state` in the user's session, then redirect to `url`.
///
/// // Step 2: Exchange the authorization code for tokens.
/// let tokens = bitbucket
///     .validate_authorization_code("authorization-code")
///     .await?;
/// println!("Access token: {}", tokens.access_token()?);
///
/// // Step 3 (optional): Refresh an expired access token.
/// let refreshed = bitbucket
///     .refresh_access_token(tokens.refresh_token()?)
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct Bitbucket<'a, H: HttpClient> {
    client: OAuth2Client,
    http_client: &'a H,
    authorization_endpoint: String,
    token_endpoint: String,
}

impl<'a, H: HttpClient> Bitbucket<'a, H> {
    /// Creates a Bitbucket client from a [`BitbucketOptions`] struct.
    ///
    /// Use this when you need a custom HTTP client. For the common case,
    /// use [`Bitbucket::new`] instead.
    pub fn from_options(options: BitbucketOptions<'a, H>) -> Self {
        Self {
            http_client: options.http_client,
            client: OAuth2Client::new(
                options.client_id,
                Some(options.client_secret),
                Some(options.redirect_uri),
            ),
            authorization_endpoint: AUTHORIZATION_ENDPOINT.to_string(),
            token_endpoint: TOKEN_ENDPOINT.to_string(),
        }
    }
}

#[cfg(feature = "reqwest-client")]
impl Bitbucket<'static, reqwest::Client> {
    /// Creates a new Bitbucket OAuth 2.0 client using the default HTTP client.
    ///
    /// # Arguments
    ///
    /// * `client_id` - The OAuth 2.0 client ID (Key) from Bitbucket's OAuth consumer settings.
    /// * `client_secret` - The OAuth 2.0 client secret (Secret) from Bitbucket's OAuth consumer settings.
    /// * `redirect_uri` - The URI Bitbucket will redirect to after authorization.
    ///   Must match the callback URL configured in your OAuth consumer.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::Bitbucket;
    ///
    /// let bitbucket = Bitbucket::new(
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
        Self::from_options(BitbucketOptions {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri: redirect_uri.into(),
            http_client: crate::http::default_client(),
        })
    }
}

impl<'a, H: HttpClient> Bitbucket<'a, H> {
    /// Returns the provider name (`"Bitbucket"`).
    pub fn name(&self) -> &'static str {
        "Bitbucket"
    }

    /// Builds the Bitbucket authorization URL that the user should be redirected to.
    ///
    /// The returned URL includes all required OAuth 2.0 parameters. Your application
    /// should store `state` in the user's session before redirecting, as it is needed
    /// to prevent CSRF attacks.
    ///
    /// Note: Bitbucket permissions are configured during OAuth consumer creation and
    /// are not passed as scopes in the authorization URL.
    ///
    /// # Arguments
    ///
    /// * `state` - A CSRF token. Use [`generate_state`](crate::generate_state) to create one.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{Bitbucket, generate_state};
    ///
    /// let bitbucket = Bitbucket::new("client-id", "client-secret", "https://example.com/cb");
    /// let state = generate_state();
    ///
    /// let url = bitbucket.authorization_url(&state);
    /// assert!(url.as_str().starts_with("https://bitbucket.org/"));
    /// ```
    pub fn authorization_url(&self, state: &str) -> url::Url {
        self.client
            .create_authorization_url(&self.authorization_endpoint, state, &[])
    }

    /// Exchanges an authorization code for access and refresh tokens.
    ///
    /// Call this in your redirect URI handler after Bitbucket redirects back with a `code`
    /// query parameter.
    ///
    /// # Arguments
    ///
    /// * `code` - The authorization code from the `code` query parameter.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OAuthRequest`] if Bitbucket rejects the code, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::Bitbucket;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let bitbucket = Bitbucket::new("client-id", "secret", "https://example.com/cb");
    ///
    /// let tokens = bitbucket
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
    /// Bitbucket access tokens typically expire after 2 hours. Use this method to
    /// obtain a new access token without requiring the user to re-authenticate.
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
    /// # use arctic_oauth::Bitbucket;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let bitbucket = Bitbucket::new("client-id", "secret", "https://example.com/cb");
    ///
    /// let new_tokens = bitbucket
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

    fn get_header<'a>(request: &'a HttpRequest, name: &str) -> Option<&'a str> {
        request
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn make_bitbucket(http_client: &MockHttpClient) -> Bitbucket<'_, MockHttpClient> {
        Bitbucket::from_options(BitbucketOptions {
            client_id: "cid".into(),
            client_secret: "secret".into(),
            redirect_uri: "https://app/cb".into(),
            http_client,
        })
    }

    #[test]
    fn new_sets_production_endpoints() {
        let mock = MockHttpClient::new(vec![]);
        let bitbucket = make_bitbucket(&mock);
        assert_eq!(bitbucket.authorization_endpoint, AUTHORIZATION_ENDPOINT);
        assert_eq!(bitbucket.token_endpoint, TOKEN_ENDPOINT);
    }

    #[test]
    fn name_returns_bitbucket() {
        let mock = MockHttpClient::new(vec![]);
        let bitbucket = make_bitbucket(&mock);
        assert_eq!(bitbucket.name(), "Bitbucket");
    }

    #[test]
    fn authorization_url_has_no_scope_param() {
        let mock = MockHttpClient::new(vec![]);
        let bitbucket = make_bitbucket(&mock);
        let url = bitbucket.authorization_url("state123");

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.contains(&("client_id".into(), "cid".into())));
        assert!(pairs.contains(&("state".into(), "state123".into())));
        assert!(pairs.contains(&("redirect_uri".into(), "https://app/cb".into())));
        assert!(!pairs.iter().any(|(k, _)| k == "scope"));
    }

    #[tokio::test]
    async fn validate_authorization_code_delegates_to_client() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "bb-tok",
                "token_type": "Bearer",
                "expires_in": 7200
            }))
            .unwrap(),
        }]);
        let bitbucket = make_bitbucket(&mock);

        let tokens = bitbucket
            .validate_authorization_code("auth-code")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "bb-tok");

        let requests = mock.take_requests();
        assert_eq!(requests[0].url, TOKEN_ENDPOINT);
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
        let bitbucket = make_bitbucket(&mock);

        let tokens = bitbucket.refresh_access_token("refresh-tok").await.unwrap();

        assert_eq!(tokens.access_token().unwrap(), "new-tok");

        let requests = mock.take_requests();
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("grant_type".into(), "refresh_token".into())));
        assert!(body.contains(&("refresh_token".into(), "refresh-tok".into())));
    }
}
