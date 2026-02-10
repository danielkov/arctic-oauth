use crate::client::OAuth2Client;
use crate::error::Error;
use crate::http::HttpClient;
use crate::tokens::OAuth2Tokens;

const AUTHORIZATION_ENDPOINT: &str = "https://api.notion.com/v1/oauth/authorize";
const TOKEN_ENDPOINT: &str = "https://api.notion.com/v1/oauth/token";

/// Configuration for creating a [`Notion`] client with a custom HTTP client.
///
/// Use this when you need to provide your own [`HttpClient`] implementation
/// (e.g. a pre-configured `reqwest::Client` with custom timeouts or proxies).
/// For the common case, use [`Notion::new`] which uses the built-in default client.
pub struct NotionOptions<'a, H: HttpClient> {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub http_client: &'a H,
}

/// OAuth 2.0 client for [Notion](https://developers.notion.com/docs/authorization).
///
/// Notion does not require PKCE and does not use OAuth scopes. This client supports
/// the authorization code flow for obtaining access tokens. Note that Notion access
/// tokens do not expire, and Notion does not provide token refresh or revocation
/// endpoints.
///
/// # Setup
///
/// 1. Create an integration in the [Notion integrations page](https://www.notion.so/my-integrations).
/// 2. Choose **Public integration** and configure OAuth settings.
/// 3. Copy your OAuth client ID and OAuth client secret.
/// 4. Add the redirect URI to match the `redirect_uri` you pass to [`Notion::new`].
///
/// # Scopes
///
/// Notion does not use traditional OAuth 2.0 scopes. Instead, you configure capabilities
/// during integration creation (such as read content, update content, insert content).
/// These capabilities determine what your integration can access once a user grants
/// authorization.
///
/// See <https://developers.notion.com/docs/authorization#capabilities> for more details.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{Notion, generate_state};
///
/// # async fn example() -> Result<(), arctic_oauth::Error> {
/// let notion = Notion::new(
///     "your-client-id",
///     "your-client-secret",
///     "https://example.com/callback",
/// );
///
/// // Step 1: Generate CSRF state and redirect the user.
/// let state = generate_state();
/// let url = notion.authorization_url(&state);
/// // Store `state` in the user's session, then redirect to `url`.
///
/// // Step 2: Exchange the authorization code for tokens.
/// let tokens = notion
///     .validate_authorization_code("authorization-code")
///     .await?;
/// println!("Access token: {}", tokens.access_token()?);
/// # Ok(())
/// # }
/// ```
pub struct Notion<'a, H: HttpClient> {
    client: OAuth2Client,
    http_client: &'a H,
    authorization_endpoint: String,
    token_endpoint: String,
}

impl<'a, H: HttpClient> Notion<'a, H> {
    /// Creates a Notion client from a [`NotionOptions`] struct.
    ///
    /// Use this when you need a custom HTTP client. For the common case,
    /// use [`Notion::new`] instead.
    pub fn from_options(options: NotionOptions<'a, H>) -> Self {
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
impl Notion<'static, reqwest::Client> {
    /// Creates a new Notion OAuth 2.0 client using the default HTTP client.
    ///
    /// # Arguments
    ///
    /// * `client_id` - The OAuth 2.0 client ID from Notion's integration settings.
    /// * `client_secret` - The OAuth 2.0 client secret from Notion's integration settings.
    /// * `redirect_uri` - The URI Notion will redirect to after authorization.
    ///   Must match one configured in your integration settings.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::Notion;
    ///
    /// let notion = Notion::new(
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
        Self::from_options(NotionOptions {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri: redirect_uri.into(),
            http_client: crate::http::default_client(),
        })
    }
}

impl<'a, H: HttpClient> Notion<'a, H> {
    /// Returns the provider name (`"Notion"`).
    pub fn name(&self) -> &'static str {
        "Notion"
    }

    /// Builds the Notion authorization URL that the user should be redirected to.
    ///
    /// The returned URL includes all required OAuth 2.0 parameters. Your application
    /// should store `state` in the user's session before redirecting, as it is needed
    /// to prevent CSRF attacks.
    ///
    /// Note: This method automatically includes `owner=user` in the authorization URL,
    /// which is required by Notion's OAuth implementation.
    ///
    /// # Arguments
    ///
    /// * `state` - A CSRF token. Use [`generate_state`](crate::generate_state) to create one.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{Notion, generate_state};
    ///
    /// let notion = Notion::new("client-id", "client-secret", "https://example.com/cb");
    /// let state = generate_state();
    ///
    /// let url = notion.authorization_url(&state);
    /// assert!(url.as_str().starts_with("https://api.notion.com/"));
    /// ```
    pub fn authorization_url(&self, state: &str) -> url::Url {
        let mut url =
            self.client
                .create_authorization_url(&self.authorization_endpoint, state, &[]);
        url.query_pairs_mut().append_pair("owner", "user");
        url
    }

    /// Exchanges an authorization code for an access token.
    ///
    /// Call this in your redirect URI handler after Notion redirects back with a `code`
    /// query parameter. Note that Notion access tokens do not expire and no refresh
    /// token is provided.
    ///
    /// # Arguments
    ///
    /// * `code` - The authorization code from the `code` query parameter.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OAuthRequest`] if Notion rejects the code, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::Notion;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let notion = Notion::new("client-id", "secret", "https://example.com/cb");
    ///
    /// let tokens = notion
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

    fn get_header<'a>(request: &'a HttpRequest, name: &str) -> Option<&'a str> {
        request
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn make_notion(http_client: &MockHttpClient) -> Notion<'_, MockHttpClient> {
        Notion::from_options(NotionOptions {
            client_id: "cid".into(),
            client_secret: "secret".into(),
            redirect_uri: "https://app/cb".into(),
            http_client,
        })
    }

    #[test]
    fn new_sets_production_endpoints() {
        let mock = MockHttpClient::new(vec![]);
        let notion = make_notion(&mock);
        assert_eq!(notion.authorization_endpoint, AUTHORIZATION_ENDPOINT);
        assert_eq!(notion.token_endpoint, TOKEN_ENDPOINT);
    }

    #[test]
    fn name_returns_notion() {
        let mock = MockHttpClient::new(vec![]);
        let notion = make_notion(&mock);
        assert_eq!(notion.name(), "Notion");
    }

    #[test]
    fn authorization_url_includes_owner_user() {
        let mock = MockHttpClient::new(vec![]);
        let notion = make_notion(&mock);
        let url = notion.authorization_url("state123");

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.contains(&("client_id".into(), "cid".into())));
        assert!(pairs.contains(&("state".into(), "state123".into())));
        assert!(pairs.contains(&("redirect_uri".into(), "https://app/cb".into())));
        assert!(pairs.contains(&("owner".into(), "user".into())));
        assert!(!pairs.iter().any(|(k, _)| k == "scope"));
    }

    #[tokio::test]
    async fn validate_authorization_code_delegates_to_client() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "notion-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);
        let notion = make_notion(&mock);

        let tokens = notion
            .validate_authorization_code("auth-code")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "notion-tok");

        let requests = mock.take_requests();
        assert_eq!(requests[0].url, "https://api.notion.com/v1/oauth/token");
        assert!(get_header(&requests[0], "Authorization").is_some());
    }
}
