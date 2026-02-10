use crate::client::OAuth2Client;
use crate::error::Error;
use crate::http::HttpClient;
use crate::tokens::OAuth2Tokens;

const AUTHORIZATION_ENDPOINT: &str = "https://www.reddit.com/api/v1/authorize";
const TOKEN_ENDPOINT: &str = "https://www.reddit.com/api/v1/access_token";

/// OAuth 2.0 client for [Reddit](https://www.reddit.com/dev/api/oauth).
///
/// Reddit uses standard OAuth 2.0 authorization code flow without PKCE.
/// The client supports authorization, token exchange, and token refresh.
///
/// # Setup
///
/// 1. Create an application in your [Reddit app preferences](https://www.reddit.com/prefs/apps).
/// 2. Select "web app" as the app type to receive a client ID and client secret.
/// 3. Set the redirect URI to match your application's callback URL.
///
/// # Scopes
///
/// Reddit uses space-separated scopes. Common scopes include:
///
/// | Scope | Description |
/// |-------|-------------|
/// | `identity` | Access to user account information |
/// | `edit` | Edit and delete posts and comments |
/// | `read` | Read posts and comments |
/// | `submit` | Submit links and comments |
/// | `vote` | Submit and change votes |
///
/// See the full list at <https://www.reddit.com/dev/api/oauth>.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{Reddit, ReqwestClient, generate_state};
///
/// # async fn example() -> Result<(), arctic_oauth::Error> {
/// let provider = Reddit::new(
///     "your-client-id",
///     "your-client-secret",
///     "https://example.com/callback",
/// );
///
/// // Step 1: Generate CSRF state and redirect the user.
/// let state = generate_state();
/// let url = provider.authorization_url(&state, &["identity", "read"]);
///
/// // Step 2: Exchange the authorization code for tokens.
/// let http = ReqwestClient::new();
/// let tokens = provider
///     .validate_authorization_code(&http, "authorization-code")
///     .await?;
/// println!("Access token: {}", tokens.access_token()?);
///
/// // Step 3 (optional): Refresh an expired access token.
/// let refreshed = provider
///     .refresh_access_token(&http, tokens.refresh_token()?)
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct Reddit {
    client: OAuth2Client,
    authorization_endpoint: String,
    token_endpoint: String,
}

impl Reddit {
    /// Creates a new Reddit OAuth 2.0 client configured with production endpoints.
    ///
    /// # Arguments
    ///
    /// * `client_id` - The OAuth 2.0 client ID from Reddit's app preferences.
    /// * `client_secret` - The OAuth 2.0 client secret from Reddit's app preferences.
    /// * `redirect_uri` - The URI Reddit will redirect to after authorization.
    ///   Must match one configured in your app settings.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::Reddit;
    ///
    /// let provider = Reddit::new(
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
        Self {
            client: OAuth2Client::new(
                client_id,
                Some(client_secret.into()),
                Some(redirect_uri.into()),
            ),
            authorization_endpoint: AUTHORIZATION_ENDPOINT.to_string(),
            token_endpoint: TOKEN_ENDPOINT.to_string(),
        }
    }
}

#[cfg(any(test, feature = "testing"))]
impl Reddit {
    /// Creates a Reddit client with custom endpoint URLs.
    ///
    /// This is useful for integration testing with mock servers (e.g.
    /// [`wiremock`](https://docs.rs/wiremock)). Only available when the `testing` feature
    /// is enabled or in `#[cfg(test)]` builds.
    ///
    /// # Example
    ///
    /// ```rust
    /// # #[cfg(feature = "testing")]
    /// # {
    /// use arctic_oauth::Reddit;
    ///
    /// let provider = Reddit::with_endpoints(
    ///     "test-client-id",
    ///     "test-secret",
    ///     "http://localhost/callback",
    ///     "http://localhost:8080/authorize",
    ///     "http://localhost:8080/token",
    /// );
    /// # }
    /// ```
    pub fn with_endpoints(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
        authorization_endpoint: &str,
        token_endpoint: &str,
    ) -> Self {
        Self {
            client: OAuth2Client::new(
                client_id,
                Some(client_secret.into()),
                Some(redirect_uri.into()),
            ),
            authorization_endpoint: authorization_endpoint.to_string(),
            token_endpoint: token_endpoint.to_string(),
        }
    }
}

impl Reddit {
    /// Returns the provider name (`"Reddit"`).
    pub fn name(&self) -> &'static str {
        "Reddit"
    }

    /// Builds the Reddit authorization URL that the user should be redirected to.
    ///
    /// The returned URL includes all required OAuth 2.0 parameters. Your application
    /// should store `state` in the user's session before redirecting, as it is needed
    /// to complete the flow.
    ///
    /// # Arguments
    ///
    /// * `state` - A CSRF token. Use [`generate_state`](crate::generate_state) to create one.
    /// * `scopes` - The OAuth 2.0 scopes to request (e.g. `&["identity", "read"]`).
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{Reddit, generate_state};
    ///
    /// let provider = Reddit::new("client-id", "client-secret", "https://example.com/cb");
    /// let state = generate_state();
    ///
    /// let url = provider.authorization_url(&state, &["identity", "read"]);
    /// ```
    pub fn authorization_url(&self, state: &str, scopes: &[&str]) -> url::Url {
        self.client
            .create_authorization_url(&self.authorization_endpoint, state, scopes)
    }

    /// Exchanges an authorization code for access and refresh tokens.
    ///
    /// Call this in your redirect URI handler after Reddit redirects back with a `code`
    /// query parameter.
    ///
    /// # Arguments
    ///
    /// * `http_client` - An [`HttpClient`](crate::HttpClient) implementation (e.g.
    ///   [`ReqwestClient`](crate::ReqwestClient)).
    /// * `code` - The authorization code from the `code` query parameter.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OAuthRequest`] if Reddit rejects the code, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::{Reddit, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let provider = Reddit::new("client-id", "client-secret", "https://example.com/cb");
    /// let http = ReqwestClient::new();
    ///
    /// let tokens = provider
    ///     .validate_authorization_code(&http, "the-auth-code")
    ///     .await?;
    ///
    /// println!("Access token: {}", tokens.access_token()?);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn validate_authorization_code(
        &self,
        http_client: &(impl HttpClient + ?Sized),
        code: &str,
    ) -> Result<OAuth2Tokens, Error> {
        self.client
            .validate_authorization_code(http_client, &self.token_endpoint, code, None)
            .await
    }

    /// Refreshes an expired access token using a refresh token.
    ///
    /// Reddit access tokens typically expire after 1 hour. Use this method to
    /// obtain a new access token without requiring the user to re-authenticate.
    ///
    /// # Arguments
    ///
    /// * `http_client` - An [`HttpClient`](crate::HttpClient) implementation.
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
    /// # use arctic_oauth::{Reddit, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let provider = Reddit::new("client-id", "client-secret", "https://example.com/cb");
    /// let http = ReqwestClient::new();
    ///
    /// let new_tokens = provider
    ///     .refresh_access_token(&http, "stored-refresh-token")
    ///     .await?;
    ///
    /// println!("New access token: {}", new_tokens.access_token()?);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn refresh_access_token(
        &self,
        http_client: &(impl HttpClient + ?Sized),
        refresh_token: &str,
    ) -> Result<OAuth2Tokens, Error> {
        self.client
            .refresh_access_token(http_client, &self.token_endpoint, refresh_token, &[])
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

    #[test]
    fn new_sets_production_endpoints() {
        let reddit = Reddit::new("cid", "secret", "https://app/cb");
        assert_eq!(reddit.authorization_endpoint, AUTHORIZATION_ENDPOINT);
        assert_eq!(reddit.token_endpoint, TOKEN_ENDPOINT);
    }

    #[test]
    fn with_endpoints_overrides_urls() {
        let reddit = Reddit::with_endpoints(
            "cid",
            "secret",
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
        );
        assert_eq!(reddit.authorization_endpoint, "https://mock/authorize");
        assert_eq!(reddit.token_endpoint, "https://mock/token");
    }

    #[test]
    fn name_returns_correct_name() {
        let reddit = Reddit::new("cid", "secret", "https://app/cb");
        assert_eq!(reddit.name(), "Reddit");
    }

    #[test]
    fn authorization_url_builds_correct_params() {
        let reddit = Reddit::new("cid", "secret", "https://app/cb");
        let url = reddit.authorization_url("state123", &["read", "identity"]);

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.contains(&("client_id".into(), "cid".into())));
        assert!(pairs.contains(&("state".into(), "state123".into())));
        assert!(pairs.contains(&("scope".into(), "read identity".into())));
        assert!(pairs.contains(&("redirect_uri".into(), "https://app/cb".into())));
        assert!(!pairs.iter().any(|(k, _)| k == "code_challenge"));
    }

    #[tokio::test]
    async fn validate_authorization_code_delegates_to_client() {
        let reddit = Reddit::with_endpoints(
            "cid",
            "secret",
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "reddit-tok",
                "token_type": "Bearer",
                "expires_in": 3600
            }))
            .unwrap(),
        }]);

        let tokens = reddit
            .validate_authorization_code(&mock, "auth-code")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "reddit-tok");

        let requests = mock.take_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url, "https://mock/token");

        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("grant_type".into(), "authorization_code".into())));
        assert!(body.contains(&("code".into(), "auth-code".into())));
        assert!(!body.iter().any(|(k, _)| k == "code_verifier"));
    }

    #[tokio::test]
    async fn refresh_access_token_delegates_to_client() {
        let reddit = Reddit::with_endpoints(
            "cid",
            "secret",
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "new-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);

        let tokens = reddit
            .refresh_access_token(&mock, "refresh-tok")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "new-tok");

        let requests = mock.take_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url, "https://mock/token");

        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("grant_type".into(), "refresh_token".into())));
        assert!(body.contains(&("refresh_token".into(), "refresh-tok".into())));
    }
}
