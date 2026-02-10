use crate::client::OAuth2Client;
use crate::error::Error;
use crate::http::HttpClient;
use crate::tokens::OAuth2Tokens;

const AUTHORIZATION_ENDPOINT: &str = "https://www.figma.com/oauth";
const TOKEN_ENDPOINT: &str = "https://api.figma.com/v1/oauth/token";
const REFRESH_ENDPOINT: &str = "https://api.figma.com/v1/oauth/refresh";

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
/// use arctic_oauth::{Figma, ReqwestClient, generate_state};
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
/// let http = ReqwestClient::new();
/// let tokens = figma
///     .validate_authorization_code(&http, "authorization-code")
///     .await?;
/// println!("Access token: {}", tokens.access_token()?);
///
/// // Step 3 (optional): Refresh an expired access token.
/// let refreshed = figma
///     .refresh_access_token(&http, tokens.refresh_token()?)
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct Figma {
    client: OAuth2Client,
    authorization_endpoint: String,
    token_endpoint: String,
    refresh_endpoint: String,
}

impl Figma {
    /// Creates a new Figma OAuth 2.0 client configured with production endpoints.
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
        Self {
            client: OAuth2Client::new(
                client_id,
                Some(client_secret.into()),
                Some(redirect_uri.into()),
            ),
            authorization_endpoint: AUTHORIZATION_ENDPOINT.to_string(),
            token_endpoint: TOKEN_ENDPOINT.to_string(),
            refresh_endpoint: REFRESH_ENDPOINT.to_string(),
        }
    }
}

#[cfg(any(test, feature = "testing"))]
impl Figma {
    /// Creates a Figma client with custom endpoint URLs.
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
    /// use arctic_oauth::Figma;
    ///
    /// let figma = Figma::with_endpoints(
    ///     "test-client-id",
    ///     "test-secret",
    ///     "http://localhost/callback",
    ///     "http://localhost:8080/authorize",
    ///     "http://localhost:8080/token",
    ///     "http://localhost:8080/refresh",
    /// );
    /// # }
    /// ```
    pub fn with_endpoints(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
        authorization_endpoint: &str,
        token_endpoint: &str,
        refresh_endpoint: &str,
    ) -> Self {
        Self {
            client: OAuth2Client::new(
                client_id,
                Some(client_secret.into()),
                Some(redirect_uri.into()),
            ),
            authorization_endpoint: authorization_endpoint.to_string(),
            token_endpoint: token_endpoint.to_string(),
            refresh_endpoint: refresh_endpoint.to_string(),
        }
    }
}

impl Figma {
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
    /// * `http_client` - An [`HttpClient`](crate::HttpClient) implementation (e.g.
    ///   [`ReqwestClient`](crate::ReqwestClient)).
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
    /// # use arctic_oauth::{Figma, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let figma = Figma::new("client-id", "secret", "https://example.com/cb");
    /// let http = ReqwestClient::new();
    ///
    /// let tokens = figma
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
    /// Figma access tokens typically expire after 90 days. Use this method to obtain a new
    /// access token without user interaction. Note that Figma uses a separate endpoint
    /// for token refresh.
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
    /// # use arctic_oauth::{Figma, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let figma = Figma::new("client-id", "secret", "https://example.com/cb");
    /// let http = ReqwestClient::new();
    ///
    /// let new_tokens = figma
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
            .refresh_access_token(http_client, &self.refresh_endpoint, refresh_token, &[])
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

    #[test]
    fn new_sets_production_endpoints() {
        let figma = Figma::new("cid", "secret", "https://app/cb");
        assert_eq!(figma.authorization_endpoint, AUTHORIZATION_ENDPOINT);
        assert_eq!(figma.token_endpoint, TOKEN_ENDPOINT);
        assert_eq!(figma.refresh_endpoint, REFRESH_ENDPOINT);
    }

    #[test]
    fn name_returns_figma() {
        let figma = Figma::new("cid", "secret", "https://app/cb");
        assert_eq!(figma.name(), "Figma");
    }

    #[test]
    fn authorization_url_builds_correct_params() {
        let figma = Figma::new("cid", "secret", "https://app/cb");
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
        let figma = Figma::new("cid", "secret", "https://app/cb");
        let url = figma.authorization_url("state123", &[]);

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(!pairs.iter().any(|(k, _)| k == "scope"));
    }

    #[tokio::test]
    async fn validate_authorization_code_sends_to_token_endpoint() {
        let figma = Figma::with_endpoints(
            "cid",
            "secret",
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
            "https://mock/refresh",
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "figma-tok",
                "token_type": "Bearer",
                "expires_in": 7776000
            }))
            .unwrap(),
        }]);

        let tokens = figma
            .validate_authorization_code(&mock, "auth-code")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "figma-tok");

        let requests = mock.take_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url, "https://mock/token");

        assert!(get_header(&requests[0], "Authorization").is_some());

        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("grant_type".into(), "authorization_code".into())));
        assert!(body.contains(&("code".into(), "auth-code".into())));
    }

    #[tokio::test]
    async fn refresh_access_token_sends_to_refresh_endpoint() {
        let figma = Figma::with_endpoints(
            "cid",
            "secret",
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
            "https://mock/refresh",
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "new-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);

        let tokens = figma
            .refresh_access_token(&mock, "refresh-tok")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "new-tok");

        let requests = mock.take_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url, "https://mock/refresh");

        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("grant_type".into(), "refresh_token".into())));
        assert!(body.contains(&("refresh_token".into(), "refresh-tok".into())));
    }
}
