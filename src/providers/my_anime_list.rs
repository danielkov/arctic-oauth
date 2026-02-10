use crate::client::OAuth2Client;
use crate::error::Error;
use crate::http::HttpClient;
use crate::pkce::CodeChallengeMethod;
use crate::tokens::OAuth2Tokens;

const AUTHORIZATION_ENDPOINT: &str = "https://myanimelist.net/v1/oauth2/authorize";
const TOKEN_ENDPOINT: &str = "https://myanimelist.net/v1/oauth2/token";

/// OAuth 2.0 client for [MyAnimeList](https://myanimelist.net/apiconfig/references/authorization).
///
/// MyAnimeList requires PKCE with the Plain challenge method (not S256) on all authorization
/// requests. The redirect URI is optional for this provider. This client supports the
/// authorization code flow including token refresh but not token revocation.
///
/// # Setup
///
/// 1. Register your application at the [MyAnimeList API](https://myanimelist.net/apiconfig) page.
/// 2. Obtain your Client ID and Client Secret from the application settings.
/// 3. Optionally configure the redirect URL (can be omitted for some applications).
///
/// # Scopes
///
/// MyAnimeList does not use explicit scopes in the OAuth flow. All authenticated users
/// have access to the same set of API endpoints based on their account permissions.
/// The API provides access to:
///
/// | Feature | Description |
/// |---------|-------------|
/// | User Profile | Read and update user anime/manga lists |
/// | Anime Data | Search and retrieve anime information |
/// | Manga Data | Search and retrieve manga information |
///
/// See the full documentation at <https://myanimelist.net/apiconfig/references/api/v2>.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{MyAnimeList, ReqwestClient, generate_state, generate_code_verifier};
///
/// # async fn example() -> Result<(), arctic_oauth::Error> {
/// let myanimelist = MyAnimeList::new(
///     "your-client-id",
///     "your-client-secret",
///     Some("https://example.com/callback".to_string()),
/// );
///
/// // Step 1: Generate PKCE verifier and CSRF state, then redirect the user.
/// let state = generate_state();
/// let code_verifier = generate_code_verifier();
/// let url = myanimelist.authorization_url(&state, &code_verifier);
/// // Store `state` and `code_verifier` in the user's session, then redirect to `url`.
///
/// // Step 2: In your callback handler, exchange the authorization code for tokens.
/// let http = ReqwestClient::new();
/// let tokens = myanimelist
///     .validate_authorization_code(&http, "authorization-code", &code_verifier)
///     .await?;
/// println!("Access token: {}", tokens.access_token()?);
///
/// // Step 3 (optional): Refresh an expired access token.
/// let refreshed = myanimelist
///     .refresh_access_token(&http, tokens.refresh_token()?)
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct MyAnimeList {
    client: OAuth2Client,
    authorization_endpoint: String,
    token_endpoint: String,
}

impl MyAnimeList {
    /// Creates a new MyAnimeList OAuth 2.0 client configured with production endpoints.
    ///
    /// # Arguments
    ///
    /// * `client_id` - The OAuth 2.0 client ID from MyAnimeList API settings.
    /// * `client_secret` - The OAuth 2.0 client secret from MyAnimeList API settings.
    /// * `redirect_uri` - Optional redirect URI. If provided, it must match the redirect URL
    ///   configured in your MyAnimeList application. Can be `None` for some applications.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::MyAnimeList;
    ///
    /// // With redirect URI
    /// let myanimelist = MyAnimeList::new(
    ///     "your-client-id",
    ///     "your-client-secret",
    ///     Some("https://example.com/callback".to_string()),
    /// );
    ///
    /// // Without redirect URI
    /// let myanimelist = MyAnimeList::new(
    ///     "your-client-id",
    ///     "your-client-secret",
    ///     None,
    /// );
    /// ```
    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: Option<String>,
    ) -> Self {
        Self {
            client: OAuth2Client::new(client_id, Some(client_secret.into()), redirect_uri),
            authorization_endpoint: AUTHORIZATION_ENDPOINT.to_string(),
            token_endpoint: TOKEN_ENDPOINT.to_string(),
        }
    }
}

#[cfg(any(test, feature = "testing"))]
impl MyAnimeList {
    /// Creates a MyAnimeList client with custom endpoint URLs.
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
    /// use arctic_oauth::MyAnimeList;
    ///
    /// let myanimelist = MyAnimeList::with_endpoints(
    ///     "test-client-id",
    ///     "test-secret",
    ///     Some("http://localhost/callback".to_string()),
    ///     "http://localhost:8080/authorize",
    ///     "http://localhost:8080/token",
    /// );
    /// # }
    /// ```
    pub fn with_endpoints(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: Option<String>,
        authorization_endpoint: &str,
        token_endpoint: &str,
    ) -> Self {
        Self {
            client: OAuth2Client::new(client_id, Some(client_secret.into()), redirect_uri),
            authorization_endpoint: authorization_endpoint.to_string(),
            token_endpoint: token_endpoint.to_string(),
        }
    }
}

impl MyAnimeList {
    /// Returns the provider name (`"MyAnimeList"`).
    pub fn name(&self) -> &'static str {
        "MyAnimeList"
    }

    /// Builds the MyAnimeList authorization URL that the user should be redirected to.
    ///
    /// MyAnimeList uses PKCE with the Plain challenge method (not S256). The returned URL
    /// includes all required OAuth 2.0 and PKCE parameters. Your application should store
    /// `state` and `code_verifier` in the user's session before redirecting, as both are
    /// needed to complete the flow.
    ///
    /// # Arguments
    ///
    /// * `state` - A CSRF token to prevent cross-site request forgery. Use
    ///   [`generate_state`](crate::generate_state) to create one.
    /// * `code_verifier` - The PKCE code verifier. Use
    ///   [`generate_code_verifier`](crate::generate_code_verifier) to create one.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{MyAnimeList, generate_state, generate_code_verifier};
    ///
    /// let myanimelist = MyAnimeList::new("client-id", "client-secret", Some("https://example.com/cb".to_string()));
    /// let state = generate_state();
    /// let verifier = generate_code_verifier();
    ///
    /// let url = myanimelist.authorization_url(&state, &verifier);
    /// assert!(url.as_str().starts_with("https://myanimelist.net/"));
    /// ```
    pub fn authorization_url(&self, state: &str, code_verifier: &str) -> url::Url {
        self.client.create_authorization_url_with_pkce(
            &self.authorization_endpoint,
            state,
            CodeChallengeMethod::Plain,
            code_verifier,
            &[],
        )
    }

    /// Exchanges an authorization code for access and refresh tokens.
    ///
    /// Call this in your redirect URI handler after MyAnimeList redirects back with a `code`
    /// query parameter. The `code_verifier` must be the same value used to generate the
    /// authorization URL. Credentials are sent via HTTP Basic authentication.
    ///
    /// # Arguments
    ///
    /// * `http_client` - An [`HttpClient`](crate::HttpClient) implementation (e.g.
    ///   [`ReqwestClient`](crate::ReqwestClient)).
    /// * `code` - The authorization code from the `code` query parameter.
    /// * `code_verifier` - The PKCE code verifier stored during the authorization step.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OAuthRequest`] if MyAnimeList rejects the code, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::{MyAnimeList, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let myanimelist = MyAnimeList::new("client-id", "secret", Some("https://example.com/cb".to_string()));
    /// let http = ReqwestClient::new();
    ///
    /// let tokens = myanimelist
    ///     .validate_authorization_code(&http, "the-auth-code", "the-code-verifier")
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
        code_verifier: &str,
    ) -> Result<OAuth2Tokens, Error> {
        self.client
            .validate_authorization_code(
                http_client,
                &self.token_endpoint,
                code,
                Some(code_verifier),
            )
            .await
    }

    /// Refreshes an expired access token using a refresh token.
    ///
    /// MyAnimeList access tokens typically expire after a set period. Use the refresh token
    /// from the initial token response to obtain a new access token without user interaction.
    /// Credentials are sent via HTTP Basic authentication.
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
    /// # use arctic_oauth::{MyAnimeList, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let myanimelist = MyAnimeList::new("client-id", "secret", Some("https://example.com/cb".to_string()));
    /// let http = ReqwestClient::new();
    ///
    /// let new_tokens = myanimelist
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

    fn get_header<'a>(request: &'a HttpRequest, name: &str) -> Option<&'a str> {
        request
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn new_sets_production_endpoints() {
        let provider = MyAnimeList::new("cid", "secret", Some("https://app/cb".into()));
        assert_eq!(provider.authorization_endpoint, AUTHORIZATION_ENDPOINT);
        assert_eq!(provider.token_endpoint, TOKEN_ENDPOINT);
    }

    #[test]
    fn new_with_no_redirect_uri() {
        let provider = MyAnimeList::new("cid", "secret", None);
        assert_eq!(provider.name(), "MyAnimeList");
    }

    #[test]
    fn name_returns_myanimelist() {
        let provider = MyAnimeList::new("cid", "secret", Some("https://app/cb".into()));
        assert_eq!(provider.name(), "MyAnimeList");
    }

    #[test]
    fn authorization_url_uses_plain_pkce() {
        let provider = MyAnimeList::new("cid", "secret", Some("https://app/cb".into()));
        let url = provider.authorization_url("state123", "my-plain-verifier");

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.contains(&("client_id".into(), "cid".into())));
        assert!(pairs.contains(&("state".into(), "state123".into())));
        assert!(pairs.contains(&("redirect_uri".into(), "https://app/cb".into())));
        // Plain PKCE: code_challenge == verifier
        assert!(pairs.contains(&("code_challenge".into(), "my-plain-verifier".into())));
        assert!(pairs.contains(&("code_challenge_method".into(), "plain".into())));
        // No scopes
        assert!(!pairs.iter().any(|(k, _)| k == "scope"));
    }

    #[test]
    fn authorization_url_without_redirect_uri() {
        let provider = MyAnimeList::new("cid", "secret", None);
        let url = provider.authorization_url("state123", "verifier");

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(!pairs.iter().any(|(k, _)| k == "redirect_uri"));
        assert!(pairs.contains(&("code_challenge_method".into(), "plain".into())));
    }

    #[tokio::test]
    async fn validate_authorization_code_uses_basic_auth() {
        let provider = MyAnimeList::with_endpoints(
            "cid",
            "secret",
            Some("https://app/cb".into()),
            "https://mock/authorize",
            "https://mock/token",
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "mal-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);

        let tokens = provider
            .validate_authorization_code(&mock, "auth-code", "my-verifier")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "mal-tok");

        let requests = mock.take_requests();
        assert_eq!(requests[0].url, "https://mock/token");
        // Pattern A: Basic Auth
        assert!(get_header(&requests[0], "Authorization").is_some());

        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("grant_type".into(), "authorization_code".into())));
        assert!(body.contains(&("code".into(), "auth-code".into())));
        assert!(body.contains(&("code_verifier".into(), "my-verifier".into())));
        assert!(body.contains(&("redirect_uri".into(), "https://app/cb".into())));
    }

    #[tokio::test]
    async fn refresh_access_token_uses_basic_auth() {
        let provider = MyAnimeList::with_endpoints(
            "cid",
            "secret",
            Some("https://app/cb".into()),
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

        let tokens = provider
            .refresh_access_token(&mock, "refresh-tok")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "new-tok");

        let requests = mock.take_requests();
        assert!(get_header(&requests[0], "Authorization").is_some());
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("grant_type".into(), "refresh_token".into())));
        assert!(body.contains(&("refresh_token".into(), "refresh-tok".into())));
    }
}
