use crate::client::OAuth2Client;
use crate::error::Error;
use crate::http::HttpClient;
use crate::tokens::OAuth2Tokens;

const AUTHORIZATION_ENDPOINT: &str = "https://anilist.co/api/v2/oauth/authorize";
const TOKEN_ENDPOINT: &str = "https://anilist.co/api/v2/oauth/token";

/// OAuth 2.0 client for [AniList](https://anilist.gitbook.io/anilist-apiv2-docs/docs/guide/auth/index).
///
/// AniList does not require PKCE and does not use OAuth scopes. This client supports
/// the authorization code flow for obtaining access tokens.
///
/// # Setup
///
/// 1. Navigate to [AniList Developer Settings](https://anilist.co/settings/developer) while logged in.
/// 2. Create a new API client and obtain your Client ID and Client Secret.
/// 3. Set the redirect URI to match the `redirect_uri` you pass to [`AniList::new`].
///
/// # Scopes
///
/// AniList does not use OAuth 2.0 scopes. All authenticated requests have access to the
/// same set of permissions based on the user's authorization.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{AniList, ReqwestClient, generate_state};
///
/// # async fn example() -> Result<(), arctic_oauth::Error> {
/// let anilist = AniList::new(
///     "your-client-id",
///     "your-client-secret",
///     "https://example.com/callback",
/// );
///
/// // Step 1: Generate CSRF state and redirect the user.
/// let state = generate_state();
/// let url = anilist.authorization_url(&state);
/// // Store `state` in the user's session, then redirect to `url`.
///
/// // Step 2: Exchange the authorization code for tokens.
/// let http = ReqwestClient::new();
/// let tokens = anilist
///     .validate_authorization_code(&http, "authorization-code")
///     .await?;
/// println!("Access token: {}", tokens.access_token()?);
/// # Ok(())
/// # }
/// ```
pub struct AniList {
    client: OAuth2Client,
    authorization_endpoint: String,
    token_endpoint: String,
}

impl AniList {
    /// Creates a new AniList OAuth 2.0 client configured with production endpoints.
    ///
    /// # Arguments
    ///
    /// * `client_id` - The OAuth 2.0 client ID from AniList's developer settings.
    /// * `client_secret` - The OAuth 2.0 client secret from AniList's developer settings.
    /// * `redirect_uri` - The URI AniList will redirect to after authorization.
    ///   Must match one configured in your app settings.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::AniList;
    ///
    /// let anilist = AniList::new(
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
impl AniList {
    /// Creates an AniList client with custom endpoint URLs.
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
    /// use arctic_oauth::AniList;
    ///
    /// let anilist = AniList::with_endpoints(
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

impl AniList {
    /// Returns the provider name (`"AniList"`).
    pub fn name(&self) -> &'static str {
        "AniList"
    }

    /// Builds the AniList authorization URL that the user should be redirected to.
    ///
    /// The returned URL includes all required OAuth 2.0 parameters. Your application
    /// should store `state` in the user's session before redirecting, as it is needed
    /// to prevent CSRF attacks.
    ///
    /// # Arguments
    ///
    /// * `state` - A CSRF token. Use [`generate_state`](crate::generate_state) to create one.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{AniList, generate_state};
    ///
    /// let anilist = AniList::new("client-id", "client-secret", "https://example.com/cb");
    /// let state = generate_state();
    ///
    /// let url = anilist.authorization_url(&state);
    /// assert!(url.as_str().starts_with("https://anilist.co/"));
    /// ```
    pub fn authorization_url(&self, state: &str) -> url::Url {
        self.client
            .create_authorization_url(&self.authorization_endpoint, state, &[])
    }

    /// Exchanges an authorization code for access and refresh tokens.
    ///
    /// Call this in your redirect URI handler after AniList redirects back with a `code`
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
    /// Returns [`Error::OAuthRequest`] if AniList rejects the code, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::{AniList, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let anilist = AniList::new("client-id", "secret", "https://example.com/cb");
    /// let http = ReqwestClient::new();
    ///
    /// let tokens = anilist
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
        let anilist = AniList::new("cid", "secret", "https://app/cb");
        assert_eq!(anilist.authorization_endpoint, AUTHORIZATION_ENDPOINT);
        assert_eq!(anilist.token_endpoint, TOKEN_ENDPOINT);
    }

    #[test]
    fn with_endpoints_overrides_urls() {
        let anilist = AniList::with_endpoints(
            "cid",
            "secret",
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
        );
        assert_eq!(anilist.authorization_endpoint, "https://mock/authorize");
        assert_eq!(anilist.token_endpoint, "https://mock/token");
    }

    #[test]
    fn name_returns_correct_name() {
        let anilist = AniList::new("cid", "secret", "https://app/cb");
        assert_eq!(anilist.name(), "AniList");
    }

    #[test]
    fn authorization_url_builds_correct_params() {
        let anilist = AniList::new("cid", "secret", "https://app/cb");
        let url = anilist.authorization_url("state123");

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.contains(&("client_id".into(), "cid".into())));
        assert!(pairs.contains(&("state".into(), "state123".into())));
        assert!(pairs.contains(&("redirect_uri".into(), "https://app/cb".into())));
        assert!(!pairs.iter().any(|(k, _)| k == "scope"));
        assert!(!pairs.iter().any(|(k, _)| k == "code_challenge"));
    }

    #[tokio::test]
    async fn validate_authorization_code_delegates_to_client() {
        let anilist = AniList::with_endpoints(
            "cid",
            "secret",
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "anilist-tok",
                "token_type": "Bearer",
                "expires_in": 3600
            }))
            .unwrap(),
        }]);

        let tokens = anilist
            .validate_authorization_code(&mock, "auth-code")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "anilist-tok");

        let requests = mock.take_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url, "https://mock/token");

        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("grant_type".into(), "authorization_code".into())));
        assert!(body.contains(&("code".into(), "auth-code".into())));
        assert!(!body.iter().any(|(k, _)| k == "code_verifier"));
    }
}
