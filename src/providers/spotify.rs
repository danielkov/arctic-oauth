use crate::client::OAuth2Client;
use crate::error::Error;
use crate::http::HttpClient;
use crate::pkce::CodeChallengeMethod;
use crate::tokens::OAuth2Tokens;

const AUTHORIZATION_ENDPOINT: &str = "https://accounts.spotify.com/authorize";
const TOKEN_ENDPOINT: &str = "https://accounts.spotify.com/api/token";

/// Configuration for creating a [`Spotify`] client with a custom HTTP client.
///
/// Use this when you need to provide your own [`HttpClient`] implementation
/// (e.g. a pre-configured `reqwest::Client` with custom timeouts or proxies).
/// For the common case, use [`Spotify::new`] which uses the built-in default client.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{Spotify, SpotifyOptions, HttpClient};
///
/// let custom_client = reqwest::Client::builder()
///     .timeout(std::time::Duration::from_secs(10))
///     .build()
///     .unwrap();
///
/// let spotify = Spotify::from_options(SpotifyOptions {
///     client_id: "your-client-id".into(),
///     client_secret: Some("your-client-secret".into()),
///     redirect_uri: "https://example.com/callback".into(),
///     http_client: &custom_client,
/// });
/// ```
pub struct SpotifyOptions<'a, H: HttpClient> {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_uri: String,
    pub http_client: &'a H,
}

/// OAuth 2.0 client for [Spotify](https://developer.spotify.com/documentation/web-api/concepts/authorization).
///
/// Spotify supports optional PKCE with the S256 challenge method for enhanced security,
/// especially recommended for mobile and desktop applications. This client supports the
/// full authorization code flow including token refresh. The client can be configured as
/// either a confidential client (with client secret) or a public client (without client secret).
///
/// # Setup
///
/// 1. Create an app in the [Spotify Developer Dashboard](https://developer.spotify.com/dashboard).
/// 2. Note your **Client ID** and **Client Secret** from the app settings.
/// 3. Add a **Redirect URI** in the app settings that matches the `redirect_uri` you pass to [`Spotify::new`].
///
/// # Scopes
///
/// Spotify uses space-separated scopes. Common scopes include:
///
/// | Scope | Description |
/// |-------|-------------|
/// | `user-read-email` | Read access to user's email address |
/// | `user-read-private` | Read access to user's subscription details |
/// | `playlist-read-private` | Read access to user's private playlists |
/// | `playlist-modify-public` | Write access to user's public playlists |
/// | `user-library-read` | Read access to user's library |
///
/// See the full list at <https://developer.spotify.com/documentation/web-api/concepts/scopes>.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{Spotify, generate_state, generate_code_verifier};
///
/// # async fn example() -> Result<(), arctic_oauth::Error> {
/// let spotify = Spotify::new(
///     "your-client-id",
///     Some("your-client-secret".to_string()),
///     "https://example.com/callback",
/// );
///
/// // Step 1: Generate PKCE verifier (optional) and CSRF state, then redirect the user.
/// let state = generate_state();
/// let code_verifier = generate_code_verifier();
/// let url = spotify.authorization_url(&state, &["user-read-email", "playlist-read-private"], Some(&code_verifier))?;
/// // Store `state` and optionally `code_verifier` in the user's session, then redirect to `url`.
///
/// // Step 2: In your callback handler, exchange the authorization code for tokens.
/// let tokens = spotify
///     .validate_authorization_code("authorization-code", Some(&code_verifier))
///     .await?;
/// println!("Access token: {}", tokens.access_token()?);
///
/// // Step 3 (optional): Refresh an expired access token.
/// let refreshed = spotify
///     .refresh_access_token(tokens.refresh_token()?)
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct Spotify<'a, H: HttpClient> {
    client: OAuth2Client,
    http_client: &'a H,
    authorization_endpoint: String,
    token_endpoint: String,
}

impl<'a, H: HttpClient> Spotify<'a, H> {
    /// Creates a Spotify client from a [`SpotifyOptions`] struct.
    ///
    /// Use this when you need a custom HTTP client. For the common case,
    /// use [`Spotify::new`] instead.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{Spotify, SpotifyOptions};
    ///
    /// let custom_client = reqwest::Client::new();
    /// let spotify = Spotify::from_options(SpotifyOptions {
    ///     client_id: "your-client-id".into(),
    ///     client_secret: Some("your-client-secret".into()),
    ///     redirect_uri: "https://example.com/callback".into(),
    ///     http_client: &custom_client,
    /// });
    /// ```
    pub fn from_options(options: SpotifyOptions<'a, H>) -> Self {
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
impl Spotify<'static, reqwest::Client> {
    /// Creates a new Spotify OAuth 2.0 client using the default HTTP client.
    ///
    /// Uses the built-in `reqwest::Client` for HTTP requests. To provide a custom
    /// HTTP client, use [`Spotify::from_options`] instead.
    ///
    /// # Arguments
    ///
    /// * `client_id` - The OAuth 2.0 client ID from Spotify's developer dashboard.
    /// * `client_secret` - The OAuth 2.0 client secret from Spotify's developer dashboard.
    ///   Pass `None` to create a public client (for mobile/desktop apps with PKCE).
    /// * `redirect_uri` - The URI Spotify will redirect to after authorization.
    ///   Must match one configured in your Spotify app settings.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::Spotify;
    ///
    /// // Confidential client (web apps)
    /// let spotify = Spotify::new(
    ///     "your-client-id",
    ///     Some("your-client-secret".to_string()),
    ///     "https://example.com/callback",
    /// );
    ///
    /// // Public client (mobile/desktop apps)
    /// let spotify_public = Spotify::new(
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
        Self::from_options(SpotifyOptions {
            client_id: client_id.into(),
            client_secret,
            redirect_uri: redirect_uri.into(),
            http_client: crate::http::default_client(),
        })
    }
}

impl<'a, H: HttpClient> Spotify<'a, H> {
    /// Returns the provider name (`"Spotify"`).
    pub fn name(&self) -> &'static str {
        "Spotify"
    }

    /// Builds the Spotify authorization URL that the user should be redirected to.
    ///
    /// The returned URL includes all required OAuth 2.0 parameters and optionally PKCE
    /// parameters. Your application should store `state` (and `code_verifier` if PKCE is
    /// used) in the user's session before redirecting, as they are needed to complete the flow.
    ///
    /// # Arguments
    ///
    /// * `state` - A CSRF token to prevent cross-site request forgery. Use
    ///   [`generate_state`](crate::generate_state) to create one.
    /// * `scopes` - The OAuth 2.0 scopes to request (e.g. `&["user-read-email", "playlist-read-private"]`).
    /// * `code_verifier` - Optional PKCE code verifier. Use
    ///   [`generate_code_verifier`](crate::generate_code_verifier) to create one.
    ///   Pass `None` to skip PKCE.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{Spotify, generate_state, generate_code_verifier};
    ///
    /// # fn example() -> Result<(), arctic_oauth::Error> {
    /// let spotify = Spotify::new("client-id", Some("secret".to_string()), "https://example.com/cb");
    /// let state = generate_state();
    /// let verifier = generate_code_verifier();
    ///
    /// // With PKCE
    /// let url = spotify.authorization_url(&state, &["user-read-email"], Some(&verifier))?;
    ///
    /// // Without PKCE
    /// let url_no_pkce = spotify.authorization_url(&state, &["user-read-email"], None)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn authorization_url(
        &self,
        state: &str,
        scopes: &[&str],
        code_verifier: Option<&str>,
    ) -> Result<url::Url, Error> {
        match code_verifier {
            Some(verifier) => Ok(self.client.create_authorization_url_with_pkce(
                &self.authorization_endpoint,
                state,
                CodeChallengeMethod::S256,
                verifier,
                scopes,
            )),
            None => Ok(self.client.create_authorization_url(
                &self.authorization_endpoint,
                state,
                scopes,
            )),
        }
    }

    /// Exchanges an authorization code for access and refresh tokens.
    ///
    /// Call this in your redirect URI handler after Spotify redirects back with a `code`
    /// query parameter. If PKCE was used, the `code_verifier` must be the same value used
    /// to generate the authorization URL.
    ///
    /// # Arguments
    ///
    /// * `code` - The authorization code from the `code` query parameter.
    /// * `code_verifier` - The PKCE code verifier stored during the authorization step.
    ///   Pass `None` if PKCE was not used.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OAuthRequest`] if Spotify rejects the code, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::Spotify;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let spotify = Spotify::new("client-id", Some("secret".to_string()), "https://example.com/cb");
    ///
    /// let tokens = spotify
    ///     .validate_authorization_code("the-auth-code", Some("the-code-verifier"))
    ///     .await?;
    ///
    /// println!("Access token: {}", tokens.access_token()?);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn validate_authorization_code(
        &self,
        code: &str,
        code_verifier: Option<&str>,
    ) -> Result<OAuth2Tokens, Error> {
        self.client
            .validate_authorization_code(
                self.http_client,
                &self.token_endpoint,
                code,
                code_verifier,
            )
            .await
    }

    /// Refreshes an expired access token using a refresh token.
    ///
    /// Spotify access tokens typically expire after 1 hour. If your initial token response
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
    /// # use arctic_oauth::Spotify;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let spotify = Spotify::new("client-id", Some("secret".to_string()), "https://example.com/cb");
    ///
    /// let new_tokens = spotify
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

    fn make_spotify(http_client: &MockHttpClient) -> Spotify<'_, MockHttpClient> {
        Spotify::from_options(SpotifyOptions {
            client_id: "cid".into(),
            client_secret: Some("secret".into()),
            redirect_uri: "https://app/cb".into(),
            http_client,
        })
    }

    #[test]
    fn new_sets_production_endpoints() {
        let mock = MockHttpClient::new(vec![]);
        let spotify = make_spotify(&mock);
        assert_eq!(spotify.authorization_endpoint, AUTHORIZATION_ENDPOINT);
        assert_eq!(spotify.token_endpoint, TOKEN_ENDPOINT);
    }

    #[test]
    fn name_returns_spotify() {
        let mock = MockHttpClient::new(vec![]);
        let spotify = make_spotify(&mock);
        assert_eq!(spotify.name(), "Spotify");
    }

    #[test]
    fn authorization_url_without_pkce() {
        let mock = MockHttpClient::new(vec![]);
        let spotify = make_spotify(&mock);
        let url = spotify
            .authorization_url(
                "state123",
                &["user-read-email", "playlist-read-private"],
                None,
            )
            .unwrap();

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.contains(&("client_id".into(), "cid".into())));
        assert!(pairs.contains(&("state".into(), "state123".into())));
        assert!(pairs.contains(&(
            "scope".into(),
            "user-read-email playlist-read-private".into()
        )));
        assert!(pairs.contains(&("redirect_uri".into(), "https://app/cb".into())));
        assert!(!pairs.iter().any(|(k, _)| k == "code_challenge"));
    }

    #[test]
    fn authorization_url_with_pkce() {
        let mock = MockHttpClient::new(vec![]);
        let spotify = make_spotify(&mock);
        let url = spotify
            .authorization_url("state123", &["user-read-email"], Some("my-verifier"))
            .unwrap();

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.iter().any(|(k, _)| k == "code_challenge"));
        assert!(pairs.contains(&("code_challenge_method".into(), "S256".into())));
    }

    #[tokio::test]
    async fn validate_authorization_code_delegates_to_client() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "spotify-tok",
                "token_type": "Bearer",
                "expires_in": 3600
            }))
            .unwrap(),
        }]);
        let spotify = make_spotify(&mock);

        let tokens = spotify
            .validate_authorization_code("auth-code", Some("verifier"))
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "spotify-tok");

        let requests = mock.take_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url, TOKEN_ENDPOINT);

        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("grant_type".into(), "authorization_code".into())));
        assert!(body.contains(&("code".into(), "auth-code".into())));
        assert!(body.contains(&("code_verifier".into(), "verifier".into())));
    }

    #[tokio::test]
    async fn validate_authorization_code_public_client_sends_client_id_in_body() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "spotify-tok",
                "token_type": "Bearer",
                "expires_in": 3600
            }))
            .unwrap(),
        }]);
        let spotify = Spotify::from_options(SpotifyOptions {
            client_id: "cid".into(),
            client_secret: None,
            redirect_uri: "https://app/cb".into(),
            http_client: &mock,
        });

        spotify
            .validate_authorization_code("auth-code", Some("verifier"))
            .await
            .unwrap();

        let requests = mock.take_requests();
        assert!(get_header(&requests[0], "Authorization").is_none());
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("client_id".into(), "cid".into())));
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
        let spotify = make_spotify(&mock);

        let tokens = spotify.refresh_access_token("refresh-tok").await.unwrap();

        assert_eq!(tokens.access_token().unwrap(), "new-tok");

        let requests = mock.take_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url, TOKEN_ENDPOINT);

        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("grant_type".into(), "refresh_token".into())));
        assert!(body.contains(&("refresh_token".into(), "refresh-tok".into())));
    }
}
