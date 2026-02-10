use crate::client::OAuth2Client;
use crate::error::Error;
use crate::http::HttpClient;
use crate::pkce::CodeChallengeMethod;
use crate::tokens::OAuth2Tokens;

const AUTHORIZATION_ENDPOINT: &str = "https://accounts.spotify.com/authorize";
const TOKEN_ENDPOINT: &str = "https://accounts.spotify.com/api/token";

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
/// use arctic_oauth::{Spotify, ReqwestClient, generate_state, generate_code_verifier};
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
/// let http = ReqwestClient::new();
/// let tokens = spotify
///     .validate_authorization_code(&http, "authorization-code", Some(&code_verifier))
///     .await?;
/// println!("Access token: {}", tokens.access_token()?);
///
/// // Step 3 (optional): Refresh an expired access token.
/// let refreshed = spotify
///     .refresh_access_token(&http, tokens.refresh_token()?)
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct Spotify {
    client: OAuth2Client,
    authorization_endpoint: String,
    token_endpoint: String,
}

impl Spotify {
    /// Creates a new Spotify OAuth 2.0 client configured with production endpoints.
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
        Self {
            client: OAuth2Client::new(client_id, client_secret, Some(redirect_uri.into())),
            authorization_endpoint: AUTHORIZATION_ENDPOINT.to_string(),
            token_endpoint: TOKEN_ENDPOINT.to_string(),
        }
    }
}

#[cfg(any(test, feature = "testing"))]
impl Spotify {
    /// Creates a Spotify client with custom endpoint URLs.
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
    /// use arctic_oauth::Spotify;
    ///
    /// let spotify = Spotify::with_endpoints(
    ///     "test-client-id",
    ///     Some("test-secret".to_string()),
    ///     "http://localhost/callback",
    ///     "http://localhost:8080/authorize",
    ///     "http://localhost:8080/token",
    /// );
    /// # }
    /// ```
    pub fn with_endpoints(
        client_id: impl Into<String>,
        client_secret: Option<String>,
        redirect_uri: impl Into<String>,
        authorization_endpoint: &str,
        token_endpoint: &str,
    ) -> Self {
        Self {
            client: OAuth2Client::new(client_id, client_secret, Some(redirect_uri.into())),
            authorization_endpoint: authorization_endpoint.to_string(),
            token_endpoint: token_endpoint.to_string(),
        }
    }
}

impl Spotify {
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
    /// * `http_client` - An [`HttpClient`](crate::HttpClient) implementation (e.g.
    ///   [`ReqwestClient`](crate::ReqwestClient)).
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
    /// # use arctic_oauth::{Spotify, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let spotify = Spotify::new("client-id", Some("secret".to_string()), "https://example.com/cb");
    /// let http = ReqwestClient::new();
    ///
    /// let tokens = spotify
    ///     .validate_authorization_code(&http, "the-auth-code", Some("the-code-verifier"))
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
        code_verifier: Option<&str>,
    ) -> Result<OAuth2Tokens, Error> {
        self.client
            .validate_authorization_code(http_client, &self.token_endpoint, code, code_verifier)
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
    /// # use arctic_oauth::{Spotify, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let spotify = Spotify::new("client-id", Some("secret".to_string()), "https://example.com/cb");
    /// let http = ReqwestClient::new();
    ///
    /// let new_tokens = spotify
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
        let spotify = Spotify::new("cid", Some("secret".into()), "https://app/cb");
        assert_eq!(spotify.authorization_endpoint, AUTHORIZATION_ENDPOINT);
        assert_eq!(spotify.token_endpoint, TOKEN_ENDPOINT);
    }

    #[test]
    fn with_endpoints_overrides_urls() {
        let spotify = Spotify::with_endpoints(
            "cid",
            Some("secret".into()),
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
        );
        assert_eq!(spotify.authorization_endpoint, "https://mock/authorize");
        assert_eq!(spotify.token_endpoint, "https://mock/token");
    }

    #[test]
    fn name_returns_spotify() {
        let spotify = Spotify::new("cid", Some("secret".into()), "https://app/cb");
        assert_eq!(spotify.name(), "Spotify");
    }

    #[test]
    fn authorization_url_without_pkce() {
        let spotify = Spotify::new("cid", Some("secret".into()), "https://app/cb");
        let url = spotify
            .authorization_url("state123", &["user-read-email", "playlist-read-private"], None)
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
        let spotify = Spotify::new("cid", Some("secret".into()), "https://app/cb");
        let url = spotify
            .authorization_url("state123", &["user-read-email"], Some("my-verifier"))
            .unwrap();

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.iter().any(|(k, _)| k == "code_challenge"));
        assert!(pairs.contains(&("code_challenge_method".into(), "S256".into())));
    }

    #[tokio::test]
    async fn validate_authorization_code_delegates_to_client() {
        let spotify = Spotify::with_endpoints(
            "cid",
            Some("secret".into()),
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "spotify-tok",
                "token_type": "Bearer",
                "expires_in": 3600
            }))
            .unwrap(),
        }]);

        let tokens = spotify
            .validate_authorization_code(&mock, "auth-code", Some("verifier"))
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "spotify-tok");

        let requests = mock.take_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url, "https://mock/token");

        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("grant_type".into(), "authorization_code".into())));
        assert!(body.contains(&("code".into(), "auth-code".into())));
        assert!(body.contains(&("code_verifier".into(), "verifier".into())));
    }

    #[tokio::test]
    async fn validate_authorization_code_public_client_sends_client_id_in_body() {
        let spotify = Spotify::with_endpoints(
            "cid",
            None,
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "spotify-tok",
                "token_type": "Bearer",
                "expires_in": 3600
            }))
            .unwrap(),
        }]);

        spotify
            .validate_authorization_code(&mock, "auth-code", Some("verifier"))
            .await
            .unwrap();

        let requests = mock.take_requests();
        assert!(get_header(&requests[0], "Authorization").is_none());
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("client_id".into(), "cid".into())));
    }

    #[tokio::test]
    async fn refresh_access_token_delegates_to_client() {
        let spotify = Spotify::with_endpoints(
            "cid",
            Some("secret".into()),
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

        let tokens = spotify
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
