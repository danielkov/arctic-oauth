use crate::client::OAuth2Client;
use crate::error::Error;
use crate::http::HttpClient;
use crate::pkce::CodeChallengeMethod;
use crate::request::create_oauth2_request;
use crate::tokens::OAuth2Tokens;

const AUTHORIZATION_ENDPOINT: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_ENDPOINT: &str = "https://oauth2.googleapis.com/token";
const REVOCATION_ENDPOINT: &str = "https://oauth2.googleapis.com/revoke";

/// OAuth 2.0 client for [Google](https://developers.google.com/identity/protocols/oauth2).
///
/// Google requires PKCE with the S256 challenge method on all authorization requests.
/// This client supports the full authorization code flow including token refresh and
/// revocation.
///
/// # Setup
///
/// 1. Create a project in the [Google Cloud Console](https://console.cloud.google.com/).
/// 2. Navigate to **APIs & Services > Credentials** and create an **OAuth 2.0 Client ID**.
/// 3. Set the authorized redirect URI to match the `redirect_uri` you pass to [`Google::new`].
///
/// # Scopes
///
/// Google uses space-separated scopes. Common scopes include:
///
/// | Scope | Description |
/// |-------|-------------|
/// | `openid` | OpenID Connect authentication |
/// | `email` | User's email address |
/// | `profile` | User's basic profile info |
///
/// See the full list at <https://developers.google.com/identity/protocols/oauth2/scopes>.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{Google, ReqwestClient, generate_state, generate_code_verifier};
///
/// # async fn example() -> Result<(), arctic_oauth::Error> {
/// let google = Google::new(
///     "your-client-id",
///     "your-client-secret",
///     "https://example.com/callback",
/// );
///
/// // Step 1: Generate PKCE verifier and CSRF state, then redirect the user.
/// let state = generate_state();
/// let code_verifier = generate_code_verifier();
/// let url = google.authorization_url(&state, &["openid", "email"], &code_verifier);
/// // Store `state` and `code_verifier` in the user's session, then redirect to `url`.
///
/// // Step 2: In your callback handler, exchange the authorization code for tokens.
/// let http = ReqwestClient::new();
/// let tokens = google
///     .validate_authorization_code(&http, "authorization-code", &code_verifier)
///     .await?;
/// println!("Access token: {}", tokens.access_token()?);
///
/// // Step 3 (optional): Refresh an expired access token.
/// let refreshed = google
///     .refresh_access_token(&http, tokens.refresh_token()?)
///     .await?;
///
/// // Step 4 (optional): Revoke a token.
/// google.revoke_token(&http, tokens.access_token()?).await?;
/// # Ok(())
/// # }
/// ```
pub struct Google {
    client: OAuth2Client,
    authorization_endpoint: String,
    token_endpoint: String,
    revocation_endpoint: String,
}

impl Google {
    /// Creates a new Google OAuth 2.0 client configured with production endpoints.
    ///
    /// # Arguments
    ///
    /// * `client_id` - The OAuth 2.0 client ID from Google Cloud Console.
    /// * `client_secret` - The OAuth 2.0 client secret from Google Cloud Console.
    /// * `redirect_uri` - The URI Google will redirect to after authorization. Must match
    ///   one of the authorized redirect URIs configured in your Google Cloud project.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::Google;
    ///
    /// let google = Google::new(
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
            revocation_endpoint: REVOCATION_ENDPOINT.to_string(),
        }
    }
}

#[cfg(any(test, feature = "testing"))]
impl Google {
    /// Creates a Google client with custom endpoint URLs.
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
    /// use arctic_oauth::Google;
    ///
    /// let google = Google::with_endpoints(
    ///     "test-client-id",
    ///     "test-secret",
    ///     "http://localhost/callback",
    ///     "http://localhost:8080/authorize",
    ///     "http://localhost:8080/token",
    ///     Some("http://localhost:8080/revoke"),
    /// );
    /// # }
    /// ```
    pub fn with_endpoints(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
        authorization_endpoint: &str,
        token_endpoint: &str,
        revocation_endpoint: Option<&str>,
    ) -> Self {
        Self {
            client: OAuth2Client::new(
                client_id,
                Some(client_secret.into()),
                Some(redirect_uri.into()),
            ),
            authorization_endpoint: authorization_endpoint.to_string(),
            token_endpoint: token_endpoint.to_string(),
            revocation_endpoint: revocation_endpoint
                .unwrap_or(REVOCATION_ENDPOINT)
                .to_string(),
        }
    }
}

impl Google {
    /// Returns the provider name (`"Google"`).
    pub fn name(&self) -> &'static str {
        "Google"
    }

    /// Builds the Google authorization URL that the user should be redirected to.
    ///
    /// The returned URL includes all required OAuth 2.0 and PKCE parameters. Your
    /// application should store `state` and `code_verifier` in the user's session
    /// before redirecting, as both are needed to complete the flow.
    ///
    /// # Arguments
    ///
    /// * `state` - A CSRF token to prevent cross-site request forgery. Use
    ///   [`generate_state`](crate::generate_state) to create one.
    /// * `scopes` - The OAuth 2.0 scopes to request (e.g. `&["openid", "email"]`).
    /// * `code_verifier` - The PKCE code verifier. Use
    ///   [`generate_code_verifier`](crate::generate_code_verifier) to create one.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{Google, generate_state, generate_code_verifier};
    ///
    /// let google = Google::new("client-id", "client-secret", "https://example.com/cb");
    /// let state = generate_state();
    /// let verifier = generate_code_verifier();
    ///
    /// let url = google.authorization_url(&state, &["openid", "email"], &verifier);
    /// assert!(url.as_str().starts_with("https://accounts.google.com/"));
    /// ```
    pub fn authorization_url(&self, state: &str, scopes: &[&str], code_verifier: &str) -> url::Url {
        self.client.create_authorization_url_with_pkce(
            &self.authorization_endpoint,
            state,
            CodeChallengeMethod::S256,
            code_verifier,
            scopes,
        )
    }

    /// Exchanges an authorization code for access and refresh tokens.
    ///
    /// Call this in your redirect URI handler after Google redirects back with a `code`
    /// query parameter. The `code_verifier` must be the same value used to generate the
    /// authorization URL.
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
    /// Returns [`Error::OAuthRequest`] if Google rejects the code, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::{Google, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let google = Google::new("client-id", "secret", "https://example.com/cb");
    /// let http = ReqwestClient::new();
    ///
    /// let tokens = google
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
    /// Google access tokens typically expire after 1 hour. If your initial token response
    /// included a refresh token (requires `access_type=offline` in the authorization
    /// request), you can use it to obtain a new access token without user interaction.
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
    /// # use arctic_oauth::{Google, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let google = Google::new("client-id", "secret", "https://example.com/cb");
    /// let http = ReqwestClient::new();
    ///
    /// let new_tokens = google
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

    /// Revokes an access token or refresh token.
    ///
    /// Revoking an access token also revokes the associated refresh token, and vice versa.
    /// Use this when a user signs out or disconnects your application.
    ///
    /// Google-specific: the token is sent in the POST form body (not via Basic auth).
    ///
    /// # Arguments
    ///
    /// * `http_client` - An [`HttpClient`](crate::HttpClient) implementation.
    /// * `token` - The access token or refresh token to revoke.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedResponse`] if Google returns a non-200 status, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::{Google, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let google = Google::new("client-id", "secret", "https://example.com/cb");
    /// let http = ReqwestClient::new();
    ///
    /// google.revoke_token(&http, "token-to-revoke").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn revoke_token(
        &self,
        http_client: &(impl HttpClient + ?Sized),
        token: &str,
    ) -> Result<(), Error> {
        let body = vec![("token".to_string(), token.to_string())];
        let request = create_oauth2_request(&self.revocation_endpoint, &body);

        let response = http_client.send(request).await?;

        match response.status {
            200 => Ok(()),
            status => Err(Error::UnexpectedResponse { status }),
        }
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
        let google = Google::new("cid", "secret", "https://app/cb");
        assert_eq!(google.authorization_endpoint, AUTHORIZATION_ENDPOINT);
        assert_eq!(google.token_endpoint, TOKEN_ENDPOINT);
        assert_eq!(google.revocation_endpoint, REVOCATION_ENDPOINT);
    }

    #[test]
    fn with_endpoints_overrides_urls() {
        let google = Google::with_endpoints(
            "cid",
            "secret",
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
            Some("https://mock/revoke"),
        );
        assert_eq!(google.authorization_endpoint, "https://mock/authorize");
        assert_eq!(google.token_endpoint, "https://mock/token");
        assert_eq!(google.revocation_endpoint, "https://mock/revoke");
    }

    #[test]
    fn with_endpoints_defaults_revocation() {
        let google = Google::with_endpoints(
            "cid",
            "secret",
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
            None,
        );
        assert_eq!(google.revocation_endpoint, REVOCATION_ENDPOINT);
    }

    #[test]
    fn name_returns_google() {
        let google = Google::new("cid", "secret", "https://app/cb");
        assert_eq!(google.name(), "Google");
    }

    #[test]
    fn authorization_url_includes_pkce_params() {
        let google = Google::new("cid", "secret", "https://app/cb");
        let url = google.authorization_url("state123", &["openid", "email"], "my-verifier");

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.contains(&("client_id".into(), "cid".into())));
        assert!(pairs.contains(&("state".into(), "state123".into())));
        assert!(pairs.contains(&("scope".into(), "openid email".into())));
        assert!(pairs.contains(&("redirect_uri".into(), "https://app/cb".into())));
        assert!(pairs.iter().any(|(k, _)| k == "code_challenge"));
        assert!(pairs.contains(&("code_challenge_method".into(), "S256".into())));
    }

    #[tokio::test]
    async fn validate_authorization_code_delegates_to_client() {
        let google = Google::with_endpoints(
            "cid",
            "secret",
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
            None,
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "google-tok",
                "token_type": "Bearer",
                "expires_in": 3600
            }))
            .unwrap(),
        }]);

        let tokens = google
            .validate_authorization_code(&mock, "auth-code", "verifier")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "google-tok");

        let requests = mock.take_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url, "https://mock/token");

        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("grant_type".into(), "authorization_code".into())));
        assert!(body.contains(&("code".into(), "auth-code".into())));
        assert!(body.contains(&("code_verifier".into(), "verifier".into())));
    }

    #[tokio::test]
    async fn refresh_access_token_delegates_to_client() {
        let google = Google::with_endpoints(
            "cid",
            "secret",
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
            None,
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "new-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);

        let tokens = google
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

    #[tokio::test]
    async fn revoke_token_sends_post_with_form_body() {
        let google = Google::with_endpoints(
            "cid",
            "secret",
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
            Some("https://mock/revoke"),
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: vec![],
        }]);

        let result = google.revoke_token(&mock, "tok-to-revoke").await;
        assert!(result.is_ok());

        let requests = mock.take_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url, "https://mock/revoke");

        // Google-specific: token sent in POST form body, not Basic auth
        assert!(get_header(&requests[0], "Authorization").is_none());

        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("token".into(), "tok-to-revoke".into())));
    }

    #[tokio::test]
    async fn revoke_token_non_200_returns_error() {
        let google = Google::with_endpoints(
            "cid",
            "secret",
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
            Some("https://mock/revoke"),
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 503,
            body: vec![],
        }]);

        let result = google.revoke_token(&mock, "tok").await;
        assert!(matches!(
            result,
            Err(Error::UnexpectedResponse { status: 503 })
        ));
    }
}
