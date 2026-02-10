use crate::client::OAuth2Client;
use crate::error::Error;
use crate::http::HttpClient;
use crate::pkce::CodeChallengeMethod;
use crate::tokens::OAuth2Tokens;

const AUTHORIZATION_ENDPOINT: &str =
    "https://developer.api.autodesk.com/authentication/v2/authorize";
const TOKEN_ENDPOINT: &str = "https://developer.api.autodesk.com/authentication/v2/token";
const REVOCATION_ENDPOINT: &str = "https://developer.api.autodesk.com/authentication/v2/revoke";

/// Configuration for creating an [`Autodesk`] client with a custom HTTP client.
///
/// Use this when you need to provide your own [`HttpClient`] implementation
/// (e.g. a pre-configured `reqwest::Client` with custom timeouts or proxies).
/// For the common case, use [`Autodesk::new`] which uses the built-in default client.
pub struct AutodeskOptions<'a, H: HttpClient> {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_uri: String,
    pub http_client: &'a H,
}

/// OAuth 2.0 client for [Autodesk Platform Services](https://aps.autodesk.com/en/docs/oauth/v2/developers_guide/overview/).
///
/// Autodesk requires PKCE with the S256 challenge method on all authorization requests.
/// This client supports both public clients (without client secret) and confidential
/// clients (with client secret), as well as the full authorization code flow including
/// token refresh and revocation.
///
/// # Setup
///
/// 1. Create an application in the [Autodesk Platform Services Console](https://aps.autodesk.com/myapps).
/// 2. Obtain your client ID and optionally client secret from the application settings.
/// 3. Set the callback URL to match the `redirect_uri` you pass to [`Autodesk::new`].
///
/// # Scopes
///
/// Autodesk uses space-separated scopes. Common scopes include:
///
/// | Scope | Description |
/// |-------|-------------|
/// | `data:read` | Read user data and files |
/// | `data:write` | Create and modify files |
/// | `bucket:read` | Read bucket contents |
/// | `account:read` | Read account information |
///
/// See the full list at <https://aps.autodesk.com/en/docs/oauth/v2/developers_guide/scopes/>.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{Autodesk, generate_state, generate_code_verifier};
///
/// # async fn example() -> Result<(), arctic_oauth::Error> {
/// let autodesk = Autodesk::new(
///     "your-client-id",
///     Some("your-client-secret".into()),  // Pass None for public clients
///     "https://example.com/callback",
/// );
///
/// // Step 1: Generate PKCE verifier and CSRF state, then redirect the user.
/// let state = generate_state();
/// let code_verifier = generate_code_verifier();
/// let url = autodesk.authorization_url(&state, &["data:read", "data:write"], &code_verifier);
/// // Store `state` and `code_verifier` in the user's session, then redirect to `url`.
///
/// // Step 2: In your callback handler, exchange the authorization code for tokens.
/// let tokens = autodesk
///     .validate_authorization_code("authorization-code", &code_verifier)
///     .await?;
/// println!("Access token: {}", tokens.access_token()?);
///
/// // Step 3 (optional): Refresh an expired access token.
/// let refreshed = autodesk
///     .refresh_access_token(tokens.refresh_token()?)
///     .await?;
///
/// // Step 4 (optional): Revoke a token.
/// autodesk.revoke_token(tokens.access_token()?).await?;
/// # Ok(())
/// # }
/// ```
pub struct Autodesk<'a, H: HttpClient> {
    client: OAuth2Client,
    http_client: &'a H,
    authorization_endpoint: String,
    token_endpoint: String,
    revocation_endpoint: String,
}

impl<'a, H: HttpClient> Autodesk<'a, H> {
    /// Creates an Autodesk client from an [`AutodeskOptions`] struct.
    ///
    /// Use this when you need a custom HTTP client. For the common case,
    /// use [`Autodesk::new`] instead.
    pub fn from_options(options: AutodeskOptions<'a, H>) -> Self {
        Self {
            client: OAuth2Client::new(
                options.client_id,
                options.client_secret,
                Some(options.redirect_uri),
            ),
            http_client: options.http_client,
            authorization_endpoint: AUTHORIZATION_ENDPOINT.to_string(),
            token_endpoint: TOKEN_ENDPOINT.to_string(),
            revocation_endpoint: REVOCATION_ENDPOINT.to_string(),
        }
    }
}

#[cfg(feature = "reqwest-client")]
impl Autodesk<'static, reqwest::Client> {
    /// Creates a new Autodesk OAuth 2.0 client configured with production endpoints.
    ///
    /// Uses the built-in `reqwest::Client` for HTTP requests. To provide a custom
    /// HTTP client, use [`Autodesk::from_options`] instead.
    ///
    /// # Arguments
    ///
    /// * `client_id` - The OAuth 2.0 client ID from the Autodesk Platform Services Console.
    /// * `client_secret` - The OAuth 2.0 client secret (pass `Some("secret")` for confidential
    ///   clients or `None` for public clients).
    /// * `redirect_uri` - The URI Autodesk will redirect to after authorization. Must match
    ///   the callback URL configured in your application settings.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::Autodesk;
    ///
    /// // Confidential client with secret
    /// let autodesk = Autodesk::new(
    ///     "your-client-id",
    ///     Some("your-client-secret".into()),
    ///     "https://example.com/callback",
    /// );
    ///
    /// // Public client without secret
    /// let autodesk_public = Autodesk::new(
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
        Self::from_options(AutodeskOptions {
            client_id: client_id.into(),
            client_secret,
            redirect_uri: redirect_uri.into(),
            http_client: crate::http::default_client(),
        })
    }
}

impl<'a, H: HttpClient> Autodesk<'a, H> {
    /// Returns the provider name (`"Autodesk"`).
    pub fn name(&self) -> &'static str {
        "Autodesk"
    }

    /// Builds the Autodesk authorization URL that the user should be redirected to.
    ///
    /// The returned URL includes all required OAuth 2.0 and PKCE parameters. Your
    /// application should store `state` and `code_verifier` in the user's session
    /// before redirecting, as both are needed to complete the flow.
    ///
    /// # Arguments
    ///
    /// * `state` - A CSRF token to prevent cross-site request forgery. Use
    ///   [`generate_state`](crate::generate_state) to create one.
    /// * `scopes` - The OAuth 2.0 scopes to request (e.g. `&["data:read", "data:write"]`).
    /// * `code_verifier` - The PKCE code verifier. Use
    ///   [`generate_code_verifier`](crate::generate_code_verifier) to create one.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{Autodesk, generate_state, generate_code_verifier};
    ///
    /// let autodesk = Autodesk::new("client-id", None, "https://example.com/cb");
    /// let state = generate_state();
    /// let verifier = generate_code_verifier();
    ///
    /// let url = autodesk.authorization_url(&state, &["data:read"], &verifier);
    /// assert!(url.as_str().starts_with("https://developer.api.autodesk.com/"));
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
    /// Call this in your redirect URI handler after Autodesk redirects back with a `code`
    /// query parameter. The `code_verifier` must be the same value used to generate the
    /// authorization URL.
    ///
    /// # Arguments
    ///
    /// * `code` - The authorization code from the `code` query parameter.
    /// * `code_verifier` - The PKCE code verifier stored during the authorization step.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OAuthRequest`] if Autodesk rejects the code, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::Autodesk;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let autodesk = Autodesk::new("client-id", None, "https://example.com/cb");
    ///
    /// let tokens = autodesk
    ///     .validate_authorization_code("the-auth-code", "the-code-verifier")
    ///     .await?;
    ///
    /// println!("Access token: {}", tokens.access_token()?);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn validate_authorization_code(
        &self,
        code: &str,
        code_verifier: &str,
    ) -> Result<OAuth2Tokens, Error> {
        self.client
            .validate_authorization_code(
                self.http_client,
                &self.token_endpoint,
                code,
                Some(code_verifier),
            )
            .await
    }

    /// Refreshes an expired access token using a refresh token.
    ///
    /// Autodesk access tokens typically expire after 1 hour. If your initial token
    /// response included a refresh token, you can use it to obtain a new access token
    /// without user interaction.
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
    /// # use arctic_oauth::Autodesk;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let autodesk = Autodesk::new("client-id", None, "https://example.com/cb");
    ///
    /// let new_tokens = autodesk
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

    /// Revokes an access token or refresh token.
    ///
    /// Use this when a user signs out or disconnects your application. Revoking a
    /// token immediately invalidates it with Autodesk.
    ///
    /// # Arguments
    ///
    /// * `token` - The access token or refresh token to revoke.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedResponse`] if Autodesk returns a non-200 status, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::Autodesk;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let autodesk = Autodesk::new("client-id", None, "https://example.com/cb");
    ///
    /// autodesk.revoke_token("token-to-revoke").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn revoke_token(&self, token: &str) -> Result<(), Error> {
        self.client
            .revoke_token(self.http_client, &self.revocation_endpoint, token)
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

    fn make_autodesk(http_client: &MockHttpClient) -> Autodesk<'_, MockHttpClient> {
        Autodesk::from_options(AutodeskOptions {
            client_id: "cid".into(),
            client_secret: Some("secret".into()),
            redirect_uri: "https://app/cb".into(),
            http_client,
        })
    }

    #[test]
    fn new_sets_production_endpoints() {
        let mock = MockHttpClient::new(vec![]);
        let autodesk = make_autodesk(&mock);
        assert_eq!(autodesk.authorization_endpoint, AUTHORIZATION_ENDPOINT);
        assert_eq!(autodesk.token_endpoint, TOKEN_ENDPOINT);
        assert_eq!(autodesk.revocation_endpoint, REVOCATION_ENDPOINT);
    }

    #[test]
    fn name_returns_autodesk() {
        let mock = MockHttpClient::new(vec![]);
        let autodesk = make_autodesk(&mock);
        assert_eq!(autodesk.name(), "Autodesk");
    }

    #[test]
    fn authorization_url_includes_pkce() {
        let mock = MockHttpClient::new(vec![]);
        let autodesk = make_autodesk(&mock);
        let url = autodesk.authorization_url("state123", &["data:read"], "my-verifier");

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.iter().any(|(k, _)| k == "code_challenge"));
        assert!(pairs.contains(&("code_challenge_method".into(), "S256".into())));
    }

    #[tokio::test]
    async fn validate_authorization_code_sends_verifier() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "autodesk-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);
        let autodesk = make_autodesk(&mock);

        let tokens = autodesk
            .validate_authorization_code("code", "verifier")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "autodesk-tok");

        let requests = mock.take_requests();
        assert_eq!(requests[0].url, TOKEN_ENDPOINT);
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("code_verifier".into(), "verifier".into())));
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
        let autodesk = make_autodesk(&mock);

        let tokens = autodesk.refresh_access_token("rt").await.unwrap();
        assert_eq!(tokens.access_token().unwrap(), "new-tok");
    }

    #[tokio::test]
    async fn revoke_token_delegates_to_client() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: vec![],
        }]);
        let autodesk = make_autodesk(&mock);

        let result = autodesk.revoke_token("tok").await;
        assert!(result.is_ok());

        let requests = mock.take_requests();
        assert_eq!(requests[0].url, REVOCATION_ENDPOINT);
    }
}
