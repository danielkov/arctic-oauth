use crate::client::OAuth2Client;
use crate::error::Error;
use crate::http::HttpClient;
use crate::pkce::CodeChallengeMethod;
use crate::tokens::OAuth2Tokens;

/// Configuration for creating an [`Authentik`] client with a custom HTTP client.
///
/// Use this when you need to provide your own [`HttpClient`] implementation
/// (e.g. a pre-configured `reqwest::Client` with custom timeouts or proxies).
/// For the common case, use [`Authentik::new`] which uses the built-in default client.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{Authentik, AuthentikOptions, HttpClient};
///
/// let custom_client = reqwest::Client::builder()
///     .timeout(std::time::Duration::from_secs(10))
///     .build()
///     .unwrap();
///
/// let authentik = Authentik::from_options(AuthentikOptions {
///     base_url: "https://auth.example.com".into(),
///     client_id: "your-client-id".into(),
///     client_secret: Some("your-client-secret".into()),
///     redirect_uri: "https://example.com/callback".into(),
///     http_client: &custom_client,
/// });
/// ```
pub struct AuthentikOptions<'a, H: HttpClient> {
    pub base_url: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_uri: String,
    pub http_client: &'a H,
}

/// OAuth 2.0 client for [Authentik](https://docs.goauthentik.io/add-secure-apps/providers/oauth2/).
///
/// Authentik requires PKCE with the S256 challenge method on all authorization requests.
/// This client supports the authorization code flow including token refresh and revocation.
/// The client secret is optional for public clients.
///
/// # Setup
///
/// 1. Create an OAuth2/OpenID Provider in your Authentik instance.
/// 2. Obtain the **Client ID** and optionally the **Client Secret** (required for confidential clients).
/// 3. Set the **Redirect URIs** to match the `redirect_uri` you pass to [`Authentik::new`].
///
/// # Scopes
///
/// Authentik uses space-separated scopes. Common scopes include:
///
/// | Scope | Description |
/// |-------|-------------|
/// | `openid` | OpenID Connect authentication |
/// | `email` | User's email address |
/// | `profile` | User's profile information |
///
/// See your Authentik instance's provider configuration for available scopes.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{Authentik, generate_state, generate_code_verifier};
///
/// # async fn example() -> Result<(), arctic_oauth::Error> {
/// let authentik = Authentik::new(
///     "https://auth.example.com",
///     "your-client-id",
///     Some("your-client-secret".to_string()),
///     "https://example.com/callback",
/// );
///
/// // Step 1: Generate PKCE verifier and CSRF state, then redirect the user.
/// let state = generate_state();
/// let code_verifier = generate_code_verifier();
/// let url = authentik.authorization_url(&state, &["openid", "email"], &code_verifier);
///
/// // Step 2: Exchange the authorization code for tokens.
/// let tokens = authentik
///     .validate_authorization_code("authorization-code", &code_verifier)
///     .await?;
/// println!("Access token: {}", tokens.access_token()?);
///
/// // Step 3 (optional): Refresh an expired access token.
/// let refreshed = authentik
///     .refresh_access_token(tokens.refresh_token()?)
///     .await?;
///
/// // Step 4 (optional): Revoke a token.
/// authentik.revoke_token(tokens.access_token()?).await?;
/// # Ok(())
/// # }
/// ```
pub struct Authentik<'a, H: HttpClient> {
    client: OAuth2Client,
    http_client: &'a H,
    authorization_endpoint: String,
    token_endpoint: String,
    revocation_endpoint: String,
}

impl<'a, H: HttpClient> Authentik<'a, H> {
    /// Creates an Authentik client from an [`AuthentikOptions`] struct.
    ///
    /// Use this when you need a custom HTTP client. For the common case,
    /// use [`Authentik::new`] instead.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{Authentik, AuthentikOptions};
    ///
    /// let custom_client = reqwest::Client::new();
    /// let authentik = Authentik::from_options(AuthentikOptions {
    ///     base_url: "https://auth.example.com".into(),
    ///     client_id: "your-client-id".into(),
    ///     client_secret: Some("your-client-secret".into()),
    ///     redirect_uri: "https://example.com/callback".into(),
    ///     http_client: &custom_client,
    /// });
    /// ```
    pub fn from_options(options: AuthentikOptions<'a, H>) -> Self {
        let base = options.base_url;
        Self {
            http_client: options.http_client,
            client: OAuth2Client::new(
                options.client_id,
                options.client_secret,
                Some(options.redirect_uri),
            ),
            authorization_endpoint: format!("{base}/application/o/authorize/"),
            token_endpoint: format!("{base}/application/o/token/"),
            revocation_endpoint: format!("{base}/application/o/revoke/"),
        }
    }
}

#[cfg(feature = "reqwest-client")]
impl Authentik<'static, reqwest::Client> {
    /// Creates a new Authentik OAuth 2.0 client configured for a specific instance.
    ///
    /// Uses the built-in `reqwest::Client` for HTTP requests. To provide a custom
    /// HTTP client, use [`Authentik::from_options`] instead.
    ///
    /// # Arguments
    ///
    /// * `base_url` - The base URL of your Authentik instance (e.g. `"https://auth.example.com"`).
    /// * `client_id` - The OAuth 2.0 client ID from your Authentik provider configuration.
    /// * `client_secret` - The OAuth 2.0 client secret (optional for public clients, required for confidential clients).
    /// * `redirect_uri` - The URI Authentik will redirect to after authorization. Must match
    ///   one of the redirect URIs configured in your provider.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::Authentik;
    ///
    /// // Confidential client (with secret)
    /// let authentik = Authentik::new(
    ///     "https://auth.example.com",
    ///     "your-client-id",
    ///     Some("your-client-secret".to_string()),
    ///     "https://example.com/callback",
    /// );
    ///
    /// // Public client (without secret)
    /// let authentik_public = Authentik::new(
    ///     "https://auth.example.com",
    ///     "your-client-id",
    ///     None,
    ///     "https://example.com/callback",
    /// );
    /// ```
    pub fn new(
        base_url: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: Option<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        Self::from_options(AuthentikOptions {
            base_url: base_url.into(),
            client_id: client_id.into(),
            client_secret,
            redirect_uri: redirect_uri.into(),
            http_client: crate::http::default_client(),
        })
    }
}

impl<'a, H: HttpClient> Authentik<'a, H> {
    /// Returns the provider name (`"Authentik"`).
    pub fn name(&self) -> &'static str {
        "Authentik"
    }

    /// Builds the Authentik authorization URL that the user should be redirected to.
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
    /// use arctic_oauth::{Authentik, generate_state, generate_code_verifier};
    ///
    /// let authentik = Authentik::new("https://auth.example.com", "client-id", None, "https://example.com/cb");
    /// let state = generate_state();
    /// let verifier = generate_code_verifier();
    ///
    /// let url = authentik.authorization_url(&state, &["openid", "profile"], &verifier);
    /// assert!(url.as_str().starts_with("https://auth.example.com/"));
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
    /// Call this in your redirect URI handler after Authentik redirects back with a `code`
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
    /// Returns [`Error::OAuthRequest`] if Authentik rejects the code, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::Authentik;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let authentik = Authentik::new("https://auth.example.com", "client-id", None, "https://example.com/cb");
    ///
    /// let tokens = authentik
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
    /// Authentik access tokens have configurable expiration times. If your initial token
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
    /// # use arctic_oauth::Authentik;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let authentik = Authentik::new("https://auth.example.com", "client-id", None, "https://example.com/cb");
    ///
    /// let new_tokens = authentik
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
    /// Use this when a user signs out or disconnects your application.
    ///
    /// # Arguments
    ///
    /// * `token` - The access token or refresh token to revoke.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedResponse`] if Authentik returns a non-200 status, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::Authentik;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let authentik = Authentik::new("https://auth.example.com", "client-id", None, "https://example.com/cb");
    ///
    /// authentik.revoke_token("token-to-revoke").await?;
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

    fn make_authentik(http_client: &MockHttpClient) -> Authentik<'_, MockHttpClient> {
        Authentik::from_options(AuthentikOptions {
            base_url: "https://auth.example.com".into(),
            client_id: "cid".into(),
            client_secret: Some("secret".into()),
            redirect_uri: "https://app/cb".into(),
            http_client,
        })
    }

    #[test]
    fn new_builds_endpoints_with_trailing_slashes() {
        let mock = MockHttpClient::new(vec![]);
        let authentik = make_authentik(&mock);
        assert_eq!(
            authentik.authorization_endpoint,
            "https://auth.example.com/application/o/authorize/"
        );
        assert_eq!(
            authentik.token_endpoint,
            "https://auth.example.com/application/o/token/"
        );
        assert_eq!(
            authentik.revocation_endpoint,
            "https://auth.example.com/application/o/revoke/"
        );
    }

    #[test]
    fn name_returns_authentik() {
        let mock = MockHttpClient::new(vec![]);
        let authentik = Authentik::from_options(AuthentikOptions {
            base_url: "https://auth.example.com".into(),
            client_id: "cid".into(),
            client_secret: None,
            redirect_uri: "https://app/cb".into(),
            http_client: &mock,
        });
        assert_eq!(authentik.name(), "Authentik");
    }

    #[test]
    fn authorization_url_includes_pkce() {
        let mock = MockHttpClient::new(vec![]);
        let authentik = Authentik::from_options(AuthentikOptions {
            base_url: "https://auth.example.com".into(),
            client_id: "cid".into(),
            client_secret: None,
            redirect_uri: "https://app/cb".into(),
            http_client: &mock,
        });
        let url = authentik.authorization_url("state123", &["openid"], "my-verifier");

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
                "access_token": "auth-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);
        let authentik = make_authentik(&mock);

        let tokens = authentik
            .validate_authorization_code("code", "verifier")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "auth-tok");

        let requests = mock.take_requests();
        assert_eq!(
            requests[0].url,
            "https://auth.example.com/application/o/token/"
        );
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("code_verifier".into(), "verifier".into())));
    }

    #[tokio::test]
    async fn revoke_token_delegates_to_client() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: vec![],
        }]);
        let authentik = make_authentik(&mock);

        let result = authentik.revoke_token("tok").await;
        assert!(result.is_ok());

        let requests = mock.take_requests();
        assert_eq!(
            requests[0].url,
            "https://auth.example.com/application/o/revoke/"
        );
    }
}
