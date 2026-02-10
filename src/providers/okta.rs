use crate::client::OAuth2Client;
use crate::error::Error;
use crate::http::HttpClient;
use crate::pkce::CodeChallengeMethod;
use crate::tokens::OAuth2Tokens;

/// Configuration for creating an [`Okta`] client with a custom HTTP client.
///
/// Use this when you need to provide your own [`HttpClient`] implementation
/// (e.g. a pre-configured `reqwest::Client` with custom timeouts or proxies).
/// For the common case, use [`Okta::new`] which uses the built-in default client.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{Okta, OktaOptions, HttpClient};
///
/// let custom_client = reqwest::Client::builder()
///     .timeout(std::time::Duration::from_secs(10))
///     .build()
///     .unwrap();
///
/// let okta = Okta::from_options(OktaOptions {
///     domain: "dev-123456.okta.com".into(),
///     authorization_server_id: Some("default".into()),
///     client_id: "your-client-id".into(),
///     client_secret: "your-client-secret".into(),
///     redirect_uri: "https://example.com/callback".into(),
///     http_client: &custom_client,
/// });
/// ```
pub struct OktaOptions<'a, H: HttpClient> {
    pub domain: String,
    pub authorization_server_id: Option<String>,
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub http_client: &'a H,
}

/// OAuth 2.0 client for [Okta](https://developer.okta.com/docs/reference/api/oidc/).
///
/// Okta requires PKCE with the S256 challenge method on all authorization requests.
/// This client supports the full authorization code flow including token refresh and
/// revocation. Endpoints are dynamically constructed based on your Okta domain and
/// optional authorization server ID.
///
/// # Setup
///
/// 1. Create an application in the [Okta Admin Console](https://developer.okta.com/).
/// 2. Navigate to **Applications > Applications** and create a new **Web** application.
/// 3. Obtain your client ID and client secret from the application settings.
/// 4. Set the sign-in redirect URI to match the `redirect_uri` you pass to [`Okta::new`].
///
/// # Scopes
///
/// Okta uses space-separated scopes. Common scopes include:
///
/// | Scope | Description |
/// |-------|-------------|
/// | `openid` | OpenID Connect authentication |
/// | `profile` | User's profile information |
/// | `email` | User's email address |
/// | `offline_access` | Refresh token access |
///
/// See the full list at <https://developer.okta.com/docs/reference/api/oidc/#scopes>.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{Okta, generate_state, generate_code_verifier};
///
/// # async fn example() -> Result<(), arctic_oauth::Error> {
/// let okta = Okta::new(
///     "dev-123456.okta.com",
///     Some("default".into()),  // Authorization server ID (or None)
///     "your-client-id",
///     "your-client-secret",
///     "https://example.com/callback",
/// );
///
/// // Step 1: Generate PKCE verifier and CSRF state, then redirect the user.
/// let state = generate_state();
/// let code_verifier = generate_code_verifier();
/// let url = okta.authorization_url(&state, &["openid", "profile", "email"], &code_verifier);
/// // Store `state` and `code_verifier` in the user's session, then redirect to `url`.
///
/// // Step 2: In your callback handler, exchange the authorization code for tokens.
/// let tokens = okta
///     .validate_authorization_code("authorization-code", &code_verifier)
///     .await?;
/// println!("Access token: {}", tokens.access_token()?);
///
/// // Step 3 (optional): Refresh an expired access token.
/// let refreshed = okta
///     .refresh_access_token(tokens.refresh_token()?, &[])
///     .await?;
///
/// // Step 4 (optional): Revoke a token.
/// okta.revoke_token(tokens.access_token()?).await?;
/// # Ok(())
/// # }
/// ```
pub struct Okta<'a, H: HttpClient> {
    client: OAuth2Client,
    http_client: &'a H,
    authorization_endpoint: String,
    token_endpoint: String,
    revocation_endpoint: String,
}

impl<'a, H: HttpClient> Okta<'a, H> {
    /// Creates an Okta client from an [`OktaOptions`] struct.
    ///
    /// Use this when you need a custom HTTP client. For the common case,
    /// use [`Okta::new`] instead.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{Okta, OktaOptions};
    ///
    /// let custom_client = reqwest::Client::new();
    /// let okta = Okta::from_options(OktaOptions {
    ///     domain: "dev-123456.okta.com".into(),
    ///     authorization_server_id: Some("default".into()),
    ///     client_id: "your-client-id".into(),
    ///     client_secret: "your-client-secret".into(),
    ///     redirect_uri: "https://example.com/callback".into(),
    ///     http_client: &custom_client,
    /// });
    /// ```
    pub fn from_options(options: OktaOptions<'a, H>) -> Self {
        let domain = options.domain;
        let base = match options.authorization_server_id {
            Some(ref server_id) => format!("https://{domain}/oauth2/{server_id}"),
            None => format!("https://{domain}/oauth2"),
        };
        Self {
            http_client: options.http_client,
            client: OAuth2Client::new(
                options.client_id,
                Some(options.client_secret),
                Some(options.redirect_uri),
            ),
            authorization_endpoint: format!("{base}/v1/authorize"),
            token_endpoint: format!("{base}/v1/token"),
            revocation_endpoint: format!("{base}/v1/revoke"),
        }
    }
}

#[cfg(feature = "reqwest-client")]
impl Okta<'static, reqwest::Client> {
    /// Creates a new Okta OAuth 2.0 client with dynamically constructed endpoints using the default HTTP client.
    ///
    /// The endpoints are automatically constructed from your Okta domain and authorization server ID.
    /// Uses the built-in `reqwest::Client` for HTTP requests. To provide a custom
    /// HTTP client, use [`Okta::from_options`] instead.
    ///
    /// # Arguments
    ///
    /// * `domain` - Your Okta domain (e.g. `"dev-123456.okta.com"`).
    /// * `authorization_server_id` - Optional authorization server ID (e.g. `Some("default")`)
    ///   for custom authorization servers. Pass `None` to use the org authorization server.
    /// * `client_id` - The OAuth 2.0 client ID from the Okta Admin Console.
    /// * `client_secret` - The OAuth 2.0 client secret from the Okta Admin Console.
    /// * `redirect_uri` - The URI Okta will redirect to after authorization. Must match
    ///   one of the sign-in redirect URIs configured in your Okta application.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::Okta;
    ///
    /// // Using the default authorization server
    /// let okta = Okta::new(
    ///     "dev-123456.okta.com",
    ///     Some("default".into()),
    ///     "your-client-id",
    ///     "your-client-secret",
    ///     "https://example.com/callback",
    /// );
    ///
    /// // Using the org authorization server
    /// let okta_org = Okta::new(
    ///     "dev-123456.okta.com",
    ///     None,
    ///     "your-client-id",
    ///     "your-client-secret",
    ///     "https://example.com/callback",
    /// );
    /// ```
    pub fn new(
        domain: impl Into<String>,
        authorization_server_id: Option<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        Self::from_options(OktaOptions {
            domain: domain.into(),
            authorization_server_id,
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri: redirect_uri.into(),
            http_client: crate::http::default_client(),
        })
    }
}

impl<'a, H: HttpClient> Okta<'a, H> {
    /// Returns the provider name (`"Okta"`).
    pub fn name(&self) -> &'static str {
        "Okta"
    }

    /// Builds the Okta authorization URL that the user should be redirected to.
    ///
    /// The returned URL includes all required OAuth 2.0 and PKCE parameters. Your
    /// application should store `state` and `code_verifier` in the user's session
    /// before redirecting, as both are needed to complete the flow.
    ///
    /// # Arguments
    ///
    /// * `state` - A CSRF token to prevent cross-site request forgery. Use
    ///   [`generate_state`](crate::generate_state) to create one.
    /// * `scopes` - The OAuth 2.0 scopes to request (e.g. `&["openid", "profile", "email"]`).
    /// * `code_verifier` - The PKCE code verifier. Use
    ///   [`generate_code_verifier`](crate::generate_code_verifier) to create one.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{Okta, generate_state, generate_code_verifier};
    ///
    /// let okta = Okta::new("dev-123.okta.com", None, "client-id", "secret", "https://example.com/cb");
    /// let state = generate_state();
    /// let verifier = generate_code_verifier();
    ///
    /// let url = okta.authorization_url(&state, &["openid", "email"], &verifier);
    /// assert!(url.as_str().contains("dev-123.okta.com"));
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
    /// Call this in your redirect URI handler after Okta redirects back with a `code`
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
    /// Returns [`Error::OAuthRequest`] if Okta rejects the code, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::Okta;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let okta = Okta::new("dev-123.okta.com", None, "client-id", "secret", "https://example.com/cb");
    ///
    /// let tokens = okta
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
    /// Okta access tokens typically expire after 1 hour. If your initial token response
    /// included a refresh token (requires the `offline_access` scope), you can use it to
    /// obtain a new access token without user interaction.
    ///
    /// # Arguments
    ///
    /// * `refresh_token` - The refresh token from a previous token response.
    /// * `scopes` - Optional scopes to request. Pass an empty slice to use the original scopes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OAuthRequest`] if the refresh token is invalid or revoked, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::Okta;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let okta = Okta::new("dev-123.okta.com", None, "client-id", "secret", "https://example.com/cb");
    ///
    /// let new_tokens = okta
    ///     .refresh_access_token("stored-refresh-token", &[])
    ///     .await?;
    ///
    /// println!("New access token: {}", new_tokens.access_token()?);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn refresh_access_token(
        &self,
        refresh_token: &str,
        scopes: &[&str],
    ) -> Result<OAuth2Tokens, Error> {
        self.client
            .refresh_access_token(
                self.http_client,
                &self.token_endpoint,
                refresh_token,
                scopes,
            )
            .await
    }

    /// Revokes an access token or refresh token.
    ///
    /// Use this when a user signs out or disconnects your application. Revoking a
    /// refresh token invalidates all access tokens issued for that authorization.
    ///
    /// # Arguments
    ///
    /// * `token` - The access token or refresh token to revoke.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedResponse`] if Okta returns a non-200 status, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::Okta;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let okta = Okta::new("dev-123.okta.com", None, "client-id", "secret", "https://example.com/cb");
    ///
    /// okta.revoke_token("token-to-revoke").await?;
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

    fn make_okta(http_client: &MockHttpClient) -> Okta<'_, MockHttpClient> {
        Okta::from_options(OktaOptions {
            domain: "dev-123.okta.com".into(),
            authorization_server_id: None,
            client_id: "cid".into(),
            client_secret: "secret".into(),
            redirect_uri: "https://app/cb".into(),
            http_client,
        })
    }

    #[test]
    fn new_builds_endpoints_without_auth_server_id() {
        let mock = MockHttpClient::new(vec![]);
        let okta = make_okta(&mock);
        assert_eq!(
            okta.authorization_endpoint,
            "https://dev-123.okta.com/oauth2/v1/authorize"
        );
        assert_eq!(
            okta.token_endpoint,
            "https://dev-123.okta.com/oauth2/v1/token"
        );
        assert_eq!(
            okta.revocation_endpoint,
            "https://dev-123.okta.com/oauth2/v1/revoke"
        );
    }

    #[test]
    fn new_builds_endpoints_with_auth_server_id() {
        let mock = MockHttpClient::new(vec![]);
        let okta = Okta::from_options(OktaOptions {
            domain: "dev-123.okta.com".into(),
            authorization_server_id: Some("default".into()),
            client_id: "cid".into(),
            client_secret: "secret".into(),
            redirect_uri: "https://app/cb".into(),
            http_client: &mock,
        });
        assert_eq!(
            okta.authorization_endpoint,
            "https://dev-123.okta.com/oauth2/default/v1/authorize"
        );
        assert_eq!(
            okta.token_endpoint,
            "https://dev-123.okta.com/oauth2/default/v1/token"
        );
        assert_eq!(
            okta.revocation_endpoint,
            "https://dev-123.okta.com/oauth2/default/v1/revoke"
        );
    }

    #[test]
    fn name_returns_okta() {
        let mock = MockHttpClient::new(vec![]);
        let okta = Okta::from_options(OktaOptions {
            domain: "dev-123.okta.com".into(),
            authorization_server_id: None,
            client_id: "cid".into(),
            client_secret: "secret".into(),
            redirect_uri: "https://app/cb".into(),
            http_client: &mock,
        });
        assert_eq!(okta.name(), "Okta");
    }

    #[test]
    fn authorization_url_includes_pkce() {
        let mock = MockHttpClient::new(vec![]);
        let okta = Okta::from_options(OktaOptions {
            domain: "dev-123.okta.com".into(),
            authorization_server_id: None,
            client_id: "cid".into(),
            client_secret: "secret".into(),
            redirect_uri: "https://app/cb".into(),
            http_client: &mock,
        });
        let url = okta.authorization_url("state123", &["openid"], "my-verifier");

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
                "access_token": "okta-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);
        let okta = make_okta(&mock);

        let tokens = okta
            .validate_authorization_code("code", "verifier")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "okta-tok");

        let requests = mock.take_requests();
        assert_eq!(requests[0].url, "https://dev-123.okta.com/oauth2/v1/token");
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("code_verifier".into(), "verifier".into())));
    }

    #[tokio::test]
    async fn refresh_access_token_passes_scopes() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "new-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);
        let okta = make_okta(&mock);

        let tokens = okta
            .refresh_access_token("rt", &["openid", "profile"])
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "new-tok");

        let requests = mock.take_requests();
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("scope".into(), "openid profile".into())));
    }

    #[tokio::test]
    async fn revoke_token_delegates_to_client() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: vec![],
        }]);
        let okta = make_okta(&mock);

        let result = okta.revoke_token("tok").await;
        assert!(result.is_ok());

        let requests = mock.take_requests();
        assert_eq!(requests[0].url, "https://dev-123.okta.com/oauth2/v1/revoke");
    }
}
