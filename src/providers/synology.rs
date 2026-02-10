use crate::client::OAuth2Client;
use crate::error::Error;
use crate::http::HttpClient;
use crate::pkce::CodeChallengeMethod;
use crate::tokens::OAuth2Tokens;

/// Configuration for creating a [`Synology`] client with a custom HTTP client.
///
/// Use this when you need to provide your own [`HttpClient`] implementation
/// (e.g. a pre-configured `reqwest::Client` with custom timeouts or proxies).
/// For the common case, use [`Synology::new`] which uses the built-in default client.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{Synology, SynologyOptions, HttpClient};
///
/// let custom_client = reqwest::Client::builder()
///     .timeout(std::time::Duration::from_secs(10))
///     .build()
///     .unwrap();
///
/// let synology = Synology::from_options(SynologyOptions {
///     base_url: "https://nas.example.com:5001".into(),
///     application_id: "your-application-id".into(),
///     application_secret: "your-application-secret".into(),
///     redirect_uri: "https://example.com/callback".into(),
///     http_client: &custom_client,
/// });
/// ```
pub struct SynologyOptions<'a, H: HttpClient> {
    pub base_url: String,
    pub application_id: String,
    pub application_secret: String,
    pub redirect_uri: String,
    pub http_client: &'a H,
}

/// OAuth 2.0 client for [Synology](https://kb.synology.com/en-global/DSM/help/OAuthService/oauth_service_desc?version=7).
///
/// Synology requires PKCE with the S256 challenge method. This client supports
/// the authorization code flow for authenticating with self-hosted Synology NAS devices.
///
/// # Setup
///
/// 1. Access your Synology NAS and navigate to **Control Panel > Application Portal > OAuth**.
/// 2. Click **Create** to register a new OAuth application.
/// 3. Configure the redirect URI to match the `redirect_uri` you pass to [`Synology::new`].
/// 4. Note your Application ID and Application Secret.
///
/// # Scopes
///
/// Synology uses space-separated scopes. Common scopes include:
///
/// | Scope | Description |
/// |-------|-------------|
/// | `user.profile` | Access to user profile information |
/// | `files` | Access to file station |
///
/// Refer to your Synology NAS documentation for the complete list of available scopes.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{Synology, generate_state, generate_code_verifier};
///
/// # async fn example() -> Result<(), arctic_oauth::Error> {
/// let synology = Synology::new(
///     "https://nas.example.com:5001",
///     "your-application-id",
///     "your-application-secret",
///     "https://example.com/callback",
/// );
///
/// // Step 1: Generate PKCE verifier and CSRF state, then redirect the user.
/// let state = generate_state();
/// let code_verifier = generate_code_verifier();
/// let url = synology.authorization_url(&state, &["user.profile"], &code_verifier);
/// // Store `state` and `code_verifier` in the user's session, then redirect to `url`.
///
/// // Step 2: In your callback handler, exchange the authorization code for tokens.
/// let tokens = synology
///     .validate_authorization_code("authorization-code", &code_verifier)
///     .await?;
/// println!("Access token: {}", tokens.access_token()?);
/// # Ok(())
/// # }
/// ```
pub struct Synology<'a, H: HttpClient> {
    client: OAuth2Client,
    http_client: &'a H,
    authorization_endpoint: String,
    token_endpoint: String,
}

impl<'a, H: HttpClient> Synology<'a, H> {
    /// Creates a Synology client from a [`SynologyOptions`] struct.
    ///
    /// Use this when you need a custom HTTP client. For the common case,
    /// use [`Synology::new`] instead.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{Synology, SynologyOptions};
    ///
    /// let custom_client = reqwest::Client::new();
    /// let synology = Synology::from_options(SynologyOptions {
    ///     base_url: "https://nas.example.com:5001".into(),
    ///     application_id: "your-application-id".into(),
    ///     application_secret: "your-application-secret".into(),
    ///     redirect_uri: "https://example.com/callback".into(),
    ///     http_client: &custom_client,
    /// });
    /// ```
    pub fn from_options(options: SynologyOptions<'a, H>) -> Self {
        let base = options.base_url;
        Self {
            http_client: options.http_client,
            client: OAuth2Client::new(
                options.application_id,
                Some(options.application_secret),
                Some(options.redirect_uri),
            ),
            authorization_endpoint: format!("{base}/webman/sso/SSOOauth.cgi"),
            token_endpoint: format!("{base}/webman/sso/SSOAccessToken.cgi"),
        }
    }
}

#[cfg(feature = "reqwest-client")]
impl Synology<'static, reqwest::Client> {
    /// Creates a new Synology OAuth 2.0 client for a self-hosted NAS using the default HTTP client.
    ///
    /// Uses the built-in `reqwest::Client` for HTTP requests. To provide a custom
    /// HTTP client, use [`Synology::from_options`] instead.
    ///
    /// # Arguments
    ///
    /// * `base_url` - The base URL of your Synology NAS (e.g., `https://nas.example.com:5001`).
    /// * `application_id` - The Application ID from your Synology OAuth application.
    /// * `application_secret` - The Application Secret from your Synology OAuth application.
    /// * `redirect_uri` - The URI Synology will redirect to after authorization. Must match
    ///   the redirect URI configured in your OAuth application settings.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::Synology;
    ///
    /// let synology = Synology::new(
    ///     "https://nas.example.com:5001",
    ///     "your-application-id",
    ///     "your-application-secret",
    ///     "https://example.com/callback",
    /// );
    /// ```
    pub fn new(
        base_url: impl Into<String>,
        application_id: impl Into<String>,
        application_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        Self::from_options(SynologyOptions {
            base_url: base_url.into(),
            application_id: application_id.into(),
            application_secret: application_secret.into(),
            redirect_uri: redirect_uri.into(),
            http_client: crate::http::default_client(),
        })
    }
}

impl<'a, H: HttpClient> Synology<'a, H> {
    /// Returns the provider name (`"Synology"`).
    pub fn name(&self) -> &'static str {
        "Synology"
    }

    /// Builds the Synology authorization URL that the user should be redirected to.
    ///
    /// The returned URL includes all required OAuth 2.0 and PKCE parameters. Your
    /// application should store `state` and `code_verifier` in the user's session
    /// before redirecting, as both are needed to complete the flow.
    ///
    /// # Arguments
    ///
    /// * `state` - A CSRF token to prevent cross-site request forgery. Use
    ///   [`generate_state`](crate::generate_state) to create one.
    /// * `scopes` - The OAuth 2.0 scopes to request (e.g. `&["user.profile"]`).
    /// * `code_verifier` - The PKCE code verifier. Use
    ///   [`generate_code_verifier`](crate::generate_code_verifier) to create one.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{Synology, generate_state, generate_code_verifier};
    ///
    /// let synology = Synology::new(
    ///     "https://nas.example.com:5001",
    ///     "app-id",
    ///     "app-secret",
    ///     "https://example.com/cb"
    /// );
    /// let state = generate_state();
    /// let verifier = generate_code_verifier();
    ///
    /// let url = synology.authorization_url(&state, &["user.profile"], &verifier);
    /// assert!(url.as_str().starts_with("https://nas.example.com:5001/webman/sso/"));
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
    /// Call this in your redirect URI handler after Synology redirects back with a `code`
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
    /// Returns [`Error::OAuthRequest`] if Synology rejects the code, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::Synology;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let synology = Synology::new(
    ///     "https://nas.example.com:5001",
    ///     "app-id",
    ///     "secret",
    ///     "https://example.com/cb"
    /// );
    ///
    /// let tokens = synology
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

    fn make_synology(http_client: &MockHttpClient) -> Synology<'_, MockHttpClient> {
        Synology::from_options(SynologyOptions {
            base_url: "https://nas.example.com:5001".into(),
            application_id: "app-id".into(),
            application_secret: "app-secret".into(),
            redirect_uri: "https://app/cb".into(),
            http_client,
        })
    }

    #[test]
    fn new_builds_endpoints_from_base_url() {
        let mock = MockHttpClient::new(vec![]);
        let synology = make_synology(&mock);
        assert_eq!(
            synology.authorization_endpoint,
            "https://nas.example.com:5001/webman/sso/SSOOauth.cgi"
        );
        assert_eq!(
            synology.token_endpoint,
            "https://nas.example.com:5001/webman/sso/SSOAccessToken.cgi"
        );
    }

    #[test]
    fn name_returns_synology() {
        let mock = MockHttpClient::new(vec![]);
        let synology = make_synology(&mock);
        assert_eq!(synology.name(), "Synology");
    }

    #[test]
    fn authorization_url_includes_pkce() {
        let mock = MockHttpClient::new(vec![]);
        let synology = make_synology(&mock);
        let url = synology.authorization_url("state123", &[], "my-verifier");

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.contains(&("client_id".into(), "app-id".into())));
        assert!(pairs.iter().any(|(k, _)| k == "code_challenge"));
        assert!(pairs.contains(&("code_challenge_method".into(), "S256".into())));
    }

    #[tokio::test]
    async fn validate_authorization_code_sends_verifier() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "synology-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);
        let synology = make_synology(&mock);

        let tokens = synology
            .validate_authorization_code("code", "verifier")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "synology-tok");

        let requests = mock.take_requests();
        assert_eq!(
            requests[0].url,
            "https://nas.example.com:5001/webman/sso/SSOAccessToken.cgi"
        );
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("code_verifier".into(), "verifier".into())));
    }
}
