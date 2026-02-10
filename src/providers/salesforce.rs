use crate::client::OAuth2Client;
use crate::error::Error;
use crate::http::HttpClient;
use crate::pkce::CodeChallengeMethod;
use crate::tokens::OAuth2Tokens;

/// Configuration for creating a [`Salesforce`] client with a custom HTTP client.
///
/// Use this when you need to provide your own [`HttpClient`] implementation
/// (e.g. a pre-configured `reqwest::Client` with custom timeouts or proxies).
/// For the common case, use [`Salesforce::new`] which uses the built-in default client.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{Salesforce, SalesforceOptions, HttpClient};
///
/// let custom_client = reqwest::Client::builder()
///     .timeout(std::time::Duration::from_secs(10))
///     .build()
///     .unwrap();
///
/// let salesforce = Salesforce::from_options(SalesforceOptions {
///     domain: "login.salesforce.com".into(),
///     client_id: "your-consumer-key".into(),
///     client_secret: Some("your-consumer-secret".into()),
///     redirect_uri: "https://example.com/callback".into(),
///     http_client: &custom_client,
/// });
/// ```
pub struct SalesforceOptions<'a, H: HttpClient> {
    pub domain: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_uri: String,
    pub http_client: &'a H,
}

/// OAuth 2.0 client for [Salesforce](https://help.salesforce.com/s/articleView?id=sf.remoteaccess_oauth_web_server_flow.htm).
///
/// Salesforce requires PKCE with the S256 challenge method for authorization requests.
/// This client supports the full authorization code flow including token refresh and
/// revocation. The client secret is optional for public clients. Unlike most providers,
/// Salesforce requires you to specify the authentication domain (e.g., `login.salesforce.com`
/// for production or `test.salesforce.com` for sandboxes).
///
/// # Setup
///
/// 1. Create a Connected App in your Salesforce org via **Setup > Apps > App Manager**.
/// 2. Enable **OAuth Settings** and configure the callback URL to match the `redirect_uri`
///    you pass to [`Salesforce::new`].
/// 3. Select the required **OAuth Scopes** for your application.
/// 4. Obtain your **Consumer Key** (Client ID) and **Consumer Secret** (Client Secret).
///
/// # Scopes
///
/// Salesforce uses space-separated scopes. Common scopes include:
///
/// | Scope | Description |
/// |-------|-------------|
/// | `api` | Access to REST API resources |
/// | `refresh_token` | Enable refresh tokens |
/// | `openid` | OpenID Connect authentication |
/// | `profile` | Access to user profile |
/// | `full` | Full access to all data (use with caution) |
///
/// See the full list at <https://help.salesforce.com/s/articleView?id=sf.remoteaccess_oauth_tokens_scopes.htm>.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{Salesforce, generate_state, generate_code_verifier};
///
/// # async fn example() -> Result<(), arctic_oauth::Error> {
/// let salesforce = Salesforce::new(
///     "login.salesforce.com",  // Use "test.salesforce.com" for sandboxes
///     "your-consumer-key",
///     Some("your-consumer-secret".into()),
///     "https://example.com/callback",
/// );
///
/// // Step 1: Generate PKCE verifier and CSRF state, then redirect the user.
/// let state = generate_state();
/// let code_verifier = generate_code_verifier();
/// let url = salesforce.authorization_url(&state, &["api", "refresh_token"], &code_verifier);
/// // Store `state` and `code_verifier` in the user's session, then redirect to `url`.
///
/// // Step 2: In your callback handler, exchange the authorization code for tokens.
/// let tokens = salesforce
///     .validate_authorization_code("authorization-code", &code_verifier)
///     .await?;
/// println!("Access token: {}", tokens.access_token()?);
///
/// // Step 3 (optional): Refresh an expired access token.
/// let refreshed = salesforce
///     .refresh_access_token(tokens.refresh_token()?)
///     .await?;
///
/// // Step 4 (optional): Revoke a token.
/// salesforce.revoke_token(tokens.access_token()?).await?;
/// # Ok(())
/// # }
/// ```
pub struct Salesforce<'a, H: HttpClient> {
    client: OAuth2Client,
    http_client: &'a H,
    authorization_endpoint: String,
    token_endpoint: String,
    revocation_endpoint: String,
}

impl<'a, H: HttpClient> Salesforce<'a, H> {
    /// Creates a Salesforce client from a [`SalesforceOptions`] struct.
    ///
    /// Use this when you need a custom HTTP client. For the common case,
    /// use [`Salesforce::new`] instead.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{Salesforce, SalesforceOptions};
    ///
    /// let custom_client = reqwest::Client::new();
    /// let salesforce = Salesforce::from_options(SalesforceOptions {
    ///     domain: "login.salesforce.com".into(),
    ///     client_id: "your-consumer-key".into(),
    ///     client_secret: Some("your-consumer-secret".into()),
    ///     redirect_uri: "https://example.com/callback".into(),
    ///     http_client: &custom_client,
    /// });
    /// ```
    pub fn from_options(options: SalesforceOptions<'a, H>) -> Self {
        let domain = options.domain;
        Self {
            http_client: options.http_client,
            client: OAuth2Client::new(
                options.client_id,
                options.client_secret,
                Some(options.redirect_uri),
            ),
            authorization_endpoint: format!("https://{domain}/services/oauth2/authorize"),
            token_endpoint: format!("https://{domain}/services/oauth2/token"),
            revocation_endpoint: format!("https://{domain}/services/oauth2/revoke"),
        }
    }
}

#[cfg(feature = "reqwest-client")]
impl Salesforce<'static, reqwest::Client> {
    /// Creates a new Salesforce OAuth 2.0 client configured for the specified domain using the default HTTP client.
    ///
    /// The endpoints are automatically constructed from your Salesforce domain.
    /// Uses the built-in `reqwest::Client` for HTTP requests. To provide a custom
    /// HTTP client, use [`Salesforce::from_options`] instead.
    ///
    /// # Arguments
    ///
    /// * `domain` - The Salesforce authentication domain (e.g., `"login.salesforce.com"` for
    ///   production orgs, `"test.salesforce.com"` for sandboxes, or your custom My Domain).
    /// * `client_id` - The Consumer Key from your Connected App.
    /// * `client_secret` - The Consumer Secret (optional for public clients).
    /// * `redirect_uri` - The URI Salesforce will redirect to after authorization. Must match
    ///   one of the callback URLs configured in your Connected App.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::Salesforce;
    ///
    /// // Production org
    /// let salesforce = Salesforce::new(
    ///     "login.salesforce.com",
    ///     "your-consumer-key",
    ///     Some("your-consumer-secret".into()),
    ///     "https://example.com/callback",
    /// );
    ///
    /// // Sandbox org
    /// let salesforce_sandbox = Salesforce::new(
    ///     "test.salesforce.com",
    ///     "your-consumer-key",
    ///     Some("your-consumer-secret".into()),
    ///     "https://example.com/callback",
    /// );
    ///
    /// // Public client (no secret)
    /// let salesforce_public = Salesforce::new(
    ///     "login.salesforce.com",
    ///     "your-consumer-key",
    ///     None,
    ///     "https://example.com/callback",
    /// );
    /// ```
    pub fn new(
        domain: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: Option<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        Self::from_options(SalesforceOptions {
            domain: domain.into(),
            client_id: client_id.into(),
            client_secret,
            redirect_uri: redirect_uri.into(),
            http_client: crate::http::default_client(),
        })
    }
}

impl<'a, H: HttpClient> Salesforce<'a, H> {
    /// Returns the provider name (`"Salesforce"`).
    pub fn name(&self) -> &'static str {
        "Salesforce"
    }

    /// Builds the Salesforce authorization URL that the user should be redirected to.
    ///
    /// The returned URL includes all required OAuth 2.0 and PKCE parameters. Your
    /// application should store `state` and `code_verifier` in the user's session
    /// before redirecting, as both are needed to complete the flow.
    ///
    /// # Arguments
    ///
    /// * `state` - A CSRF token to prevent cross-site request forgery. Use
    ///   [`generate_state`](crate::generate_state) to create one.
    /// * `scopes` - The OAuth 2.0 scopes to request (e.g. `&["api", "refresh_token"]`).
    /// * `code_verifier` - The PKCE code verifier. Use
    ///   [`generate_code_verifier`](crate::generate_code_verifier) to create one.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{Salesforce, generate_state, generate_code_verifier};
    ///
    /// let salesforce = Salesforce::new(
    ///     "login.salesforce.com",
    ///     "client-id",
    ///     None,
    ///     "https://example.com/cb"
    /// );
    /// let state = generate_state();
    /// let verifier = generate_code_verifier();
    ///
    /// let url = salesforce.authorization_url(&state, &["api", "refresh_token"], &verifier);
    /// assert!(url.as_str().starts_with("https://login.salesforce.com/"));
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
    /// Call this in your redirect URI handler after Salesforce redirects back with a `code`
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
    /// Returns [`Error::OAuthRequest`] if Salesforce rejects the code, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::Salesforce;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let salesforce = Salesforce::new(
    ///     "login.salesforce.com",
    ///     "client-id",
    ///     Some("secret".into()),
    ///     "https://example.com/cb"
    /// );
    ///
    /// let tokens = salesforce
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
    /// Salesforce access tokens do not have a fixed expiration time but may be invalidated
    /// due to various reasons. If you requested the `refresh_token` scope and your initial
    /// token response included a refresh token, you can use it to obtain a new access token
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
    /// # use arctic_oauth::Salesforce;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let salesforce = Salesforce::new(
    ///     "login.salesforce.com",
    ///     "client-id",
    ///     Some("secret".into()),
    ///     "https://example.com/cb"
    /// );
    ///
    /// let new_tokens = salesforce
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
    /// Use this when a user signs out or disconnects your application. Revoking a token
    /// invalidates it immediately.
    ///
    /// # Arguments
    ///
    /// * `token` - The access token or refresh token to revoke.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OAuthRequest`] if Salesforce rejects the request, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::Salesforce;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let salesforce = Salesforce::new(
    ///     "login.salesforce.com",
    ///     "client-id",
    ///     Some("secret".into()),
    ///     "https://example.com/cb"
    /// );
    ///
    /// salesforce.revoke_token("token-to-revoke").await?;
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

    fn make_salesforce(http_client: &MockHttpClient) -> Salesforce<'_, MockHttpClient> {
        Salesforce::from_options(SalesforceOptions {
            domain: "login.salesforce.com".into(),
            client_id: "cid".into(),
            client_secret: Some("secret".into()),
            redirect_uri: "https://app/cb".into(),
            http_client,
        })
    }

    #[test]
    fn new_builds_endpoints_from_domain() {
        let mock = MockHttpClient::new(vec![]);
        let sf = make_salesforce(&mock);
        assert_eq!(
            sf.authorization_endpoint,
            "https://login.salesforce.com/services/oauth2/authorize"
        );
        assert_eq!(
            sf.token_endpoint,
            "https://login.salesforce.com/services/oauth2/token"
        );
        assert_eq!(
            sf.revocation_endpoint,
            "https://login.salesforce.com/services/oauth2/revoke"
        );
    }

    #[test]
    fn name_returns_salesforce() {
        let mock = MockHttpClient::new(vec![]);
        let sf = Salesforce::from_options(SalesforceOptions {
            domain: "login.salesforce.com".into(),
            client_id: "cid".into(),
            client_secret: None,
            redirect_uri: "https://app/cb".into(),
            http_client: &mock,
        });
        assert_eq!(sf.name(), "Salesforce");
    }

    #[test]
    fn authorization_url_includes_pkce() {
        let mock = MockHttpClient::new(vec![]);
        let sf = Salesforce::from_options(SalesforceOptions {
            domain: "login.salesforce.com".into(),
            client_id: "cid".into(),
            client_secret: None,
            redirect_uri: "https://app/cb".into(),
            http_client: &mock,
        });
        let url = sf.authorization_url("state123", &["api"], "my-verifier");

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
                "access_token": "sf-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);
        let sf = make_salesforce(&mock);

        let tokens = sf
            .validate_authorization_code("code", "verifier")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "sf-tok");

        let requests = mock.take_requests();
        assert_eq!(
            requests[0].url,
            "https://login.salesforce.com/services/oauth2/token"
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
        let sf = make_salesforce(&mock);

        let result = sf.revoke_token("tok").await;
        assert!(result.is_ok());

        let requests = mock.take_requests();
        assert_eq!(
            requests[0].url,
            "https://login.salesforce.com/services/oauth2/revoke"
        );
    }
}
