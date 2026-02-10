use crate::error::Error;
use crate::http::HttpClient;
use crate::request::{create_oauth2_request, send_token_request};
use crate::tokens::OAuth2Tokens;

const AUTHORIZATION_ENDPOINT: &str = "https://auth.atlassian.com/authorize";
const TOKEN_ENDPOINT: &str = "https://auth.atlassian.com/oauth/token";

/// Configuration for creating an [`Atlassian`] client with a custom HTTP client.
///
/// Use this when you need to provide your own [`HttpClient`] implementation
/// (e.g. a pre-configured `reqwest::Client` with custom timeouts or proxies).
/// For the common case, use [`Atlassian::new`] which uses the built-in default client.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{Atlassian, AtlassianOptions, HttpClient};
///
/// let custom_client = reqwest::Client::builder()
///     .timeout(std::time::Duration::from_secs(10))
///     .build()
///     .unwrap();
///
/// let atlassian = Atlassian::from_options(AtlassianOptions {
///     client_id: "your-client-id".into(),
///     client_secret: "your-client-secret".into(),
///     redirect_uri: "https://example.com/callback".into(),
///     http_client: &custom_client,
/// });
/// ```
pub struct AtlassianOptions<'a, H: HttpClient> {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub http_client: &'a H,
}

/// OAuth 2.0 client for [Atlassian](https://developer.atlassian.com/cloud/jira/platform/oauth-2-3lo-apps/).
///
/// Atlassian does not require PKCE. The authorization URL automatically includes
/// `audience=api.atlassian.com` and `prompt=consent` as required by Atlassian's OAuth 2.0
/// implementation. This client supports the full authorization code flow including token refresh.
///
/// # Setup
///
/// 1. Go to the [Atlassian Developer Console](https://developer.atlassian.com/console/myapps/).
/// 2. Create a new app and configure OAuth 2.0 settings.
/// 3. Add the callback URL to match the `redirect_uri` you pass to [`Atlassian::new`].
/// 4. Note your Client ID and Client Secret.
///
/// # Scopes
///
/// Atlassian uses space-separated scopes. Common scopes include:
///
/// | Scope | Description |
/// |-------|-------------|
/// | `read:jira-work` | Read Jira work data |
/// | `write:jira-work` | Write Jira work data |
/// | `read:confluence-content.all` | Read Confluence content |
/// | `write:confluence-content` | Write Confluence content |
/// | `offline_access` | Request refresh tokens |
///
/// See the full list at <https://developer.atlassian.com/cloud/jira/platform/scopes-for-oauth-2-3LO-and-forge-apps/>.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{Atlassian, generate_state};
///
/// # async fn example() -> Result<(), arctic_oauth::Error> {
/// let atlassian = Atlassian::new(
///     "your-client-id",
///     "your-client-secret",
///     "https://example.com/callback",
/// );
///
/// // Step 1: Generate CSRF state, then redirect the user.
/// let state = generate_state();
/// let url = atlassian.authorization_url(&state, &["read:jira-work", "offline_access"]);
/// // Store `state` in the user's session, then redirect to `url`.
///
/// // Step 2: In your callback handler, exchange the authorization code for tokens.
/// let tokens = atlassian
///     .validate_authorization_code("authorization-code")
///     .await?;
/// println!("Access token: {}", tokens.access_token()?);
///
/// // Step 3 (optional): Refresh an expired access token.
/// let refreshed = atlassian
///     .refresh_access_token(tokens.refresh_token()?)
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct Atlassian<'a, H: HttpClient> {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    http_client: &'a H,
    authorization_endpoint: String,
    token_endpoint: String,
}

impl<'a, H: HttpClient> Atlassian<'a, H> {
    /// Creates an Atlassian client from an [`AtlassianOptions`] struct.
    ///
    /// Use this when you need a custom HTTP client. For the common case,
    /// use [`Atlassian::new`] instead.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{Atlassian, AtlassianOptions};
    ///
    /// let custom_client = reqwest::Client::new();
    /// let atlassian = Atlassian::from_options(AtlassianOptions {
    ///     client_id: "your-client-id".into(),
    ///     client_secret: "your-client-secret".into(),
    ///     redirect_uri: "https://example.com/callback".into(),
    ///     http_client: &custom_client,
    /// });
    /// ```
    pub fn from_options(options: AtlassianOptions<'a, H>) -> Self {
        Self {
            http_client: options.http_client,
            client_id: options.client_id,
            client_secret: options.client_secret,
            redirect_uri: options.redirect_uri,
            authorization_endpoint: AUTHORIZATION_ENDPOINT.to_string(),
            token_endpoint: TOKEN_ENDPOINT.to_string(),
        }
    }
}

#[cfg(feature = "reqwest-client")]
impl Atlassian<'static, reqwest::Client> {
    /// Creates a new Atlassian OAuth 2.0 client configured with production endpoints using the default HTTP client.
    ///
    /// Uses the built-in `reqwest::Client` for HTTP requests. To provide a custom
    /// HTTP client, use [`Atlassian::from_options`] instead.
    ///
    /// # Arguments
    ///
    /// * `client_id` - The OAuth 2.0 client ID from the Atlassian Developer Console.
    /// * `client_secret` - The OAuth 2.0 client secret from the Atlassian Developer Console.
    /// * `redirect_uri` - The URI Atlassian will redirect to after authorization. Must match
    ///   one of the callback URLs configured in your Atlassian app.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::Atlassian;
    ///
    /// let atlassian = Atlassian::new(
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
        Self::from_options(AtlassianOptions {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri: redirect_uri.into(),
            http_client: crate::http::default_client(),
        })
    }
}

impl<'a, H: HttpClient> Atlassian<'a, H> {
    /// Returns the provider name (`"Atlassian"`).
    pub fn name(&self) -> &'static str {
        "Atlassian"
    }

    /// Builds the Atlassian authorization URL that the user should be redirected to.
    ///
    /// The returned URL includes all required OAuth 2.0 parameters, plus Atlassian-specific
    /// `audience=api.atlassian.com` and `prompt=consent` parameters. Your application should
    /// store `state` in the user's session before redirecting.
    ///
    /// # Arguments
    ///
    /// * `state` - A CSRF token to prevent cross-site request forgery. Use
    ///   [`generate_state`](crate::generate_state) to create one.
    /// * `scopes` - The OAuth 2.0 scopes to request (e.g. `&["read:jira-work", "offline_access"]`).
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{Atlassian, generate_state};
    ///
    /// let atlassian = Atlassian::new("client-id", "client-secret", "https://example.com/cb");
    /// let state = generate_state();
    ///
    /// let url = atlassian.authorization_url(&state, &["read:jira-work"]);
    /// assert!(url.as_str().starts_with("https://auth.atlassian.com/"));
    /// ```
    pub fn authorization_url(&self, state: &str, scopes: &[&str]) -> url::Url {
        let mut url = url::Url::parse(&self.authorization_endpoint)
            .expect("invalid authorization endpoint URL");

        {
            let mut params = url.query_pairs_mut();
            params.append_pair("response_type", "code");
            params.append_pair("client_id", &self.client_id);
            params.append_pair("state", state);

            if !scopes.is_empty() {
                params.append_pair("scope", &scopes.join(" "));
            }

            params.append_pair("redirect_uri", &self.redirect_uri);
            params.append_pair("audience", "api.atlassian.com");
            params.append_pair("prompt", "consent");
        }

        url
    }

    /// Exchanges an authorization code for access and refresh tokens.
    ///
    /// Call this in your redirect URI handler after Atlassian redirects back with a `code`
    /// query parameter. Atlassian-specific: credentials are sent in the POST body (not via
    /// Basic auth).
    ///
    /// # Arguments
    ///
    /// * `code` - The authorization code from the `code` query parameter.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OAuthRequest`] if Atlassian rejects the code, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::Atlassian;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let atlassian = Atlassian::new("client-id", "secret", "https://example.com/cb");
    ///
    /// let tokens = atlassian
    ///     .validate_authorization_code("the-auth-code")
    ///     .await?;
    ///
    /// println!("Access token: {}", tokens.access_token()?);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn validate_authorization_code(&self, code: &str) -> Result<OAuth2Tokens, Error> {
        let body = vec![
            ("grant_type".to_string(), "authorization_code".to_string()),
            ("code".to_string(), code.to_string()),
            ("redirect_uri".to_string(), self.redirect_uri.clone()),
            ("client_id".to_string(), self.client_id.clone()),
            ("client_secret".to_string(), self.client_secret.clone()),
        ];

        let request = create_oauth2_request(&self.token_endpoint, &body);
        send_token_request(self.http_client, request).await
    }

    /// Refreshes an expired access token using a refresh token.
    ///
    /// Use this to obtain a new access token without user interaction. To receive a refresh
    /// token in the initial authorization, include the `offline_access` scope.
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
    /// # use arctic_oauth::Atlassian;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let atlassian = Atlassian::new("client-id", "secret", "https://example.com/cb");
    ///
    /// let new_tokens = atlassian
    ///     .refresh_access_token("stored-refresh-token")
    ///     .await?;
    ///
    /// println!("New access token: {}", new_tokens.access_token()?);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn refresh_access_token(&self, refresh_token: &str) -> Result<OAuth2Tokens, Error> {
        let body = vec![
            ("grant_type".to_string(), "refresh_token".to_string()),
            ("refresh_token".to_string(), refresh_token.to_string()),
            ("client_id".to_string(), self.client_id.clone()),
            ("client_secret".to_string(), self.client_secret.clone()),
        ];

        let request = create_oauth2_request(&self.token_endpoint, &body);
        send_token_request(self.http_client, request).await
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

    fn make_atlassian(http_client: &MockHttpClient) -> Atlassian<'_, MockHttpClient> {
        Atlassian::from_options(AtlassianOptions {
            client_id: "cid".into(),
            client_secret: "secret".into(),
            redirect_uri: "https://app/cb".into(),
            http_client,
        })
    }

    #[test]
    fn new_sets_production_endpoints() {
        let mock = MockHttpClient::new(vec![]);
        let provider = make_atlassian(&mock);
        assert_eq!(provider.authorization_endpoint, AUTHORIZATION_ENDPOINT);
        assert_eq!(provider.token_endpoint, TOKEN_ENDPOINT);
    }

    #[test]
    fn name_returns_atlassian() {
        let mock = MockHttpClient::new(vec![]);
        let provider = make_atlassian(&mock);
        assert_eq!(provider.name(), "Atlassian");
    }

    #[test]
    fn authorization_url_includes_audience_and_prompt() {
        let mock = MockHttpClient::new(vec![]);
        let provider = make_atlassian(&mock);
        let url = provider.authorization_url("state123", &["read:jira-work"]);

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.contains(&("client_id".into(), "cid".into())));
        assert!(pairs.contains(&("state".into(), "state123".into())));
        assert!(pairs.contains(&("scope".into(), "read:jira-work".into())));
        assert!(pairs.contains(&("redirect_uri".into(), "https://app/cb".into())));
        assert!(pairs.contains(&("audience".into(), "api.atlassian.com".into())));
        assert!(pairs.contains(&("prompt".into(), "consent".into())));
    }

    #[test]
    fn authorization_url_omits_scope_when_empty() {
        let mock = MockHttpClient::new(vec![]);
        let provider = make_atlassian(&mock);
        let url = provider.authorization_url("state123", &[]);

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(!pairs.iter().any(|(k, _)| k == "scope"));
        assert!(pairs.contains(&("audience".into(), "api.atlassian.com".into())));
        assert!(pairs.contains(&("prompt".into(), "consent".into())));
    }

    #[tokio::test]
    async fn validate_authorization_code_sends_body_credentials() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "atl-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);
        let provider = make_atlassian(&mock);

        let tokens = provider
            .validate_authorization_code("auth-code")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "atl-tok");

        let requests = mock.take_requests();
        assert_eq!(requests[0].url, "https://auth.atlassian.com/oauth/token");
        assert!(get_header(&requests[0], "Authorization").is_none());

        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("grant_type".into(), "authorization_code".into())));
        assert!(body.contains(&("code".into(), "auth-code".into())));
        assert!(body.contains(&("client_id".into(), "cid".into())));
        assert!(body.contains(&("client_secret".into(), "secret".into())));
        assert!(body.contains(&("redirect_uri".into(), "https://app/cb".into())));
    }

    #[tokio::test]
    async fn refresh_access_token_sends_body_credentials() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "new-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);
        let provider = make_atlassian(&mock);

        let tokens = provider.refresh_access_token("refresh-tok").await.unwrap();

        assert_eq!(tokens.access_token().unwrap(), "new-tok");

        let requests = mock.take_requests();
        assert!(get_header(&requests[0], "Authorization").is_none());
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("grant_type".into(), "refresh_token".into())));
        assert!(body.contains(&("refresh_token".into(), "refresh-tok".into())));
        assert!(body.contains(&("client_id".into(), "cid".into())));
        assert!(body.contains(&("client_secret".into(), "secret".into())));
    }
}
