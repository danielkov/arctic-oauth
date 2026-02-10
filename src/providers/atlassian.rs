use crate::error::Error;
use crate::http::HttpClient;
use crate::request::{create_oauth2_request, send_token_request};
use crate::tokens::OAuth2Tokens;

const AUTHORIZATION_ENDPOINT: &str = "https://auth.atlassian.com/authorize";
const TOKEN_ENDPOINT: &str = "https://auth.atlassian.com/oauth/token";

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
/// use arctic_oauth::{Atlassian, ReqwestClient, generate_state};
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
/// let http = ReqwestClient::new();
/// let tokens = atlassian
///     .validate_authorization_code(&http, "authorization-code")
///     .await?;
/// println!("Access token: {}", tokens.access_token()?);
///
/// // Step 3 (optional): Refresh an expired access token.
/// let refreshed = atlassian
///     .refresh_access_token(&http, tokens.refresh_token()?)
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct Atlassian {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    authorization_endpoint: String,
    token_endpoint: String,
}

impl Atlassian {
    /// Creates a new Atlassian OAuth 2.0 client configured with production endpoints.
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
        Self {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri: redirect_uri.into(),
            authorization_endpoint: AUTHORIZATION_ENDPOINT.to_string(),
            token_endpoint: TOKEN_ENDPOINT.to_string(),
        }
    }
}

#[cfg(any(test, feature = "testing"))]
impl Atlassian {
    /// Creates an Atlassian client with custom endpoint URLs.
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
    /// use arctic_oauth::Atlassian;
    ///
    /// let atlassian = Atlassian::with_endpoints(
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
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri: redirect_uri.into(),
            authorization_endpoint: authorization_endpoint.to_string(),
            token_endpoint: token_endpoint.to_string(),
        }
    }
}

impl Atlassian {
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
    /// * `http_client` - An [`HttpClient`](crate::HttpClient) implementation (e.g.
    ///   [`ReqwestClient`](crate::ReqwestClient)).
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
    /// # use arctic_oauth::{Atlassian, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let atlassian = Atlassian::new("client-id", "secret", "https://example.com/cb");
    /// let http = ReqwestClient::new();
    ///
    /// let tokens = atlassian
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
        let body = vec![
            ("grant_type".to_string(), "authorization_code".to_string()),
            ("code".to_string(), code.to_string()),
            ("redirect_uri".to_string(), self.redirect_uri.clone()),
            ("client_id".to_string(), self.client_id.clone()),
            ("client_secret".to_string(), self.client_secret.clone()),
        ];

        let request = create_oauth2_request(&self.token_endpoint, &body);
        send_token_request(http_client, request).await
    }

    /// Refreshes an expired access token using a refresh token.
    ///
    /// Use this to obtain a new access token without user interaction. To receive a refresh
    /// token in the initial authorization, include the `offline_access` scope.
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
    /// # use arctic_oauth::{Atlassian, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let atlassian = Atlassian::new("client-id", "secret", "https://example.com/cb");
    /// let http = ReqwestClient::new();
    ///
    /// let new_tokens = atlassian
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
        let body = vec![
            ("grant_type".to_string(), "refresh_token".to_string()),
            ("refresh_token".to_string(), refresh_token.to_string()),
            ("client_id".to_string(), self.client_id.clone()),
            ("client_secret".to_string(), self.client_secret.clone()),
        ];

        let request = create_oauth2_request(&self.token_endpoint, &body);
        send_token_request(http_client, request).await
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
        let provider = Atlassian::new("cid", "secret", "https://app/cb");
        assert_eq!(provider.authorization_endpoint, AUTHORIZATION_ENDPOINT);
        assert_eq!(provider.token_endpoint, TOKEN_ENDPOINT);
    }

    #[test]
    fn name_returns_atlassian() {
        let provider = Atlassian::new("cid", "secret", "https://app/cb");
        assert_eq!(provider.name(), "Atlassian");
    }

    #[test]
    fn authorization_url_includes_audience_and_prompt() {
        let provider = Atlassian::new("cid", "secret", "https://app/cb");
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
        let provider = Atlassian::new("cid", "secret", "https://app/cb");
        let url = provider.authorization_url("state123", &[]);

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(!pairs.iter().any(|(k, _)| k == "scope"));
        assert!(pairs.contains(&("audience".into(), "api.atlassian.com".into())));
        assert!(pairs.contains(&("prompt".into(), "consent".into())));
    }

    #[tokio::test]
    async fn validate_authorization_code_sends_body_credentials() {
        let provider = Atlassian::with_endpoints(
            "cid",
            "secret",
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "atl-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);

        let tokens = provider
            .validate_authorization_code(&mock, "auth-code")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "atl-tok");

        let requests = mock.take_requests();
        assert_eq!(requests[0].url, "https://mock/token");
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
        let provider = Atlassian::with_endpoints(
            "cid",
            "secret",
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

        let tokens = provider
            .refresh_access_token(&mock, "refresh-tok")
            .await
            .unwrap();

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
