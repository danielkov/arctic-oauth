use crate::error::Error;
use crate::http::HttpClient;
use crate::request::{create_oauth2_request, send_token_request};
use crate::tokens::OAuth2Tokens;

const AUTHORIZATION_ENDPOINT: &str = "https://www.donationalerts.com/oauth/authorize";
const TOKEN_ENDPOINT: &str = "https://www.donationalerts.com/oauth/token";

/// OAuth 2.0 client for [DonationAlerts](https://www.donationalerts.com/apidoc#authorization).
///
/// DonationAlerts does not use PKCE or state parameters in the authorization flow.
/// This client supports the authorization code flow including token refresh but not
/// token revocation.
///
/// # Setup
///
/// 1. Register your application at the [DonationAlerts Application Management](https://www.donationalerts.com/application/clients) page.
/// 2. Obtain your Client ID and Client Secret from the application settings.
/// 3. Configure the redirect URI to match the `redirect_uri` you pass to [`DonationAlerts::new`].
///
/// # Scopes
///
/// DonationAlerts uses space-separated scopes. Common scopes include:
///
/// | Scope | Description |
/// |-------|-------------|
/// | `oauth-user-show` | Read user profile information |
/// | `oauth-donation-subscribe` | Subscribe to donation alerts |
/// | `oauth-donation-index` | Read donation history |
///
/// See the full list at <https://www.donationalerts.com/apidoc#authorization__scopes>.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{DonationAlerts, ReqwestClient};
///
/// # async fn example() -> Result<(), arctic_oauth::Error> {
/// let donation_alerts = DonationAlerts::new(
///     "your-client-id",
///     "your-client-secret",
///     "https://example.com/callback",
/// );
///
/// // Step 1: Redirect the user (no state or PKCE required).
/// let url = donation_alerts.authorization_url(&["oauth-user-show"]);
/// // Redirect to `url`.
///
/// // Step 2: In your callback handler, exchange the authorization code for tokens.
/// let http = ReqwestClient::new();
/// let tokens = donation_alerts
///     .validate_authorization_code(&http, "authorization-code")
///     .await?;
/// println!("Access token: {}", tokens.access_token()?);
///
/// // Step 3 (optional): Refresh an expired access token.
/// let refreshed = donation_alerts
///     .refresh_access_token(&http, tokens.refresh_token()?, &["oauth-user-show"])
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct DonationAlerts {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    authorization_endpoint: String,
    token_endpoint: String,
}

impl DonationAlerts {
    /// Creates a new DonationAlerts OAuth 2.0 client configured with production endpoints.
    ///
    /// # Arguments
    ///
    /// * `client_id` - The OAuth 2.0 client ID from DonationAlerts application settings.
    /// * `client_secret` - The OAuth 2.0 client secret from DonationAlerts application settings.
    /// * `redirect_uri` - The URI DonationAlerts will redirect to after authorization. Must match
    ///   the redirect URI configured in your DonationAlerts application.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::DonationAlerts;
    ///
    /// let donation_alerts = DonationAlerts::new(
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
impl DonationAlerts {
    /// Creates a DonationAlerts client with custom endpoint URLs.
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
    /// use arctic_oauth::DonationAlerts;
    ///
    /// let donation_alerts = DonationAlerts::with_endpoints(
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

impl DonationAlerts {
    /// Returns the provider name (`"DonationAlerts"`).
    pub fn name(&self) -> &'static str {
        "DonationAlerts"
    }

    /// Builds the DonationAlerts authorization URL that the user should be redirected to.
    ///
    /// DonationAlerts does not use state or PKCE parameters. The scope parameter is always
    /// included in the URL, even when empty.
    ///
    /// # Arguments
    ///
    /// * `scopes` - The OAuth 2.0 scopes to request (e.g. `&["oauth-user-show"]`).
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::DonationAlerts;
    ///
    /// let donation_alerts = DonationAlerts::new("client-id", "secret", "https://example.com/cb");
    /// let url = donation_alerts.authorization_url(&["oauth-user-show"]);
    /// assert!(url.as_str().starts_with("https://www.donationalerts.com/"));
    /// ```
    pub fn authorization_url(&self, scopes: &[&str]) -> url::Url {
        let mut url = url::Url::parse(&self.authorization_endpoint)
            .expect("invalid authorization endpoint URL");

        {
            let mut params = url.query_pairs_mut();
            params.append_pair("response_type", "code");
            params.append_pair("client_id", &self.client_id);
            // Scope always sent, even if empty
            params.append_pair("scope", &scopes.join(" "));
            params.append_pair("redirect_uri", &self.redirect_uri);
        }

        url
    }

    /// Exchanges an authorization code for access and refresh tokens.
    ///
    /// Call this in your redirect URI handler after DonationAlerts redirects back with a `code`
    /// query parameter. Credentials are sent in the POST body (not via Basic auth).
    ///
    /// # Arguments
    ///
    /// * `http_client` - An [`HttpClient`](crate::HttpClient) implementation (e.g.
    ///   [`ReqwestClient`](crate::ReqwestClient)).
    /// * `code` - The authorization code from the `code` query parameter.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OAuthRequest`] if DonationAlerts rejects the code, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::{DonationAlerts, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let donation_alerts = DonationAlerts::new("client-id", "secret", "https://example.com/cb");
    /// let http = ReqwestClient::new();
    ///
    /// let tokens = donation_alerts
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
    /// DonationAlerts requires scopes to be included in the refresh request. The scope parameter
    /// is always sent in the body, even when empty.
    ///
    /// # Arguments
    ///
    /// * `http_client` - An [`HttpClient`](crate::HttpClient) implementation.
    /// * `refresh_token` - The refresh token from a previous token response.
    /// * `scopes` - The OAuth 2.0 scopes to request in the refreshed token.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OAuthRequest`] if the refresh token is invalid or revoked, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::{DonationAlerts, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let donation_alerts = DonationAlerts::new("client-id", "secret", "https://example.com/cb");
    /// let http = ReqwestClient::new();
    ///
    /// let new_tokens = donation_alerts
    ///     .refresh_access_token(&http, "stored-refresh-token", &["oauth-user-show"])
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
        scopes: &[&str],
    ) -> Result<OAuth2Tokens, Error> {
        let mut body = vec![
            ("grant_type".to_string(), "refresh_token".to_string()),
            ("refresh_token".to_string(), refresh_token.to_string()),
            ("client_id".to_string(), self.client_id.clone()),
            ("client_secret".to_string(), self.client_secret.clone()),
        ];

        body.push(("scope".to_string(), scopes.join(" ")));

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
        let provider = DonationAlerts::new("cid", "secret", "https://app/cb");
        assert_eq!(provider.authorization_endpoint, AUTHORIZATION_ENDPOINT);
        assert_eq!(provider.token_endpoint, TOKEN_ENDPOINT);
    }

    #[test]
    fn name_returns_donation_alerts() {
        let provider = DonationAlerts::new("cid", "secret", "https://app/cb");
        assert_eq!(provider.name(), "DonationAlerts");
    }

    #[test]
    fn authorization_url_has_no_state_param() {
        let provider = DonationAlerts::new("cid", "secret", "https://app/cb");
        let url = provider.authorization_url(&["oauth-donation-subscribe"]);

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.contains(&("client_id".into(), "cid".into())));
        assert!(pairs.contains(&("scope".into(), "oauth-donation-subscribe".into())));
        assert!(pairs.contains(&("redirect_uri".into(), "https://app/cb".into())));
        // No state parameter
        assert!(!pairs.iter().any(|(k, _)| k == "state"));
    }

    #[test]
    fn authorization_url_includes_empty_scope_when_no_scopes() {
        let provider = DonationAlerts::new("cid", "secret", "https://app/cb");
        let url = provider.authorization_url(&[]);

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("scope".into(), "".into())));
        assert!(!pairs.iter().any(|(k, _)| k == "state"));
    }

    #[tokio::test]
    async fn validate_authorization_code_sends_body_credentials() {
        let provider = DonationAlerts::with_endpoints(
            "cid",
            "secret",
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "da-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);

        let tokens = provider
            .validate_authorization_code(&mock, "auth-code")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "da-tok");

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
    async fn refresh_access_token_includes_scopes_in_body() {
        let provider = DonationAlerts::with_endpoints(
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
            .refresh_access_token(&mock, "refresh-tok", &["oauth-donation-subscribe"])
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
        assert!(body.contains(&("scope".into(), "oauth-donation-subscribe".into())));
    }

    #[tokio::test]
    async fn refresh_access_token_sends_empty_scope_when_no_scopes() {
        let provider = DonationAlerts::with_endpoints(
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

        provider
            .refresh_access_token(&mock, "refresh-tok", &[])
            .await
            .unwrap();

        let requests = mock.take_requests();
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("scope".into(), "".into())));
    }
}
