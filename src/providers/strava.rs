use crate::error::Error;
use crate::http::HttpClient;
use crate::request::{create_oauth2_request, send_token_request};
use crate::tokens::OAuth2Tokens;

const AUTHORIZATION_ENDPOINT: &str = "https://www.strava.com/oauth/authorize";
const TOKEN_ENDPOINT: &str = "https://www.strava.com/api/v3/oauth/token";

/// Configuration for creating a [`Strava`] client with a custom HTTP client.
///
/// Use this when you need to provide your own [`HttpClient`] implementation
/// (e.g. a pre-configured `reqwest::Client` with custom timeouts or proxies).
/// For the common case, use [`Strava::new`] which uses the built-in default client.
pub struct StravaOptions<'a, H: HttpClient> {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub http_client: &'a H,
}

/// OAuth 2.0 client for [Strava](https://developers.strava.com/docs/authentication/).
///
/// Strava uses the standard authorization code flow without requiring PKCE.
/// This client supports the full authorization code flow including token refresh.
/// Note that Strava uses comma-separated scopes instead of the standard space-separated format.
///
/// # Setup
///
/// 1. Create an application at [Strava API Settings](https://www.strava.com/settings/api).
/// 2. Note your client ID and client secret from the application page.
/// 3. Set the authorization callback domain to match the domain of the `redirect_uri` you pass to [`Strava::new`].
///
/// # Scopes
///
/// Strava uses comma-separated scopes. Common scopes include:
///
/// | Scope | Description |
/// |-------|-------------|
/// | `read` | Read public profile and activities |
/// | `read_all` | Read private activities |
/// | `activity:read` | Read activity data |
/// | `activity:write` | Create and modify activities |
///
/// See the full list at <https://developers.strava.com/docs/authentication/>.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{Strava, generate_state};
///
/// # async fn example() -> Result<(), arctic_oauth::Error> {
/// let strava = Strava::new(
///     "your-client-id",
///     "your-client-secret",
///     "https://example.com/callback",
/// );
///
/// // Step 1: Generate CSRF state and redirect the user.
/// let state = generate_state();
/// let url = strava.authorization_url(&state, &["read", "activity:read"]);
/// // Store `state` in the user's session, then redirect to `url`.
///
/// // Step 2: In your callback handler, exchange the authorization code for tokens.
/// let tokens = strava
///     .validate_authorization_code("authorization-code")
///     .await?;
/// println!("Access token: {}", tokens.access_token()?);
///
/// // Step 3 (optional): Refresh an expired access token.
/// let refreshed = strava
///     .refresh_access_token(tokens.refresh_token()?)
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct Strava<'a, H: HttpClient> {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    http_client: &'a H,
    authorization_endpoint: String,
    token_endpoint: String,
}

impl<'a, H: HttpClient> Strava<'a, H> {
    /// Creates a Strava client from a [`StravaOptions`] struct.
    ///
    /// Use this when you need a custom HTTP client. For the common case,
    /// use [`Strava::new`] instead.
    pub fn from_options(options: StravaOptions<'a, H>) -> Self {
        Self {
            client_id: options.client_id,
            client_secret: options.client_secret,
            redirect_uri: options.redirect_uri,
            http_client: options.http_client,
            authorization_endpoint: AUTHORIZATION_ENDPOINT.to_string(),
            token_endpoint: TOKEN_ENDPOINT.to_string(),
        }
    }
}

#[cfg(feature = "reqwest-client")]
impl Strava<'static, reqwest::Client> {
    /// Creates a new Strava OAuth 2.0 client using the default HTTP client.
    ///
    /// # Arguments
    ///
    /// * `client_id` - The OAuth 2.0 client ID from your Strava application settings.
    /// * `client_secret` - The OAuth 2.0 client secret from your Strava application settings.
    /// * `redirect_uri` - The URI Strava will redirect to after authorization. Must be on
    ///   the same domain as the authorization callback domain configured in your Strava application.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::Strava;
    ///
    /// let strava = Strava::new(
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
        Self::from_options(StravaOptions {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri: redirect_uri.into(),
            http_client: crate::http::default_client(),
        })
    }
}

impl<'a, H: HttpClient> Strava<'a, H> {
    /// Returns the provider name (`"Strava"`).
    pub fn name(&self) -> &'static str {
        "Strava"
    }

    /// Builds the Strava authorization URL that the user should be redirected to.
    ///
    /// The returned URL includes all required OAuth 2.0 parameters. Your application
    /// should store `state` in the user's session before redirecting, as it is needed
    /// to prevent CSRF attacks.
    ///
    /// Note: Strava uses comma-separated scopes, so the scopes array will be joined
    /// with commas instead of spaces.
    ///
    /// # Arguments
    ///
    /// * `state` - A CSRF token to prevent cross-site request forgery. Use
    ///   [`generate_state`](crate::generate_state) to create one.
    /// * `scopes` - The OAuth 2.0 scopes to request (e.g. `&["read", "activity:read"]`).
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{Strava, generate_state};
    ///
    /// let strava = Strava::new("client-id", "client-secret", "https://example.com/cb");
    /// let state = generate_state();
    ///
    /// let url = strava.authorization_url(&state, &["read", "activity:read"]);
    /// assert!(url.as_str().starts_with("https://www.strava.com/"));
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
                params.append_pair("scope", &scopes.join(","));
            }
            params.append_pair("redirect_uri", &self.redirect_uri);
        }
        url
    }

    /// Exchanges an authorization code for access and refresh tokens.
    ///
    /// Call this in your redirect URI handler after Strava redirects back with a `code`
    /// query parameter.
    ///
    /// # Arguments
    ///
    /// * `code` - The authorization code from the `code` query parameter.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OAuthRequest`] if Strava rejects the code, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::Strava;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let strava = Strava::new("client-id", "secret", "https://example.com/cb");
    ///
    /// let tokens = strava
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
    /// Strava access tokens typically expire after 6 hours. If your initial token response
    /// included a refresh token, you can use it to obtain a new access token without
    /// user interaction.
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
    /// # use arctic_oauth::Strava;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let strava = Strava::new("client-id", "secret", "https://example.com/cb");
    ///
    /// let new_tokens = strava
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

    fn make_strava(http_client: &MockHttpClient) -> Strava<'_, MockHttpClient> {
        Strava::from_options(StravaOptions {
            client_id: "cid".into(),
            client_secret: "secret".into(),
            redirect_uri: "https://app/cb".into(),
            http_client,
        })
    }

    #[test]
    fn new_sets_production_endpoints() {
        let mock = MockHttpClient::new(vec![]);
        let strava = make_strava(&mock);
        assert_eq!(strava.authorization_endpoint, AUTHORIZATION_ENDPOINT);
        assert_eq!(strava.token_endpoint, TOKEN_ENDPOINT);
    }

    #[test]
    fn name_returns_strava() {
        let mock = MockHttpClient::new(vec![]);
        let strava = make_strava(&mock);
        assert_eq!(strava.name(), "Strava");
    }

    #[test]
    fn authorization_url_scopes_are_comma_delimited() {
        let mock = MockHttpClient::new(vec![]);
        let strava = make_strava(&mock);
        let url = strava.authorization_url("state123", &["read", "activity:read"]);

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.contains(&("client_id".into(), "cid".into())));
        assert!(pairs.contains(&("state".into(), "state123".into())));
        assert!(pairs.contains(&("scope".into(), "read,activity:read".into())));
        assert!(pairs.contains(&("redirect_uri".into(), "https://app/cb".into())));
    }

    #[test]
    fn authorization_url_omits_scope_when_empty() {
        let mock = MockHttpClient::new(vec![]);
        let strava = make_strava(&mock);
        let url = strava.authorization_url("state123", &[]);

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(!pairs.iter().any(|(k, _)| k == "scope"));
    }

    #[tokio::test]
    async fn validate_authorization_code_sends_body_credentials() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "strava-tok",
                "token_type": "Bearer",
                "expires_in": 21600
            }))
            .unwrap(),
        }]);
        let strava = make_strava(&mock);

        let tokens = strava
            .validate_authorization_code("auth-code")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "strava-tok");

        let requests = mock.take_requests();
        assert_eq!(requests[0].url, TOKEN_ENDPOINT);
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
        let strava = make_strava(&mock);

        let tokens = strava.refresh_access_token("refresh-tok").await.unwrap();

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
