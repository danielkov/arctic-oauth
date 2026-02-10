use crate::error::Error;
use crate::http::HttpClient;
use crate::request::{create_oauth2_request, send_token_request};
use crate::tokens::OAuth2Tokens;

const AUTHORIZATION_ENDPOINT: &str = "https://osu.ppy.sh/oauth/authorize";
const TOKEN_ENDPOINT: &str = "https://osu.ppy.sh/oauth/token";

/// OAuth 2.0 client for [osu!](https://osu.ppy.sh/docs/index.html#authentication).
///
/// osu! does not require PKCE for authorization requests. This client supports the standard
/// authorization code flow including token refresh. The redirect URI is optional for osu!
/// and credentials are sent in the request body rather than via HTTP Basic authentication.
///
/// # Setup
///
/// 1. Register an OAuth application at [osu! Account Settings](https://osu.ppy.sh/home/account/edit#oauth).
/// 2. Obtain your client ID and client secret from the application details.
/// 3. If using a redirect URI, set the Application Callback URL to match the `redirect_uri` you pass to [`Osu::new`].
///
/// # Scopes
///
/// osu! uses space-separated scopes. Common scopes include:
///
/// | Scope | Description |
/// |-------|-------------|
/// | `identify` | Read user's public profile |
/// | `public` | Access public data (default) |
/// | `friends.read` | Read user's friends list |
/// | `forum.write` | Post to forums on behalf of user |
///
/// See the full list at <https://osu.ppy.sh/docs/index.html#scopes>.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{Osu, ReqwestClient, generate_state};
///
/// # async fn example() -> Result<(), arctic_oauth::Error> {
/// let osu = Osu::new(
///     "your-client-id",
///     "your-client-secret",
///     Some("https://example.com/callback".into()),
/// );
///
/// // Step 1: Generate CSRF state, then redirect the user.
/// let state = generate_state();
/// let url = osu.authorization_url(&state, &["identify", "public"]);
/// // Store `state` in the user's session, then redirect to `url`.
///
/// // Step 2: In your callback handler, exchange the authorization code for tokens.
/// let http = ReqwestClient::new();
/// let tokens = osu
///     .validate_authorization_code(&http, "authorization-code")
///     .await?;
/// println!("Access token: {}", tokens.access_token()?);
///
/// // Step 3 (optional): Refresh an expired access token.
/// let refreshed = osu
///     .refresh_access_token(&http, tokens.refresh_token()?)
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct Osu {
    client_id: String,
    client_secret: String,
    redirect_uri: Option<String>,
    authorization_endpoint: String,
    token_endpoint: String,
}

impl Osu {
    /// Creates a new osu! OAuth 2.0 client configured with production endpoints.
    ///
    /// # Arguments
    ///
    /// * `client_id` - The OAuth 2.0 client ID from osu! Account Settings.
    /// * `client_secret` - The OAuth 2.0 client secret from osu! Account Settings.
    /// * `redirect_uri` - Optional redirect URI. If provided, must match the Application
    ///   Callback URL configured in your osu! application. Pass `None` if not using a redirect URI.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::Osu;
    ///
    /// let osu = Osu::new(
    ///     "your-client-id",
    ///     "your-client-secret",
    ///     Some("https://example.com/callback".into()),
    /// );
    /// ```
    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: Option<String>,
    ) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri,
            authorization_endpoint: AUTHORIZATION_ENDPOINT.to_string(),
            token_endpoint: TOKEN_ENDPOINT.to_string(),
        }
    }
}

#[cfg(any(test, feature = "testing"))]
impl Osu {
    /// Creates an osu! client with custom endpoint URLs.
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
    /// use arctic_oauth::Osu;
    ///
    /// let osu = Osu::with_endpoints(
    ///     "test-client-id",
    ///     "test-secret",
    ///     Some("http://localhost/callback".into()),
    ///     "http://localhost:8080/authorize",
    ///     "http://localhost:8080/token",
    /// );
    /// # }
    /// ```
    pub fn with_endpoints(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: Option<String>,
        authorization_endpoint: &str,
        token_endpoint: &str,
    ) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri,
            authorization_endpoint: authorization_endpoint.to_string(),
            token_endpoint: token_endpoint.to_string(),
        }
    }
}

impl Osu {
    /// Returns the provider name (`"osu!"`).
    pub fn name(&self) -> &'static str {
        "osu!"
    }

    /// Builds the osu! authorization URL that the user should be redirected to.
    ///
    /// The returned URL includes all required OAuth 2.0 parameters. Your application
    /// should store `state` in the user's session before redirecting, as it is needed
    /// to prevent CSRF attacks. The redirect URI is included only if it was provided
    /// to [`Osu::new`].
    ///
    /// # Arguments
    ///
    /// * `state` - A CSRF token to prevent cross-site request forgery. Use
    ///   [`generate_state`](crate::generate_state) to create one.
    /// * `scopes` - The OAuth 2.0 scopes to request (e.g. `&["identify", "public"]`).
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{Osu, generate_state};
    ///
    /// let osu = Osu::new("client-id", "client-secret", Some("https://example.com/cb".into()));
    /// let state = generate_state();
    ///
    /// let url = osu.authorization_url(&state, &["identify"]);
    /// assert!(url.as_str().starts_with("https://osu.ppy.sh/"));
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
            if let Some(ref redirect_uri) = self.redirect_uri {
                params.append_pair("redirect_uri", redirect_uri);
            }
        }
        url
    }

    /// Exchanges an authorization code for access and refresh tokens.
    ///
    /// Call this in your redirect URI handler after osu! redirects back with a `code`
    /// query parameter.
    ///
    /// # Arguments
    ///
    /// * `http_client` - An [`HttpClient`](crate::HttpClient) implementation (e.g.
    ///   [`ReqwestClient`](crate::ReqwestClient)).
    /// * `code` - The authorization code from the `code` query parameter.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OAuthRequest`] if osu! rejects the code, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::{Osu, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let osu = Osu::new("client-id", "secret", Some("https://example.com/cb".into()));
    /// let http = ReqwestClient::new();
    ///
    /// let tokens = osu
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
        let mut body = vec![
            ("grant_type".to_string(), "authorization_code".to_string()),
            ("code".to_string(), code.to_string()),
            ("client_id".to_string(), self.client_id.clone()),
            ("client_secret".to_string(), self.client_secret.clone()),
        ];
        if let Some(ref redirect_uri) = self.redirect_uri {
            body.push(("redirect_uri".to_string(), redirect_uri.clone()));
        }
        let request = create_oauth2_request(&self.token_endpoint, &body);
        send_token_request(http_client, request).await
    }

    /// Refreshes an expired access token using a refresh token.
    ///
    /// osu! access tokens typically expire after 24 hours. If your initial token response
    /// included a refresh token, you can use it to obtain a new access token without user
    /// interaction.
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
    /// # use arctic_oauth::{Osu, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let osu = Osu::new("client-id", "secret", Some("https://example.com/cb".into()));
    /// let http = ReqwestClient::new();
    ///
    /// let new_tokens = osu
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
        let osu = Osu::new("cid", "secret", None);
        assert_eq!(osu.authorization_endpoint, AUTHORIZATION_ENDPOINT);
        assert_eq!(osu.token_endpoint, TOKEN_ENDPOINT);
    }

    #[test]
    fn with_endpoints_overrides_urls() {
        let osu = Osu::with_endpoints(
            "cid",
            "secret",
            None,
            "https://mock/authorize",
            "https://mock/token",
        );
        assert_eq!(osu.authorization_endpoint, "https://mock/authorize");
        assert_eq!(osu.token_endpoint, "https://mock/token");
    }

    #[test]
    fn name_returns_osu() {
        let osu = Osu::new("cid", "secret", None);
        assert_eq!(osu.name(), "osu!");
    }

    #[test]
    fn authorization_url_with_redirect_uri() {
        let osu = Osu::new("cid", "secret", Some("https://app/cb".into()));
        let url = osu.authorization_url("state123", &["public", "identify"]);

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.contains(&("client_id".into(), "cid".into())));
        assert!(pairs.contains(&("state".into(), "state123".into())));
        assert!(pairs.contains(&("scope".into(), "public identify".into())));
        assert!(pairs.contains(&("redirect_uri".into(), "https://app/cb".into())));
    }

    #[test]
    fn authorization_url_omits_redirect_uri_when_none() {
        let osu = Osu::new("cid", "secret", None);
        let url = osu.authorization_url("state123", &["public"]);

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.contains(&("client_id".into(), "cid".into())));
        assert!(!pairs.iter().any(|(k, _)| k == "redirect_uri"));
    }

    #[test]
    fn authorization_url_omits_scope_when_empty() {
        let osu = Osu::new("cid", "secret", None);
        let url = osu.authorization_url("state123", &[]);

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(!pairs.iter().any(|(k, _)| k == "scope"));
    }

    #[tokio::test]
    async fn validate_authorization_code_sends_body_credentials_with_redirect_uri() {
        let osu = Osu::with_endpoints(
            "cid",
            "secret",
            Some("https://app/cb".into()),
            "https://mock/authorize",
            "https://mock/token",
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "osu-tok",
                "token_type": "Bearer",
                "expires_in": 86400
            }))
            .unwrap(),
        }]);

        let tokens = osu
            .validate_authorization_code(&mock, "auth-code")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "osu-tok");

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
    async fn validate_authorization_code_omits_redirect_uri_when_none() {
        let osu = Osu::with_endpoints(
            "cid",
            "secret",
            None,
            "https://mock/authorize",
            "https://mock/token",
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "osu-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);

        osu.validate_authorization_code(&mock, "auth-code")
            .await
            .unwrap();

        let requests = mock.take_requests();
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("grant_type".into(), "authorization_code".into())));
        assert!(body.contains(&("code".into(), "auth-code".into())));
        assert!(body.contains(&("client_id".into(), "cid".into())));
        assert!(body.contains(&("client_secret".into(), "secret".into())));
        assert!(!body.iter().any(|(k, _)| k == "redirect_uri"));
    }

    #[tokio::test]
    async fn refresh_access_token_sends_body_credentials() {
        let osu = Osu::with_endpoints(
            "cid",
            "secret",
            Some("https://app/cb".into()),
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

        let tokens = osu
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
