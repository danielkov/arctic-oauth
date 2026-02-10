use crate::error::Error;
use crate::http::HttpClient;
use crate::request::{create_oauth2_request, send_token_request};
use crate::tokens::OAuth2Tokens;

const AUTHORIZATION_ENDPOINT: &str = "https://account.box.com/api/oauth2/authorize";
const TOKEN_ENDPOINT: &str = "https://api.box.com/oauth2/token";
const REVOCATION_ENDPOINT: &str = "https://api.box.com/oauth2/revoke";

/// OAuth 2.0 client for [Box](https://developer.box.com/guides/authentication/oauth2/).
///
/// Box does not require PKCE. This client supports the authorization code flow including
/// token refresh and revocation.
///
/// # Setup
///
/// 1. Create an application in the [Box Developer Console](https://app.box.com/developers/console).
/// 2. Choose **Standard OAuth 2.0** as the authentication method.
/// 3. Obtain the **Client ID** and **Client Secret** from the Configuration tab.
/// 4. Set the **Redirect URI** to match the `redirect_uri` you pass to [`BoxOAuth::new`].
///
/// # Scopes
///
/// Box does not use traditional OAuth scopes. Instead, access is controlled by application
/// permissions configured in the Developer Console. Common permissions include:
///
/// | Permission | Description |
/// |-------|-------------|
/// | Read all files and folders | Access to user's Box content |
/// | Write all files and folders | Create and modify content |
/// | Manage users | Administer users (enterprise only) |
///
/// See the full list at <https://developer.box.com/guides/api-calls/permissions-and-errors/scopes/>.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{BoxOAuth, ReqwestClient, generate_state};
///
/// # async fn example() -> Result<(), arctic_oauth::Error> {
/// let box_oauth = BoxOAuth::new(
///     "your-client-id",
///     "your-client-secret",
///     "https://example.com/callback",
/// );
///
/// // Step 1: Generate CSRF state and redirect the user.
/// let state = generate_state();
/// let url = box_oauth.authorization_url(&state, &[]);
///
/// // Step 2: Exchange the authorization code for tokens.
/// let http = ReqwestClient::new();
/// let tokens = box_oauth
///     .validate_authorization_code(&http, "authorization-code")
///     .await?;
/// println!("Access token: {}", tokens.access_token()?);
///
/// // Step 3 (optional): Refresh an expired access token.
/// let refreshed = box_oauth
///     .refresh_access_token(&http, tokens.refresh_token()?)
///     .await?;
///
/// // Step 4 (optional): Revoke a token.
/// box_oauth.revoke_token(&http, tokens.access_token()?).await?;
/// # Ok(())
/// # }
/// ```
pub struct BoxOAuth {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    authorization_endpoint: String,
    token_endpoint: String,
    revocation_endpoint: String,
}

impl BoxOAuth {
    /// Creates a new Box OAuth 2.0 client configured with production endpoints.
    ///
    /// # Arguments
    ///
    /// * `client_id` - The OAuth 2.0 client ID from the Box Developer Console.
    /// * `client_secret` - The OAuth 2.0 client secret from the Box Developer Console.
    /// * `redirect_uri` - The URI Box will redirect to after authorization. Must match
    ///   the redirect URI configured in your application settings.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::BoxOAuth;
    ///
    /// let box_oauth = BoxOAuth::new(
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
            revocation_endpoint: REVOCATION_ENDPOINT.to_string(),
        }
    }
}

#[cfg(any(test, feature = "testing"))]
impl BoxOAuth {
    /// Creates a Box client with custom endpoint URLs.
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
    /// use arctic_oauth::BoxOAuth;
    ///
    /// let box_oauth = BoxOAuth::with_endpoints(
    ///     "test-client-id",
    ///     "test-secret",
    ///     "http://localhost/callback",
    ///     "http://localhost:8080/authorize",
    ///     "http://localhost:8080/token",
    ///     Some("http://localhost:8080/revoke"),
    /// );
    /// # }
    /// ```
    pub fn with_endpoints(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
        authorization_endpoint: &str,
        token_endpoint: &str,
        revocation_endpoint: Option<&str>,
    ) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri: redirect_uri.into(),
            authorization_endpoint: authorization_endpoint.to_string(),
            token_endpoint: token_endpoint.to_string(),
            revocation_endpoint: revocation_endpoint
                .unwrap_or(REVOCATION_ENDPOINT)
                .to_string(),
        }
    }
}

impl BoxOAuth {
    /// Returns the provider name (`"Box"`).
    pub fn name(&self) -> &'static str {
        "Box"
    }

    /// Builds the Box authorization URL that the user should be redirected to.
    ///
    /// The returned URL includes all required OAuth 2.0 parameters. Your application should
    /// store `state` in the user's session before redirecting to validate the callback.
    ///
    /// # Arguments
    ///
    /// * `state` - A CSRF token to prevent cross-site request forgery. Use
    ///   [`generate_state`](crate::generate_state) to create one.
    /// * `scopes` - Box does not use traditional OAuth scopes. Pass an empty array or specific
    ///   scopes if required by your application configuration.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{BoxOAuth, generate_state};
    ///
    /// let box_oauth = BoxOAuth::new("client-id", "client-secret", "https://example.com/cb");
    /// let state = generate_state();
    ///
    /// let url = box_oauth.authorization_url(&state, &[]);
    /// assert!(url.as_str().starts_with("https://account.box.com/"));
    /// ```
    pub fn authorization_url(&self, state: &str, scopes: &[&str]) -> url::Url {
        let mut url =
            url::Url::parse(&self.authorization_endpoint).expect("invalid authorization endpoint");
        {
            let mut params = url.query_pairs_mut();
            params.append_pair("response_type", "code");
            params.append_pair("client_id", &self.client_id);
            params.append_pair("state", state);
            if !scopes.is_empty() {
                params.append_pair("scope", &scopes.join(" "));
            }
            params.append_pair("redirect_uri", &self.redirect_uri);
        }
        url
    }

    /// Exchanges an authorization code for access and refresh tokens.
    ///
    /// Call this in your redirect URI handler after Box redirects back with a `code`
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
    /// Returns [`Error::OAuthRequest`] if Box rejects the code, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::{BoxOAuth, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let box_oauth = BoxOAuth::new("client-id", "secret", "https://example.com/cb");
    /// let http = ReqwestClient::new();
    ///
    /// let tokens = box_oauth
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
    /// Box access tokens typically expire after 60 minutes. If your initial token response
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
    /// # use arctic_oauth::{BoxOAuth, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let box_oauth = BoxOAuth::new("client-id", "secret", "https://example.com/cb");
    /// let http = ReqwestClient::new();
    ///
    /// let new_tokens = box_oauth
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

    /// Revokes an access token or refresh token.
    ///
    /// Use this when a user signs out or disconnects your application.
    ///
    /// # Arguments
    ///
    /// * `http_client` - An [`HttpClient`](crate::HttpClient) implementation.
    /// * `token` - The access token or refresh token to revoke.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedResponse`] if Box returns a non-200 status, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::{BoxOAuth, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let box_oauth = BoxOAuth::new("client-id", "secret", "https://example.com/cb");
    /// let http = ReqwestClient::new();
    ///
    /// box_oauth.revoke_token(&http, "token-to-revoke").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn revoke_token(
        &self,
        http_client: &(impl HttpClient + ?Sized),
        token: &str,
    ) -> Result<(), Error> {
        let body = vec![
            ("token".to_string(), token.to_string()),
            ("client_id".to_string(), self.client_id.clone()),
            ("client_secret".to_string(), self.client_secret.clone()),
        ];
        let request = create_oauth2_request(&self.revocation_endpoint, &body);
        let response = http_client.send(request).await?;
        match response.status {
            200 => Ok(()),
            status => Err(Error::UnexpectedResponse { status }),
        }
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
        let box_oauth = BoxOAuth::new("cid", "secret", "https://app/cb");
        assert_eq!(box_oauth.authorization_endpoint, AUTHORIZATION_ENDPOINT);
        assert_eq!(box_oauth.token_endpoint, TOKEN_ENDPOINT);
        assert_eq!(box_oauth.revocation_endpoint, REVOCATION_ENDPOINT);
    }

    #[test]
    fn name_returns_box() {
        let box_oauth = BoxOAuth::new("cid", "secret", "https://app/cb");
        assert_eq!(box_oauth.name(), "Box");
    }

    #[test]
    fn authorization_url_builds_correct_params() {
        let box_oauth = BoxOAuth::new("cid", "secret", "https://app/cb");
        let url = box_oauth.authorization_url("state123", &["root_readwrite"]);

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.contains(&("client_id".into(), "cid".into())));
        assert!(pairs.contains(&("state".into(), "state123".into())));
        assert!(pairs.contains(&("scope".into(), "root_readwrite".into())));
        assert!(pairs.contains(&("redirect_uri".into(), "https://app/cb".into())));
        assert!(!pairs.iter().any(|(k, _)| k == "code_challenge"));
    }

    #[tokio::test]
    async fn validate_authorization_code_sends_body_credentials() {
        let box_oauth = BoxOAuth::with_endpoints(
            "cid",
            "secret",
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
            None,
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "box-tok",
                "token_type": "Bearer",
                "expires_in": 3600
            }))
            .unwrap(),
        }]);

        let tokens = box_oauth
            .validate_authorization_code(&mock, "auth-code")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "box-tok");

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
        let box_oauth = BoxOAuth::with_endpoints(
            "cid",
            "secret",
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
            None,
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "new-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);

        let tokens = box_oauth
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

    #[tokio::test]
    async fn revoke_token_sends_body_credentials() {
        let box_oauth = BoxOAuth::with_endpoints(
            "cid",
            "secret",
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
            Some("https://mock/revoke"),
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: vec![],
        }]);

        let result = box_oauth.revoke_token(&mock, "tok-to-revoke").await;
        assert!(result.is_ok());

        let requests = mock.take_requests();
        assert_eq!(requests[0].url, "https://mock/revoke");
        assert!(get_header(&requests[0], "Authorization").is_none());
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("token".into(), "tok-to-revoke".into())));
        assert!(body.contains(&("client_id".into(), "cid".into())));
        assert!(body.contains(&("client_secret".into(), "secret".into())));
    }

    #[tokio::test]
    async fn revoke_token_non_200_returns_error() {
        let box_oauth = BoxOAuth::with_endpoints(
            "cid",
            "secret",
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
            Some("https://mock/revoke"),
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 503,
            body: vec![],
        }]);

        let result = box_oauth.revoke_token(&mock, "tok").await;
        assert!(matches!(
            result,
            Err(Error::UnexpectedResponse { status: 503 })
        ));
    }
}
