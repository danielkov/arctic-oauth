use crate::error::Error;
use crate::http::HttpClient;
use crate::pkce::{CodeChallengeMethod, create_code_challenge};
use crate::request::{create_oauth2_request, send_token_request};
use crate::tokens::OAuth2Tokens;

const AUTHORIZATION_ENDPOINT: &str = "https://polar.sh/oauth2/authorize";
const TOKEN_ENDPOINT: &str = "https://api.polar.sh/v1/oauth2/token";
const REVOCATION_ENDPOINT: &str = "https://api.polar.sh/v1/oauth2/revoke";

/// OAuth 2.0 client for [Polar](https://polar.sh/docs/api-reference/oauth2/connect/authorize).
///
/// Polar requires PKCE with the S256 challenge method on all authorization requests.
/// This client supports the full authorization code flow including token refresh and
/// revocation. The client secret is optional for public clients.
///
/// # Setup
///
/// 1. Create an application in your [Polar Settings](https://polar.sh/settings).
/// 2. Navigate to the OAuth section and create a new OAuth application.
/// 3. Copy your client ID and optionally your client secret.
/// 4. Configure the redirect URI to match what you pass to [`Polar::new`].
///
/// # Scopes
///
/// Polar uses space-separated scopes. Common scopes include:
///
/// | Scope | Description |
/// |-------|-------------|
/// | `openid` | OpenID Connect authentication |
/// | `profile` | Read user profile |
/// | `email` | Read user email address |
/// | `projects:read` | Read project information |
/// | `projects:write` | Write project information |
///
/// See the full list at <https://polar.sh/docs/api-reference/oauth2/connect/authorize>.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{Polar, ReqwestClient, generate_state, generate_code_verifier};
///
/// # async fn example() -> Result<(), arctic_oauth::Error> {
/// let polar = Polar::new(
///     "your-client-id",
///     Some("your-client-secret".into()),
///     "https://example.com/callback",
/// );
///
/// // Step 1: Generate PKCE verifier and CSRF state, then redirect the user.
/// let state = generate_state();
/// let code_verifier = generate_code_verifier();
/// let url = polar.authorization_url(&state, &["openid", "profile"], &code_verifier);
/// // Store `state` and `code_verifier` in the user's session, then redirect to `url`.
///
/// // Step 2: In your callback handler, exchange the authorization code for tokens.
/// let http = ReqwestClient::new();
/// let tokens = polar
///     .validate_authorization_code(&http, "authorization-code", &code_verifier)
///     .await?;
/// println!("Access token: {}", tokens.access_token()?);
///
/// // Step 3 (optional): Refresh an expired access token.
/// let refreshed = polar
///     .refresh_access_token(&http, tokens.refresh_token()?)
///     .await?;
///
/// // Step 4 (optional): Revoke a token.
/// polar.revoke_token(&http, tokens.access_token()?).await?;
/// # Ok(())
/// # }
/// ```
pub struct Polar {
    client_id: String,
    client_secret: Option<String>,
    redirect_uri: String,
    authorization_endpoint: String,
    token_endpoint: String,
    revocation_endpoint: String,
}

impl Polar {
    /// Creates a new Polar OAuth 2.0 client configured with production endpoints.
    ///
    /// # Arguments
    ///
    /// * `client_id` - The client ID from your Polar OAuth application.
    /// * `client_secret` - The client secret (optional for public clients).
    /// * `redirect_uri` - The URI Polar will redirect to after authorization. Must match
    ///   the redirect URI configured in your Polar application.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::Polar;
    ///
    /// let polar = Polar::new(
    ///     "your-client-id",
    ///     Some("your-client-secret".into()),
    ///     "https://example.com/callback",
    /// );
    /// ```
    pub fn new(
        client_id: impl Into<String>,
        client_secret: Option<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret,
            redirect_uri: redirect_uri.into(),
            authorization_endpoint: AUTHORIZATION_ENDPOINT.to_string(),
            token_endpoint: TOKEN_ENDPOINT.to_string(),
            revocation_endpoint: REVOCATION_ENDPOINT.to_string(),
        }
    }
}

#[cfg(any(test, feature = "testing"))]
impl Polar {
    /// Creates a Polar client with custom endpoint URLs.
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
    /// use arctic_oauth::Polar;
    ///
    /// let polar = Polar::with_endpoints(
    ///     "test-client-id",
    ///     Some("test-secret".into()),
    ///     "http://localhost/callback",
    ///     "http://localhost:8080/authorize",
    ///     "http://localhost:8080/token",
    ///     Some("http://localhost:8080/revoke"),
    /// );
    /// # }
    /// ```
    pub fn with_endpoints(
        client_id: impl Into<String>,
        client_secret: Option<String>,
        redirect_uri: impl Into<String>,
        authorization_endpoint: &str,
        token_endpoint: &str,
        revocation_endpoint: Option<&str>,
    ) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret,
            redirect_uri: redirect_uri.into(),
            authorization_endpoint: authorization_endpoint.to_string(),
            token_endpoint: token_endpoint.to_string(),
            revocation_endpoint: revocation_endpoint
                .unwrap_or(REVOCATION_ENDPOINT)
                .to_string(),
        }
    }
}

impl Polar {
    /// Returns the provider name (`"Polar"`).
    pub fn name(&self) -> &'static str {
        "Polar"
    }

    /// Builds the Polar authorization URL that the user should be redirected to.
    ///
    /// The returned URL includes all required OAuth 2.0 and PKCE parameters. Your
    /// application should store `state` and `code_verifier` in the user's session
    /// before redirecting, as both are needed to complete the flow.
    ///
    /// # Arguments
    ///
    /// * `state` - A CSRF token to prevent cross-site request forgery. Use
    ///   [`generate_state`](crate::generate_state) to create one.
    /// * `scopes` - The OAuth 2.0 scopes to request (e.g. `&["openid", "profile"]`).
    /// * `code_verifier` - The PKCE code verifier. Use
    ///   [`generate_code_verifier`](crate::generate_code_verifier) to create one.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{Polar, generate_state, generate_code_verifier};
    ///
    /// let polar = Polar::new("client-id", Some("secret".into()), "https://example.com/cb");
    /// let state = generate_state();
    /// let verifier = generate_code_verifier();
    ///
    /// let url = polar.authorization_url(&state, &["openid", "profile"], &verifier);
    /// assert!(url.as_str().starts_with("https://polar.sh/"));
    /// ```
    pub fn authorization_url(&self, state: &str, scopes: &[&str], code_verifier: &str) -> url::Url {
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
            let challenge = create_code_challenge(code_verifier, CodeChallengeMethod::S256);
            params.append_pair("code_challenge", &challenge);
            params.append_pair("code_challenge_method", "S256");
        }
        url
    }

    /// Exchanges an authorization code for access and refresh tokens.
    ///
    /// Call this in your redirect URI handler after Polar redirects back with a `code`
    /// query parameter. The `code_verifier` must be the same value used to generate the
    /// authorization URL. The client credentials are sent in the request body.
    ///
    /// # Arguments
    ///
    /// * `http_client` - An [`HttpClient`](crate::HttpClient) implementation (e.g.
    ///   [`ReqwestClient`](crate::ReqwestClient)).
    /// * `code` - The authorization code from the `code` query parameter.
    /// * `code_verifier` - The PKCE code verifier stored during the authorization step.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OAuthRequest`] if Polar rejects the code, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::{Polar, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let polar = Polar::new("client-id", Some("secret".into()), "https://example.com/cb");
    /// let http = ReqwestClient::new();
    ///
    /// let tokens = polar
    ///     .validate_authorization_code(&http, "the-auth-code", "the-code-verifier")
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
        code_verifier: &str,
    ) -> Result<OAuth2Tokens, Error> {
        let mut body = vec![
            ("grant_type".to_string(), "authorization_code".to_string()),
            ("code".to_string(), code.to_string()),
            ("redirect_uri".to_string(), self.redirect_uri.clone()),
            ("client_id".to_string(), self.client_id.clone()),
            ("code_verifier".to_string(), code_verifier.to_string()),
        ];
        if let Some(ref secret) = self.client_secret {
            body.push(("client_secret".to_string(), secret.clone()));
        }
        let request = create_oauth2_request(&self.token_endpoint, &body);
        send_token_request(http_client, request).await
    }

    /// Refreshes an expired access token using a refresh token.
    ///
    /// Polar access tokens expire after a set period. If your initial token response
    /// included a refresh token, you can use it to obtain a new access token without
    /// user interaction. The client credentials are sent in the request body.
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
    /// # use arctic_oauth::{Polar, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let polar = Polar::new("client-id", Some("secret".into()), "https://example.com/cb");
    /// let http = ReqwestClient::new();
    ///
    /// let new_tokens = polar
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
        let mut body = vec![
            ("grant_type".to_string(), "refresh_token".to_string()),
            ("refresh_token".to_string(), refresh_token.to_string()),
            ("client_id".to_string(), self.client_id.clone()),
        ];
        if let Some(ref secret) = self.client_secret {
            body.push(("client_secret".to_string(), secret.clone()));
        }
        let request = create_oauth2_request(&self.token_endpoint, &body);
        send_token_request(http_client, request).await
    }

    /// Revokes an access token or refresh token.
    ///
    /// Use this when a user signs out or disconnects your application. The client
    /// credentials are sent in the request body.
    ///
    /// # Arguments
    ///
    /// * `http_client` - An [`HttpClient`](crate::HttpClient) implementation.
    /// * `token` - The access token or refresh token to revoke.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedResponse`] if Polar returns a non-200 status, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::{Polar, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let polar = Polar::new("client-id", Some("secret".into()), "https://example.com/cb");
    /// let http = ReqwestClient::new();
    ///
    /// polar.revoke_token(&http, "token-to-revoke").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn revoke_token(
        &self,
        http_client: &(impl HttpClient + ?Sized),
        token: &str,
    ) -> Result<(), Error> {
        let mut body = vec![
            ("token".to_string(), token.to_string()),
            ("client_id".to_string(), self.client_id.clone()),
        ];
        if let Some(ref secret) = self.client_secret {
            body.push(("client_secret".to_string(), secret.clone()));
        }
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
        let polar = Polar::new("cid", Some("secret".into()), "https://app/cb");
        assert_eq!(polar.authorization_endpoint, AUTHORIZATION_ENDPOINT);
        assert_eq!(polar.token_endpoint, TOKEN_ENDPOINT);
        assert_eq!(polar.revocation_endpoint, REVOCATION_ENDPOINT);
    }

    #[test]
    fn name_returns_polar() {
        let polar = Polar::new("cid", Some("secret".into()), "https://app/cb");
        assert_eq!(polar.name(), "Polar");
    }

    #[test]
    fn authorization_url_includes_pkce_params() {
        let polar = Polar::new("cid", Some("secret".into()), "https://app/cb");
        let url = polar.authorization_url("state123", &["read"], "my-verifier");

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.contains(&("client_id".into(), "cid".into())));
        assert!(pairs.contains(&("state".into(), "state123".into())));
        assert!(pairs.contains(&("scope".into(), "read".into())));
        assert!(pairs.contains(&("redirect_uri".into(), "https://app/cb".into())));
        assert!(pairs.iter().any(|(k, _)| k == "code_challenge"));
        assert!(pairs.contains(&("code_challenge_method".into(), "S256".into())));
    }

    #[tokio::test]
    async fn validate_authorization_code_with_secret() {
        let polar = Polar::with_endpoints(
            "cid",
            Some("secret".into()),
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
            None,
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "polar-tok",
                "token_type": "Bearer",
                "expires_in": 3600
            }))
            .unwrap(),
        }]);

        let tokens = polar
            .validate_authorization_code(&mock, "auth-code", "my-verifier")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "polar-tok");

        let requests = mock.take_requests();
        assert!(get_header(&requests[0], "Authorization").is_none());

        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("grant_type".into(), "authorization_code".into())));
        assert!(body.contains(&("code".into(), "auth-code".into())));
        assert!(body.contains(&("client_id".into(), "cid".into())));
        assert!(body.contains(&("client_secret".into(), "secret".into())));
        assert!(body.contains(&("code_verifier".into(), "my-verifier".into())));
    }

    #[tokio::test]
    async fn validate_authorization_code_without_secret() {
        let polar = Polar::with_endpoints(
            "cid",
            None,
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
            None,
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "polar-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);

        polar
            .validate_authorization_code(&mock, "auth-code", "my-verifier")
            .await
            .unwrap();

        let requests = mock.take_requests();
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("client_id".into(), "cid".into())));
        assert!(!body.iter().any(|(k, _)| k == "client_secret"));
        assert!(body.contains(&("code_verifier".into(), "my-verifier".into())));
    }

    #[tokio::test]
    async fn refresh_access_token_with_secret() {
        let polar = Polar::with_endpoints(
            "cid",
            Some("secret".into()),
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

        let tokens = polar
            .refresh_access_token(&mock, "refresh-tok")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "new-tok");

        let requests = mock.take_requests();
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("grant_type".into(), "refresh_token".into())));
        assert!(body.contains(&("client_id".into(), "cid".into())));
        assert!(body.contains(&("client_secret".into(), "secret".into())));
    }

    #[tokio::test]
    async fn refresh_access_token_without_secret() {
        let polar = Polar::with_endpoints(
            "cid",
            None,
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

        polar
            .refresh_access_token(&mock, "refresh-tok")
            .await
            .unwrap();

        let requests = mock.take_requests();
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("client_id".into(), "cid".into())));
        assert!(!body.iter().any(|(k, _)| k == "client_secret"));
    }

    #[tokio::test]
    async fn revoke_token_with_secret() {
        let polar = Polar::with_endpoints(
            "cid",
            Some("secret".into()),
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
            Some("https://mock/revoke"),
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: vec![],
        }]);

        let result = polar.revoke_token(&mock, "tok-to-revoke").await;
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
    async fn revoke_token_without_secret() {
        let polar = Polar::with_endpoints(
            "cid",
            None,
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
            Some("https://mock/revoke"),
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: vec![],
        }]);

        let result = polar.revoke_token(&mock, "tok-to-revoke").await;
        assert!(result.is_ok());

        let requests = mock.take_requests();
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("token".into(), "tok-to-revoke".into())));
        assert!(body.contains(&("client_id".into(), "cid".into())));
        assert!(!body.iter().any(|(k, _)| k == "client_secret"));
    }

    #[tokio::test]
    async fn revoke_token_non_200_returns_error() {
        let polar = Polar::with_endpoints(
            "cid",
            Some("secret".into()),
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
            Some("https://mock/revoke"),
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 503,
            body: vec![],
        }]);

        let result = polar.revoke_token(&mock, "tok").await;
        assert!(matches!(
            result,
            Err(Error::UnexpectedResponse { status: 503 })
        ));
    }
}
