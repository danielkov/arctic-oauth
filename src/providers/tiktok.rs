use crate::error::Error;
use crate::http::HttpClient;
use crate::pkce::{CodeChallengeMethod, create_code_challenge};
use crate::request::create_oauth2_request;
use crate::tokens::OAuth2Tokens;

const AUTHORIZATION_ENDPOINT: &str = "https://www.tiktok.com/v2/auth/authorize/";
const TOKEN_ENDPOINT: &str = "https://open.tiktokapis.com/v2/oauth/token/";
const REVOCATION_ENDPOINT: &str = "https://open.tiktokapis.com/v2/oauth/revoke/";

/// Configuration for creating a [`TikTok`] client with a custom HTTP client.
pub struct TikTokOptions<'a, H: HttpClient> {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub http_client: &'a H,
}

/// OAuth 2.0 client for [TikTok for Developers](https://developers.tiktok.com/).
///
/// TikTok requires PKCE with the S256 challenge method on all authorization requests
/// and uses `client_key` instead of the standard `client_id` parameter. TikTok also
/// returns errors with HTTP 200 status codes, which this client handles automatically.
/// This client supports the full authorization code flow including token refresh and revocation.
///
/// # Setup
///
/// 1. Create a TikTok for Developers account at <https://developers.tiktok.com/>.
/// 2. Create a new app in the [TikTok Developer Portal](https://developers.tiktok.com/apps).
/// 3. Note your **Client Key** (this is your `client_id`) and **Client Secret**.
/// 4. Configure the **Redirect URI** in your app settings to match the `redirect_uri` you pass to [`TikTok::new`].
/// 5. Add the required scopes/permissions to your app.
///
/// # Scopes
///
/// TikTok uses comma-separated scopes. Common scopes include:
///
/// | Scope | Description |
/// |-------|-------------|
/// | `user.info.basic` | User's basic profile information |
/// | `video.list` | List user's videos |
/// | `video.upload` | Upload videos on behalf of the user |
///
/// See the full list at <https://developers.tiktok.com/doc/login-kit-manage-user-access-tokens>.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{TikTok, generate_state, generate_code_verifier};
///
/// # async fn example() -> Result<(), arctic_oauth::Error> {
/// let tiktok = TikTok::new(
///     "your-client-key",
///     "your-client-secret",
///     "https://example.com/callback",
/// );
///
/// // Step 1: Generate PKCE verifier and CSRF state, then redirect the user.
/// let state = generate_state();
/// let code_verifier = generate_code_verifier();
/// let url = tiktok.authorization_url(&state, &["user.info.basic", "video.list"], &code_verifier);
/// // Store `state` and `code_verifier` in the user's session, then redirect to `url`.
///
/// // Step 2: In your callback handler, exchange the authorization code for tokens.
/// let tokens = tiktok
///     .validate_authorization_code("authorization-code", &code_verifier)
///     .await?;
/// println!("Access token: {}", tokens.access_token()?);
///
/// // Step 3 (optional): Refresh an expired access token.
/// let refreshed = tiktok
///     .refresh_access_token(tokens.refresh_token()?)
///     .await?;
///
/// // Step 4 (optional): Revoke a token.
/// tiktok.revoke_token(tokens.access_token()?).await?;
/// # Ok(())
/// # }
/// ```
pub struct TikTok<'a, H: HttpClient> {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    http_client: &'a H,
    authorization_endpoint: String,
    token_endpoint: String,
    revocation_endpoint: String,
}

impl<'a, H: HttpClient> TikTok<'a, H> {
    /// Creates a TikTok client from a [`TikTokOptions`] struct.
    pub fn from_options(options: TikTokOptions<'a, H>) -> Self {
        Self {
            client_id: options.client_id,
            client_secret: options.client_secret,
            redirect_uri: options.redirect_uri,
            http_client: options.http_client,
            authorization_endpoint: AUTHORIZATION_ENDPOINT.to_string(),
            token_endpoint: TOKEN_ENDPOINT.to_string(),
            revocation_endpoint: REVOCATION_ENDPOINT.to_string(),
        }
    }
}

#[cfg(feature = "reqwest-client")]
impl TikTok<'static, reqwest::Client> {
    /// Creates a new TikTok OAuth 2.0 client using the default HTTP client.
    ///
    /// # Arguments
    ///
    /// * `client_id` - The Client Key from TikTok Developer Portal.
    /// * `client_secret` - The Client Secret from TikTok Developer Portal.
    /// * `redirect_uri` - The URI TikTok will redirect to after authorization. Must match
    ///   one of the redirect URIs configured in your TikTok app settings.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::TikTok;
    ///
    /// let tiktok = TikTok::new(
    ///     "your-client-key",
    ///     "your-client-secret",
    ///     "https://example.com/callback",
    /// );
    /// ```
    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        Self::from_options(TikTokOptions {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri: redirect_uri.into(),
            http_client: crate::http::default_client(),
        })
    }
}

impl<'a, H: HttpClient> TikTok<'a, H> {
    /// Returns the provider name (`"TikTok"`).
    pub fn name(&self) -> &'static str {
        "TikTok"
    }

    /// Builds the TikTok authorization URL that the user should be redirected to.
    ///
    /// The returned URL includes all required OAuth 2.0 and PKCE parameters. Note that
    /// TikTok uses comma-separated scopes and includes a `scope` parameter even when
    /// the scope list is empty. Your application should store `state` and `code_verifier`
    /// in the user's session before redirecting, as both are needed to complete the flow.
    ///
    /// # Arguments
    ///
    /// * `state` - A CSRF token to prevent cross-site request forgery. Use
    ///   [`generate_state`](crate::generate_state) to create one.
    /// * `scopes` - The OAuth 2.0 scopes to request (e.g. `&["user.info.basic", "video.list"]`).
    /// * `code_verifier` - The PKCE code verifier. Use
    ///   [`generate_code_verifier`](crate::generate_code_verifier) to create one.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{TikTok, generate_state, generate_code_verifier};
    ///
    /// let tiktok = TikTok::new("client-key", "client-secret", "https://example.com/cb");
    /// let state = generate_state();
    /// let verifier = generate_code_verifier();
    ///
    /// let url = tiktok.authorization_url(&state, &["user.info.basic"], &verifier);
    /// assert!(url.as_str().starts_with("https://www.tiktok.com/"));
    /// ```
    pub fn authorization_url(&self, state: &str, scopes: &[&str], code_verifier: &str) -> url::Url {
        let mut url = url::Url::parse(&self.authorization_endpoint)
            .expect("invalid authorization endpoint URL");
        {
            let mut params = url.query_pairs_mut();
            params.append_pair("response_type", "code");
            // TikTok uses client_key instead of client_id
            params.append_pair("client_key", &self.client_id);
            params.append_pair("state", state);
            // TikTok always sends scope, even when empty; comma-delimited
            params.append_pair("scope", &scopes.join(","));
            params.append_pair("redirect_uri", &self.redirect_uri);
            let challenge = create_code_challenge(code_verifier, CodeChallengeMethod::S256);
            params.append_pair("code_challenge", &challenge);
            params.append_pair("code_challenge_method", "S256");
        }
        url
    }

    /// Exchanges an authorization code for access and refresh tokens.
    ///
    /// Call this in your redirect URI handler after TikTok redirects back with a `code`
    /// query parameter. The `code_verifier` must be the same value used to generate the
    /// authorization URL. This method handles TikTok's non-standard error responses
    /// (errors returned with HTTP 200 status).
    ///
    /// # Arguments
    ///
    /// * `code` - The authorization code from the `code` query parameter.
    /// * `code_verifier` - The PKCE code verifier stored during the authorization step.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OAuthRequest`] if TikTok rejects the code, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::TikTok;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let tiktok = TikTok::new("client-key", "secret", "https://example.com/cb");
    ///
    /// let tokens = tiktok
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
        let body = vec![
            ("grant_type".to_string(), "authorization_code".to_string()),
            ("code".to_string(), code.to_string()),
            ("redirect_uri".to_string(), self.redirect_uri.clone()),
            // TikTok uses client_key instead of client_id
            ("client_key".to_string(), self.client_id.clone()),
            ("client_secret".to_string(), self.client_secret.clone()),
            ("code_verifier".to_string(), code_verifier.to_string()),
        ];
        let request = create_oauth2_request(&self.token_endpoint, &body);
        self.parse_token_response(request).await
    }

    /// Refreshes an expired access token using a refresh token.
    ///
    /// TikTok access tokens expire after a period determined by the API. If your initial
    /// token response included a refresh token, you can use it to obtain a new access
    /// token without user interaction. This method handles TikTok's non-standard error
    /// responses (errors returned with HTTP 200 status).
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
    /// # use arctic_oauth::TikTok;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let tiktok = TikTok::new("client-key", "secret", "https://example.com/cb");
    ///
    /// let new_tokens = tiktok
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
            ("client_key".to_string(), self.client_id.clone()),
            ("client_secret".to_string(), self.client_secret.clone()),
        ];
        let request = create_oauth2_request(&self.token_endpoint, &body);
        self.parse_token_response(request).await
    }

    /// Revokes an access token or refresh token.
    ///
    /// Use this when a user signs out or disconnects your application. TikTok
    /// requires the token to be sent in the POST form body along with the client
    /// credentials.
    ///
    /// # Arguments
    ///
    /// * `token` - The access token or refresh token to revoke.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedResponse`] if TikTok returns a non-200 status, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::TikTok;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let tiktok = TikTok::new("client-key", "secret", "https://example.com/cb");
    ///
    /// tiktok.revoke_token("token-to-revoke").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn revoke_token(&self, token: &str) -> Result<(), Error> {
        let body = vec![
            ("token".to_string(), token.to_string()),
            ("client_key".to_string(), self.client_id.clone()),
            ("client_secret".to_string(), self.client_secret.clone()),
        ];
        let request = create_oauth2_request(&self.revocation_endpoint, &body);
        let response = self.http_client.send(request).await?;
        match response.status {
            200 => Ok(()),
            status => Err(Error::UnexpectedResponse { status }),
        }
    }

    /// TikTok returns errors with HTTP 200 status, so we need custom parsing.
    async fn parse_token_response(
        &self,
        request: crate::http::HttpRequest,
    ) -> Result<OAuth2Tokens, Error> {
        let response = self.http_client.send(request).await?;

        match response.status {
            200 => {
                let body_str = String::from_utf8_lossy(&response.body).into_owned();
                let json: serde_json::Value =
                    serde_json::from_str(&body_str).map_err(|_| Error::UnexpectedErrorBody {
                        status: 200,
                        body: body_str.clone(),
                    })?;

                // TikTok returns errors with HTTP 200
                if let Some(error_code) = json.get("error").and_then(|e| e.as_str()) {
                    return Err(Error::OAuthRequest {
                        code: error_code.to_string(),
                        description: json
                            .get("error_description")
                            .and_then(|v| v.as_str())
                            .map(String::from),
                        uri: json
                            .get("error_uri")
                            .and_then(|v| v.as_str())
                            .map(String::from),
                        state: json.get("state").and_then(|v| v.as_str()).map(String::from),
                    });
                }

                Ok(OAuth2Tokens::new(json))
            }
            400 | 401 => {
                let body_str = String::from_utf8_lossy(&response.body).into_owned();
                match serde_json::from_str::<serde_json::Value>(&body_str) {
                    Ok(json) if json.get("error").and_then(|e| e.as_str()).is_some() => {
                        Err(Error::OAuthRequest {
                            code: json["error"].as_str().unwrap().to_string(),
                            description: json
                                .get("error_description")
                                .and_then(|v| v.as_str())
                                .map(String::from),
                            uri: json
                                .get("error_uri")
                                .and_then(|v| v.as_str())
                                .map(String::from),
                            state: json.get("state").and_then(|v| v.as_str()).map(String::from),
                        })
                    }
                    _ => Err(Error::UnexpectedErrorBody {
                        status: response.status,
                        body: body_str,
                    }),
                }
            }
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

    fn make_tiktok(http_client: &MockHttpClient) -> TikTok<'_, MockHttpClient> {
        TikTok::from_options(TikTokOptions {
            client_id: "cid".into(),
            client_secret: "secret".into(),
            redirect_uri: "https://app/cb".into(),
            http_client,
        })
    }

    #[test]
    fn new_sets_production_endpoints() {
        let mock = MockHttpClient::new(vec![]);
        let tiktok = make_tiktok(&mock);
        assert_eq!(tiktok.authorization_endpoint, AUTHORIZATION_ENDPOINT);
        assert_eq!(tiktok.token_endpoint, TOKEN_ENDPOINT);
        assert_eq!(tiktok.revocation_endpoint, REVOCATION_ENDPOINT);
    }

    #[test]
    fn name_returns_tiktok() {
        let mock = MockHttpClient::new(vec![]);
        let tiktok = make_tiktok(&mock);
        assert_eq!(tiktok.name(), "TikTok");
    }

    #[test]
    fn authorization_url_uses_client_key() {
        let mock = MockHttpClient::new(vec![]);
        let tiktok = make_tiktok(&mock);
        let url = tiktok.authorization_url("state123", &["user.info.basic"], "my-verifier");

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("client_key".into(), "cid".into())));
        // Should NOT contain client_id
        assert!(!pairs.iter().any(|(k, _)| k == "client_id"));
    }

    #[test]
    fn authorization_url_always_sends_scope() {
        let mock = MockHttpClient::new(vec![]);
        let tiktok = make_tiktok(&mock);
        // Even with empty scopes, scope param should be present
        let url = tiktok.authorization_url("state123", &[], "my-verifier");

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("scope".into(), "".into())));
    }

    #[test]
    fn authorization_url_uses_comma_delimited_scopes() {
        let mock = MockHttpClient::new(vec![]);
        let tiktok = make_tiktok(&mock);
        let url = tiktok.authorization_url("state123", &["user.info.basic", "video.list"], "v");

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("scope".into(), "user.info.basic,video.list".into())));
    }

    #[test]
    fn authorization_url_includes_pkce_params() {
        let mock = MockHttpClient::new(vec![]);
        let tiktok = make_tiktok(&mock);
        let url = tiktok.authorization_url("state123", &[], "my-verifier");

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.contains(&("state".into(), "state123".into())));
        assert!(pairs.contains(&("redirect_uri".into(), "https://app/cb".into())));
        assert!(pairs.iter().any(|(k, _)| k == "code_challenge"));
        assert!(pairs.contains(&("code_challenge_method".into(), "S256".into())));
    }

    #[tokio::test]
    async fn validate_authorization_code_uses_client_key_in_body() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "tt-tok",
                "token_type": "Bearer",
                "expires_in": 86400,
                "refresh_token": "tt-refresh"
            }))
            .unwrap(),
        }]);
        let tiktok = make_tiktok(&mock);

        let tokens = tiktok
            .validate_authorization_code("auth-code", "my-verifier")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "tt-tok");

        let requests = mock.take_requests();
        assert_eq!(requests[0].url, TOKEN_ENDPOINT);
        // No Authorization header (body credentials)
        assert!(get_header(&requests[0], "Authorization").is_none());

        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("grant_type".into(), "authorization_code".into())));
        assert!(body.contains(&("code".into(), "auth-code".into())));
        assert!(body.contains(&("client_key".into(), "cid".into())));
        assert!(body.contains(&("client_secret".into(), "secret".into())));
        assert!(body.contains(&("code_verifier".into(), "my-verifier".into())));
        assert!(body.contains(&("redirect_uri".into(), "https://app/cb".into())));
        // Should NOT contain client_id
        assert!(!body.iter().any(|(k, _)| k == "client_id"));
    }

    #[tokio::test]
    async fn validate_authorization_code_handles_error_as_200() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "error": "invalid_request",
                "error_description": "The code has expired."
            }))
            .unwrap(),
        }]);
        let tiktok = make_tiktok(&mock);

        let err = tiktok
            .validate_authorization_code("bad-code", "verifier")
            .await
            .unwrap_err();

        match err {
            Error::OAuthRequest {
                code, description, ..
            } => {
                assert_eq!(code, "invalid_request");
                assert_eq!(description.as_deref(), Some("The code has expired."));
            }
            other => panic!("Expected OAuthRequest, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn validate_authorization_code_400_error() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 400,
            body: serde_json::to_vec(&serde_json::json!({
                "error": "invalid_grant",
                "error_description": "The code is invalid"
            }))
            .unwrap(),
        }]);
        let tiktok = make_tiktok(&mock);

        let err = tiktok
            .validate_authorization_code("code", "verifier")
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            Error::OAuthRequest { code, .. } if code == "invalid_grant"
        ));
    }

    #[tokio::test]
    async fn validate_authorization_code_unexpected_status() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 500,
            body: b"Internal Server Error".to_vec(),
        }]);
        let tiktok = make_tiktok(&mock);

        let err = tiktok
            .validate_authorization_code("code", "verifier")
            .await
            .unwrap_err();

        assert!(matches!(err, Error::UnexpectedResponse { status: 500 }));
    }

    #[tokio::test]
    async fn refresh_access_token_uses_client_key() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "new-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);
        let tiktok = make_tiktok(&mock);

        let tokens = tiktok.refresh_access_token("refresh-tok").await.unwrap();

        assert_eq!(tokens.access_token().unwrap(), "new-tok");

        let requests = mock.take_requests();
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("grant_type".into(), "refresh_token".into())));
        assert!(body.contains(&("refresh_token".into(), "refresh-tok".into())));
        assert!(body.contains(&("client_key".into(), "cid".into())));
        assert!(body.contains(&("client_secret".into(), "secret".into())));
        assert!(!body.iter().any(|(k, _)| k == "client_id"));
    }

    #[tokio::test]
    async fn refresh_access_token_handles_error_as_200() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "error": "invalid_refresh_token",
                "error_description": "Refresh token is expired."
            }))
            .unwrap(),
        }]);
        let tiktok = make_tiktok(&mock);

        let err = tiktok
            .refresh_access_token("bad-refresh")
            .await
            .unwrap_err();

        match err {
            Error::OAuthRequest {
                code, description, ..
            } => {
                assert_eq!(code, "invalid_refresh_token");
                assert_eq!(description.as_deref(), Some("Refresh token is expired."));
            }
            other => panic!("Expected OAuthRequest, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn revoke_token_uses_client_key() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: vec![],
        }]);
        let tiktok = make_tiktok(&mock);

        let result = tiktok.revoke_token("tok-to-revoke").await;
        assert!(result.is_ok());

        let requests = mock.take_requests();
        assert_eq!(requests[0].url, REVOCATION_ENDPOINT);
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("token".into(), "tok-to-revoke".into())));
        assert!(body.contains(&("client_key".into(), "cid".into())));
        assert!(body.contains(&("client_secret".into(), "secret".into())));
        assert!(!body.iter().any(|(k, _)| k == "client_id"));
    }

    #[tokio::test]
    async fn revoke_token_non_200_returns_error() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 503,
            body: vec![],
        }]);
        let tiktok = make_tiktok(&mock);

        let result = tiktok.revoke_token("tok").await;
        assert!(matches!(
            result,
            Err(Error::UnexpectedResponse { status: 503 })
        ));
    }
}
