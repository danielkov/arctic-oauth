use crate::client::OAuth2Client;
use crate::error::Error;
use crate::http::HttpClient;
use crate::pkce::CodeChallengeMethod;
use crate::tokens::OAuth2Tokens;

const AUTHORIZATION_ENDPOINT: &str = "https://discord.com/oauth2/authorize";
const TOKEN_ENDPOINT: &str = "https://discord.com/api/oauth2/token";
const REVOCATION_ENDPOINT: &str = "https://discord.com/api/oauth2/token/revoke";

/// OAuth 2.0 client for [Discord](https://discord.com/developers/docs/topics/oauth2).
///
/// Discord supports optional PKCE with the S256 challenge method for enhanced security.
/// This client supports the full authorization code flow including token refresh and
/// revocation. The client can be configured as either a confidential client (with
/// client secret) or a public client (without client secret).
///
/// # Setup
///
/// 1. Create an application in the [Discord Developer Portal](https://discord.com/developers/applications).
/// 2. Navigate to **OAuth2** section and copy your **Client ID** and **Client Secret**.
/// 3. Add a redirect URI in the **OAuth2 > Redirects** section that matches the `redirect_uri` you pass to [`Discord::new`].
///
/// # Scopes
///
/// Discord uses space-separated scopes. Common scopes include:
///
/// | Scope | Description |
/// |-------|-------------|
/// | `identify` | Read user's basic account info |
/// | `email` | Read user's email address |
/// | `guilds` | Read user's guilds (servers) |
/// | `guilds.join` | Join guilds on behalf of the user |
/// | `connections` | Read user's connected accounts |
///
/// See the full list at <https://discord.com/developers/docs/topics/oauth2#shared-resources-oauth2-scopes>.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{Discord, ReqwestClient, generate_state, generate_code_verifier};
///
/// # async fn example() -> Result<(), arctic_oauth::Error> {
/// let discord = Discord::new(
///     "your-client-id",
///     Some("your-client-secret".to_string()),
///     "https://example.com/callback",
/// );
///
/// // Step 1: Generate PKCE verifier (optional) and CSRF state, then redirect the user.
/// let state = generate_state();
/// let code_verifier = generate_code_verifier();
/// let url = discord.authorization_url(&state, &["identify", "email"], Some(&code_verifier))?;
/// // Store `state` and optionally `code_verifier` in the user's session, then redirect to `url`.
///
/// // Step 2: In your callback handler, exchange the authorization code for tokens.
/// let http = ReqwestClient::new();
/// let tokens = discord
///     .validate_authorization_code(&http, "authorization-code", Some(&code_verifier))
///     .await?;
/// println!("Access token: {}", tokens.access_token()?);
///
/// // Step 3 (optional): Refresh an expired access token.
/// let refreshed = discord
///     .refresh_access_token(&http, tokens.refresh_token()?)
///     .await?;
///
/// // Step 4 (optional): Revoke a token.
/// discord.revoke_token(&http, tokens.access_token()?).await?;
/// # Ok(())
/// # }
/// ```
pub struct Discord {
    client: OAuth2Client,
    authorization_endpoint: String,
    token_endpoint: String,
    revocation_endpoint: String,
}

impl Discord {
    /// Creates a new Discord OAuth 2.0 client configured with production endpoints.
    ///
    /// # Arguments
    ///
    /// * `client_id` - The OAuth 2.0 client ID from Discord's developer portal.
    /// * `client_secret` - The OAuth 2.0 client secret from Discord's developer portal.
    ///   Pass `None` to create a public client (for mobile/desktop apps).
    /// * `redirect_uri` - The URI Discord will redirect to after authorization.
    ///   Must match one configured in your app settings.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::Discord;
    ///
    /// // Confidential client (web apps)
    /// let discord = Discord::new(
    ///     "your-client-id",
    ///     Some("your-client-secret".to_string()),
    ///     "https://example.com/callback",
    /// );
    ///
    /// // Public client (mobile/desktop apps)
    /// let discord_public = Discord::new(
    ///     "your-client-id",
    ///     None,
    ///     "https://example.com/callback",
    /// );
    /// ```
    pub fn new(
        client_id: impl Into<String>,
        client_secret: Option<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        Self {
            client: OAuth2Client::new(client_id, client_secret, Some(redirect_uri.into())),
            authorization_endpoint: AUTHORIZATION_ENDPOINT.to_string(),
            token_endpoint: TOKEN_ENDPOINT.to_string(),
            revocation_endpoint: REVOCATION_ENDPOINT.to_string(),
        }
    }
}

#[cfg(any(test, feature = "testing"))]
impl Discord {
    /// Creates a Discord client with custom endpoint URLs.
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
    /// use arctic_oauth::Discord;
    ///
    /// let discord = Discord::with_endpoints(
    ///     "test-client-id",
    ///     Some("test-secret".to_string()),
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
            client: OAuth2Client::new(client_id, client_secret, Some(redirect_uri.into())),
            authorization_endpoint: authorization_endpoint.to_string(),
            token_endpoint: token_endpoint.to_string(),
            revocation_endpoint: revocation_endpoint
                .unwrap_or(REVOCATION_ENDPOINT)
                .to_string(),
        }
    }
}

impl Discord {
    /// Returns the provider name (`"Discord"`).
    pub fn name(&self) -> &'static str {
        "Discord"
    }

    /// Builds the Discord authorization URL that the user should be redirected to.
    ///
    /// The returned URL includes all required OAuth 2.0 parameters and optionally PKCE
    /// parameters. Your application should store `state` (and `code_verifier` if PKCE is
    /// used) in the user's session before redirecting, as they are needed to complete the flow.
    ///
    /// # Arguments
    ///
    /// * `state` - A CSRF token to prevent cross-site request forgery. Use
    ///   [`generate_state`](crate::generate_state) to create one.
    /// * `scopes` - The OAuth 2.0 scopes to request (e.g. `&["identify", "email"]`).
    /// * `code_verifier` - Optional PKCE code verifier. Use
    ///   [`generate_code_verifier`](crate::generate_code_verifier) to create one.
    ///   Pass `None` to skip PKCE.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{Discord, generate_state, generate_code_verifier};
    ///
    /// # fn example() -> Result<(), arctic_oauth::Error> {
    /// let discord = Discord::new("client-id", Some("secret".to_string()), "https://example.com/cb");
    /// let state = generate_state();
    /// let verifier = generate_code_verifier();
    ///
    /// // With PKCE
    /// let url = discord.authorization_url(&state, &["identify", "email"], Some(&verifier))?;
    ///
    /// // Without PKCE
    /// let url_no_pkce = discord.authorization_url(&state, &["identify"], None)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn authorization_url(
        &self,
        state: &str,
        scopes: &[&str],
        code_verifier: Option<&str>,
    ) -> Result<url::Url, Error> {
        match code_verifier {
            Some(verifier) => Ok(self.client.create_authorization_url_with_pkce(
                &self.authorization_endpoint,
                state,
                CodeChallengeMethod::S256,
                verifier,
                scopes,
            )),
            None => Ok(self.client.create_authorization_url(
                &self.authorization_endpoint,
                state,
                scopes,
            )),
        }
    }

    /// Exchanges an authorization code for access and refresh tokens.
    ///
    /// Call this in your redirect URI handler after Discord redirects back with a `code`
    /// query parameter. If PKCE was used, the `code_verifier` must be the same value used
    /// to generate the authorization URL.
    ///
    /// # Arguments
    ///
    /// * `http_client` - An [`HttpClient`](crate::HttpClient) implementation (e.g.
    ///   [`ReqwestClient`](crate::ReqwestClient)).
    /// * `code` - The authorization code from the `code` query parameter.
    /// * `code_verifier` - The PKCE code verifier stored during the authorization step.
    ///   Pass `None` if PKCE was not used.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OAuthRequest`] if Discord rejects the code, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::{Discord, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let discord = Discord::new("client-id", Some("secret".to_string()), "https://example.com/cb");
    /// let http = ReqwestClient::new();
    ///
    /// let tokens = discord
    ///     .validate_authorization_code(&http, "the-auth-code", Some("the-code-verifier"))
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
        code_verifier: Option<&str>,
    ) -> Result<OAuth2Tokens, Error> {
        self.client
            .validate_authorization_code(http_client, &self.token_endpoint, code, code_verifier)
            .await
    }

    /// Refreshes an expired access token using a refresh token.
    ///
    /// Discord access tokens typically expire after 7 days. If your initial token response
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
    /// # use arctic_oauth::{Discord, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let discord = Discord::new("client-id", Some("secret".to_string()), "https://example.com/cb");
    /// let http = ReqwestClient::new();
    ///
    /// let new_tokens = discord
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
        self.client
            .refresh_access_token(http_client, &self.token_endpoint, refresh_token, &[])
            .await
    }

    /// Revokes an access token or refresh token.
    ///
    /// Use this when a user signs out or disconnects your application from their Discord account.
    ///
    /// # Arguments
    ///
    /// * `http_client` - An [`HttpClient`](crate::HttpClient) implementation.
    /// * `token` - The access token or refresh token to revoke.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedResponse`] if Discord returns a non-200 status, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::{Discord, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let discord = Discord::new("client-id", Some("secret".to_string()), "https://example.com/cb");
    /// let http = ReqwestClient::new();
    ///
    /// discord.revoke_token(&http, "token-to-revoke").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn revoke_token(
        &self,
        http_client: &(impl HttpClient + ?Sized),
        token: &str,
    ) -> Result<(), Error> {
        self.client
            .revoke_token(http_client, &self.revocation_endpoint, token)
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

    fn get_header<'a>(request: &'a HttpRequest, name: &str) -> Option<&'a str> {
        request
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn new_sets_production_endpoints() {
        let discord = Discord::new("cid", Some("secret".into()), "https://app/cb");
        assert_eq!(discord.authorization_endpoint, AUTHORIZATION_ENDPOINT);
        assert_eq!(discord.token_endpoint, TOKEN_ENDPOINT);
        assert_eq!(discord.revocation_endpoint, REVOCATION_ENDPOINT);
    }

    #[test]
    fn with_endpoints_overrides_urls() {
        let discord = Discord::with_endpoints(
            "cid",
            Some("secret".into()),
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
            Some("https://mock/revoke"),
        );
        assert_eq!(discord.authorization_endpoint, "https://mock/authorize");
        assert_eq!(discord.token_endpoint, "https://mock/token");
        assert_eq!(discord.revocation_endpoint, "https://mock/revoke");
    }

    #[test]
    fn with_endpoints_defaults_revocation() {
        let discord = Discord::with_endpoints(
            "cid",
            Some("secret".into()),
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
            None,
        );
        assert_eq!(discord.revocation_endpoint, REVOCATION_ENDPOINT);
    }

    #[test]
    fn name_returns_discord() {
        let discord = Discord::new("cid", Some("secret".into()), "https://app/cb");
        assert_eq!(discord.name(), "Discord");
    }

    #[test]
    fn new_with_no_secret_creates_public_client() {
        let discord = Discord::new("cid", None, "https://app/cb");
        assert_eq!(discord.name(), "Discord");
    }

    #[test]
    fn authorization_url_without_pkce() {
        let discord = Discord::new("cid", Some("secret".into()), "https://app/cb");
        let url = discord
            .authorization_url("state123", &["identify", "email"], None)
            .unwrap();

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.contains(&("client_id".into(), "cid".into())));
        assert!(pairs.contains(&("state".into(), "state123".into())));
        assert!(pairs.contains(&("scope".into(), "identify email".into())));
        assert!(pairs.contains(&("redirect_uri".into(), "https://app/cb".into())));
        // No PKCE params
        assert!(!pairs.iter().any(|(k, _)| k == "code_challenge"));
        assert!(!pairs.iter().any(|(k, _)| k == "code_challenge_method"));
    }

    #[test]
    fn authorization_url_with_pkce() {
        let discord = Discord::new("cid", Some("secret".into()), "https://app/cb");
        let url = discord
            .authorization_url("state123", &["identify", "email"], Some("my-verifier"))
            .unwrap();

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.contains(&("client_id".into(), "cid".into())));
        assert!(pairs.contains(&("state".into(), "state123".into())));
        assert!(pairs.contains(&("scope".into(), "identify email".into())));
        assert!(pairs.contains(&("redirect_uri".into(), "https://app/cb".into())));
        assert!(pairs.iter().any(|(k, _)| k == "code_challenge"));
        assert!(pairs.contains(&("code_challenge_method".into(), "S256".into())));
    }

    #[tokio::test]
    async fn validate_authorization_code_delegates_to_client() {
        let discord = Discord::with_endpoints(
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
                "access_token": "discord-tok",
                "token_type": "Bearer",
                "expires_in": 604800
            }))
            .unwrap(),
        }]);

        let tokens = discord
            .validate_authorization_code(&mock, "auth-code", Some("verifier"))
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "discord-tok");

        let requests = mock.take_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url, "https://mock/token");

        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("grant_type".into(), "authorization_code".into())));
        assert!(body.contains(&("code".into(), "auth-code".into())));
        assert!(body.contains(&("code_verifier".into(), "verifier".into())));
    }

    #[tokio::test]
    async fn validate_authorization_code_without_pkce() {
        let discord = Discord::with_endpoints(
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
                "access_token": "discord-tok",
                "token_type": "Bearer",
                "expires_in": 604800
            }))
            .unwrap(),
        }]);

        let tokens = discord
            .validate_authorization_code(&mock, "auth-code", None)
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "discord-tok");

        let requests = mock.take_requests();
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("grant_type".into(), "authorization_code".into())));
        assert!(body.contains(&("code".into(), "auth-code".into())));
        assert!(!body.iter().any(|(k, _)| k == "code_verifier"));
    }

    #[tokio::test]
    async fn validate_authorization_code_public_client_sends_client_id_in_body() {
        let discord = Discord::with_endpoints(
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
                "access_token": "discord-tok",
                "token_type": "Bearer",
                "expires_in": 604800
            }))
            .unwrap(),
        }]);

        discord
            .validate_authorization_code(&mock, "auth-code", Some("verifier"))
            .await
            .unwrap();

        let requests = mock.take_requests();
        // Public client: no Basic auth header
        assert!(get_header(&requests[0], "Authorization").is_none());
        // client_id sent in body instead
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("client_id".into(), "cid".into())));
    }

    #[tokio::test]
    async fn refresh_access_token_delegates_to_client() {
        let discord = Discord::with_endpoints(
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

        let tokens = discord
            .refresh_access_token(&mock, "refresh-tok")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "new-tok");

        let requests = mock.take_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url, "https://mock/token");

        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("grant_type".into(), "refresh_token".into())));
        assert!(body.contains(&("refresh_token".into(), "refresh-tok".into())));
    }

    #[tokio::test]
    async fn revoke_token_delegates_to_client() {
        let discord = Discord::with_endpoints(
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

        let result = discord.revoke_token(&mock, "tok-to-revoke").await;
        assert!(result.is_ok());

        let requests = mock.take_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url, "https://mock/revoke");

        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("token".into(), "tok-to-revoke".into())));
    }

    #[tokio::test]
    async fn revoke_token_non_200_returns_error() {
        let discord = Discord::with_endpoints(
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

        let result = discord.revoke_token(&mock, "tok").await;
        assert!(matches!(
            result,
            Err(Error::UnexpectedResponse { status: 503 })
        ));
    }
}
