use crate::client::OAuth2Client;
use crate::error::Error;
use crate::http::HttpClient;
use crate::pkce::CodeChallengeMethod;
use crate::tokens::OAuth2Tokens;

/// OAuth 2.0 client for [Keycloak](https://www.keycloak.org/docs/latest/securing_apps/#_oidc).
///
/// Keycloak requires PKCE with the S256 challenge method on all authorization requests.
/// This client supports self-hosted Keycloak instances by allowing you to specify a
/// realm-specific URL. The client supports the full authorization code flow including
/// token refresh and revocation.
///
/// # Setup
///
/// 1. In your Keycloak admin console, create or select a realm.
/// 2. Go to **Clients** and create a new OpenID Connect client.
/// 3. Note your **Client ID** and **Client Secret** (if using confidential access type).
/// 4. Add your redirect URI to the **Valid Redirect URIs** setting.
///
/// # Scopes
///
/// Keycloak uses space-separated scopes. Common scopes include:
///
/// | Scope | Description |
/// |-------|-------------|
/// | `openid` | OpenID Connect authentication |
/// | `profile` | User's profile information |
/// | `email` | User's email address |
/// | `offline_access` | Request a refresh token |
///
/// See your Keycloak realm's client scope configuration for available scopes.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{KeyCloak, ReqwestClient, generate_state, generate_code_verifier};
///
/// # async fn example() -> Result<(), arctic_oauth::Error> {
/// let keycloak = KeyCloak::new(
///     "https://keycloak.example.com/realms/myrealm",
///     "your-client-id",
///     Some("your-client-secret".into()),
///     "https://example.com/callback",
/// );
///
/// // Step 1: Generate PKCE verifier and CSRF state, then redirect the user.
/// let state = generate_state();
/// let code_verifier = generate_code_verifier();
/// let url = keycloak.authorization_url(&state, &["openid", "profile", "email"], &code_verifier);
/// // Store `state` and `code_verifier` in the user's session, then redirect to `url`.
///
/// // Step 2: In your callback handler, exchange the authorization code for tokens.
/// let http = ReqwestClient::new();
/// let tokens = keycloak
///     .validate_authorization_code(&http, "authorization-code", &code_verifier)
///     .await?;
/// println!("Access token: {}", tokens.access_token()?);
///
/// // Step 3 (optional): Refresh an expired access token.
/// let refreshed = keycloak
///     .refresh_access_token(&http, tokens.refresh_token()?)
///     .await?;
///
/// // Step 4 (optional): Revoke a token.
/// keycloak.revoke_token(&http, tokens.access_token()?).await?;
/// # Ok(())
/// # }
/// ```
pub struct KeyCloak {
    client: OAuth2Client,
    authorization_endpoint: String,
    token_endpoint: String,
    revocation_endpoint: String,
}

impl KeyCloak {
    /// Creates a new Keycloak OAuth 2.0 client for a specific realm.
    ///
    /// # Arguments
    ///
    /// * `realm_url` - The full URL to the Keycloak realm (e.g.
    ///   `"https://keycloak.example.com/realms/myrealm"`). This should include the
    ///   `/realms/{realm-name}` path.
    /// * `client_id` - The OAuth 2.0 client ID from Keycloak.
    /// * `client_secret` - Optional client secret. Use `None` for public clients.
    /// * `redirect_uri` - The URI Keycloak will redirect to after authorization.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::KeyCloak;
    ///
    /// let keycloak = KeyCloak::new(
    ///     "https://keycloak.example.com/realms/myrealm",
    ///     "your-client-id",
    ///     Some("your-client-secret".into()),
    ///     "https://example.com/callback",
    /// );
    /// ```
    pub fn new(
        realm_url: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: Option<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        let realm = realm_url.into();
        Self {
            client: OAuth2Client::new(client_id, client_secret, Some(redirect_uri.into())),
            authorization_endpoint: format!("{realm}/protocol/openid-connect/auth"),
            token_endpoint: format!("{realm}/protocol/openid-connect/token"),
            revocation_endpoint: format!("{realm}/protocol/openid-connect/revoke"),
        }
    }
}

impl KeyCloak {
    /// Returns the provider name (`"KeyCloak"`).
    pub fn name(&self) -> &'static str {
        "KeyCloak"
    }

    /// Builds the Keycloak authorization URL that the user should be redirected to.
    ///
    /// The returned URL includes all required OAuth 2.0 and PKCE parameters. Your
    /// application should store `state` and `code_verifier` in the user's session
    /// before redirecting, as both are needed to complete the flow.
    ///
    /// # Arguments
    ///
    /// * `state` - A CSRF token to prevent cross-site request forgery. Use
    ///   [`generate_state`](crate::generate_state) to create one.
    /// * `scopes` - The OAuth 2.0 scopes to request (e.g. `&["openid", "profile", "email"]`).
    /// * `code_verifier` - The PKCE code verifier. Use
    ///   [`generate_code_verifier`](crate::generate_code_verifier) to create one.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{KeyCloak, generate_state, generate_code_verifier};
    ///
    /// let keycloak = KeyCloak::new("https://kc.example.com/realms/r", "client-id", None, "https://example.com/cb");
    /// let state = generate_state();
    /// let verifier = generate_code_verifier();
    ///
    /// let url = keycloak.authorization_url(&state, &["openid"], &verifier);
    /// assert!(url.as_str().contains("/protocol/openid-connect/auth"));
    /// ```
    pub fn authorization_url(
        &self,
        state: &str,
        scopes: &[&str],
        code_verifier: &str,
    ) -> url::Url {
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
    /// Call this in your redirect URI handler after Keycloak redirects back with a `code`
    /// query parameter. The `code_verifier` must be the same value used to generate the
    /// authorization URL.
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
    /// Returns [`Error::OAuthRequest`] if Keycloak rejects the code, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::{KeyCloak, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let keycloak = KeyCloak::new("https://kc.example.com/realms/r", "client-id", Some("secret".into()), "https://example.com/cb");
    /// let http = ReqwestClient::new();
    ///
    /// let tokens = keycloak
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
        self.client
            .validate_authorization_code(
                http_client,
                &self.token_endpoint,
                code,
                Some(code_verifier),
            )
            .await
    }

    /// Refreshes an expired access token using a refresh token.
    ///
    /// Keycloak access tokens expire after a configurable period (often 5-15 minutes).
    /// If your initial token response included a refresh token (requires `offline_access`
    /// scope), you can use it to obtain a new access token without user interaction.
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
    /// # use arctic_oauth::{KeyCloak, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let keycloak = KeyCloak::new("https://kc.example.com/realms/r", "client-id", Some("secret".into()), "https://example.com/cb");
    /// let http = ReqwestClient::new();
    ///
    /// let new_tokens = keycloak
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
    /// Use this when a user signs out or disconnects your application. Keycloak will
    /// invalidate the token and prevent further use.
    ///
    /// # Arguments
    ///
    /// * `http_client` - An [`HttpClient`](crate::HttpClient) implementation.
    /// * `token` - The access token or refresh token to revoke.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedResponse`] if Keycloak returns a non-200 status, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::{KeyCloak, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let keycloak = KeyCloak::new("https://kc.example.com/realms/r", "client-id", Some("secret".into()), "https://example.com/cb");
    /// let http = ReqwestClient::new();
    ///
    /// keycloak.revoke_token(&http, "token-to-revoke").await?;
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

    #[test]
    fn new_builds_endpoints_from_realm_url() {
        let kc = KeyCloak::new(
            "https://keycloak.example.com/realms/myrealm",
            "cid",
            Some("secret".into()),
            "https://app/cb",
        );
        assert_eq!(
            kc.authorization_endpoint,
            "https://keycloak.example.com/realms/myrealm/protocol/openid-connect/auth"
        );
        assert_eq!(
            kc.token_endpoint,
            "https://keycloak.example.com/realms/myrealm/protocol/openid-connect/token"
        );
        assert_eq!(
            kc.revocation_endpoint,
            "https://keycloak.example.com/realms/myrealm/protocol/openid-connect/revoke"
        );
    }

    #[test]
    fn name_returns_keycloak() {
        let kc = KeyCloak::new("https://kc.example.com/realms/r", "cid", None, "https://app/cb");
        assert_eq!(kc.name(), "KeyCloak");
    }

    #[test]
    fn authorization_url_includes_pkce() {
        let kc = KeyCloak::new("https://kc.example.com/realms/r", "cid", None, "https://app/cb");
        let url = kc.authorization_url("state123", &["openid"], "my-verifier");

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.iter().any(|(k, _)| k == "code_challenge"));
        assert!(pairs.contains(&("code_challenge_method".into(), "S256".into())));
    }

    #[tokio::test]
    async fn validate_authorization_code_sends_verifier() {
        let kc = KeyCloak::new("https://mock", "cid", Some("secret".into()), "https://app/cb");
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "kc-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);

        let tokens = kc
            .validate_authorization_code(&mock, "code", "verifier")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "kc-tok");

        let requests = mock.take_requests();
        assert_eq!(
            requests[0].url,
            "https://mock/protocol/openid-connect/token"
        );
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("code_verifier".into(), "verifier".into())));
    }

    #[tokio::test]
    async fn revoke_token_delegates_to_client() {
        let kc = KeyCloak::new("https://mock", "cid", Some("secret".into()), "https://app/cb");
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: vec![],
        }]);

        let result = kc.revoke_token(&mock, "tok").await;
        assert!(result.is_ok());

        let requests = mock.take_requests();
        assert_eq!(
            requests[0].url,
            "https://mock/protocol/openid-connect/revoke"
        );
    }
}
