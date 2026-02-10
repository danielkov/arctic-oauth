use crate::client::OAuth2Client;
use crate::error::Error;
use crate::http::HttpClient;
use crate::pkce::CodeChallengeMethod;
use crate::tokens::OAuth2Tokens;

/// OAuth 2.0 client for [Authentik](https://docs.goauthentik.io/add-secure-apps/providers/oauth2/).
///
/// Authentik requires PKCE with the S256 challenge method on all authorization requests.
/// This client supports the authorization code flow including token refresh and revocation.
/// The client secret is optional for public clients.
///
/// # Setup
///
/// 1. Create an OAuth2/OpenID Provider in your Authentik instance.
/// 2. Obtain the **Client ID** and optionally the **Client Secret** (required for confidential clients).
/// 3. Set the **Redirect URIs** to match the `redirect_uri` you pass to [`Authentik::new`].
///
/// # Scopes
///
/// Authentik uses space-separated scopes. Common scopes include:
///
/// | Scope | Description |
/// |-------|-------------|
/// | `openid` | OpenID Connect authentication |
/// | `email` | User's email address |
/// | `profile` | User's profile information |
///
/// See your Authentik instance's provider configuration for available scopes.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{Authentik, ReqwestClient, generate_state, generate_code_verifier};
///
/// # async fn example() -> Result<(), arctic_oauth::Error> {
/// let authentik = Authentik::new(
///     "https://auth.example.com",
///     "your-client-id",
///     Some("your-client-secret".to_string()),
///     "https://example.com/callback",
/// );
///
/// // Step 1: Generate PKCE verifier and CSRF state, then redirect the user.
/// let state = generate_state();
/// let code_verifier = generate_code_verifier();
/// let url = authentik.authorization_url(&state, &["openid", "email"], &code_verifier);
///
/// // Step 2: Exchange the authorization code for tokens.
/// let http = ReqwestClient::new();
/// let tokens = authentik
///     .validate_authorization_code(&http, "authorization-code", &code_verifier)
///     .await?;
/// println!("Access token: {}", tokens.access_token()?);
///
/// // Step 3 (optional): Refresh an expired access token.
/// let refreshed = authentik
///     .refresh_access_token(&http, tokens.refresh_token()?)
///     .await?;
///
/// // Step 4 (optional): Revoke a token.
/// authentik.revoke_token(&http, tokens.access_token()?).await?;
/// # Ok(())
/// # }
/// ```
pub struct Authentik {
    client: OAuth2Client,
    authorization_endpoint: String,
    token_endpoint: String,
    revocation_endpoint: String,
}

impl Authentik {
    /// Creates a new Authentik OAuth 2.0 client configured for a specific instance.
    ///
    /// # Arguments
    ///
    /// * `base_url` - The base URL of your Authentik instance (e.g. `"https://auth.example.com"`).
    /// * `client_id` - The OAuth 2.0 client ID from your Authentik provider configuration.
    /// * `client_secret` - The OAuth 2.0 client secret (optional for public clients, required for confidential clients).
    /// * `redirect_uri` - The URI Authentik will redirect to after authorization. Must match
    ///   one of the redirect URIs configured in your provider.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::Authentik;
    ///
    /// // Confidential client (with secret)
    /// let authentik = Authentik::new(
    ///     "https://auth.example.com",
    ///     "your-client-id",
    ///     Some("your-client-secret".to_string()),
    ///     "https://example.com/callback",
    /// );
    ///
    /// // Public client (without secret)
    /// let authentik_public = Authentik::new(
    ///     "https://auth.example.com",
    ///     "your-client-id",
    ///     None,
    ///     "https://example.com/callback",
    /// );
    /// ```
    pub fn new(
        base_url: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: Option<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        let base = base_url.into();
        Self {
            client: OAuth2Client::new(client_id, client_secret, Some(redirect_uri.into())),
            authorization_endpoint: format!("{base}/application/o/authorize/"),
            token_endpoint: format!("{base}/application/o/token/"),
            revocation_endpoint: format!("{base}/application/o/revoke/"),
        }
    }
}

impl Authentik {
    /// Returns the provider name (`"Authentik"`).
    pub fn name(&self) -> &'static str {
        "Authentik"
    }

    /// Builds the Authentik authorization URL that the user should be redirected to.
    ///
    /// The returned URL includes all required OAuth 2.0 and PKCE parameters. Your
    /// application should store `state` and `code_verifier` in the user's session
    /// before redirecting, as both are needed to complete the flow.
    ///
    /// # Arguments
    ///
    /// * `state` - A CSRF token to prevent cross-site request forgery. Use
    ///   [`generate_state`](crate::generate_state) to create one.
    /// * `scopes` - The OAuth 2.0 scopes to request (e.g. `&["openid", "email"]`).
    /// * `code_verifier` - The PKCE code verifier. Use
    ///   [`generate_code_verifier`](crate::generate_code_verifier) to create one.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{Authentik, generate_state, generate_code_verifier};
    ///
    /// let authentik = Authentik::new("https://auth.example.com", "client-id", None, "https://example.com/cb");
    /// let state = generate_state();
    /// let verifier = generate_code_verifier();
    ///
    /// let url = authentik.authorization_url(&state, &["openid", "profile"], &verifier);
    /// assert!(url.as_str().starts_with("https://auth.example.com/"));
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
    /// Call this in your redirect URI handler after Authentik redirects back with a `code`
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
    /// Returns [`Error::OAuthRequest`] if Authentik rejects the code, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::{Authentik, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let authentik = Authentik::new("https://auth.example.com", "client-id", None, "https://example.com/cb");
    /// let http = ReqwestClient::new();
    ///
    /// let tokens = authentik
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
    /// Authentik access tokens have configurable expiration times. If your initial token
    /// response included a refresh token, you can use it to obtain a new access token
    /// without user interaction.
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
    /// # use arctic_oauth::{Authentik, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let authentik = Authentik::new("https://auth.example.com", "client-id", None, "https://example.com/cb");
    /// let http = ReqwestClient::new();
    ///
    /// let new_tokens = authentik
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
    /// Use this when a user signs out or disconnects your application.
    ///
    /// # Arguments
    ///
    /// * `http_client` - An [`HttpClient`](crate::HttpClient) implementation.
    /// * `token` - The access token or refresh token to revoke.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedResponse`] if Authentik returns a non-200 status, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::{Authentik, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let authentik = Authentik::new("https://auth.example.com", "client-id", None, "https://example.com/cb");
    /// let http = ReqwestClient::new();
    ///
    /// authentik.revoke_token(&http, "token-to-revoke").await?;
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
    fn new_builds_endpoints_with_trailing_slashes() {
        let authentik = Authentik::new(
            "https://auth.example.com",
            "cid",
            Some("secret".into()),
            "https://app/cb",
        );
        assert_eq!(
            authentik.authorization_endpoint,
            "https://auth.example.com/application/o/authorize/"
        );
        assert_eq!(
            authentik.token_endpoint,
            "https://auth.example.com/application/o/token/"
        );
        assert_eq!(
            authentik.revocation_endpoint,
            "https://auth.example.com/application/o/revoke/"
        );
    }

    #[test]
    fn name_returns_authentik() {
        let authentik = Authentik::new("https://auth.example.com", "cid", None, "https://app/cb");
        assert_eq!(authentik.name(), "Authentik");
    }

    #[test]
    fn authorization_url_includes_pkce() {
        let authentik = Authentik::new("https://auth.example.com", "cid", None, "https://app/cb");
        let url = authentik.authorization_url("state123", &["openid"], "my-verifier");

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.iter().any(|(k, _)| k == "code_challenge"));
        assert!(pairs.contains(&("code_challenge_method".into(), "S256".into())));
    }

    #[tokio::test]
    async fn validate_authorization_code_sends_verifier() {
        let authentik =
            Authentik::new("https://mock", "cid", Some("secret".into()), "https://app/cb");
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "auth-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);

        let tokens = authentik
            .validate_authorization_code(&mock, "code", "verifier")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "auth-tok");

        let requests = mock.take_requests();
        assert_eq!(requests[0].url, "https://mock/application/o/token/");
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("code_verifier".into(), "verifier".into())));
    }

    #[tokio::test]
    async fn revoke_token_delegates_to_client() {
        let authentik =
            Authentik::new("https://mock", "cid", Some("secret".into()), "https://app/cb");
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: vec![],
        }]);

        let result = authentik.revoke_token(&mock, "tok").await;
        assert!(result.is_ok());

        let requests = mock.take_requests();
        assert_eq!(requests[0].url, "https://mock/application/o/revoke/");
    }
}
