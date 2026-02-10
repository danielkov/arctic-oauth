use crate::client::OAuth2Client;
use crate::error::Error;
use crate::http::HttpClient;
use crate::pkce::CodeChallengeMethod;
use crate::tokens::OAuth2Tokens;

/// OAuth 2.0 client for [Mastodon](https://docs.joinmastodon.org/client/token/).
///
/// Mastodon requires PKCE with the S256 challenge method on all authorization requests.
/// This client supports the authorization code flow including token revocation. Note that
/// Mastodon is a federated platform, so you must specify the instance base URL.
///
/// # Setup
///
/// 1. Register your application on the target Mastodon instance via the API (`POST /api/v1/apps`) or web interface.
/// 2. Obtain the **client_id** and **client_secret** from the registration response.
/// 3. Set the **redirect_uri** to match the value you pass to [`Mastodon::new`].
///
/// # Scopes
///
/// Mastodon uses space-separated scopes. Common scopes include:
///
/// | Scope | Description |
/// |-------|-------------|
/// | `read` | Read access to all data |
/// | `write` | Write access to all data |
/// | `follow` | Modify account relationships |
/// | `push` | Receive push notifications |
///
/// See the full list at <https://docs.joinmastodon.org/api/oauth-scopes/>.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{Mastodon, ReqwestClient, generate_state, generate_code_verifier};
///
/// # async fn example() -> Result<(), arctic_oauth::Error> {
/// let mastodon = Mastodon::new(
///     "https://mastodon.social",
///     "your-client-id",
///     "your-client-secret",
///     "https://example.com/callback",
/// );
///
/// // Step 1: Generate PKCE verifier and CSRF state, then redirect the user.
/// let state = generate_state();
/// let code_verifier = generate_code_verifier();
/// let url = mastodon.authorization_url(&state, &["read", "write"], &code_verifier);
///
/// // Step 2: Exchange the authorization code for tokens.
/// let http = ReqwestClient::new();
/// let tokens = mastodon
///     .validate_authorization_code(&http, "authorization-code", &code_verifier)
///     .await?;
/// println!("Access token: {}", tokens.access_token()?);
///
/// // Step 3 (optional): Revoke a token.
/// mastodon.revoke_token(&http, tokens.access_token()?).await?;
/// # Ok(())
/// # }
/// ```
pub struct Mastodon {
    client: OAuth2Client,
    authorization_endpoint: String,
    token_endpoint: String,
    revocation_endpoint: String,
}

impl Mastodon {
    /// Creates a new Mastodon OAuth 2.0 client configured for a specific instance.
    ///
    /// # Arguments
    ///
    /// * `base_url` - The base URL of the Mastodon instance (e.g. `"https://mastodon.social"`).
    /// * `client_id` - The OAuth 2.0 client ID from app registration.
    /// * `client_secret` - The OAuth 2.0 client secret from app registration.
    /// * `redirect_uri` - The URI Mastodon will redirect to after authorization. Must match
    ///   the redirect URI configured during app registration.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::Mastodon;
    ///
    /// let mastodon = Mastodon::new(
    ///     "https://mastodon.social",
    ///     "your-client-id",
    ///     "your-client-secret",
    ///     "https://example.com/callback",
    /// );
    /// ```
    pub fn new(
        base_url: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        let base = base_url.into();
        Self {
            client: OAuth2Client::new(
                client_id,
                Some(client_secret.into()),
                Some(redirect_uri.into()),
            ),
            authorization_endpoint: format!("{base}/api/v1/oauth/authorize"),
            token_endpoint: format!("{base}/api/v1/oauth/token"),
            revocation_endpoint: format!("{base}/api/v1/oauth/revoke"),
        }
    }
}

impl Mastodon {
    /// Returns the provider name (`"Mastodon"`).
    pub fn name(&self) -> &'static str {
        "Mastodon"
    }

    /// Builds the Mastodon authorization URL that the user should be redirected to.
    ///
    /// The returned URL includes all required OAuth 2.0 and PKCE parameters. Your
    /// application should store `state` and `code_verifier` in the user's session
    /// before redirecting, as both are needed to complete the flow.
    ///
    /// # Arguments
    ///
    /// * `state` - A CSRF token to prevent cross-site request forgery. Use
    ///   [`generate_state`](crate::generate_state) to create one.
    /// * `scopes` - The OAuth 2.0 scopes to request (e.g. `&["read", "write"]`).
    /// * `code_verifier` - The PKCE code verifier. Use
    ///   [`generate_code_verifier`](crate::generate_code_verifier) to create one.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{Mastodon, generate_state, generate_code_verifier};
    ///
    /// let mastodon = Mastodon::new("https://mastodon.social", "client-id", "client-secret", "https://example.com/cb");
    /// let state = generate_state();
    /// let verifier = generate_code_verifier();
    ///
    /// let url = mastodon.authorization_url(&state, &["read"], &verifier);
    /// assert!(url.as_str().starts_with("https://mastodon.social/"));
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

    /// Exchanges an authorization code for access tokens.
    ///
    /// Call this in your redirect URI handler after Mastodon redirects back with a `code`
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
    /// Returns [`Error::OAuthRequest`] if Mastodon rejects the code, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::{Mastodon, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let mastodon = Mastodon::new("https://mastodon.social", "client-id", "secret", "https://example.com/cb");
    /// let http = ReqwestClient::new();
    ///
    /// let tokens = mastodon
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

    /// Revokes an access token.
    ///
    /// Use this when a user signs out or disconnects your application.
    ///
    /// # Arguments
    ///
    /// * `http_client` - An [`HttpClient`](crate::HttpClient) implementation.
    /// * `token` - The access token to revoke.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedResponse`] if Mastodon returns a non-200 status, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::{Mastodon, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let mastodon = Mastodon::new("https://mastodon.social", "client-id", "secret", "https://example.com/cb");
    /// let http = ReqwestClient::new();
    ///
    /// mastodon.revoke_token(&http, "token-to-revoke").await?;
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
    fn new_builds_endpoints_from_base_url() {
        let mastodon = Mastodon::new(
            "https://mastodon.social",
            "cid",
            "secret",
            "https://app/cb",
        );
        assert_eq!(
            mastodon.authorization_endpoint,
            "https://mastodon.social/api/v1/oauth/authorize"
        );
        assert_eq!(
            mastodon.token_endpoint,
            "https://mastodon.social/api/v1/oauth/token"
        );
        assert_eq!(
            mastodon.revocation_endpoint,
            "https://mastodon.social/api/v1/oauth/revoke"
        );
    }

    #[test]
    fn name_returns_mastodon() {
        let mastodon = Mastodon::new("https://mastodon.social", "cid", "secret", "https://app/cb");
        assert_eq!(mastodon.name(), "Mastodon");
    }

    #[test]
    fn authorization_url_includes_pkce() {
        let mastodon = Mastodon::new("https://mastodon.social", "cid", "secret", "https://app/cb");
        let url = mastodon.authorization_url("state123", &["read"], "my-verifier");

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.iter().any(|(k, _)| k == "code_challenge"));
        assert!(pairs.contains(&("code_challenge_method".into(), "S256".into())));
    }

    #[tokio::test]
    async fn validate_authorization_code_sends_verifier() {
        let mastodon = Mastodon::new("https://mock", "cid", "secret", "https://app/cb");
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "masto-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);

        let tokens = mastodon
            .validate_authorization_code(&mock, "code", "verifier")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "masto-tok");

        let requests = mock.take_requests();
        assert_eq!(requests[0].url, "https://mock/api/v1/oauth/token");
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("code_verifier".into(), "verifier".into())));
    }

    #[tokio::test]
    async fn revoke_token_delegates_to_client() {
        let mastodon = Mastodon::new("https://mock", "cid", "secret", "https://app/cb");
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: vec![],
        }]);

        let result = mastodon.revoke_token(&mock, "tok").await;
        assert!(result.is_ok());

        let requests = mock.take_requests();
        assert_eq!(requests[0].url, "https://mock/api/v1/oauth/revoke");
    }
}
