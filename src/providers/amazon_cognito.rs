use crate::client::OAuth2Client;
use crate::error::Error;
use crate::http::HttpClient;
use crate::pkce::CodeChallengeMethod;
use crate::tokens::OAuth2Tokens;

/// OAuth 2.0 client for [Amazon Cognito](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-userpools-server-contract-reference.html).
///
/// Amazon Cognito requires PKCE with the S256 challenge method on all authorization requests.
/// This client supports the full authorization code flow including token refresh and revocation.
/// The client secret is optional for public clients.
///
/// # Setup
///
/// 1. Create a User Pool in the [AWS Cognito Console](https://console.aws.amazon.com/cognito/).
/// 2. Add an app client under **App integration > App clients and analytics**.
/// 3. Configure the app client with your redirect URI under **Hosted UI settings**.
/// 4. Note your user pool domain (e.g., `myapp.auth.us-east-1.amazoncognito.com`).
///
/// # Scopes
///
/// Amazon Cognito uses space-separated scopes. Common scopes include:
///
/// | Scope | Description |
/// |-------|-------------|
/// | `openid` | OpenID Connect authentication |
/// | `email` | User's email address |
/// | `profile` | User's profile information |
/// | `phone` | User's phone number |
/// | `aws.cognito.signin.user.admin` | Full user pool access |
///
/// See the full list at <https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-define-resource-servers.html>.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{AmazonCognito, ReqwestClient, generate_state, generate_code_verifier};
///
/// # async fn example() -> Result<(), arctic_oauth::Error> {
/// let cognito = AmazonCognito::new(
///     "myapp.auth.us-east-1.amazoncognito.com",
///     "your-client-id",
///     Some("your-client-secret".into()),
///     "https://example.com/callback",
/// );
///
/// // Step 1: Generate PKCE verifier and CSRF state, then redirect the user.
/// let state = generate_state();
/// let code_verifier = generate_code_verifier();
/// let url = cognito.authorization_url(&state, &["openid", "email"], &code_verifier);
/// // Store `state` and `code_verifier` in the user's session, then redirect to `url`.
///
/// // Step 2: In your callback handler, exchange the authorization code for tokens.
/// let http = ReqwestClient::new();
/// let tokens = cognito
///     .validate_authorization_code(&http, "authorization-code", &code_verifier)
///     .await?;
/// println!("Access token: {}", tokens.access_token()?);
///
/// // Step 3 (optional): Refresh an expired access token.
/// let refreshed = cognito
///     .refresh_access_token(&http, tokens.refresh_token()?, &["openid", "email"])
///     .await?;
///
/// // Step 4 (optional): Revoke a token.
/// cognito.revoke_token(&http, tokens.access_token()?).await?;
/// # Ok(())
/// # }
/// ```
pub struct AmazonCognito {
    client: OAuth2Client,
    authorization_endpoint: String,
    token_endpoint: String,
    revocation_endpoint: String,
}

impl AmazonCognito {
    /// Creates a new Amazon Cognito OAuth 2.0 client.
    ///
    /// The endpoints are automatically constructed from your Cognito domain.
    ///
    /// # Arguments
    ///
    /// * `domain` - Your Cognito user pool domain (e.g., `myapp.auth.us-east-1.amazoncognito.com`).
    /// * `client_id` - The app client ID from your Cognito user pool.
    /// * `client_secret` - The app client secret (optional for public clients).
    /// * `redirect_uri` - The URI Cognito will redirect to after authorization. Must match
    ///   the redirect URI configured in your app client settings.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::AmazonCognito;
    ///
    /// let cognito = AmazonCognito::new(
    ///     "myapp.auth.us-east-1.amazoncognito.com",
    ///     "your-client-id",
    ///     Some("your-client-secret".into()),
    ///     "https://example.com/callback",
    /// );
    /// ```
    pub fn new(
        domain: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: Option<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        let domain = domain.into();
        Self {
            client: OAuth2Client::new(client_id, client_secret, Some(redirect_uri.into())),
            authorization_endpoint: format!("https://{domain}/oauth2/authorize"),
            token_endpoint: format!("https://{domain}/oauth2/token"),
            revocation_endpoint: format!("https://{domain}/oauth2/revoke"),
        }
    }
}

impl AmazonCognito {
    /// Returns the provider name (`"Amazon Cognito"`).
    pub fn name(&self) -> &'static str {
        "Amazon Cognito"
    }

    /// Builds the Amazon Cognito authorization URL that the user should be redirected to.
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
    /// use arctic_oauth::{AmazonCognito, generate_state, generate_code_verifier};
    ///
    /// let cognito = AmazonCognito::new("myapp.auth.us-east-1.amazoncognito.com", "client-id", None, "https://example.com/cb");
    /// let state = generate_state();
    /// let verifier = generate_code_verifier();
    ///
    /// let url = cognito.authorization_url(&state, &["openid", "email"], &verifier);
    /// assert!(url.as_str().starts_with("https://"));
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
    /// Call this in your redirect URI handler after Cognito redirects back with a `code`
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
    /// Returns [`Error::OAuthRequest`] if Cognito rejects the code, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::{AmazonCognito, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let cognito = AmazonCognito::new("myapp.auth.us-east-1.amazoncognito.com", "client-id", Some("secret".into()), "https://example.com/cb");
    /// let http = ReqwestClient::new();
    ///
    /// let tokens = cognito
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
    /// Amazon Cognito access tokens typically expire after 1 hour. If your initial token
    /// response included a refresh token, you can use it to obtain a new access token
    /// without user interaction. You can optionally specify scopes to narrow the access.
    ///
    /// # Arguments
    ///
    /// * `http_client` - An [`HttpClient`](crate::HttpClient) implementation.
    /// * `refresh_token` - The refresh token from a previous token response.
    /// * `scopes` - Optional scopes to request for the new token (can be empty).
    ///
    /// # Errors
    ///
    /// Returns [`Error::OAuthRequest`] if the refresh token is invalid or revoked, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::{AmazonCognito, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let cognito = AmazonCognito::new("myapp.auth.us-east-1.amazoncognito.com", "client-id", Some("secret".into()), "https://example.com/cb");
    /// let http = ReqwestClient::new();
    ///
    /// let new_tokens = cognito
    ///     .refresh_access_token(&http, "stored-refresh-token", &["openid", "email"])
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
        self.client
            .refresh_access_token(http_client, &self.token_endpoint, refresh_token, scopes)
            .await
    }

    /// Revokes an access token or refresh token.
    ///
    /// Use this when a user signs out or disconnects your application. Revoking a
    /// refresh token will invalidate all access tokens issued from it.
    ///
    /// # Arguments
    ///
    /// * `http_client` - An [`HttpClient`](crate::HttpClient) implementation.
    /// * `token` - The access token or refresh token to revoke.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedResponse`] if Cognito returns a non-200 status, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::{AmazonCognito, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let cognito = AmazonCognito::new("myapp.auth.us-east-1.amazoncognito.com", "client-id", Some("secret".into()), "https://example.com/cb");
    /// let http = ReqwestClient::new();
    ///
    /// cognito.revoke_token(&http, "token-to-revoke").await?;
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
    fn new_builds_endpoints_from_domain() {
        let cognito = AmazonCognito::new(
            "myapp.auth.us-east-1.amazoncognito.com",
            "cid",
            Some("secret".into()),
            "https://app/cb",
        );
        assert_eq!(
            cognito.authorization_endpoint,
            "https://myapp.auth.us-east-1.amazoncognito.com/oauth2/authorize"
        );
        assert_eq!(
            cognito.token_endpoint,
            "https://myapp.auth.us-east-1.amazoncognito.com/oauth2/token"
        );
        assert_eq!(
            cognito.revocation_endpoint,
            "https://myapp.auth.us-east-1.amazoncognito.com/oauth2/revoke"
        );
    }

    #[test]
    fn name_returns_amazon_cognito() {
        let cognito = AmazonCognito::new("example.com", "cid", None, "https://app/cb");
        assert_eq!(cognito.name(), "Amazon Cognito");
    }

    #[test]
    fn authorization_url_includes_pkce() {
        let cognito = AmazonCognito::new("example.com", "cid", None, "https://app/cb");
        let url = cognito.authorization_url("state123", &["openid"], "my-verifier");

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.iter().any(|(k, _)| k == "code_challenge"));
        assert!(pairs.contains(&("code_challenge_method".into(), "S256".into())));
    }

    #[tokio::test]
    async fn validate_authorization_code_sends_verifier() {
        let cognito =
            AmazonCognito::new("mock.example.com", "cid", Some("secret".into()), "https://app/cb");
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "cognito-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);

        let tokens = cognito
            .validate_authorization_code(&mock, "code", "verifier")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "cognito-tok");

        let requests = mock.take_requests();
        assert_eq!(requests[0].url, "https://mock.example.com/oauth2/token");
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("code_verifier".into(), "verifier".into())));
    }

    #[tokio::test]
    async fn refresh_access_token_passes_scopes() {
        let cognito =
            AmazonCognito::new("mock.example.com", "cid", Some("secret".into()), "https://app/cb");
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "new-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);

        let tokens = cognito
            .refresh_access_token(&mock, "rt", &["openid", "email"])
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "new-tok");

        let requests = mock.take_requests();
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("scope".into(), "openid email".into())));
    }

    #[tokio::test]
    async fn revoke_token_delegates_to_client() {
        let cognito =
            AmazonCognito::new("mock.example.com", "cid", Some("secret".into()), "https://app/cb");
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: vec![],
        }]);

        let result = cognito.revoke_token(&mock, "tok").await;
        assert!(result.is_ok());

        let requests = mock.take_requests();
        assert_eq!(requests[0].url, "https://mock.example.com/oauth2/revoke");
    }
}
