use crate::client::OAuth2Client;
use crate::error::Error;
use crate::http::HttpClient;
use crate::pkce::CodeChallengeMethod;
use crate::tokens::OAuth2Tokens;

const AUTHORIZATION_ENDPOINT: &str = "https://lichess.org/oauth";
const TOKEN_ENDPOINT: &str = "https://lichess.org/api/token";

/// Configuration for creating a [`Lichess`] client with a custom HTTP client.
///
/// Use this when you need to provide your own [`HttpClient`] implementation
/// (e.g. a pre-configured `reqwest::Client` with custom timeouts or proxies).
/// For the common case, use [`Lichess::new`] which uses the built-in default client.
pub struct LichessOptions<'a, H: HttpClient> {
    pub client_id: String,
    pub redirect_uri: String,
    pub http_client: &'a H,
}

/// OAuth 2.0 client for [Lichess](https://lichess.org/api).
///
/// Lichess requires PKCE with the S256 challenge method on all authorization requests.
/// This is a public client (no client secret required) that supports the authorization
/// code flow with optional token refresh. Lichess does not support token revocation.
///
/// # Setup
///
/// 1. Create an OAuth application at <https://lichess.org/account/oauth/app/create>.
/// 2. Obtain your client ID from the application settings.
/// 3. Set the redirect URI to match the `redirect_uri` you pass to [`Lichess::new`].
///
/// # Scopes
///
/// Lichess uses space-separated scopes. Common scopes include:
///
/// | Scope | Description |
/// |-------|-------------|
/// | `challenge:read` | Read received challenges |
/// | `puzzle:read` | Read puzzle activity |
/// | `tournament:write` | Create and join tournaments |
/// | `email:read` | Read email address |
///
/// See the full list at <https://lichess.org/api#tag/oauth>.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{Lichess, generate_state, generate_code_verifier};
///
/// # async fn example() -> Result<(), arctic_oauth::Error> {
/// let lichess = Lichess::new(
///     "your-client-id",
///     "https://example.com/callback",
/// );
///
/// // Step 1: Generate PKCE verifier and CSRF state, then redirect the user.
/// let state = generate_state();
/// let code_verifier = generate_code_verifier();
/// let url = lichess.authorization_url(&state, &["challenge:read", "puzzle:read"], &code_verifier);
/// // Store `state` and `code_verifier` in the user's session, then redirect to `url`.
///
/// // Step 2: In your callback handler, exchange the authorization code for tokens.
/// let tokens = lichess
///     .validate_authorization_code("authorization-code", &code_verifier)
///     .await?;
/// println!("Access token: {}", tokens.access_token()?);
/// # Ok(())
/// # }
/// ```
pub struct Lichess<'a, H: HttpClient> {
    client: OAuth2Client,
    http_client: &'a H,
    authorization_endpoint: String,
    token_endpoint: String,
}

impl<'a, H: HttpClient> Lichess<'a, H> {
    /// Creates a Lichess client from a [`LichessOptions`] struct.
    ///
    /// Use this when you need a custom HTTP client. For the common case,
    /// use [`Lichess::new`] instead.
    pub fn from_options(options: LichessOptions<'a, H>) -> Self {
        Self {
            client: OAuth2Client::new(options.client_id, None, Some(options.redirect_uri)),
            http_client: options.http_client,
            authorization_endpoint: AUTHORIZATION_ENDPOINT.to_string(),
            token_endpoint: TOKEN_ENDPOINT.to_string(),
        }
    }
}

#[cfg(feature = "reqwest-client")]
impl Lichess<'static, reqwest::Client> {
    /// Creates a new Lichess OAuth 2.0 client configured with production endpoints.
    ///
    /// Note: Lichess is a public client and does not require a client secret.
    /// Uses the built-in `reqwest::Client` for HTTP requests. To provide a custom
    /// HTTP client, use [`Lichess::from_options`] instead.
    ///
    /// # Arguments
    ///
    /// * `client_id` - The OAuth 2.0 client ID from your Lichess application.
    /// * `redirect_uri` - The URI Lichess will redirect to after authorization. Must match
    ///   the redirect URI configured in your Lichess application settings.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::Lichess;
    ///
    /// let lichess = Lichess::new(
    ///     "your-client-id",
    ///     "https://example.com/callback",
    /// );
    /// ```
    pub fn new(client_id: impl Into<String>, redirect_uri: impl Into<String>) -> Self {
        Self::from_options(LichessOptions {
            client_id: client_id.into(),
            redirect_uri: redirect_uri.into(),
            http_client: crate::http::default_client(),
        })
    }
}

impl<'a, H: HttpClient> Lichess<'a, H> {
    /// Returns the provider name (`"Lichess"`).
    pub fn name(&self) -> &'static str {
        "Lichess"
    }

    /// Builds the Lichess authorization URL that the user should be redirected to.
    ///
    /// The returned URL includes all required OAuth 2.0 and PKCE parameters. Your
    /// application should store `state` and `code_verifier` in the user's session
    /// before redirecting, as both are needed to complete the flow.
    ///
    /// # Arguments
    ///
    /// * `state` - A CSRF token to prevent cross-site request forgery. Use
    ///   [`generate_state`](crate::generate_state) to create one.
    /// * `scopes` - The OAuth 2.0 scopes to request (e.g. `&["challenge:read", "puzzle:read"]`).
    ///   Pass an empty slice for the default scope.
    /// * `code_verifier` - The PKCE code verifier. Use
    ///   [`generate_code_verifier`](crate::generate_code_verifier) to create one.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{Lichess, generate_state, generate_code_verifier};
    ///
    /// let lichess = Lichess::new("client-id", "https://example.com/cb");
    /// let state = generate_state();
    /// let verifier = generate_code_verifier();
    ///
    /// let url = lichess.authorization_url(&state, &["challenge:read"], &verifier);
    /// assert!(url.as_str().starts_with("https://lichess.org/"));
    /// ```
    pub fn authorization_url(&self, state: &str, scopes: &[&str], code_verifier: &str) -> url::Url {
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
    /// Call this in your redirect URI handler after Lichess redirects back with a `code`
    /// query parameter. The `code_verifier` must be the same value used to generate the
    /// authorization URL.
    ///
    /// # Arguments
    ///
    /// * `code` - The authorization code from the `code` query parameter.
    /// * `code_verifier` - The PKCE code verifier stored during the authorization step.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OAuthRequest`] if Lichess rejects the code, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::Lichess;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let lichess = Lichess::new("client-id", "https://example.com/cb");
    ///
    /// let tokens = lichess
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
        self.client
            .validate_authorization_code(
                self.http_client,
                &self.token_endpoint,
                code,
                Some(code_verifier),
            )
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

    fn make_lichess(http_client: &MockHttpClient) -> Lichess<'_, MockHttpClient> {
        Lichess::from_options(LichessOptions {
            client_id: "cid".into(),
            redirect_uri: "https://app/cb".into(),
            http_client,
        })
    }

    #[test]
    fn new_sets_production_endpoints() {
        let mock = MockHttpClient::new(vec![]);
        let lichess = make_lichess(&mock);
        assert_eq!(lichess.authorization_endpoint, AUTHORIZATION_ENDPOINT);
        assert_eq!(lichess.token_endpoint, TOKEN_ENDPOINT);
    }

    #[test]
    fn name_returns_lichess() {
        let mock = MockHttpClient::new(vec![]);
        let lichess = make_lichess(&mock);
        assert_eq!(lichess.name(), "Lichess");
    }

    #[test]
    fn authorization_url_includes_pkce_params() {
        let mock = MockHttpClient::new(vec![]);
        let lichess = make_lichess(&mock);
        let url = lichess.authorization_url(
            "state123",
            &["challenge:read", "puzzle:read"],
            "my-verifier",
        );

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.contains(&("client_id".into(), "cid".into())));
        assert!(pairs.contains(&("state".into(), "state123".into())));
        assert!(pairs.contains(&("scope".into(), "challenge:read puzzle:read".into())));
        assert!(pairs.contains(&("redirect_uri".into(), "https://app/cb".into())));
        assert!(pairs.iter().any(|(k, _)| k == "code_challenge"));
        assert!(pairs.contains(&("code_challenge_method".into(), "S256".into())));
    }

    #[test]
    fn authorization_url_omits_scope_when_empty() {
        let mock = MockHttpClient::new(vec![]);
        let lichess = make_lichess(&mock);
        let url = lichess.authorization_url("state123", &[], "my-verifier");

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(!pairs.iter().any(|(k, _)| k == "scope"));
        assert!(pairs.iter().any(|(k, _)| k == "code_challenge"));
        assert!(pairs.contains(&("code_challenge_method".into(), "S256".into())));
    }

    #[tokio::test]
    async fn validate_authorization_code_public_client_sends_client_id_in_body() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "lichess-tok",
                "token_type": "Bearer",
                "expires_in": 5270400
            }))
            .unwrap(),
        }]);
        let lichess = make_lichess(&mock);

        let tokens = lichess
            .validate_authorization_code("auth-code", "my-verifier")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "lichess-tok");

        let requests = mock.take_requests();
        assert_eq!(requests[0].url, "https://lichess.org/api/token");
        // Public client: no Authorization header
        assert!(get_header(&requests[0], "Authorization").is_none());

        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("grant_type".into(), "authorization_code".into())));
        assert!(body.contains(&("code".into(), "auth-code".into())));
        assert!(body.contains(&("code_verifier".into(), "my-verifier".into())));
        assert!(body.contains(&("client_id".into(), "cid".into())));
        assert!(body.contains(&("redirect_uri".into(), "https://app/cb".into())));
    }
}
