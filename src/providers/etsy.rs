use crate::client::OAuth2Client;
use crate::error::Error;
use crate::http::HttpClient;
use crate::pkce::CodeChallengeMethod;
use crate::tokens::OAuth2Tokens;

const AUTHORIZATION_ENDPOINT: &str = "https://www.etsy.com/oauth/connect";
const TOKEN_ENDPOINT: &str = "https://api.etsy.com/v3/public/oauth/token";

/// OAuth 2.0 client for [Etsy](https://developers.etsy.com/documentation/essentials/authentication).
///
/// Etsy requires PKCE with the S256 challenge method on all authorization requests.
/// This is a public client (no client secret) supporting the authorization code flow
/// with token refresh. Etsy uses the Open API v3.
///
/// # Setup
///
/// 1. Create an app in the [Etsy Developer Portal](https://www.etsy.com/developers/register).
/// 2. Copy your API Key (client ID) from the app settings.
/// 3. Add the redirect URI to your app's allowed redirect URIs.
///
/// # Scopes
///
/// Etsy uses space-separated scopes. Common scopes include:
///
/// | Scope | Description |
/// |-------|-------------|
/// | `listings_r` | Read shop listings |
/// | `listings_w` | Write shop listings |
/// | `transactions_r` | Read shop transactions |
/// | `shops_r` | Read shop information |
/// | `profile_r` | Read user profile |
///
/// See the full list at <https://developers.etsy.com/documentation/essentials/authentication#scopes>.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{Etsy, ReqwestClient, generate_state, generate_code_verifier};
///
/// # async fn example() -> Result<(), arctic_oauth::Error> {
/// let etsy = Etsy::new(
///     "your-api-key",
///     "https://example.com/callback",
/// );
///
/// // Step 1: Generate PKCE verifier and CSRF state, then redirect the user.
/// let state = generate_state();
/// let code_verifier = generate_code_verifier();
/// let url = etsy.authorization_url(&state, &["listings_r", "transactions_r"], &code_verifier);
/// // Store `state` and `code_verifier` in the user's session, then redirect to `url`.
///
/// // Step 2: In your callback handler, exchange the authorization code for tokens.
/// let http = ReqwestClient::new();
/// let tokens = etsy
///     .validate_authorization_code(&http, "authorization-code", &code_verifier)
///     .await?;
/// println!("Access token: {}", tokens.access_token()?);
///
/// // Step 3 (optional): Refresh an expired access token.
/// let refreshed = etsy
///     .refresh_access_token(&http, tokens.refresh_token()?)
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct Etsy {
    client: OAuth2Client,
    authorization_endpoint: String,
    token_endpoint: String,
}

impl Etsy {
    /// Creates a new Etsy OAuth 2.0 client configured with production endpoints.
    ///
    /// # Arguments
    ///
    /// * `client_id` - The API Key from your Etsy Developer Portal app.
    /// * `redirect_uri` - The URI Etsy will redirect to after authorization. Must match
    ///   one of the redirect URIs configured in your Etsy app.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::Etsy;
    ///
    /// let etsy = Etsy::new(
    ///     "your-api-key",
    ///     "https://example.com/callback",
    /// );
    /// ```
    pub fn new(
        client_id: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        Self {
            client: OAuth2Client::new(client_id, None, Some(redirect_uri.into())),
            authorization_endpoint: AUTHORIZATION_ENDPOINT.to_string(),
            token_endpoint: TOKEN_ENDPOINT.to_string(),
        }
    }
}

#[cfg(any(test, feature = "testing"))]
impl Etsy {
    /// Creates an Etsy client with custom endpoint URLs.
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
    /// use arctic_oauth::Etsy;
    ///
    /// let etsy = Etsy::with_endpoints(
    ///     "test-api-key",
    ///     "http://localhost/callback",
    ///     "http://localhost:8080/authorize",
    ///     "http://localhost:8080/token",
    /// );
    /// # }
    /// ```
    pub fn with_endpoints(
        client_id: impl Into<String>,
        redirect_uri: impl Into<String>,
        authorization_endpoint: &str,
        token_endpoint: &str,
    ) -> Self {
        Self {
            client: OAuth2Client::new(client_id, None, Some(redirect_uri.into())),
            authorization_endpoint: authorization_endpoint.to_string(),
            token_endpoint: token_endpoint.to_string(),
        }
    }
}

impl Etsy {
    /// Returns the provider name (`"Etsy"`).
    pub fn name(&self) -> &'static str {
        "Etsy"
    }

    /// Builds the Etsy authorization URL that the user should be redirected to.
    ///
    /// The returned URL includes all required OAuth 2.0 and PKCE parameters. Your
    /// application should store `state` and `code_verifier` in the user's session
    /// before redirecting, as both are needed to complete the flow.
    ///
    /// # Arguments
    ///
    /// * `state` - A CSRF token to prevent cross-site request forgery. Use
    ///   [`generate_state`](crate::generate_state) to create one.
    /// * `scopes` - The OAuth 2.0 scopes to request (e.g. `&["listings_r", "transactions_r"]`).
    /// * `code_verifier` - The PKCE code verifier. Use
    ///   [`generate_code_verifier`](crate::generate_code_verifier) to create one.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{Etsy, generate_state, generate_code_verifier};
    ///
    /// let etsy = Etsy::new("api-key", "https://example.com/cb");
    /// let state = generate_state();
    /// let verifier = generate_code_verifier();
    ///
    /// let url = etsy.authorization_url(&state, &["listings_r", "shops_r"], &verifier);
    /// assert!(url.as_str().starts_with("https://www.etsy.com/"));
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
    /// Call this in your redirect URI handler after Etsy redirects back with a `code`
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
    /// Returns [`Error::OAuthRequest`] if Etsy rejects the code, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::{Etsy, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let etsy = Etsy::new("api-key", "https://example.com/cb");
    /// let http = ReqwestClient::new();
    ///
    /// let tokens = etsy
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
            .validate_authorization_code(http_client, &self.token_endpoint, code, Some(code_verifier))
            .await
    }

    /// Refreshes an expired access token using a refresh token.
    ///
    /// Etsy access tokens typically expire after a set period. If your initial token
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
    /// # use arctic_oauth::{Etsy, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let etsy = Etsy::new("api-key", "https://example.com/cb");
    /// let http = ReqwestClient::new();
    ///
    /// let new_tokens = etsy
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
        let etsy = Etsy::new("cid", "https://app/cb");
        assert_eq!(etsy.authorization_endpoint, AUTHORIZATION_ENDPOINT);
        assert_eq!(etsy.token_endpoint, TOKEN_ENDPOINT);
    }

    #[test]
    fn with_endpoints_overrides_urls() {
        let etsy = Etsy::with_endpoints(
            "cid",
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
        );
        assert_eq!(etsy.authorization_endpoint, "https://mock/authorize");
        assert_eq!(etsy.token_endpoint, "https://mock/token");
    }

    #[test]
    fn name_returns_etsy() {
        let etsy = Etsy::new("cid", "https://app/cb");
        assert_eq!(etsy.name(), "Etsy");
    }

    #[test]
    fn authorization_url_includes_pkce_params() {
        let etsy = Etsy::new("cid", "https://app/cb");
        let url = etsy.authorization_url("state123", &["listings_r", "transactions_r"], "my-verifier");

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.contains(&("client_id".into(), "cid".into())));
        assert!(pairs.contains(&("state".into(), "state123".into())));
        assert!(pairs.contains(&("scope".into(), "listings_r transactions_r".into())));
        assert!(pairs.contains(&("redirect_uri".into(), "https://app/cb".into())));
        assert!(pairs.iter().any(|(k, _)| k == "code_challenge"));
        assert!(pairs.contains(&("code_challenge_method".into(), "S256".into())));
    }

    #[test]
    fn authorization_url_omits_scope_when_empty() {
        let etsy = Etsy::new("cid", "https://app/cb");
        let url = etsy.authorization_url("state123", &[], "my-verifier");

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(!pairs.iter().any(|(k, _)| k == "scope"));
        // PKCE params should still be present
        assert!(pairs.iter().any(|(k, _)| k == "code_challenge"));
        assert!(pairs.contains(&("code_challenge_method".into(), "S256".into())));
    }

    #[tokio::test]
    async fn validate_authorization_code_public_client_sends_client_id_in_body() {
        let etsy = Etsy::with_endpoints(
            "cid",
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "etsy-tok",
                "token_type": "Bearer",
                "expires_in": 3600
            }))
            .unwrap(),
        }]);

        let tokens = etsy
            .validate_authorization_code(&mock, "auth-code", "my-verifier")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "etsy-tok");

        let requests = mock.take_requests();
        assert_eq!(requests[0].url, "https://mock/token");
        // Public client: no Authorization header
        assert!(get_header(&requests[0], "Authorization").is_none());

        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("grant_type".into(), "authorization_code".into())));
        assert!(body.contains(&("code".into(), "auth-code".into())));
        assert!(body.contains(&("code_verifier".into(), "my-verifier".into())));
        assert!(body.contains(&("client_id".into(), "cid".into())));
        assert!(body.contains(&("redirect_uri".into(), "https://app/cb".into())));
    }

    #[tokio::test]
    async fn refresh_access_token_public_client() {
        let etsy = Etsy::with_endpoints(
            "cid",
            "https://app/cb",
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

        let tokens = etsy
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
    }
}
