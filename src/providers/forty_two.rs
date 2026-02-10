use crate::error::Error;
use crate::http::HttpClient;
use crate::request::{create_oauth2_request, send_token_request};
use crate::tokens::OAuth2Tokens;

const AUTHORIZATION_ENDPOINT: &str = "https://api.intra.42.fr/oauth/authorize";
const TOKEN_ENDPOINT: &str = "https://api.intra.42.fr/oauth/token";

/// OAuth 2.0 client for [42 (École 42)](https://api.intra.42.fr/apidoc).
///
/// 42 uses the standard authorization code flow without requiring PKCE.
/// This client supports token exchange using client credentials sent in the request body.
///
/// # Setup
///
/// 1. Register your application at the [42 API applications page](https://profile.intra.42.fr/oauth/applications).
/// 2. Note your client ID and client secret from the application settings.
/// 3. Set the redirect URI to match the `redirect_uri` you pass to [`FortyTwo::new`].
///
/// # Scopes
///
/// 42 uses space-separated scopes. Common scopes include:
///
/// | Scope | Description |
/// |-------|-------------|
/// | `public` | Read public profile information |
/// | `projects` | Access project information |
/// | `profile` | Read detailed user profile |
///
/// See the full list at <https://api.intra.42.fr/apidoc/guides/getting_started>.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{FortyTwo, ReqwestClient, generate_state};
///
/// # async fn example() -> Result<(), arctic_oauth::Error> {
/// let forty_two = FortyTwo::new(
///     "your-client-id",
///     "your-client-secret",
///     "https://example.com/callback",
/// );
///
/// // Step 1: Generate CSRF state and redirect the user.
/// let state = generate_state();
/// let url = forty_two.authorization_url(&state, &["public", "projects"]);
/// // Store `state` in the user's session, then redirect to `url`.
///
/// // Step 2: In your callback handler, exchange the authorization code for tokens.
/// let http = ReqwestClient::new();
/// let tokens = forty_two
///     .validate_authorization_code(&http, "authorization-code")
///     .await?;
/// println!("Access token: {}", tokens.access_token()?);
/// # Ok(())
/// # }
/// ```
pub struct FortyTwo {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    authorization_endpoint: String,
    token_endpoint: String,
}

impl FortyTwo {
    /// Creates a new 42 OAuth 2.0 client configured with production endpoints.
    ///
    /// # Arguments
    ///
    /// * `client_id` - The OAuth 2.0 client ID from your 42 application settings.
    /// * `client_secret` - The OAuth 2.0 client secret from your 42 application settings.
    /// * `redirect_uri` - The URI 42 will redirect to after authorization. Must match
    ///   one of the redirect URIs configured in your 42 application.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::FortyTwo;
    ///
    /// let forty_two = FortyTwo::new(
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
        }
    }
}

#[cfg(any(test, feature = "testing"))]
impl FortyTwo {
    /// Creates a 42 client with custom endpoint URLs.
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
    /// use arctic_oauth::FortyTwo;
    ///
    /// let forty_two = FortyTwo::with_endpoints(
    ///     "test-client-id",
    ///     "test-secret",
    ///     "http://localhost/callback",
    ///     "http://localhost:8080/authorize",
    ///     "http://localhost:8080/token",
    /// );
    /// # }
    /// ```
    pub fn with_endpoints(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
        authorization_endpoint: &str,
        token_endpoint: &str,
    ) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri: redirect_uri.into(),
            authorization_endpoint: authorization_endpoint.to_string(),
            token_endpoint: token_endpoint.to_string(),
        }
    }
}

impl FortyTwo {
    /// Returns the provider name (`"42"`).
    pub fn name(&self) -> &'static str {
        "42"
    }

    /// Builds the 42 authorization URL that the user should be redirected to.
    ///
    /// The returned URL includes all required OAuth 2.0 parameters. Your application
    /// should store `state` in the user's session before redirecting, as it is needed
    /// to prevent CSRF attacks.
    ///
    /// # Arguments
    ///
    /// * `state` - A CSRF token to prevent cross-site request forgery. Use
    ///   [`generate_state`](crate::generate_state) to create one.
    /// * `scopes` - The OAuth 2.0 scopes to request (e.g. `&["public", "projects"]`).
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{FortyTwo, generate_state};
    ///
    /// let forty_two = FortyTwo::new("client-id", "client-secret", "https://example.com/cb");
    /// let state = generate_state();
    ///
    /// let url = forty_two.authorization_url(&state, &["public", "projects"]);
    /// assert!(url.as_str().starts_with("https://api.intra.42.fr/"));
    /// ```
    pub fn authorization_url(&self, state: &str, scopes: &[&str]) -> url::Url {
        let mut url = url::Url::parse(&self.authorization_endpoint)
            .expect("invalid authorization endpoint URL");

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
    /// Call this in your redirect URI handler after 42 redirects back with a `code`
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
    /// Returns [`Error::OAuthRequest`] if 42 rejects the code, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::{FortyTwo, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let forty_two = FortyTwo::new("client-id", "secret", "https://example.com/cb");
    /// let http = ReqwestClient::new();
    ///
    /// let tokens = forty_two
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
            ("client_id".to_string(), self.client_id.clone()),
            ("client_secret".to_string(), self.client_secret.clone()),
            ("redirect_uri".to_string(), self.redirect_uri.clone()),
        ];

        let request = create_oauth2_request(&self.token_endpoint, &body);
        send_token_request(http_client, request).await
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
        let provider = FortyTwo::new("cid", "secret", "https://app/cb");
        assert_eq!(provider.authorization_endpoint, AUTHORIZATION_ENDPOINT);
        assert_eq!(provider.token_endpoint, TOKEN_ENDPOINT);
    }

    #[test]
    fn name_returns_42() {
        let provider = FortyTwo::new("cid", "secret", "https://app/cb");
        assert_eq!(provider.name(), "42");
    }

    #[test]
    fn authorization_url_builds_correct_params() {
        let provider = FortyTwo::new("cid", "secret", "https://app/cb");
        let url = provider.authorization_url("state123", &["public", "projects"]);

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.contains(&("client_id".into(), "cid".into())));
        assert!(pairs.contains(&("state".into(), "state123".into())));
        assert!(pairs.contains(&("scope".into(), "public projects".into())));
        assert!(pairs.contains(&("redirect_uri".into(), "https://app/cb".into())));
    }

    #[test]
    fn authorization_url_omits_scope_when_empty() {
        let provider = FortyTwo::new("cid", "secret", "https://app/cb");
        let url = provider.authorization_url("state123", &[]);

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(!pairs.iter().any(|(k, _)| k == "scope"));
    }

    #[tokio::test]
    async fn validate_authorization_code_sends_body_credentials() {
        let provider = FortyTwo::with_endpoints(
            "cid",
            "secret",
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "42-tok",
                "token_type": "bearer"
            }))
            .unwrap(),
        }]);

        let tokens = provider
            .validate_authorization_code(&mock, "auth-code")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "42-tok");

        let requests = mock.take_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url, "https://mock/token");

        // No Authorization header (body credentials, not Basic Auth)
        assert!(get_header(&requests[0], "Authorization").is_none());

        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("grant_type".into(), "authorization_code".into())));
        assert!(body.contains(&("code".into(), "auth-code".into())));
        assert!(body.contains(&("client_id".into(), "cid".into())));
        assert!(body.contains(&("client_secret".into(), "secret".into())));
        assert!(body.contains(&("redirect_uri".into(), "https://app/cb".into())));
    }
}
