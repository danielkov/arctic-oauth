use crate::error::Error;
use crate::http::HttpClient;
use crate::pkce::{CodeChallengeMethod, create_code_challenge};
use crate::request::{create_oauth2_request, send_token_request};
use crate::tokens::OAuth2Tokens;

const AUTHORIZATION_ENDPOINT: &str = "https://api.workos.com/sso/authorize";
const TOKEN_ENDPOINT: &str = "https://api.workos.com/sso/token";

/// Configuration for creating a [`WorkOS`] client with a custom HTTP client.
///
/// Use this when you need to provide your own [`HttpClient`] implementation
/// (e.g. a pre-configured `reqwest::Client` with custom timeouts or proxies).
/// For the common case, use [`WorkOS::new`] which uses the built-in default client.
pub struct WorkOSOptions<'a, H: HttpClient> {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_uri: String,
    pub http_client: &'a H,
}

/// OAuth 2.0 client for [WorkOS](https://workos.com/docs/reference/sso).
///
/// WorkOS supports optional PKCE with the S256 challenge method. The client secret is
/// also optional, allowing for public clients using PKCE. This client supports the
/// authorization code flow but not token refresh or revocation.
///
/// # Setup
///
/// 1. Create an account and configure SSO at the [WorkOS Dashboard](https://dashboard.workos.com/).
/// 2. Obtain your Client ID from the Configuration section.
/// 3. Optionally obtain a Client Secret for confidential clients.
/// 4. Configure the redirect URI to match the `redirect_uri` you pass to [`WorkOS::new`].
///
/// # Scopes
///
/// WorkOS does not use scopes in the traditional OAuth sense. Instead, authentication
/// is configured through SSO connections and organizations in the WorkOS Dashboard.
/// The authorization flow automatically grants access based on the organization's
/// configuration.
///
/// See the documentation at <https://workos.com/docs/reference/sso>.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{WorkOS, generate_state, generate_code_verifier};
///
/// # async fn example() -> Result<(), arctic_oauth::Error> {
/// // Public client with PKCE
/// let workos = WorkOS::new(
///     "your-client-id",
///     None,
///     "https://example.com/callback",
/// );
///
/// // Step 1: Generate PKCE verifier and CSRF state, then redirect the user.
/// let state = generate_state();
/// let code_verifier = generate_code_verifier();
/// let url = workos.authorization_url(&state, Some(&code_verifier));
/// // Store `state` and `code_verifier` in the user's session, then redirect to `url`.
///
/// // Step 2: In your callback handler, exchange the authorization code for tokens.
/// let tokens = workos
///     .validate_authorization_code("authorization-code", Some(&code_verifier))
///     .await?;
/// println!("Access token: {}", tokens.access_token()?);
/// # Ok(())
/// # }
/// ```
pub struct WorkOS<'a, H: HttpClient> {
    client_id: String,
    client_secret: Option<String>,
    redirect_uri: String,
    http_client: &'a H,
    authorization_endpoint: String,
    token_endpoint: String,
}

impl<'a, H: HttpClient> WorkOS<'a, H> {
    /// Creates a WorkOS client from a [`WorkOSOptions`] struct.
    ///
    /// Use this when you need a custom HTTP client. For the common case,
    /// use [`WorkOS::new`] instead.
    pub fn from_options(options: WorkOSOptions<'a, H>) -> Self {
        Self {
            client_id: options.client_id,
            client_secret: options.client_secret,
            redirect_uri: options.redirect_uri,
            http_client: options.http_client,
            authorization_endpoint: AUTHORIZATION_ENDPOINT.to_string(),
            token_endpoint: TOKEN_ENDPOINT.to_string(),
        }
    }
}

#[cfg(feature = "reqwest-client")]
impl WorkOS<'static, reqwest::Client> {
    /// Creates a new WorkOS OAuth 2.0 client using the default HTTP client.
    ///
    /// # Arguments
    ///
    /// * `client_id` - The OAuth 2.0 client ID from WorkOS Dashboard.
    /// * `client_secret` - The OAuth 2.0 client secret (optional). Use `None` for public
    ///   clients using PKCE, or `Some(secret)` for confidential clients.
    /// * `redirect_uri` - The URI WorkOS will redirect to after authorization. Must match
    ///   the redirect URI configured in your WorkOS application.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::WorkOS;
    ///
    /// // Public client
    /// let workos = WorkOS::new(
    ///     "your-client-id",
    ///     None,
    ///     "https://example.com/callback",
    /// );
    ///
    /// // Confidential client
    /// let workos = WorkOS::new(
    ///     "your-client-id",
    ///     Some("your-client-secret".to_string()),
    ///     "https://example.com/callback",
    /// );
    /// ```
    pub fn new(
        client_id: impl Into<String>,
        client_secret: Option<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        Self::from_options(WorkOSOptions {
            client_id: client_id.into(),
            client_secret,
            redirect_uri: redirect_uri.into(),
            http_client: crate::http::default_client(),
        })
    }
}

impl<'a, H: HttpClient> WorkOS<'a, H> {
    /// Returns the provider name (`"WorkOS"`).
    pub fn name(&self) -> &'static str {
        "WorkOS"
    }

    /// Builds the WorkOS authorization URL that the user should be redirected to.
    ///
    /// The returned URL includes all required OAuth 2.0 parameters. If a code verifier is
    /// provided, PKCE parameters with S256 challenge method are included. Your application
    /// should store `state` and `code_verifier` (if used) in the user's session before
    /// redirecting.
    ///
    /// # Arguments
    ///
    /// * `state` - A CSRF token to prevent cross-site request forgery. Use
    ///   [`generate_state`](crate::generate_state) to create one.
    /// * `code_verifier` - Optional PKCE code verifier. Use
    ///   [`generate_code_verifier`](crate::generate_code_verifier) to create one for
    ///   public clients.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{WorkOS, generate_state, generate_code_verifier};
    ///
    /// let workos = WorkOS::new("client-id", None, "https://example.com/cb");
    /// let state = generate_state();
    /// let verifier = generate_code_verifier();
    ///
    /// let url = workos.authorization_url(&state, Some(&verifier));
    /// assert!(url.as_str().starts_with("https://api.workos.com/"));
    /// ```
    pub fn authorization_url(&self, state: &str, code_verifier: Option<&str>) -> url::Url {
        let mut url =
            url::Url::parse(&self.authorization_endpoint).expect("invalid authorization endpoint");
        {
            let mut params = url.query_pairs_mut();
            params.append_pair("response_type", "code");
            params.append_pair("client_id", &self.client_id);
            params.append_pair("state", state);
            params.append_pair("redirect_uri", &self.redirect_uri);
            if let Some(verifier) = code_verifier {
                let challenge = create_code_challenge(verifier, CodeChallengeMethod::S256);
                params.append_pair("code_challenge", &challenge);
                params.append_pair("code_challenge_method", "S256");
            }
        }
        url
    }

    /// Exchanges an authorization code for access tokens.
    ///
    /// Call this in your redirect URI handler after WorkOS redirects back with a `code`
    /// query parameter. The `code_verifier` must be provided if PKCE was used during
    /// authorization. Credentials are sent in the POST body (not via Basic auth).
    ///
    /// # Arguments
    ///
    /// * `code` - The authorization code from the `code` query parameter.
    /// * `code_verifier` - The PKCE code verifier if it was used during authorization.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OAuthRequest`] if WorkOS rejects the code, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::WorkOS;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let workos = WorkOS::new("client-id", None, "https://example.com/cb");
    ///
    /// let tokens = workos
    ///     .validate_authorization_code("the-auth-code", Some("the-code-verifier"))
    ///     .await?;
    ///
    /// println!("Access token: {}", tokens.access_token()?);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn validate_authorization_code(
        &self,
        code: &str,
        code_verifier: Option<&str>,
    ) -> Result<OAuth2Tokens, Error> {
        let mut body = vec![
            ("grant_type".to_string(), "authorization_code".to_string()),
            ("code".to_string(), code.to_string()),
            ("redirect_uri".to_string(), self.redirect_uri.clone()),
            ("client_id".to_string(), self.client_id.clone()),
        ];
        if let Some(ref secret) = self.client_secret {
            body.push(("client_secret".to_string(), secret.clone()));
        }
        if let Some(verifier) = code_verifier {
            body.push(("code_verifier".to_string(), verifier.to_string()));
        }
        let request = create_oauth2_request(&self.token_endpoint, &body);
        send_token_request(self.http_client, request).await
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

    fn make_workos_confidential(http_client: &MockHttpClient) -> WorkOS<'_, MockHttpClient> {
        WorkOS::from_options(WorkOSOptions {
            client_id: "cid".into(),
            client_secret: Some("secret".into()),
            redirect_uri: "https://app/cb".into(),
            http_client,
        })
    }

    fn make_workos_public(http_client: &MockHttpClient) -> WorkOS<'_, MockHttpClient> {
        WorkOS::from_options(WorkOSOptions {
            client_id: "cid".into(),
            client_secret: None,
            redirect_uri: "https://app/cb".into(),
            http_client,
        })
    }

    #[test]
    fn new_sets_production_endpoints() {
        let mock = MockHttpClient::new(vec![]);
        let workos = make_workos_confidential(&mock);
        assert_eq!(workos.authorization_endpoint, AUTHORIZATION_ENDPOINT);
        assert_eq!(workos.token_endpoint, TOKEN_ENDPOINT);
    }

    #[test]
    fn name_returns_workos() {
        let mock = MockHttpClient::new(vec![]);
        let workos = make_workos_confidential(&mock);
        assert_eq!(workos.name(), "WorkOS");
    }

    #[test]
    fn authorization_url_without_pkce() {
        let mock = MockHttpClient::new(vec![]);
        let workos = make_workos_confidential(&mock);
        let url = workos.authorization_url("state123", None);

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.contains(&("client_id".into(), "cid".into())));
        assert!(pairs.contains(&("state".into(), "state123".into())));
        assert!(pairs.contains(&("redirect_uri".into(), "https://app/cb".into())));
        assert!(!pairs.iter().any(|(k, _)| k == "scope"));
        assert!(!pairs.iter().any(|(k, _)| k == "code_challenge"));
        assert!(!pairs.iter().any(|(k, _)| k == "code_challenge_method"));
    }

    #[test]
    fn authorization_url_with_pkce() {
        let mock = MockHttpClient::new(vec![]);
        let workos = make_workos_confidential(&mock);
        let url = workos.authorization_url("state123", Some("my-verifier"));

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.contains(&("client_id".into(), "cid".into())));
        assert!(pairs.iter().any(|(k, _)| k == "code_challenge"));
        assert!(pairs.contains(&("code_challenge_method".into(), "S256".into())));
    }

    #[test]
    fn authorization_url_no_scopes() {
        let mock = MockHttpClient::new(vec![]);
        let workos = make_workos_confidential(&mock);
        let url = workos.authorization_url("state123", None);

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(!pairs.iter().any(|(k, _)| k == "scope"));
    }

    #[tokio::test]
    async fn validate_authorization_code_with_secret() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "workos-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);
        let workos = make_workos_confidential(&mock);

        let tokens = workos
            .validate_authorization_code("auth-code", None)
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "workos-tok");

        let requests = mock.take_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url, "https://api.workos.com/sso/token");
        assert!(get_header(&requests[0], "Authorization").is_none());

        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("grant_type".into(), "authorization_code".into())));
        assert!(body.contains(&("code".into(), "auth-code".into())));
        assert!(body.contains(&("client_id".into(), "cid".into())));
        assert!(body.contains(&("client_secret".into(), "secret".into())));
        assert!(body.contains(&("redirect_uri".into(), "https://app/cb".into())));
        assert!(!body.iter().any(|(k, _)| k == "code_verifier"));
    }

    #[tokio::test]
    async fn validate_authorization_code_public_client() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "workos-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);
        let workos = make_workos_public(&mock);

        workos
            .validate_authorization_code("auth-code", Some("my-verifier"))
            .await
            .unwrap();

        let requests = mock.take_requests();
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("client_id".into(), "cid".into())));
        assert!(!body.iter().any(|(k, _)| k == "client_secret"));
        assert!(body.contains(&("code_verifier".into(), "my-verifier".into())));
    }

    #[tokio::test]
    async fn validate_authorization_code_with_pkce() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "workos-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);
        let workos = make_workos_confidential(&mock);

        workos
            .validate_authorization_code("auth-code", Some("my-verifier"))
            .await
            .unwrap();

        let requests = mock.take_requests();
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("code_verifier".into(), "my-verifier".into())));
        assert!(body.contains(&("client_secret".into(), "secret".into())));
    }
}
