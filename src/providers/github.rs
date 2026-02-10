use crate::error::Error;
use crate::http::HttpClient;
use crate::request::{create_oauth2_request, encode_basic_credentials};
use crate::tokens::OAuth2Tokens;

const AUTHORIZATION_ENDPOINT: &str = "https://github.com/login/oauth/authorize";
const TOKEN_ENDPOINT: &str = "https://github.com/login/oauth/access_token";

/// OAuth 2.0 client for [GitHub](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps).
///
/// GitHub does not require or support PKCE for OAuth Apps. This client supports the authorization
/// code flow for token exchange. Note that GitHub has a unique behavior where OAuth errors can be
/// returned with HTTP 200 status code, which this client handles correctly.
///
/// # Setup
///
/// 1. Go to **Settings > Developer settings > OAuth Apps** in your GitHub account or organization.
/// 2. Click **New OAuth App** and fill in the application details.
/// 3. Set the **Authorization callback URL** to match the `redirect_uri` you pass to [`GitHub::new`].
/// 4. Note your **Client ID** and generate a **Client Secret**.
///
/// # Scopes
///
/// GitHub uses space-separated scopes. Common scopes include:
///
/// | Scope | Description |
/// |-------|-------------|
/// | `repo` | Full control of private repositories |
/// | `user` | Read/write access to profile info |
/// | `read:user` | Read access to profile info |
/// | `user:email` | Access to user email addresses |
/// | `gist` | Write access to gists |
///
/// See the full list at <https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps>.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{GitHub, ReqwestClient, generate_state};
///
/// # async fn example() -> Result<(), arctic_oauth::Error> {
/// let github = GitHub::new(
///     "your-client-id",
///     "your-client-secret",
///     Some("https://example.com/callback".to_string()),
/// );
///
/// // Step 1: Generate CSRF state and redirect the user.
/// let state = generate_state();
/// let url = github.authorization_url(&state, &["repo", "user"]);
/// // Store `state` in the user's session, then redirect to `url`.
///
/// // Step 2: In your callback handler, exchange the authorization code for tokens.
/// let http = ReqwestClient::new();
/// let tokens = github
///     .validate_authorization_code(&http, "authorization-code")
///     .await?;
/// println!("Access token: {}", tokens.access_token()?);
/// # Ok(())
/// # }
/// ```
pub struct GitHub {
    client_id: String,
    client_secret: String,
    redirect_uri: Option<String>,
    authorization_endpoint: String,
    token_endpoint: String,
}

impl GitHub {
    /// Creates a new GitHub OAuth 2.0 client configured with production endpoints.
    ///
    /// # Arguments
    ///
    /// * `client_id` - The OAuth 2.0 client ID from GitHub's OAuth App settings.
    /// * `client_secret` - The OAuth 2.0 client secret from GitHub's OAuth App settings.
    /// * `redirect_uri` - The URI GitHub will redirect to after authorization. Must match
    ///   the callback URL configured in your GitHub OAuth App. Pass `None` to omit the
    ///   redirect URI from requests (GitHub will use the default configured in the app).
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::GitHub;
    ///
    /// let github = GitHub::new(
    ///     "your-client-id",
    ///     "your-client-secret",
    ///     Some("https://example.com/callback".to_string()),
    /// );
    /// ```
    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: Option<String>,
    ) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri,
            authorization_endpoint: AUTHORIZATION_ENDPOINT.to_string(),
            token_endpoint: TOKEN_ENDPOINT.to_string(),
        }
    }
}

#[cfg(any(test, feature = "testing"))]
impl GitHub {
    /// Creates a GitHub client with custom endpoint URLs.
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
    /// use arctic_oauth::GitHub;
    ///
    /// let github = GitHub::with_endpoints(
    ///     "test-client-id",
    ///     "test-secret",
    ///     Some("http://localhost/callback".to_string()),
    ///     "http://localhost:8080/authorize",
    ///     "http://localhost:8080/token",
    /// );
    /// # }
    /// ```
    pub fn with_endpoints(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: Option<String>,
        authorization_endpoint: &str,
        token_endpoint: &str,
    ) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri,
            authorization_endpoint: authorization_endpoint.to_string(),
            token_endpoint: token_endpoint.to_string(),
        }
    }
}

impl GitHub {
    /// Returns the provider name (`"GitHub"`).
    pub fn name(&self) -> &'static str {
        "GitHub"
    }

    /// Builds the GitHub authorization URL that the user should be redirected to.
    ///
    /// The returned URL includes all required OAuth 2.0 parameters. Your application should
    /// store `state` in the user's session before redirecting, as it is needed to validate
    /// the callback and prevent CSRF attacks.
    ///
    /// # Arguments
    ///
    /// * `state` - A CSRF token to prevent cross-site request forgery. Use
    ///   [`generate_state`](crate::generate_state) to create one.
    /// * `scopes` - The OAuth 2.0 scopes to request (e.g. `&["repo", "user"]`).
    ///   Pass an empty slice `&[]` for no specific scopes.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{GitHub, generate_state};
    ///
    /// let github = GitHub::new("client-id", "client-secret", Some("https://example.com/cb".to_string()));
    /// let state = generate_state();
    ///
    /// let url = github.authorization_url(&state, &["repo", "user"]);
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

            if let Some(ref redirect_uri) = self.redirect_uri {
                params.append_pair("redirect_uri", redirect_uri);
            }
        }

        url
    }

    /// Exchanges an authorization code for access and refresh tokens.
    ///
    /// Call this in your redirect URI handler after GitHub redirects back with a `code`
    /// query parameter. Note that GitHub has a unique behavior where OAuth errors can be
    /// returned with HTTP 200 status code; this method handles that correctly.
    ///
    /// # Arguments
    ///
    /// * `http_client` - An [`HttpClient`](crate::HttpClient) implementation (e.g.
    ///   [`ReqwestClient`](crate::ReqwestClient)).
    /// * `code` - The authorization code from the `code` query parameter.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OAuthRequest`] if GitHub rejects the code (including errors returned
    /// with HTTP 200), or [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::{GitHub, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let github = GitHub::new("client-id", "secret", Some("https://example.com/cb".to_string()));
    /// let http = ReqwestClient::new();
    ///
    /// let tokens = github
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
        let mut body = vec![
            ("grant_type".to_string(), "authorization_code".to_string()),
            ("code".to_string(), code.to_string()),
            ("client_id".to_string(), self.client_id.clone()),
        ];

        if let Some(ref redirect_uri) = self.redirect_uri {
            body.push(("redirect_uri".to_string(), redirect_uri.clone()));
        }

        let mut request = create_oauth2_request(&self.token_endpoint, &body);
        request.headers.push((
            "Authorization".to_string(),
            encode_basic_credentials(&self.client_id, &self.client_secret),
        ));

        let response = http_client.send(request).await?;

        match response.status {
            200 => {
                let body_str = String::from_utf8_lossy(&response.body).into_owned();
                let json: serde_json::Value =
                    serde_json::from_str(&body_str).map_err(|_| Error::UnexpectedErrorBody {
                        status: 200,
                        body: body_str.clone(),
                    })?;

                // GitHub returns errors with HTTP 200 status
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

    #[test]
    fn new_sets_production_endpoints() {
        let github = GitHub::new("cid", "secret", None);
        assert_eq!(github.authorization_endpoint, AUTHORIZATION_ENDPOINT);
        assert_eq!(github.token_endpoint, TOKEN_ENDPOINT);
    }

    #[test]
    fn with_endpoints_overrides_urls() {
        let github = GitHub::with_endpoints(
            "cid",
            "secret",
            None,
            "https://mock/authorize",
            "https://mock/token",
        );
        assert_eq!(github.authorization_endpoint, "https://mock/authorize");
        assert_eq!(github.token_endpoint, "https://mock/token");
    }

    #[test]
    fn name_returns_github() {
        let github = GitHub::new("cid", "secret", None);
        assert_eq!(github.name(), "GitHub");
    }

    #[test]
    fn authorization_url_builds_correct_params() {
        let github = GitHub::new("cid", "secret", Some("https://app/cb".into()));
        let url = github.authorization_url("state123", &["repo", "user"]);

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.contains(&("client_id".into(), "cid".into())));
        assert!(pairs.contains(&("state".into(), "state123".into())));
        assert!(pairs.contains(&("scope".into(), "repo user".into())));
        assert!(pairs.contains(&("redirect_uri".into(), "https://app/cb".into())));
    }

    #[test]
    fn authorization_url_omits_scope_when_empty() {
        let github = GitHub::new("cid", "secret", None);
        let url = github.authorization_url("state123", &[]);

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(!pairs.iter().any(|(k, _)| k == "scope"));
    }

    #[test]
    fn authorization_url_omits_redirect_uri_when_none() {
        let github = GitHub::new("cid", "secret", None);
        let url = github.authorization_url("state123", &["repo"]);

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(!pairs.iter().any(|(k, _)| k == "redirect_uri"));
    }

    #[tokio::test]
    async fn validate_authorization_code_sends_correct_request() {
        let github = GitHub::with_endpoints(
            "cid",
            "secret",
            Some("https://app/cb".into()),
            "https://mock/authorize",
            "https://mock/token",
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "gh-tok",
                "token_type": "bearer",
                "scope": "repo"
            }))
            .unwrap(),
        }]);

        let tokens = github
            .validate_authorization_code(&mock, "auth-code")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "gh-tok");

        let requests = mock.take_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url, "https://mock/token");

        // Check Basic auth header
        let auth = get_header(&requests[0], "Authorization").unwrap();
        assert!(auth.starts_with("Basic "));

        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("grant_type".into(), "authorization_code".into())));
        assert!(body.contains(&("code".into(), "auth-code".into())));
        assert!(body.contains(&("client_id".into(), "cid".into())));
        assert!(body.contains(&("redirect_uri".into(), "https://app/cb".into())));
    }

    #[tokio::test]
    async fn validate_authorization_code_omits_redirect_uri_when_none() {
        let github = GitHub::with_endpoints(
            "cid",
            "secret",
            None,
            "https://mock/authorize",
            "https://mock/token",
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "gh-tok",
                "token_type": "bearer"
            }))
            .unwrap(),
        }]);

        github
            .validate_authorization_code(&mock, "auth-code")
            .await
            .unwrap();

        let requests = mock.take_requests();
        let body = parse_form_body(&requests[0]);
        assert!(!body.iter().any(|(k, _)| k == "redirect_uri"));
    }

    #[tokio::test]
    async fn validate_authorization_code_error_as_200() {
        let github = GitHub::with_endpoints(
            "cid",
            "secret",
            None,
            "https://mock/authorize",
            "https://mock/token",
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "error": "bad_verification_code",
                "error_description": "The code passed is incorrect or expired."
            }))
            .unwrap(),
        }]);

        let err = github
            .validate_authorization_code(&mock, "bad-code")
            .await
            .unwrap_err();

        match err {
            Error::OAuthRequest {
                code, description, ..
            } => {
                assert_eq!(code, "bad_verification_code");
                assert_eq!(
                    description.as_deref(),
                    Some("The code passed is incorrect or expired.")
                );
            }
            other => panic!("Expected OAuthRequest, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn validate_authorization_code_400_error() {
        let github = GitHub::with_endpoints(
            "cid",
            "secret",
            None,
            "https://mock/authorize",
            "https://mock/token",
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 400,
            body: serde_json::to_vec(&serde_json::json!({
                "error": "invalid_grant",
                "error_description": "The code has expired"
            }))
            .unwrap(),
        }]);

        let err = github
            .validate_authorization_code(&mock, "code")
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            Error::OAuthRequest {
                code,
                ..
            } if code == "invalid_grant"
        ));
    }

    #[tokio::test]
    async fn validate_authorization_code_unexpected_status() {
        let github = GitHub::with_endpoints(
            "cid",
            "secret",
            None,
            "https://mock/authorize",
            "https://mock/token",
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 500,
            body: b"Internal Server Error".to_vec(),
        }]);

        let err = github
            .validate_authorization_code(&mock, "code")
            .await
            .unwrap_err();

        assert!(matches!(err, Error::UnexpectedResponse { status: 500 }));
    }
}
