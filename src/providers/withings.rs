use crate::error::Error;
use crate::http::HttpClient;
use crate::request::create_oauth2_request;
use crate::tokens::OAuth2Tokens;

const AUTHORIZATION_ENDPOINT: &str = "https://account.withings.com/oauth2_user/authorize2";
const TOKEN_ENDPOINT: &str = "https://wbsapi.withings.net/v2/oauth2";

/// Configuration for creating a [`Withings`] client with a custom HTTP client.
///
/// Use this when you need to provide your own [`HttpClient`] implementation
/// (e.g. a pre-configured `reqwest::Client` with custom timeouts or proxies).
/// For the common case, use [`Withings::new`] which uses the built-in default client.
pub struct WithingsOptions<'a, H: HttpClient> {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub http_client: &'a H,
}

/// OAuth 2.0 client for [Withings](https://developer.withings.com/).
///
/// Withings uses a non-standard token response format where successful responses are
/// wrapped in `{"status": 0, "body": {...}}`. Errors can also be returned with HTTP 200
/// status, indicated by a non-zero status field. This client handles these quirks automatically
/// and supports the authorization code flow. Withings does not require PKCE.
///
/// # Setup
///
/// 1. Create a Withings developer account at <https://developer.withings.com/>.
/// 2. Create a new application in the [Withings Developer Dashboard](https://account.withings.com/partner/dashboard_oauth2).
/// 3. Note your **Client ID** and **Client Secret**.
/// 4. Configure the **Callback URI** to match the `redirect_uri` you pass to [`Withings::new`].
/// 5. Request access to the required scopes for your application.
///
/// # Scopes
///
/// Withings uses comma-separated scopes. Common scopes include:
///
/// | Scope | Description |
/// |-------|-------------|
/// | `user.info` | User's basic profile information |
/// | `user.metrics` | User's weight, height, and body measurements |
/// | `user.activity` | User's activity and workout data |
///
/// See the full list at <https://developer.withings.com/api-reference#section/Authentication/Scopes>.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{Withings, generate_state};
///
/// # async fn example() -> Result<(), arctic_oauth::Error> {
/// let withings = Withings::new(
///     "your-client-id",
///     "your-client-secret",
///     "https://example.com/callback",
/// );
///
/// // Step 1: Generate CSRF state and redirect the user.
/// let state = generate_state();
/// let url = withings.authorization_url(&state, &["user.info", "user.metrics"]);
/// // Store `state` in the user's session, then redirect to `url`.
///
/// // Step 2: In your callback handler, exchange the authorization code for tokens.
/// let tokens = withings
///     .validate_authorization_code("authorization-code")
///     .await?;
/// println!("Access token: {}", tokens.access_token()?);
/// # Ok(())
/// # }
/// ```
pub struct Withings<'a, H: HttpClient> {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    http_client: &'a H,
    authorization_endpoint: String,
    token_endpoint: String,
}

impl<'a, H: HttpClient> Withings<'a, H> {
    /// Creates a Withings client from a [`WithingsOptions`] struct.
    ///
    /// Use this when you need a custom HTTP client. For the common case,
    /// use [`Withings::new`] instead.
    pub fn from_options(options: WithingsOptions<'a, H>) -> Self {
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
impl Withings<'static, reqwest::Client> {
    /// Creates a new Withings OAuth 2.0 client using the default HTTP client.
    ///
    /// # Arguments
    ///
    /// * `client_id` - The Client ID from Withings Developer Dashboard.
    /// * `client_secret` - The Client Secret from Withings Developer Dashboard.
    /// * `redirect_uri` - The URI Withings will redirect to after authorization. Must match
    ///   one of the callback URIs configured in your Withings application settings.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::Withings;
    ///
    /// let withings = Withings::new(
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
        Self::from_options(WithingsOptions {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri: redirect_uri.into(),
            http_client: crate::http::default_client(),
        })
    }
}

impl<'a, H: HttpClient> Withings<'a, H> {
    /// Returns the provider name (`"Withings"`).
    pub fn name(&self) -> &'static str {
        "Withings"
    }

    /// Builds the Withings authorization URL that the user should be redirected to.
    ///
    /// The returned URL includes all required OAuth 2.0 parameters. Withings uses
    /// comma-separated scopes and does not require PKCE. Your application should
    /// store `state` in the user's session before redirecting, as it is needed to
    /// validate the callback.
    ///
    /// # Arguments
    ///
    /// * `state` - A CSRF token to prevent cross-site request forgery. Use
    ///   [`generate_state`](crate::generate_state) to create one.
    /// * `scopes` - The OAuth 2.0 scopes to request (e.g. `&["user.info", "user.metrics"]`).
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{Withings, generate_state};
    ///
    /// let withings = Withings::new("client-id", "client-secret", "https://example.com/cb");
    /// let state = generate_state();
    ///
    /// let url = withings.authorization_url(&state, &["user.info", "user.metrics"]);
    /// assert!(url.as_str().starts_with("https://account.withings.com/"));
    /// ```
    pub fn authorization_url(&self, state: &str, scopes: &[&str]) -> url::Url {
        let mut url = url::Url::parse(&self.authorization_endpoint)
            .expect("invalid authorization endpoint URL");
        {
            let mut params = url.query_pairs_mut();
            params.append_pair("response_type", "code");
            params.append_pair("client_id", &self.client_id);
            params.append_pair("state", state);
            // Withings uses comma-delimited scopes
            if !scopes.is_empty() {
                params.append_pair("scope", &scopes.join(","));
            }
            params.append_pair("redirect_uri", &self.redirect_uri);
        }
        url
    }

    /// Exchanges an authorization code for access and refresh tokens.
    ///
    /// Call this in your redirect URI handler after Withings redirects back with a `code`
    /// query parameter. This method handles Withings' non-standard response format by
    /// unwrapping the token data from the nested `body` field and checking the `status`
    /// field for errors.
    ///
    /// # Arguments
    ///
    /// * `code` - The authorization code from the `code` query parameter.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OAuthRequest`] if Withings rejects the code,
    /// [`Error::UnexpectedErrorBody`] if the response status is non-zero, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::Withings;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let withings = Withings::new("client-id", "secret", "https://example.com/cb");
    ///
    /// let tokens = withings
    ///     .validate_authorization_code("the-auth-code")
    ///     .await?;
    ///
    /// println!("Access token: {}", tokens.access_token()?);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn validate_authorization_code(&self, code: &str) -> Result<OAuth2Tokens, Error> {
        let body = vec![
            ("action".to_string(), "requesttoken".to_string()),
            ("grant_type".to_string(), "authorization_code".to_string()),
            ("code".to_string(), code.to_string()),
            ("redirect_uri".to_string(), self.redirect_uri.clone()),
            ("client_id".to_string(), self.client_id.clone()),
            ("client_secret".to_string(), self.client_secret.clone()),
        ];
        let request = create_oauth2_request(&self.token_endpoint, &body);
        self.parse_token_response(request).await
    }

    /// Withings wraps token responses in `{"status": 0, "body": {...}}`.
    /// Errors are also returned with HTTP 200, indicated by a non-zero status field.
    async fn parse_token_response(
        &self,
        request: crate::http::HttpRequest,
    ) -> Result<OAuth2Tokens, Error> {
        let response = self.http_client.send(request).await?;

        match response.status {
            200 => {
                let body_str = String::from_utf8_lossy(&response.body).into_owned();
                let json: serde_json::Value =
                    serde_json::from_str(&body_str).map_err(|_| Error::UnexpectedErrorBody {
                        status: 200,
                        body: body_str.clone(),
                    })?;

                // Check for standard OAuth error field
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

                // Withings uses status field: 0 means success, non-zero means error
                let status = json.get("status").and_then(|s| s.as_i64());
                if status != Some(0) {
                    return Err(Error::UnexpectedErrorBody {
                        status: 200,
                        body: body_str,
                    });
                }

                // Unwrap the nested body field
                match json.get("body") {
                    Some(inner) => Ok(OAuth2Tokens::new(inner.clone())),
                    None => Err(Error::MissingField { field: "body" }),
                }
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

    fn make_withings(http_client: &MockHttpClient) -> Withings<'_, MockHttpClient> {
        Withings::from_options(WithingsOptions {
            client_id: "cid".into(),
            client_secret: "secret".into(),
            redirect_uri: "https://app/cb".into(),
            http_client,
        })
    }

    #[test]
    fn new_sets_production_endpoints() {
        let mock = MockHttpClient::new(vec![]);
        let withings = make_withings(&mock);
        assert_eq!(withings.authorization_endpoint, AUTHORIZATION_ENDPOINT);
        assert_eq!(withings.token_endpoint, TOKEN_ENDPOINT);
    }

    #[test]
    fn name_returns_withings() {
        let mock = MockHttpClient::new(vec![]);
        let withings = make_withings(&mock);
        assert_eq!(withings.name(), "Withings");
    }

    #[test]
    fn authorization_url_uses_comma_delimited_scopes() {
        let mock = MockHttpClient::new(vec![]);
        let withings = make_withings(&mock);
        let url = withings.authorization_url("state123", &["user.metrics", "user.activity"]);

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.contains(&("client_id".into(), "cid".into())));
        assert!(pairs.contains(&("state".into(), "state123".into())));
        assert!(pairs.contains(&("scope".into(), "user.metrics,user.activity".into())));
        assert!(pairs.contains(&("redirect_uri".into(), "https://app/cb".into())));
    }

    #[test]
    fn authorization_url_omits_scope_when_empty() {
        let mock = MockHttpClient::new(vec![]);
        let withings = make_withings(&mock);
        let url = withings.authorization_url("state123", &[]);

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(!pairs.iter().any(|(k, _)| k == "scope"));
    }

    #[tokio::test]
    async fn validate_authorization_code_sends_action_requesttoken() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "status": 0,
                "body": {
                    "access_token": "w-tok",
                    "token_type": "Bearer",
                    "expires_in": 10800,
                    "refresh_token": "w-refresh"
                }
            }))
            .unwrap(),
        }]);
        let withings = make_withings(&mock);

        let tokens = withings
            .validate_authorization_code("auth-code")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "w-tok");
        assert_eq!(tokens.refresh_token().unwrap(), "w-refresh");

        let requests = mock.take_requests();
        assert_eq!(requests[0].url, TOKEN_ENDPOINT);
        // No Authorization header (body credentials)
        assert!(get_header(&requests[0], "Authorization").is_none());

        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("action".into(), "requesttoken".into())));
        assert!(body.contains(&("grant_type".into(), "authorization_code".into())));
        assert!(body.contains(&("code".into(), "auth-code".into())));
        assert!(body.contains(&("client_id".into(), "cid".into())));
        assert!(body.contains(&("client_secret".into(), "secret".into())));
        assert!(body.contains(&("redirect_uri".into(), "https://app/cb".into())));
    }

    #[tokio::test]
    async fn validate_authorization_code_unwraps_nested_body() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "status": 0,
                "body": {
                    "access_token": "inner-token",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "scope": "user.metrics"
                }
            }))
            .unwrap(),
        }]);
        let withings = make_withings(&mock);

        let tokens = withings.validate_authorization_code("code").await.unwrap();

        // Token data should come from the nested body, not the outer envelope
        assert_eq!(tokens.access_token().unwrap(), "inner-token");
        assert_eq!(tokens.access_token_expires_in_seconds().unwrap(), 3600);
    }

    #[tokio::test]
    async fn validate_authorization_code_handles_error_as_200() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "error": "invalid_request",
                "error_description": "The code has expired."
            }))
            .unwrap(),
        }]);
        let withings = make_withings(&mock);

        let err = withings
            .validate_authorization_code("bad-code")
            .await
            .unwrap_err();

        match err {
            Error::OAuthRequest {
                code, description, ..
            } => {
                assert_eq!(code, "invalid_request");
                assert_eq!(description.as_deref(), Some("The code has expired."));
            }
            other => panic!("Expected OAuthRequest, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn validate_authorization_code_non_zero_status_is_error() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "status": 503,
                "body": {}
            }))
            .unwrap(),
        }]);
        let withings = make_withings(&mock);

        let err = withings
            .validate_authorization_code("code")
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            Error::UnexpectedErrorBody { status: 200, .. }
        ));
    }

    #[tokio::test]
    async fn validate_authorization_code_missing_body_field() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "status": 0
            }))
            .unwrap(),
        }]);
        let withings = make_withings(&mock);

        let err = withings
            .validate_authorization_code("code")
            .await
            .unwrap_err();

        assert!(matches!(err, Error::MissingField { field: "body" }));
    }

    #[tokio::test]
    async fn validate_authorization_code_400_error() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 400,
            body: serde_json::to_vec(&serde_json::json!({
                "error": "invalid_grant",
                "error_description": "The code is invalid"
            }))
            .unwrap(),
        }]);
        let withings = make_withings(&mock);

        let err = withings
            .validate_authorization_code("code")
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            Error::OAuthRequest { code, .. } if code == "invalid_grant"
        ));
    }

    #[tokio::test]
    async fn validate_authorization_code_unexpected_status() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 500,
            body: b"Internal Server Error".to_vec(),
        }]);
        let withings = make_withings(&mock);

        let err = withings
            .validate_authorization_code("code")
            .await
            .unwrap_err();

        assert!(matches!(err, Error::UnexpectedResponse { status: 500 }));
    }
}
