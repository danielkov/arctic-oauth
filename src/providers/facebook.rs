use crate::error::Error;
use crate::http::HttpClient;
use crate::request::{create_oauth2_request, send_token_request};
use crate::tokens::OAuth2Tokens;

const AUTHORIZATION_ENDPOINT: &str = "https://www.facebook.com/v16.0/dialog/oauth";
const TOKEN_ENDPOINT: &str = "https://graph.facebook.com/v16.0/oauth/access_token";

/// Configuration for creating a [`Facebook`] client with a custom HTTP client.
///
/// Use this when you need to provide your own [`HttpClient`] implementation
/// (e.g. a pre-configured `reqwest::Client` with custom timeouts or proxies).
/// For the common case, use [`Facebook::new`] which uses the built-in default client.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{Facebook, FacebookOptions, HttpClient};
///
/// let custom_client = reqwest::Client::builder()
///     .timeout(std::time::Duration::from_secs(10))
///     .build()
///     .unwrap();
///
/// let facebook = Facebook::from_options(FacebookOptions {
///     client_id: "your-client-id".into(),
///     client_secret: "your-client-secret".into(),
///     redirect_uri: "https://example.com/callback".into(),
///     http_client: &custom_client,
/// });
/// ```
pub struct FacebookOptions<'a, H: HttpClient> {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub http_client: &'a H,
}

/// OAuth 2.0 client for [Facebook](https://developers.facebook.com/docs/facebook-login).
///
/// Facebook does not require PKCE for authorization requests. This client supports the
/// authorization code flow but does not support token refresh or revocation through standard
/// OAuth 2.0 endpoints. Facebook uses space-separated scopes to control access to user data.
///
/// # Setup
///
/// 1. Create an app in [Meta for Developers](https://developers.facebook.com/apps/).
/// 2. Add **Facebook Login** as a product to your app.
/// 3. Navigate to **Facebook Login > Settings** and add your redirect URI to the
///    **Valid OAuth Redirect URIs** list to match the `redirect_uri` you pass to [`Facebook::new`].
///
/// # Scopes
///
/// Facebook uses space-separated scopes. Common scopes include:
///
/// | Scope | Description |
/// |-------|-------------|
/// | `email` | Access to user's email address |
/// | `public_profile` | Access to user's public profile info |
/// | `user_friends` | Access to user's friends list |
/// | `user_posts` | Access to user's posts |
///
/// See the full list at <https://developers.facebook.com/docs/permissions/reference>.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{Facebook, generate_state};
///
/// # async fn example() -> Result<(), arctic_oauth::Error> {
/// let facebook = Facebook::new(
///     "your-client-id",
///     "your-client-secret",
///     "https://example.com/callback",
/// );
///
/// // Step 1: Generate CSRF state, then redirect the user.
/// let state = generate_state();
/// let url = facebook.authorization_url(&state, &["email", "public_profile"]);
/// // Store `state` in the user's session, then redirect to `url`.
///
/// // Step 2: In your callback handler, exchange the authorization code for tokens.
/// let tokens = facebook
///     .validate_authorization_code("authorization-code")
///     .await?;
/// println!("Access token: {}", tokens.access_token()?);
/// # Ok(())
/// # }
/// ```
pub struct Facebook<'a, H: HttpClient> {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    http_client: &'a H,
    authorization_endpoint: String,
    token_endpoint: String,
}

impl<'a, H: HttpClient> Facebook<'a, H> {
    /// Creates a Facebook client from a [`FacebookOptions`] struct.
    ///
    /// Use this when you need a custom HTTP client. For the common case,
    /// use [`Facebook::new`] instead.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{Facebook, FacebookOptions};
    ///
    /// let custom_client = reqwest::Client::new();
    /// let facebook = Facebook::from_options(FacebookOptions {
    ///     client_id: "your-client-id".into(),
    ///     client_secret: "your-client-secret".into(),
    ///     redirect_uri: "https://example.com/callback".into(),
    ///     http_client: &custom_client,
    /// });
    /// ```
    pub fn from_options(options: FacebookOptions<'a, H>) -> Self {
        Self {
            http_client: options.http_client,
            client_id: options.client_id,
            client_secret: options.client_secret,
            redirect_uri: options.redirect_uri,
            authorization_endpoint: AUTHORIZATION_ENDPOINT.to_string(),
            token_endpoint: TOKEN_ENDPOINT.to_string(),
        }
    }
}

#[cfg(feature = "reqwest-client")]
impl Facebook<'static, reqwest::Client> {
    /// Creates a new Facebook OAuth 2.0 client configured with production endpoints using the default HTTP client.
    ///
    /// Uses the built-in `reqwest::Client` for HTTP requests. To provide a custom
    /// HTTP client, use [`Facebook::from_options`] instead.
    ///
    /// # Arguments
    ///
    /// * `client_id` - The App ID from Meta for Developers.
    /// * `client_secret` - The App Secret from Meta for Developers.
    /// * `redirect_uri` - The URI Facebook will redirect to after authorization. Must be listed
    ///   in your app's Valid OAuth Redirect URIs.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::Facebook;
    ///
    /// let facebook = Facebook::new(
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
        Self::from_options(FacebookOptions {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri: redirect_uri.into(),
            http_client: crate::http::default_client(),
        })
    }
}

impl<'a, H: HttpClient> Facebook<'a, H> {
    /// Returns the provider name (`"Facebook"`).
    pub fn name(&self) -> &'static str {
        "Facebook"
    }

    /// Builds the Facebook authorization URL that the user should be redirected to.
    ///
    /// The returned URL includes all required OAuth 2.0 parameters. Your application
    /// should store `state` in the user's session before redirecting to verify the
    /// callback request.
    ///
    /// # Arguments
    ///
    /// * `state` - A CSRF token to prevent cross-site request forgery. Use
    ///   [`generate_state`](crate::generate_state) to create one.
    /// * `scopes` - The OAuth 2.0 scopes to request (e.g. `&["email", "public_profile"]`).
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{Facebook, generate_state};
    ///
    /// let facebook = Facebook::new("client-id", "client-secret", "https://example.com/cb");
    /// let state = generate_state();
    ///
    /// let url = facebook.authorization_url(&state, &["email", "public_profile"]);
    /// assert!(url.as_str().starts_with("https://www.facebook.com/"));
    /// ```
    pub fn authorization_url(&self, state: &str, scopes: &[&str]) -> url::Url {
        let mut url =
            url::Url::parse(&self.authorization_endpoint).expect("invalid authorization endpoint");
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

    /// Exchanges an authorization code for an access token.
    ///
    /// Call this in your redirect URI handler after Facebook redirects back with a `code`
    /// query parameter. Note that Facebook does not provide refresh tokens through this
    /// standard OAuth flow.
    ///
    /// # Arguments
    ///
    /// * `code` - The authorization code from the `code` query parameter.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OAuthRequest`] if Facebook rejects the code, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::Facebook;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let facebook = Facebook::new("client-id", "secret", "https://example.com/cb");
    ///
    /// let tokens = facebook
    ///     .validate_authorization_code("the-auth-code")
    ///     .await?;
    ///
    /// println!("Access token: {}", tokens.access_token()?);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn validate_authorization_code(&self, code: &str) -> Result<OAuth2Tokens, Error> {
        let body = vec![
            ("grant_type".to_string(), "authorization_code".to_string()),
            ("code".to_string(), code.to_string()),
            ("redirect_uri".to_string(), self.redirect_uri.clone()),
            ("client_id".to_string(), self.client_id.clone()),
            ("client_secret".to_string(), self.client_secret.clone()),
        ];
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

    fn make_facebook(http_client: &MockHttpClient) -> Facebook<'_, MockHttpClient> {
        Facebook::from_options(FacebookOptions {
            client_id: "cid".into(),
            client_secret: "secret".into(),
            redirect_uri: "https://app/cb".into(),
            http_client,
        })
    }

    #[test]
    fn new_sets_production_endpoints() {
        let mock = MockHttpClient::new(vec![]);
        let fb = make_facebook(&mock);
        assert_eq!(fb.authorization_endpoint, AUTHORIZATION_ENDPOINT);
        assert_eq!(fb.token_endpoint, TOKEN_ENDPOINT);
    }

    #[test]
    fn name_returns_facebook() {
        let mock = MockHttpClient::new(vec![]);
        let fb = make_facebook(&mock);
        assert_eq!(fb.name(), "Facebook");
    }

    #[test]
    fn authorization_url_builds_correct_params() {
        let mock = MockHttpClient::new(vec![]);
        let fb = make_facebook(&mock);
        let url = fb.authorization_url("state123", &["email", "public_profile"]);

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.contains(&("client_id".into(), "cid".into())));
        assert!(pairs.contains(&("state".into(), "state123".into())));
        assert!(pairs.contains(&("scope".into(), "email public_profile".into())));
        assert!(pairs.contains(&("redirect_uri".into(), "https://app/cb".into())));
        assert!(!pairs.iter().any(|(k, _)| k == "code_challenge"));
    }

    #[test]
    fn authorization_url_without_scopes() {
        let mock = MockHttpClient::new(vec![]);
        let fb = make_facebook(&mock);
        let url = fb.authorization_url("state123", &[]);

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(!pairs.iter().any(|(k, _)| k == "scope"));
    }

    #[tokio::test]
    async fn validate_authorization_code_sends_body_credentials() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "fb-tok",
                "token_type": "Bearer",
                "expires_in": 5184000
            }))
            .unwrap(),
        }]);
        let fb = make_facebook(&mock);

        let tokens = fb.validate_authorization_code("auth-code").await.unwrap();

        assert_eq!(tokens.access_token().unwrap(), "fb-tok");

        let requests = mock.take_requests();
        assert_eq!(
            requests[0].url,
            "https://graph.facebook.com/v16.0/oauth/access_token"
        );
        assert!(get_header(&requests[0], "Authorization").is_none());

        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("grant_type".into(), "authorization_code".into())));
        assert!(body.contains(&("code".into(), "auth-code".into())));
        assert!(body.contains(&("client_id".into(), "cid".into())));
        assert!(body.contains(&("client_secret".into(), "secret".into())));
        assert!(body.contains(&("redirect_uri".into(), "https://app/cb".into())));
    }
}
