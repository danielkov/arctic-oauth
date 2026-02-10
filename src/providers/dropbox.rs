use crate::client::OAuth2Client;
use crate::error::Error;
use crate::http::HttpClient;
use crate::tokens::OAuth2Tokens;

const AUTHORIZATION_ENDPOINT: &str = "https://www.dropbox.com/oauth2/authorize";
const TOKEN_ENDPOINT: &str = "https://api.dropboxapi.com/oauth2/token";
const REVOCATION_ENDPOINT: &str = "https://api.dropboxapi.com/2/auth/token/revoke";

/// Configuration for creating a [`Dropbox`] client with a custom HTTP client.
///
/// Use this when you need to provide your own [`HttpClient`] implementation
/// (e.g. a pre-configured `reqwest::Client` with custom timeouts or proxies).
/// For the common case, use [`Dropbox::new`] which uses the built-in default client.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{Dropbox, DropboxOptions, HttpClient};
///
/// let custom_client = reqwest::Client::builder()
///     .timeout(std::time::Duration::from_secs(10))
///     .build()
///     .unwrap();
///
/// let dropbox = Dropbox::from_options(DropboxOptions {
///     client_id: "your-client-id".into(),
///     client_secret: "your-client-secret".into(),
///     redirect_uri: "https://example.com/callback".into(),
///     http_client: &custom_client,
/// });
/// ```
pub struct DropboxOptions<'a, H: HttpClient> {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub http_client: &'a H,
}

/// OAuth 2.0 client for [Dropbox](https://developers.dropbox.com/oauth-guide).
///
/// Dropbox uses standard OAuth 2.0 authorization code flow without PKCE.
/// The client supports authorization, token exchange, token refresh, and token revocation.
///
/// # Setup
///
/// 1. Create an app in the [Dropbox App Console](https://www.dropbox.com/developers/apps/create).
/// 2. Choose your API access level (Full Dropbox or App folder) and obtain the app key (client ID) and app secret (client secret).
/// 3. Add your redirect URI to the OAuth 2 redirect URIs list in your app settings.
///
/// # Scopes
///
/// Dropbox uses space-separated scopes. Common scopes include:
///
/// | Scope | Description |
/// |-------|-------------|
/// | `account_info.read` | View user's account information |
/// | `files.metadata.read` | View metadata for files and folders |
/// | `files.metadata.write` | Create, modify, and delete file metadata |
/// | `files.content.read` | View content of files |
/// | `files.content.write` | Create, modify, and delete file content |
///
/// See the full list at <https://developers.dropbox.com/oauth-guide#permissions>.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{Dropbox, generate_state};
///
/// # async fn example() -> Result<(), arctic_oauth::Error> {
/// let provider = Dropbox::new(
///     "your-client-id",
///     "your-client-secret",
///     "https://example.com/callback",
/// );
///
/// // Step 1: Generate CSRF state and redirect the user.
/// let state = generate_state();
/// let url = provider.authorization_url(&state, &["account_info.read", "files.content.read"]);
///
/// // Step 2: Exchange the authorization code for tokens.
/// let tokens = provider
///     .validate_authorization_code("authorization-code")
///     .await?;
/// println!("Access token: {}", tokens.access_token()?);
///
/// // Step 3 (optional): Refresh an expired access token.
/// let refreshed = provider
///     .refresh_access_token(tokens.refresh_token()?)
///     .await?;
///
/// // Step 4 (optional): Revoke a token.
/// provider.revoke_token(tokens.access_token()?).await?;
/// # Ok(())
/// # }
/// ```
pub struct Dropbox<'a, H: HttpClient> {
    client: OAuth2Client,
    http_client: &'a H,
    authorization_endpoint: String,
    token_endpoint: String,
    revocation_endpoint: String,
}

impl<'a, H: HttpClient> Dropbox<'a, H> {
    /// Creates a Dropbox client from a [`DropboxOptions`] struct.
    ///
    /// Use this when you need a custom HTTP client. For the common case,
    /// use [`Dropbox::new`] instead.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{Dropbox, DropboxOptions};
    ///
    /// let custom_client = reqwest::Client::new();
    /// let dropbox = Dropbox::from_options(DropboxOptions {
    ///     client_id: "your-client-id".into(),
    ///     client_secret: "your-client-secret".into(),
    ///     redirect_uri: "https://example.com/callback".into(),
    ///     http_client: &custom_client,
    /// });
    /// ```
    pub fn from_options(options: DropboxOptions<'a, H>) -> Self {
        Self {
            http_client: options.http_client,
            client: OAuth2Client::new(
                options.client_id,
                Some(options.client_secret),
                Some(options.redirect_uri),
            ),
            authorization_endpoint: AUTHORIZATION_ENDPOINT.to_string(),
            token_endpoint: TOKEN_ENDPOINT.to_string(),
            revocation_endpoint: REVOCATION_ENDPOINT.to_string(),
        }
    }
}

#[cfg(feature = "reqwest-client")]
impl Dropbox<'static, reqwest::Client> {
    /// Creates a new Dropbox OAuth 2.0 client configured with production endpoints using the default HTTP client.
    ///
    /// Uses the built-in `reqwest::Client` for HTTP requests. To provide a custom
    /// HTTP client, use [`Dropbox::from_options`] instead.
    ///
    /// # Arguments
    ///
    /// * `client_id` - The OAuth 2.0 client ID (app key) from Dropbox's App Console.
    /// * `client_secret` - The OAuth 2.0 client secret (app secret) from Dropbox's App Console.
    /// * `redirect_uri` - The URI Dropbox will redirect to after authorization.
    ///   Must match one configured in your app settings.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::Dropbox;
    ///
    /// let provider = Dropbox::new(
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
        Self::from_options(DropboxOptions {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri: redirect_uri.into(),
            http_client: crate::http::default_client(),
        })
    }
}

impl<'a, H: HttpClient> Dropbox<'a, H> {
    /// Returns the provider name (`"Dropbox"`).
    pub fn name(&self) -> &'static str {
        "Dropbox"
    }

    /// Builds the Dropbox authorization URL that the user should be redirected to.
    ///
    /// The returned URL includes all required OAuth 2.0 parameters. Your application
    /// should store `state` in the user's session before redirecting, as it is needed
    /// to complete the flow.
    ///
    /// # Arguments
    ///
    /// * `state` - A CSRF token. Use [`generate_state`](crate::generate_state) to create one.
    /// * `scopes` - The OAuth 2.0 scopes to request (e.g. `&["account_info.read", "files.content.read"]`).
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{Dropbox, generate_state};
    ///
    /// let provider = Dropbox::new("client-id", "client-secret", "https://example.com/cb");
    /// let state = generate_state();
    ///
    /// let url = provider.authorization_url(&state, &["account_info.read", "files.content.read"]);
    /// ```
    pub fn authorization_url(&self, state: &str, scopes: &[&str]) -> url::Url {
        self.client
            .create_authorization_url(&self.authorization_endpoint, state, scopes)
    }

    /// Exchanges an authorization code for access and refresh tokens.
    ///
    /// Call this in your redirect URI handler after Dropbox redirects back with a `code`
    /// query parameter.
    ///
    /// # Arguments
    ///
    /// * `code` - The authorization code from the `code` query parameter.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OAuthRequest`] if Dropbox rejects the code, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::Dropbox;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let provider = Dropbox::new("client-id", "client-secret", "https://example.com/cb");
    ///
    /// let tokens = provider
    ///     .validate_authorization_code("the-auth-code")
    ///     .await?;
    ///
    /// println!("Access token: {}", tokens.access_token()?);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn validate_authorization_code(&self, code: &str) -> Result<OAuth2Tokens, Error> {
        self.client
            .validate_authorization_code(self.http_client, &self.token_endpoint, code, None)
            .await
    }

    /// Refreshes an expired access token using a refresh token.
    ///
    /// Dropbox access tokens typically expire after 4 hours. Use this method to
    /// obtain a new access token without requiring the user to re-authenticate.
    ///
    /// # Arguments
    ///
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
    /// # use arctic_oauth::Dropbox;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let provider = Dropbox::new("client-id", "client-secret", "https://example.com/cb");
    ///
    /// let new_tokens = provider
    ///     .refresh_access_token("stored-refresh-token")
    ///     .await?;
    ///
    /// println!("New access token: {}", new_tokens.access_token()?);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn refresh_access_token(&self, refresh_token: &str) -> Result<OAuth2Tokens, Error> {
        self.client
            .refresh_access_token(self.http_client, &self.token_endpoint, refresh_token, &[])
            .await
    }

    /// Revokes an access token or refresh token.
    ///
    /// This invalidates the token immediately, preventing further use. Note that
    /// Dropbox's revocation endpoint only accepts access tokens, not refresh tokens.
    ///
    /// # Arguments
    ///
    /// * `token` - The access token to revoke.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedResponse`] if Dropbox returns a non-200 status, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::Dropbox;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let provider = Dropbox::new("client-id", "client-secret", "https://example.com/cb");
    ///
    /// provider.revoke_token("token-to-revoke").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn revoke_token(&self, token: &str) -> Result<(), Error> {
        self.client
            .revoke_token(self.http_client, &self.revocation_endpoint, token)
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

    fn make_dropbox(http_client: &MockHttpClient) -> Dropbox<'_, MockHttpClient> {
        Dropbox::from_options(DropboxOptions {
            client_id: "cid".into(),
            client_secret: "secret".into(),
            redirect_uri: "https://app/cb".into(),
            http_client,
        })
    }

    #[test]
    fn new_sets_production_endpoints() {
        let mock = MockHttpClient::new(vec![]);
        let dropbox = make_dropbox(&mock);
        assert_eq!(dropbox.authorization_endpoint, AUTHORIZATION_ENDPOINT);
        assert_eq!(dropbox.token_endpoint, TOKEN_ENDPOINT);
        assert_eq!(dropbox.revocation_endpoint, REVOCATION_ENDPOINT);
    }

    #[test]
    fn name_returns_dropbox() {
        let mock = MockHttpClient::new(vec![]);
        let dropbox = make_dropbox(&mock);
        assert_eq!(dropbox.name(), "Dropbox");
    }

    #[test]
    fn authorization_url_builds_correct_params() {
        let mock = MockHttpClient::new(vec![]);
        let dropbox = make_dropbox(&mock);
        let url = dropbox.authorization_url("state123", &["files.content.read"]);

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.contains(&("client_id".into(), "cid".into())));
        assert!(pairs.contains(&("state".into(), "state123".into())));
        assert!(pairs.contains(&("scope".into(), "files.content.read".into())));
        assert!(pairs.contains(&("redirect_uri".into(), "https://app/cb".into())));
        assert!(!pairs.iter().any(|(k, _)| k == "code_challenge"));
    }

    #[tokio::test]
    async fn validate_authorization_code_delegates_to_client() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "dropbox-tok",
                "token_type": "Bearer",
                "expires_in": 14400
            }))
            .unwrap(),
        }]);
        let dropbox = make_dropbox(&mock);

        let tokens = dropbox
            .validate_authorization_code("auth-code")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "dropbox-tok");

        let requests = mock.take_requests();
        assert_eq!(requests[0].url, "https://api.dropboxapi.com/oauth2/token");
        assert!(get_header(&requests[0], "Authorization").is_some());
    }

    #[tokio::test]
    async fn refresh_access_token_delegates_to_client() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "new-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);
        let dropbox = make_dropbox(&mock);

        let tokens = dropbox.refresh_access_token("refresh-tok").await.unwrap();

        assert_eq!(tokens.access_token().unwrap(), "new-tok");
    }

    #[tokio::test]
    async fn revoke_token_delegates_to_client() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: vec![],
        }]);
        let dropbox = make_dropbox(&mock);

        let result = dropbox.revoke_token("tok-to-revoke").await;
        assert!(result.is_ok());

        let requests = mock.take_requests();
        assert_eq!(
            requests[0].url,
            "https://api.dropboxapi.com/2/auth/token/revoke"
        );
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("token".into(), "tok-to-revoke".into())));
    }
}
