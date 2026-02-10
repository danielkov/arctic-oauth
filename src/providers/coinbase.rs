use crate::error::Error;
use crate::http::HttpClient;
use crate::request::{create_oauth2_request, send_token_request};
use crate::tokens::OAuth2Tokens;

const AUTHORIZATION_ENDPOINT: &str = "https://www.coinbase.com/oauth/authorize";
const TOKEN_ENDPOINT: &str = "https://www.coinbase.com/oauth/token";
const REVOCATION_ENDPOINT: &str = "https://api.coinbase.com/oauth/revoke";

/// Configuration for creating a [`Coinbase`] client with a custom HTTP client.
///
/// Use this when you need to provide your own [`HttpClient`] implementation.
/// For the common case, use [`Coinbase::new`] which uses the built-in default client.
pub struct CoinbaseOptions<'a, H: HttpClient> {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub http_client: &'a H,
}

/// OAuth 2.0 client for [Coinbase](https://docs.cdp.coinbase.com/coinbase-app/oauth2-integration/overview).
///
/// Coinbase does not require PKCE. This client supports the authorization code flow including
/// token refresh and revocation.
///
/// # Setup
///
/// 1. Create an OAuth2 application in the [Coinbase Developer Portal](https://www.coinbase.com/settings/api).
/// 2. Obtain the **Client ID** and **Client Secret** from your application settings.
/// 3. Set the **Redirect URI** to match the `redirect_uri` you pass to [`Coinbase::new`].
///
/// # Scopes
///
/// Coinbase uses space-separated scopes. Common scopes include:
///
/// | Scope | Description |
/// |-------|-------------|
/// | `wallet:user:read` | Read user information |
/// | `wallet:accounts:read` | Read account balances |
/// | `wallet:transactions:read` | Read transaction history |
/// | `wallet:transactions:send` | Send cryptocurrency |
///
/// See the full list at <https://docs.cdp.coinbase.com/coinbase-app/oauth2-integration/overview>.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{Coinbase, generate_state};
///
/// # async fn example() -> Result<(), arctic_oauth::Error> {
/// let coinbase = Coinbase::new(
///     "your-client-id",
///     "your-client-secret",
///     "https://example.com/callback",
/// );
///
/// // Step 1: Generate CSRF state and redirect the user.
/// let state = generate_state();
/// let url = coinbase.authorization_url(&state, &["wallet:user:read", "wallet:accounts:read"]);
///
/// // Step 2: Exchange the authorization code for tokens.
/// let tokens = coinbase
///     .validate_authorization_code("authorization-code")
///     .await?;
/// println!("Access token: {}", tokens.access_token()?);
///
/// // Step 3 (optional): Refresh an expired access token.
/// let refreshed = coinbase
///     .refresh_access_token(tokens.refresh_token()?)
///     .await?;
///
/// // Step 4 (optional): Revoke a token.
/// coinbase.revoke_token(tokens.access_token()?).await?;
/// # Ok(())
/// # }
/// ```
pub struct Coinbase<'a, H: HttpClient> {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    http_client: &'a H,
    authorization_endpoint: String,
    token_endpoint: String,
    revocation_endpoint: String,
}

impl<'a, H: HttpClient> Coinbase<'a, H> {
    /// Creates a Coinbase client from a [`CoinbaseOptions`] struct.
    ///
    /// Use this when you need a custom HTTP client. For the common case,
    /// use [`Coinbase::new`] instead.
    pub fn from_options(options: CoinbaseOptions<'a, H>) -> Self {
        Self {
            http_client: options.http_client,
            client_id: options.client_id,
            client_secret: options.client_secret,
            redirect_uri: options.redirect_uri,
            authorization_endpoint: AUTHORIZATION_ENDPOINT.to_string(),
            token_endpoint: TOKEN_ENDPOINT.to_string(),
            revocation_endpoint: REVOCATION_ENDPOINT.to_string(),
        }
    }
}

#[cfg(feature = "reqwest-client")]
impl Coinbase<'static, reqwest::Client> {
    /// Creates a new Coinbase OAuth 2.0 client using the default HTTP client.
    ///
    /// # Arguments
    ///
    /// * `client_id` - The OAuth 2.0 client ID from the Coinbase Developer Portal.
    /// * `client_secret` - The OAuth 2.0 client secret from the Coinbase Developer Portal.
    /// * `redirect_uri` - The URI Coinbase will redirect to after authorization. Must match
    ///   the redirect URI configured in your application settings.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::Coinbase;
    ///
    /// let coinbase = Coinbase::new(
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
        Self::from_options(CoinbaseOptions {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri: redirect_uri.into(),
            http_client: crate::http::default_client(),
        })
    }
}

impl<'a, H: HttpClient> Coinbase<'a, H> {
    /// Returns the provider name (`"Coinbase"`).
    pub fn name(&self) -> &'static str {
        "Coinbase"
    }

    /// Builds the Coinbase authorization URL that the user should be redirected to.
    ///
    /// The returned URL includes all required OAuth 2.0 parameters. Your application should
    /// store `state` in the user's session before redirecting to validate the callback.
    ///
    /// # Arguments
    ///
    /// * `state` - A CSRF token to prevent cross-site request forgery. Use
    ///   [`generate_state`](crate::generate_state) to create one.
    /// * `scopes` - The OAuth 2.0 scopes to request (e.g. `&["wallet:user:read", "wallet:accounts:read"]`).
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{Coinbase, generate_state};
    ///
    /// let coinbase = Coinbase::new("client-id", "client-secret", "https://example.com/cb");
    /// let state = generate_state();
    ///
    /// let url = coinbase.authorization_url(&state, &["wallet:user:read"]);
    /// assert!(url.as_str().starts_with("https://www.coinbase.com/"));
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

    /// Exchanges an authorization code for access and refresh tokens.
    ///
    /// Call this in your redirect URI handler after Coinbase redirects back with a `code`
    /// query parameter.
    ///
    /// # Arguments
    ///
    /// * `code` - The authorization code from the `code` query parameter.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OAuthRequest`] if Coinbase rejects the code, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::Coinbase;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let coinbase = Coinbase::new("client-id", "secret", "https://example.com/cb");
    ///
    /// let tokens = coinbase
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

    /// Refreshes an expired access token using a refresh token.
    ///
    /// Coinbase access tokens typically expire after 2 hours. If your initial token response
    /// included a refresh token, you can use it to obtain a new access token without user
    /// interaction.
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
    /// # use arctic_oauth::Coinbase;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let coinbase = Coinbase::new("client-id", "secret", "https://example.com/cb");
    ///
    /// let new_tokens = coinbase
    ///     .refresh_access_token("stored-refresh-token")
    ///     .await?;
    ///
    /// println!("New access token: {}", new_tokens.access_token()?);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn refresh_access_token(&self, refresh_token: &str) -> Result<OAuth2Tokens, Error> {
        let body = vec![
            ("grant_type".to_string(), "refresh_token".to_string()),
            ("refresh_token".to_string(), refresh_token.to_string()),
            ("client_id".to_string(), self.client_id.clone()),
            ("client_secret".to_string(), self.client_secret.clone()),
        ];
        let request = create_oauth2_request(&self.token_endpoint, &body);
        send_token_request(self.http_client, request).await
    }

    /// Revokes an access token or refresh token.
    ///
    /// Use this when a user signs out or disconnects your application.
    ///
    /// # Arguments
    ///
    /// * `token` - The access token or refresh token to revoke.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedResponse`] if Coinbase returns a non-200 status, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::Coinbase;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let coinbase = Coinbase::new("client-id", "secret", "https://example.com/cb");
    ///
    /// coinbase.revoke_token("token-to-revoke").await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn revoke_token(&self, token: &str) -> Result<(), Error> {
        let body = vec![
            ("token".to_string(), token.to_string()),
            ("client_id".to_string(), self.client_id.clone()),
            ("client_secret".to_string(), self.client_secret.clone()),
        ];
        let request = create_oauth2_request(&self.revocation_endpoint, &body);
        let response = self.http_client.send(request).await?;
        match response.status {
            200 => Ok(()),
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

    fn make_coinbase(http_client: &MockHttpClient) -> Coinbase<'_, MockHttpClient> {
        Coinbase::from_options(CoinbaseOptions {
            client_id: "cid".into(),
            client_secret: "secret".into(),
            redirect_uri: "https://app/cb".into(),
            http_client,
        })
    }

    #[test]
    fn new_sets_production_endpoints() {
        let mock = MockHttpClient::new(vec![]);
        let coinbase = make_coinbase(&mock);
        assert_eq!(coinbase.authorization_endpoint, AUTHORIZATION_ENDPOINT);
        assert_eq!(coinbase.token_endpoint, TOKEN_ENDPOINT);
        assert_eq!(coinbase.revocation_endpoint, REVOCATION_ENDPOINT);
    }

    #[test]
    fn name_returns_coinbase() {
        let mock = MockHttpClient::new(vec![]);
        let coinbase = make_coinbase(&mock);
        assert_eq!(coinbase.name(), "Coinbase");
    }

    #[test]
    fn authorization_url_builds_correct_params() {
        let mock = MockHttpClient::new(vec![]);
        let coinbase = make_coinbase(&mock);
        let url = coinbase.authorization_url("state123", &["wallet:accounts:read"]);

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.contains(&("client_id".into(), "cid".into())));
        assert!(pairs.contains(&("state".into(), "state123".into())));
        assert!(pairs.contains(&("scope".into(), "wallet:accounts:read".into())));
        assert!(pairs.contains(&("redirect_uri".into(), "https://app/cb".into())));
        assert!(!pairs.iter().any(|(k, _)| k == "code_challenge"));
    }

    #[tokio::test]
    async fn validate_authorization_code_sends_body_credentials() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "cb-tok",
                "token_type": "Bearer",
                "expires_in": 7200
            }))
            .unwrap(),
        }]);
        let coinbase = make_coinbase(&mock);

        let tokens = coinbase
            .validate_authorization_code("auth-code")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "cb-tok");

        let requests = mock.take_requests();
        assert_eq!(requests[0].url, TOKEN_ENDPOINT);
        assert!(get_header(&requests[0], "Authorization").is_none());

        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("grant_type".into(), "authorization_code".into())));
        assert!(body.contains(&("code".into(), "auth-code".into())));
        assert!(body.contains(&("client_id".into(), "cid".into())));
        assert!(body.contains(&("client_secret".into(), "secret".into())));
        assert!(body.contains(&("redirect_uri".into(), "https://app/cb".into())));
    }

    #[tokio::test]
    async fn refresh_access_token_sends_body_credentials() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "new-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);
        let coinbase = make_coinbase(&mock);

        let tokens = coinbase.refresh_access_token("refresh-tok").await.unwrap();

        assert_eq!(tokens.access_token().unwrap(), "new-tok");

        let requests = mock.take_requests();
        assert!(get_header(&requests[0], "Authorization").is_none());
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("grant_type".into(), "refresh_token".into())));
        assert!(body.contains(&("refresh_token".into(), "refresh-tok".into())));
        assert!(body.contains(&("client_id".into(), "cid".into())));
        assert!(body.contains(&("client_secret".into(), "secret".into())));
    }

    #[tokio::test]
    async fn revoke_token_sends_body_credentials() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: vec![],
        }]);
        let coinbase = make_coinbase(&mock);

        let result = coinbase.revoke_token("tok-to-revoke").await;
        assert!(result.is_ok());

        let requests = mock.take_requests();
        assert_eq!(requests[0].url, REVOCATION_ENDPOINT);
        assert!(get_header(&requests[0], "Authorization").is_none());
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("token".into(), "tok-to-revoke".into())));
        assert!(body.contains(&("client_id".into(), "cid".into())));
        assert!(body.contains(&("client_secret".into(), "secret".into())));
    }

    #[tokio::test]
    async fn revoke_token_non_200_returns_error() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 503,
            body: vec![],
        }]);
        let coinbase = make_coinbase(&mock);

        let result = coinbase.revoke_token("tok").await;
        assert!(matches!(
            result,
            Err(Error::UnexpectedResponse { status: 503 })
        ));
    }
}
