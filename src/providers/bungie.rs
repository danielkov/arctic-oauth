use crate::client::OAuth2Client;
use crate::error::Error;
use crate::http::HttpClient;
use crate::tokens::OAuth2Tokens;

const AUTHORIZATION_ENDPOINT: &str = "https://www.bungie.net/en/oauth/authorize";
const TOKEN_ENDPOINT: &str = "https://www.bungie.net/platform/app/oauth/token";

/// OAuth 2.0 client for [Bungie](https://github.com/Bungie-net/api/wiki/OAuth-Documentation).
///
/// Bungie does not require PKCE for authorization requests. This client supports the
/// authorization code flow including token refresh but does not support token revocation.
/// The client secret is optional for public clients.
///
/// # Setup
///
/// 1. Create an application on the [Bungie Application Portal](https://www.bungie.net/en/Application).
/// 2. Obtain your **OAuth Client ID** and **OAuth Client Secret** (if using a confidential client).
/// 3. Set your redirect URL to match the `redirect_uri` you pass to [`Bungie::new`].
///
/// # Scopes
///
/// Bungie does not use traditional OAuth scopes. Access permissions are configured through
/// your application settings in the Bungie Application Portal.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{Bungie, ReqwestClient, generate_state};
///
/// # async fn example() -> Result<(), arctic_oauth::Error> {
/// let bungie = Bungie::new(
///     "your-client-id",
///     Some("your-client-secret".into()),
///     "https://example.com/callback",
/// );
///
/// // Step 1: Generate CSRF state, then redirect the user.
/// let state = generate_state();
/// let url = bungie.authorization_url(&state, &[]);
/// // Store `state` in the user's session, then redirect to `url`.
///
/// // Step 2: In your callback handler, exchange the authorization code for tokens.
/// let http = ReqwestClient::new();
/// let tokens = bungie
///     .validate_authorization_code(&http, "authorization-code")
///     .await?;
/// println!("Access token: {}", tokens.access_token()?);
///
/// // Step 3 (optional): Refresh an expired access token.
/// let refreshed = bungie
///     .refresh_access_token(&http, tokens.refresh_token()?)
///     .await?;
/// # Ok(())
/// # }
/// ```
pub struct Bungie {
    client: OAuth2Client,
    authorization_endpoint: String,
    token_endpoint: String,
}

impl Bungie {
    /// Creates a new Bungie OAuth 2.0 client configured with production endpoints.
    ///
    /// # Arguments
    ///
    /// * `client_id` - The OAuth Client ID from the Bungie Application Portal.
    /// * `client_secret` - The OAuth Client Secret (optional for public clients).
    /// * `redirect_uri` - The URI Bungie will redirect to after authorization. Must match
    ///   the redirect URL configured in your application settings.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::Bungie;
    ///
    /// // With client secret (confidential client)
    /// let bungie = Bungie::new(
    ///     "your-client-id",
    ///     Some("your-client-secret".into()),
    ///     "https://example.com/callback",
    /// );
    ///
    /// // Without client secret (public client)
    /// let bungie_public = Bungie::new(
    ///     "your-client-id",
    ///     None,
    ///     "https://example.com/callback",
    /// );
    /// ```
    pub fn new(
        client_id: impl Into<String>,
        client_secret: Option<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        Self {
            client: OAuth2Client::new(client_id, client_secret, Some(redirect_uri.into())),
            authorization_endpoint: AUTHORIZATION_ENDPOINT.to_string(),
            token_endpoint: TOKEN_ENDPOINT.to_string(),
        }
    }
}

impl Bungie {
    /// Returns the provider name (`"Bungie"`).
    pub fn name(&self) -> &'static str {
        "Bungie"
    }

    /// Builds the Bungie authorization URL that the user should be redirected to.
    ///
    /// The returned URL includes all required OAuth 2.0 parameters. Your application
    /// should store `state` in the user's session before redirecting to verify the
    /// callback request.
    ///
    /// # Arguments
    ///
    /// * `state` - A CSRF token to prevent cross-site request forgery. Use
    ///   [`generate_state`](crate::generate_state) to create one.
    /// * `scopes` - OAuth 2.0 scopes (typically empty for Bungie as permissions are
    ///   configured in the application portal).
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{Bungie, generate_state};
    ///
    /// let bungie = Bungie::new("client-id", None, "https://example.com/cb");
    /// let state = generate_state();
    ///
    /// let url = bungie.authorization_url(&state, &[]);
    /// assert!(url.as_str().starts_with("https://www.bungie.net/"));
    /// ```
    pub fn authorization_url(&self, state: &str, scopes: &[&str]) -> url::Url {
        self.client
            .create_authorization_url(&self.authorization_endpoint, state, scopes)
    }

    /// Exchanges an authorization code for access and refresh tokens.
    ///
    /// Call this in your redirect URI handler after Bungie redirects back with a `code`
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
    /// Returns [`Error::OAuthRequest`] if Bungie rejects the code, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::{Bungie, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let bungie = Bungie::new("client-id", Some("secret".into()), "https://example.com/cb");
    /// let http = ReqwestClient::new();
    ///
    /// let tokens = bungie
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
        self.client
            .validate_authorization_code(http_client, &self.token_endpoint, code, None)
            .await
    }

    /// Refreshes an expired access token using a refresh token.
    ///
    /// Bungie access tokens expire after a certain period. If your initial token response
    /// included a refresh token, you can use it to obtain a new access token without user
    /// interaction.
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
    /// # use arctic_oauth::{Bungie, ReqwestClient};
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let bungie = Bungie::new("client-id", Some("secret".into()), "https://example.com/cb");
    /// let http = ReqwestClient::new();
    ///
    /// let new_tokens = bungie
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

    #[test]
    fn new_sets_production_endpoints() {
        let bungie = Bungie::new("cid", Some("secret".into()), "https://app/cb");
        assert_eq!(bungie.authorization_endpoint, AUTHORIZATION_ENDPOINT);
        assert_eq!(bungie.token_endpoint, TOKEN_ENDPOINT);
    }

    #[test]
    fn name_returns_bungie() {
        let bungie = Bungie::new("cid", None, "https://app/cb");
        assert_eq!(bungie.name(), "Bungie");
    }

    #[test]
    fn authorization_url_no_pkce() {
        let bungie = Bungie::new("cid", Some("secret".into()), "https://app/cb");
        let url = bungie.authorization_url("state123", &[]);

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.contains(&("client_id".into(), "cid".into())));
        assert!(!pairs.iter().any(|(k, _)| k == "code_challenge"));
    }

    #[tokio::test]
    async fn validate_authorization_code_delegates_to_client() {
        let bungie = Bungie::new("cid", Some("secret".into()), "https://app/cb");
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "bungie-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);

        let tokens = bungie
            .validate_authorization_code(&mock, "code")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "bungie-tok");

        let requests = mock.take_requests();
        assert_eq!(requests[0].url, TOKEN_ENDPOINT);
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("grant_type".into(), "authorization_code".into())));
    }

    #[tokio::test]
    async fn refresh_access_token_delegates_to_client() {
        let bungie = Bungie::new("cid", Some("secret".into()), "https://app/cb");
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "new-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);

        let tokens = bungie.refresh_access_token(&mock, "rt").await.unwrap();
        assert_eq!(tokens.access_token().unwrap(), "new-tok");
    }
}
