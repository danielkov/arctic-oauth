use crate::client::OAuth2Client;
use crate::error::Error;
use crate::http::HttpClient;
use crate::tokens::OAuth2Tokens;

const AUTHORIZATION_ENDPOINT: &str = "https://slack.com/openid/connect/authorize";
const TOKEN_ENDPOINT: &str = "https://slack.com/api/openid.connect.token";

/// Configuration for creating a [`Slack`] client with a custom HTTP client.
///
/// Use this when you need to provide your own [`HttpClient`] implementation
/// (e.g. a pre-configured `reqwest::Client` with custom timeouts or proxies).
/// For the common case, use [`Slack::new`] which uses the built-in default client.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{Slack, SlackOptions, HttpClient};
///
/// let custom_client = reqwest::Client::builder()
///     .timeout(std::time::Duration::from_secs(10))
///     .build()
///     .unwrap();
///
/// let slack = Slack::from_options(SlackOptions {
///     client_id: "your-client-id".into(),
///     client_secret: "your-client-secret".into(),
///     redirect_uri: Some("https://example.com/callback".into()),
///     http_client: &custom_client,
/// });
/// ```
pub struct SlackOptions<'a, H: HttpClient> {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: Option<String>,
    pub http_client: &'a H,
}

/// OAuth 2.0 client for [Slack](https://api.slack.com/authentication/oauth-v2).
///
/// Slack's OAuth implementation follows the standard authorization code flow without
/// requiring PKCE. This client supports token exchange but does not support token
/// refresh or revocation through the standard OAuth endpoints.
///
/// # Setup
///
/// 1. Create a new Slack app at the [Slack API portal](https://api.slack.com/apps).
/// 2. Navigate to **OAuth & Permissions** and note your **Client ID** and **Client Secret**.
/// 3. Add your redirect URI to the **Redirect URLs** section.
///
/// # Scopes
///
/// Slack uses space-separated scopes. Common scopes include:
///
/// | Scope | Description |
/// |-------|-------------|
/// | `openid` | OpenID Connect authentication |
/// | `profile` | User's profile information |
/// | `email` | User's email address |
///
/// See the full list at <https://api.slack.com/scopes>.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{Slack, generate_state};
///
/// # async fn example() -> Result<(), arctic_oauth::Error> {
/// let slack = Slack::new(
///     "your-client-id",
///     "your-client-secret",
///     Some("https://example.com/callback".into()),
/// );
///
/// // Step 1: Generate CSRF state and redirect the user.
/// let state = generate_state();
/// let url = slack.authorization_url(&state, &["openid", "profile", "email"]);
/// // Store `state` in the user's session, then redirect to `url`.
///
/// // Step 2: In your callback handler, exchange the authorization code for tokens.
/// let tokens = slack
///     .validate_authorization_code("authorization-code")
///     .await?;
/// println!("Access token: {}", tokens.access_token()?);
/// # Ok(())
/// # }
/// ```
pub struct Slack<'a, H: HttpClient> {
    client: OAuth2Client,
    http_client: &'a H,
    authorization_endpoint: String,
    token_endpoint: String,
}

impl<'a, H: HttpClient> Slack<'a, H> {
    /// Creates a Slack client from a [`SlackOptions`] struct.
    ///
    /// Use this when you need a custom HTTP client. For the common case,
    /// use [`Slack::new`] instead.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{Slack, SlackOptions};
    ///
    /// let custom_client = reqwest::Client::new();
    /// let slack = Slack::from_options(SlackOptions {
    ///     client_id: "your-client-id".into(),
    ///     client_secret: "your-client-secret".into(),
    ///     redirect_uri: Some("https://example.com/callback".into()),
    ///     http_client: &custom_client,
    /// });
    /// ```
    pub fn from_options(options: SlackOptions<'a, H>) -> Self {
        Self {
            http_client: options.http_client,
            client: OAuth2Client::new(
                options.client_id,
                Some(options.client_secret),
                options.redirect_uri,
            ),
            authorization_endpoint: AUTHORIZATION_ENDPOINT.to_string(),
            token_endpoint: TOKEN_ENDPOINT.to_string(),
        }
    }
}

#[cfg(feature = "reqwest-client")]
impl Slack<'static, reqwest::Client> {
    /// Creates a new Slack OAuth 2.0 client configured with production endpoints using the default HTTP client.
    ///
    /// Uses the built-in `reqwest::Client` for HTTP requests. To provide a custom
    /// HTTP client, use [`Slack::from_options`] instead.
    ///
    /// # Arguments
    ///
    /// * `client_id` - The OAuth 2.0 client ID from Slack's OAuth & Permissions page.
    /// * `client_secret` - The OAuth 2.0 client secret from Slack's OAuth & Permissions page.
    /// * `redirect_uri` - Optional redirect URI. If `None`, the redirect URI must be configured
    ///   in your Slack app and omitted from authorization requests.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::Slack;
    ///
    /// let slack = Slack::new(
    ///     "your-client-id",
    ///     "your-client-secret",
    ///     Some("https://example.com/callback".into()),
    /// );
    /// ```
    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: Option<String>,
    ) -> Self {
        Self::from_options(SlackOptions {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri,
            http_client: crate::http::default_client(),
        })
    }
}

impl<'a, H: HttpClient> Slack<'a, H> {
    /// Returns the provider name (`"Slack"`).
    pub fn name(&self) -> &'static str {
        "Slack"
    }

    /// Builds the Slack authorization URL that the user should be redirected to.
    ///
    /// The returned URL includes all required OAuth 2.0 parameters. Your application should
    /// store `state` in the user's session before redirecting.
    ///
    /// # Arguments
    ///
    /// * `state` - A CSRF token to prevent cross-site request forgery. Use
    ///   [`generate_state`](crate::generate_state) to create one.
    /// * `scopes` - The OAuth 2.0 scopes to request (e.g. `&["openid", "profile"]`).
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{Slack, generate_state};
    ///
    /// let slack = Slack::new("client-id", "client-secret", Some("https://example.com/cb".into()));
    /// let state = generate_state();
    ///
    /// let url = slack.authorization_url(&state, &["openid", "profile", "email"]);
    /// assert!(url.as_str().starts_with("https://slack.com/"));
    /// ```
    pub fn authorization_url(&self, state: &str, scopes: &[&str]) -> url::Url {
        self.client
            .create_authorization_url(&self.authorization_endpoint, state, scopes)
    }

    /// Exchanges an authorization code for access tokens.
    ///
    /// Call this in your redirect URI handler after Slack redirects back with a `code`
    /// query parameter.
    ///
    /// # Arguments
    ///
    /// * `code` - The authorization code from the `code` query parameter.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OAuthRequest`] if Slack rejects the code, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::Slack;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// let slack = Slack::new("client-id", "secret", Some("https://example.com/cb".into()));
    ///
    /// let tokens = slack
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

    fn get_header<'a>(request: &'a HttpRequest, name: &str) -> Option<&'a str> {
        request
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn make_slack(http_client: &MockHttpClient) -> Slack<'_, MockHttpClient> {
        Slack::from_options(SlackOptions {
            client_id: "cid".into(),
            client_secret: "secret".into(),
            redirect_uri: Some("https://app/cb".into()),
            http_client,
        })
    }

    #[test]
    fn new_sets_production_endpoints() {
        let mock = MockHttpClient::new(vec![]);
        let slack = make_slack(&mock);
        assert_eq!(slack.authorization_endpoint, AUTHORIZATION_ENDPOINT);
        assert_eq!(slack.token_endpoint, TOKEN_ENDPOINT);
    }

    #[test]
    fn name_returns_slack() {
        let mock = MockHttpClient::new(vec![]);
        let slack = make_slack(&mock);
        assert_eq!(slack.name(), "Slack");
    }

    #[test]
    fn new_with_no_redirect_uri() {
        let mock = MockHttpClient::new(vec![]);
        let slack = Slack::from_options(SlackOptions {
            client_id: "cid".into(),
            client_secret: "secret".into(),
            redirect_uri: None,
            http_client: &mock,
        });
        assert_eq!(slack.name(), "Slack");
    }

    #[test]
    fn authorization_url_with_scopes() {
        let mock = MockHttpClient::new(vec![]);
        let slack = make_slack(&mock);
        let url = slack.authorization_url("state123", &["openid", "profile", "email"]);

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.contains(&("client_id".into(), "cid".into())));
        assert!(pairs.contains(&("state".into(), "state123".into())));
        assert!(pairs.contains(&("scope".into(), "openid profile email".into())));
        assert!(pairs.contains(&("redirect_uri".into(), "https://app/cb".into())));
    }

    #[test]
    fn authorization_url_omits_redirect_uri_when_none() {
        let mock = MockHttpClient::new(vec![]);
        let slack = Slack::from_options(SlackOptions {
            client_id: "cid".into(),
            client_secret: "secret".into(),
            redirect_uri: None,
            http_client: &mock,
        });
        let url = slack.authorization_url("state123", &["openid"]);

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(!pairs.iter().any(|(k, _)| k == "redirect_uri"));
    }

    #[tokio::test]
    async fn validate_authorization_code_delegates_to_client() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "slack-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);
        let slack = make_slack(&mock);

        let tokens = slack
            .validate_authorization_code("auth-code")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "slack-tok");

        let requests = mock.take_requests();
        assert_eq!(
            requests[0].url,
            "https://slack.com/api/openid.connect.token"
        );
        assert!(get_header(&requests[0], "Authorization").is_some());
    }
}
