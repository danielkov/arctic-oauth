use base64::Engine;
use p256::ecdsa::{SigningKey, signature::Signer};
use p256::pkcs8::DecodePrivateKey;

use crate::error::Error;
use crate::http::HttpClient;
use crate::request::{create_oauth2_request, send_token_request};
use crate::tokens::OAuth2Tokens;

const AUTHORIZATION_ENDPOINT: &str = "https://appleid.apple.com/auth/authorize";
const TOKEN_ENDPOINT: &str = "https://appleid.apple.com/auth/token";

/// Configuration for creating an [`Apple`] client with a custom HTTP client.
///
/// Use this when you need to provide your own [`HttpClient`] implementation
/// (e.g. a pre-configured `reqwest::Client` with custom timeouts or proxies).
/// For the common case, use [`Apple::new`] which uses the built-in default client.
///
/// # Example
///
/// ```rust
/// use arctic_oauth::{Apple, AppleOptions, HttpClient};
///
/// # fn example() -> Result<(), arctic_oauth::Error> {
/// # let private_key = vec![0u8; 32];
/// let custom_client = reqwest::Client::builder()
///     .timeout(std::time::Duration::from_secs(10))
///     .build()
///     .unwrap();
///
/// let apple = Apple::from_options(AppleOptions {
///     client_id: "com.example.myapp".into(),
///     team_id: "ABC123DEF4".into(),
///     key_id: "XYZ987WVU6".into(),
///     pkcs8_private_key: private_key,
///     redirect_uri: "https://example.com/callback".into(),
///     http_client: &custom_client,
/// })?;
/// # Ok(())
/// # }
/// ```
pub struct AppleOptions<'a, H: HttpClient> {
    pub client_id: String,
    pub team_id: String,
    pub key_id: String,
    pub pkcs8_private_key: Vec<u8>,
    pub redirect_uri: String,
    pub http_client: &'a H,
}

/// OAuth 2.0 client for [Sign in with Apple](https://developer.apple.com/sign-in-with-apple/).
///
/// Apple uses a unique authentication approach that requires a dynamically generated JWT
/// client secret signed with your private key. This client handles JWT generation internally
/// and supports the authorization code flow with refresh tokens.
///
/// # Setup
///
/// 1. Register for an Apple Developer account at <https://developer.apple.com/>.
/// 2. Create an **App ID** in the Apple Developer portal and enable **Sign in with Apple**.
/// 3. Create a **Services ID** (this becomes your `client_id`) and configure the redirect URI.
/// 4. Create a **Private Key** for Sign in with Apple and download the `.p8` file.
/// 5. Note your **Team ID** and **Key ID** from the portal.
/// 6. Convert the `.p8` key to PKCS#8 DER format for use with this client.
///
/// # Scopes
///
/// Apple uses space-separated scopes. Common scopes include:
///
/// | Scope | Description |
/// |-------|-------------|
/// | `name` | User's full name |
/// | `email` | User's email address |
///
/// See the full documentation at <https://developer.apple.com/documentation/sign_in_with_apple/clientconfigi/3230955-scope>.
///
/// # Example
///
/// ```rust,no_run
/// use arctic_oauth::{Apple, generate_state};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Load your Apple private key in PKCS#8 DER format
/// let private_key = std::fs::read("apple_private_key.p8")?;
///
/// let apple = Apple::new(
///     "com.example.myapp",        // Services ID (client_id)
///     "ABC123DEF4",                // Team ID
///     "XYZ987WVU6",                // Key ID
///     &private_key,                // PKCS#8 DER-encoded private key
///     "https://example.com/callback",
/// )?;
///
/// // Step 1: Generate CSRF state and redirect the user.
/// let state = generate_state();
/// let url = apple.authorization_url(&state, &["name", "email"]);
/// // Store `state` in the user's session, then redirect to `url`.
///
/// // Step 2: In your callback handler, exchange the authorization code for tokens.
/// let tokens = apple
///     .validate_authorization_code("authorization-code")
///     .await?;
/// println!("Access token: {}", tokens.access_token()?);
/// # Ok(())
/// # }
/// ```
pub struct Apple<'a, H: HttpClient> {
    client_id: String,
    team_id: String,
    key_id: String,
    signing_key: SigningKey,
    redirect_uri: String,
    http_client: &'a H,
    authorization_endpoint: String,
    token_endpoint: String,
}

impl<'a, H: HttpClient> Apple<'a, H> {
    /// Creates an Apple client from an [`AppleOptions`] struct.
    ///
    /// Use this when you need a custom HTTP client. For the common case,
    /// use [`Apple::new`] instead.
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{Apple, AppleOptions};
    ///
    /// # fn example() -> Result<(), arctic_oauth::Error> {
    /// # let private_key = vec![0u8; 32];
    /// let custom_client = reqwest::Client::new();
    /// let apple = Apple::from_options(AppleOptions {
    ///     client_id: "com.example.myapp".into(),
    ///     team_id: "ABC123DEF4".into(),
    ///     key_id: "XYZ987WVU6".into(),
    ///     pkcs8_private_key: private_key,
    ///     redirect_uri: "https://example.com/callback".into(),
    ///     http_client: &custom_client,
    /// })?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_options(options: AppleOptions<'a, H>) -> Result<Self, Error> {
        let signing_key = SigningKey::from_pkcs8_der(&options.pkcs8_private_key)
            .map_err(|e| Error::Http(Box::new(e)))?;
        Ok(Self {
            http_client: options.http_client,
            client_id: options.client_id,
            team_id: options.team_id,
            key_id: options.key_id,
            signing_key,
            redirect_uri: options.redirect_uri,
            authorization_endpoint: AUTHORIZATION_ENDPOINT.to_string(),
            token_endpoint: TOKEN_ENDPOINT.to_string(),
        })
    }
}

#[cfg(feature = "reqwest-client")]
impl Apple<'static, reqwest::Client> {
    /// Creates a new Apple OAuth 2.0 client using the default HTTP client.
    ///
    /// The endpoints are automatically set to production values.
    /// Uses the built-in `reqwest::Client` for HTTP requests. To provide a custom
    /// HTTP client, use [`Apple::from_options`] instead.
    ///
    /// # Arguments
    ///
    /// * `client_id` - The Services ID from Apple Developer portal.
    /// * `team_id` - Your Apple Developer Team ID.
    /// * `key_id` - The Key ID associated with your Sign in with Apple private key.
    /// * `pkcs8_private_key` - Your private key in PKCS#8 DER format (the contents of the `.p8` file converted to DER).
    /// * `redirect_uri` - The URI Apple will redirect to after authorization. Must match
    ///   one of the redirect URIs configured in your Services ID.
    ///
    /// # Errors
    ///
    /// Returns an error if the private key is not valid PKCS#8 DER-encoded data.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use arctic_oauth::Apple;
    ///
    /// # fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let private_key = std::fs::read("apple_key.p8")?;
    /// let apple = Apple::new(
    ///     "com.example.myapp",
    ///     "ABC123DEF4",
    ///     "XYZ987WVU6",
    ///     &private_key,
    ///     "https://example.com/callback",
    /// )?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(
        client_id: impl Into<String>,
        team_id: impl Into<String>,
        key_id: impl Into<String>,
        pkcs8_private_key: &[u8],
        redirect_uri: impl Into<String>,
    ) -> Result<Self, Error> {
        Self::from_options(AppleOptions {
            client_id: client_id.into(),
            team_id: team_id.into(),
            key_id: key_id.into(),
            pkcs8_private_key: pkcs8_private_key.to_vec(),
            redirect_uri: redirect_uri.into(),
            http_client: crate::http::default_client(),
        })
    }
}

impl<'a, H: HttpClient> Apple<'a, H> {
    /// Returns the provider name (`"Apple"`).
    pub fn name(&self) -> &'static str {
        "Apple"
    }

    /// Builds the Apple authorization URL that the user should be redirected to.
    ///
    /// The returned URL includes all required OAuth 2.0 parameters. Your application
    /// should store `state` in the user's session before redirecting, as it is needed
    /// to validate the callback. Apple does not require PKCE for this flow.
    ///
    /// # Arguments
    ///
    /// * `state` - A CSRF token to prevent cross-site request forgery. Use
    ///   [`generate_state`](crate::generate_state) to create one.
    /// * `scopes` - The OAuth 2.0 scopes to request (e.g. `&["name", "email"]`).
    ///
    /// # Example
    ///
    /// ```rust
    /// use arctic_oauth::{Apple, generate_state};
    ///
    /// # fn example() -> Result<(), arctic_oauth::Error> {
    /// # let test_key = vec![0u8; 32];
    /// let apple = Apple::new("client-id", "team-id", "key-id", &test_key, "https://example.com/cb")?;
    /// let state = generate_state();
    ///
    /// let url = apple.authorization_url(&state, &["name", "email"]);
    /// assert!(url.as_str().starts_with("https://appleid.apple.com/"));
    /// # Ok(())
    /// # }
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

    fn generate_client_secret(&self) -> String {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let header = serde_json::json!({
            "alg": "ES256",
            "kid": self.key_id
        });
        let header_encoded = b64.encode(header.to_string().as_bytes());

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before UNIX epoch")
            .as_secs();

        let claims = serde_json::json!({
            "iss": self.team_id,
            "sub": self.client_id,
            "aud": "https://appleid.apple.com",
            "iat": now,
            "exp": now + 300
        });
        let claims_encoded = b64.encode(claims.to_string().as_bytes());

        let signing_input = format!("{header_encoded}.{claims_encoded}");

        let signature: p256::ecdsa::Signature = self.signing_key.sign(signing_input.as_bytes());
        let signature_encoded = b64.encode(signature.to_bytes());

        format!("{signing_input}.{signature_encoded}")
    }

    /// Exchanges an authorization code for access and refresh tokens.
    ///
    /// Call this in your redirect URI handler after Apple redirects back with a `code`
    /// query parameter. This method automatically generates a JWT client secret signed
    /// with your private key and includes it in the token request.
    ///
    /// # Arguments
    ///
    /// * `code` - The authorization code from the `code` query parameter.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OAuthRequest`] if Apple rejects the code, or
    /// [`Error::Http`] on network failure.
    ///
    /// # Example
    ///
    /// ```rust
    /// # use arctic_oauth::Apple;
    /// # async fn example() -> Result<(), arctic_oauth::Error> {
    /// # let test_key = vec![0u8; 32];
    /// let apple = Apple::new("client-id", "team-id", "key-id", &test_key, "https://example.com/cb")?;
    ///
    /// let tokens = apple
    ///     .validate_authorization_code("the-auth-code")
    ///     .await?;
    ///
    /// println!("Access token: {}", tokens.access_token()?);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn validate_authorization_code(&self, code: &str) -> Result<OAuth2Tokens, Error> {
        let client_secret = self.generate_client_secret();
        let body = vec![
            ("grant_type".to_string(), "authorization_code".to_string()),
            ("code".to_string(), code.to_string()),
            ("client_id".to_string(), self.client_id.clone()),
            ("client_secret".to_string(), client_secret),
            ("redirect_uri".to_string(), self.redirect_uri.clone()),
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

    /// Generate a test PKCS#8 DER-encoded P-256 private key.
    fn test_pkcs8_key() -> Vec<u8> {
        let signing_key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        use p256::pkcs8::EncodePrivateKey;
        signing_key
            .to_pkcs8_der()
            .expect("failed to encode test key")
            .as_bytes()
            .to_vec()
    }

    fn make_apple(http_client: &MockHttpClient) -> Apple<'_, MockHttpClient> {
        let key = test_pkcs8_key();
        Apple::from_options(AppleOptions {
            client_id: "cid".into(),
            team_id: "team".into(),
            key_id: "kid".into(),
            pkcs8_private_key: key,
            redirect_uri: "https://app/cb".into(),
            http_client,
        })
        .unwrap()
    }

    #[test]
    fn new_sets_production_endpoints() {
        let key = test_pkcs8_key();
        let provider = Apple::new("cid", "team", "kid", &key, "https://app/cb").unwrap();
        assert_eq!(provider.authorization_endpoint, AUTHORIZATION_ENDPOINT);
        assert_eq!(provider.token_endpoint, TOKEN_ENDPOINT);
    }

    #[test]
    fn new_fails_with_invalid_pkcs8_key() {
        let result = Apple::new("cid", "team", "kid", b"not-a-valid-key", "https://app/cb");
        assert!(result.is_err());
    }

    #[test]
    fn name_returns_apple() {
        let mock = MockHttpClient::new(vec![]);
        let provider = make_apple(&mock);
        assert_eq!(provider.name(), "Apple");
    }

    #[test]
    fn authorization_url_builds_correct_params() {
        let mock = MockHttpClient::new(vec![]);
        let provider = make_apple(&mock);
        let url = provider.authorization_url("state123", &["name", "email"]);

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.contains(&("client_id".into(), "cid".into())));
        assert!(pairs.contains(&("state".into(), "state123".into())));
        assert!(pairs.contains(&("scope".into(), "name email".into())));
        assert!(pairs.contains(&("redirect_uri".into(), "https://app/cb".into())));
    }

    #[test]
    fn authorization_url_omits_scope_when_empty() {
        let mock = MockHttpClient::new(vec![]);
        let provider = make_apple(&mock);
        let url = provider.authorization_url("state123", &[]);

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(!pairs.iter().any(|(k, _)| k == "scope"));
    }

    #[test]
    fn generate_client_secret_has_valid_jwt_structure() {
        let mock = MockHttpClient::new(vec![]);
        let key = test_pkcs8_key();
        let provider = Apple::from_options(AppleOptions {
            client_id: "cid".into(),
            team_id: "TEAMID".into(),
            key_id: "KEYID".into(),
            pkcs8_private_key: key,
            redirect_uri: "https://app/cb".into(),
            http_client: &mock,
        })
        .unwrap();
        let jwt = provider.generate_client_secret();

        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT must have 3 parts");

        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;

        // Verify header
        let header_bytes = b64
            .decode(parts[0])
            .expect("header should be valid base64url");
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["kid"], "KEYID");

        // Verify claims
        let claims_bytes = b64
            .decode(parts[1])
            .expect("claims should be valid base64url");
        let claims: serde_json::Value = serde_json::from_slice(&claims_bytes).unwrap();
        assert_eq!(claims["iss"], "TEAMID");
        assert_eq!(claims["sub"], "cid");
        assert_eq!(claims["aud"], "https://appleid.apple.com");
        assert!(claims["iat"].is_u64());
        assert!(claims["exp"].is_u64());

        let iat = claims["iat"].as_u64().unwrap();
        let exp = claims["exp"].as_u64().unwrap();
        assert_eq!(exp - iat, 300);

        // Verify signature is valid base64url (non-empty)
        let sig_bytes = b64
            .decode(parts[2])
            .expect("signature should be valid base64url");
        assert!(!sig_bytes.is_empty());
    }

    #[tokio::test]
    async fn validate_authorization_code_sends_body_credentials() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "apple-tok",
                "token_type": "bearer"
            }))
            .unwrap(),
        }]);
        let provider = make_apple(&mock);

        let tokens = provider
            .validate_authorization_code("auth-code")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "apple-tok");

        let requests = mock.take_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url, TOKEN_ENDPOINT);

        // No Authorization header (body credentials, not Basic Auth)
        assert!(get_header(&requests[0], "Authorization").is_none());

        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("grant_type".into(), "authorization_code".into())));
        assert!(body.contains(&("code".into(), "auth-code".into())));
        assert!(body.contains(&("client_id".into(), "cid".into())));
        assert!(body.contains(&("redirect_uri".into(), "https://app/cb".into())));

        // client_secret should be present and be a JWT (3 dot-separated parts)
        let client_secret = body
            .iter()
            .find(|(k, _)| k == "client_secret")
            .expect("client_secret must be in body");
        let jwt_parts: Vec<&str> = client_secret.1.split('.').collect();
        assert_eq!(jwt_parts.len(), 3, "client_secret must be a JWT");
    }
}
