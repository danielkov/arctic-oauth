use crate::error::Error;
use crate::http::HttpClient;
use crate::tokens::OAuth2Tokens;

use super::auth_request::AuthorizationRequest;
use super::callback::CallbackParams;
use super::token_request::{
    AuthorizationCodeGrant, ClientCredentialsGrant, RefreshTokenGrant, TokenIntrospection,
    introspect, revoke_token, send_authorization_code_grant, send_client_credentials_grant,
    send_refresh_token_grant,
};

/// Client authentication method used at the token endpoint.
///
/// OAuth 2.1 mandates that authorization servers support `client_secret_post`;
/// `client_secret_basic` is optional. A generic 2.1 client therefore defaults
/// to `client_secret_post` for confidential clients unless metadata or
/// configuration explicitly says otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAuthenticationMethod {
    /// Public client. Token requests include `client_id` in the form body and
    /// no `Authorization` header.
    None,
    /// Mandatory-to-support method for OAuth 2.1 servers. Token requests
    /// include `client_id` and `client_secret` in the form body.
    ClientSecretPost,
    /// Optional method. Each credential is form-encoded, joined with `:`,
    /// base64-encoded, and sent as `Authorization: Basic ...`.
    ClientSecretBasic,
}

/// Whether the RFC 9207 `iss` parameter is required on the authorization response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssuerPolicy {
    /// `iss` is not required, but if present it must match the configured
    /// issuer.
    Optional,
    /// `iss` is required. Missing or mismatched values are rejected.
    Required,
}

/// Loopback redirect host (RFC 8252 §7.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopbackHost {
    /// `127.0.0.1`
    V4,
    /// `[::1]`
    V6,
}

impl LoopbackHost {
    fn as_host(self) -> &'static str {
        match self {
            LoopbackHost::V4 => "127.0.0.1",
            LoopbackHost::V6 => "[::1]",
        }
    }
}

/// Redirect URI configuration.
///
/// OAuth 2.1 mandates exact-string matching for redirect URIs (RFC 3986 §6.2.1
/// simple string comparison). The sole exception is native-app loopback URIs
/// (RFC 8252 §7.3) where the port may vary at runtime.
#[derive(Debug, Clone)]
pub enum RedirectUri {
    /// Exact-string redirect URI.
    Exact(String),
    /// Loopback URI per RFC 8252 §7.3. Path must start with `/`.
    Loopback {
        host: LoopbackHost,
        port: u16,
        path: String,
    },
}

impl RedirectUri {
    /// Render to a wire-format URI string.
    pub fn to_uri_string(&self) -> String {
        match self {
            RedirectUri::Exact(s) => s.clone(),
            RedirectUri::Loopback { host, port, path } => {
                let path = if path.starts_with('/') {
                    path.clone()
                } else {
                    format!("/{path}")
                };
                format!("http://{}:{}{}", host.as_host(), port, path)
            }
        }
    }
}

/// Configuration for [`OAuth21Client`].
pub struct OAuth21Options<'a, H: HttpClient> {
    /// Issuer identifier (base URL of the AS). Used for RFC 9207 `iss`
    /// validation and metadata discovery.
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    /// RFC 7009.
    pub revocation_endpoint: Option<String>,
    /// RFC 7662.
    pub introspection_endpoint: Option<String>,
    pub client_id: String,
    /// `None` for public clients.
    pub client_secret: Option<String>,
    pub client_auth_method: ClientAuthenticationMethod,
    pub issuer_policy: IssuerPolicy,
    pub redirect_uri: RedirectUri,
    pub http_client: &'a H,
}

/// Generic OAuth 2.1 client.
///
/// Speaks the RFC 6749/2.1 wire format with the 2.1 invariants enforced:
/// PKCE is always sent (S256 only), redirect URI matching is exact (with the
/// loopback exception), and only the three standard grants are reachable.
pub struct OAuth21Client<'a, H: HttpClient> {
    pub(super) http_client: &'a H,
    pub(super) issuer: String,
    pub(super) authorization_endpoint: String,
    pub(super) token_endpoint: String,
    pub(super) revocation_endpoint: Option<String>,
    pub(super) introspection_endpoint: Option<String>,
    pub(super) client_id: String,
    pub(super) client_secret: Option<String>,
    pub(super) client_auth_method: ClientAuthenticationMethod,
    pub(super) issuer_policy: IssuerPolicy,
    pub(super) redirect_uri: RedirectUri,
}

impl<'a, H: HttpClient> OAuth21Client<'a, H> {
    /// Construct a client from explicit options. Validates that
    /// `client_secret` and `client_auth_method` are consistent.
    pub fn from_options(options: OAuth21Options<'a, H>) -> Result<Self, Error> {
        match (&options.client_secret, options.client_auth_method) {
            (None, ClientAuthenticationMethod::None) => {}
            (Some(_), ClientAuthenticationMethod::ClientSecretPost)
            | (Some(_), ClientAuthenticationMethod::ClientSecretBasic) => {}
            (None, _) => {
                return Err(Error::InvalidConfiguration {
                    reason: "public client must use ClientAuthenticationMethod::None",
                });
            }
            (Some(_), ClientAuthenticationMethod::None) => {
                return Err(Error::InvalidConfiguration {
                    reason: "confidential client must not use ClientAuthenticationMethod::None",
                });
            }
        }

        Ok(Self {
            http_client: options.http_client,
            issuer: options.issuer,
            authorization_endpoint: options.authorization_endpoint,
            token_endpoint: options.token_endpoint,
            revocation_endpoint: options.revocation_endpoint,
            introspection_endpoint: options.introspection_endpoint,
            client_id: options.client_id,
            client_secret: options.client_secret,
            client_auth_method: options.client_auth_method,
            issuer_policy: options.issuer_policy,
            redirect_uri: options.redirect_uri,
        })
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    pub fn issuer_policy(&self) -> IssuerPolicy {
        self.issuer_policy
    }

    pub fn client_auth_method(&self) -> ClientAuthenticationMethod {
        self.client_auth_method
    }

    pub fn http_client(&self) -> &H {
        self.http_client
    }

    /// Begin building an authorization request. PKCE and state are generated
    /// automatically if not supplied via the builder.
    pub fn authorization_request(&self) -> AuthorizationRequest<'_, H> {
        AuthorizationRequest::new(self)
    }

    /// Parse the authorization response from the redirect URL and validate
    /// state and `iss` against this client's configured policy.
    pub fn parse_callback(
        &self,
        redirect_url: &url::Url,
        expected_state: &str,
    ) -> Result<CallbackParams, Error> {
        CallbackParams::parse(
            redirect_url,
            expected_state,
            &self.issuer,
            self.issuer_policy,
        )
    }

    /// Exchange an authorization code for tokens.
    pub async fn validate_authorization_code(
        &self,
        params: AuthorizationCodeGrant<'_>,
    ) -> Result<OAuth2Tokens, Error> {
        send_authorization_code_grant(self, params).await
    }

    /// Refresh an access token.
    pub async fn refresh_access_token(
        &self,
        params: RefreshTokenGrant<'_>,
    ) -> Result<OAuth2Tokens, Error> {
        send_refresh_token_grant(self, params).await
    }

    /// Run the client_credentials grant. Confidential clients only.
    pub async fn client_credentials(
        &self,
        params: ClientCredentialsGrant<'_>,
    ) -> Result<OAuth2Tokens, Error> {
        send_client_credentials_grant(self, params).await
    }

    /// Revoke a token (RFC 7009). Returns
    /// `Err(Error::UnsupportedByServer { capability: "revocation" })` if no
    /// revocation endpoint is configured.
    pub async fn revoke_token(&self, token: &str) -> Result<(), Error> {
        revoke_token(self, token).await
    }

    /// Introspect a token (RFC 7662). Returns
    /// `Err(Error::UnsupportedByServer { capability: "introspection" })` if
    /// no introspection endpoint is configured.
    pub async fn introspect(&self, token: &str) -> Result<TokenIntrospection, Error> {
        introspect(self, token).await
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
        fn new() -> Self {
            Self {
                responses: Mutex::new(Vec::new()),
                recorded: Mutex::new(Vec::new()),
            }
        }
    }

    impl HttpClient for MockHttpClient {
        async fn send(
            &self,
            request: HttpRequest,
        ) -> Result<HttpResponse, Box<dyn std::error::Error + Send + Sync>> {
            self.recorded.lock().unwrap().push(request);
            Ok(self.responses.lock().unwrap().remove(0))
        }
    }

    #[test]
    fn loopback_v4_renders_correctly() {
        let r = RedirectUri::Loopback {
            host: LoopbackHost::V4,
            port: 8080,
            path: "/callback".into(),
        };
        assert_eq!(r.to_uri_string(), "http://127.0.0.1:8080/callback");
    }

    #[test]
    fn loopback_v6_renders_correctly() {
        let r = RedirectUri::Loopback {
            host: LoopbackHost::V6,
            port: 9090,
            path: "/cb".into(),
        };
        assert_eq!(r.to_uri_string(), "http://[::1]:9090/cb");
    }

    #[test]
    fn loopback_path_without_leading_slash_is_normalized() {
        let r = RedirectUri::Loopback {
            host: LoopbackHost::V4,
            port: 1,
            path: "callback".into(),
        };
        assert_eq!(r.to_uri_string(), "http://127.0.0.1:1/callback");
    }

    #[test]
    fn exact_redirect_uri_passes_through() {
        let r = RedirectUri::Exact("https://app.example.com/cb".into());
        assert_eq!(r.to_uri_string(), "https://app.example.com/cb");
    }

    fn options(http: &MockHttpClient) -> OAuth21Options<'_, MockHttpClient> {
        OAuth21Options {
            issuer: "https://as.example.com".into(),
            authorization_endpoint: "https://as.example.com/authorize".into(),
            token_endpoint: "https://as.example.com/token".into(),
            revocation_endpoint: None,
            introspection_endpoint: None,
            client_id: "cid".into(),
            client_secret: None,
            client_auth_method: ClientAuthenticationMethod::None,
            issuer_policy: IssuerPolicy::Optional,
            redirect_uri: RedirectUri::Exact("https://app/cb".into()),
            http_client: http,
        }
    }

    #[test]
    fn from_options_accepts_public_client() {
        let http = MockHttpClient::new();
        let client = OAuth21Client::from_options(options(&http)).unwrap();
        assert_eq!(client.issuer(), "https://as.example.com");
    }

    #[test]
    fn from_options_rejects_public_client_with_post_auth() {
        let http = MockHttpClient::new();
        let mut opts = options(&http);
        opts.client_auth_method = ClientAuthenticationMethod::ClientSecretPost;
        let err = OAuth21Client::from_options(opts).err().unwrap();
        assert!(matches!(err, Error::InvalidConfiguration { .. }));
    }

    #[test]
    fn from_options_rejects_confidential_client_with_none_auth() {
        let http = MockHttpClient::new();
        let mut opts = options(&http);
        opts.client_secret = Some("sec".into());
        opts.client_auth_method = ClientAuthenticationMethod::None;
        let err = OAuth21Client::from_options(opts).err().unwrap();
        assert!(matches!(err, Error::InvalidConfiguration { .. }));
    }

    #[test]
    fn from_options_accepts_confidential_with_post_auth() {
        let http = MockHttpClient::new();
        let mut opts = options(&http);
        opts.client_secret = Some("sec".into());
        opts.client_auth_method = ClientAuthenticationMethod::ClientSecretPost;
        OAuth21Client::from_options(opts).unwrap();
    }

    #[test]
    fn from_options_accepts_confidential_with_basic_auth() {
        let http = MockHttpClient::new();
        let mut opts = options(&http);
        opts.client_secret = Some("sec".into());
        opts.client_auth_method = ClientAuthenticationMethod::ClientSecretBasic;
        OAuth21Client::from_options(opts).unwrap();
    }
}
