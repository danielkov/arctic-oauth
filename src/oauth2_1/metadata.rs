use serde::Deserialize;
use url::{Host, Url};

use crate::error::Error;
use crate::http::{HttpClient, HttpRequest, HttpResponse};

use super::client::{
    ClientAuthenticationMethod, IssuerPolicy, OAuth21Client, OAuth21Options, RedirectUri,
};

/// Subset of RFC 8414 / OIDC Discovery metadata used by [`OAuth21Client`].
#[derive(Debug, Clone, Deserialize)]
pub struct AuthorizationServerMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub revocation_endpoint: Option<String>,
    pub introspection_endpoint: Option<String>,
    pub registration_endpoint: Option<String>,
    pub jwks_uri: Option<String>,
    pub scopes_supported: Option<Vec<String>>,
    pub response_types_supported: Vec<String>,
    pub grant_types_supported: Option<Vec<String>>,
    pub code_challenge_methods_supported: Option<Vec<String>>,
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    pub authorization_response_iss_parameter_supported: Option<bool>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl AuthorizationServerMetadata {
    /// Fetch RFC 8414 metadata from the well-known URL derived from `issuer`.
    pub async fn fetch(http: &impl HttpClient, issuer: &str) -> Result<Self, Error> {
        let url = derive_rfc8414_url(issuer)?;
        fetch_metadata(http, &url).await
    }

    /// Fetch OIDC discovery metadata from `<issuer>/.well-known/openid-configuration`.
    pub async fn fetch_oidc(http: &impl HttpClient, issuer: &str) -> Result<Self, Error> {
        let url = derive_oidc_url(issuer)?;
        fetch_metadata(http, &url).await
    }

    /// Verify that the AS advertises `code` response type, the
    /// `authorization_code` grant (if `grant_types_supported` is published),
    /// and `S256` PKCE.
    pub fn assert_supports_authorization_code_with_pkce_s256(&self) -> Result<(), Error> {
        if !self.response_types_supported.iter().any(|t| t == "code") {
            return Err(Error::UnsupportedByServer {
                capability: "response_type=code",
            });
        }
        if let Some(grants) = &self.grant_types_supported
            && !grants.iter().any(|g| g == "authorization_code")
        {
            return Err(Error::UnsupportedByServer {
                capability: "grant_type=authorization_code",
            });
        }
        if let Some(methods) = &self.code_challenge_methods_supported
            && !methods.iter().any(|m| m == "S256")
        {
            return Err(Error::UnsupportedByServer {
                capability: "code_challenge_method=S256",
            });
        }
        Ok(())
    }

    /// Pick an appropriate client authentication method given the metadata
    /// and whether the caller has a `client_secret`.
    ///
    /// Public clients always use [`ClientAuthenticationMethod::None`].
    /// Confidential clients prefer [`ClientAuthenticationMethod::ClientSecretPost`]
    /// (mandatory-to-support per OAuth 2.1) and fall back to
    /// [`ClientAuthenticationMethod::ClientSecretBasic`] only when metadata
    /// explicitly advertises `client_secret_basic` and does not advertise
    /// `client_secret_post`.
    pub fn select_client_auth_method(
        &self,
        client_secret: Option<&str>,
    ) -> Result<ClientAuthenticationMethod, Error> {
        if client_secret.is_none() {
            return Ok(ClientAuthenticationMethod::None);
        }
        match &self.token_endpoint_auth_methods_supported {
            None => Ok(ClientAuthenticationMethod::ClientSecretPost),
            Some(methods) => {
                let has_post = methods.iter().any(|m| m == "client_secret_post");
                let has_basic = methods.iter().any(|m| m == "client_secret_basic");
                if has_post {
                    Ok(ClientAuthenticationMethod::ClientSecretPost)
                } else if has_basic {
                    Ok(ClientAuthenticationMethod::ClientSecretBasic)
                } else {
                    Err(Error::UnsupportedByServer {
                        capability: "client_secret_post or client_secret_basic",
                    })
                }
            }
        }
    }

    /// Derive [`IssuerPolicy`] from the
    /// `authorization_response_iss_parameter_supported` metadata field.
    pub fn issuer_policy(&self) -> IssuerPolicy {
        match self.authorization_response_iss_parameter_supported {
            Some(true) => IssuerPolicy::Required,
            _ => IssuerPolicy::Optional,
        }
    }
}

async fn fetch_metadata(
    http: &impl HttpClient,
    url: &str,
) -> Result<AuthorizationServerMetadata, Error> {
    let request = HttpRequest {
        url: url.to_string(),
        headers: vec![
            ("Accept".into(), "application/json".into()),
            ("User-Agent".into(), "arctic-oauth".into()),
        ],
        body: Vec::new(),
        method: http::Method::GET,
    };
    let response: HttpResponse = http.send(request).await?;

    match response.status {
        200 => {
            serde_json::from_slice::<AuthorizationServerMetadata>(&response.body).map_err(|_| {
                Error::UnexpectedErrorBody {
                    status: 200,
                    body: String::from_utf8_lossy(&response.body).into_owned(),
                }
            })
        }
        status => Err(Error::UnexpectedResponse { status }),
    }
}

/// RFC 8414 §3.1: insert `/.well-known/oauth-authorization-server` after the
/// host (and before the issuer path).
pub(super) fn derive_rfc8414_url(issuer: &str) -> Result<String, Error> {
    let parsed = Url::parse(issuer).map_err(|_| Error::InvalidConfiguration {
        reason: "issuer is not a valid URL",
    })?;
    let scheme = parsed.scheme();
    let host = parsed.host().ok_or(Error::InvalidConfiguration {
        reason: "issuer has no host",
    })?;
    let host = match host {
        Host::Ipv6(addr) => format!("[{addr}]"),
        _ => parsed.host_str().unwrap().to_string(),
    };
    let port = parsed.port().map(|p| format!(":{p}")).unwrap_or_default();
    let path = parsed.path().trim_end_matches('/');
    if path.is_empty() {
        Ok(format!(
            "{scheme}://{host}{port}/.well-known/oauth-authorization-server"
        ))
    } else {
        Ok(format!(
            "{scheme}://{host}{port}/.well-known/oauth-authorization-server{path}"
        ))
    }
}

/// OIDC Discovery: append `/.well-known/openid-configuration` after the
/// issuer path.
pub(super) fn derive_oidc_url(issuer: &str) -> Result<String, Error> {
    let parsed = Url::parse(issuer).map_err(|_| Error::InvalidConfiguration {
        reason: "issuer is not a valid URL",
    })?;
    if parsed.host_str().is_none() {
        return Err(Error::InvalidConfiguration {
            reason: "issuer has no host",
        });
    }
    let trimmed = issuer.trim_end_matches('/');
    Ok(format!("{trimmed}/.well-known/openid-configuration"))
}

impl<'a, H: HttpClient> OAuth21Client<'a, H> {
    /// Discover endpoints from the RFC 8414 well-known metadata URL derived
    /// from `issuer`. Falls back to OIDC discovery if the RFC 8414 fetch
    /// fails.
    pub async fn discover(
        http_client: &'a H,
        issuer: &str,
        client_id: impl Into<String>,
        client_secret: Option<String>,
        redirect_uri: RedirectUri,
    ) -> Result<Self, Error> {
        let metadata = match AuthorizationServerMetadata::fetch(http_client, issuer).await {
            Ok(m) => m,
            Err(_) => AuthorizationServerMetadata::fetch_oidc(http_client, issuer).await?,
        };

        if metadata.issuer != issuer {
            return Err(Error::IssuerMismatch {
                expected: issuer.to_string(),
                got: Some(metadata.issuer.clone()),
            });
        }

        metadata.assert_supports_authorization_code_with_pkce_s256()?;

        let client_auth_method = metadata.select_client_auth_method(client_secret.as_deref())?;
        let issuer_policy = metadata.issuer_policy();

        OAuth21Client::from_options(OAuth21Options {
            issuer: metadata.issuer,
            authorization_endpoint: metadata.authorization_endpoint,
            token_endpoint: metadata.token_endpoint,
            revocation_endpoint: metadata.revocation_endpoint,
            introspection_endpoint: metadata.introspection_endpoint,
            client_id: client_id.into(),
            client_secret,
            client_auth_method,
            issuer_policy,
            redirect_uri,
            http_client,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
            Ok(self.responses.lock().unwrap().remove(0))
        }
    }

    #[test]
    fn rfc8414_url_for_root_issuer() {
        let url = derive_rfc8414_url("https://example.com").unwrap();
        assert_eq!(
            url,
            "https://example.com/.well-known/oauth-authorization-server"
        );
    }

    #[test]
    fn rfc8414_url_for_root_issuer_with_trailing_slash() {
        let url = derive_rfc8414_url("https://example.com/").unwrap();
        assert_eq!(
            url,
            "https://example.com/.well-known/oauth-authorization-server"
        );
    }

    #[test]
    fn rfc8414_url_for_path_issuer() {
        let url = derive_rfc8414_url("https://example.com/issuer1").unwrap();
        assert_eq!(
            url,
            "https://example.com/.well-known/oauth-authorization-server/issuer1"
        );
    }

    #[test]
    fn rfc8414_url_preserves_port() {
        let url = derive_rfc8414_url("https://example.com:8443/issuer1").unwrap();
        assert_eq!(
            url,
            "https://example.com:8443/.well-known/oauth-authorization-server/issuer1"
        );
    }

    #[test]
    fn rfc8414_url_preserves_ipv6_brackets() {
        let url = derive_rfc8414_url("http://[::1]:8080/issuer1").unwrap();
        assert_eq!(
            url,
            "http://[::1]:8080/.well-known/oauth-authorization-server/issuer1"
        );
    }

    #[test]
    fn oidc_url_for_root_issuer() {
        let url = derive_oidc_url("https://example.com").unwrap();
        assert_eq!(url, "https://example.com/.well-known/openid-configuration");
    }

    #[test]
    fn oidc_url_for_path_issuer() {
        let url = derive_oidc_url("https://example.com/issuer1").unwrap();
        assert_eq!(
            url,
            "https://example.com/issuer1/.well-known/openid-configuration"
        );
    }

    fn metadata_response(issuer: &str) -> HttpResponse {
        let body = serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"),
            "revocation_endpoint": format!("{issuer}/revoke"),
            "introspection_endpoint": format!("{issuer}/introspect"),
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
            "authorization_response_iss_parameter_supported": true,
        });
        HttpResponse {
            headers: vec![],
            status: 200,
            body: serde_json::to_vec(&body).unwrap(),
        }
    }

    #[tokio::test]
    async fn fetch_uses_rfc8414_url() {
        let mock = MockHttpClient::new(vec![metadata_response("https://as.example.com")]);
        let m = AuthorizationServerMetadata::fetch(&mock, "https://as.example.com")
            .await
            .unwrap();
        assert_eq!(m.issuer, "https://as.example.com");
        let req = &mock.take_requests()[0];
        assert_eq!(
            req.url,
            "https://as.example.com/.well-known/oauth-authorization-server"
        );
        assert_eq!(req.method, http::Method::GET);
    }

    #[tokio::test]
    async fn fetch_oidc_uses_oidc_url() {
        let mock = MockHttpClient::new(vec![metadata_response("https://as.example.com/r")]);
        let _ = AuthorizationServerMetadata::fetch_oidc(&mock, "https://as.example.com/r")
            .await
            .unwrap();
        let req = &mock.take_requests()[0];
        assert_eq!(
            req.url,
            "https://as.example.com/r/.well-known/openid-configuration"
        );
    }

    #[test]
    fn assert_pkce_s256_passes_when_advertised() {
        let m: AuthorizationServerMetadata = serde_json::from_value(serde_json::json!({
            "issuer": "https://as",
            "authorization_endpoint": "https://as/a",
            "token_endpoint": "https://as/t",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code"],
            "code_challenge_methods_supported": ["S256"],
        }))
        .unwrap();
        m.assert_supports_authorization_code_with_pkce_s256()
            .unwrap();
    }

    #[test]
    fn assert_pkce_s256_fails_when_only_plain() {
        let m: AuthorizationServerMetadata = serde_json::from_value(serde_json::json!({
            "issuer": "https://as",
            "authorization_endpoint": "https://as/a",
            "token_endpoint": "https://as/t",
            "response_types_supported": ["code"],
            "code_challenge_methods_supported": ["plain"],
        }))
        .unwrap();
        let err = m
            .assert_supports_authorization_code_with_pkce_s256()
            .unwrap_err();
        assert!(matches!(err, Error::UnsupportedByServer { .. }));
    }

    #[test]
    fn assert_pkce_s256_passes_when_methods_omitted() {
        // RFC 8414 makes code_challenge_methods_supported optional;
        // absence shouldn't fail the assertion.
        let m: AuthorizationServerMetadata = serde_json::from_value(serde_json::json!({
            "issuer": "https://as",
            "authorization_endpoint": "https://as/a",
            "token_endpoint": "https://as/t",
            "response_types_supported": ["code"],
        }))
        .unwrap();
        m.assert_supports_authorization_code_with_pkce_s256()
            .unwrap();
    }

    #[test]
    fn select_client_auth_public() {
        let m: AuthorizationServerMetadata = serde_json::from_value(serde_json::json!({
            "issuer": "https://as",
            "authorization_endpoint": "https://as/a",
            "token_endpoint": "https://as/t",
            "response_types_supported": ["code"],
        }))
        .unwrap();
        assert_eq!(
            m.select_client_auth_method(None).unwrap(),
            ClientAuthenticationMethod::None
        );
    }

    #[test]
    fn select_client_auth_prefers_post() {
        let m: AuthorizationServerMetadata = serde_json::from_value(serde_json::json!({
            "issuer": "https://as",
            "authorization_endpoint": "https://as/a",
            "token_endpoint": "https://as/t",
            "response_types_supported": ["code"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        }))
        .unwrap();
        assert_eq!(
            m.select_client_auth_method(Some("sec")).unwrap(),
            ClientAuthenticationMethod::ClientSecretPost
        );
    }

    #[test]
    fn select_client_auth_falls_back_to_basic() {
        let m: AuthorizationServerMetadata = serde_json::from_value(serde_json::json!({
            "issuer": "https://as",
            "authorization_endpoint": "https://as/a",
            "token_endpoint": "https://as/t",
            "response_types_supported": ["code"],
            "token_endpoint_auth_methods_supported": ["client_secret_basic"],
        }))
        .unwrap();
        assert_eq!(
            m.select_client_auth_method(Some("sec")).unwrap(),
            ClientAuthenticationMethod::ClientSecretBasic
        );
    }

    #[test]
    fn select_client_auth_defaults_to_post_when_unspecified() {
        let m: AuthorizationServerMetadata = serde_json::from_value(serde_json::json!({
            "issuer": "https://as",
            "authorization_endpoint": "https://as/a",
            "token_endpoint": "https://as/t",
            "response_types_supported": ["code"],
        }))
        .unwrap();
        assert_eq!(
            m.select_client_auth_method(Some("sec")).unwrap(),
            ClientAuthenticationMethod::ClientSecretPost
        );
    }

    #[test]
    fn issuer_policy_required_when_advertised() {
        let m: AuthorizationServerMetadata = serde_json::from_value(serde_json::json!({
            "issuer": "https://as",
            "authorization_endpoint": "https://as/a",
            "token_endpoint": "https://as/t",
            "response_types_supported": ["code"],
            "authorization_response_iss_parameter_supported": true,
        }))
        .unwrap();
        assert_eq!(m.issuer_policy(), IssuerPolicy::Required);
    }

    #[test]
    fn issuer_policy_optional_when_unset_or_false() {
        let m: AuthorizationServerMetadata = serde_json::from_value(serde_json::json!({
            "issuer": "https://as",
            "authorization_endpoint": "https://as/a",
            "token_endpoint": "https://as/t",
            "response_types_supported": ["code"],
        }))
        .unwrap();
        assert_eq!(m.issuer_policy(), IssuerPolicy::Optional);
    }

    #[tokio::test]
    async fn discover_validates_issuer_match() {
        let mock = MockHttpClient::new(vec![metadata_response("https://different.example.com")]);
        let err = OAuth21Client::discover(
            &mock,
            "https://as.example.com",
            "cid",
            None,
            RedirectUri::Exact("https://app/cb".into()),
        )
        .await
        .err()
        .unwrap();
        match err {
            Error::IssuerMismatch { expected, got } => {
                assert_eq!(expected, "https://as.example.com");
                assert_eq!(got.as_deref(), Some("https://different.example.com"));
            }
            other => panic!("expected IssuerMismatch, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn discover_falls_back_to_oidc() {
        // First fetch (8414) returns 404, second (OIDC) returns metadata.
        let mock = MockHttpClient::new(vec![
            HttpResponse {
                headers: vec![],
                status: 404,
                body: vec![],
            },
            metadata_response("https://as.example.com"),
        ]);
        let client = OAuth21Client::discover(
            &mock,
            "https://as.example.com",
            "cid",
            Some("sec".into()),
            RedirectUri::Exact("https://app/cb".into()),
        )
        .await
        .unwrap();
        assert_eq!(client.issuer(), "https://as.example.com");
        assert_eq!(client.issuer_policy(), IssuerPolicy::Required);
        assert_eq!(
            client.client_auth_method(),
            ClientAuthenticationMethod::ClientSecretPost
        );

        let requests = mock.take_requests();
        assert_eq!(
            requests[0].url,
            "https://as.example.com/.well-known/oauth-authorization-server"
        );
        assert_eq!(
            requests[1].url,
            "https://as.example.com/.well-known/openid-configuration"
        );
    }

    #[tokio::test]
    async fn discover_succeeds_via_8414() {
        let mock = MockHttpClient::new(vec![metadata_response("https://as.example.com")]);
        let client = OAuth21Client::discover(
            &mock,
            "https://as.example.com",
            "cid",
            None,
            RedirectUri::Exact("https://app/cb".into()),
        )
        .await
        .unwrap();
        assert_eq!(client.issuer(), "https://as.example.com");
        assert_eq!(
            client.client_auth_method(),
            ClientAuthenticationMethod::None
        );
    }
}
