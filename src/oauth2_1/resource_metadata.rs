use serde::Deserialize;
use url::{Host, Url};

use crate::error::Error;
use crate::http::{HttpClient, HttpRequest, HttpResponse};

/// Subset of RFC 9728 OAuth 2.0 Protected Resource Metadata.
#[derive(Debug, Clone, Deserialize)]
pub struct ProtectedResourceMetadata {
    pub resource: String,
    /// Issuer identifiers of authorization servers that may issue tokens for
    /// this resource. Use the first entry as input to
    /// [`OAuth21Client::discover`](crate::OAuth21Client::discover).
    #[serde(default)]
    pub authorization_servers: Vec<String>,
    pub jwks_uri: Option<String>,
    pub scopes_supported: Option<Vec<String>>,
    pub bearer_methods_supported: Option<Vec<String>>,
    pub resource_documentation: Option<String>,
    pub resource_policy_uri: Option<String>,
    pub resource_tos_uri: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl ProtectedResourceMetadata {
    /// Fetch metadata from a specific URL (e.g. one obtained from a
    /// `WWW-Authenticate` challenge).
    pub async fn fetch(http: &impl HttpClient, metadata_url: &str) -> Result<Self, Error> {
        let req = HttpRequest {
            url: metadata_url.to_string(),
            headers: vec![
                ("Accept".into(), "application/json".into()),
                ("User-Agent".into(), "arctic-oauth".into()),
            ],
            body: Vec::new(),
            method: http::Method::GET,
        };
        let response: HttpResponse = http.send(req).await?;
        match response.status {
            200 => serde_json::from_slice::<Self>(&response.body).map_err(|_| {
                Error::UnexpectedErrorBody {
                    status: 200,
                    body: String::from_utf8_lossy(&response.body).into_owned(),
                }
            }),
            status => Err(Error::UnexpectedResponse { status }),
        }
    }

    /// Fetch metadata using the well-known URL derived from `resource_url`
    /// per RFC 9728 §3.1.
    pub async fn fetch_from_resource(
        http: &impl HttpClient,
        resource_url: &str,
    ) -> Result<Self, Error> {
        let url = derive_well_known_url(resource_url)?;
        Self::fetch(http, &url).await
    }

    /// RFC 9728 §5.1. GET the resource URL; on a 401 with a Bearer challenge
    /// containing `resource_metadata="<url>"`, return that URL.
    /// Returns `Ok(None)` if the server didn't 401 or the challenge has no
    /// `resource_metadata` parameter.
    pub async fn probe(
        http: &impl HttpClient,
        resource_url: &str,
    ) -> Result<Option<String>, Error> {
        let req = HttpRequest {
            url: resource_url.to_string(),
            headers: vec![("User-Agent".into(), "arctic-oauth".into())],
            body: Vec::new(),
            method: http::Method::GET,
        };
        let response: HttpResponse = http.send(req).await?;
        if response.status != 401 {
            return Ok(None);
        }
        Ok(response
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("WWW-Authenticate"))
            .find_map(|(_, value)| parse_challenge_resource_metadata(value)))
    }

    /// Full discovery: probe (RFC 9728 §5.1), fall back to the well-known
    /// URL (RFC 9728 §3.1).
    pub async fn discover(http: &impl HttpClient, resource_url: &str) -> Result<Self, Error> {
        if let Some(url) = Self::probe(http, resource_url).await? {
            return Self::fetch(http, &url).await;
        }
        Self::fetch_from_resource(http, resource_url).await
    }
}

/// RFC 9728 §3.1: insert `/.well-known/oauth-protected-resource` after the
/// host and before the resource's path.
pub fn derive_well_known_url(resource_url: &str) -> Result<String, Error> {
    let parsed = Url::parse(resource_url).map_err(|_| Error::InvalidConfiguration {
        reason: "resource URL is not a valid URL",
    })?;
    let scheme = parsed.scheme();
    let host = parsed.host().ok_or(Error::InvalidConfiguration {
        reason: "resource URL has no host",
    })?;
    let host = match host {
        Host::Ipv6(addr) => format!("[{addr}]"),
        _ => parsed.host_str().unwrap().to_string(),
    };
    let port = parsed.port().map(|p| format!(":{p}")).unwrap_or_default();
    let path = parsed.path().trim_end_matches('/');
    if path.is_empty() {
        Ok(format!(
            "{scheme}://{host}{port}/.well-known/oauth-protected-resource"
        ))
    } else {
        Ok(format!(
            "{scheme}://{host}{port}/.well-known/oauth-protected-resource{path}"
        ))
    }
}

/// Parse the `resource_metadata="<url>"` parameter out of a
/// `WWW-Authenticate` challenge value. Tolerates quoted and unquoted forms
/// and multiple challenges in one header.
pub fn parse_challenge_resource_metadata(header_value: &str) -> Option<String> {
    let key = "resource_metadata";
    let idx = header_value.find(key)?;
    let after = header_value[idx + key.len()..].trim_start();
    let rest = after.strip_prefix('=')?.trim_start();
    if let Some(stripped) = rest.strip_prefix('"') {
        let end = stripped.find('"')?;
        return Some(stripped[..end].to_owned());
    }
    let end = rest
        .find(|c: char| c == ',' || c.is_whitespace())
        .unwrap_or(rest.len());
    Some(rest[..end].to_owned())
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
    fn well_known_url_for_root_resource() {
        let u = derive_well_known_url("https://api.example.com/").unwrap();
        assert_eq!(
            u,
            "https://api.example.com/.well-known/oauth-protected-resource"
        );
    }

    #[test]
    fn well_known_url_for_path_resource() {
        let u = derive_well_known_url("https://api.example.com/v1/foo").unwrap();
        assert_eq!(
            u,
            "https://api.example.com/.well-known/oauth-protected-resource/v1/foo"
        );
    }

    #[test]
    fn well_known_url_preserves_port() {
        let u = derive_well_known_url("https://api.example.com:8443/v1").unwrap();
        assert_eq!(
            u,
            "https://api.example.com:8443/.well-known/oauth-protected-resource/v1"
        );
    }

    #[test]
    fn well_known_url_preserves_ipv6_brackets() {
        let u = derive_well_known_url("http://[::1]:3000/mcp").unwrap();
        assert_eq!(
            u,
            "http://[::1]:3000/.well-known/oauth-protected-resource/mcp"
        );
    }

    #[test]
    fn parse_quoted_resource_metadata() {
        let h = r#"Bearer realm="api", resource_metadata="https://api/.well-known/oauth-protected-resource""#;
        assert_eq!(
            parse_challenge_resource_metadata(h).as_deref(),
            Some("https://api/.well-known/oauth-protected-resource")
        );
    }

    #[test]
    fn parse_unquoted_resource_metadata() {
        let h = "Bearer resource_metadata=https://api/meta, realm=api";
        assert_eq!(
            parse_challenge_resource_metadata(h).as_deref(),
            Some("https://api/meta")
        );
    }

    #[test]
    fn parse_missing_resource_metadata_is_none() {
        assert!(parse_challenge_resource_metadata("Bearer realm=api").is_none());
    }

    fn metadata_response() -> HttpResponse {
        let body = serde_json::json!({
            "resource": "https://api.example.com/v1",
            "authorization_servers": ["https://as.example.com"],
            "scopes_supported": ["read", "write"],
            "bearer_methods_supported": ["header"],
        });
        HttpResponse {
            headers: vec![],
            status: 200,
            body: serde_json::to_vec(&body).unwrap(),
        }
    }

    #[tokio::test]
    async fn fetch_from_resource_uses_well_known_url() {
        let mock = MockHttpClient::new(vec![metadata_response()]);
        let m = ProtectedResourceMetadata::fetch_from_resource(&mock, "https://api.example.com/v1")
            .await
            .unwrap();
        assert_eq!(m.authorization_servers, vec!["https://as.example.com"]);
        let req = &mock.take_requests()[0];
        assert_eq!(
            req.url,
            "https://api.example.com/.well-known/oauth-protected-resource/v1"
        );
        assert_eq!(req.method, http::Method::GET);
    }

    #[tokio::test]
    async fn fetch_uses_explicit_url() {
        let mock = MockHttpClient::new(vec![metadata_response()]);
        let _ = ProtectedResourceMetadata::fetch(&mock, "https://example.com/custom/metadata")
            .await
            .unwrap();
        let req = &mock.take_requests()[0];
        assert_eq!(req.url, "https://example.com/custom/metadata");
    }

    #[tokio::test]
    async fn fetch_returns_unexpected_response_on_404() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            headers: vec![],
            status: 404,
            body: vec![],
        }]);
        let err = ProtectedResourceMetadata::fetch(&mock, "https://example.com/m")
            .await
            .unwrap_err();
        assert!(matches!(err, Error::UnexpectedResponse { status: 404 }));
    }

    fn challenge_401(metadata_url: &str) -> HttpResponse {
        HttpResponse {
            status: 401,
            headers: vec![(
                "WWW-Authenticate".into(),
                format!(
                    "Bearer realm=\"OAuth\", resource_metadata=\"{metadata_url}\", error=\"invalid_token\""
                ),
            )],
            body: Vec::new(),
        }
    }

    #[tokio::test]
    async fn probe_extracts_metadata_url_from_challenge() {
        let mock = MockHttpClient::new(vec![challenge_401(
            "https://api.example.com/.well-known/oauth-protected-resource",
        )]);
        let url = ProtectedResourceMetadata::probe(&mock, "https://api.example.com/mcp")
            .await
            .unwrap();
        assert_eq!(
            url.as_deref(),
            Some("https://api.example.com/.well-known/oauth-protected-resource")
        );
        let req = &mock.take_requests()[0];
        assert_eq!(req.url, "https://api.example.com/mcp");
        assert_eq!(req.method, http::Method::GET);
    }

    #[tokio::test]
    async fn probe_checks_all_www_authenticate_headers() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 401,
            headers: vec![
                ("WWW-Authenticate".into(), "Basic realm=\"api\"".into()),
                (
                    "WWW-Authenticate".into(),
                    "Bearer resource_metadata=\"https://api.example.com/meta\"".into(),
                ),
            ],
            body: Vec::new(),
        }]);
        let url = ProtectedResourceMetadata::probe(&mock, "https://api.example.com/mcp")
            .await
            .unwrap();
        assert_eq!(url.as_deref(), Some("https://api.example.com/meta"));
    }

    #[tokio::test]
    async fn probe_returns_none_when_not_401() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            headers: vec![],
            body: vec![],
        }]);
        let url = ProtectedResourceMetadata::probe(&mock, "https://api.example.com/")
            .await
            .unwrap();
        assert!(url.is_none());
    }

    #[tokio::test]
    async fn probe_returns_none_when_401_has_no_resource_metadata() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 401,
            headers: vec![("WWW-Authenticate".into(), "Bearer realm=api".into())],
            body: vec![],
        }]);
        let url = ProtectedResourceMetadata::probe(&mock, "https://api.example.com/")
            .await
            .unwrap();
        assert!(url.is_none());
    }

    #[tokio::test]
    async fn discover_uses_probe_when_challenge_present() {
        let mock = MockHttpClient::new(vec![
            challenge_401("https://api.example.com/custom/metadata"),
            metadata_response(),
        ]);
        let m = ProtectedResourceMetadata::discover(&mock, "https://api.example.com/mcp")
            .await
            .unwrap();
        assert_eq!(m.authorization_servers, vec!["https://as.example.com"]);
        let requests = mock.take_requests();
        assert_eq!(requests[0].url, "https://api.example.com/mcp");
        assert_eq!(requests[1].url, "https://api.example.com/custom/metadata");
    }

    #[tokio::test]
    async fn discover_falls_back_to_well_known_when_no_challenge() {
        let mock = MockHttpClient::new(vec![
            HttpResponse {
                status: 200,
                headers: vec![],
                body: vec![],
            },
            metadata_response(),
        ]);
        let m = ProtectedResourceMetadata::discover(&mock, "https://api.example.com/v1")
            .await
            .unwrap();
        assert_eq!(m.authorization_servers, vec!["https://as.example.com"]);
        let requests = mock.take_requests();
        assert_eq!(requests[0].url, "https://api.example.com/v1");
        assert_eq!(
            requests[1].url,
            "https://api.example.com/.well-known/oauth-protected-resource/v1"
        );
    }
}
