use base64::Engine;

use crate::error::Error;
use crate::http::{HttpClient, HttpRequest};
use crate::request::{create_oauth2_request, send_token_request};
use crate::tokens::OAuth2Tokens;

use super::client::{ClientAuthenticationMethod, OAuth21Client};
use super::resource::Resource;

/// Inputs for the `authorization_code` grant.
pub struct AuthorizationCodeGrant<'a> {
    pub code: &'a str,
    pub code_verifier: &'a str,
    /// RFC 8707 resource indicator(s). When non-empty, the same value(s) used
    /// at the authorization endpoint should be passed here.
    pub resource: &'a [Resource],
}

/// Inputs for the `refresh_token` grant.
pub struct RefreshTokenGrant<'a> {
    pub refresh_token: &'a str,
    /// Per RFC 6749 §6, scope MUST be a subset of the originally granted
    /// scopes. Empty slice omits the parameter.
    pub scopes: &'a [&'a str],
    pub resource: &'a [Resource],
}

/// Inputs for the `client_credentials` grant. Confidential clients only.
pub struct ClientCredentialsGrant<'a> {
    pub scopes: &'a [&'a str],
    pub resource: &'a [Resource],
    pub audience: Option<&'a str>,
}

/// RFC 7662 token introspection response.
#[derive(Debug, Clone)]
pub struct TokenIntrospection {
    data: serde_json::Value,
}

impl TokenIntrospection {
    pub fn new(data: serde_json::Value) -> Self {
        Self { data }
    }

    pub fn data(&self) -> &serde_json::Value {
        &self.data
    }

    /// `active` is the only required field per RFC 7662 §2.2.
    pub fn active(&self) -> bool {
        self.data["active"].as_bool().unwrap_or(false)
    }

    pub fn scope(&self) -> Option<&str> {
        self.data["scope"].as_str()
    }

    pub fn client_id(&self) -> Option<&str> {
        self.data["client_id"].as_str()
    }

    pub fn username(&self) -> Option<&str> {
        self.data["username"].as_str()
    }

    pub fn token_type(&self) -> Option<&str> {
        self.data["token_type"].as_str()
    }

    pub fn exp(&self) -> Option<u64> {
        self.data["exp"].as_u64()
    }

    pub fn iat(&self) -> Option<u64> {
        self.data["iat"].as_u64()
    }

    pub fn sub(&self) -> Option<&str> {
        self.data["sub"].as_str()
    }

    pub fn aud(&self) -> Option<&str> {
        self.data["aud"].as_str()
    }

    pub fn iss(&self) -> Option<&str> {
        self.data["iss"].as_str()
    }
}

/// Encode credentials per RFC 6749 §2.3.1: each component is first
/// form-urlencoded, then joined with `:`, then base64-encoded.
pub(super) fn encode_basic_credentials_form_encoded(
    client_id: &str,
    client_secret: &str,
) -> String {
    let id = url::form_urlencoded::byte_serialize(client_id.as_bytes()).collect::<String>();
    let secret = url::form_urlencoded::byte_serialize(client_secret.as_bytes()).collect::<String>();
    let joined = format!("{id}:{secret}");
    let encoded = base64::engine::general_purpose::STANDARD.encode(joined.as_bytes());
    format!("Basic {encoded}")
}

fn apply_client_auth<H: HttpClient>(
    client: &OAuth21Client<'_, H>,
    body: &mut Vec<(String, String)>,
    headers: &mut Vec<(String, String)>,
) {
    match client.client_auth_method {
        ClientAuthenticationMethod::None => {
            body.push(("client_id".into(), client.client_id.clone()));
        }
        ClientAuthenticationMethod::ClientSecretPost => {
            body.push(("client_id".into(), client.client_id.clone()));
            if let Some(secret) = &client.client_secret {
                body.push(("client_secret".into(), secret.clone()));
            }
        }
        ClientAuthenticationMethod::ClientSecretBasic => {
            if let Some(secret) = &client.client_secret {
                headers.push((
                    "Authorization".into(),
                    encode_basic_credentials_form_encoded(&client.client_id, secret),
                ));
            }
        }
    }
}

fn build_request<H: HttpClient>(
    client: &OAuth21Client<'_, H>,
    endpoint: &str,
    mut body: Vec<(String, String)>,
) -> HttpRequest {
    let mut extra_headers: Vec<(String, String)> = Vec::new();
    apply_client_auth(client, &mut body, &mut extra_headers);

    let mut request = create_oauth2_request(endpoint, &body);
    request.headers.extend(extra_headers);
    request
}

pub(super) async fn send_authorization_code_grant<H: HttpClient>(
    client: &OAuth21Client<'_, H>,
    params: AuthorizationCodeGrant<'_>,
) -> Result<OAuth2Tokens, Error> {
    let mut body: Vec<(String, String)> = vec![
        ("grant_type".into(), "authorization_code".into()),
        ("code".into(), params.code.into()),
        ("code_verifier".into(), params.code_verifier.into()),
        ("redirect_uri".into(), client.redirect_uri.to_uri_string()),
    ];
    for r in params.resource {
        body.push(("resource".into(), r.as_str().into()));
    }

    let request = build_request(client, &client.token_endpoint, body);
    send_token_request(client.http_client, request).await
}

pub(super) async fn send_refresh_token_grant<H: HttpClient>(
    client: &OAuth21Client<'_, H>,
    params: RefreshTokenGrant<'_>,
) -> Result<OAuth2Tokens, Error> {
    let mut body: Vec<(String, String)> = vec![
        ("grant_type".into(), "refresh_token".into()),
        ("refresh_token".into(), params.refresh_token.into()),
    ];
    if !params.scopes.is_empty() {
        body.push(("scope".into(), params.scopes.join(" ")));
    }
    for r in params.resource {
        body.push(("resource".into(), r.as_str().into()));
    }

    let request = build_request(client, &client.token_endpoint, body);
    send_token_request(client.http_client, request).await
}

pub(super) async fn send_client_credentials_grant<H: HttpClient>(
    client: &OAuth21Client<'_, H>,
    params: ClientCredentialsGrant<'_>,
) -> Result<OAuth2Tokens, Error> {
    if client.client_secret.is_none() {
        return Err(Error::PublicClientNotAllowed);
    }

    let mut body: Vec<(String, String)> = vec![("grant_type".into(), "client_credentials".into())];
    if !params.scopes.is_empty() {
        body.push(("scope".into(), params.scopes.join(" ")));
    }
    for r in params.resource {
        body.push(("resource".into(), r.as_str().into()));
    }
    if let Some(audience) = params.audience {
        body.push(("audience".into(), audience.into()));
    }

    let request = build_request(client, &client.token_endpoint, body);
    send_token_request(client.http_client, request).await
}

pub(super) async fn revoke_token<H: HttpClient>(
    client: &OAuth21Client<'_, H>,
    token: &str,
) -> Result<(), Error> {
    let endpoint = client
        .revocation_endpoint
        .as_deref()
        .ok_or(Error::UnsupportedByServer {
            capability: "revocation",
        })?;

    let body: Vec<(String, String)> = vec![("token".into(), token.into())];
    let request = build_request(client, endpoint, body);

    let response = client.http_client.send(request).await?;
    match response.status {
        // RFC 7009: invalid tokens MAY return 200; other 2xx allowed.
        200..=204 => Ok(()),
        status => Err(Error::UnexpectedResponse { status }),
    }
}

pub(super) async fn introspect<H: HttpClient>(
    client: &OAuth21Client<'_, H>,
    token: &str,
) -> Result<TokenIntrospection, Error> {
    let endpoint = client
        .introspection_endpoint
        .as_deref()
        .ok_or(Error::UnsupportedByServer {
            capability: "introspection",
        })?;

    let body: Vec<(String, String)> = vec![("token".into(), token.into())];
    let request = build_request(client, endpoint, body);

    let response = client.http_client.send(request).await?;
    match response.status {
        200 => {
            let json: serde_json::Value =
                serde_json::from_slice(&response.body).map_err(|_| Error::UnexpectedErrorBody {
                    status: 200,
                    body: String::from_utf8_lossy(&response.body).into_owned(),
                })?;
            Ok(TokenIntrospection::new(json))
        }
        status => Err(Error::UnexpectedResponse { status }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{HttpRequest, HttpResponse};
    use crate::oauth2_1::client::{
        ClientAuthenticationMethod, IssuerPolicy, OAuth21Options, RedirectUri,
    };
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

    fn parse_form_body(request: &HttpRequest) -> Vec<(String, String)> {
        url::form_urlencoded::parse(&request.body)
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect()
    }

    fn header<'a>(request: &'a HttpRequest, name: &str) -> Option<&'a str> {
        request
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn token_response() -> HttpResponse {
        HttpResponse {
            headers: vec![],
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }
    }

    fn make_client<'a>(
        http: &'a MockHttpClient,
        client_secret: Option<String>,
        method: ClientAuthenticationMethod,
    ) -> OAuth21Client<'a, MockHttpClient> {
        OAuth21Client::from_options(OAuth21Options {
            issuer: "https://as.example.com".into(),
            authorization_endpoint: "https://as.example.com/authorize".into(),
            token_endpoint: "https://as.example.com/token".into(),
            revocation_endpoint: Some("https://as.example.com/revoke".into()),
            introspection_endpoint: Some("https://as.example.com/introspect".into()),
            client_id: "cid".into(),
            client_secret,
            client_auth_method: method,
            issuer_policy: IssuerPolicy::Optional,
            redirect_uri: RedirectUri::Exact("https://app/cb".into()),
            http_client: http,
        })
        .unwrap()
    }

    #[tokio::test]
    async fn auth_code_public_client_sends_client_id_in_body() {
        let mock = MockHttpClient::new(vec![token_response()]);
        let client = make_client(&mock, None, ClientAuthenticationMethod::None);

        client
            .validate_authorization_code(AuthorizationCodeGrant {
                code: "c",
                code_verifier: "v",
                resource: &[],
            })
            .await
            .unwrap();

        let req = &mock.take_requests()[0];
        assert!(header(req, "Authorization").is_none());
        let body = parse_form_body(req);
        assert!(body.contains(&("client_id".into(), "cid".into())));
        assert!(body.contains(&("grant_type".into(), "authorization_code".into())));
        assert!(body.contains(&("code".into(), "c".into())));
        assert!(body.contains(&("code_verifier".into(), "v".into())));
        assert!(body.contains(&("redirect_uri".into(), "https://app/cb".into())));
    }

    #[tokio::test]
    async fn auth_code_secret_post_sends_secret_in_body() {
        let mock = MockHttpClient::new(vec![token_response()]);
        let client = make_client(
            &mock,
            Some("sec".into()),
            ClientAuthenticationMethod::ClientSecretPost,
        );

        client
            .validate_authorization_code(AuthorizationCodeGrant {
                code: "c",
                code_verifier: "v",
                resource: &[],
            })
            .await
            .unwrap();

        let req = &mock.take_requests()[0];
        assert!(header(req, "Authorization").is_none());
        let body = parse_form_body(req);
        assert!(body.contains(&("client_id".into(), "cid".into())));
        assert!(body.contains(&("client_secret".into(), "sec".into())));
    }

    #[tokio::test]
    async fn auth_code_basic_uses_form_encoded_basic_header() {
        let mock = MockHttpClient::new(vec![token_response()]);
        let client = make_client(
            &mock,
            Some("se cret".into()),
            ClientAuthenticationMethod::ClientSecretBasic,
        );

        client
            .validate_authorization_code(AuthorizationCodeGrant {
                code: "c",
                code_verifier: "v",
                resource: &[],
            })
            .await
            .unwrap();

        let req = &mock.take_requests()[0];
        let h = header(req, "Authorization").unwrap();
        // form-urlencode each piece, join with ":", base64
        let expected = encode_basic_credentials_form_encoded("cid", "se cret");
        assert_eq!(h, expected);
        let body = parse_form_body(req);
        assert!(!body.iter().any(|(k, _)| k == "client_id"));
        assert!(!body.iter().any(|(k, _)| k == "client_secret"));
    }

    #[test]
    fn basic_credentials_form_encoded_encodes_special_chars() {
        let header = encode_basic_credentials_form_encoded("a:b", "p w");
        // each piece is form-urlencoded: "a%3Ab" and "p+w"
        let inner = "a%3Ab:p+w";
        let expected = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(inner.as_bytes())
        );
        assert_eq!(header, expected);
    }

    #[tokio::test]
    async fn auth_code_includes_repeated_resource_params() {
        let mock = MockHttpClient::new(vec![token_response()]);
        let client = make_client(&mock, None, ClientAuthenticationMethod::None);
        let r1 = Resource::parse("https://api1.example.com").unwrap();
        let r2 = Resource::parse("https://api2.example.com").unwrap();

        client
            .validate_authorization_code(AuthorizationCodeGrant {
                code: "c",
                code_verifier: "v",
                resource: &[r1, r2],
            })
            .await
            .unwrap();

        let req = &mock.take_requests()[0];
        let body = parse_form_body(req);
        let resources: Vec<&String> = body
            .iter()
            .filter(|(k, _)| k == "resource")
            .map(|(_, v)| v)
            .collect();
        assert_eq!(resources.len(), 2);
        assert_eq!(resources[0], "https://api1.example.com/");
        assert_eq!(resources[1], "https://api2.example.com/");
    }

    #[tokio::test]
    async fn refresh_token_grant_includes_optional_scope_and_resource() {
        let mock = MockHttpClient::new(vec![token_response()]);
        let client = make_client(
            &mock,
            Some("sec".into()),
            ClientAuthenticationMethod::ClientSecretPost,
        );
        let r = Resource::parse("https://api.example.com").unwrap();

        client
            .refresh_access_token(RefreshTokenGrant {
                refresh_token: "rt",
                scopes: &["read", "write"],
                resource: &[r],
            })
            .await
            .unwrap();

        let req = &mock.take_requests()[0];
        let body = parse_form_body(req);
        assert!(body.contains(&("grant_type".into(), "refresh_token".into())));
        assert!(body.contains(&("refresh_token".into(), "rt".into())));
        assert!(body.contains(&("scope".into(), "read write".into())));
        assert!(body.contains(&("resource".into(), "https://api.example.com/".into())));
    }

    #[tokio::test]
    async fn refresh_token_omits_scope_when_empty() {
        let mock = MockHttpClient::new(vec![token_response()]);
        let client = make_client(
            &mock,
            Some("sec".into()),
            ClientAuthenticationMethod::ClientSecretPost,
        );

        client
            .refresh_access_token(RefreshTokenGrant {
                refresh_token: "rt",
                scopes: &[],
                resource: &[],
            })
            .await
            .unwrap();

        let req = &mock.take_requests()[0];
        let body = parse_form_body(req);
        assert!(!body.iter().any(|(k, _)| k == "scope"));
    }

    #[tokio::test]
    async fn client_credentials_rejects_public_client() {
        let mock = MockHttpClient::new(vec![]);
        let client = make_client(&mock, None, ClientAuthenticationMethod::None);

        let err = client
            .client_credentials(ClientCredentialsGrant {
                scopes: &[],
                resource: &[],
                audience: None,
            })
            .await
            .unwrap_err();
        assert!(matches!(err, Error::PublicClientNotAllowed));
    }

    #[tokio::test]
    async fn client_credentials_includes_audience_and_resource() {
        let mock = MockHttpClient::new(vec![token_response()]);
        let client = make_client(
            &mock,
            Some("sec".into()),
            ClientAuthenticationMethod::ClientSecretPost,
        );
        let r = Resource::parse("https://api.example.com").unwrap();

        client
            .client_credentials(ClientCredentialsGrant {
                scopes: &["api.read"],
                resource: &[r],
                audience: Some("https://api"),
            })
            .await
            .unwrap();

        let req = &mock.take_requests()[0];
        let body = parse_form_body(req);
        assert!(body.contains(&("grant_type".into(), "client_credentials".into())));
        assert!(body.contains(&("scope".into(), "api.read".into())));
        assert!(body.contains(&("resource".into(), "https://api.example.com/".into())));
        assert!(body.contains(&("audience".into(), "https://api".into())));
    }

    #[tokio::test]
    async fn revoke_returns_unsupported_when_no_endpoint() {
        let mock = MockHttpClient::new(vec![]);
        let client = OAuth21Client::from_options(OAuth21Options {
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
            http_client: &mock,
        })
        .unwrap();

        let err = client.revoke_token("tok").await.unwrap_err();
        assert!(matches!(
            err,
            Error::UnsupportedByServer {
                capability: "revocation"
            }
        ));
    }

    #[tokio::test]
    async fn revoke_sends_token_with_client_auth() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            headers: vec![],
            status: 200,
            body: vec![],
        }]);
        let client = make_client(
            &mock,
            Some("sec".into()),
            ClientAuthenticationMethod::ClientSecretPost,
        );

        client.revoke_token("tok").await.unwrap();

        let req = &mock.take_requests()[0];
        assert_eq!(req.url, "https://as.example.com/revoke");
        let body = parse_form_body(req);
        assert!(body.contains(&("token".into(), "tok".into())));
        assert!(body.contains(&("client_id".into(), "cid".into())));
        assert!(body.contains(&("client_secret".into(), "sec".into())));
    }

    #[tokio::test]
    async fn introspect_parses_response() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            headers: vec![],
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "active": true,
                "scope": "read write",
                "client_id": "cid",
                "exp": 1700000000_u64
            }))
            .unwrap(),
        }]);
        let client = make_client(
            &mock,
            Some("sec".into()),
            ClientAuthenticationMethod::ClientSecretPost,
        );

        let result = client.introspect("tok").await.unwrap();
        assert!(result.active());
        assert_eq!(result.scope(), Some("read write"));
        assert_eq!(result.client_id(), Some("cid"));
        assert_eq!(result.exp(), Some(1700000000));
    }

    #[tokio::test]
    async fn introspect_returns_unsupported_when_no_endpoint() {
        let mock = MockHttpClient::new(vec![]);
        let client = OAuth21Client::from_options(OAuth21Options {
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
            http_client: &mock,
        })
        .unwrap();

        let err = client.introspect("tok").await.unwrap_err();
        assert!(matches!(
            err,
            Error::UnsupportedByServer {
                capability: "introspection"
            }
        ));
    }
}
