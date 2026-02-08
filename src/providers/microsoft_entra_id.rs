use crate::error::Error;
use crate::http::HttpClient;
use crate::pkce::{CodeChallengeMethod, create_code_challenge};
use crate::request::{create_oauth2_request, encode_basic_credentials, send_token_request};
use crate::tokens::OAuth2Tokens;

pub struct MicrosoftEntraId {
    client_id: String,
    client_secret: Option<String>,
    redirect_uri: String,
    authorization_endpoint: String,
    token_endpoint: String,
}

impl MicrosoftEntraId {
    pub fn new(
        tenant: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: Option<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        let tenant = tenant.into();
        Self {
            client_id: client_id.into(),
            client_secret,
            redirect_uri: redirect_uri.into(),
            authorization_endpoint: format!(
                "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize"
            ),
            token_endpoint: format!(
                "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
            ),
        }
    }
}

#[cfg(any(test, feature = "testing"))]
impl MicrosoftEntraId {
    pub fn with_endpoints(
        client_id: impl Into<String>,
        client_secret: Option<String>,
        redirect_uri: impl Into<String>,
        authorization_endpoint: &str,
        token_endpoint: &str,
    ) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret,
            redirect_uri: redirect_uri.into(),
            authorization_endpoint: authorization_endpoint.to_string(),
            token_endpoint: token_endpoint.to_string(),
        }
    }
}

impl MicrosoftEntraId {
    pub fn name(&self) -> &'static str {
        "Microsoft Entra ID"
    }

    pub fn authorization_url(
        &self,
        state: &str,
        scopes: &[&str],
        code_verifier: &str,
    ) -> url::Url {
        let code_challenge = create_code_challenge(code_verifier, CodeChallengeMethod::S256);

        let mut url = url::Url::parse(&self.authorization_endpoint)
            .expect("invalid authorization endpoint URL");

        {
            let mut params = url.query_pairs_mut();
            params.append_pair("response_type", "code");
            params.append_pair("client_id", &self.client_id);
            params.append_pair("state", state);
            params.append_pair("redirect_uri", &self.redirect_uri);
            params.append_pair("code_challenge", &code_challenge);
            params.append_pair("code_challenge_method", "S256");

            if !scopes.is_empty() {
                params.append_pair("scope", &scopes.join(" "));
            }
        }

        url
    }

    pub async fn validate_authorization_code(
        &self,
        http_client: &(impl HttpClient + ?Sized),
        code: &str,
        code_verifier: &str,
    ) -> Result<OAuth2Tokens, Error> {
        let mut body = vec![
            ("grant_type".to_string(), "authorization_code".to_string()),
            ("code".to_string(), code.to_string()),
            ("redirect_uri".to_string(), self.redirect_uri.clone()),
            ("code_verifier".to_string(), code_verifier.to_string()),
        ];

        let request = match &self.client_secret {
            Some(secret) => {
                let mut request = create_oauth2_request(&self.token_endpoint, &body);
                request.headers.push((
                    "Authorization".to_string(),
                    encode_basic_credentials(&self.client_id, secret),
                ));
                request
            }
            None => {
                body.push(("client_id".to_string(), self.client_id.clone()));
                let mut request = create_oauth2_request(&self.token_endpoint, &body);
                request
                    .headers
                    .push(("Origin".to_string(), "arctic".to_string()));
                request
            }
        };

        send_token_request(http_client, request).await
    }

    pub async fn refresh_access_token(
        &self,
        http_client: &(impl HttpClient + ?Sized),
        refresh_token: &str,
        scopes: &[&str],
    ) -> Result<OAuth2Tokens, Error> {
        let mut body = vec![
            ("grant_type".to_string(), "refresh_token".to_string()),
            ("refresh_token".to_string(), refresh_token.to_string()),
        ];

        if !scopes.is_empty() {
            body.push(("scope".to_string(), scopes.join(" ")));
        }

        let request = match &self.client_secret {
            Some(secret) => {
                let mut request = create_oauth2_request(&self.token_endpoint, &body);
                request.headers.push((
                    "Authorization".to_string(),
                    encode_basic_credentials(&self.client_id, secret),
                ));
                request
            }
            None => {
                body.push(("client_id".to_string(), self.client_id.clone()));
                let mut request = create_oauth2_request(&self.token_endpoint, &body);
                request
                    .headers
                    .push(("Origin".to_string(), "arctic".to_string()));
                request
            }
        };

        send_token_request(http_client, request).await
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

    fn success_response() -> HttpResponse {
        HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "test-token",
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "test-refresh"
            }))
            .unwrap(),
        }
    }

    #[test]
    fn new_builds_dynamic_endpoints_from_tenant() {
        let provider = MicrosoftEntraId::new("my-tenant", "cid", Some("secret".into()), "https://app/cb");
        assert_eq!(
            provider.authorization_endpoint,
            "https://login.microsoftonline.com/my-tenant/oauth2/v2.0/authorize"
        );
        assert_eq!(
            provider.token_endpoint,
            "https://login.microsoftonline.com/my-tenant/oauth2/v2.0/token"
        );
    }

    #[test]
    fn name_returns_microsoft_entra_id() {
        let provider = MicrosoftEntraId::new("tenant", "cid", None, "https://app/cb");
        assert_eq!(provider.name(), "Microsoft Entra ID");
    }

    #[test]
    fn authorization_url_includes_pkce_s256() {
        let provider = MicrosoftEntraId::new("tenant", "cid", None, "https://app/cb");
        let url = provider.authorization_url("state123", &["openid", "profile"], "test-verifier");

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.contains(&("client_id".into(), "cid".into())));
        assert!(pairs.contains(&("state".into(), "state123".into())));
        assert!(pairs.contains(&("redirect_uri".into(), "https://app/cb".into())));
        assert!(pairs.contains(&("code_challenge_method".into(), "S256".into())));
        assert!(pairs.contains(&("scope".into(), "openid profile".into())));

        // Verify code_challenge is present and is a valid S256 challenge
        let challenge = pairs.iter().find(|(k, _)| k == "code_challenge").unwrap();
        let expected = create_code_challenge("test-verifier", CodeChallengeMethod::S256);
        assert_eq!(challenge.1, expected);
    }

    #[test]
    fn authorization_url_omits_scope_when_empty() {
        let provider = MicrosoftEntraId::new("tenant", "cid", None, "https://app/cb");
        let url = provider.authorization_url("state123", &[], "test-verifier");

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(!pairs.iter().any(|(k, _)| k == "scope"));
    }

    #[tokio::test]
    async fn validate_code_confidential_uses_basic_auth() {
        let provider = MicrosoftEntraId::with_endpoints(
            "cid",
            Some("secret".into()),
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
        );
        let mock = MockHttpClient::new(vec![success_response()]);

        let tokens = provider
            .validate_authorization_code(&mock, "auth-code", "verifier")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "test-token");

        let requests = mock.take_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url, "https://mock/token");

        // Confidential: should have Basic Auth header
        let auth = get_header(&requests[0], "Authorization").unwrap();
        assert!(auth.starts_with("Basic "));
        assert_eq!(auth, &encode_basic_credentials("cid", "secret"));

        // Confidential: should NOT have Origin header
        assert!(get_header(&requests[0], "Origin").is_none());

        // Should NOT have client_id in body
        let body = parse_form_body(&requests[0]);
        assert!(!body.iter().any(|(k, _)| k == "client_id"));
        assert!(body.contains(&("grant_type".into(), "authorization_code".into())));
        assert!(body.contains(&("code".into(), "auth-code".into())));
        assert!(body.contains(&("redirect_uri".into(), "https://app/cb".into())));
        assert!(body.contains(&("code_verifier".into(), "verifier".into())));
    }

    #[tokio::test]
    async fn validate_code_public_uses_body_and_origin() {
        let provider = MicrosoftEntraId::with_endpoints(
            "cid",
            None,
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
        );
        let mock = MockHttpClient::new(vec![success_response()]);

        let tokens = provider
            .validate_authorization_code(&mock, "auth-code", "verifier")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "test-token");

        let requests = mock.take_requests();
        assert_eq!(requests.len(), 1);

        // Public: should NOT have Basic Auth header
        assert!(get_header(&requests[0], "Authorization").is_none());

        // Public: should have Origin header
        assert_eq!(get_header(&requests[0], "Origin").unwrap(), "arctic");

        // Public: should have client_id in body
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("client_id".into(), "cid".into())));
        assert!(body.contains(&("grant_type".into(), "authorization_code".into())));
        assert!(body.contains(&("code".into(), "auth-code".into())));
        assert!(body.contains(&("code_verifier".into(), "verifier".into())));
    }

    #[tokio::test]
    async fn refresh_confidential_uses_basic_auth() {
        let provider = MicrosoftEntraId::with_endpoints(
            "cid",
            Some("secret".into()),
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
        );
        let mock = MockHttpClient::new(vec![success_response()]);

        provider
            .refresh_access_token(&mock, "rt-123", &["openid"])
            .await
            .unwrap();

        let requests = mock.take_requests();
        assert_eq!(requests.len(), 1);

        // Confidential: Basic Auth
        let auth = get_header(&requests[0], "Authorization").unwrap();
        assert_eq!(auth, &encode_basic_credentials("cid", "secret"));

        // No Origin header
        assert!(get_header(&requests[0], "Origin").is_none());

        let body = parse_form_body(&requests[0]);
        assert!(!body.iter().any(|(k, _)| k == "client_id"));
        assert!(body.contains(&("grant_type".into(), "refresh_token".into())));
        assert!(body.contains(&("refresh_token".into(), "rt-123".into())));
        assert!(body.contains(&("scope".into(), "openid".into())));
    }

    #[tokio::test]
    async fn refresh_public_uses_body_and_origin() {
        let provider = MicrosoftEntraId::with_endpoints(
            "cid",
            None,
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
        );
        let mock = MockHttpClient::new(vec![success_response()]);

        provider
            .refresh_access_token(&mock, "rt-123", &["openid", "profile"])
            .await
            .unwrap();

        let requests = mock.take_requests();
        assert_eq!(requests.len(), 1);

        // Public: no Basic Auth
        assert!(get_header(&requests[0], "Authorization").is_none());

        // Public: Origin header
        assert_eq!(get_header(&requests[0], "Origin").unwrap(), "arctic");

        // Public: client_id in body
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("client_id".into(), "cid".into())));
        assert!(body.contains(&("grant_type".into(), "refresh_token".into())));
        assert!(body.contains(&("refresh_token".into(), "rt-123".into())));
        assert!(body.contains(&("scope".into(), "openid profile".into())));
    }

    #[tokio::test]
    async fn refresh_omits_scope_when_empty() {
        let provider = MicrosoftEntraId::with_endpoints(
            "cid",
            Some("secret".into()),
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
        );
        let mock = MockHttpClient::new(vec![success_response()]);

        provider
            .refresh_access_token(&mock, "rt-123", &[])
            .await
            .unwrap();

        let requests = mock.take_requests();
        let body = parse_form_body(&requests[0]);
        assert!(!body.iter().any(|(k, _)| k == "scope"));
    }

    #[test]
    fn with_endpoints_overrides_urls() {
        let provider = MicrosoftEntraId::with_endpoints(
            "cid",
            None,
            "https://app/cb",
            "https://custom/authorize",
            "https://custom/token",
        );
        assert_eq!(provider.authorization_endpoint, "https://custom/authorize");
        assert_eq!(provider.token_endpoint, "https://custom/token");
    }
}
