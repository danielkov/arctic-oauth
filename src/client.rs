use url::Url;

use crate::error::Error;
use crate::http::HttpClient;
use crate::pkce::{CodeChallengeMethod, create_code_challenge};
use crate::request::{create_oauth2_request, encode_basic_credentials, send_token_request};
use crate::tokens::OAuth2Tokens;

pub struct OAuth2Client {
    client_id: String,
    /// None for public clients (credentials sent in body).
    /// Some for confidential clients (credentials sent via Basic auth).
    client_secret: Option<String>,
    redirect_uri: Option<String>,
}

impl OAuth2Client {
    pub fn new(
        client_id: impl Into<String>,
        client_secret: Option<String>,
        redirect_uri: Option<String>,
    ) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret,
            redirect_uri,
        }
    }

    /// Build an authorization URL with standard parameters:
    /// response_type=code, client_id, state, scope (space-joined), redirect_uri.
    pub fn create_authorization_url(
        &self,
        authorization_endpoint: &str,
        state: &str,
        scopes: &[&str],
    ) -> Url {
        let mut url =
            Url::parse(authorization_endpoint).expect("invalid authorization endpoint URL");

        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.client_id)
            .append_pair("state", state);

        if !scopes.is_empty() {
            url.query_pairs_mut()
                .append_pair("scope", &scopes.join(" "));
        }

        if let Some(ref redirect_uri) = self.redirect_uri {
            url.query_pairs_mut()
                .append_pair("redirect_uri", redirect_uri);
        }

        url
    }

    /// Build an authorization URL with PKCE parameters appended:
    /// code_challenge, code_challenge_method.
    pub fn create_authorization_url_with_pkce(
        &self,
        authorization_endpoint: &str,
        state: &str,
        code_challenge_method: CodeChallengeMethod,
        code_verifier: &str,
        scopes: &[&str],
    ) -> Url {
        let mut url = self.create_authorization_url(authorization_endpoint, state, scopes);

        let code_challenge = create_code_challenge(code_verifier, code_challenge_method);
        let method_str = match code_challenge_method {
            CodeChallengeMethod::S256 => "S256",
            CodeChallengeMethod::Plain => "plain",
        };

        url.query_pairs_mut()
            .append_pair("code_challenge", &code_challenge)
            .append_pair("code_challenge_method", method_str);

        url
    }

    /// Exchange an authorization code for tokens.
    pub async fn validate_authorization_code(
        &self,
        http_client: &impl HttpClient,
        token_endpoint: &str,
        code: &str,
        code_verifier: Option<&str>,
    ) -> Result<OAuth2Tokens, Error> {
        let mut body = vec![
            ("grant_type".to_string(), "authorization_code".to_string()),
            ("code".to_string(), code.to_string()),
        ];

        if let Some(verifier) = code_verifier {
            body.push(("code_verifier".to_string(), verifier.to_string()));
        }

        if let Some(ref redirect_uri) = self.redirect_uri {
            body.push(("redirect_uri".to_string(), redirect_uri.clone()));
        }

        if self.client_secret.is_none() {
            body.push(("client_id".to_string(), self.client_id.clone()));
        }

        let mut request = create_oauth2_request(token_endpoint, &body);

        if let Some(ref secret) = self.client_secret {
            request.headers.push((
                "Authorization".to_string(),
                encode_basic_credentials(&self.client_id, secret),
            ));
        }

        send_token_request(http_client, request).await
    }

    /// Refresh an access token.
    pub async fn refresh_access_token(
        &self,
        http_client: &impl HttpClient,
        token_endpoint: &str,
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

        if self.client_secret.is_none() {
            body.push(("client_id".to_string(), self.client_id.clone()));
        }

        let mut request = create_oauth2_request(token_endpoint, &body);

        if let Some(ref secret) = self.client_secret {
            request.headers.push((
                "Authorization".to_string(),
                encode_basic_credentials(&self.client_id, secret),
            ));
        }

        send_token_request(http_client, request).await
    }

    /// Revoke a token (RFC 7009).
    pub async fn revoke_token(
        &self,
        http_client: &impl HttpClient,
        revocation_endpoint: &str,
        token: &str,
    ) -> Result<(), Error> {
        let mut body = vec![("token".to_string(), token.to_string())];

        if self.client_secret.is_none() {
            body.push(("client_id".to_string(), self.client_id.clone()));
        }

        let mut request = create_oauth2_request(revocation_endpoint, &body);

        if let Some(ref secret) = self.client_secret {
            request.headers.push((
                "Authorization".to_string(),
                encode_basic_credentials(&self.client_id, secret),
            ));
        }

        let response = http_client.send(request).await?;

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

    // --- Authorization URL tests ---

    #[test]
    fn auth_url_basic_params() {
        let client = OAuth2Client::new("my-client", None, None);
        let url =
            client.create_authorization_url("https://example.com/authorize", "random-state", &[]);

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("example.com"));
        assert_eq!(url.path(), "/authorize");
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.contains(&("client_id".into(), "my-client".into())));
        assert!(pairs.contains(&("state".into(), "random-state".into())));
        assert!(!pairs.iter().any(|(k, _)| k == "scope"));
        assert!(!pairs.iter().any(|(k, _)| k == "redirect_uri"));
    }

    #[test]
    fn auth_url_with_scopes() {
        let client = OAuth2Client::new("cid", None, None);
        let url = client.create_authorization_url(
            "https://example.com/authorize",
            "st",
            &["openid", "email", "profile"],
        );

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("scope".into(), "openid email profile".into())));
    }

    #[test]
    fn auth_url_with_redirect_uri() {
        let client = OAuth2Client::new("cid", None, Some("https://app.test/callback".into()));
        let url = client.create_authorization_url("https://example.com/authorize", "st", &[]);

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("redirect_uri".into(), "https://app.test/callback".into())));
    }

    #[test]
    fn auth_url_no_redirect_uri() {
        let client = OAuth2Client::new("cid", None, None);
        let url = client.create_authorization_url("https://example.com/authorize", "st", &[]);

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(!pairs.iter().any(|(k, _)| k == "redirect_uri"));
    }

    // --- PKCE URL tests ---

    #[test]
    fn auth_url_with_pkce_s256() {
        let client = OAuth2Client::new("cid", None, None);
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let url = client.create_authorization_url_with_pkce(
            "https://example.com/authorize",
            "st",
            CodeChallengeMethod::S256,
            verifier,
            &[],
        );

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&(
            "code_challenge".into(),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".into()
        )));
        assert!(pairs.contains(&("code_challenge_method".into(), "S256".into())));
    }

    #[test]
    fn auth_url_with_pkce_plain() {
        let client = OAuth2Client::new("cid", None, None);
        let verifier = "my-plain-verifier";
        let url = client.create_authorization_url_with_pkce(
            "https://example.com/authorize",
            "st",
            CodeChallengeMethod::Plain,
            verifier,
            &[],
        );

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("code_challenge".into(), "my-plain-verifier".into())));
        assert!(pairs.contains(&("code_challenge_method".into(), "plain".into())));
    }

    #[test]
    fn auth_url_with_pkce_includes_base_params() {
        let client = OAuth2Client::new(
            "cid",
            Some("secret".into()),
            Some("https://app.test/cb".into()),
        );
        let url = client.create_authorization_url_with_pkce(
            "https://example.com/authorize",
            "st",
            CodeChallengeMethod::S256,
            "verifier",
            &["openid"],
        );

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.contains(&("client_id".into(), "cid".into())));
        assert!(pairs.contains(&("state".into(), "st".into())));
        assert!(pairs.contains(&("scope".into(), "openid".into())));
        assert!(pairs.contains(&("redirect_uri".into(), "https://app.test/cb".into())));
        assert!(pairs.iter().any(|(k, _)| k == "code_challenge"));
        assert!(pairs.iter().any(|(k, _)| k == "code_challenge_method"));
    }

    // --- Credential transmission tests ---

    #[tokio::test]
    async fn validate_code_confidential_client_uses_basic_auth() {
        let client = OAuth2Client::new("my-id", Some("my-secret".into()), None);
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);

        let _ = client
            .validate_authorization_code(&mock, "https://example.com/token", "code123", None)
            .await;

        let requests = mock.take_requests();
        assert_eq!(requests.len(), 1);

        let auth = get_header(&requests[0], "Authorization").expect("missing Authorization header");
        assert_eq!(auth, encode_basic_credentials("my-id", "my-secret"));

        let body = parse_form_body(&requests[0]);
        assert!(!body.iter().any(|(k, _)| k == "client_id"));
    }

    #[tokio::test]
    async fn validate_code_public_client_sends_client_id_in_body() {
        let client = OAuth2Client::new("pub-id", None, None);
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);

        let _ = client
            .validate_authorization_code(&mock, "https://example.com/token", "code123", None)
            .await;

        let requests = mock.take_requests();
        assert_eq!(requests.len(), 1);

        assert!(get_header(&requests[0], "Authorization").is_none());

        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("client_id".into(), "pub-id".into())));
    }

    #[tokio::test]
    async fn validate_code_includes_code_verifier() {
        let client = OAuth2Client::new("cid", Some("sec".into()), None);
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);

        let _ = client
            .validate_authorization_code(
                &mock,
                "https://example.com/token",
                "code123",
                Some("my-verifier"),
            )
            .await;

        let requests = mock.take_requests();
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("code_verifier".into(), "my-verifier".into())));
    }

    #[tokio::test]
    async fn validate_code_omits_code_verifier_when_none() {
        let client = OAuth2Client::new("cid", Some("sec".into()), None);
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);

        let _ = client
            .validate_authorization_code(&mock, "https://example.com/token", "code123", None)
            .await;

        let requests = mock.take_requests();
        let body = parse_form_body(&requests[0]);
        assert!(!body.iter().any(|(k, _)| k == "code_verifier"));
    }

    #[tokio::test]
    async fn validate_code_includes_redirect_uri() {
        let client = OAuth2Client::new("cid", Some("sec".into()), Some("https://app/cb".into()));
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);

        let _ = client
            .validate_authorization_code(&mock, "https://example.com/token", "code123", None)
            .await;

        let requests = mock.take_requests();
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("redirect_uri".into(), "https://app/cb".into())));
    }

    #[tokio::test]
    async fn validate_code_sends_correct_grant_type() {
        let client = OAuth2Client::new("cid", Some("sec".into()), None);
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);

        let _ = client
            .validate_authorization_code(&mock, "https://example.com/token", "the-code", None)
            .await;

        let requests = mock.take_requests();
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("grant_type".into(), "authorization_code".into())));
        assert!(body.contains(&("code".into(), "the-code".into())));
    }

    // --- Refresh token tests ---

    #[tokio::test]
    async fn refresh_token_sends_correct_body() {
        let client = OAuth2Client::new("cid", Some("sec".into()), None);
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "new-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);

        let _ = client
            .refresh_access_token(&mock, "https://example.com/token", "rt-123", &[])
            .await;

        let requests = mock.take_requests();
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("grant_type".into(), "refresh_token".into())));
        assert!(body.contains(&("refresh_token".into(), "rt-123".into())));
        assert!(!body.iter().any(|(k, _)| k == "scope"));
    }

    #[tokio::test]
    async fn refresh_token_includes_scopes() {
        let client = OAuth2Client::new("cid", Some("sec".into()), None);
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);

        let _ = client
            .refresh_access_token(&mock, "https://example.com/token", "rt", &["read", "write"])
            .await;

        let requests = mock.take_requests();
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("scope".into(), "read write".into())));
    }

    #[tokio::test]
    async fn refresh_token_confidential_uses_basic_auth() {
        let client = OAuth2Client::new("cid", Some("sec".into()), None);
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);

        let _ = client
            .refresh_access_token(&mock, "https://example.com/token", "rt", &[])
            .await;

        let requests = mock.take_requests();
        let auth = get_header(&requests[0], "Authorization").expect("missing Authorization");
        assert_eq!(auth, encode_basic_credentials("cid", "sec"));
    }

    #[tokio::test]
    async fn refresh_token_public_sends_client_id_in_body() {
        let client = OAuth2Client::new("pub-id", None, None);
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);

        let _ = client
            .refresh_access_token(&mock, "https://example.com/token", "rt", &[])
            .await;

        let requests = mock.take_requests();
        assert!(get_header(&requests[0], "Authorization").is_none());
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("client_id".into(), "pub-id".into())));
    }

    // --- Revoke token tests ---

    #[tokio::test]
    async fn revoke_token_sends_correct_body() {
        let client = OAuth2Client::new("cid", Some("sec".into()), None);
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: vec![],
        }]);

        let result = client
            .revoke_token(&mock, "https://example.com/revoke", "tok-to-revoke")
            .await;

        assert!(result.is_ok());

        let requests = mock.take_requests();
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("token".into(), "tok-to-revoke".into())));
    }

    #[tokio::test]
    async fn revoke_token_confidential_uses_basic_auth() {
        let client = OAuth2Client::new("cid", Some("sec".into()), None);
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: vec![],
        }]);

        let _ = client
            .revoke_token(&mock, "https://example.com/revoke", "tok")
            .await;

        let requests = mock.take_requests();
        let auth = get_header(&requests[0], "Authorization").expect("missing Authorization");
        assert_eq!(auth, encode_basic_credentials("cid", "sec"));
    }

    #[tokio::test]
    async fn revoke_token_public_sends_client_id_in_body() {
        let client = OAuth2Client::new("pub-id", None, None);
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: vec![],
        }]);

        let _ = client
            .revoke_token(&mock, "https://example.com/revoke", "tok")
            .await;

        let requests = mock.take_requests();
        assert!(get_header(&requests[0], "Authorization").is_none());
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("client_id".into(), "pub-id".into())));
    }

    #[tokio::test]
    async fn revoke_token_non_200_returns_error() {
        let client = OAuth2Client::new("cid", Some("sec".into()), None);
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 503,
            body: vec![],
        }]);

        let result = client
            .revoke_token(&mock, "https://example.com/revoke", "tok")
            .await;

        match result {
            Err(Error::UnexpectedResponse { status: 503 }) => {}
            other => panic!("Expected UnexpectedResponse(503), got: {other:?}"),
        }
    }
}
