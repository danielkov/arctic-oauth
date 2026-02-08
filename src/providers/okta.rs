use crate::client::OAuth2Client;
use crate::error::Error;
use crate::http::HttpClient;
use crate::pkce::CodeChallengeMethod;
use crate::tokens::OAuth2Tokens;

pub struct Okta {
    client: OAuth2Client,
    authorization_endpoint: String,
    token_endpoint: String,
    revocation_endpoint: String,
}

impl Okta {
    pub fn new(
        domain: impl Into<String>,
        authorization_server_id: Option<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        let domain = domain.into();
        let base = match authorization_server_id {
            Some(ref server_id) => format!("https://{domain}/oauth2/{server_id}"),
            None => format!("https://{domain}/oauth2"),
        };
        Self {
            client: OAuth2Client::new(
                client_id,
                Some(client_secret.into()),
                Some(redirect_uri.into()),
            ),
            authorization_endpoint: format!("{base}/v1/authorize"),
            token_endpoint: format!("{base}/v1/token"),
            revocation_endpoint: format!("{base}/v1/revoke"),
        }
    }
}

impl Okta {
    pub fn name(&self) -> &'static str {
        "Okta"
    }

    pub fn authorization_url(
        &self,
        state: &str,
        scopes: &[&str],
        code_verifier: &str,
    ) -> url::Url {
        self.client.create_authorization_url_with_pkce(
            &self.authorization_endpoint,
            state,
            CodeChallengeMethod::S256,
            code_verifier,
            scopes,
        )
    }

    pub async fn validate_authorization_code(
        &self,
        http_client: &(impl HttpClient + ?Sized),
        code: &str,
        code_verifier: &str,
    ) -> Result<OAuth2Tokens, Error> {
        self.client
            .validate_authorization_code(
                http_client,
                &self.token_endpoint,
                code,
                Some(code_verifier),
            )
            .await
    }

    pub async fn refresh_access_token(
        &self,
        http_client: &(impl HttpClient + ?Sized),
        refresh_token: &str,
        scopes: &[&str],
    ) -> Result<OAuth2Tokens, Error> {
        self.client
            .refresh_access_token(http_client, &self.token_endpoint, refresh_token, scopes)
            .await
    }

    pub async fn revoke_token(
        &self,
        http_client: &(impl HttpClient + ?Sized),
        token: &str,
    ) -> Result<(), Error> {
        self.client
            .revoke_token(http_client, &self.revocation_endpoint, token)
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
    fn new_builds_endpoints_without_auth_server_id() {
        let okta = Okta::new("dev-123.okta.com", None, "cid", "secret", "https://app/cb");
        assert_eq!(
            okta.authorization_endpoint,
            "https://dev-123.okta.com/oauth2/v1/authorize"
        );
        assert_eq!(
            okta.token_endpoint,
            "https://dev-123.okta.com/oauth2/v1/token"
        );
        assert_eq!(
            okta.revocation_endpoint,
            "https://dev-123.okta.com/oauth2/v1/revoke"
        );
    }

    #[test]
    fn new_builds_endpoints_with_auth_server_id() {
        let okta = Okta::new(
            "dev-123.okta.com",
            Some("default".into()),
            "cid",
            "secret",
            "https://app/cb",
        );
        assert_eq!(
            okta.authorization_endpoint,
            "https://dev-123.okta.com/oauth2/default/v1/authorize"
        );
        assert_eq!(
            okta.token_endpoint,
            "https://dev-123.okta.com/oauth2/default/v1/token"
        );
        assert_eq!(
            okta.revocation_endpoint,
            "https://dev-123.okta.com/oauth2/default/v1/revoke"
        );
    }

    #[test]
    fn name_returns_okta() {
        let okta = Okta::new("dev-123.okta.com", None, "cid", "secret", "https://app/cb");
        assert_eq!(okta.name(), "Okta");
    }

    #[test]
    fn authorization_url_includes_pkce() {
        let okta = Okta::new("dev-123.okta.com", None, "cid", "secret", "https://app/cb");
        let url = okta.authorization_url("state123", &["openid"], "my-verifier");

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.iter().any(|(k, _)| k == "code_challenge"));
        assert!(pairs.contains(&("code_challenge_method".into(), "S256".into())));
    }

    #[tokio::test]
    async fn validate_authorization_code_sends_verifier() {
        let okta = Okta::new("mock.okta.com", None, "cid", "secret", "https://app/cb");
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "okta-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);

        let tokens = okta
            .validate_authorization_code(&mock, "code", "verifier")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "okta-tok");

        let requests = mock.take_requests();
        assert_eq!(requests[0].url, "https://mock.okta.com/oauth2/v1/token");
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("code_verifier".into(), "verifier".into())));
    }

    #[tokio::test]
    async fn refresh_access_token_passes_scopes() {
        let okta = Okta::new("mock.okta.com", None, "cid", "secret", "https://app/cb");
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "new-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);

        let tokens = okta
            .refresh_access_token(&mock, "rt", &["openid", "profile"])
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "new-tok");

        let requests = mock.take_requests();
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("scope".into(), "openid profile".into())));
    }

    #[tokio::test]
    async fn revoke_token_delegates_to_client() {
        let okta = Okta::new("mock.okta.com", None, "cid", "secret", "https://app/cb");
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: vec![],
        }]);

        let result = okta.revoke_token(&mock, "tok").await;
        assert!(result.is_ok());

        let requests = mock.take_requests();
        assert_eq!(requests[0].url, "https://mock.okta.com/oauth2/v1/revoke");
    }
}
