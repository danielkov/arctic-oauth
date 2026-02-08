use crate::client::OAuth2Client;
use crate::error::Error;
use crate::http::HttpClient;
use crate::tokens::OAuth2Tokens;

pub struct GitLab {
    client: OAuth2Client,
    authorization_endpoint: String,
    token_endpoint: String,
    revocation_endpoint: String,
}

impl GitLab {
    pub fn new(
        base_url: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: Option<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        let base = base_url.into();
        Self {
            client: OAuth2Client::new(client_id, client_secret, Some(redirect_uri.into())),
            authorization_endpoint: format!("{base}/oauth/authorize"),
            token_endpoint: format!("{base}/oauth/token"),
            revocation_endpoint: format!("{base}/oauth/revoke"),
        }
    }
}

impl GitLab {
    pub fn name(&self) -> &'static str {
        "GitLab"
    }

    pub fn authorization_url(&self, state: &str, scopes: &[&str]) -> url::Url {
        self.client
            .create_authorization_url(&self.authorization_endpoint, state, scopes)
    }

    pub async fn validate_authorization_code(
        &self,
        http_client: &(impl HttpClient + ?Sized),
        code: &str,
    ) -> Result<OAuth2Tokens, Error> {
        self.client
            .validate_authorization_code(http_client, &self.token_endpoint, code, None)
            .await
    }

    pub async fn refresh_access_token(
        &self,
        http_client: &(impl HttpClient + ?Sized),
        refresh_token: &str,
    ) -> Result<OAuth2Tokens, Error> {
        self.client
            .refresh_access_token(http_client, &self.token_endpoint, refresh_token, &[])
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

    fn get_header<'a>(request: &'a HttpRequest, name: &str) -> Option<&'a str> {
        request
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn new_builds_endpoints_from_base_url() {
        let gitlab = GitLab::new(
            "https://gitlab.example.com",
            "cid",
            Some("secret".into()),
            "https://app/cb",
        );
        assert_eq!(
            gitlab.authorization_endpoint,
            "https://gitlab.example.com/oauth/authorize"
        );
        assert_eq!(
            gitlab.token_endpoint,
            "https://gitlab.example.com/oauth/token"
        );
        assert_eq!(
            gitlab.revocation_endpoint,
            "https://gitlab.example.com/oauth/revoke"
        );
    }

    #[test]
    fn name_returns_gitlab() {
        let gitlab = GitLab::new("https://gitlab.com", "cid", Some("secret".into()), "https://app/cb");
        assert_eq!(gitlab.name(), "GitLab");
    }

    #[test]
    fn authorization_url_includes_standard_params() {
        let gitlab = GitLab::new("https://gitlab.com", "cid", Some("secret".into()), "https://app/cb");
        let url = gitlab.authorization_url("state123", &["read_user", "api"]);

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.contains(&("client_id".into(), "cid".into())));
        assert!(pairs.contains(&("state".into(), "state123".into())));
        assert!(pairs.contains(&("scope".into(), "read_user api".into())));
        assert!(pairs.contains(&("redirect_uri".into(), "https://app/cb".into())));
        // No PKCE
        assert!(!pairs.iter().any(|(k, _)| k == "code_challenge"));
    }

    #[tokio::test]
    async fn validate_authorization_code_delegates_to_client() {
        let gitlab = GitLab::new("https://mock", "cid", Some("secret".into()), "https://app/cb");
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "gitlab-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);

        let tokens = gitlab
            .validate_authorization_code(&mock, "auth-code")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "gitlab-tok");

        let requests = mock.take_requests();
        assert_eq!(requests[0].url, "https://mock/oauth/token");
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("grant_type".into(), "authorization_code".into())));
        assert!(body.contains(&("code".into(), "auth-code".into())));
        assert!(get_header(&requests[0], "Authorization").is_some());
    }

    #[tokio::test]
    async fn validate_authorization_code_public_client() {
        let gitlab = GitLab::new("https://mock", "cid", None, "https://app/cb");
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "gitlab-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);

        gitlab
            .validate_authorization_code(&mock, "auth-code")
            .await
            .unwrap();

        let requests = mock.take_requests();
        assert!(get_header(&requests[0], "Authorization").is_none());
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("client_id".into(), "cid".into())));
    }

    #[tokio::test]
    async fn refresh_access_token_delegates_to_client() {
        let gitlab = GitLab::new("https://mock", "cid", Some("secret".into()), "https://app/cb");
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "new-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);

        let tokens = gitlab.refresh_access_token(&mock, "rt").await.unwrap();
        assert_eq!(tokens.access_token().unwrap(), "new-tok");

        let requests = mock.take_requests();
        assert_eq!(requests[0].url, "https://mock/oauth/token");
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("grant_type".into(), "refresh_token".into())));
    }

    #[tokio::test]
    async fn revoke_token_delegates_to_client() {
        let gitlab = GitLab::new("https://mock", "cid", Some("secret".into()), "https://app/cb");
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: vec![],
        }]);

        let result = gitlab.revoke_token(&mock, "tok").await;
        assert!(result.is_ok());

        let requests = mock.take_requests();
        assert_eq!(requests[0].url, "https://mock/oauth/revoke");
    }
}
