use crate::client::OAuth2Client;
use crate::error::Error;
use crate::http::HttpClient;
use crate::pkce::CodeChallengeMethod;
use crate::tokens::OAuth2Tokens;

pub struct Mastodon {
    client: OAuth2Client,
    authorization_endpoint: String,
    token_endpoint: String,
    revocation_endpoint: String,
}

impl Mastodon {
    pub fn new(
        base_url: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        let base = base_url.into();
        Self {
            client: OAuth2Client::new(
                client_id,
                Some(client_secret.into()),
                Some(redirect_uri.into()),
            ),
            authorization_endpoint: format!("{base}/api/v1/oauth/authorize"),
            token_endpoint: format!("{base}/api/v1/oauth/token"),
            revocation_endpoint: format!("{base}/api/v1/oauth/revoke"),
        }
    }
}

impl Mastodon {
    pub fn name(&self) -> &'static str {
        "Mastodon"
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
    fn new_builds_endpoints_from_base_url() {
        let mastodon = Mastodon::new(
            "https://mastodon.social",
            "cid",
            "secret",
            "https://app/cb",
        );
        assert_eq!(
            mastodon.authorization_endpoint,
            "https://mastodon.social/api/v1/oauth/authorize"
        );
        assert_eq!(
            mastodon.token_endpoint,
            "https://mastodon.social/api/v1/oauth/token"
        );
        assert_eq!(
            mastodon.revocation_endpoint,
            "https://mastodon.social/api/v1/oauth/revoke"
        );
    }

    #[test]
    fn name_returns_mastodon() {
        let mastodon = Mastodon::new("https://mastodon.social", "cid", "secret", "https://app/cb");
        assert_eq!(mastodon.name(), "Mastodon");
    }

    #[test]
    fn authorization_url_includes_pkce() {
        let mastodon = Mastodon::new("https://mastodon.social", "cid", "secret", "https://app/cb");
        let url = mastodon.authorization_url("state123", &["read"], "my-verifier");

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.iter().any(|(k, _)| k == "code_challenge"));
        assert!(pairs.contains(&("code_challenge_method".into(), "S256".into())));
    }

    #[tokio::test]
    async fn validate_authorization_code_sends_verifier() {
        let mastodon = Mastodon::new("https://mock", "cid", "secret", "https://app/cb");
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "masto-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);

        let tokens = mastodon
            .validate_authorization_code(&mock, "code", "verifier")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "masto-tok");

        let requests = mock.take_requests();
        assert_eq!(requests[0].url, "https://mock/api/v1/oauth/token");
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("code_verifier".into(), "verifier".into())));
    }

    #[tokio::test]
    async fn revoke_token_delegates_to_client() {
        let mastodon = Mastodon::new("https://mock", "cid", "secret", "https://app/cb");
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: vec![],
        }]);

        let result = mastodon.revoke_token(&mock, "tok").await;
        assert!(result.is_ok());

        let requests = mock.take_requests();
        assert_eq!(requests[0].url, "https://mock/api/v1/oauth/revoke");
    }
}
