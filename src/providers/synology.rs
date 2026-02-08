use crate::client::OAuth2Client;
use crate::error::Error;
use crate::http::HttpClient;
use crate::pkce::CodeChallengeMethod;
use crate::tokens::OAuth2Tokens;

pub struct Synology {
    client: OAuth2Client,
    authorization_endpoint: String,
    token_endpoint: String,
}

impl Synology {
    pub fn new(
        base_url: impl Into<String>,
        application_id: impl Into<String>,
        application_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        let base = base_url.into();
        Self {
            client: OAuth2Client::new(
                application_id,
                Some(application_secret.into()),
                Some(redirect_uri.into()),
            ),
            authorization_endpoint: format!("{base}/webman/sso/SSOOauth.cgi"),
            token_endpoint: format!("{base}/webman/sso/SSOAccessToken.cgi"),
        }
    }
}

impl Synology {
    pub fn name(&self) -> &'static str {
        "Synology"
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
        let synology = Synology::new(
            "https://nas.example.com:5001",
            "app-id",
            "app-secret",
            "https://app/cb",
        );
        assert_eq!(
            synology.authorization_endpoint,
            "https://nas.example.com:5001/webman/sso/SSOOauth.cgi"
        );
        assert_eq!(
            synology.token_endpoint,
            "https://nas.example.com:5001/webman/sso/SSOAccessToken.cgi"
        );
    }

    #[test]
    fn name_returns_synology() {
        let synology = Synology::new("https://nas.local", "app-id", "app-secret", "https://app/cb");
        assert_eq!(synology.name(), "Synology");
    }

    #[test]
    fn authorization_url_includes_pkce() {
        let synology = Synology::new("https://nas.local", "app-id", "app-secret", "https://app/cb");
        let url = synology.authorization_url("state123", &[], "my-verifier");

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.contains(&("client_id".into(), "app-id".into())));
        assert!(pairs.iter().any(|(k, _)| k == "code_challenge"));
        assert!(pairs.contains(&("code_challenge_method".into(), "S256".into())));
    }

    #[tokio::test]
    async fn validate_authorization_code_sends_verifier() {
        let synology = Synology::new("https://mock", "app-id", "app-secret", "https://app/cb");
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "synology-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);

        let tokens = synology
            .validate_authorization_code(&mock, "code", "verifier")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "synology-tok");

        let requests = mock.take_requests();
        assert_eq!(
            requests[0].url,
            "https://mock/webman/sso/SSOAccessToken.cgi"
        );
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("code_verifier".into(), "verifier".into())));
    }
}
