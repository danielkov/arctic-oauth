use crate::client::OAuth2Client;
use crate::error::Error;
use crate::http::HttpClient;
use crate::pkce::CodeChallengeMethod;
use crate::tokens::OAuth2Tokens;

pub struct Auth0 {
    client: OAuth2Client,
    authorization_endpoint: String,
    token_endpoint: String,
    revocation_endpoint: String,
}

impl Auth0 {
    pub fn new(
        domain: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: Option<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        let domain = domain.into();
        Self {
            client: OAuth2Client::new(client_id, client_secret, Some(redirect_uri.into())),
            authorization_endpoint: format!("https://{domain}/authorize"),
            token_endpoint: format!("https://{domain}/oauth/token"),
            revocation_endpoint: format!("https://{domain}/oauth/revoke"),
        }
    }
}

impl Auth0 {
    pub fn name(&self) -> &'static str {
        "Auth0"
    }

    pub fn authorization_url(
        &self,
        state: &str,
        scopes: &[&str],
        code_verifier: Option<&str>,
    ) -> url::Url {
        match code_verifier {
            Some(verifier) => self.client.create_authorization_url_with_pkce(
                &self.authorization_endpoint,
                state,
                CodeChallengeMethod::S256,
                verifier,
                scopes,
            ),
            None => self
                .client
                .create_authorization_url(&self.authorization_endpoint, state, scopes),
        }
    }

    pub async fn validate_authorization_code(
        &self,
        http_client: &(impl HttpClient + ?Sized),
        code: &str,
        code_verifier: Option<&str>,
    ) -> Result<OAuth2Tokens, Error> {
        self.client
            .validate_authorization_code(http_client, &self.token_endpoint, code, code_verifier)
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

    #[test]
    fn new_builds_endpoints_from_domain() {
        let auth0 = Auth0::new(
            "myapp.us.auth0.com",
            "cid",
            Some("secret".into()),
            "https://app/cb",
        );
        assert_eq!(
            auth0.authorization_endpoint,
            "https://myapp.us.auth0.com/authorize"
        );
        assert_eq!(
            auth0.token_endpoint,
            "https://myapp.us.auth0.com/oauth/token"
        );
        assert_eq!(
            auth0.revocation_endpoint,
            "https://myapp.us.auth0.com/oauth/revoke"
        );
    }

    #[test]
    fn name_returns_auth0() {
        let auth0 = Auth0::new("example.auth0.com", "cid", None, "https://app/cb");
        assert_eq!(auth0.name(), "Auth0");
    }

    #[test]
    fn authorization_url_without_pkce() {
        let auth0 = Auth0::new("example.auth0.com", "cid", Some("secret".into()), "https://app/cb");
        let url = auth0.authorization_url("state123", &["openid"], None);

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(!pairs.iter().any(|(k, _)| k == "code_challenge"));
    }

    #[test]
    fn authorization_url_with_pkce() {
        let auth0 = Auth0::new("example.auth0.com", "cid", Some("secret".into()), "https://app/cb");
        let url = auth0.authorization_url("state123", &["openid"], Some("my-verifier"));

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.iter().any(|(k, _)| k == "code_challenge"));
        assert!(pairs.contains(&("code_challenge_method".into(), "S256".into())));
    }

    #[tokio::test]
    async fn validate_authorization_code_with_pkce() {
        let auth0 = Auth0::new("mock.auth0.com", "cid", Some("secret".into()), "https://app/cb");
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "auth0-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);

        let tokens = auth0
            .validate_authorization_code(&mock, "code", Some("verifier"))
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "auth0-tok");

        let requests = mock.take_requests();
        assert_eq!(requests[0].url, "https://mock.auth0.com/oauth/token");
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("code_verifier".into(), "verifier".into())));
    }

    #[tokio::test]
    async fn validate_authorization_code_without_pkce() {
        let auth0 = Auth0::new("mock.auth0.com", "cid", Some("secret".into()), "https://app/cb");
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "auth0-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);

        auth0
            .validate_authorization_code(&mock, "code", None)
            .await
            .unwrap();

        let requests = mock.take_requests();
        let body = parse_form_body(&requests[0]);
        assert!(!body.iter().any(|(k, _)| k == "code_verifier"));
    }

    #[tokio::test]
    async fn revoke_token_delegates_to_client() {
        let auth0 = Auth0::new("mock.auth0.com", "cid", Some("secret".into()), "https://app/cb");
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: vec![],
        }]);

        let result = auth0.revoke_token(&mock, "tok").await;
        assert!(result.is_ok());

        let requests = mock.take_requests();
        assert_eq!(requests[0].url, "https://mock.auth0.com/oauth/revoke");
    }
}
