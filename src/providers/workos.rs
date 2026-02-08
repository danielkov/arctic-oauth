use crate::error::Error;
use crate::http::HttpClient;
use crate::pkce::{CodeChallengeMethod, create_code_challenge};
use crate::request::{create_oauth2_request, send_token_request};
use crate::tokens::OAuth2Tokens;

const AUTHORIZATION_ENDPOINT: &str = "https://api.workos.com/sso/authorize";
const TOKEN_ENDPOINT: &str = "https://api.workos.com/sso/token";

pub struct WorkOS {
    client_id: String,
    client_secret: Option<String>,
    redirect_uri: String,
    authorization_endpoint: String,
    token_endpoint: String,
}

impl WorkOS {
    pub fn new(
        client_id: impl Into<String>,
        client_secret: Option<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret,
            redirect_uri: redirect_uri.into(),
            authorization_endpoint: AUTHORIZATION_ENDPOINT.to_string(),
            token_endpoint: TOKEN_ENDPOINT.to_string(),
        }
    }
}

#[cfg(any(test, feature = "testing"))]
impl WorkOS {
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

impl WorkOS {
    pub fn name(&self) -> &'static str {
        "WorkOS"
    }

    pub fn authorization_url(
        &self,
        state: &str,
        code_verifier: Option<&str>,
    ) -> url::Url {
        let mut url =
            url::Url::parse(&self.authorization_endpoint).expect("invalid authorization endpoint");
        {
            let mut params = url.query_pairs_mut();
            params.append_pair("response_type", "code");
            params.append_pair("client_id", &self.client_id);
            params.append_pair("state", state);
            params.append_pair("redirect_uri", &self.redirect_uri);
            if let Some(verifier) = code_verifier {
                let challenge = create_code_challenge(verifier, CodeChallengeMethod::S256);
                params.append_pair("code_challenge", &challenge);
                params.append_pair("code_challenge_method", "S256");
            }
        }
        url
    }

    pub async fn validate_authorization_code(
        &self,
        http_client: &(impl HttpClient + ?Sized),
        code: &str,
        code_verifier: Option<&str>,
    ) -> Result<OAuth2Tokens, Error> {
        let mut body = vec![
            ("grant_type".to_string(), "authorization_code".to_string()),
            ("code".to_string(), code.to_string()),
            ("redirect_uri".to_string(), self.redirect_uri.clone()),
            ("client_id".to_string(), self.client_id.clone()),
        ];
        if let Some(ref secret) = self.client_secret {
            body.push(("client_secret".to_string(), secret.clone()));
        }
        if let Some(verifier) = code_verifier {
            body.push(("code_verifier".to_string(), verifier.to_string()));
        }
        let request = create_oauth2_request(&self.token_endpoint, &body);
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

    #[test]
    fn new_sets_production_endpoints() {
        let workos = WorkOS::new("cid", Some("secret".into()), "https://app/cb");
        assert_eq!(workos.authorization_endpoint, AUTHORIZATION_ENDPOINT);
        assert_eq!(workos.token_endpoint, TOKEN_ENDPOINT);
    }

    #[test]
    fn name_returns_workos() {
        let workos = WorkOS::new("cid", Some("secret".into()), "https://app/cb");
        assert_eq!(workos.name(), "WorkOS");
    }

    #[test]
    fn authorization_url_without_pkce() {
        let workos = WorkOS::new("cid", Some("secret".into()), "https://app/cb");
        let url = workos.authorization_url("state123", None);

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.contains(&("client_id".into(), "cid".into())));
        assert!(pairs.contains(&("state".into(), "state123".into())));
        assert!(pairs.contains(&("redirect_uri".into(), "https://app/cb".into())));
        assert!(!pairs.iter().any(|(k, _)| k == "scope"));
        assert!(!pairs.iter().any(|(k, _)| k == "code_challenge"));
        assert!(!pairs.iter().any(|(k, _)| k == "code_challenge_method"));
    }

    #[test]
    fn authorization_url_with_pkce() {
        let workos = WorkOS::new("cid", Some("secret".into()), "https://app/cb");
        let url = workos.authorization_url("state123", Some("my-verifier"));

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.contains(&("client_id".into(), "cid".into())));
        assert!(pairs.iter().any(|(k, _)| k == "code_challenge"));
        assert!(pairs.contains(&("code_challenge_method".into(), "S256".into())));
    }

    #[test]
    fn authorization_url_no_scopes() {
        let workos = WorkOS::new("cid", Some("secret".into()), "https://app/cb");
        let url = workos.authorization_url("state123", None);

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(!pairs.iter().any(|(k, _)| k == "scope"));
    }

    #[tokio::test]
    async fn validate_authorization_code_with_secret() {
        let workos = WorkOS::with_endpoints(
            "cid",
            Some("secret".into()),
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "workos-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);

        let tokens = workos
            .validate_authorization_code(&mock, "auth-code", None)
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "workos-tok");

        let requests = mock.take_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url, "https://mock/token");
        assert!(get_header(&requests[0], "Authorization").is_none());

        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("grant_type".into(), "authorization_code".into())));
        assert!(body.contains(&("code".into(), "auth-code".into())));
        assert!(body.contains(&("client_id".into(), "cid".into())));
        assert!(body.contains(&("client_secret".into(), "secret".into())));
        assert!(body.contains(&("redirect_uri".into(), "https://app/cb".into())));
        assert!(!body.iter().any(|(k, _)| k == "code_verifier"));
    }

    #[tokio::test]
    async fn validate_authorization_code_public_client() {
        let workos = WorkOS::with_endpoints(
            "cid",
            None,
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "workos-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);

        workos
            .validate_authorization_code(&mock, "auth-code", Some("my-verifier"))
            .await
            .unwrap();

        let requests = mock.take_requests();
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("client_id".into(), "cid".into())));
        assert!(!body.iter().any(|(k, _)| k == "client_secret"));
        assert!(body.contains(&("code_verifier".into(), "my-verifier".into())));
    }

    #[tokio::test]
    async fn validate_authorization_code_with_pkce() {
        let workos = WorkOS::with_endpoints(
            "cid",
            Some("secret".into()),
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "workos-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);

        workos
            .validate_authorization_code(&mock, "auth-code", Some("my-verifier"))
            .await
            .unwrap();

        let requests = mock.take_requests();
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("code_verifier".into(), "my-verifier".into())));
        assert!(body.contains(&("client_secret".into(), "secret".into())));
    }
}
