use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A mock OAuth2 server built on `wiremock`. Simulates a provider's
/// token and revocation endpoints with configurable behavior.
pub struct MockOAuth2Server {
    server: MockServer,
}

impl MockOAuth2Server {
    /// Start a new mock server on a random available port.
    pub async fn start() -> Self {
        Self {
            server: MockServer::start().await,
        }
    }

    /// Base URL of the mock server (e.g. "http://127.0.0.1:PORT").
    pub fn url(&self) -> String {
        self.server.uri()
    }

    /// Mount a handler that returns a successful token response (HTTP 200)
    /// with the given JSON body at `POST /token`.
    pub async fn mock_token_success(&self, response: serde_json::Value) {
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response))
            .mount(&self.server)
            .await;
    }

    /// Mount a handler that returns an OAuth2 error response (HTTP 400)
    /// with standard error JSON at `POST /token`.
    pub async fn mock_token_error(&self, error_code: &str, description: &str) {
        let body = serde_json::json!({
            "error": error_code,
            "error_description": description,
        });
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(400).set_body_json(&body))
            .mount(&self.server)
            .await;
    }

    /// Mount a handler that returns HTTP 200 but with an `error` field
    /// in the JSON body (GitHub-style error response) at `POST /token`.
    pub async fn mock_token_error_as_200(&self, error_code: &str, description: &str) {
        let body = serde_json::json!({
            "error": error_code,
            "error_description": description,
        });
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&body))
            .mount(&self.server)
            .await;
    }

    /// Mount a handler that returns a non-standard HTTP status at `POST /token`.
    pub async fn mock_unexpected_status(&self, status: u16) {
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(status))
            .mount(&self.server)
            .await;
    }

    /// Mount a handler that returns HTTP 200 with empty body at `POST /revoke`.
    pub async fn mock_revocation_success(&self) {
        Mock::given(method("POST"))
            .and(path("/revoke"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&self.server)
            .await;
    }

    /// Assert that the last request to the mock server contained
    /// the expected form-urlencoded parameters in its body.
    pub async fn verify_token_request(&self, expected_params: &[(&str, &str)]) {
        let requests = self
            .server
            .received_requests()
            .await
            .expect("request recording enabled");
        let last = requests.last().expect("expected at least one request");
        let body_str = String::from_utf8(last.body.clone()).expect("body should be UTF-8");
        let parsed: Vec<(String, String)> = url::form_urlencoded::parse(body_str.as_bytes())
            .into_owned()
            .collect();

        for (key, value) in expected_params {
            let found = parsed.iter().any(|(k, v)| k == key && v == value);
            assert!(
                found,
                "expected form param {}={} in request body, got: {}",
                key, value, body_str
            );
        }
    }

    /// Assert that the last request contained a Basic auth header
    /// with the expected credentials.
    pub async fn verify_basic_auth(&self, client_id: &str, client_secret: &str) {
        use base64::Engine;
        let requests = self
            .server
            .received_requests()
            .await
            .expect("request recording enabled");
        let last = requests.last().expect("expected at least one request");
        let auth_header = last
            .headers
            .get("authorization")
            .expect("expected Authorization header");
        let expected_credentials = base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{}", client_id, client_secret));
        let expected = format!("Basic {}", expected_credentials);
        assert_eq!(
            auth_header.to_str().unwrap(),
            expected,
            "Basic auth credentials mismatch"
        );
    }
}
