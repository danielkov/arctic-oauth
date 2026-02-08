use crate::error::Error;
use crate::http::HttpClient;
use crate::request::create_oauth2_request;
use crate::tokens::OAuth2Tokens;

const AUTHORIZATION_ENDPOINT: &str = "https://account.withings.com/oauth2_user/authorize2";
const TOKEN_ENDPOINT: &str = "https://wbsapi.withings.net/v2/oauth2";

pub struct Withings {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    authorization_endpoint: String,
    token_endpoint: String,
}

impl Withings {
    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri: redirect_uri.into(),
            authorization_endpoint: AUTHORIZATION_ENDPOINT.to_string(),
            token_endpoint: TOKEN_ENDPOINT.to_string(),
        }
    }
}

#[cfg(any(test, feature = "testing"))]
impl Withings {
    pub fn with_endpoints(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
        authorization_endpoint: &str,
        token_endpoint: &str,
    ) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri: redirect_uri.into(),
            authorization_endpoint: authorization_endpoint.to_string(),
            token_endpoint: token_endpoint.to_string(),
        }
    }
}

impl Withings {
    pub fn name(&self) -> &'static str {
        "Withings"
    }

    pub fn authorization_url(&self, state: &str, scopes: &[&str]) -> url::Url {
        let mut url = url::Url::parse(&self.authorization_endpoint)
            .expect("invalid authorization endpoint URL");
        {
            let mut params = url.query_pairs_mut();
            params.append_pair("response_type", "code");
            params.append_pair("client_id", &self.client_id);
            params.append_pair("state", state);
            // Withings uses comma-delimited scopes
            if !scopes.is_empty() {
                params.append_pair("scope", &scopes.join(","));
            }
            params.append_pair("redirect_uri", &self.redirect_uri);
        }
        url
    }

    pub async fn validate_authorization_code(
        &self,
        http_client: &(impl HttpClient + ?Sized),
        code: &str,
    ) -> Result<OAuth2Tokens, Error> {
        let body = vec![
            ("action".to_string(), "requesttoken".to_string()),
            ("grant_type".to_string(), "authorization_code".to_string()),
            ("code".to_string(), code.to_string()),
            ("redirect_uri".to_string(), self.redirect_uri.clone()),
            ("client_id".to_string(), self.client_id.clone()),
            ("client_secret".to_string(), self.client_secret.clone()),
        ];
        let request = create_oauth2_request(&self.token_endpoint, &body);
        self.parse_token_response(http_client, request).await
    }

    /// Withings wraps token responses in `{"status": 0, "body": {...}}`.
    /// Errors are also returned with HTTP 200, indicated by a non-zero status field.
    async fn parse_token_response(
        &self,
        http_client: &(impl HttpClient + ?Sized),
        request: crate::http::HttpRequest,
    ) -> Result<OAuth2Tokens, Error> {
        let response = http_client.send(request).await?;

        match response.status {
            200 => {
                let body_str = String::from_utf8_lossy(&response.body).into_owned();
                let json: serde_json::Value =
                    serde_json::from_str(&body_str).map_err(|_| Error::UnexpectedErrorBody {
                        status: 200,
                        body: body_str.clone(),
                    })?;

                // Check for standard OAuth error field
                if let Some(error_code) = json.get("error").and_then(|e| e.as_str()) {
                    return Err(Error::OAuthRequest {
                        code: error_code.to_string(),
                        description: json
                            .get("error_description")
                            .and_then(|v| v.as_str())
                            .map(String::from),
                        uri: json
                            .get("error_uri")
                            .and_then(|v| v.as_str())
                            .map(String::from),
                        state: json.get("state").and_then(|v| v.as_str()).map(String::from),
                    });
                }

                // Withings uses status field: 0 means success, non-zero means error
                let status = json.get("status").and_then(|s| s.as_i64());
                if status != Some(0) {
                    return Err(Error::UnexpectedErrorBody {
                        status: 200,
                        body: body_str,
                    });
                }

                // Unwrap the nested body field
                match json.get("body") {
                    Some(inner) => Ok(OAuth2Tokens::new(inner.clone())),
                    None => Err(Error::MissingField { field: "body" }),
                }
            }
            400 | 401 => {
                let body_str = String::from_utf8_lossy(&response.body).into_owned();
                match serde_json::from_str::<serde_json::Value>(&body_str) {
                    Ok(json) if json.get("error").and_then(|e| e.as_str()).is_some() => {
                        Err(Error::OAuthRequest {
                            code: json["error"].as_str().unwrap().to_string(),
                            description: json
                                .get("error_description")
                                .and_then(|v| v.as_str())
                                .map(String::from),
                            uri: json
                                .get("error_uri")
                                .and_then(|v| v.as_str())
                                .map(String::from),
                            state: json.get("state").and_then(|v| v.as_str()).map(String::from),
                        })
                    }
                    _ => Err(Error::UnexpectedErrorBody {
                        status: response.status,
                        body: body_str,
                    }),
                }
            }
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

    #[test]
    fn new_sets_production_endpoints() {
        let withings = Withings::new("cid", "secret", "https://app/cb");
        assert_eq!(withings.authorization_endpoint, AUTHORIZATION_ENDPOINT);
        assert_eq!(withings.token_endpoint, TOKEN_ENDPOINT);
    }

    #[test]
    fn name_returns_withings() {
        let withings = Withings::new("cid", "secret", "https://app/cb");
        assert_eq!(withings.name(), "Withings");
    }

    #[test]
    fn authorization_url_uses_comma_delimited_scopes() {
        let withings = Withings::new("cid", "secret", "https://app/cb");
        let url = withings.authorization_url("state123", &["user.metrics", "user.activity"]);

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.contains(&("client_id".into(), "cid".into())));
        assert!(pairs.contains(&("state".into(), "state123".into())));
        assert!(pairs.contains(&("scope".into(), "user.metrics,user.activity".into())));
        assert!(pairs.contains(&("redirect_uri".into(), "https://app/cb".into())));
    }

    #[test]
    fn authorization_url_omits_scope_when_empty() {
        let withings = Withings::new("cid", "secret", "https://app/cb");
        let url = withings.authorization_url("state123", &[]);

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(!pairs.iter().any(|(k, _)| k == "scope"));
    }

    #[tokio::test]
    async fn validate_authorization_code_sends_action_requesttoken() {
        let withings = Withings::with_endpoints(
            "cid",
            "secret",
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "status": 0,
                "body": {
                    "access_token": "w-tok",
                    "token_type": "Bearer",
                    "expires_in": 10800,
                    "refresh_token": "w-refresh"
                }
            }))
            .unwrap(),
        }]);

        let tokens = withings
            .validate_authorization_code(&mock, "auth-code")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "w-tok");
        assert_eq!(tokens.refresh_token().unwrap(), "w-refresh");

        let requests = mock.take_requests();
        assert_eq!(requests[0].url, "https://mock/token");
        // No Authorization header (body credentials)
        assert!(get_header(&requests[0], "Authorization").is_none());

        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("action".into(), "requesttoken".into())));
        assert!(body.contains(&("grant_type".into(), "authorization_code".into())));
        assert!(body.contains(&("code".into(), "auth-code".into())));
        assert!(body.contains(&("client_id".into(), "cid".into())));
        assert!(body.contains(&("client_secret".into(), "secret".into())));
        assert!(body.contains(&("redirect_uri".into(), "https://app/cb".into())));
    }

    #[tokio::test]
    async fn validate_authorization_code_unwraps_nested_body() {
        let withings = Withings::with_endpoints(
            "cid",
            "secret",
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "status": 0,
                "body": {
                    "access_token": "inner-token",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "scope": "user.metrics"
                }
            }))
            .unwrap(),
        }]);

        let tokens = withings
            .validate_authorization_code(&mock, "code")
            .await
            .unwrap();

        // Token data should come from the nested body, not the outer envelope
        assert_eq!(tokens.access_token().unwrap(), "inner-token");
        assert_eq!(tokens.access_token_expires_in_seconds().unwrap(), 3600);
    }

    #[tokio::test]
    async fn validate_authorization_code_handles_error_as_200() {
        let withings = Withings::with_endpoints(
            "cid",
            "secret",
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "error": "invalid_request",
                "error_description": "The code has expired."
            }))
            .unwrap(),
        }]);

        let err = withings
            .validate_authorization_code(&mock, "bad-code")
            .await
            .unwrap_err();

        match err {
            Error::OAuthRequest {
                code, description, ..
            } => {
                assert_eq!(code, "invalid_request");
                assert_eq!(description.as_deref(), Some("The code has expired."));
            }
            other => panic!("Expected OAuthRequest, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn validate_authorization_code_non_zero_status_is_error() {
        let withings = Withings::with_endpoints(
            "cid",
            "secret",
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "status": 503,
                "body": {}
            }))
            .unwrap(),
        }]);

        let err = withings
            .validate_authorization_code(&mock, "code")
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            Error::UnexpectedErrorBody { status: 200, .. }
        ));
    }

    #[tokio::test]
    async fn validate_authorization_code_missing_body_field() {
        let withings = Withings::with_endpoints(
            "cid",
            "secret",
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "status": 0
            }))
            .unwrap(),
        }]);

        let err = withings
            .validate_authorization_code(&mock, "code")
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            Error::MissingField { field: "body" }
        ));
    }

    #[tokio::test]
    async fn validate_authorization_code_400_error() {
        let withings = Withings::with_endpoints(
            "cid",
            "secret",
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 400,
            body: serde_json::to_vec(&serde_json::json!({
                "error": "invalid_grant",
                "error_description": "The code is invalid"
            }))
            .unwrap(),
        }]);

        let err = withings
            .validate_authorization_code(&mock, "code")
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            Error::OAuthRequest { code, .. } if code == "invalid_grant"
        ));
    }

    #[tokio::test]
    async fn validate_authorization_code_unexpected_status() {
        let withings = Withings::with_endpoints(
            "cid",
            "secret",
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 500,
            body: b"Internal Server Error".to_vec(),
        }]);

        let err = withings
            .validate_authorization_code(&mock, "code")
            .await
            .unwrap_err();

        assert!(matches!(err, Error::UnexpectedResponse { status: 500 }));
    }
}
