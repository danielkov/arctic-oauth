use base64::Engine;

use crate::Error;
use crate::http::{HttpClient, HttpRequest, HttpResponse};
use crate::tokens::OAuth2Tokens;

/// Build a standard OAuth2 POST request.
/// Sets Content-Type, Accept: application/json, User-Agent: arctic-oauth.
pub fn create_oauth2_request(endpoint: &str, body: &[(String, String)]) -> HttpRequest {
    let encoded_body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(body)
        .finish();

    HttpRequest {
        url: endpoint.to_string(),
        headers: vec![
            (
                "Content-Type".to_string(),
                "application/x-www-form-urlencoded".to_string(),
            ),
            ("Accept".to_string(), "application/json".to_string()),
            ("User-Agent".to_string(), "arctic-oauth".to_string()),
        ],
        body: encoded_body.into_bytes(),
    }
}

/// Encode client credentials as HTTP Basic auth header value.
/// Returns `Basic <base64(client_id:client_secret)>`.
pub fn encode_basic_credentials(client_id: &str, client_secret: &str) -> String {
    let credentials = format!("{client_id}:{client_secret}");
    let encoded = base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes());
    format!("Basic {encoded}")
}

/// Send a token request and interpret the response.
/// - 200 -> Ok(OAuth2Tokens)
/// - 400/401 with valid error JSON -> Err(Error::OAuthRequest { .. })
/// - 400/401 with invalid body -> Err(Error::UnexpectedErrorBody { .. })
/// - Other status -> Err(Error::UnexpectedResponse { .. })
pub async fn send_token_request(
    client: &(impl HttpClient + ?Sized),
    request: HttpRequest,
) -> Result<OAuth2Tokens, Error> {
    let response: HttpResponse = client.send(request).await?;

    match response.status {
        200 => {
            let json: serde_json::Value =
                serde_json::from_slice(&response.body).map_err(|_| Error::UnexpectedErrorBody {
                    status: 200,
                    body: String::from_utf8_lossy(&response.body).into_owned(),
                })?;
            Ok(OAuth2Tokens::new(json))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::HttpResponse;
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

    #[test]
    fn encode_basic_credentials_known_values() {
        // RFC 7617 example: user "Aladdin", password "open sesame"
        let result = encode_basic_credentials("Aladdin", "open sesame");
        assert_eq!(result, "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
    }

    #[test]
    fn encode_basic_credentials_empty_values() {
        let result = encode_basic_credentials("", "");
        // base64(":")  = "Og=="
        assert_eq!(result, "Basic Og==");
    }

    #[test]
    fn encode_basic_credentials_special_characters() {
        let result = encode_basic_credentials("client:id", "secret&value");
        let expected_b64 =
            base64::engine::general_purpose::STANDARD.encode("client:id:secret&value");
        assert_eq!(result, format!("Basic {expected_b64}"));
    }

    #[test]
    fn create_oauth2_request_sets_correct_headers() {
        let request = create_oauth2_request("https://example.com/token", &[]);

        assert_eq!(request.url, "https://example.com/token");
        assert_eq!(request.headers.len(), 3);

        let headers: std::collections::HashMap<&str, &str> = request
            .headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        assert_eq!(
            headers.get("Content-Type"),
            Some(&"application/x-www-form-urlencoded")
        );
        assert_eq!(headers.get("Accept"), Some(&"application/json"));
        assert_eq!(headers.get("User-Agent"), Some(&"arctic-oauth"));
    }

    #[test]
    fn create_oauth2_request_url_encodes_body() {
        let body = vec![
            ("grant_type".to_string(), "authorization_code".to_string()),
            ("code".to_string(), "abc 123&foo=bar".to_string()),
        ];
        let request = create_oauth2_request("https://example.com/token", &body);
        let body_str = String::from_utf8(request.body).unwrap();

        assert_eq!(
            body_str,
            "grant_type=authorization_code&code=abc+123%26foo%3Dbar"
        );
    }

    #[test]
    fn create_oauth2_request_empty_body() {
        let request = create_oauth2_request("https://example.com/token", &[]);
        assert_eq!(request.body, b"");
    }

    #[tokio::test]
    async fn send_token_request_success_200() {
        let response_body = serde_json::json!({
            "access_token": "test-token",
            "token_type": "Bearer",
            "expires_in": 3600
        });
        let client = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&response_body).unwrap(),
        }]);

        let request = create_oauth2_request("https://example.com/token", &[]);
        let tokens = send_token_request(&client, request).await.unwrap();

        assert_eq!(tokens.access_token().unwrap(), "test-token");
        assert_eq!(tokens.token_type().unwrap(), "Bearer");
        assert_eq!(tokens.access_token_expires_in_seconds().unwrap(), 3600);
    }

    #[tokio::test]
    async fn send_token_request_oauth_error_400() {
        let error_body = serde_json::json!({
            "error": "invalid_grant",
            "error_description": "The authorization code has expired",
            "error_uri": "https://example.com/docs/errors"
        });
        let client = MockHttpClient::new(vec![HttpResponse {
            status: 400,
            body: serde_json::to_vec(&error_body).unwrap(),
        }]);

        let request = create_oauth2_request("https://example.com/token", &[]);
        let err = send_token_request(&client, request).await.unwrap_err();

        match err {
            Error::OAuthRequest {
                code,
                description,
                uri,
                state,
            } => {
                assert_eq!(code, "invalid_grant");
                assert_eq!(
                    description.as_deref(),
                    Some("The authorization code has expired")
                );
                assert_eq!(uri.as_deref(), Some("https://example.com/docs/errors"));
                assert!(state.is_none());
            }
            other => panic!("Expected OAuthRequest, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn send_token_request_oauth_error_401() {
        let error_body = serde_json::json!({
            "error": "invalid_client",
        });
        let client = MockHttpClient::new(vec![HttpResponse {
            status: 401,
            body: serde_json::to_vec(&error_body).unwrap(),
        }]);

        let request = create_oauth2_request("https://example.com/token", &[]);
        let err = send_token_request(&client, request).await.unwrap_err();

        match err {
            Error::OAuthRequest {
                code,
                description,
                uri,
                state,
            } => {
                assert_eq!(code, "invalid_client");
                assert!(description.is_none());
                assert!(uri.is_none());
                assert!(state.is_none());
            }
            other => panic!("Expected OAuthRequest, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn send_token_request_unexpected_error_body_400() {
        let client = MockHttpClient::new(vec![HttpResponse {
            status: 400,
            body: b"not json at all".to_vec(),
        }]);

        let request = create_oauth2_request("https://example.com/token", &[]);
        let err = send_token_request(&client, request).await.unwrap_err();

        match err {
            Error::UnexpectedErrorBody { status, body } => {
                assert_eq!(status, 400);
                assert_eq!(body, "not json at all");
            }
            other => panic!("Expected UnexpectedErrorBody, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn send_token_request_json_without_error_field_400() {
        // Valid JSON but missing the "error" field
        let body = serde_json::json!({ "message": "something went wrong" });
        let client = MockHttpClient::new(vec![HttpResponse {
            status: 400,
            body: serde_json::to_vec(&body).unwrap(),
        }]);

        let request = create_oauth2_request("https://example.com/token", &[]);
        let err = send_token_request(&client, request).await.unwrap_err();

        assert!(matches!(
            err,
            Error::UnexpectedErrorBody { status: 400, .. }
        ));
    }

    #[tokio::test]
    async fn send_token_request_unexpected_status() {
        let client = MockHttpClient::new(vec![HttpResponse {
            status: 500,
            body: b"Internal Server Error".to_vec(),
        }]);

        let request = create_oauth2_request("https://example.com/token", &[]);
        let err = send_token_request(&client, request).await.unwrap_err();

        assert!(matches!(err, Error::UnexpectedResponse { status: 500 }));
    }

    #[tokio::test]
    async fn send_token_request_records_request() {
        let client = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);

        let body = vec![("grant_type".to_string(), "authorization_code".to_string())];
        let request = create_oauth2_request("https://example.com/token", &body);
        let _ = send_token_request(&client, request).await;

        let requests = client.take_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url, "https://example.com/token");
    }
}
