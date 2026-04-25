use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::http::{HttpClient, HttpRequest, HttpResponse};

/// RFC 7591 client metadata sent to the registration endpoint.
///
/// Only the fields commonly used for OAuth 2.1 + PKCE flows are typed; any
/// extras (vendor extensions, software statements) can be added through
/// [`extra`](Self::extra).
#[derive(Debug, Clone, Serialize)]
pub struct ClientRegistrationRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    pub redirect_uris: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub grant_types: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub response_types: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_endpoint_auth_method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub application_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tos_uri: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_uri: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub contacts: Vec<String>,
    /// Vendor extensions or fields not modelled above. Serialized inline.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl ClientRegistrationRequest {
    /// Public native client (RFC 8252) using
    /// `token_endpoint_auth_method=none` and `authorization_code` +
    /// `refresh_token` grants.
    pub fn public_native(redirect_uris: Vec<String>) -> Self {
        Self {
            client_name: None,
            redirect_uris,
            grant_types: vec!["authorization_code".into(), "refresh_token".into()],
            response_types: vec!["code".into()],
            token_endpoint_auth_method: Some("none".into()),
            application_type: Some("native".into()),
            scope: None,
            software_id: None,
            software_version: None,
            client_uri: None,
            logo_uri: None,
            tos_uri: None,
            policy_uri: None,
            contacts: Vec::new(),
            extra: serde_json::Map::new(),
        }
    }

    /// Confidential web client. Defaults to `client_secret_post` (mandatory
    /// to support per OAuth 2.1).
    pub fn confidential(redirect_uris: Vec<String>) -> Self {
        Self {
            client_name: None,
            redirect_uris,
            grant_types: vec!["authorization_code".into(), "refresh_token".into()],
            response_types: vec!["code".into()],
            token_endpoint_auth_method: Some("client_secret_post".into()),
            application_type: Some("web".into()),
            scope: None,
            software_id: None,
            software_version: None,
            client_uri: None,
            logo_uri: None,
            tos_uri: None,
            policy_uri: None,
            contacts: Vec::new(),
            extra: serde_json::Map::new(),
        }
    }
}

/// Response from a successful registration. Per RFC 7591 §3.2.1.
#[derive(Debug, Clone, Deserialize)]
pub struct RegisteredClient {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub client_id_issued_at: Option<u64>,
    /// `0` indicates that the secret does not expire.
    pub client_secret_expires_at: Option<u64>,
    /// RFC 7592 — token used to read/update/delete this registration.
    pub registration_access_token: Option<String>,
    pub registration_client_uri: Option<String>,
    /// Echoed registration metadata and any other server-added fields.
    #[serde(flatten)]
    pub data: serde_json::Map<String, serde_json::Value>,
}

/// POST a registration request to the AS's registration endpoint.
pub async fn register_client(
    http: &impl HttpClient,
    registration_endpoint: &str,
    request: &ClientRegistrationRequest,
) -> Result<RegisteredClient, Error> {
    let body = serde_json::to_vec(request).map_err(|_| Error::InvalidConfiguration {
        reason: "could not serialize registration request",
    })?;

    let req = HttpRequest {
        url: registration_endpoint.to_string(),
        headers: vec![
            ("Content-Type".into(), "application/json".into()),
            ("Accept".into(), "application/json".into()),
            ("User-Agent".into(), "arctic-oauth".into()),
        ],
        body,
        method: http::Method::POST,
    };

    let response: HttpResponse = http.send(req).await?;
    match response.status {
        200 | 201 => serde_json::from_slice::<RegisteredClient>(&response.body).map_err(|_| {
            Error::UnexpectedErrorBody {
                status: response.status,
                body: String::from_utf8_lossy(&response.body).into_owned(),
            }
        }),
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
                        state: None,
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
            Ok(self.responses.lock().unwrap().remove(0))
        }
    }

    #[test]
    fn public_native_serializes_with_none_auth() {
        let req =
            ClientRegistrationRequest::public_native(vec!["http://127.0.0.1:8080/callback".into()]);
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["token_endpoint_auth_method"], "none");
        assert_eq!(json["application_type"], "native");
        assert_eq!(json["redirect_uris"][0], "http://127.0.0.1:8080/callback");
        assert_eq!(json["grant_types"][0], "authorization_code");
        assert_eq!(json["grant_types"][1], "refresh_token");
        assert_eq!(json["response_types"][0], "code");
    }

    #[test]
    fn confidential_serializes_with_post_auth() {
        let req = ClientRegistrationRequest::confidential(vec!["https://app/cb".into()]);
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["token_endpoint_auth_method"], "client_secret_post");
        assert_eq!(json["application_type"], "web");
    }

    #[test]
    fn extras_are_flattened() {
        let mut req = ClientRegistrationRequest::public_native(vec!["http://x/cb".into()]);
        req.extra.insert(
            "software_statement".into(),
            serde_json::Value::String("eyJ...".into()),
        );
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["software_statement"], "eyJ...");
    }

    #[tokio::test]
    async fn register_returns_client_id_on_201() {
        let response_body = serde_json::json!({
            "client_id": "abc-123",
            "client_id_issued_at": 1700000000_u64,
            "redirect_uris": ["http://127.0.0.1:8080/callback"],
            "token_endpoint_auth_method": "none",
        });
        let mock = MockHttpClient::new(vec![HttpResponse {
            headers: vec![],
            status: 201,
            body: serde_json::to_vec(&response_body).unwrap(),
        }]);
        let request =
            ClientRegistrationRequest::public_native(vec!["http://127.0.0.1:8080/callback".into()]);
        let registered = register_client(&mock, "https://as/register", &request)
            .await
            .unwrap();
        assert_eq!(registered.client_id, "abc-123");
        assert!(registered.client_secret.is_none());
        assert_eq!(registered.client_id_issued_at, Some(1700000000));

        let req = &mock.take_requests()[0];
        assert_eq!(req.url, "https://as/register");
        assert_eq!(req.method, http::Method::POST);
        let content_type = req
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.as_str());
        assert_eq!(content_type, Some("application/json"));
        let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap();
        assert_eq!(body["token_endpoint_auth_method"], "none");
    }

    #[tokio::test]
    async fn register_returns_secret_when_confidential() {
        let response_body = serde_json::json!({
            "client_id": "abc",
            "client_secret": "xyz",
            "client_secret_expires_at": 0_u64,
        });
        let mock = MockHttpClient::new(vec![HttpResponse {
            headers: vec![],
            status: 200,
            body: serde_json::to_vec(&response_body).unwrap(),
        }]);
        let request = ClientRegistrationRequest::confidential(vec!["https://app/cb".into()]);
        let registered = register_client(&mock, "https://as/register", &request)
            .await
            .unwrap();
        assert_eq!(registered.client_secret.as_deref(), Some("xyz"));
        assert_eq!(registered.client_secret_expires_at, Some(0));
    }

    #[tokio::test]
    async fn register_translates_oauth_error() {
        let body = serde_json::json!({
            "error": "invalid_redirect_uri",
            "error_description": "redirect_uri must use https or be loopback",
        });
        let mock = MockHttpClient::new(vec![HttpResponse {
            headers: vec![],
            status: 400,
            body: serde_json::to_vec(&body).unwrap(),
        }]);
        let request = ClientRegistrationRequest::public_native(vec!["bad".into()]);
        let err = register_client(&mock, "https://as/register", &request)
            .await
            .unwrap_err();
        match err {
            Error::OAuthRequest {
                code, description, ..
            } => {
                assert_eq!(code, "invalid_redirect_uri");
                assert_eq!(
                    description.as_deref(),
                    Some("redirect_uri must use https or be loopback")
                );
            }
            other => panic!("expected OAuthRequest, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn register_unexpected_status_yields_unexpected_response() {
        let mock = MockHttpClient::new(vec![HttpResponse {
            headers: vec![],
            status: 500,
            body: vec![],
        }]);
        let request = ClientRegistrationRequest::public_native(vec!["http://x/cb".into()]);
        let err = register_client(&mock, "https://as/register", &request)
            .await
            .unwrap_err();
        assert!(matches!(err, Error::UnexpectedResponse { status: 500 }));
    }
}
