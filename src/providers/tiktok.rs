use crate::error::Error;
use crate::http::HttpClient;
use crate::pkce::{CodeChallengeMethod, create_code_challenge};
use crate::request::create_oauth2_request;
use crate::tokens::OAuth2Tokens;

const AUTHORIZATION_ENDPOINT: &str = "https://www.tiktok.com/v2/auth/authorize/";
const TOKEN_ENDPOINT: &str = "https://open.tiktokapis.com/v2/oauth/token/";
const REVOCATION_ENDPOINT: &str = "https://open.tiktokapis.com/v2/oauth/revoke/";

pub struct TikTok {
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    authorization_endpoint: String,
    token_endpoint: String,
    revocation_endpoint: String,
}

impl TikTok {
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
            revocation_endpoint: REVOCATION_ENDPOINT.to_string(),
        }
    }
}

#[cfg(any(test, feature = "testing"))]
impl TikTok {
    pub fn with_endpoints(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
        authorization_endpoint: &str,
        token_endpoint: &str,
        revocation_endpoint: Option<&str>,
    ) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri: redirect_uri.into(),
            authorization_endpoint: authorization_endpoint.to_string(),
            token_endpoint: token_endpoint.to_string(),
            revocation_endpoint: revocation_endpoint
                .unwrap_or(REVOCATION_ENDPOINT)
                .to_string(),
        }
    }
}

impl TikTok {
    pub fn name(&self) -> &'static str {
        "TikTok"
    }

    pub fn authorization_url(&self, state: &str, scopes: &[&str], code_verifier: &str) -> url::Url {
        let mut url = url::Url::parse(&self.authorization_endpoint)
            .expect("invalid authorization endpoint URL");
        {
            let mut params = url.query_pairs_mut();
            params.append_pair("response_type", "code");
            // TikTok uses client_key instead of client_id
            params.append_pair("client_key", &self.client_id);
            params.append_pair("state", state);
            // TikTok always sends scope, even when empty; comma-delimited
            params.append_pair("scope", &scopes.join(","));
            params.append_pair("redirect_uri", &self.redirect_uri);
            let challenge = create_code_challenge(code_verifier, CodeChallengeMethod::S256);
            params.append_pair("code_challenge", &challenge);
            params.append_pair("code_challenge_method", "S256");
        }
        url
    }

    pub async fn validate_authorization_code(
        &self,
        http_client: &(impl HttpClient + ?Sized),
        code: &str,
        code_verifier: &str,
    ) -> Result<OAuth2Tokens, Error> {
        let body = vec![
            ("grant_type".to_string(), "authorization_code".to_string()),
            ("code".to_string(), code.to_string()),
            ("redirect_uri".to_string(), self.redirect_uri.clone()),
            // TikTok uses client_key instead of client_id
            ("client_key".to_string(), self.client_id.clone()),
            ("client_secret".to_string(), self.client_secret.clone()),
            ("code_verifier".to_string(), code_verifier.to_string()),
        ];
        let request = create_oauth2_request(&self.token_endpoint, &body);
        self.parse_token_response(http_client, request).await
    }

    pub async fn refresh_access_token(
        &self,
        http_client: &(impl HttpClient + ?Sized),
        refresh_token: &str,
    ) -> Result<OAuth2Tokens, Error> {
        let body = vec![
            ("grant_type".to_string(), "refresh_token".to_string()),
            ("refresh_token".to_string(), refresh_token.to_string()),
            ("client_key".to_string(), self.client_id.clone()),
            ("client_secret".to_string(), self.client_secret.clone()),
        ];
        let request = create_oauth2_request(&self.token_endpoint, &body);
        self.parse_token_response(http_client, request).await
    }

    pub async fn revoke_token(
        &self,
        http_client: &(impl HttpClient + ?Sized),
        token: &str,
    ) -> Result<(), Error> {
        let body = vec![
            ("token".to_string(), token.to_string()),
            ("client_key".to_string(), self.client_id.clone()),
            ("client_secret".to_string(), self.client_secret.clone()),
        ];
        let request = create_oauth2_request(&self.revocation_endpoint, &body);
        let response = http_client.send(request).await?;
        match response.status {
            200 => Ok(()),
            status => Err(Error::UnexpectedResponse { status }),
        }
    }

    /// TikTok returns errors with HTTP 200 status, so we need custom parsing.
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

                // TikTok returns errors with HTTP 200
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
        let tiktok = TikTok::new("cid", "secret", "https://app/cb");
        assert_eq!(tiktok.authorization_endpoint, AUTHORIZATION_ENDPOINT);
        assert_eq!(tiktok.token_endpoint, TOKEN_ENDPOINT);
        assert_eq!(tiktok.revocation_endpoint, REVOCATION_ENDPOINT);
    }

    #[test]
    fn name_returns_tiktok() {
        let tiktok = TikTok::new("cid", "secret", "https://app/cb");
        assert_eq!(tiktok.name(), "TikTok");
    }

    #[test]
    fn authorization_url_uses_client_key() {
        let tiktok = TikTok::new("cid", "secret", "https://app/cb");
        let url = tiktok.authorization_url("state123", &["user.info.basic"], "my-verifier");

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("client_key".into(), "cid".into())));
        // Should NOT contain client_id
        assert!(!pairs.iter().any(|(k, _)| k == "client_id"));
    }

    #[test]
    fn authorization_url_always_sends_scope() {
        let tiktok = TikTok::new("cid", "secret", "https://app/cb");
        // Even with empty scopes, scope param should be present
        let url = tiktok.authorization_url("state123", &[], "my-verifier");

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("scope".into(), "".into())));
    }

    #[test]
    fn authorization_url_uses_comma_delimited_scopes() {
        let tiktok = TikTok::new("cid", "secret", "https://app/cb");
        let url = tiktok.authorization_url("state123", &["user.info.basic", "video.list"], "v");

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("scope".into(), "user.info.basic,video.list".into())));
    }

    #[test]
    fn authorization_url_includes_pkce_params() {
        let tiktok = TikTok::new("cid", "secret", "https://app/cb");
        let url = tiktok.authorization_url("state123", &[], "my-verifier");

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.contains(&("state".into(), "state123".into())));
        assert!(pairs.contains(&("redirect_uri".into(), "https://app/cb".into())));
        assert!(pairs.iter().any(|(k, _)| k == "code_challenge"));
        assert!(pairs.contains(&("code_challenge_method".into(), "S256".into())));
    }

    #[tokio::test]
    async fn validate_authorization_code_uses_client_key_in_body() {
        let tiktok = TikTok::with_endpoints(
            "cid",
            "secret",
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
            None,
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "tt-tok",
                "token_type": "Bearer",
                "expires_in": 86400,
                "refresh_token": "tt-refresh"
            }))
            .unwrap(),
        }]);

        let tokens = tiktok
            .validate_authorization_code(&mock, "auth-code", "my-verifier")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "tt-tok");

        let requests = mock.take_requests();
        assert_eq!(requests[0].url, "https://mock/token");
        // No Authorization header (body credentials)
        assert!(get_header(&requests[0], "Authorization").is_none());

        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("grant_type".into(), "authorization_code".into())));
        assert!(body.contains(&("code".into(), "auth-code".into())));
        assert!(body.contains(&("client_key".into(), "cid".into())));
        assert!(body.contains(&("client_secret".into(), "secret".into())));
        assert!(body.contains(&("code_verifier".into(), "my-verifier".into())));
        assert!(body.contains(&("redirect_uri".into(), "https://app/cb".into())));
        // Should NOT contain client_id
        assert!(!body.iter().any(|(k, _)| k == "client_id"));
    }

    #[tokio::test]
    async fn validate_authorization_code_handles_error_as_200() {
        let tiktok = TikTok::with_endpoints(
            "cid",
            "secret",
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
            None,
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "error": "invalid_request",
                "error_description": "The code has expired."
            }))
            .unwrap(),
        }]);

        let err = tiktok
            .validate_authorization_code(&mock, "bad-code", "verifier")
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
    async fn validate_authorization_code_400_error() {
        let tiktok = TikTok::with_endpoints(
            "cid",
            "secret",
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
            None,
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 400,
            body: serde_json::to_vec(&serde_json::json!({
                "error": "invalid_grant",
                "error_description": "The code is invalid"
            }))
            .unwrap(),
        }]);

        let err = tiktok
            .validate_authorization_code(&mock, "code", "verifier")
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            Error::OAuthRequest { code, .. } if code == "invalid_grant"
        ));
    }

    #[tokio::test]
    async fn validate_authorization_code_unexpected_status() {
        let tiktok = TikTok::with_endpoints(
            "cid",
            "secret",
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
            None,
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 500,
            body: b"Internal Server Error".to_vec(),
        }]);

        let err = tiktok
            .validate_authorization_code(&mock, "code", "verifier")
            .await
            .unwrap_err();

        assert!(matches!(err, Error::UnexpectedResponse { status: 500 }));
    }

    #[tokio::test]
    async fn refresh_access_token_uses_client_key() {
        let tiktok = TikTok::with_endpoints(
            "cid",
            "secret",
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
            None,
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "new-tok",
                "token_type": "Bearer"
            }))
            .unwrap(),
        }]);

        let tokens = tiktok
            .refresh_access_token(&mock, "refresh-tok")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "new-tok");

        let requests = mock.take_requests();
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("grant_type".into(), "refresh_token".into())));
        assert!(body.contains(&("refresh_token".into(), "refresh-tok".into())));
        assert!(body.contains(&("client_key".into(), "cid".into())));
        assert!(body.contains(&("client_secret".into(), "secret".into())));
        assert!(!body.iter().any(|(k, _)| k == "client_id"));
    }

    #[tokio::test]
    async fn refresh_access_token_handles_error_as_200() {
        let tiktok = TikTok::with_endpoints(
            "cid",
            "secret",
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
            None,
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "error": "invalid_refresh_token",
                "error_description": "Refresh token is expired."
            }))
            .unwrap(),
        }]);

        let err = tiktok
            .refresh_access_token(&mock, "bad-refresh")
            .await
            .unwrap_err();

        match err {
            Error::OAuthRequest {
                code, description, ..
            } => {
                assert_eq!(code, "invalid_refresh_token");
                assert_eq!(
                    description.as_deref(),
                    Some("Refresh token is expired.")
                );
            }
            other => panic!("Expected OAuthRequest, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn revoke_token_uses_client_key() {
        let tiktok = TikTok::with_endpoints(
            "cid",
            "secret",
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
            Some("https://mock/revoke"),
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: vec![],
        }]);

        let result = tiktok.revoke_token(&mock, "tok-to-revoke").await;
        assert!(result.is_ok());

        let requests = mock.take_requests();
        assert_eq!(requests[0].url, "https://mock/revoke");
        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("token".into(), "tok-to-revoke".into())));
        assert!(body.contains(&("client_key".into(), "cid".into())));
        assert!(body.contains(&("client_secret".into(), "secret".into())));
        assert!(!body.iter().any(|(k, _)| k == "client_id"));
    }

    #[tokio::test]
    async fn revoke_token_non_200_returns_error() {
        let tiktok = TikTok::with_endpoints(
            "cid",
            "secret",
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
            Some("https://mock/revoke"),
        );
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 503,
            body: vec![],
        }]);

        let result = tiktok.revoke_token(&mock, "tok").await;
        assert!(matches!(
            result,
            Err(Error::UnexpectedResponse { status: 503 })
        ));
    }
}
