use base64::Engine;
use p256::ecdsa::{SigningKey, signature::Signer};
use p256::pkcs8::DecodePrivateKey;

use crate::error::Error;
use crate::http::HttpClient;
use crate::request::{create_oauth2_request, send_token_request};
use crate::tokens::OAuth2Tokens;

const AUTHORIZATION_ENDPOINT: &str = "https://appleid.apple.com/auth/authorize";
const TOKEN_ENDPOINT: &str = "https://appleid.apple.com/auth/token";

pub struct Apple {
    client_id: String,
    team_id: String,
    key_id: String,
    signing_key: SigningKey,
    redirect_uri: String,
    authorization_endpoint: String,
    token_endpoint: String,
}

impl Apple {
    pub fn new(
        client_id: impl Into<String>,
        team_id: impl Into<String>,
        key_id: impl Into<String>,
        pkcs8_private_key: &[u8],
        redirect_uri: impl Into<String>,
    ) -> Result<Self, Error> {
        let signing_key = SigningKey::from_pkcs8_der(pkcs8_private_key)
            .map_err(|e| Error::Http(Box::new(e)))?;
        Ok(Self {
            client_id: client_id.into(),
            team_id: team_id.into(),
            key_id: key_id.into(),
            signing_key,
            redirect_uri: redirect_uri.into(),
            authorization_endpoint: AUTHORIZATION_ENDPOINT.to_string(),
            token_endpoint: TOKEN_ENDPOINT.to_string(),
        })
    }
}

#[cfg(any(test, feature = "testing"))]
impl Apple {
    pub fn with_endpoints(
        client_id: impl Into<String>,
        team_id: impl Into<String>,
        key_id: impl Into<String>,
        pkcs8_private_key: &[u8],
        redirect_uri: impl Into<String>,
        authorization_endpoint: &str,
        token_endpoint: &str,
    ) -> Result<Self, Error> {
        let signing_key = SigningKey::from_pkcs8_der(pkcs8_private_key)
            .map_err(|e| Error::Http(Box::new(e)))?;
        Ok(Self {
            client_id: client_id.into(),
            team_id: team_id.into(),
            key_id: key_id.into(),
            signing_key,
            redirect_uri: redirect_uri.into(),
            authorization_endpoint: authorization_endpoint.to_string(),
            token_endpoint: token_endpoint.to_string(),
        })
    }
}

impl Apple {
    pub fn name(&self) -> &'static str {
        "Apple"
    }

    pub fn authorization_url(&self, state: &str, scopes: &[&str]) -> url::Url {
        let mut url = url::Url::parse(&self.authorization_endpoint)
            .expect("invalid authorization endpoint URL");

        {
            let mut params = url.query_pairs_mut();
            params.append_pair("response_type", "code");
            params.append_pair("client_id", &self.client_id);
            params.append_pair("state", state);

            if !scopes.is_empty() {
                params.append_pair("scope", &scopes.join(" "));
            }

            params.append_pair("redirect_uri", &self.redirect_uri);
        }

        url
    }

    fn generate_client_secret(&self) -> String {
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;

        let header = serde_json::json!({
            "alg": "ES256",
            "kid": self.key_id
        });
        let header_encoded = b64.encode(header.to_string().as_bytes());

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before UNIX epoch")
            .as_secs();

        let claims = serde_json::json!({
            "iss": self.team_id,
            "sub": self.client_id,
            "aud": "https://appleid.apple.com",
            "iat": now,
            "exp": now + 300
        });
        let claims_encoded = b64.encode(claims.to_string().as_bytes());

        let signing_input = format!("{header_encoded}.{claims_encoded}");

        let signature: p256::ecdsa::Signature = self.signing_key.sign(signing_input.as_bytes());
        let signature_encoded = b64.encode(signature.to_bytes());

        format!("{signing_input}.{signature_encoded}")
    }

    pub async fn validate_authorization_code(
        &self,
        http_client: &(impl HttpClient + ?Sized),
        code: &str,
    ) -> Result<OAuth2Tokens, Error> {
        let client_secret = self.generate_client_secret();
        let body = vec![
            ("grant_type".to_string(), "authorization_code".to_string()),
            ("code".to_string(), code.to_string()),
            ("client_id".to_string(), self.client_id.clone()),
            ("client_secret".to_string(), client_secret),
            ("redirect_uri".to_string(), self.redirect_uri.clone()),
        ];

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

    /// Generate a test PKCS#8 DER-encoded P-256 private key.
    fn test_pkcs8_key() -> Vec<u8> {
        let signing_key = SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
        use p256::pkcs8::EncodePrivateKey;
        signing_key
            .to_pkcs8_der()
            .expect("failed to encode test key")
            .as_bytes()
            .to_vec()
    }

    #[test]
    fn new_sets_production_endpoints() {
        let key = test_pkcs8_key();
        let provider = Apple::new("cid", "team", "kid", &key, "https://app/cb").unwrap();
        assert_eq!(provider.authorization_endpoint, AUTHORIZATION_ENDPOINT);
        assert_eq!(provider.token_endpoint, TOKEN_ENDPOINT);
    }

    #[test]
    fn new_fails_with_invalid_pkcs8_key() {
        let result = Apple::new("cid", "team", "kid", b"not-a-valid-key", "https://app/cb");
        assert!(result.is_err());
    }

    #[test]
    fn name_returns_apple() {
        let key = test_pkcs8_key();
        let provider = Apple::new("cid", "team", "kid", &key, "https://app/cb").unwrap();
        assert_eq!(provider.name(), "Apple");
    }

    #[test]
    fn authorization_url_builds_correct_params() {
        let key = test_pkcs8_key();
        let provider = Apple::new("cid", "team", "kid", &key, "https://app/cb").unwrap();
        let url = provider.authorization_url("state123", &["name", "email"]);

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(pairs.contains(&("response_type".into(), "code".into())));
        assert!(pairs.contains(&("client_id".into(), "cid".into())));
        assert!(pairs.contains(&("state".into(), "state123".into())));
        assert!(pairs.contains(&("scope".into(), "name email".into())));
        assert!(pairs.contains(&("redirect_uri".into(), "https://app/cb".into())));
    }

    #[test]
    fn authorization_url_omits_scope_when_empty() {
        let key = test_pkcs8_key();
        let provider = Apple::new("cid", "team", "kid", &key, "https://app/cb").unwrap();
        let url = provider.authorization_url("state123", &[]);

        let pairs: Vec<(String, String)> = url.query_pairs().into_owned().collect();
        assert!(!pairs.iter().any(|(k, _)| k == "scope"));
    }

    #[test]
    fn generate_client_secret_has_valid_jwt_structure() {
        let key = test_pkcs8_key();
        let provider = Apple::new("cid", "TEAMID", "KEYID", &key, "https://app/cb").unwrap();
        let jwt = provider.generate_client_secret();

        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT must have 3 parts");

        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;

        // Verify header
        let header_bytes = b64.decode(parts[0]).expect("header should be valid base64url");
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["kid"], "KEYID");

        // Verify claims
        let claims_bytes = b64.decode(parts[1]).expect("claims should be valid base64url");
        let claims: serde_json::Value = serde_json::from_slice(&claims_bytes).unwrap();
        assert_eq!(claims["iss"], "TEAMID");
        assert_eq!(claims["sub"], "cid");
        assert_eq!(claims["aud"], "https://appleid.apple.com");
        assert!(claims["iat"].is_u64());
        assert!(claims["exp"].is_u64());

        let iat = claims["iat"].as_u64().unwrap();
        let exp = claims["exp"].as_u64().unwrap();
        assert_eq!(exp - iat, 300);

        // Verify signature is valid base64url (non-empty)
        let sig_bytes = b64.decode(parts[2]).expect("signature should be valid base64url");
        assert!(!sig_bytes.is_empty());
    }

    #[tokio::test]
    async fn validate_authorization_code_sends_body_credentials() {
        let key = test_pkcs8_key();
        let provider = Apple::with_endpoints(
            "cid",
            "team",
            "kid",
            &key,
            "https://app/cb",
            "https://mock/authorize",
            "https://mock/token",
        )
        .unwrap();
        let mock = MockHttpClient::new(vec![HttpResponse {
            status: 200,
            body: serde_json::to_vec(&serde_json::json!({
                "access_token": "apple-tok",
                "token_type": "bearer"
            }))
            .unwrap(),
        }]);

        let tokens = provider
            .validate_authorization_code(&mock, "auth-code")
            .await
            .unwrap();

        assert_eq!(tokens.access_token().unwrap(), "apple-tok");

        let requests = mock.take_requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url, "https://mock/token");

        // No Authorization header (body credentials, not Basic Auth)
        assert!(get_header(&requests[0], "Authorization").is_none());

        let body = parse_form_body(&requests[0]);
        assert!(body.contains(&("grant_type".into(), "authorization_code".into())));
        assert!(body.contains(&("code".into(), "auth-code".into())));
        assert!(body.contains(&("client_id".into(), "cid".into())));
        assert!(body.contains(&("redirect_uri".into(), "https://app/cb".into())));

        // client_secret should be present and be a JWT (3 dot-separated parts)
        let client_secret = body
            .iter()
            .find(|(k, _)| k == "client_secret")
            .expect("client_secret must be in body");
        let jwt_parts: Vec<&str> = client_secret.1.split('.').collect();
        assert_eq!(jwt_parts.len(), 3, "client_secret must be a JWT");
    }
}
