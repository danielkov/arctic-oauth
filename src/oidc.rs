use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::Error;

/// Decode an ID token (JWT) and return the payload claims.
/// This does NOT verify the signature. Signature verification is
/// the application's responsibility.
pub fn decode_id_token(id_token: &str) -> Result<serde_json::Value, Error> {
    let segments: Vec<&str> = id_token.split('.').collect();
    if segments.len() < 2 {
        return Err(Error::MissingField { field: "id_token" });
    }

    // Strip any padding characters before decoding with URL_SAFE_NO_PAD
    let payload = segments[1].trim_end_matches('=');

    let decoded = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| Error::MissingField { field: "id_token" })?;

    serde_json::from_slice(&decoded).map_err(|_| Error::MissingField { field: "id_token" })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: base64url-encode without padding.
    fn b64url(data: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(data)
    }

    /// Build a fake JWT from header and payload JSON strings.
    fn make_jwt(header: &str, payload: &str) -> String {
        format!(
            "{}.{}.fake-signature",
            b64url(header.as_bytes()),
            b64url(payload.as_bytes())
        )
    }

    #[test]
    fn decode_known_jwt() {
        let header = r#"{"alg":"RS256","typ":"JWT"}"#;
        let payload = r#"{"sub":"1234567890","name":"Jane Doe","iat":1516239022}"#;
        let token = make_jwt(header, payload);

        let claims = decode_id_token(&token).unwrap();
        assert_eq!(claims["sub"], "1234567890");
        assert_eq!(claims["name"], "Jane Doe");
        assert_eq!(claims["iat"], 1516239022);
    }

    #[test]
    fn malformed_token_no_dots() {
        let result = decode_id_token("not-a-jwt");
        assert!(result.is_err());
    }

    #[test]
    fn malformed_token_single_segment() {
        let result = decode_id_token("header-only");
        assert!(result.is_err());
    }

    #[test]
    fn invalid_base64_payload() {
        let result = decode_id_token("header.!!!invalid-base64!!!.signature");
        assert!(result.is_err());
    }

    #[test]
    fn invalid_json_in_payload() {
        // Valid base64url but not valid JSON
        let not_json = b64url(b"this is not json");
        let token = format!("header.{not_json}.signature");
        let result = decode_id_token(&token);
        assert!(result.is_err());
    }

    #[test]
    fn token_with_padded_base64() {
        // Some JWT libraries produce base64url with padding
        let header = r#"{"alg":"none"}"#;
        let payload = r#"{"sub":"test"}"#;
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload.as_bytes());
        // Add padding manually
        let padded = match payload_b64.len() % 4 {
            2 => format!("{payload_b64}=="),
            3 => format!("{payload_b64}="),
            _ => payload_b64,
        };
        let token = format!("{}.{padded}.sig", b64url(header.as_bytes()));

        let claims = decode_id_token(&token).unwrap();
        assert_eq!(claims["sub"], "test");
    }

    #[test]
    fn two_segment_token_no_signature() {
        let header = r#"{"alg":"none"}"#;
        let payload = r#"{"sub":"no-sig"}"#;
        // JWT with only header.payload (no signature segment)
        let token = format!(
            "{}.{}",
            b64url(header.as_bytes()),
            b64url(payload.as_bytes())
        );

        let claims = decode_id_token(&token).unwrap();
        assert_eq!(claims["sub"], "no-sig");
    }
}
