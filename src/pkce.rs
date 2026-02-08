use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::Rng as _;
use sha2::{Digest, Sha256};

/// PKCE code challenge method (RFC 7636).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeChallengeMethod {
    S256,
    Plain,
}

/// Generate a cryptographically random code verifier.
/// 32 random bytes, base64url-encoded without padding (43 chars).
pub fn generate_code_verifier() -> String {
    let bytes: [u8; 32] = rand::rng().random();
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Derive the code challenge from a verifier.
/// - S256: SHA-256 hash of verifier, base64url-encoded without padding.
/// - Plain: the verifier itself.
pub fn create_code_challenge(verifier: &str, method: CodeChallengeMethod) -> String {
    match method {
        CodeChallengeMethod::S256 => {
            let hash = Sha256::digest(verifier.as_bytes());
            URL_SAFE_NO_PAD.encode(hash)
        }
        CodeChallengeMethod::Plain => verifier.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifier_length_is_43() {
        let verifier = generate_code_verifier();
        assert_eq!(verifier.len(), 43);
    }

    #[test]
    fn verifier_contains_only_base64url_chars() {
        let verifier = generate_code_verifier();
        assert!(
            verifier
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
    }

    #[test]
    fn s256_challenge_known_test_vector() {
        // RFC 7636 Appendix B uses verifier "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        // Expected challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = create_code_challenge(verifier, CodeChallengeMethod::S256);
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn plain_challenge_returns_verifier_unchanged() {
        let verifier = "some-test-verifier-value";
        let challenge = create_code_challenge(verifier, CodeChallengeMethod::Plain);
        assert_eq!(challenge, verifier);
    }
}
