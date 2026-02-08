use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::Rng;

/// Generate a cryptographically random state parameter.
/// 32 random bytes, base64url-encoded without padding.
pub fn generate_state() -> String {
    let bytes: [u8; 32] = rand::rng().random();
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_is_43_characters() {
        let state = generate_state();
        assert_eq!(state.len(), 43);
    }

    #[test]
    fn only_contains_base64url_characters() {
        let state = generate_state();
        assert!(
            state
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "state contains invalid characters: {state}"
        );
    }

    #[test]
    fn successive_calls_produce_different_values() {
        let a = generate_state();
        let b = generate_state();
        assert_ne!(a, b, "two successive calls should produce different values");
    }
}
