use crate::Error;
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone)]
pub struct OAuth2Tokens {
    data: serde_json::Value,
    received_at: SystemTime,
}

impl OAuth2Tokens {
    pub fn new(data: serde_json::Value) -> Self {
        Self {
            data,
            received_at: SystemTime::now(),
        }
    }

    pub fn data(&self) -> &serde_json::Value {
        &self.data
    }

    pub fn token_type(&self) -> Result<&str, Error> {
        self.data["token_type"].as_str().ok_or(Error::MissingField {
            field: "token_type",
        })
    }

    pub fn access_token(&self) -> Result<&str, Error> {
        self.data["access_token"]
            .as_str()
            .ok_or(Error::MissingField {
                field: "access_token",
            })
    }

    pub fn access_token_expires_in_seconds(&self) -> Result<u64, Error> {
        self.data["expires_in"].as_u64().ok_or(Error::MissingField {
            field: "expires_in",
        })
    }

    pub fn access_token_expires_at(&self) -> Result<SystemTime, Error> {
        let expires_in = self.access_token_expires_in_seconds()?;
        Ok(self.received_at + Duration::from_secs(expires_in))
    }

    pub fn has_refresh_token(&self) -> bool {
        self.data["refresh_token"].is_string()
    }

    pub fn refresh_token(&self) -> Result<&str, Error> {
        self.data["refresh_token"]
            .as_str()
            .ok_or(Error::MissingField {
                field: "refresh_token",
            })
    }

    pub fn has_scopes(&self) -> bool {
        self.data["scope"].is_string()
    }

    pub fn scopes(&self) -> Result<Vec<String>, Error> {
        let scope = self.data["scope"]
            .as_str()
            .ok_or(Error::MissingField { field: "scope" })?;
        Ok(scope.split(' ').map(String::from).collect())
    }

    pub fn id_token(&self) -> Result<&str, Error> {
        self.data["id_token"]
            .as_str()
            .ok_or(Error::MissingField { field: "id_token" })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn full_token_response() -> serde_json::Value {
        json!({
            "token_type": "Bearer",
            "access_token": "ya29.access-token-value",
            "expires_in": 3600,
            "refresh_token": "1//refresh-token-value",
            "scope": "openid email profile",
            "id_token": "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
        })
    }

    fn minimal_token_response() -> serde_json::Value {
        json!({
            "access_token": "access-token",
            "token_type": "Bearer"
        })
    }

    #[test]
    fn accessors_return_correct_values_for_present_fields() {
        let tokens = OAuth2Tokens::new(full_token_response());

        assert_eq!(tokens.token_type().unwrap(), "Bearer");
        assert_eq!(tokens.access_token().unwrap(), "ya29.access-token-value");
        assert_eq!(tokens.access_token_expires_in_seconds().unwrap(), 3600);
        assert_eq!(tokens.refresh_token().unwrap(), "1//refresh-token-value");
        assert_eq!(tokens.scopes().unwrap(), vec!["openid", "email", "profile"]);
        assert_eq!(
            tokens.id_token().unwrap(),
            "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature"
        );
    }

    #[test]
    fn accessors_return_missing_field_for_absent_fields() {
        let tokens = OAuth2Tokens::new(minimal_token_response());

        assert!(matches!(
            tokens.access_token_expires_in_seconds(),
            Err(Error::MissingField {
                field: "expires_in"
            })
        ));
        assert!(matches!(
            tokens.refresh_token(),
            Err(Error::MissingField {
                field: "refresh_token"
            })
        ));
        assert!(matches!(
            tokens.scopes(),
            Err(Error::MissingField { field: "scope" })
        ));
        assert!(matches!(
            tokens.id_token(),
            Err(Error::MissingField { field: "id_token" })
        ));
    }

    #[test]
    fn accessors_return_missing_field_for_wrong_types() {
        let tokens = OAuth2Tokens::new(json!({
            "token_type": 123,
            "access_token": true,
            "expires_in": "not_a_number",
            "refresh_token": 42,
            "scope": ["openid", "email"],
            "id_token": null
        }));

        assert!(matches!(
            tokens.token_type(),
            Err(Error::MissingField {
                field: "token_type"
            })
        ));
        assert!(matches!(
            tokens.access_token(),
            Err(Error::MissingField {
                field: "access_token"
            })
        ));
        assert!(matches!(
            tokens.access_token_expires_in_seconds(),
            Err(Error::MissingField {
                field: "expires_in"
            })
        ));
        assert!(matches!(
            tokens.refresh_token(),
            Err(Error::MissingField {
                field: "refresh_token"
            })
        ));
        assert!(matches!(
            tokens.scopes(),
            Err(Error::MissingField { field: "scope" })
        ));
        assert!(matches!(
            tokens.id_token(),
            Err(Error::MissingField { field: "id_token" })
        ));
    }

    #[test]
    fn has_refresh_token_returns_true_when_present() {
        let tokens = OAuth2Tokens::new(full_token_response());
        assert!(tokens.has_refresh_token());
    }

    #[test]
    fn has_refresh_token_returns_false_when_missing() {
        let tokens = OAuth2Tokens::new(minimal_token_response());
        assert!(!tokens.has_refresh_token());
    }

    #[test]
    fn has_refresh_token_returns_false_for_wrong_type() {
        let tokens = OAuth2Tokens::new(json!({ "refresh_token": 42 }));
        assert!(!tokens.has_refresh_token());
    }

    #[test]
    fn has_scopes_returns_true_when_present() {
        let tokens = OAuth2Tokens::new(full_token_response());
        assert!(tokens.has_scopes());
    }

    #[test]
    fn has_scopes_returns_false_when_missing() {
        let tokens = OAuth2Tokens::new(minimal_token_response());
        assert!(!tokens.has_scopes());
    }

    #[test]
    fn has_scopes_returns_false_for_wrong_type() {
        let tokens = OAuth2Tokens::new(json!({ "scope": ["openid"] }));
        assert!(!tokens.has_scopes());
    }

    #[test]
    fn scopes_splits_space_separated_string() {
        let tokens = OAuth2Tokens::new(json!({ "scope": "read write admin" }));
        assert_eq!(tokens.scopes().unwrap(), vec!["read", "write", "admin"]);
    }

    #[test]
    fn scopes_single_scope() {
        let tokens = OAuth2Tokens::new(json!({ "scope": "openid" }));
        assert_eq!(tokens.scopes().unwrap(), vec!["openid"]);
    }

    #[test]
    fn access_token_expires_at_computes_correctly() {
        let data = json!({ "expires_in": 3600 });
        let tokens = OAuth2Tokens::new(data);

        let expires_at = tokens.access_token_expires_at().unwrap();
        let expected = tokens.received_at + Duration::from_secs(3600);

        assert_eq!(expires_at, expected);
    }

    #[test]
    fn access_token_expires_at_errors_when_expires_in_missing() {
        let tokens = OAuth2Tokens::new(minimal_token_response());

        assert!(matches!(
            tokens.access_token_expires_at(),
            Err(Error::MissingField {
                field: "expires_in"
            })
        ));
    }

    #[test]
    fn data_returns_raw_json() {
        let data = full_token_response();
        let tokens = OAuth2Tokens::new(data.clone());
        assert_eq!(tokens.data(), &data);
    }
}
