use url::Url;

use crate::error::Error;

use super::client::IssuerPolicy;

/// Authorization-response parameters lifted from the redirect URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallbackParams {
    pub code: String,
    pub state: String,
    pub iss: Option<String>,
}

impl CallbackParams {
    /// Parse the redirect URL into typed fields and run the standard checks.
    ///
    /// Returns
    ///
    /// - `Err(Error::OAuthRequest)` if the AS returned an `error` parameter,
    ///   or if `state` did not match `expected_state`.
    /// - `Err(Error::IssuerMismatch)` if RFC 9207 validation fails.
    pub fn parse(
        redirect_url: &Url,
        expected_state: &str,
        expected_iss: &str,
        issuer_policy: IssuerPolicy,
    ) -> Result<Self, Error> {
        let mut error: Option<String> = None;
        let mut error_description: Option<String> = None;
        let mut error_uri: Option<String> = None;
        let mut state: Option<String> = None;
        let mut code: Option<String> = None;
        let mut iss: Option<String> = None;

        for (k, v) in redirect_url.query_pairs() {
            match k.as_ref() {
                "error" => error = Some(v.into_owned()),
                "error_description" => error_description = Some(v.into_owned()),
                "error_uri" => error_uri = Some(v.into_owned()),
                "state" => state = Some(v.into_owned()),
                "code" => code = Some(v.into_owned()),
                "iss" => iss = Some(v.into_owned()),
                _ => {}
            }
        }

        if let Some(code) = error {
            return Err(Error::OAuthRequest {
                code,
                description: error_description,
                uri: error_uri,
                state,
            });
        }

        let state = state.ok_or(Error::OAuthRequest {
            code: "invalid_request".into(),
            description: Some("missing state parameter".into()),
            uri: None,
            state: None,
        })?;

        if state != expected_state {
            return Err(Error::OAuthRequest {
                code: "invalid_state".into(),
                description: Some("state parameter did not match expected value".into()),
                uri: None,
                state: Some(state),
            });
        }

        match (issuer_policy, iss.as_deref()) {
            (IssuerPolicy::Required, None) => {
                return Err(Error::IssuerMismatch {
                    expected: expected_iss.to_string(),
                    got: None,
                });
            }
            (_, Some(value)) if value != expected_iss => {
                return Err(Error::IssuerMismatch {
                    expected: expected_iss.to_string(),
                    got: Some(value.to_string()),
                });
            }
            _ => {}
        }

        let code = code.ok_or(Error::OAuthRequest {
            code: "invalid_request".into(),
            description: Some("missing code parameter".into()),
            uri: None,
            state: Some(state.clone()),
        })?;

        Ok(CallbackParams { code, state, iss })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(qs: &str) -> Url {
        Url::parse(&format!("https://app.example.com/cb?{qs}")).unwrap()
    }

    #[test]
    fn parses_happy_path() {
        let u = url("code=abc&state=st&iss=https%3A%2F%2Fas.example.com");
        let p = CallbackParams::parse(&u, "st", "https://as.example.com", IssuerPolicy::Required)
            .unwrap();
        assert_eq!(p.code, "abc");
        assert_eq!(p.state, "st");
        assert_eq!(p.iss.as_deref(), Some("https://as.example.com"));
    }

    #[test]
    fn iss_optional_missing_is_ok() {
        let u = url("code=abc&state=st");
        let p = CallbackParams::parse(&u, "st", "https://as.example.com", IssuerPolicy::Optional)
            .unwrap();
        assert!(p.iss.is_none());
    }

    #[test]
    fn iss_required_missing_is_error() {
        let u = url("code=abc&state=st");
        let err = CallbackParams::parse(&u, "st", "https://as.example.com", IssuerPolicy::Required)
            .unwrap_err();
        assert!(matches!(err, Error::IssuerMismatch { got: None, .. }));
    }

    #[test]
    fn iss_mismatch_is_error_under_optional_policy() {
        let u = url("code=abc&state=st&iss=https%3A%2F%2Fevil.example.com");
        let err = CallbackParams::parse(&u, "st", "https://as.example.com", IssuerPolicy::Optional)
            .unwrap_err();
        match err {
            Error::IssuerMismatch { expected, got } => {
                assert_eq!(expected, "https://as.example.com");
                assert_eq!(got.as_deref(), Some("https://evil.example.com"));
            }
            other => panic!("expected IssuerMismatch, got {other:?}"),
        }
    }

    #[test]
    fn returns_oauth_error_when_present() {
        let u = url("error=access_denied&error_description=user%20said%20no&state=st");
        let err = CallbackParams::parse(&u, "st", "https://as.example.com", IssuerPolicy::Optional)
            .unwrap_err();
        match err {
            Error::OAuthRequest {
                code, description, ..
            } => {
                assert_eq!(code, "access_denied");
                assert_eq!(description.as_deref(), Some("user said no"));
            }
            other => panic!("expected OAuthRequest, got {other:?}"),
        }
    }

    #[test]
    fn rejects_state_mismatch() {
        let u = url("code=abc&state=other");
        let err = CallbackParams::parse(
            &u,
            "expected",
            "https://as.example.com",
            IssuerPolicy::Optional,
        )
        .unwrap_err();
        match err {
            Error::OAuthRequest { code, .. } => assert_eq!(code, "invalid_state"),
            other => panic!("expected OAuthRequest, got {other:?}"),
        }
    }

    #[test]
    fn rejects_missing_state() {
        let u = url("code=abc");
        let err = CallbackParams::parse(
            &u,
            "expected",
            "https://as.example.com",
            IssuerPolicy::Optional,
        )
        .unwrap_err();
        assert!(matches!(err, Error::OAuthRequest { .. }));
    }

    #[test]
    fn rejects_missing_code() {
        let u = url("state=st");
        let err = CallbackParams::parse(&u, "st", "https://as.example.com", IssuerPolicy::Optional)
            .unwrap_err();
        match err {
            Error::OAuthRequest { code, .. } => assert_eq!(code, "invalid_request"),
            other => panic!("expected OAuthRequest, got {other:?}"),
        }
    }
}
