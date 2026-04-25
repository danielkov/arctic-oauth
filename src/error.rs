#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// OAuth2 error response (HTTP 400/401 with standard error JSON body).
    /// Per RFC 6749 Section 5.2.
    #[error("OAuth2 error: {code}")]
    OAuthRequest {
        code: String,
        description: Option<String>,
        uri: Option<String>,
        state: Option<String>,
    },

    /// Token endpoint returned a non-200/400/401 status.
    #[error("Unexpected HTTP status: {status}")]
    UnexpectedResponse { status: u16 },

    /// Token endpoint returned 400/401 but the body is not valid
    /// OAuth2 error JSON.
    #[error("Unparseable error response (HTTP {status})")]
    UnexpectedErrorBody { status: u16, body: String },

    /// Network / transport error from the HTTP client.
    #[error("HTTP request failed: {0}")]
    Http(#[from] Box<dyn std::error::Error + Send + Sync>),

    /// A required field is missing from the token response JSON.
    #[error("Missing or invalid field: {field}")]
    MissingField { field: &'static str },

    /// Authorization-response `iss` parameter (RFC 9207) did not match
    /// the configured issuer, or was missing when required.
    #[error("Issuer mismatch: expected {expected}, got {got:?}")]
    IssuerMismatch {
        expected: String,
        got: Option<String>,
    },

    /// Operation requires a confidential client but the client_secret is None.
    #[error("Operation requires a confidential client")]
    PublicClientNotAllowed,

    /// Authorization server does not advertise a required capability.
    #[error("Authorization server does not support {capability}")]
    UnsupportedByServer { capability: &'static str },

    /// Invalid resource indicator per RFC 8707.
    #[error("Invalid resource indicator: {value}")]
    InvalidResource { value: String },

    /// OAuth 2.1 client configuration is internally inconsistent
    /// (e.g. confidential client with `ClientAuthenticationMethod::None`).
    #[error("Invalid OAuth 2.1 client configuration: {reason}")]
    InvalidConfiguration { reason: &'static str },
}
