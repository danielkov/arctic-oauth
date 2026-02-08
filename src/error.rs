#[derive(Debug, thiserror::Error)]
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
}
