use std::future::Future;

use crate::error::Error;
use crate::http::HttpClient;
use crate::tokens::OAuth2Tokens;

/// Describes the PKCE behavior of a provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PkceRequirement {
    /// Provider does not support PKCE.
    None,
    /// Provider supports PKCE but does not require it.
    Optional,
    /// Provider requires PKCE.
    Required,
}

/// Core trait for OAuth2 providers.
///
/// This trait captures the common authorization-code flow operations.
/// Provider-specific parameters (e.g. Apple's team_id, KeyCloak's realm_url)
/// are set during construction and are not part of the trait.
pub trait OAuthProvider: Send + Sync {
    /// Human-readable provider name (e.g. "Google", "GitHub").
    fn name(&self) -> &'static str;

    /// The provider's PKCE requirement.
    fn pkce_requirement(&self) -> PkceRequirement;

    /// Build the authorization URL.
    ///
    /// `code_verifier` must be `Some` when `pkce_requirement()` is `Required`,
    /// must be `None` when it is `None`, and may be either when `Optional`.
    fn authorization_url(
        &self,
        state: &str,
        scopes: &[&str],
        code_verifier: Option<&str>,
    ) -> Result<url::Url, Error>;

    /// Exchange an authorization code for tokens.
    fn validate_authorization_code(
        &self,
        http_client: &(impl HttpClient + ?Sized),
        code: &str,
        code_verifier: Option<&str>,
    ) -> impl Future<Output = Result<OAuth2Tokens, Error>> + Send;

    /// Refresh an access token. Returns `Err` if the provider does not
    /// support refresh.
    fn refresh_access_token(
        &self,
        http_client: &(impl HttpClient + ?Sized),
        refresh_token: &str,
    ) -> impl Future<Output = Result<OAuth2Tokens, Error>> + Send;

    /// Whether this provider supports token revocation (RFC 7009).
    fn supports_token_revocation(&self) -> bool {
        false
    }

    /// Revoke a token. Default implementation returns an error.
    fn revoke_token(
        &self,
        http_client: &(impl HttpClient + ?Sized),
        token: &str,
    ) -> impl Future<Output = Result<(), Error>> + Send {
        let _ = (http_client, token);
        async { Err(Error::UnexpectedResponse { status: 501 }) }
    }
}
