//! Generic OAuth 2.1 client (`draft-ietf-oauth-v2-1`).
//!
//! See `docs/rfcs/RFC-005-oauth-2-1.md` for design notes.

mod auth_request;
mod callback;
mod client;
mod metadata;
mod registration;
mod resource;
mod resource_metadata;
mod token_request;

pub use auth_request::{AuthorizationRequest, AuthorizationUrl};
pub use callback::CallbackParams;
pub use client::{
    ClientAuthenticationMethod, IssuerPolicy, LoopbackHost, OAuth21Client, OAuth21Options,
    RedirectUri,
};
pub use metadata::AuthorizationServerMetadata;
pub use registration::{ClientRegistrationRequest, RegisteredClient, register_client};
pub use resource::Resource;
pub use resource_metadata::{
    ProtectedResourceMetadata, derive_well_known_url, parse_challenge_resource_metadata,
};
pub use token_request::{
    AuthorizationCodeGrant, ClientCredentialsGrant, RefreshTokenGrant, TokenIntrospection,
};
