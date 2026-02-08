mod client;
mod error;
mod http;
mod oidc;
mod pkce;
mod provider;
mod providers;
mod request;
mod state;
mod tokens;

// Core
pub use client::OAuth2Client;
pub use error::Error;
pub use http::{HttpClient, HttpRequest, HttpResponse};
pub use provider::{OAuthProvider, PkceRequirement};
pub use tokens::OAuth2Tokens;

// Utilities
pub use oidc::decode_id_token;
pub use pkce::{CodeChallengeMethod, create_code_challenge, generate_code_verifier};
pub use state::generate_state;

// Default HTTP client (behind feature flag)
#[cfg(feature = "reqwest-client")]
pub use http::ReqwestClient;

// Providers (each behind its own feature flag)
#[cfg(feature = "discord")]
pub use providers::discord::Discord;
#[cfg(feature = "github")]
pub use providers::github::GitHub;
#[cfg(feature = "google")]
pub use providers::google::Google;
