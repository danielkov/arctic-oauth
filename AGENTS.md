# Codebase Overview

Rust port of [Arctic JS](https://github.com/pilcrowonpaper/arctic) — authorization-code-flow-only OAuth 2.0 client library with 64 pre-configured providers.

## Tech Stack

- **Rust** (edition 2024)
- Core deps: `url`, `serde`/`serde_json`, `sha2`, `base64`, `rand`, `thiserror`
- Optional deps: `reqwest` (HTTP client), `p256`/`ecdsa` (Apple Sign In)
- Test deps: `tokio`, `wiremock`

## Directory Structure

```
src/
├── lib.rs                  # Public API re-exports (feature-gated)
├── client.rs               # OAuth2Client — shared spec-compliant base
├── tokens.rs               # OAuth2Tokens — token response wrapper
├── error.rs                # Error enum (OAuthRequest, UnexpectedResponse, Http, etc.)
├── http.rs                 # HttpClient trait + ReqwestClient impl
├── pkce.rs                 # PKCE S256/Plain (RFC 7636)
├── state.rs                # CSRF state parameter generation
├── request.rs              # HTTP request building, Basic auth encoding
├── oidc.rs                 # JWT payload decoding (no signature verification)
└── providers/
    ├── mod.rs              # Module exports (64 providers)
    └── <provider>.rs       # One file per provider (e.g. google.rs, github.rs)

tests/
├── common/
│   ├── mock_server.rs      # WireMock-based OAuth2 mock server
│   └── mock_http_client.rs # HttpClient impl for testing
├── google_test.rs
├── github_test.rs
└── discord_test.rs

docs/rfcs/
├── RFC-001-arctic-oauth.md
├── RFC-002-provider-specific-api.md
└── RFC-003-remaining-providers.md
```

## Architecture

### Provider Pattern

Each provider is a standalone struct with a provider-specific public API (not trait-based). Method signatures encode actual requirements at compile time:

```rust
// PKCE required
Google::authorization_url(&self, state, scopes, code_verifier) -> Url
// No PKCE
GitHub::authorization_url(&self, state, scopes) -> Url
// PKCE optional
Discord::authorization_url(&self, state, scopes, code_verifier) -> Result<Url>
```

Common provider shape:

```rust
pub struct Provider {
    client: OAuth2Client,
    authorization_endpoint: String,
    token_endpoint: String,
    // ...
}

impl Provider {
    pub fn new(...) -> Self;
    #[cfg(any(test, feature = "testing"))]
    pub fn with_endpoints(...) -> Self;   // for mock testing
    pub fn authorization_url(...) -> Url;
    pub async fn validate_authorization_code(...) -> Result<OAuth2Tokens, Error>;
    pub async fn refresh_access_token(...) -> Result<OAuth2Tokens, Error>;
    pub async fn revoke_token(...) -> Result<(), Error>;
}
```

### Feature Flags

All 64 providers are feature-gated (e.g. `google`, `github`, `apple`). Convenience flag: `all-providers`. The `testing` feature enables `with_endpoints()` constructors. Default feature: `reqwest-client`.

### Key Design Decisions

- **Stateless** — no session store or token cache; apps control persistence
- **Provider-specific APIs over generic traits** — compile-time safety (RFC-002)
- **Pluggable HTTP client** — `HttpClient` trait with single async `send` method
- **Limited OIDC** — decodes JWT payload only; apps bring their own signature verification

## Commands

```bash
cargo test --all-features    # Run all tests
cargo build --all-features   # Build with all providers
```

## 64 Providers

Amazon Cognito, AniList, Apple, Atlassian, Auth0, Authentik, Autodesk, Battle.net, Bitbucket, Box, Bungie, Coinbase, Discord, Donation Alerts, Dribbble, Dropbox, Epic Games, Etsy, Facebook, Figma, 42 School, Gitea, GitHub, GitLab, Google, Intuit, Kakao, KeyCloak, Kick, Lichess, Line, Linear, LinkedIn, Mastodon, Mercado Libre, Mercado Pago, Microsoft Entra ID, MyAnimeList, Naver, Notion, Okta, osu!, Patreon, Polar, Reddit, Roblox, Salesforce, Shikimori, Slack, Spotify, start.gg, Strava, Synology, TikTok, Tiltify, Tumblr, Twitch, Twitter, VK, Withings, WorkOS, Yahoo, Yandex, Zoom.

### Notable Provider Quirks

- **Apple**: generates JWT client secret from private key (needs `team_id`, `key_id`, `certificate`)
- **Amazon Cognito, Auth0, Authentik, Gitea, GitLab, KeyCloak, Mastodon, Okta, Salesforce, Synology**: require a domain/base URL
- **GitHub, TikTok**: return OAuth errors with HTTP 200
- **Strava, Withings**: use comma-delimited scopes
- **Bungie**: requires `X-API-Key` header
- **MyAnimeList**: uses Plain PKCE (not S256)
- **Figma, start.gg**: separate refresh endpoint from token endpoint
