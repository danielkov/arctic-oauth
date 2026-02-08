# RFC-001: arctic-oauth v0.1.0

**Status**: Superseded in part
**Date**: 2026-02-07

> Note: The provider API strategy in this RFC has been superseded by
> `RFC-002-provider-specific-api.md`, which removes the shared provider trait
> in favor of provider-specific public APIs.

## Summary

`arctic-oauth` is a Rust crate that ports the design of [arctic](https://github.com/pilcrowonpaper/arctic) (v3.x), a popular TypeScript OAuth 2.0 authorization-code-flow client library with 60+ provider implementations. This RFC covers v0.1.0: core utilities, a testing harness, and the first 3 provider implementations (Google, GitHub, Discord).

---

## 1. Motivation

Arctic (JS) is popular because it is:

- **Focused**: authorization code flow only, no implicit/client-credentials grants.
- **Stateless**: generates PKCE verifiers and state tokens but does not store or verify them -- that is the application's job.
- **Minimal**: 3 dependencies (`@oslojs/crypto`, `@oslojs/encoding`, `@oslojs/jwt`), all by the same author. Uses the global `fetch` API directly.
- **Flat**: each provider is a self-contained ~50-150 line file. No deep abstraction hierarchy.

There is no equivalent in the Rust ecosystem. Existing Rust OAuth crates (`oxide-auth`, `oauth2`) are either server-side grant frameworks or generic clients that require the caller to configure every endpoint. Arctic's value is in shipping pre-configured, per-provider clients with spec-deviation handling baked in.

---

## 2. Design Principles

Carry over from the JS library:

1. **Authorization code flow only.** No implicit, client-credentials, or device-code grants.
2. **Stateless.** The library generates cryptographic values (state, PKCE verifiers) but never stores them. Storage and verification are application concerns.
3. **Per-provider correctness.** Each provider struct encodes the exact endpoints, authentication method, and spec deviations for that provider. The caller should not need to read the provider's OAuth docs.
4. **No session/token management.** The library returns token responses. Persistence, refresh scheduling, and session binding are out of scope.

Depart from the JS library where Rust idioms are stronger:

5. **Trait-based provider contract.** Arctic JS deliberately avoids a shared interface -- providers are duck-typed with varying method signatures. In Rust, we define an `OAuthProvider` trait to enable generic test harnesses and middleware integration. Provider-specific extensions (extra parameters, custom auth) are expressed through associated types and builder patterns, not by varying the method signature.
6. **Pluggable HTTP client via trait.** Arctic JS uses the global `fetch`. We accept any `HttpClient` implementation, defaulting to `reqwest`. This enables testing with a mock client and supports `no_std`-adjacent environments.

---

## 3. Architecture

### 3.1 Crate layout

```
arctic-oauth/
  Cargo.toml
  src/
    lib.rs                  # Public API re-exports, feature flags
    client.rs               # OAuth2Client -- the generic spec-compliant client
    tokens.rs               # OAuth2Tokens wrapper over token endpoint JSON
    pkce.rs                 # PKCE code_verifier / code_challenge generation
    state.rs                # Cryptographic state parameter generation
    request.rs              # HTTP request construction, credential encoding
    error.rs                # Error types
    oidc.rs                 # decodeIdToken (JWT payload decode, no verification)
    http.rs                 # HttpClient trait + reqwest default impl
    provider.rs             # OAuthProvider trait definition
    providers/
      mod.rs
      google.rs
      github.rs
      discord.rs
  tests/
    common/
      mod.rs                # Shared test utilities
      mock_server.rs        # Mock OAuth2 server (wiremock-based)
      mock_http_client.rs   # HttpClient impl that records/replays requests
    google_test.rs
    github_test.rs
    discord_test.rs
    oauth2_flow_test.rs     # Generic end-to-end flow tests parameterized over providers
```

### 3.2 Feature flags

```toml
[features]
default = ["reqwest-client"]
reqwest-client = ["dep:reqwest"]

# Provider features -- each provider is behind a feature flag so users
# only compile what they need. `all-providers` enables everything.
google   = []
github   = []
discord  = []
all-providers = ["google", "github", "discord"]
```

---

## 4. Core Modules

### 4.1 `error.rs`

Four error variants mirroring Arctic JS, mapped to a single enum:

```rust
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// OAuth2 error response (HTTP 400/401 with standard error JSON body).
    /// Per RFC 6749 Section 5.2.
    #[error("OAuth2 error: {code}")]
    OAuthRequest {
        code: String,              // e.g. "invalid_grant"
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
    UnexpectedErrorBody {
        status: u16,
        body: String,
    },

    /// Network / transport error from the HTTP client.
    #[error("HTTP request failed: {0}")]
    Http(#[from] Box<dyn std::error::Error + Send + Sync>),

    /// A required field is missing from the token response JSON.
    #[error("Missing or invalid field: {field}")]
    MissingField { field: &'static str },
}
```

### 4.2 `http.rs` -- Pluggable HTTP client

```rust
/// A minimal HTTP request representation (method is always POST for OAuth2).
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// A minimal HTTP response representation.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Trait for sending HTTP requests. Implementations must be `Send + Sync`
/// so they can be shared across async tasks.
pub trait HttpClient: Send + Sync {
    fn send(&self, request: HttpRequest) -> impl Future<Output = Result<HttpResponse, Box<dyn std::error::Error + Send + Sync>>> + Send;
}
```

The `reqwest-client` feature provides:

```rust
pub struct ReqwestClient {
    inner: reqwest::Client,
}

impl ReqwestClient {
    pub fn new() -> Self { /* ... */ }
}

impl HttpClient for ReqwestClient {
    async fn send(&self, req: HttpRequest) -> Result<HttpResponse, Box<dyn std::error::Error + Send + Sync>> {
        // Convert HttpRequest -> reqwest::Request, send, convert back
    }
}
```

### 4.3 `request.rs` -- Request construction

Mirrors `src/request.ts` from Arctic JS. All OAuth2 token requests are `POST` with `application/x-www-form-urlencoded` bodies.

```rust
/// Build a standard OAuth2 POST request.
/// Sets Content-Type, Accept: application/json, User-Agent: arctic-oauth.
pub fn create_oauth2_request(endpoint: &str, body: &[(String, String)]) -> HttpRequest;

/// Encode client credentials as HTTP Basic auth header value.
/// Returns `Basic <base64(client_id:client_secret)>`.
pub fn encode_basic_credentials(client_id: &str, client_secret: &str) -> String;

/// Send a token request and interpret the response.
/// - 200 -> Ok(OAuth2Tokens)
/// - 400/401 with valid error JSON -> Err(Error::OAuthRequest { .. })
/// - 400/401 with invalid body -> Err(Error::UnexpectedErrorBody { .. })
/// - Other status -> Err(Error::UnexpectedResponse { .. })
pub async fn send_token_request(
    client: &dyn HttpClient,
    request: HttpRequest,
) -> Result<OAuth2Tokens, Error>;
```

### 4.4 `pkce.rs`

```rust
/// PKCE code challenge method (RFC 7636).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeChallengeMethod {
    S256,
    Plain,
}

/// Generate a cryptographically random code verifier.
/// 32 random bytes, base64url-encoded without padding (43 chars).
pub fn generate_code_verifier() -> String;

/// Derive the code challenge from a verifier.
/// - S256: SHA-256 hash of verifier, base64url-encoded without padding.
/// - Plain: the verifier itself.
pub fn create_code_challenge(verifier: &str, method: CodeChallengeMethod) -> String;
```

Implementation: `rand::thread_rng().gen::<[u8; 32]>()` for randomness, `sha2::Sha256` for hashing, `base64::engine::general_purpose::URL_SAFE_NO_PAD` for encoding.

### 4.5 `state.rs`

```rust
/// Generate a cryptographically random state parameter.
/// 32 random bytes, base64url-encoded without padding.
pub fn generate_state() -> String;
```

Identical generation logic to `generate_code_verifier`. Separate function for semantic clarity.

### 4.6 `client.rs` -- `OAuth2Client`

The generic, spec-compliant OAuth2 client. Most providers delegate to it. Mirrors `src/client.ts` from Arctic JS.

```rust
pub struct OAuth2Client {
    client_id: String,
    /// None for public clients (credentials sent in body).
    /// Some for confidential clients (credentials sent via Basic auth).
    client_secret: Option<String>,
    redirect_uri: Option<String>,
}

impl OAuth2Client {
    pub fn new(
        client_id: impl Into<String>,
        client_secret: Option<String>,
        redirect_uri: Option<String>,
    ) -> Self;

    /// Build an authorization URL with standard parameters:
    /// response_type=code, client_id, state, scope (space-joined), redirect_uri.
    pub fn create_authorization_url(
        &self,
        authorization_endpoint: &str,
        state: &str,
        scopes: &[&str],
    ) -> url::Url;

    /// Build an authorization URL with PKCE parameters appended:
    /// code_challenge, code_challenge_method.
    pub fn create_authorization_url_with_pkce(
        &self,
        authorization_endpoint: &str,
        state: &str,
        code_challenge_method: CodeChallengeMethod,
        code_verifier: &str,
        scopes: &[&str],
    ) -> url::Url;

    /// Exchange an authorization code for tokens.
    pub async fn validate_authorization_code(
        &self,
        http_client: &dyn HttpClient,
        token_endpoint: &str,
        code: &str,
        code_verifier: Option<&str>,
    ) -> Result<OAuth2Tokens, Error>;

    /// Refresh an access token.
    pub async fn refresh_access_token(
        &self,
        http_client: &dyn HttpClient,
        token_endpoint: &str,
        refresh_token: &str,
        scopes: &[&str],
    ) -> Result<OAuth2Tokens, Error>;

    /// Revoke a token (RFC 7009).
    pub async fn revoke_token(
        &self,
        http_client: &dyn HttpClient,
        revocation_endpoint: &str,
        token: &str,
    ) -> Result<(), Error>;
}
```

**Credential transmission rules** (matching Arctic JS):

- `client_secret = Some(_)`: send `Authorization: Basic <base64(id:secret)>` header.
- `client_secret = None`: send `client_id` in the POST body (public client).

### 4.7 `tokens.rs` -- `OAuth2Tokens`

Thin wrapper around `serde_json::Value`. Each accessor returns `Result<T, Error>` instead of throwing (Arctic JS throws).

```rust
#[derive(Debug, Clone)]
pub struct OAuth2Tokens {
    data: serde_json::Value,
    /// Timestamp when the token response was received.
    /// Used to compute `access_token_expires_at`.
    received_at: std::time::SystemTime,
}

impl OAuth2Tokens {
    pub fn new(data: serde_json::Value) -> Self;

    /// The raw JSON response for provider-specific field access.
    pub fn data(&self) -> &serde_json::Value;

    pub fn token_type(&self) -> Result<&str, Error>;
    pub fn access_token(&self) -> Result<&str, Error>;
    pub fn access_token_expires_in_seconds(&self) -> Result<u64, Error>;
    pub fn access_token_expires_at(&self) -> Result<std::time::SystemTime, Error>;
    pub fn has_refresh_token(&self) -> bool;
    pub fn refresh_token(&self) -> Result<&str, Error>;
    pub fn has_scopes(&self) -> bool;
    pub fn scopes(&self) -> Result<Vec<String>, Error>;
    pub fn id_token(&self) -> Result<&str, Error>;
}
```

### 4.8 `oidc.rs`

Minimal OIDC support -- decode the JWT payload without signature verification (matching Arctic JS behavior, which delegates to `@oslojs/jwt`):

```rust
/// Decode an ID token (JWT) and return the payload claims.
/// This does NOT verify the signature. Signature verification is
/// the application's responsibility.
pub fn decode_id_token(id_token: &str) -> Result<serde_json::Value, Error>;
```

Implementation: split on `.`, base64url-decode the second segment, parse as JSON.

### 4.9 `provider.rs` -- `OAuthProvider` trait

This is the key departure from Arctic JS, which has no shared interface. We define a trait to enable generic testing and middleware, while keeping provider-specific configuration in constructors and builder methods.

```rust
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
        http_client: &dyn HttpClient,
        code: &str,
        code_verifier: Option<&str>,
    ) -> impl Future<Output = Result<OAuth2Tokens, Error>> + Send;

    /// Refresh an access token. Returns `Err` if the provider does not
    /// support refresh.
    fn refresh_access_token(
        &self,
        http_client: &dyn HttpClient,
        refresh_token: &str,
    ) -> impl Future<Output = Result<OAuth2Tokens, Error>> + Send;

    /// Whether this provider supports token revocation (RFC 7009).
    fn supports_token_revocation(&self) -> bool { false }

    /// Revoke a token. Default implementation returns an error.
    fn revoke_token(
        &self,
        http_client: &dyn HttpClient,
        token: &str,
    ) -> impl Future<Output = Result<(), Error>> + Send {
        let _ = (http_client, token);
        async { Err(Error::UnexpectedResponse { status: 501 }) }
    }
}
```

---

## 5. Provider Implementations

### 5.1 Google (`providers/google.rs`)

**Arctic JS reference**: `src/providers/google.ts`

Google uses the standard `OAuth2Client` delegation with required PKCE (S256). Supports token refresh and revocation. Returns OIDC `id_token`.

```
Authorization endpoint: https://accounts.google.com/o/oauth2/v2/auth
Token endpoint:         https://oauth2.googleapis.com/token
Revocation endpoint:    https://oauth2.googleapis.com/revoke
PKCE:                   Required (S256)
Auth method:            HTTP Basic (confidential client)
```

```rust
pub struct Google {
    client: OAuth2Client,
}

impl Google {
    pub fn new(client_id: impl Into<String>, client_secret: impl Into<String>, redirect_uri: impl Into<String>) -> Self;
}
```

Implements `OAuthProvider`. The `revoke_token` override sends a POST to the revocation endpoint with `token` in the body (Google-specific: uses POST with form body rather than the token in a query parameter).

### 5.2 GitHub (`providers/github.rs`)

**Arctic JS reference**: `src/providers/github.ts`

GitHub is a **custom implementation** that bypasses `OAuth2Client`. This is because GitHub returns OAuth2 error responses with HTTP 200 status codes, requiring custom response parsing logic.

```
Authorization endpoint: https://github.com/login/oauth/authorize
Token endpoint:         https://github.com/login/oauth/access_token
PKCE:                   None
Auth method:            HTTP Basic
```

```rust
pub struct GitHub {
    client_id: String,
    client_secret: String,
    redirect_uri: Option<String>,
}

impl GitHub {
    pub fn new(client_id: impl Into<String>, client_secret: impl Into<String>, redirect_uri: Option<String>) -> Self;
}
```

Implements `OAuthProvider`. Key deviation in `validate_authorization_code`: after receiving a 200 response, the body is parsed as JSON and checked for an `error` field. If present, it is treated as an `Error::OAuthRequest`. GitHub does not support token refresh or revocation via standard OAuth2 endpoints.

`refresh_access_token` returns `Err` (GitHub uses non-expiring tokens by default; GitHub Apps use a separate API).

### 5.3 Discord (`providers/discord.rs`)

**Arctic JS reference**: `src/providers/discord.ts`

Discord uses standard `OAuth2Client` delegation with optional PKCE. Supports both confidential and public clients. Supports token refresh and revocation.

```
Authorization endpoint: https://discord.com/oauth2/authorize
Token endpoint:         https://discord.com/api/oauth2/token
Revocation endpoint:    https://discord.com/api/oauth2/token/revoke
PKCE:                   Optional (S256)
Auth method:            HTTP Basic when client_secret is present; body credentials otherwise
```

```rust
pub struct Discord {
    client: OAuth2Client,
}

impl Discord {
    pub fn new(
        client_id: impl Into<String>,
        client_secret: Option<String>,
        redirect_uri: impl Into<String>,
    ) -> Self;
}
```

Implements `OAuthProvider` with `pkce_requirement() -> PkceRequirement::Optional`. Supports `revoke_token`.

---

## 6. Dependencies

```toml
[dependencies]
url = "2"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
sha2 = "0.10"
base64 = "0.22"
rand = "0.9"
thiserror = "2"
reqwest = { version = "0.12", features = ["json"], optional = true }

[dev-dependencies]
tokio = { version = "1", features = ["full"] }
wiremock = "0.6"
```

**Dependency rationale** (mapped from Arctic JS):

| Arctic JS                      | Rust crate                                | Purpose                                         |
| ------------------------------ | ----------------------------------------- | ----------------------------------------------- |
| `@oslojs/crypto` (SHA-256)     | `sha2`                                    | PKCE S256 code challenge                        |
| `@oslojs/encoding` (base64url) | `base64`                                  | Base64url encoding for PKCE, state, Basic auth  |
| `@oslojs/jwt` (JWT decode)     | manual (base64 + serde_json)              | ID token payload decoding (no signature verify) |
| `URL` / `URLSearchParams`      | `url`                                     | Authorization URL construction                  |
| `crypto.getRandomValues`       | `rand`                                    | Code verifier and state generation              |
| global `fetch`                 | `reqwest` (optional, behind feature flag) | Default HTTP client                             |
| (error handling)               | `thiserror`                               | Ergonomic error type derivation                 |

---

## 7. Test Suite Design

### 7.1 Goals

1. **Unit-test each core utility** (PKCE generation, state generation, URL construction, credential encoding, token response parsing).
2. **Integration-test the full authorization code flow** for each provider against a mock HTTP server.
3. **Make it trivial to add a new provider test** -- adding a provider should require only constructing the provider struct and calling a generic test harness.

### 7.2 Mock OAuth2 Server (`tests/common/mock_server.rs`)

Built on `wiremock`. Simulates a provider's token endpoint with configurable behavior.

```rust
pub struct MockOAuth2Server {
    server: wiremock::MockServer,
}

impl MockOAuth2Server {
    /// Start a new mock server.
    pub async fn start() -> Self;

    /// URL of the mock server (e.g. "http://127.0.0.1:PORT").
    pub fn url(&self) -> String;

    /// Mount a handler that returns a successful token response.
    pub async fn mock_token_success(&self, response: serde_json::Value);

    /// Mount a handler that returns an OAuth2 error response (HTTP 400).
    pub async fn mock_token_error(&self, error_code: &str, description: &str);

    /// Mount a handler that returns a successful token response but
    /// with HTTP 200 and an `error` field in the body (GitHub-style).
    pub async fn mock_token_error_as_200(&self, error_code: &str, description: &str);

    /// Mount a handler that returns a non-standard HTTP status.
    pub async fn mock_unexpected_status(&self, status: u16);

    /// Mount a handler for token revocation (returns 200 with empty body).
    pub async fn mock_revocation_success(&self);

    /// Assert that the last request to the token endpoint contained
    /// the expected form parameters.
    pub async fn verify_token_request(&self, expected_params: &[(&str, &str)]);

    /// Assert that the last request contained a Basic auth header
    /// with the expected credentials.
    pub async fn verify_basic_auth(&self, client_id: &str, client_secret: &str);
}
```

### 7.3 Mock HTTP Client (`tests/common/mock_http_client.rs`)

An `HttpClient` implementation that records requests and returns pre-configured responses. Used for unit-testing provider logic without a network server.

```rust
pub struct MockHttpClient {
    /// Pre-configured responses to return in order.
    responses: std::sync::Mutex<Vec<HttpResponse>>,
    /// Recorded requests for assertion.
    recorded: std::sync::Mutex<Vec<HttpRequest>>,
}

impl MockHttpClient {
    pub fn new() -> Self;
    pub fn enqueue_response(&self, response: HttpResponse);
    pub fn take_requests(&self) -> Vec<HttpRequest>;
}

impl HttpClient for MockHttpClient { /* ... */ }
```

### 7.4 Generic Flow Test Harness (`tests/oauth2_flow_test.rs`)

A parameterized test suite that exercises the full authorization-code flow against any `OAuthProvider`. Adding a new provider to the test suite requires only providing a constructor closure and expected endpoint configuration.

```rust
/// Configuration for a provider flow test.
struct ProviderFlowTestConfig {
    /// Name used in test output.
    name: &'static str,
    /// Construct the provider pointed at the mock server.
    make_provider: Box<dyn Fn(&str) -> Box<dyn OAuthProvider>>,
    /// Expected PKCE requirement.
    pkce: PkceRequirement,
    /// Whether the provider supports refresh.
    supports_refresh: bool,
    /// Whether the provider supports revocation.
    supports_revocation: bool,
    /// Additional assertions on the authorization URL.
    assert_auth_url: Option<Box<dyn Fn(&url::Url)>>,
}

/// Run the full flow test for a provider:
/// 1. Generate state (and code_verifier if PKCE).
/// 2. Build authorization URL; assert required parameters are present.
/// 3. Exchange code for tokens via mock server; assert correct request params.
/// 4. Parse token response; assert accessors work.
/// 5. Refresh token (if supported); assert correct request.
/// 6. Revoke token (if supported); assert correct request.
/// 7. Test error paths: OAuth2 error, unexpected status, malformed body.
async fn run_provider_flow_test(config: ProviderFlowTestConfig);
```

Each provider test file is concise:

```rust
// tests/google_test.rs
#[tokio::test]
async fn test_google_oauth2_flow() {
    run_provider_flow_test(ProviderFlowTestConfig {
        name: "Google",
        make_provider: Box::new(|mock_url| {
            // Google with mock endpoints
            Box::new(Google::with_endpoints(
                "client-id", "client-secret", "http://localhost/callback",
                &format!("{mock_url}/authorize"),
                &format!("{mock_url}/token"),
                Some(&format!("{mock_url}/revoke")),
            ))
        }),
        pkce: PkceRequirement::Required,
        supports_refresh: true,
        supports_revocation: true,
        assert_auth_url: None,
    }).await;
}
```

### 7.5 Provider test-endpoint overrides

To enable integration testing without hitting real OAuth servers, each provider exposes a `with_endpoints` constructor (or builder method) that overrides the hardcoded production endpoints with mock server URLs. These constructors are gated behind `#[cfg(test)]` or a `testing` feature flag so they are not part of the public API in release builds.

```rust
// Inside providers/google.rs
#[cfg(any(test, feature = "testing"))]
impl Google {
    pub fn with_endpoints(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
        authorization_endpoint: &str,
        token_endpoint: &str,
        revocation_endpoint: Option<&str>,
    ) -> Self;
}
```

### 7.6 Test cases per provider

Each provider's flow test covers:

| #   | Test case                             | What it validates                                                     |
| --- | ------------------------------------- | --------------------------------------------------------------------- |
| 1   | Authorization URL construction        | All required query params present; PKCE params if applicable          |
| 2   | Successful token exchange             | Correct POST body, correct auth header, `OAuth2Tokens` accessors work |
| 3   | Token exchange with OAuth2 error      | `Error::OAuthRequest` with correct code/description                   |
| 4   | Token exchange with unexpected status | `Error::UnexpectedResponse`                                           |
| 5   | Token exchange with malformed body    | `Error::UnexpectedErrorBody`                                          |
| 6   | Token refresh (if supported)          | Correct POST body, correct auth header                                |
| 7   | Token revocation (if supported)       | Correct POST body                                                     |
| 8   | GitHub-specific: error-as-200         | Body with `error` field on HTTP 200 treated as `Error::OAuthRequest`  |

### 7.7 Unit tests (in-module)

Each core module contains `#[cfg(test)] mod tests` with focused unit tests:

- `pkce.rs`: verifier length, S256 challenge correctness against known test vectors, Plain challenge passthrough.
- `state.rs`: length, base64url character set.
- `tokens.rs`: accessor behavior for present fields, missing fields, wrong types.
- `request.rs`: Basic auth encoding, request header construction, response status dispatch.
- `oidc.rs`: decoding a known JWT, handling malformed tokens.
- `client.rs`: URL parameter assembly for all combinations of PKCE/no-PKCE, scopes/no-scopes, redirect/no-redirect.

---

## 8. Public API Surface

```rust
// lib.rs re-exports

// Core
pub use client::OAuth2Client;
pub use tokens::OAuth2Tokens;
pub use error::Error;
pub use http::{HttpClient, HttpRequest, HttpResponse};
pub use provider::{OAuthProvider, PkceRequirement};

// Utilities
pub use pkce::{generate_code_verifier, create_code_challenge, CodeChallengeMethod};
pub use state::generate_state;
pub use oidc::decode_id_token;

// Default HTTP client (behind feature flag)
#[cfg(feature = "reqwest-client")]
pub use http::ReqwestClient;

// Providers (each behind its own feature flag)
#[cfg(feature = "google")]
pub use providers::google::Google;
#[cfg(feature = "github")]
pub use providers::github::GitHub;
#[cfg(feature = "discord")]
pub use providers::discord::Discord;
```

---

## 9. Provider-Specific Deviations

A central concern of the library is encoding provider-specific spec deviations so that callers don't need to know about them. The 3 initial providers each demonstrate a different pattern:

| Provider    | Deviation                                                | How it's handled                                                                                                                                                    |
| ----------- | -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Google**  | None -- fully spec-compliant                             | Delegates entirely to `OAuth2Client`                                                                                                                                |
| **GitHub**  | Returns OAuth2 errors with HTTP 200 status               | Custom `validate_authorization_code` that checks the response body for `error` field before returning success                                                       |
| **Discord** | Optional PKCE; optional `client_secret` (public clients) | `OAuth2Client` constructed with `client_secret: Option<String>`; `authorization_url` conditionally appends PKCE params based on whether `code_verifier` is provided |

These 3 providers cover the 3 most important implementation patterns from Arctic JS, providing a solid foundation for adding the remaining 60+ providers.

---

## 10. Usage Example

```rust
use arctic_oauth::{Google, OAuthProvider, generate_state, generate_code_verifier, ReqwestClient};

#[tokio::main]
async fn main() -> Result<(), arctic_oauth::Error> {
    let google = Google::new(
        "my-client-id",
        "my-client-secret",
        "http://localhost:3000/callback",
    );

    // 1. Generate state and PKCE verifier (store both in session/cookie)
    let state = generate_state();
    let code_verifier = generate_code_verifier();

    // 2. Build authorization URL and redirect user
    let auth_url = google.authorization_url(
        &state,
        &["openid", "email", "profile"],
        Some(&code_verifier),
    )?;
    println!("Redirect to: {auth_url}");

    // 3. After callback: exchange code for tokens
    let http = ReqwestClient::new();
    let tokens = google.validate_authorization_code(
        &http,
        "authorization-code-from-callback",
        Some(&code_verifier),
    ).await?;

    println!("Access token: {}", tokens.access_token()?);
    println!("ID token claims: {}", arctic_oauth::decode_id_token(tokens.id_token()?)?);

    // 4. Refresh
    if tokens.has_refresh_token() {
        let new_tokens = google.refresh_access_token(&http, tokens.refresh_token()?).await?;
        println!("New access token: {}", new_tokens.access_token()?);
    }

    Ok(())
}
```

---

## 11. Out of Scope for v0.1.0

- **Remaining 60+ providers.** Added incrementally in subsequent versions.
- **Token storage / session management.** Application concern.
- **OIDC discovery / ID token verification.** The library decodes but does not verify JWTs, matching Arctic JS behavior.
- **Implicit flow, client credentials flow, device code flow.** Only authorization code flow.
- **Apple provider.** Requires JWT-based client authentication (ES256 signing). Deferred to v0.2.0 to avoid pulling in `ring` or `p256` for the initial release.
- **Configurable-endpoint providers** (KeyCloak, Auth0, Okta, Microsoft Entra ID). Deferred until the core provider pattern is proven.
- **`no_std` support.** Not a goal for v0.1.0.

---

## 12. Resolved Design Decisions

1. **No `async-trait` crate.** Rust edition 2024 supports async fn in traits and `impl Future + Send` return positions natively. The `HttpClient` trait uses `fn send(...) -> impl Future<Output = ...> + Send` and `OAuthProvider` uses the same pattern. No proc-macro overhead.

2. **No blocking wrappers.** The library is async-only. Consumers who need blocking can use `tokio::runtime::Runtime::block_on` or equivalent at the call site. Shipping blocking wrappers adds API surface and a hard runtime dependency for no real gain.

3. **`&dyn HttpClient` (borrow).** Provider methods take `&dyn HttpClient`. Callers who need shared ownership wrap in `Arc` themselves. This keeps the library's API simple and avoids imposing allocation.

4. **One feature flag per provider.** Each provider gets its own feature flag. With 60+ providers planned, per-provider flags give consumers precise control over compile times and binary size. An `all-providers` convenience flag enables everything.

---

## 13. Implementation Order

| Phase | Deliverable                                                                           |
| ----- | ------------------------------------------------------------------------------------- |
| 1     | `error.rs`, `http.rs`, `request.rs` -- error types, HTTP abstraction, request helpers |
| 2     | `pkce.rs`, `state.rs` -- cryptographic utilities                                      |
| 3     | `tokens.rs`, `oidc.rs` -- token response wrapper, ID token decoding                   |
| 4     | `client.rs` -- generic `OAuth2Client`                                                 |
| 5     | `provider.rs` -- `OAuthProvider` trait                                                |
| 6     | `providers/google.rs` -- first provider (standard delegation + PKCE)                  |
| 7     | `providers/github.rs` -- custom implementation (error-as-200 handling)                |
| 8     | `providers/discord.rs` -- optional PKCE + optional client_secret                      |
| 9     | Test harness: `mock_server.rs`, `mock_http_client.rs`, `oauth2_flow_test.rs`          |
| 10    | Per-provider integration tests                                                        |
| 11    | `lib.rs` -- public re-exports, feature flags, documentation                           |
