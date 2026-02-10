# RFC-004: HTTP Client Refactor

**Status**: Draft
**Date**: 2026-02-10

## Summary

Replace the `ReqwestClient` wrapper with a direct `impl HttpClient for reqwest::Client`. Move HTTP client ownership into provider structs at construction time. Provide a process-wide default `reqwest::Client` via `LazyLock` so that most users never need to construct or pass an HTTP client.

## Motivation

The current design has two friction points:

1. **Unnecessary wrapper type.** Users must construct a `ReqwestClient` (our wrapper around `reqwest::Client`) even though we own the `HttpClient` trait and can implement it directly for `reqwest::Client`. Users who already have a configured `reqwest::Client` must re-wrap it.

2. **HTTP client passed on every call.** Every method that makes an HTTP request (`validate_authorization_code`, `refresh_access_token`, `revoke_token`) takes `http_client` as a parameter. Since most users use reqwest with default settings, this is ceremony that adds nothing.

Before:

```rust
let google = Google::new("client-id", "secret", "https://example.com/cb");
let http = ReqwestClient::new();
let tokens = google.validate_authorization_code(&http, "code", "verifier").await?;
google.refresh_access_token(&http, "refresh-token").await?;
google.revoke_token(&http, "token").await?;
```

After:

```rust
let google = Google::new("client-id", "secret", "https://example.com/cb");
let tokens = google.validate_authorization_code("code", "verifier").await?;
google.refresh_access_token("refresh-token").await?;
google.revoke_token("token").await?;
```

## Design

### 1. Implement `HttpClient` for `reqwest::Client` directly

Remove the `ReqwestClient` wrapper struct. Implement the trait on the foreign type directly, which is permitted because we own `HttpClient`.

```rust
#[cfg(feature = "reqwest-client")]
impl HttpClient for reqwest::Client {
    async fn send(
        &self,
        req: HttpRequest,
    ) -> Result<HttpResponse, Box<dyn std::error::Error + Send + Sync>> {
        let mut builder = self.post(&req.url);
        for (name, value) in &req.headers {
            builder = builder.header(name, value);
        }
        builder = builder.body(req.body);
        let response = builder.send().await?;
        let status = response.status().as_u16();
        let body = response.bytes().await?.to_vec();
        Ok(HttpResponse { status, body })
    }
}
```

This is feature-gated behind `reqwest-client` (the default feature), same as the old wrapper.

### 2. Process-wide default client via `LazyLock`

A `LazyLock<reqwest::Client>` static is initialized once on first access. A public `default_client()` function returns `&'static reqwest::Client`.

```rust
#[cfg(feature = "reqwest-client")]
static DEFAULT_CLIENT: std::sync::LazyLock<reqwest::Client> =
    std::sync::LazyLock::new(reqwest::Client::new);

#[cfg(feature = "reqwest-client")]
pub fn default_client() -> &'static reqwest::Client {
    &DEFAULT_CLIENT
}
```

`LazyLock` is in `std` since Rust 1.80. The project targets edition 2024.

`reqwest::Client` is internally `Arc`-based, so `&'static reqwest::Client` is cheap and satisfies `HttpClient: Send + Sync`. A single static instance means all providers share one connection pool.

Users who need custom TLS, proxies, or timeouts use `from_options` with their own `reqwest::Client` (or any other `HttpClient` implementation).

### 3. Store HTTP client reference on provider structs

Provider structs become generic over the HTTP client and hold a borrowed reference:

```rust
pub struct AmazonCognito<'a, H: HttpClient> {
    client: OAuth2Client,
    http_client: &'a H,
    authorization_endpoint: String,
    token_endpoint: String,
    revocation_endpoint: String,
}
```

Methods no longer accept an `http_client` parameter. They use `self.http_client`:

```rust
pub async fn validate_authorization_code(
    &self,
    code: &str,
    code_verifier: &str,
) -> Result<OAuth2Tokens, Error> {
    self.client
        .validate_authorization_code(
            self.http_client,
            &self.token_endpoint,
            code,
            Some(code_verifier),
        )
        .await
}
```

### 4. Two construction paths: `new` and `from_options`

**`new` (simple path)** — feature-gated behind `reqwest-client`. Takes only provider-specific arguments. Uses `default_client()`. Returns `Provider<'static, reqwest::Client>`.

```rust
#[cfg(feature = "reqwest-client")]
impl AmazonCognito<'static, reqwest::Client> {
    pub fn new(
        domain: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: Option<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        Self::from_options(AmazonCognitoOptions {
            domain: domain.into(),
            client_id: client_id.into(),
            client_secret,
            redirect_uri: redirect_uri.into(),
            http_client: crate::http::default_client(),
        })
    }
}
```

**`from_options` (custom client path)** — always available, generic over `H: HttpClient`. Takes a provider-specific options struct that includes an `http_client` field.

```rust
impl<'a, H: HttpClient> AmazonCognito<'a, H> {
    pub fn from_options(options: AmazonCognitoOptions<'a, H>) -> Self {
        let domain = options.domain;
        Self {
            http_client: options.http_client,
            client: OAuth2Client::new(
                options.client_id,
                options.client_secret,
                Some(options.redirect_uri),
            ),
            authorization_endpoint: format!("https://{domain}/oauth2/authorize"),
            token_endpoint: format!("https://{domain}/oauth2/token"),
            revocation_endpoint: format!("https://{domain}/oauth2/revoke"),
        }
    }
}
```

### 5. Options struct per provider

Each provider gets a corresponding options struct with all configuration fields plus `http_client`:

```rust
pub struct AmazonCognitoOptions<'a, H: HttpClient> {
    pub domain: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_uri: String,
    pub http_client: &'a H,
}
```

Fields use `String` (not `impl Into<String>`) because struct fields require concrete types. The `new` constructor keeps `impl Into<String>` parameters for ergonomics on the simple path.

Options structs are re-exported from `lib.rs` alongside the provider types.

### 6. `impl` block organization per provider

Each provider file has three `impl` blocks:

1. **`impl<'a, H: HttpClient> Provider<'a, H>`** — `from_options` constructor.
2. **`#[cfg(feature = "reqwest-client")] impl Provider<'static, reqwest::Client>`** — `new` constructor.
3. **`impl<'a, H: HttpClient> Provider<'a, H>`** — all methods (`name`, `authorization_url`, `validate_authorization_code`, `refresh_access_token`, `revoke_token`).

### 7. Applying to all 64 providers

Providers fall into two internal patterns. Both get the same public API treatment.

**Pattern A (~33 providers):** Store `client: OAuth2Client`, delegate HTTP calls via `self.client.validate_authorization_code(self.http_client, ...)`. Examples: Google, Discord, Bungie, Spotify.

**Pattern B (~31 providers):** Store credentials directly, call `send_token_request(self.http_client, request)` or `self.http_client.send(request)` for custom response handling. Examples: GitHub, TikTok, Apple, Withings.

Both patterns change identically at the public API level. The only difference is internal: Pattern B providers pass `self.http_client` to `send_token_request` or `.send()` instead of through `OAuth2Client`.

Providers with private helper methods that currently take `http_client` as a parameter (e.g. TikTok's `parse_token_response`, Withings' custom response handling) should drop that parameter and use `self.http_client` directly, since the struct already holds the reference.

### 8. `OAuth2Client` internals unchanged

`OAuth2Client` methods keep their current signatures accepting `http_client: &(impl HttpClient + ?Sized)`. They are internal building blocks, not part of the public construction API. The provider is responsible for passing `self.http_client` into these methods.

### 9. `request.rs` unchanged

`send_token_request` keeps its current signature. It is a utility called by providers with the `http_client` they already hold.

### 10. `lib.rs` export changes

```rust
// Remove:
#[cfg(feature = "reqwest-client")]
pub use http::ReqwestClient;

// Add:
#[cfg(feature = "reqwest-client")]
pub use http::default_client;

// Each provider re-export gains its options struct:
#[cfg(feature = "amazon-cognito")]
pub use providers::amazon_cognito::{AmazonCognito, AmazonCognitoOptions};
```

### 11. Testing

**Unit tests** in each provider's `#[cfg(test)]` module use `from_options` with a local `MockHttpClient`, same as before. A `make_provider` test helper reduces boilerplate:

```rust
fn make_cognito(http_client: &MockHttpClient) -> AmazonCognito<'_, MockHttpClient> {
    AmazonCognito::from_options(AmazonCognitoOptions {
        domain: "mock.example.com".into(),
        client_id: "cid".into(),
        client_secret: Some("secret".into()),
        redirect_uri: "https://app/cb".into(),
        http_client,
    })
}
```

Test method calls no longer pass an HTTP client argument:

```rust
// Before:
cognito.validate_authorization_code(&mock, "code", "verifier").await

// After:
cognito.validate_authorization_code("code", "verifier").await
```

**Integration tests** (`tests/google_test.rs`, etc.) that previously created `ReqwestClient::new()` either use `Provider::new(...)` (which uses the default client) or pass `&reqwest::Client::new()` via `from_options`.

**`tests/common/mock_http_client.rs`** is unchanged. It implements `HttpClient` and is used in integration tests via `from_options`.

### 12. Doc examples

Every doc example that previously showed `ReqwestClient::new()` + passing `&http` on each call is simplified to use `Provider::new(...)` and call methods directly. The `from_options` path is shown on the options struct and `from_options` method docs.

## Breaking changes

This is a breaking change. Affected surface:

| What | Change |
|------|--------|
| `ReqwestClient` | Removed. Use `reqwest::Client` directly. |
| `Provider::new(...)` | No longer takes `http_client`. Uses default reqwest client. |
| Provider method signatures | `http_client` parameter removed from all methods. |
| Provider types | Now generic: `Provider<'a, H: HttpClient>`. |
| New types | `ProviderOptions<'a, H>` struct per provider. |
| New export | `default_client()` function. |

## Trade-offs

### Pros

- Simpler happy path: `new` + call methods, no HTTP client boilerplate.
- `reqwest::Client` works directly, no wrapper type to learn.
- Custom clients still fully supported via `from_options`.
- Shared connection pool for default users.

### Cons

- Provider types gain generic parameters (`<'a, H>`). In practice, users on the default path see `Provider<'static, reqwest::Client>` which is inferred.
- One options struct per provider (64 new types). These are simple data structs with no logic.
- `String` fields on options structs are slightly less ergonomic than `impl Into<String>` on `new()`.
