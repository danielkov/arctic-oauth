# RFC-005: Generic OAuth 2.1 Client

**Status**: Draft
**Date**: 2026-04-25

## Summary

Add a generic OAuth 2.1 client to `arctic-oauth` so applications can talk to any OAuth 2.1-compliant authorization server without writing a bespoke provider module. The client reuses existing primitives (`OAuth2Client`, `pkce`, `state`, `OAuth2Tokens`, `HttpClient`) and follows the existing per-provider DX pattern, but is configured at runtime from endpoint URLs (or discovered via RFC 8414 metadata) rather than baked into source.

## Motivation

The crate currently exposes 64 provider-specific structs because real-world OAuth 2.0 deployments diverge from the spec in dozens of ways (PKCE optionality, error-as-200, scope delimiters, custom headers, JWT client auth, separate refresh endpoints, etc.). Each new provider is a copy-paste of ~150 lines.

OAuth 2.1 (`draft-ietf-oauth-v2-1-15`, 2026-03-02; obsoletes RFC 6749 and RFC 6750) deliberately removes the most common spec-deviation surface area. For an authorization server that _actually_ implements 2.1, a single generic client is sufficient — no per-provider module needed. Examples already in the crate that lean toward 2.1 today: KeyCloak, Auth0, Okta, Authentik, Salesforce, WorkOS, Microsoft Entra ID, Google. These will continue to ship as named providers (for setup ergonomics, branded docs, well-known endpoint defaults), but a `OAuth21Client` type lets users target self-hosted or future providers with no code changes to this crate.

References:

- Spec: <https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/>
- Summary: <https://oauth.net/2.1/>
- AS Metadata: RFC 8414
- Issuer ID in auth response: RFC 9207
- Resource Indicators: RFC 8707
- Token Revocation: RFC 7009
- Token Introspection: RFC 7662

## What OAuth 2.1 Constrains (Relative to RFC 6749)

This is what a 2.1 client can rely on, and what it MUST enforce:

1. **Three grants only:** `authorization_code`, `client_credentials`, `refresh_token`. Implicit and ROPC are removed. Device-code (`urn:ietf:params:oauth:grant-type:device_code`, RFC 8628) is an extension grant.
2. **PKCE is required.** Servers MUST reject auth requests from public clients without `code_challenge`, and MUST reject from confidential clients unless authorization-code injection is otherwise mitigated. Clients SHOULD always send PKCE.
3. **`S256` is mandatory-to-implement on the server**; if the client can do `S256`, it MUST use `S256`. `plain` exists only for constrained clients.
4. **Redirect URI matching is exact-string** (RFC 3986 §6.2.1 simple string comparison). Sole exception: native-app loopback URIs (`http://127.0.0.1` / `[::1]`) where port numbers may vary (RFC 8252 §7.3).
5. **Refresh tokens for public clients** MUST be either sender-constrained (DPoP / mTLS) or rotated (one-time use, AS replaces on each refresh, revokes the chain on replay).
6. **Bearer tokens** travel only via `Authorization: Bearer <token>` or `application/x-www-form-urlencoded` body. Query-string transport is banned.
7. **Token response** is JSON, HTTP 200, `Cache-Control: no-store`. Same field set as 6749.
8. **Token error response** is JSON HTTP 400/401, same code set as 6749. `invalid_request` semantics expanded to cover PKCE mismatches.
9. **Issuer parameter (RFC 9207)** in the authorization response is OPTIONAL but recommended for mix-up defense.
10. **Confidential client authentication differs from OAuth 2.0 practice.** OAuth 2.1 authorization servers MUST support `client_secret_post`; `client_secret_basic` is optional. A generic 2.1 client therefore cannot hard-code Basic auth.

## Non-Goals

1. Replace existing provider modules. Keycloak/Auth0/Okta/Google etc. stay where they are; some may internally adopt the 2.1 client later but that's out of scope.
2. Build server-side primitives (no AS, no resource server).
3. Implement DPoP (RFC 9449) or mTLS (RFC 8705). These belong behind their own future feature flags. The 2.1 client will emit and accept the wire shape such that adding them later is non-breaking.
4. Implement Pushed Authorization Requests (RFC 9126) or Rich Authorization Requests (RFC 9396). Same reasoning.
5. JWT signature verification for ID tokens. Same boundary as today (`oidc::decode_id_token`).

## Goals

1. One generic client (`OAuth21Client`) usable against any 2.1-conforming AS.
2. Optional endpoint discovery via RFC 8414 (`.well-known/oauth-authorization-server`) and OIDC `.well-known/openid-configuration`.
3. Zero new top-level dependencies. Reuse `url`, `serde_json`, `sha2`, `base64`, `rand`, existing `HttpClient`.
4. Encode 2.1's invariants in the type signature: PKCE always present, redirect URI required (or explicit loopback variant), no implicit/ROPC paths reachable.
5. Support optional 2.1-compatible extensions through additive parameters: resource indicators (`resource`), audience (`audience`), `iss` validation on callback, `prompt`/`login_hint`/`max_age`/`acr_values`/`ui_locales` from OIDC.
6. Stay stateless. Same as the rest of the crate.

## Design

### Module layout

```
src/
├── oauth2_1/
│   ├── mod.rs              # Public API re-exports
│   ├── client.rs           # OAuth21Client + OAuth21Options
│   ├── auth_request.rs     # AuthorizationRequest builder
│   ├── token_request.rs    # token-endpoint grant builders (code/refresh/cc)
│   ├── callback.rs         # CallbackParams parsing (code/state/iss/error)
│   ├── metadata.rs         # AuthorizationServerMetadata + RFC 8414 discovery
│   ├── resource.rs         # RFC 8707 Resource indicator type
│   └── grants.rs           # GrantType enum + extension-grant URI helpers
└── lib.rs                  # add: pub use oauth2_1::*;  behind `oauth2_1` feature
```

Feature gate: `oauth2_1` (off by default, enabled by `all-providers`). Ships in `0.3` alongside the `HttpRequest::method` field already added to support GET-based metadata discovery.

### Public API

```rust
// oauth2_1/client.rs

pub struct OAuth21Options<'a, H: HttpClient> {
    pub issuer: String,                       // base URL of the AS (used by RFC 9207 iss check)
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub revocation_endpoint: Option<String>,  // RFC 7009
    pub introspection_endpoint: Option<String>, // RFC 7662
    pub client_id: String,
    pub client_secret: Option<String>,        // None => public client
    pub client_auth_method: ClientAuthenticationMethod,
    pub issuer_policy: IssuerPolicy,
    pub redirect_uri: RedirectUri,            // see below
    pub http_client: &'a H,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAuthenticationMethod {
    /// Public client; token requests include `client_id` in the form body.
    None,
    /// OAuth 2.1 mandatory-to-support method for clients with a shared secret.
    /// Token requests include `client_id` and `client_secret` in the form body.
    ClientSecretPost,
    /// Optional method. Each credential is first form-encoded, then joined with
    /// `:`, base64-encoded, and sent as `Authorization: Basic ...`.
    ClientSecretBasic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssuerPolicy {
    /// Do not require `iss`, but reject the response if `iss` is present and mismatched.
    Optional,
    /// Require `iss` and reject missing or mismatched values. Used when RFC 9207
    /// support is configured or advertised in metadata.
    Required,
}

#[derive(Debug, Clone)]
pub enum RedirectUri {
    /// Exact-string redirect URI (the 2.1 default).
    Exact(String),
    /// Loopback URI per RFC 8252 §7.3. Port may vary at runtime.
    /// Encoded as `http://127.0.0.1:{port}{path}` or `http://[::1]:{port}{path}`.
    Loopback { host: LoopbackHost, port: u16, path: String },
}

#[derive(Debug, Clone, Copy)]
pub enum LoopbackHost { V4, V6 }

pub struct OAuth21Client<'a, H: HttpClient> {
    inner: OAuth2Client,                // reused for authorization URL construction only
    http_client: &'a H,
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    revocation_endpoint: Option<String>,
    introspection_endpoint: Option<String>,
    client_auth_method: ClientAuthenticationMethod,
    issuer_policy: IssuerPolicy,
}

impl<'a, H: HttpClient> OAuth21Client<'a, H> {
    pub fn from_options(options: OAuth21Options<'a, H>) -> Result<Self, Error>;

    /// Discover endpoints from the RFC 8414 well-known metadata URL derived
    /// from `issuer`. Falls back to OIDC discovery if requested.
    pub async fn discover(
        http_client: &'a H,
        issuer: &str,
        client_id: impl Into<String>,
        client_secret: Option<String>,
        redirect_uri: RedirectUri,
    ) -> Result<Self, Error>;

    pub fn authorization_request(&self) -> AuthorizationRequest<'_, H>;

    pub async fn validate_authorization_code(
        &self,
        params: AuthorizationCodeGrant<'_>,
    ) -> Result<OAuth2Tokens, Error>;

    pub async fn refresh_access_token(
        &self,
        params: RefreshTokenGrant<'_>,
    ) -> Result<OAuth2Tokens, Error>;

    pub async fn client_credentials(
        &self,
        params: ClientCredentialsGrant<'_>,
    ) -> Result<OAuth2Tokens, Error>;

    pub async fn revoke_token(&self, token: &str) -> Result<(), Error>;
    pub async fn introspect(&self, token: &str) -> Result<TokenIntrospection, Error>;
}
```

`from_options` validates the relationship between `client_secret` and `client_auth_method`: public clients must use `ClientAuthenticationMethod::None`; confidential clients must use either `ClientSecretPost` or `ClientSecretBasic`. Invalid combinations return `Error::InvalidConfiguration`.

### `AuthorizationRequest` builder

PKCE is always present. The verifier is generated unless the caller supplies one (so it can be persisted to session storage). The state is generated unless supplied. `S256` is the only supported method on the wire; `plain` is intentionally not exposed.

```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resource(url::Url);

impl Resource {
    /// Parse and validate an RFC 8707 resource indicator.
    /// The value must be an absolute URI and must not contain a fragment.
    pub fn parse(value: &str) -> Result<Self, Error>;
    pub fn as_str(&self) -> &str;
    pub fn into_url(self) -> url::Url;
}

pub struct AuthorizationRequest<'a, H: HttpClient> {
    client: &'a OAuth21Client<'a, H>,
    scopes: Vec<String>,
    state: Option<String>,
    code_verifier: Option<String>,
    resource: Vec<Resource>,         // RFC 8707, may repeat
    audience: Option<String>,
    prompt: Option<String>,
    login_hint: Option<String>,
    max_age: Option<u64>,
    acr_values: Vec<String>,
    ui_locales: Vec<String>,
    extra: Vec<(String, String)>,    // escape hatch for non-conformant ASes
}

impl<'a, H: HttpClient> AuthorizationRequest<'a, H> {
    pub fn scope(mut self, scope: impl Into<String>) -> Self;
    pub fn scopes<I, S>(mut self, scopes: I) -> Self where I: IntoIterator<Item = S>, S: Into<String>;
    pub fn state(mut self, state: impl Into<String>) -> Self;
    pub fn code_verifier(mut self, verifier: impl Into<String>) -> Self;
    pub fn resource(mut self, resource: Resource) -> Self;
    pub fn resource_url(mut self, resource: &str) -> Result<Self, Error>;
    pub fn prompt(mut self, prompt: impl Into<String>) -> Self;
    pub fn login_hint(mut self, hint: impl Into<String>) -> Self;
    pub fn extra_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self;
    pub fn build(self) -> AuthorizationUrl;
}

pub struct AuthorizationUrl {
    pub url: url::Url,
    pub state: String,
    pub code_verifier: String,    // 43-char base64url, store in session
}
```

The returned struct hands back `state` and `code_verifier` together with the URL so callers don't have to thread them separately. This is a small DX win over the pattern used in the existing per-provider modules.

### `validate_authorization_code` input

```rust
pub struct AuthorizationCodeGrant<'a> {
    pub code: &'a str,
    pub code_verifier: &'a str,
    pub resource: &'a [Resource],     // optional; same value(s) used at /authorize
}
```

The `resource` parameter is sent on the token request when the AS supports RFC 8707. If unused, no `resource` form pair is added. `Resource::parse` rejects relative URLs and URLs with fragments, matching RFC 8707.

### `CallbackParams` parsing

Helper to lift the redirect URL into typed fields and run the standard checks.

```rust
pub struct CallbackParams {
    pub code: String,
    pub state: String,
    pub iss: Option<String>,
}

impl CallbackParams {
    /// Parse the redirect URL. Returns `Err(Error::OAuthRequest)` if the AS
    /// returned an `error` parameter. Returns `Err(Error::IssuerMismatch)` if
    /// RFC 9207 validation fails under `issuer_policy`.
    pub fn parse(
        redirect_url: &url::Url,
        expected_state: &str,
        expected_iss: &str,
        issuer_policy: IssuerPolicy,
    ) -> Result<Self, Error>;
}
```

When metadata is used and `authorization_response_iss_parameter_supported` is `true`, `issuer_policy` is `Required` and a missing `iss` is rejected. If support is not advertised, `issuer_policy` is `Optional`: missing `iss` is accepted, but a present mismatched `iss` is still rejected by local policy.

### Refresh and client-credentials grants

```rust
pub struct RefreshTokenGrant<'a> {
    pub refresh_token: &'a str,
    pub scopes: &'a [&'a str],   // §6 RFC 6749: MUST be subset of original; AS may reject otherwise
    pub resource: &'a [Resource],
}

pub struct ClientCredentialsGrant<'a> {
    pub scopes: &'a [&'a str],
    pub resource: &'a [Resource],
    pub audience: Option<&'a str>,
}
```

Public clients calling `client_credentials` is rejected at compile/runtime per 2.1 §4.2 (client_credentials requires confidential clients). Implementation: `client_credentials()` returns `Err(Error::PublicClientNotAllowed)` if `client_secret` is `None`.

### Reuse of existing primitives

| 2.1 need                                                                                                                            | Existing module                                               | Action                                                         |
| ----------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- | -------------------------------------------------------------- |
| Auth URL with `code_challenge` (S256), `state`, `scope`, `redirect_uri`                                                             | `OAuth2Client::create_authorization_url_with_pkce`            | Reuse as-is.                                                   |
| Token form encoding and base HTTP request headers                                                                                   | `request::create_oauth2_request`                              | Reuse.                                                         |
| Client authentication, including `client_secret_post`, OAuth-compliant Basic encoding, and public-client `client_id` body parameter | `oauth2_1::token_request`                                     | New. Do not reuse existing `OAuth2Client` token helpers as-is. |
| Authorization-code, refresh, and client-credentials token request bodies with repeatable `resource` and optional `audience`         | `oauth2_1::token_request`                                     | New. Existing token helpers cannot express the 2.1 surface.    |
| Token response parsing (200 vs OAuth error vs unexpected)                                                                           | `request::send_token_request`                                 | Reuse.                                                         |
| `OAuth2Tokens` accessors                                                                                                            | `tokens.rs`                                                   | Reuse.                                                         |
| State generation                                                                                                                    | `state::generate_state`                                       | Reuse.                                                         |
| Verifier generation, S256 challenge                                                                                                 | `pkce::generate_code_verifier`, `pkce::create_code_challenge` | Reuse. `S256` only — `Plain` not exposed.                      |
| ID token payload decode                                                                                                             | `oidc::decode_id_token`                                       | Reuse.                                                         |

The new module is mostly composition. The genuinely new pieces are (a) the `AuthorizationRequest` builder with 2.1/OIDC parameters, (b) token request builders that understand 2.1 client authentication and extension parameters, and (c) RFC 8414 metadata discovery.

### Metadata (RFC 8414)

```rust
// oauth2_1/metadata.rs

#[derive(Debug, Clone, serde::Deserialize)]
pub struct AuthorizationServerMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub revocation_endpoint: Option<String>,
    pub introspection_endpoint: Option<String>,
    pub jwks_uri: Option<String>,
    pub scopes_supported: Option<Vec<String>>,
    pub response_types_supported: Vec<String>,
    pub grant_types_supported: Option<Vec<String>>,
    pub code_challenge_methods_supported: Option<Vec<String>>,
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    pub authorization_response_iss_parameter_supported: Option<bool>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

impl AuthorizationServerMetadata {
    pub async fn fetch(http: &impl HttpClient, issuer: &str) -> Result<Self, Error>;
    pub async fn fetch_oidc(http: &impl HttpClient, issuer: &str) -> Result<Self, Error>;

    /// Verify the AS advertises support for what we need. Returns
    /// `Err(Error::UnsupportedByServer { capability })` on failure.
    pub fn assert_supports_authorization_code_with_pkce_s256(&self) -> Result<(), Error>;

    /// Choose the token endpoint authentication method for this client.
    /// Confidential clients prefer `client_secret_post` because OAuth 2.1
    /// requires servers to support it. If metadata omits
    /// `token_endpoint_auth_methods_supported`, discovery still selects
    /// `client_secret_post` under OAuth 2.1 semantics. `client_secret_basic` is
    /// used only when explicitly configured or when metadata explicitly
    /// advertises Basic and does not advertise post.
    pub fn select_client_auth_method(
        &self,
        client_secret: Option<&str>,
    ) -> Result<ClientAuthenticationMethod, Error>;

    pub fn issuer_policy(&self) -> IssuerPolicy;
}
```

Discovery URLs:

- RFC 8414: derive the URL by inserting `/.well-known/oauth-authorization-server` before the issuer path. For example, issuer `https://example.com/issuer1` becomes `https://example.com/.well-known/oauth-authorization-server/issuer1`.
- OIDC: derive the URL according to OpenID Connect Discovery. For a path issuer, this appends `/.well-known/openid-configuration` after the issuer path, e.g. `https://example.com/issuer1/.well-known/openid-configuration`.

`OAuth21Client::discover` calls `fetch`, falls back to `fetch_oidc`, validates that `metadata.issuer` is an exact string match for the configured issuer, selects a client authentication method from metadata, sets `issuer_policy` from `authorization_response_iss_parameter_supported`, populates options, and constructs the client.

### Error model

New variants on `Error`:

```rust
pub enum Error {
    // ...existing...
    /// Authorization-response `iss` parameter did not match the configured issuer (RFC 9207).
    #[error("Issuer mismatch: expected {expected}, got {got:?}")]
    IssuerMismatch { expected: String, got: Option<String> },

    /// Operation requires a confidential client but the client_secret is None.
    #[error("Operation requires a confidential client")]
    PublicClientNotAllowed,

    /// Authorization server does not advertise required capability.
    #[error("Authorization server does not support {capability}")]
    UnsupportedByServer { capability: &'static str },

    /// Invalid resource indicator per RFC 8707.
    #[error("Invalid resource indicator: {value}")]
    InvalidResource { value: String },

    /// Manual configuration is internally inconsistent.
    #[error("Invalid OAuth 2.1 client configuration: {reason}")]
    InvalidConfiguration { reason: &'static str },
}
```

These are additive enum variants. Downstream code with non-exhaustive matches keeps compiling; exhaustive matches need updating, which is the standard cost of `enum Error` extensions in this crate today (`error.rs` is not `#[non_exhaustive]`). Recommendation: mark `Error` as `#[non_exhaustive]` as part of this RFC to make future variant additions non-breaking.

### Provider integration (optional follow-up)

For providers that already implement OAuth 2.1 cleanly (KeyCloak, Auth0, Okta, Authentik, WorkOS, Microsoft Entra ID), expose a method that hands back an `OAuth21Client` so application code can opt into the unified shape:

```rust
impl<'a, H: HttpClient> KeyCloak<'a, H> {
    pub fn as_oauth2_1(&self) -> OAuth21Client<'_, H>;
}
```

This keeps the named-provider DX (branded docs, `new()` shortcuts, well-known endpoint defaults) while letting libraries that consume arctic-oauth program against a single type. Implementing `as_oauth2_1` on every provider is out of scope for the initial RFC — start with KeyCloak as the proof point.

## Wire-Level Behavior (Authoritative)

For implementers of `OAuth21Client`:

**Authorization request (`GET <authorization_endpoint>?...`):**

- `response_type=code` (only)
- `client_id={client_id}`
- `redirect_uri={exact match | loopback with port}`
- `state={base64url 32-byte random}`
- `scope={space-joined}` (omitted if empty)
- `code_challenge={base64url(sha256(verifier))}`
- `code_challenge_method=S256`
- `resource={absolute URI}` (repeatable; RFC 8707; only when caller supplied)
- Optional OIDC: `prompt`, `login_hint`, `max_age`, `acr_values`, `ui_locales`
- Optional escape hatch: `extra_param(k, v)` pairs

**Token request (`POST <token_endpoint>`):**

- `Content-Type: application/x-www-form-urlencoded`
- `Accept: application/json`
- `User-Agent: arctic-oauth`
- Public: no `Authorization`; `client_id={client_id}` in body.
- Confidential with `ClientSecretPost`: no `Authorization`; `client_id={client_id}` and `client_secret={client_secret}` in body. This is the default for OAuth 2.1 clients with a shared secret.
- Confidential with `ClientSecretBasic`: `Authorization: Basic base64(form_urlencode(client_id):form_urlencode(client_secret))`; no `client_id` or `client_secret` in body. This is only used when explicitly configured or advertised.
- `grant_type=authorization_code` and `code={code}`, `code_verifier={verifier}`, `redirect_uri={...}`, `resource=...` (repeatable)
- Or `grant_type=refresh_token` and `refresh_token={...}`, `scope={...}`, `resource=...`
- Or `grant_type=client_credentials` and `scope={...}`, `resource=...`, `audience={...}` (confidential only)

**Token response handling:**

- 200 → parse JSON → `OAuth2Tokens`
- 400/401 with `error` field → `Error::OAuthRequest`
- 400/401 without parseable error → `Error::UnexpectedErrorBody`
- Other → `Error::UnexpectedResponse`

(Identical to existing `request::send_token_request` — no changes required.)

**Callback parsing:**

- If `error` present → `Error::OAuthRequest { code, description, uri, state }`
- If `state` ≠ expected → `Error::OAuthRequest { code: "invalid_state", ... }` (or a new variant; see open questions)
- If `IssuerPolicy::Required` and `iss` is missing → `Error::IssuerMismatch`
- If `iss` is present and does not exactly match the configured issuer → `Error::IssuerMismatch`
- Otherwise → `CallbackParams { code, state, iss }`

## Trade-offs

### Pros

- Single client for any 2.1-compliant AS — drops integration cost for self-hosted KeyCloak/Authentik/Okta/etc., and for any future 2.1 provider that doesn't yet have a named module.
- Encodes 2.1 invariants (mandatory PKCE, S256 only, exact redirect match, no implicit/ROPC) at the type level. Easier to use correctly than an open-ended OAuth 2.0 client.
- Reuses most existing primitives. New surface area is concentrated in the builder, token request construction, callback parser, and metadata discovery.
- Lays groundwork for future RFC support (DPoP, PAR, RAR, Resource Indicators) without forcing it now.

### Cons

- Ships in `0.3` (`HttpRequest::method` is the only mechanical break for downstream `HttpClient` impls).
- Adds a parallel idiom to the per-provider pattern. Application code now has two ways to talk to (e.g.) Keycloak — the named provider, or the generic 2.1 client. This is a feature for consumers but a documentation burden.
- Not all providers labelled "OAuth 2.1" actually implement the full draft (e.g. some skip RFC 9207). The client must degrade gracefully when `iss` is unconfigured.

## Open Questions

1. Should `Error` gain a dedicated `InvalidState` variant, or should mismatched-state surface as `OAuthRequest { code: "invalid_state", ... }`? Existing crate convention is "spec-defined error code → `OAuthRequest`", which suggests the latter, but state validation is a _client-side_ check, not an AS error.
2. Do we want `OAuth21Client` to take owned or borrowed config? The named providers take owned `String`s and a `&H`. Match that pattern.
3. For loopback redirect URIs, is the port resolved at `authorization_request().build()` time (caller passes it in), or set once at construction? The `RedirectUri::Loopback { port }` variant assumes the latter, which matches single-process native apps. A method like `with_loopback_port(u16)` could allow per-call override.
4. Should `discover` cache metadata? Out of scope for v1; document that callers should construct once and reuse.
5. Should we add `#[non_exhaustive]` to `Error` retroactively, or only to the new variants? Leaning toward a one-time breaking change to the whole enum.

## Resolved Design Decisions

1. **No new top-level dependencies.** Metadata struct uses existing `serde_json` + `serde`.
2. **`S256` only on the wire.** `Plain` exists in `pkce::CodeChallengeMethod` for legacy providers (e.g. MyAnimeList) but is not exposed through `OAuth21Client`.
3. **Stateless.** `AuthorizationRequest::build()` returns `state` and `code_verifier` for the caller to persist; the client holds neither.
4. **Behind an `oauth2_1` feature flag.** Off by default. Included in `all-providers`.
5. **Generic over `HttpClient`** like every named provider. No `dyn` boxing.
6. **Resource indicators are typed.** RFC 8707 `resource` values use `Resource`, a `url::Url`-backed type that rejects non-absolute URIs and fragments before request construction.
7. **Token requests use a new 2.1 builder.** The generic client does not delegate token request construction to `OAuth2Client` because the existing helpers cannot express `client_secret_post`, OAuth-compliant Basic encoding, client credentials, repeated `resource`, or `audience`.

## Runnable Examples

Because OAuth 2.1 is generic over the authorization server, a single example binary covers every supported provider. Ship one `examples/oauth2_1.rs` that takes a `--provider <name>` flag and runs the same flow against any of the providers in the table below.

Invocation:

```sh
CLIENT_ID=... CLIENT_SECRET=... cargo run --example oauth2_1 -- --provider linear
CLIENT_ID=... CLIENT_SECRET=... cargo run --example oauth2_1 -- --provider keycloak --issuer http://localhost:8080/realms/demo
```

Flow (identical for every provider):

1. Look up the selected provider in a static `PROVIDERS` table (endpoints, scopes, client-auth method, whether to use `discover()` instead of explicit endpoints).
2. Bind a TCP listener on `127.0.0.1:0` (OS-assigned port).
3. Use the resolved port to construct the loopback `redirect_uri` (`RedirectUri::Loopback { host: V4, port, path: "/callback".into() }`).
4. Construct `OAuth21Client` either from `from_options` or from `discover(issuer)` depending on the provider entry.
5. Call `OAuth21Client::authorization_request()`, build the URL, open it in the user's default browser.
6. Block the listener until the AS redirects back. Parse with `CallbackParams::parse`.
7. Exchange the code via `validate_authorization_code`. Print the access-token prefix (first 12 chars + `…`) and scope/expiry.
8. Sleep 5s. Call `refresh_access_token` with the returned refresh token. Print the new access-token prefix.
9. Sleep 5s. Call `revoke_token` on the refresh token (or the access token, depending on what the AS supports). Print "revoked".

Provider entries are a small `struct` — name, endpoints (or `Discover { issuer_default: Option<&str> }`), default scopes, client-auth method, any provider-specific quirks (e.g. Notion's rotated refresh tokens, GitHub's `DELETE /applications/{client_id}/grant` revoke shape). Adding a provider is one row in the table.

Credentials come from env: `CLIENT_ID`, `CLIENT_SECRET` (omit for public clients). Provider-specific overrides (e.g. `--issuer` for self-hosted Keycloak/Authentik, `--scopes`) are CLI flags.

### Candidate providers

Selection criteria: (a) OAuth 2.1-leaning (mandatory or strongly recommended PKCE, exact-string redirect matching, no implicit/ROPC), (b) documented refresh-token grant, (c) documented revocation endpoint (RFC 7009) — without (c) the example can't demonstrate the full lifecycle. Also prefer providers with a free developer tier and a loopback-redirect-friendly app registration.

**Tier 1 — full PKCE + refresh + revoke, ship in v1:**

| Provider                                | PKCE                             | Refresh                                                                   | Revoke (RFC 7009)                                                       | Metadata (RFC 8414)                                      | Notes                                                                                                                                           |
| --------------------------------------- | -------------------------------- | ------------------------------------------------------------------------- | ----------------------------------------------------------------------- | -------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| **Linear**                              | Supported (S256)                 | Yes; 30-min replay grace                                                  | `https://api.linear.app/oauth/revoke` (form `token`, `token_type_hint`) | No published well-known                                  | User-named in RFC scope. Confidential client; `client_secret_post`. Scopes: `read,write`.                                                       |
| **Notion**                              | Supported via SDK                | Yes; **rotated** every refresh                                            | `revoke` endpoint (client_id + client_secret + token)                   | No published well-known                                  | User-named. Confidential client. Note: refresh-token rotation invalidates the previous one — example must overwrite the stored token each loop. |
| **GitHub** (GitHub App, user-to-server) | S256 only (since 2025-07)        | Yes (GitHub Apps with refresh enabled; classic OAuth Apps do not refresh) | `DELETE /applications/{client_id}/grant` (Basic auth)                   | No                                                       | GitHub App preferred over OAuth App for the refresh half of the demo.                                                                           |
| **Spotify**                             | S256 mandatory (post-migration)  | Yes; rotated under PKCE                                                   | No revoke endpoint — user must revoke from account UI                   | No                                                       | Drop from Tier 1 unless we soften the "revoke" step. Move to Tier 2.                                                                            |
| **Keycloak** (self-hosted)              | Yes; OAuth 2.1 profile available | Yes                                                                       | Yes (`revocation_endpoint` in metadata)                                 | Yes (`/realms/{realm}/.well-known/openid-configuration`) | Best `discover()` proof point. Bundle a `docker-compose.yml` so `cargo run --example keycloak` works against a local realm with one command.    |
| **Authentik** (self-hosted)             | Yes                              | Yes                                                                       | Yes (`revocation_endpoint` in metadata)                                 | Yes                                                      | Same shape as Keycloak; one less dependency on hosted credentials.                                                                              |
| **Auth0**                               | Yes (default for public clients) | Yes                                                                       | Yes (`/oauth/revoke`)                                                   | Yes (`/.well-known/openid-configuration`)                | Free tenant. Good second `discover()` target — hosted, not self-hosted.                                                                         |
| **Okta** (Customer Identity Cloud)      | Yes                              | Yes                                                                       | Yes (`/oauth2/{authServer}/v1/revoke`)                                  | Yes                                                      | Developer-edition tenant.                                                                                                                       |

**Tier 2 — partial 2.1 conformance, useful as smoke tests but not flagship examples:**

- **Twitter/X**: PKCE + refresh (`offline.access` scope) + `oauth2/invalidate_token`. Aggressive rate limits and app-review friction make it a poor first-run experience. Keep behind a `--example x` opt-in.
- **Atlassian (Jira/Confluence 3LO)**: PKCE + rotating refresh + revoke. Tenant setup is heavy.
- **WorkOS**: OAuth + refresh; revoke story less prominent in docs. Worth revisiting once their 2.1 posture is clearer.

**Excluded (no revoke endpoint or no refresh):**

- Slack, Discord, Reddit, Google (no documented OAuth 2.0 token-revocation endpoint that fits RFC 7009 cleanly without provider-specific quirks). They can still be exercised by named provider modules; they're just not good demos for the full revoke half.

### Initial provider table

Seed `PROVIDERS` with these entries in v1, in this priority order:

1. **keycloak** — `discover(issuer)`. Proves RFC 8414, RFC 9207, full revoke. Bundle a `docker-compose.yml` so `cargo run --example oauth2_1 -- --provider keycloak` works against a local realm with one command.
2. **linear** — manual endpoints. Proves `from_options` + hosted AS + user-named provider in scope.
3. **notion** — manual endpoints. Proves rotated-refresh-token handling end-to-end (the example must overwrite the stored refresh token after step 8).
4. **auth0** — `discover(issuer)`. Proves discovery against a hosted AS without docker.

Adding more (Authentik, Okta, GitHub App, X, Atlassian) is a one-row PR against the table once v1 lands.

The example is not run by CI; it's for manual verification and as the canonical copy-pasteable starting point in docs.

### Dependencies for the example only

Add to `[dev-dependencies]`:

- `tokio` (already used by tests) — runtime.
- Hand-rolled `tokio::net::TcpListener` + minimal HTTP parser (~40 lines) for the callback server. Prefer this over pulling axum just to read one query string.
- `webbrowser` — opens the auth URL in the default browser. Tiny, no transitive bloat.
- A trivial arg parser (`std::env::args` is fine for `--provider` / `--issuer`; no need for `clap`).

These are dev-only; the crate itself stays at zero new top-level dependencies as stated in the Resolved Design Decisions.

## Implementation Order

| Phase | Deliverable                                                                                                                                                                                                                                                                |
| ----- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1     | Add `Error::IssuerMismatch`, `PublicClientNotAllowed`, `UnsupportedByServer`, `InvalidResource`, `InvalidConfiguration`. Mark `Error` `#[non_exhaustive]`. (`HttpRequest::method` already landed.)                                                                         |
| 2     | `oauth2_1::client::OAuth21Client` + `OAuth21Options` + `RedirectUri`. Authorization-code grant only.                                                                                                                                                                       |
| 3     | `oauth2_1::resource::Resource` and `oauth2_1::auth_request::AuthorizationRequest` builder.                                                                                                                                                                                 |
| 4     | `oauth2_1::callback::CallbackParams` with state + RFC 9207 issuer-policy validation.                                                                                                                                                                                       |
| 5     | `oauth2_1::token_request` — authorization-code, refresh, client_credentials, `client_secret_post`, OAuth-compliant `client_secret_basic`, repeatable `resource`, and `audience`.                                                                                           |
| 6     | Revocation + introspection delegating to existing helpers (introspection is a thin POST).                                                                                                                                                                                  |
| 7     | `oauth2_1::metadata` — RFC 8414 + OIDC discovery URL derivation, exact issuer validation, auth-method selection, issuer-policy selection, `OAuth21Client::discover`.                                                                                                       |
| 8     | Integration tests against mock AS using the existing `tests/common/mock_server.rs` harness; add 2.1-conformance scenarios covering PKCE-only, exact redirect match, loopback, path-issuer discovery, RFC 9207 iss roundtrip, client auth methods, and resource validation. |
| 9     | Optional: `KeyCloak::as_oauth2_1()` as the first named-provider bridge.                                                                                                                                                                                                    |
| 10    | Docs: README section + module-level rustdoc with end-to-end example.                                                                                                                                                                                                       |
