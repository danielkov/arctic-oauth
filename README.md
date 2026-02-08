# arctic-oauth

Rust-first OAuth 2.0 authorization-code client that ports the ergonomics of the [Arctic (TypeScript)](https://github.com/pilcrowonpaper/arctic) project to strongly typed, async Rust.

## Table of contents

- [Overview](#overview)
- [Why arctic-oauth?](#why-arctic-oauth)
- [Feature matrix](#feature-matrix)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Additional examples](#additional-examples)
- [Core building blocks](#core-building-blocks)
- [Use cases](#use-cases)
- [Trade-offs & limitations](#trade-offs--limitations)
- [Testing & quality](#testing--quality)
- [Roadmap](#roadmap)
- [Related documents](#related-documents)

## Overview

`arctic-oauth` focuses exclusively on the OAuth 2.0 authorization-code flow. It ships pre-configured, per-provider clients that know which parameters, endpoints, and PKCE requirements each provider expects. The crate is intentionally stateless: it generates things like PKCE code verifiers and CSRF state tokens, but storage, re-use, and signature verification always remain the application's responsibility.

## Why arctic-oauth?

- **Provider-aware clients.** Each provider struct encodes its production endpoints, HTTP authentication style, PKCE requirements, and spec deviations (e.g., GitHub returning OAuth errors with HTTP 200).
- **Minimal surface area.** The crate exposes a handful of core types (`OAuthProvider`, `OAuth2Client`, `OAuth2Tokens`, `HttpClient`) plus utilities for PKCE, CSRF state, and ID token decoding.
- **Bring-your-own HTTP stack.** Any async HTTP client that implements the lightweight `HttpClient` trait will work. A `reqwest` implementation is included behind the `reqwest-client` feature (enabled by default).
- **Stateless by design.** No session store, clock skew, or token cache assumptions. You control persistence and verification.
- **High test coverage.** Each module ships with unit tests, and every provider has an integration suite that drives mocked OAuth servers end-to-end.

## Feature matrix

| Capability                                          | Status                                |
| --------------------------------------------------- | ------------------------------------- |
| Authorization-code flow                             | ✅                                    |
| PKCE utilities (S256 + plain)                       | ✅                                    |
| State (anti-CSRF) generator                         | ✅                                    |
| ID token (JWT) payload decoding                     | ✅ (no signature verification)        |
| Pluggable HTTP client trait                         | ✅                                    |
| Built-in providers                                  | Google, GitHub, Discord (more coming) |
| Token refresh helpers                               | ✅ (per provider support)             |
| RFC 7009 token revocation                           | ✅ (where the provider supports it)   |
| Other grants (implicit, device, client credentials) | ❌ (out of scope)                     |

## Installation

Add the crate and opt into the providers you plan to ship:

```bash
cargo add arctic-oauth --features "google"
```

Feature flags:

| Flag                       | Enables                                                                                                                                      |
| -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `reqwest-client` (default) | `ReqwestClient`, a drop-in `HttpClient` backed by `reqwest`                                                                                  |
| `google`                   | `Google` provider exports                                                                                                                    |
| `github`                   | `GitHub` provider exports                                                                                                                    |
| `discord`                  | `Discord` provider exports                                                                                                                   |
| `all-providers`            | Convenience flag that enables `google`, `github`, and `discord`                                                                              |
| `testing`                  | Exposes constructors like `with_endpoints` outside of tests so you can point providers at custom OAuth servers in your own integration suite |

Disable the default HTTP client if you prefer to supply your own implementation:

```toml
# Cargo.toml
arctic-oauth = { version = "0.1", default-features = false, features = ["google"] }
```

```rust
use arctic_oauth::{HttpClient, HttpRequest, HttpResponse};
use std::future::Future;

struct MyClient { /* ... */ }

impl HttpClient for MyClient {
    fn send(&self, req: HttpRequest) -> impl Future<Output = Result<HttpResponse, Box<dyn std::error::Error + Send + Sync>>> + Send {
        async move {
            // translate HttpRequest into your HTTP stack
            todo!()
        }
    }
}
```

## Quick start

```rust
use arctic_oauth::{
    generate_code_verifier, generate_state, decode_id_token,
    Google, OAuthProvider, ReqwestClient,
};

#[tokio::main]
async fn main() -> Result<(), arctic_oauth::Error> {
    // 1. Configure the provider (Google requires PKCE + client secret)
    let google = Google::new(
        "google-client-id",
        "google-client-secret",
        "https://app.example.com/oauth/callback",
    );

    // 2. Generate anti-CSRF state + PKCE verifier and store them server-side
    let state = generate_state();
    let code_verifier = generate_code_verifier();

    // 3. Redirect the browser to the authorization URL
    let auth_url = google
        .authorization_url(&state, &["openid", "email", "profile"], Some(&code_verifier))?;
    println!("Redirect user to: {auth_url}");

    // 4. After the callback, exchange the authorization code for tokens
    let http = ReqwestClient::new();
    let tokens = google
        .validate_authorization_code(&http, "authorization-code", Some(&code_verifier))
        .await?;

    println!("access_token = {}", tokens.access_token()?);

    // 5. Optional helpers
    if tokens.has_refresh_token() {
        let refreshed = google
            .refresh_access_token(&http, tokens.refresh_token()?)
            .await?;
        println!("new access_token = {}", refreshed.access_token()?);
    }

    if tokens.has_scopes() {
        println!("scopes = {:?}", tokens.scopes()?);
    }

    let claims = decode_id_token(tokens.id_token()?)?;
    println!("ID token sub = {}", claims["sub"].as_str().unwrap_or("?"));

    Ok(())
}
```

## Additional examples

### Axum: cookie-backed PKCE/state (Google)

This example stores `oauth_state` and `oauth_code_verifier` in HttpOnly cookies before redirect, then validates both during callback.

```rust
use std::sync::Arc;

use arctic_oauth::{
    generate_code_verifier, generate_state, Google, OAuthProvider, ReqwestClient,
};
use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Redirect},
    routing::get,
    Router,
};
use axum_extra::extract::cookie::{Cookie, SameSite};
use axum_extra::extract::CookieJar;
use serde::Deserialize;

#[derive(Clone)]
struct AppState {
    google: Arc<Google>,
}

#[derive(Deserialize)]
struct OAuthCallback {
    code: String,
    state: String,
}

fn auth_cookie(name: &'static str, value: String) -> Cookie<'static> {
    let mut cookie = Cookie::new(name, value);
    cookie.set_path("/");
    cookie.set_http_only(true);
    cookie.set_secure(true);
    cookie.set_same_site(SameSite::Lax);
    cookie
}

fn expired_cookie(name: &'static str) -> Cookie<'static> {
    let mut cookie = Cookie::new(name, "");
    cookie.set_path("/");
    cookie.set_http_only(true);
    cookie.set_secure(true);
    cookie.set_same_site(SameSite::Lax);
    cookie.make_removal();
    cookie
}

async fn login(
    State(state): State<AppState>,
    jar: CookieJar,
) -> Result<(CookieJar, Redirect), (StatusCode, String)> {
    let oauth_state = generate_state();
    let code_verifier = generate_code_verifier();

    let auth_url = state
        .google
        .authorization_url(
            &oauth_state,
            &["openid", "email", "profile"],
            Some(&code_verifier),
        )
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let jar = jar
        .add(auth_cookie("oauth_state", oauth_state))
        .add(auth_cookie("oauth_code_verifier", code_verifier));

    Ok((jar, Redirect::to(auth_url.as_ref())))
}

async fn callback(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(query): Query<OAuthCallback>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let expected_state = jar
        .get("oauth_state")
        .map(|c| c.value().to_owned())
        .ok_or((StatusCode::BAD_REQUEST, "missing oauth_state cookie".into()))?;

    if expected_state != query.state {
        return Err((StatusCode::BAD_REQUEST, "invalid oauth state".into()));
    }

    let code_verifier = jar
        .get("oauth_code_verifier")
        .map(|c| c.value().to_owned())
        .ok_or((StatusCode::BAD_REQUEST, "missing code verifier cookie".into()))?;

    let http = ReqwestClient::new();
    let tokens = state
        .google
        .validate_authorization_code(&http, &query.code, Some(&code_verifier))
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;
    let access_token = tokens
        .access_token()
        .map_err(|e| (StatusCode::BAD_GATEWAY, e.to_string()))?;

    // Persist app session here (database, encrypted cookie, etc.).
    let jar = jar
        .remove(expired_cookie("oauth_state"))
        .remove(expired_cookie("oauth_code_verifier"))
        .add(auth_cookie("session_user", access_token.to_string()));

    Ok((jar, Redirect::to("/dashboard")))
}

fn app() -> Router {
    let state = AppState {
        google: Arc::new(Google::new(
            "google-client-id",
            "google-client-secret",
            "http://localhost:3000/auth/google/callback",
        )),
    };

    Router::new()
        .route("/auth/google", get(login))
        .route("/auth/google/callback", get(callback))
        .with_state(state)
}
```

### Actix Web: cookie-backed PKCE/state (Google)

Same flow as Axum, but using `HttpRequest::cookie` and `HttpResponse` cookie builders.

```rust
use arctic_oauth::{
    generate_code_verifier, generate_state, Google, OAuthProvider, ReqwestClient,
};
use actix_web::{
    cookie::{
        time::Duration,
        Cookie, SameSite,
    },
    get,
    http::header,
    web, App, HttpRequest, HttpResponse, HttpServer, Responder,
};
use serde::Deserialize;

struct AppState {
    google: Google,
}

#[derive(Deserialize)]
struct OAuthCallback {
    code: String,
    state: String,
}

fn auth_cookie(name: &'static str, value: String) -> Cookie<'static> {
    Cookie::build(name, value)
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .finish()
}

fn expired_cookie(name: &'static str) -> Cookie<'static> {
    Cookie::build(name, "")
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .max_age(Duration::seconds(0))
        .finish()
}

#[get("/auth/google")]
async fn login(state: web::Data<AppState>) -> Result<HttpResponse, actix_web::Error> {
    let oauth_state = generate_state();
    let code_verifier = generate_code_verifier();

    let auth_url = state
        .google
        .authorization_url(
            &oauth_state,
            &["openid", "email", "profile"],
            Some(&code_verifier),
        )
        .map_err(actix_web::error::ErrorInternalServerError)?;

    Ok(HttpResponse::Found()
        .append_header((header::LOCATION, auth_url.to_string()))
        .cookie(auth_cookie("oauth_state", oauth_state))
        .cookie(auth_cookie("oauth_code_verifier", code_verifier))
        .finish())
}

#[get("/auth/google/callback")]
async fn callback(
    state: web::Data<AppState>,
    req: HttpRequest,
    query: web::Query<OAuthCallback>,
) -> Result<impl Responder, actix_web::Error> {
    let expected_state = req
        .cookie("oauth_state")
        .map(|c| c.value().to_owned())
        .ok_or_else(|| actix_web::error::ErrorBadRequest("missing oauth_state cookie"))?;

    if expected_state != query.state {
        return Err(actix_web::error::ErrorBadRequest("invalid oauth state"));
    }

    let code_verifier = req
        .cookie("oauth_code_verifier")
        .map(|c| c.value().to_owned())
        .ok_or_else(|| actix_web::error::ErrorBadRequest("missing code verifier cookie"))?;

    let http = ReqwestClient::new();
    let tokens = state
        .google
        .validate_authorization_code(&http, &query.code, Some(&code_verifier))
        .await
        .map_err(actix_web::error::ErrorBadGateway)?;
    let access_token = tokens
        .access_token()
        .map_err(actix_web::error::ErrorBadGateway)?;

    Ok(HttpResponse::Found()
        .append_header((header::LOCATION, "/dashboard"))
        .cookie(expired_cookie("oauth_state"))
        .cookie(expired_cookie("oauth_code_verifier"))
        .cookie(auth_cookie("session_user", access_token.to_string()))
        .finish())
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let state = web::Data::new(AppState {
        google: Google::new(
            "google-client-id",
            "google-client-secret",
            "http://localhost:8080/auth/google/callback",
        ),
    });

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .service(login)
            .service(callback)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
```

Cookie persistence notes:

- Use encrypted/signed cookie storage for real session state (for example, `axum-extra` `PrivateCookieJar` or Actix `SessionMiddleware`).
- Keep OAuth helper cookies short-lived and clear them immediately after callback.
- Always set `HttpOnly`, `Secure`, and an explicit `SameSite` policy.

## Core building blocks

- **`OAuthProvider` trait.** Normalizes how you construct authorization URLs, exchange codes, refresh tokens, and (optionally) revoke them. Each provider implements its own PKCE rules through `PkceRequirement`.
- **`OAuth2Client`.** Spec-compliant helper that most providers embed. It understands when to send credentials via HTTP Basic versus form body and automatically injects PKCE parameters.
- **`HttpClient` trait.** Minimal abstraction with a single asynchronous `send` method. Ship your own implementation or rely on the built-in `ReqwestClient`.
- **`OAuth2Tokens`.** Convenience wrapper around the raw JSON response. Provides typed accessors (`access_token()`, `scopes()`, `access_token_expires_at()`, etc.) and exposes the original `serde_json::Value` for provider-specific attributes.
- **Utilities.** `generate_state`, `generate_code_verifier`, `create_code_challenge`, and `decode_id_token` let you reproduce the ergonomic helpers from Arctic JS without dragging in heavyweight crypto dependencies.

### Provider capabilities

| Provider | Feature flag | PKCE requirement | Refresh support | Revocation | Notes                                                                  |
| -------- | ------------ | ---------------- | --------------- | ---------- | ---------------------------------------------------------------------- |
| Google   | `google`     | Required (S256)  | ✅              | ✅         | Returns OIDC `id_token`, uses HTTP Basic auth                          |
| GitHub   | `github`     | Not supported    | ❌              | ❌         | Automatically interprets OAuth errors even when returned with HTTP 200 |
| Discord  | `discord`    | Optional         | ✅              | ✅         | Works for public (no secret) and confidential clients                  |

Use the `testing` feature (or plain `cargo test`) to access helper constructors such as `Google::with_endpoints` for pointing providers at mock OAuth servers.

## Use cases

- Implement "Sign in with Google/GitHub/Discord" in async Rust web frameworks (Axum, Actix, Poem, etc.).
- Embed OAuth-backed desktop or CLI flows where you control the HTTP client stack and want deterministic mocks in tests.
- Port TypeScript/Node.js apps that already rely on Arctic's behavior to a Rust backend without re-learning every provider's quirks.
- Build middleware or SDKs that expose a higher-level authentication abstraction by programming against the `OAuthProvider` trait.

## Trade-offs & limitations

- **Authorization-code flow only.** There are no helpers for implicit, device-code, or client-credentials grants.
- **Stateless utilities.** The crate never stores PKCE verifiers, CSRF state, or refresh tokens; you must persist and validate them.
- **No JWT signature verification.** `decode_id_token` only base64url-decodes the payload. Bring your own JOSE/JWK validation if you need it.
- **Limited provider catalog (for now).** v0.1 ships Google, GitHub, and Discord. Refer to the roadmap below for expansion plans.
- **Async-only.** There is no blocking API surface; call sites should run inside an async runtime.
- **No automatic retries/backoff.** Error handling is explicit so you can plug in your own policies.

## Testing & quality

- Run `cargo test --all-features` to execute every unit test plus the provider flow suites (they spin up mock OAuth servers via `wiremock`).
- Each provider-specific test module (`tests/google_test.rs`, etc.) reuses a shared `provider_flow_tests!` macro so new providers inherit the same behavioral coverage automatically.
- A complete architecture + rationale document lives in [`RFC-001-arctic-oauth.md`](./docs/rfcs/RFC-001-arctic-oauth.md). Use it as a checklist when contributing new providers or refactors.

## Roadmap

1. Ship additional providers from the upstream Arctic JS catalog (Apple, Twitter, Microsoft Entra ID, Auth0, etc.).
2. Expose higher-level helpers for multi-provider routing (e.g., a registry keyed by slug).
3. Optional middleware utilities for Axum/Actix to streamline callback handling.
4. Error reporting improvements (attach raw HTTP traces or response bodies behind feature flags).
5. Explore lightweight JWT verification helpers without pulling full crypto stacks.

## Related documents

- [`RFC-001-arctic-oauth.md`](./docs/rfcs/RFC-001-arctic-oauth.md) — design goals, architecture overview, and testing philosophy for `arctic-oauth` v0.1.0.
