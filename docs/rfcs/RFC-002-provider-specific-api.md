# RFC-002: Provider-Specific Public API

**Status**: Draft  
**Date**: 2026-02-08

## Summary

Replace the trait-based provider abstraction with provider-specific public APIs.

The crate no longer exposes a shared `OAuthProvider` trait or `PkceRequirement`. Each provider (`Google`, `GitHub`, `Discord`) exposes only methods and parameters that match its real behavior.

## Motivation

The previous trait design normalized providers with a single shape:

- shared methods for authorization URL, code exchange, refresh, and revocation
- optional PKCE verifier argument
- capability checks like `supports_token_revocation()`

In practice, providers are not uniform. This created "comment-level contracts" and runtime checks where Rust types could have represented constraints directly.

Example of the old mismatch:

- "`code_verifier` must be present when PKCE is required" was documented, but represented as `Option<&str>`.
- unsupported capabilities were represented as methods that returned `501`-style errors.

## Goals

1. Encode provider behavior in method signatures.
2. Remove runtime capability probing from the happy path.
3. Keep shared internals reusable without forcing a shared public trait.
4. Keep ergonomics straightforward for application code.

## Non-goals

1. Introduce a new generic provider trait to replace `OAuthProvider`.
2. Hide provider differences behind a common facade.

## Design

### 1. Public API shape

No common provider trait is exposed.

Each provider has inherent methods only.

### 2. PKCE handling by provider

- `Google`: PKCE required in type signature (`code_verifier: &str`).
- `GitHub`: PKCE not represented in API (no verifier argument).
- `Discord`: PKCE optional by provider behavior (`Option<&str>`).

This keeps PKCE constraints local and explicit.

### 3. Capability surface

Providers expose only supported operations.

- If a provider supports refresh/revocation, it has those methods.
- If it does not, the method is absent rather than returning an error for unsupported behavior.

### 4. Internal reuse

Shared internals remain:

- `OAuth2Client`
- request construction helpers
- token/error parsing
- HTTP client abstraction

These are implementation building blocks, not a forced public provider abstraction.

### 5. Testing approach

Cross-provider tests now use provider-specific integration tests instead of a trait-parameterized test harness.

This keeps tests aligned with the new API philosophy: provider behavior is explicit, not abstracted away.

## Rationale

Why this over a trait + associated builders?

- A trait-based abstraction still encourages an artificial common surface.
- Builder-heavy generics increase complexity without changing the core truth that providers differ materially.
- Provider-specific APIs are easier to read, easier to evolve, and more honest about behavior.

## Trade-offs

### Pros

- Better type-level correctness.
- Fewer runtime "unsupported" branches.
- Clearer provider docs and call sites.

### Cons

- Less generic programming across providers.
- More duplicated surface area across provider types.

## Decision

Adopt provider-specific public APIs and remove the common provider trait abstraction.
