# RFC-003: Remaining OAuth2 Provider Implementations

**Status**: Draft
**Date**: 2026-02-08

## Summary

This RFC catalogs the remaining 61 OAuth2 providers from [Arctic JS v3](https://github.com/pilcrowonpaper/arctic) that have not yet been implemented in `arctic-oauth`. For each provider, it specifies the exact endpoints, authentication method, PKCE behavior, constructor parameters, supported operations, and any spec deviations that require custom handling.

The 3 providers already implemented (Google, GitHub, Discord) are excluded.

---

## 1. Implementation Patterns

Before detailing individual providers, we define the implementation patterns observed in Arctic JS. Each provider falls into one of these categories:

### Pattern A: Standard OAuth2Client delegation

The provider wraps `OAuth2Client` and delegates all operations. When a `client_secret` is present, credentials are sent via HTTP Basic Auth. When absent, `client_id` is sent in the POST body (public client).

### Pattern B: Body-credential providers

The provider does NOT use `OAuth2Client`. Instead, it manually constructs requests using `create_oauth2_request` and sends `client_id` + `client_secret` in the POST body rather than via Basic Auth. This is used when a provider does not support HTTP Basic Auth or when Arctic JS chose body credentials for that provider.

### Pattern C: Custom response handling

The provider has non-standard token response formats that require custom parsing logic (e.g., errors returned with HTTP 200, wrapped response bodies).

### Pattern D: JWT client authentication

The provider uses a dynamically-generated JWT as the `client_secret` (Apple only).

---

## 2. Provider Catalog

### 2.1 42 (FortyTwo)

| Property                   | Value                                      |
| -------------------------- | ------------------------------------------ |
| **Rust struct name**       | `FortyTwo`                                 |
| **Authorization endpoint** | `https://api.intra.42.fr/oauth/authorize`  |
| **Token endpoint**         | `https://api.intra.42.fr/oauth/token`      |
| **Revocation endpoint**    | None                                       |
| **PKCE**                   | None                                       |
| **Constructor**            | `(client_id, client_secret, redirect_uri)` |
| **Auth method**            | Body credentials (Pattern B)               |
| **Token refresh**          | No                                         |
| **Token revocation**       | No                                         |
| **Scopes**                 | Optional                                   |
| **Special behavior**       | None                                       |

---

### 2.2 Amazon Cognito

| Property                   | Value                                                                                                                                          |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| **Rust struct name**       | `AmazonCognito`                                                                                                                                |
| **Authorization endpoint** | `https://{domain}/oauth2/authorize`                                                                                                            |
| **Token endpoint**         | `https://{domain}/oauth2/token`                                                                                                                |
| **Revocation endpoint**    | `https://{domain}/oauth2/revoke`                                                                                                               |
| **PKCE**                   | Required (S256)                                                                                                                                |
| **Constructor**            | `(domain, client_id, client_secret: Option, redirect_uri)`                                                                                     |
| **Auth method**            | OAuth2Client (Pattern A) -- Basic Auth when secret present, body when public                                                                   |
| **Token refresh**          | Yes (accepts scopes on refresh)                                                                                                                |
| **Token revocation**       | Yes                                                                                                                                            |
| **Scopes**                 | Optional                                                                                                                                       |
| **Special behavior**       | All endpoints are dynamic, built from `domain` parameter. Supports both confidential and public clients. Refresh accepts a `scopes` parameter. |

---

### 2.3 AniList

| Property                   | Value                                                        |
| -------------------------- | ------------------------------------------------------------ |
| **Rust struct name**       | `AniList`                                                    |
| **Authorization endpoint** | `https://anilist.co/api/v2/oauth/authorize`                  |
| **Token endpoint**         | `https://anilist.co/api/v2/oauth/token`                      |
| **Revocation endpoint**    | None                                                         |
| **PKCE**                   | None                                                         |
| **Constructor**            | `(client_id, client_secret, redirect_uri)`                   |
| **Auth method**            | OAuth2Client (Pattern A) -- Basic Auth                       |
| **Token refresh**          | No                                                           |
| **Token revocation**       | No                                                           |
| **Scopes**                 | Not supported -- authorization URL takes no scopes parameter |
| **Special behavior**       | No scopes parameter in authorization URL (hardcoded empty).  |

---

### 2.4 Apple

| Property                   | Value                                                                                                                                                                                                                                                                                                                                                                                                   |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Rust struct name**       | `Apple`                                                                                                                                                                                                                                                                                                                                                                                                 |
| **Authorization endpoint** | `https://appleid.apple.com/auth/authorize`                                                                                                                                                                                                                                                                                                                                                              |
| **Token endpoint**         | `https://appleid.apple.com/auth/token`                                                                                                                                                                                                                                                                                                                                                                  |
| **Revocation endpoint**    | None                                                                                                                                                                                                                                                                                                                                                                                                    |
| **PKCE**                   | None                                                                                                                                                                                                                                                                                                                                                                                                    |
| **Constructor**            | `(client_id, team_id, key_id, pkcs8_private_key: Vec<u8>, redirect_uri)`                                                                                                                                                                                                                                                                                                                                |
| **Auth method**            | JWT client secret (Pattern D)                                                                                                                                                                                                                                                                                                                                                                           |
| **Token refresh**          | No                                                                                                                                                                                                                                                                                                                                                                                                      |
| **Token revocation**       | No                                                                                                                                                                                                                                                                                                                                                                                                      |
| **Scopes**                 | Optional                                                                                                                                                                                                                                                                                                                                                                                                |
| **Special behavior**       | **Highly non-standard.** The `client_secret` is a JWT signed with ES256 (ECDSA P-256) using a provided PKCS#8 private key. JWT claims: `iss` = team_id, `sub` = client_id, `aud` = `"https://appleid.apple.com"`, `exp` = now + 5 minutes. JWT header includes `kid` = key_id, `alg` = "ES256". Credentials sent in POST body. Requires a crypto dependency for ES256 signing (e.g., `p256` or `ring`). |

**Implementation note**: This is the only provider requiring asymmetric cryptography. A new dependency (`p256` + `ecdsa` or `ring`) will be needed behind the `apple` feature flag. Consider deferring or gating this behind an optional feature.

---

### 2.5 Atlassian

| Property                   | Value                                                                                                        |
| -------------------------- | ------------------------------------------------------------------------------------------------------------ |
| **Rust struct name**       | `Atlassian`                                                                                                  |
| **Authorization endpoint** | `https://auth.atlassian.com/authorize`                                                                       |
| **Token endpoint**         | `https://auth.atlassian.com/oauth/token`                                                                     |
| **Revocation endpoint**    | None                                                                                                         |
| **PKCE**                   | None                                                                                                         |
| **Constructor**            | `(client_id, client_secret, redirect_uri)`                                                                   |
| **Auth method**            | Body credentials (Pattern B)                                                                                 |
| **Token refresh**          | Yes                                                                                                          |
| **Token revocation**       | No                                                                                                           |
| **Scopes**                 | Optional                                                                                                     |
| **Special behavior**       | Adds two extra query parameters to the authorization URL: `audience=api.atlassian.com` and `prompt=consent`. |

---

### 2.6 Auth0

| Property                   | Value                                                                                                                                             |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Rust struct name**       | `Auth0`                                                                                                                                           |
| **Authorization endpoint** | `https://{domain}/authorize`                                                                                                                      |
| **Token endpoint**         | `https://{domain}/oauth/token`                                                                                                                    |
| **Revocation endpoint**    | `https://{domain}/oauth/revoke`                                                                                                                   |
| **PKCE**                   | Optional (S256)                                                                                                                                   |
| **Constructor**            | `(domain, client_id, client_secret: Option, redirect_uri)`                                                                                        |
| **Auth method**            | OAuth2Client (Pattern A) -- Basic Auth when secret present, body when public                                                                      |
| **Token refresh**          | Yes                                                                                                                                               |
| **Token revocation**       | Yes                                                                                                                                               |
| **Scopes**                 | Optional                                                                                                                                          |
| **Special behavior**       | All endpoints dynamic from `domain`. Supports both confidential and public clients. PKCE is optional (include if verifier provided, omit if not). |

---

### 2.7 Authentik

| Property                   | Value                                                                          |
| -------------------------- | ------------------------------------------------------------------------------ |
| **Rust struct name**       | `Authentik`                                                                    |
| **Authorization endpoint** | `{base_url}/application/o/authorize/`                                          |
| **Token endpoint**         | `{base_url}/application/o/token/`                                              |
| **Revocation endpoint**    | `{base_url}/application/o/revoke/`                                             |
| **PKCE**                   | Required (S256)                                                                |
| **Constructor**            | `(base_url, client_id, client_secret: Option, redirect_uri)`                   |
| **Auth method**            | OAuth2Client (Pattern A) -- Basic Auth when secret present, body when public   |
| **Token refresh**          | Yes                                                                            |
| **Token revocation**       | Yes                                                                            |
| **Scopes**                 | Optional                                                                       |
| **Special behavior**       | Self-hosted. All endpoints dynamic from `base_url`. Trailing slashes on paths. |

---

### 2.8 Autodesk

| Property                   | Value                                                                        |
| -------------------------- | ---------------------------------------------------------------------------- |
| **Rust struct name**       | `Autodesk`                                                                   |
| **Authorization endpoint** | `https://developer.api.autodesk.com/authentication/v2/authorize`             |
| **Token endpoint**         | `https://developer.api.autodesk.com/authentication/v2/token`                 |
| **Revocation endpoint**    | `https://developer.api.autodesk.com/authentication/v2/revoke`                |
| **PKCE**                   | Required (S256)                                                              |
| **Constructor**            | `(client_id, client_secret: Option, redirect_uri)`                           |
| **Auth method**            | OAuth2Client (Pattern A) -- Basic Auth when secret present, body when public |
| **Token refresh**          | Yes                                                                          |
| **Token revocation**       | Yes                                                                          |
| **Scopes**                 | Optional                                                                     |
| **Special behavior**       | None -- standard OAuth2Client delegation.                                    |

---

### 2.9 Battle.net

| Property                   | Value                                                                                                        |
| -------------------------- | ------------------------------------------------------------------------------------------------------------ |
| **Rust struct name**       | `BattleNet`                                                                                                  |
| **Authorization endpoint** | `https://oauth.battle.net/authorize`                                                                         |
| **Token endpoint**         | `https://oauth.battle.net/token`                                                                             |
| **Revocation endpoint**    | None                                                                                                         |
| **PKCE**                   | None                                                                                                         |
| **Constructor**            | `(client_id, client_secret, redirect_uri)`                                                                   |
| **Auth method**            | Body credentials (Pattern B)                                                                                 |
| **Token refresh**          | No                                                                                                           |
| **Token revocation**       | No                                                                                                           |
| **Scopes**                 | Always sent (even when empty -- scope param set unconditionally)                                             |
| **Special behavior**       | Scope parameter is always included in the authorization URL, even when empty (no `scopes.length > 0` check). |

---

### 2.10 Bitbucket

| Property                   | Value                                                     |
| -------------------------- | --------------------------------------------------------- |
| **Rust struct name**       | `Bitbucket`                                               |
| **Authorization endpoint** | `https://bitbucket.org/site/oauth2/authorize`             |
| **Token endpoint**         | `https://bitbucket.org/site/oauth2/access_token`          |
| **Revocation endpoint**    | None                                                      |
| **PKCE**                   | None                                                      |
| **Constructor**            | `(client_id, client_secret, redirect_uri)`                |
| **Auth method**            | OAuth2Client (Pattern A) -- Basic Auth                    |
| **Token refresh**          | Yes                                                       |
| **Token revocation**       | No                                                        |
| **Scopes**                 | Not supported -- no scopes parameter in authorization URL |
| **Special behavior**       | No scopes parameter exposed (hardcoded empty).            |

---

### 2.11 Box

| Property                   | Value                                                                                                                                                                                                                                          |
| -------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Rust struct name**       | `Box` (note: Rust keyword conflict -- may need `BoxProvider` or `BoxOAuth`)                                                                                                                                                                    |
| **Authorization endpoint** | `https://account.box.com/api/oauth2/authorize`                                                                                                                                                                                                 |
| **Token endpoint**         | `https://api.box.com/oauth2/token`                                                                                                                                                                                                             |
| **Revocation endpoint**    | `https://api.box.com/oauth2/revoke`                                                                                                                                                                                                            |
| **PKCE**                   | None                                                                                                                                                                                                                                           |
| **Constructor**            | `(client_id, client_secret, redirect_uri)`                                                                                                                                                                                                     |
| **Auth method**            | Body credentials (Pattern B)                                                                                                                                                                                                                   |
| **Token refresh**          | Yes                                                                                                                                                                                                                                            |
| **Token revocation**       | Yes (sends `client_id`/`client_secret` in revocation body)                                                                                                                                                                                     |
| **Scopes**                 | Optional                                                                                                                                                                                                                                       |
| **Special behavior**       | Authorization endpoint on `account.box.com`, token/revocation on `api.box.com`. Revocation sends credentials in body. **Naming**: `Box` is not a Rust keyword but shadows `std::boxed::Box` -- consider naming it `BoxOAuth` or `BoxProvider`. |

---

### 2.12 Bungie

| Property                   | Value                                                                        |
| -------------------------- | ---------------------------------------------------------------------------- |
| **Rust struct name**       | `Bungie`                                                                     |
| **Authorization endpoint** | `https://www.bungie.net/en/oauth/authorize`                                  |
| **Token endpoint**         | `https://www.bungie.net/platform/app/oauth/token`                            |
| **Revocation endpoint**    | None                                                                         |
| **PKCE**                   | None                                                                         |
| **Constructor**            | `(client_id, client_secret: Option, redirect_uri)`                           |
| **Auth method**            | OAuth2Client (Pattern A) -- Basic Auth when secret present, body when public |
| **Token refresh**          | Yes                                                                          |
| **Token revocation**       | No                                                                           |
| **Scopes**                 | Optional                                                                     |
| **Special behavior**       | Supports both confidential and public clients.                               |

---

### 2.13 Coinbase

| Property                   | Value                                                                                  |
| -------------------------- | -------------------------------------------------------------------------------------- |
| **Rust struct name**       | `Coinbase`                                                                             |
| **Authorization endpoint** | `https://www.coinbase.com/oauth/authorize`                                             |
| **Token endpoint**         | `https://www.coinbase.com/oauth/token`                                                 |
| **Revocation endpoint**    | `https://api.coinbase.com/oauth/revoke`                                                |
| **PKCE**                   | None                                                                                   |
| **Constructor**            | `(client_id, client_secret, redirect_uri)`                                             |
| **Auth method**            | Body credentials (Pattern B)                                                           |
| **Token refresh**          | Yes                                                                                    |
| **Token revocation**       | Yes (sends `client_id`/`client_secret` in body)                                        |
| **Scopes**                 | Optional                                                                               |
| **Special behavior**       | Authorization/token endpoints on `www.coinbase.com`, revocation on `api.coinbase.com`. |

---

### 2.14 DonationAlerts

| Property                   | Value                                                                                                                                                                                                   |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Rust struct name**       | `DonationAlerts`                                                                                                                                                                                        |
| **Authorization endpoint** | `https://www.donationalerts.com/oauth/authorize`                                                                                                                                                        |
| **Token endpoint**         | `https://www.donationalerts.com/oauth/token`                                                                                                                                                            |
| **Revocation endpoint**    | None                                                                                                                                                                                                    |
| **PKCE**                   | None                                                                                                                                                                                                    |
| **Constructor**            | `(client_id, client_secret, redirect_uri)`                                                                                                                                                              |
| **Auth method**            | Body credentials (Pattern B)                                                                                                                                                                            |
| **Token refresh**          | Yes (accepts `scopes` parameter on refresh)                                                                                                                                                             |
| **Token revocation**       | No                                                                                                                                                                                                      |
| **Scopes**                 | Always sent (no length check)                                                                                                                                                                           |
| **Special behavior**       | **No `state` parameter** in `authorization_url` -- takes only scopes. Scopes always sent (even if empty). Refresh token method also accepts a `scopes` parameter. This is a significant CSRF deviation. |

---

### 2.15 Dribbble

| Property                   | Value                                      |
| -------------------------- | ------------------------------------------ |
| **Rust struct name**       | `Dribbble`                                 |
| **Authorization endpoint** | `https://dribbble.com/oauth/authorize`     |
| **Token endpoint**         | `https://dribbble.com/oauth/token`         |
| **Revocation endpoint**    | None                                       |
| **PKCE**                   | None                                       |
| **Constructor**            | `(client_id, client_secret, redirect_uri)` |
| **Auth method**            | Body credentials (Pattern B)               |
| **Token refresh**          | No                                         |
| **Token revocation**       | No                                         |
| **Scopes**                 | Optional                                   |
| **Special behavior**       | None                                       |

---

### 2.16 Dropbox

| Property                   | Value                                                                                                                                   |
| -------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| **Rust struct name**       | `Dropbox`                                                                                                                               |
| **Authorization endpoint** | `https://www.dropbox.com/oauth2/authorize`                                                                                              |
| **Token endpoint**         | `https://api.dropboxapi.com/oauth2/token`                                                                                               |
| **Revocation endpoint**    | `https://api.dropboxapi.com/2/auth/token/revoke`                                                                                        |
| **PKCE**                   | None                                                                                                                                    |
| **Constructor**            | `(client_id, client_secret, redirect_uri)`                                                                                              |
| **Auth method**            | OAuth2Client (Pattern A) -- Basic Auth                                                                                                  |
| **Token refresh**          | Yes                                                                                                                                     |
| **Token revocation**       | Yes                                                                                                                                     |
| **Scopes**                 | Optional                                                                                                                                |
| **Special behavior**       | Authorization on `www.dropbox.com`, token/revocation on `api.dropboxapi.com`. Revocation path is non-standard (`/2/auth/token/revoke`). |

---

### 2.17 Epic Games

| Property                   | Value                                                                          |
| -------------------------- | ------------------------------------------------------------------------------ |
| **Rust struct name**       | `EpicGames`                                                                    |
| **Authorization endpoint** | `https://www.epicgames.com/id/authorize`                                       |
| **Token endpoint**         | `https://api.epicgames.dev/epic/oauth/v2/token`                                |
| **Revocation endpoint**    | `https://api.epicgames.dev/epic/oauth/v2/revoke`                               |
| **PKCE**                   | None                                                                           |
| **Constructor**            | `(client_id, client_secret, redirect_uri)`                                     |
| **Auth method**            | OAuth2Client (Pattern A) -- Basic Auth                                         |
| **Token refresh**          | Yes                                                                            |
| **Token revocation**       | Yes                                                                            |
| **Scopes**                 | Optional                                                                       |
| **Special behavior**       | Authorization on `www.epicgames.com`, token/revocation on `api.epicgames.dev`. |

---

### 2.18 Etsy

| Property                   | Value                                                                                                                 |
| -------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| **Rust struct name**       | `Etsy`                                                                                                                |
| **Authorization endpoint** | `https://www.etsy.com/oauth/connect`                                                                                  |
| **Token endpoint**         | `https://api.etsy.com/v3/public/oauth/token`                                                                          |
| **Revocation endpoint**    | None                                                                                                                  |
| **PKCE**                   | Required (S256)                                                                                                       |
| **Constructor**            | `(client_id, redirect_uri)` -- **no client_secret**                                                                   |
| **Auth method**            | OAuth2Client (Pattern A) -- public client only (no secret)                                                            |
| **Token refresh**          | Yes                                                                                                                   |
| **Token revocation**       | No                                                                                                                    |
| **Scopes**                 | Optional                                                                                                              |
| **Special behavior**       | **Public client only** -- no `client_secret` parameter at all. Constructor takes only `client_id` and `redirect_uri`. |

---

### 2.19 Facebook

| Property                   | Value                                                                                                                                                                                 |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Rust struct name**       | `Facebook`                                                                                                                                                                            |
| **Authorization endpoint** | `https://www.facebook.com/v16.0/dialog/oauth`                                                                                                                                         |
| **Token endpoint**         | `https://graph.facebook.com/v16.0/oauth/access_token`                                                                                                                                 |
| **Revocation endpoint**    | None                                                                                                                                                                                  |
| **PKCE**                   | None                                                                                                                                                                                  |
| **Constructor**            | `(client_id, client_secret, redirect_uri)`                                                                                                                                            |
| **Auth method**            | Body credentials (Pattern B)                                                                                                                                                          |
| **Token refresh**          | No                                                                                                                                                                                    |
| **Token revocation**       | No                                                                                                                                                                                    |
| **Scopes**                 | Optional                                                                                                                                                                              |
| **Special behavior**       | Uses versioned API URLs (`v16.0`). Authorization on `www.facebook.com`, token on `graph.facebook.com`. Consider making the API version configurable or using a recent stable version. |

---

### 2.20 Figma

| Property                   | Value                                                                                                                                                                                                 |
| -------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Rust struct name**       | `Figma`                                                                                                                                                                                               |
| **Authorization endpoint** | `https://www.figma.com/oauth`                                                                                                                                                                         |
| **Token endpoint**         | `https://api.figma.com/v1/oauth/token`                                                                                                                                                                |
| **Revocation endpoint**    | None                                                                                                                                                                                                  |
| **Refresh endpoint**       | `https://api.figma.com/v1/oauth/refresh` (separate from token endpoint)                                                                                                                               |
| **PKCE**                   | None                                                                                                                                                                                                  |
| **Constructor**            | `(client_id, client_secret, redirect_uri)`                                                                                                                                                            |
| **Auth method**            | OAuth2Client (Pattern A) -- Basic Auth                                                                                                                                                                |
| **Token refresh**          | Yes -- **uses a separate refresh endpoint**                                                                                                                                                           |
| **Token revocation**       | No                                                                                                                                                                                                    |
| **Scopes**                 | Optional                                                                                                                                                                                              |
| **Special behavior**       | **Non-standard refresh endpoint.** Token exchange uses `/token`, but refresh uses `/refresh`. The `refresh_access_token` implementation must call the refresh endpoint instead of the token endpoint. |

---

### 2.21 Gitea

| Property                   | Value                                                                        |
| -------------------------- | ---------------------------------------------------------------------------- |
| **Rust struct name**       | `Gitea`                                                                      |
| **Authorization endpoint** | `{base_url}/login/oauth/authorize`                                           |
| **Token endpoint**         | `{base_url}/login/oauth/access_token`                                        |
| **Revocation endpoint**    | None                                                                         |
| **PKCE**                   | Required (S256)                                                              |
| **Constructor**            | `(base_url, client_id, client_secret: Option, redirect_uri)`                 |
| **Auth method**            | OAuth2Client (Pattern A) -- Basic Auth when secret present, body when public |
| **Token refresh**          | Yes                                                                          |
| **Token revocation**       | No                                                                           |
| **Scopes**                 | Optional                                                                     |
| **Special behavior**       | Self-hosted. All endpoints dynamic from `base_url`.                          |

---

### 2.22 GitLab

| Property                   | Value                                                                                              |
| -------------------------- | -------------------------------------------------------------------------------------------------- |
| **Rust struct name**       | `GitLab`                                                                                           |
| **Authorization endpoint** | `{base_url}/oauth/authorize`                                                                       |
| **Token endpoint**         | `{base_url}/oauth/token`                                                                           |
| **Revocation endpoint**    | `{base_url}/oauth/revoke`                                                                          |
| **PKCE**                   | None                                                                                               |
| **Constructor**            | `(base_url, client_id, client_secret: Option, redirect_uri)`                                       |
| **Auth method**            | OAuth2Client (Pattern A) -- Basic Auth when secret present, body when public                       |
| **Token refresh**          | Yes                                                                                                |
| **Token revocation**       | Yes                                                                                                |
| **Scopes**                 | Optional                                                                                           |
| **Special behavior**       | Self-hosted. All endpoints dynamic from `base_url`. Supports both confidential and public clients. |

---

### 2.23 Intuit

| Property                   | Value                                                                          |
| -------------------------- | ------------------------------------------------------------------------------ |
| **Rust struct name**       | `Intuit`                                                                       |
| **Authorization endpoint** | `https://appcenter.intuit.com/connect/oauth2`                                  |
| **Token endpoint**         | `https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer`                    |
| **Revocation endpoint**    | `https://developer.api.intuit.com/v2/oauth2/tokens/revoke`                     |
| **PKCE**                   | None                                                                           |
| **Constructor**            | `(client_id, client_secret, redirect_uri)`                                     |
| **Auth method**            | OAuth2Client (Pattern A) -- Basic Auth                                         |
| **Token refresh**          | Yes                                                                            |
| **Token revocation**       | Yes                                                                            |
| **Scopes**                 | Optional                                                                       |
| **Special behavior**       | Authorization, token, and revocation endpoints are on three different domains. |

---

### 2.24 Kakao

| Property                   | Value                                      |
| -------------------------- | ------------------------------------------ |
| **Rust struct name**       | `Kakao`                                    |
| **Authorization endpoint** | `https://kauth.kakao.com/oauth/authorize`  |
| **Token endpoint**         | `https://kauth.kakao.com/oauth/token`      |
| **Revocation endpoint**    | None                                       |
| **PKCE**                   | None                                       |
| **Constructor**            | `(client_id, client_secret, redirect_uri)` |
| **Auth method**            | Body credentials (Pattern B)               |
| **Token refresh**          | Yes                                        |
| **Token revocation**       | No                                         |
| **Scopes**                 | Optional                                   |
| **Special behavior**       | None                                       |

---

### 2.25 KeyCloak

| Property                   | Value                                                                                    |
| -------------------------- | ---------------------------------------------------------------------------------------- |
| **Rust struct name**       | `KeyCloak`                                                                               |
| **Authorization endpoint** | `{realm_url}/protocol/openid-connect/auth`                                               |
| **Token endpoint**         | `{realm_url}/protocol/openid-connect/token`                                              |
| **Revocation endpoint**    | `{realm_url}/protocol/openid-connect/revoke`                                             |
| **PKCE**                   | Required (S256)                                                                          |
| **Constructor**            | `(realm_url, client_id, client_secret: Option, redirect_uri)`                            |
| **Auth method**            | OAuth2Client (Pattern A) -- Basic Auth when secret present, body when public             |
| **Token refresh**          | Yes                                                                                      |
| **Token revocation**       | Yes                                                                                      |
| **Scopes**                 | Optional                                                                                 |
| **Special behavior**       | Self-hosted. All endpoints dynamic from `realm_url`. Endpoints use OpenID Connect paths. |

---

### 2.26 Kick

| Property                   | Value                                                          |
| -------------------------- | -------------------------------------------------------------- |
| **Rust struct name**       | `Kick`                                                         |
| **Authorization endpoint** | `https://id.kick.com/oauth/authorize`                          |
| **Token endpoint**         | `https://id.kick.com/oauth/token`                              |
| **Revocation endpoint**    | `https://id.kick.com/oauth/revoke`                             |
| **PKCE**                   | Required (S256)                                                |
| **Constructor**            | `(client_id, client_secret, redirect_uri)`                     |
| **Auth method**            | Body credentials (Pattern B)                                   |
| **Token refresh**          | Yes                                                            |
| **Token revocation**       | Yes                                                            |
| **Scopes**                 | Optional                                                       |
| **Special behavior**       | Uses PKCE but sends credentials in body instead of Basic Auth. |

---

### 2.27 Lichess

| Property                   | Value                                                      |
| -------------------------- | ---------------------------------------------------------- |
| **Rust struct name**       | `Lichess`                                                  |
| **Authorization endpoint** | `https://lichess.org/oauth`                                |
| **Token endpoint**         | `https://lichess.org/api/token`                            |
| **Revocation endpoint**    | None                                                       |
| **PKCE**                   | Required (S256)                                            |
| **Constructor**            | `(client_id, redirect_uri)` -- **no client_secret**        |
| **Auth method**            | OAuth2Client (Pattern A) -- public client only (no secret) |
| **Token refresh**          | No                                                         |
| **Token revocation**       | No                                                         |
| **Scopes**                 | Optional                                                   |
| **Special behavior**       | **Public client only** -- no `client_secret` at all.       |

---

### 2.28 Line

| Property                   | Value                                                      |
| -------------------------- | ---------------------------------------------------------- |
| **Rust struct name**       | `Line`                                                     |
| **Authorization endpoint** | `https://access.line.me/oauth2/v2.1/authorize`             |
| **Token endpoint**         | `https://api.line.me/oauth2/v2.1/token`                    |
| **Revocation endpoint**    | None                                                       |
| **PKCE**                   | Required (S256)                                            |
| **Constructor**            | `(client_id, client_secret, redirect_uri)`                 |
| **Auth method**            | Body credentials (Pattern B)                               |
| **Token refresh**          | Yes                                                        |
| **Token revocation**       | No                                                         |
| **Scopes**                 | Optional                                                   |
| **Special behavior**       | Authorization on `access.line.me`, token on `api.line.me`. |

---

### 2.29 Linear

| Property                   | Value                                      |
| -------------------------- | ------------------------------------------ |
| **Rust struct name**       | `Linear`                                   |
| **Authorization endpoint** | `https://linear.app/oauth/authorize`       |
| **Token endpoint**         | `https://api.linear.app/oauth/token`       |
| **Revocation endpoint**    | None                                       |
| **PKCE**                   | None                                       |
| **Constructor**            | `(client_id, client_secret, redirect_uri)` |
| **Auth method**            | Body credentials (Pattern B)               |
| **Token refresh**          | No                                         |
| **Token revocation**       | No                                         |
| **Scopes**                 | Optional                                   |
| **Special behavior**       | None                                       |

---

### 2.30 LinkedIn

| Property                   | Value                                                                                             |
| -------------------------- | ------------------------------------------------------------------------------------------------- |
| **Rust struct name**       | `LinkedIn`                                                                                        |
| **Authorization endpoint** | `https://www.linkedin.com/oauth/v2/authorization`                                                 |
| **Token endpoint**         | `https://www.linkedin.com/oauth/v2/accessToken`                                                   |
| **Revocation endpoint**    | None                                                                                              |
| **PKCE**                   | None                                                                                              |
| **Constructor**            | `(client_id, client_secret, redirect_uri)`                                                        |
| **Auth method**            | Body credentials (Pattern B)                                                                      |
| **Token refresh**          | Yes                                                                                               |
| **Token revocation**       | No                                                                                                |
| **Scopes**                 | Optional                                                                                          |
| **Special behavior**       | LinkedIn does not support HTTP Basic Auth (noted in Arctic JS source). Must use body credentials. |

---

### 2.31 Mastodon

| Property                   | Value                                                           |
| -------------------------- | --------------------------------------------------------------- |
| **Rust struct name**       | `Mastodon`                                                      |
| **Authorization endpoint** | `{base_url}/api/v1/oauth/authorize`                             |
| **Token endpoint**         | `{base_url}/api/v1/oauth/token`                                 |
| **Revocation endpoint**    | `{base_url}/api/v1/oauth/revoke`                                |
| **PKCE**                   | Required (S256)                                                 |
| **Constructor**            | `(base_url, client_id, client_secret, redirect_uri)`            |
| **Auth method**            | OAuth2Client (Pattern A) -- Basic Auth                          |
| **Token refresh**          | No                                                              |
| **Token revocation**       | Yes                                                             |
| **Scopes**                 | Optional                                                        |
| **Special behavior**       | Self-hosted (federated). All endpoints dynamic from `base_url`. |

---

### 2.32 MercadoLibre

| Property                   | Value                                                                                  |
| -------------------------- | -------------------------------------------------------------------------------------- |
| **Rust struct name**       | `MercadoLibre`                                                                         |
| **Authorization endpoint** | `https://auth.mercadolibre.com/authorization`                                          |
| **Token endpoint**         | `https://api.mercadolibre.com/oauth/token`                                             |
| **Revocation endpoint**    | None                                                                                   |
| **PKCE**                   | Required (S256)                                                                        |
| **Constructor**            | `(client_id, client_secret, redirect_uri)`                                             |
| **Auth method**            | Body credentials (Pattern B)                                                           |
| **Token refresh**          | Yes                                                                                    |
| **Token revocation**       | No                                                                                     |
| **Scopes**                 | Not supported -- scopes are defined in application settings, not at authorization time |
| **Special behavior**       | No scopes parameter. `client_id` is public on the struct in Arctic JS.                 |

---

### 2.33 MercadoPago

| Property                   | Value                                                       |
| -------------------------- | ----------------------------------------------------------- |
| **Rust struct name**       | `MercadoPago`                                               |
| **Authorization endpoint** | `https://auth.mercadopago.com/authorization`                |
| **Token endpoint**         | `https://api.mercadopago.com/oauth/token`                   |
| **Revocation endpoint**    | None                                                        |
| **PKCE**                   | Required (S256)                                             |
| **Constructor**            | `(client_id, client_secret, redirect_uri)`                  |
| **Auth method**            | Body credentials (Pattern B)                                |
| **Token refresh**          | Yes                                                         |
| **Token revocation**       | No                                                          |
| **Scopes**                 | Not supported -- scopes are defined in application settings |
| **Special behavior**       | Nearly identical to MercadoLibre. No scopes parameter.      |

---

### 2.34 Microsoft Entra ID

| Property                   | Value                                                                                                                                                                                                                                                                                                                                                             |
| -------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Rust struct name**       | `MicrosoftEntraId`                                                                                                                                                                                                                                                                                                                                                |
| **Authorization endpoint** | `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize`                                                                                                                                                                                                                                                                                                |
| **Token endpoint**         | `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`                                                                                                                                                                                                                                                                                                    |
| **Revocation endpoint**    | None                                                                                                                                                                                                                                                                                                                                                              |
| **PKCE**                   | Required (S256)                                                                                                                                                                                                                                                                                                                                                   |
| **Constructor**            | `(tenant, client_id, client_secret: Option, redirect_uri)`                                                                                                                                                                                                                                                                                                        |
| **Auth method**            | Confidential: Basic Auth. Public: body credentials + `Origin: "arctic"` header                                                                                                                                                                                                                                                                                    |
| **Token refresh**          | Yes (accepts `scopes` parameter on refresh)                                                                                                                                                                                                                                                                                                                       |
| **Token revocation**       | No                                                                                                                                                                                                                                                                                                                                                                |
| **Scopes**                 | Optional                                                                                                                                                                                                                                                                                                                                                          |
| **Special behavior**       | **Most complex provider.** Does NOT use OAuth2Client. Endpoints are dynamic from `tenant`. When `client_secret` is null (public client), adds an `Origin` header (value can be anything -- set to `"arctic"`). Refresh accepts a `scopes` parameter. Two code paths for confidential vs. public in both `validate_authorization_code` and `refresh_access_token`. |

---

### 2.35 MyAnimeList

| Property                   | Value                                                                                                              |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| **Rust struct name**       | `MyAnimeList`                                                                                                      |
| **Authorization endpoint** | `https://myanimelist.net/v1/oauth2/authorize`                                                                      |
| **Token endpoint**         | `https://myanimelist.net/v1/oauth2/token`                                                                          |
| **Revocation endpoint**    | None                                                                                                               |
| **PKCE**                   | Required (**Plain** -- not S256)                                                                                   |
| **Constructor**            | `(client_id, client_secret, redirect_uri: Option)`                                                                 |
| **Auth method**            | OAuth2Client (Pattern A) -- Basic Auth                                                                             |
| **Token refresh**          | Yes                                                                                                                |
| **Token revocation**       | No                                                                                                                 |
| **Scopes**                 | Not supported -- hardcoded empty                                                                                   |
| **Special behavior**       | **Uses Plain PKCE** (not S256), which is unusual. No scopes parameter. `redirect_uri` is optional (can be `None`). |

---

### 2.36 Naver

| Property                   | Value                                                                                                                                                                           |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Rust struct name**       | `Naver`                                                                                                                                                                         |
| **Authorization endpoint** | `https://nid.naver.com/oauth2.0/authorize`                                                                                                                                      |
| **Token endpoint**         | `https://nid.naver.com/oauth2.0/token`                                                                                                                                          |
| **Revocation endpoint**    | None                                                                                                                                                                            |
| **PKCE**                   | None                                                                                                                                                                            |
| **Constructor**            | `(client_id, client_secret, redirect_uri)`                                                                                                                                      |
| **Auth method**            | Body credentials (Pattern B)                                                                                                                                                    |
| **Token refresh**          | Yes                                                                                                                                                                             |
| **Token revocation**       | No                                                                                                                                                                              |
| **Scopes**                 | Not supported                                                                                                                                                                   |
| **Special behavior**       | **No `state` parameter and no scopes** in `authorization_url` -- the method takes no parameters at all. This is very unusual and means no CSRF protection at the library level. |

---

### 2.37 Notion

| Property                   | Value                                                                         |
| -------------------------- | ----------------------------------------------------------------------------- |
| **Rust struct name**       | `Notion`                                                                      |
| **Authorization endpoint** | `https://api.notion.com/v1/oauth/authorize`                                   |
| **Token endpoint**         | `https://api.notion.com/v1/oauth/token`                                       |
| **Revocation endpoint**    | None                                                                          |
| **PKCE**                   | None                                                                          |
| **Constructor**            | `(client_id, client_secret, redirect_uri)`                                    |
| **Auth method**            | OAuth2Client (Pattern A) -- Basic Auth                                        |
| **Token refresh**          | No                                                                            |
| **Token revocation**       | No                                                                            |
| **Scopes**                 | Not supported                                                                 |
| **Special behavior**       | Adds `owner=user` to authorization URL query parameters. No scopes parameter. |

---

### 2.38 Okta

| Property                   | Value                                                                                                                                                                          |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Rust struct name**       | `Okta`                                                                                                                                                                         |
| **Authorization endpoint** | `https://{domain}/oauth2[/{authorization_server_id}]/v1/authorize`                                                                                                             |
| **Token endpoint**         | `https://{domain}/oauth2[/{authorization_server_id}]/v1/token`                                                                                                                 |
| **Revocation endpoint**    | `https://{domain}/oauth2[/{authorization_server_id}]/v1/revoke`                                                                                                                |
| **PKCE**                   | Required (S256)                                                                                                                                                                |
| **Constructor**            | `(domain, authorization_server_id: Option, client_id, client_secret, redirect_uri)`                                                                                            |
| **Auth method**            | OAuth2Client (Pattern A) -- Basic Auth                                                                                                                                         |
| **Token refresh**          | Yes (accepts `scopes` parameter on refresh)                                                                                                                                    |
| **Token revocation**       | Yes                                                                                                                                                                            |
| **Scopes**                 | Optional                                                                                                                                                                       |
| **Special behavior**       | Endpoints are dynamic from `domain` and optional `authorization_server_id`. If `authorization_server_id` is provided, it's inserted into the URL path. Refresh accepts scopes. |

---

### 2.39 osu!

| Property                   | Value                                                                                        |
| -------------------------- | -------------------------------------------------------------------------------------------- |
| **Rust struct name**       | `Osu`                                                                                        |
| **Authorization endpoint** | `https://osu.ppy.sh/oauth/authorize`                                                         |
| **Token endpoint**         | `https://osu.ppy.sh/oauth/token`                                                             |
| **Revocation endpoint**    | None                                                                                         |
| **PKCE**                   | None                                                                                         |
| **Constructor**            | `(client_id, client_secret, redirect_uri: Option)`                                           |
| **Auth method**            | Body credentials (Pattern B)                                                                 |
| **Token refresh**          | Yes                                                                                          |
| **Token revocation**       | No                                                                                           |
| **Scopes**                 | Optional                                                                                     |
| **Special behavior**       | `redirect_uri` is optional -- if `None`, not included in authorization URL or token request. |

---

### 2.40 Patreon

| Property                   | Value                                      |
| -------------------------- | ------------------------------------------ |
| **Rust struct name**       | `Patreon`                                  |
| **Authorization endpoint** | `https://www.patreon.com/oauth2/authorize` |
| **Token endpoint**         | `https://www.patreon.com/api/oauth2/token` |
| **Revocation endpoint**    | None                                       |
| **PKCE**                   | None                                       |
| **Constructor**            | `(client_id, client_secret, redirect_uri)` |
| **Auth method**            | Body credentials (Pattern B)               |
| **Token refresh**          | Yes                                        |
| **Token revocation**       | No                                         |
| **Scopes**                 | Optional                                   |
| **Special behavior**       | None                                       |

---

### 2.41 Polar

| Property                   | Value                                                                                                                |
| -------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| **Rust struct name**       | `Polar`                                                                                                              |
| **Authorization endpoint** | `https://polar.sh/oauth2/authorize`                                                                                  |
| **Token endpoint**         | `https://api.polar.sh/v1/oauth2/token`                                                                               |
| **Revocation endpoint**    | `https://api.polar.sh/v1/oauth2/revoke`                                                                              |
| **PKCE**                   | Required (S256)                                                                                                      |
| **Constructor**            | `(client_id, client_secret: Option, redirect_uri)`                                                                   |
| **Auth method**            | Body credentials (Pattern B) -- despite supporting Basic Auth, uses body credentials                                 |
| **Token refresh**          | Yes                                                                                                                  |
| **Token revocation**       | Yes                                                                                                                  |
| **Scopes**                 | Optional                                                                                                             |
| **Special behavior**       | Supports both confidential and public clients. Sends credentials in body despite the provider supporting Basic Auth. |

---

### 2.42 Reddit

| Property                   | Value                                                                                     |
| -------------------------- | ----------------------------------------------------------------------------------------- |
| **Rust struct name**       | `Reddit`                                                                                  |
| **Authorization endpoint** | `https://www.reddit.com/api/v1/authorize`                                                 |
| **Token endpoint**         | `https://www.reddit.com/api/v1/access_token`                                              |
| **Revocation endpoint**    | None                                                                                      |
| **PKCE**                   | None                                                                                      |
| **Constructor**            | `(client_id, client_secret, redirect_uri)`                                                |
| **Auth method**            | OAuth2Client (Pattern A) -- Basic Auth                                                    |
| **Token refresh**          | Yes                                                                                       |
| **Token revocation**       | No                                                                                        |
| **Scopes**                 | Optional                                                                                  |
| **Special behavior**       | Reddit requires the `Content-Length` header (already set by our `create_oauth2_request`). |

---

### 2.43 Roblox

| Property                   | Value                                                                        |
| -------------------------- | ---------------------------------------------------------------------------- |
| **Rust struct name**       | `Roblox`                                                                     |
| **Authorization endpoint** | `https://apis.roblox.com/oauth/v1/authorize`                                 |
| **Token endpoint**         | `https://apis.roblox.com/oauth/v1/token`                                     |
| **Revocation endpoint**    | `https://apis.roblox.com/oauth/v1/token/revoke`                              |
| **PKCE**                   | Required (S256)                                                              |
| **Constructor**            | `(client_id, client_secret: Option, redirect_uri)`                           |
| **Auth method**            | OAuth2Client (Pattern A) -- Basic Auth when secret present, body when public |
| **Token refresh**          | Yes                                                                          |
| **Token revocation**       | Yes                                                                          |
| **Scopes**                 | Optional                                                                     |
| **Special behavior**       | None -- standard OAuth2Client delegation with PKCE.                          |

---

### 2.44 Salesforce

| Property                   | Value                                                                                         |
| -------------------------- | --------------------------------------------------------------------------------------------- |
| **Rust struct name**       | `Salesforce`                                                                                  |
| **Authorization endpoint** | `https://{domain}/services/oauth2/authorize`                                                  |
| **Token endpoint**         | `https://{domain}/services/oauth2/token`                                                      |
| **Revocation endpoint**    | `https://{domain}/services/oauth2/revoke`                                                     |
| **PKCE**                   | Required (S256)                                                                               |
| **Constructor**            | `(domain, client_id, client_secret: Option, redirect_uri)`                                    |
| **Auth method**            | OAuth2Client (Pattern A) -- Basic Auth when secret present, body when public                  |
| **Token refresh**          | Yes                                                                                           |
| **Token revocation**       | Yes                                                                                           |
| **Scopes**                 | Optional                                                                                      |
| **Special behavior**       | All endpoints dynamic from `domain` parameter. Supports both confidential and public clients. |

---

### 2.45 Shikimori

| Property                   | Value                                                     |
| -------------------------- | --------------------------------------------------------- |
| **Rust struct name**       | `Shikimori`                                               |
| **Authorization endpoint** | `https://shikimori.one/oauth/authorize`                   |
| **Token endpoint**         | `https://shikimori.one/oauth/token`                       |
| **Revocation endpoint**    | None                                                      |
| **PKCE**                   | None                                                      |
| **Constructor**            | `(client_id, client_secret, redirect_uri)`                |
| **Auth method**            | Body credentials (Pattern B)                              |
| **Token refresh**          | Yes                                                       |
| **Token revocation**       | No                                                        |
| **Scopes**                 | Not supported -- no scopes parameter in authorization URL |
| **Special behavior**       | No scopes parameter exposed.                              |

---

### 2.46 Slack

| Property                   | Value                                                                                                                                        |
| -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| **Rust struct name**       | `Slack`                                                                                                                                      |
| **Authorization endpoint** | `https://slack.com/openid/connect/authorize`                                                                                                 |
| **Token endpoint**         | `https://slack.com/api/openid.connect.token`                                                                                                 |
| **Revocation endpoint**    | None                                                                                                                                         |
| **PKCE**                   | None                                                                                                                                         |
| **Constructor**            | `(client_id, client_secret, redirect_uri: Option)`                                                                                           |
| **Auth method**            | OAuth2Client (Pattern A) -- Basic Auth                                                                                                       |
| **Token refresh**          | No                                                                                                                                           |
| **Token revocation**       | No                                                                                                                                           |
| **Scopes**                 | Optional                                                                                                                                     |
| **Special behavior**       | Uses OpenID Connect endpoints (not generic OAuth2). `redirect_uri` is optional. Token endpoint path uses dots (`/api/openid.connect.token`). |

---

### 2.47 Spotify

| Property                   | Value                                                                                                        |
| -------------------------- | ------------------------------------------------------------------------------------------------------------ |
| **Rust struct name**       | `Spotify`                                                                                                    |
| **Authorization endpoint** | `https://accounts.spotify.com/authorize`                                                                     |
| **Token endpoint**         | `https://accounts.spotify.com/api/token`                                                                     |
| **Revocation endpoint**    | None                                                                                                         |
| **PKCE**                   | Optional (S256)                                                                                              |
| **Constructor**            | `(client_id, client_secret: Option, redirect_uri)`                                                           |
| **Auth method**            | OAuth2Client (Pattern A) -- Basic Auth when secret present, body when public                                 |
| **Token refresh**          | Yes                                                                                                          |
| **Token revocation**       | No                                                                                                           |
| **Scopes**                 | Optional                                                                                                     |
| **Special behavior**       | PKCE is optional (include if verifier provided, omit if not). Supports both confidential and public clients. |

---

### 2.48 Start.gg

| Property                   | Value                                                                                                                                                                               |
| -------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Rust struct name**       | `StartGG`                                                                                                                                                                           |
| **Authorization endpoint** | `https://start.gg/oauth/authorize`                                                                                                                                                  |
| **Token endpoint**         | `https://api.start.gg/oauth/access_token`                                                                                                                                           |
| **Refresh endpoint**       | `https://api.start.gg/oauth/refresh` (separate from token endpoint)                                                                                                                 |
| **Revocation endpoint**    | None                                                                                                                                                                                |
| **PKCE**                   | None                                                                                                                                                                                |
| **Constructor**            | `(client_id, client_secret, redirect_uri)`                                                                                                                                          |
| **Auth method**            | Body credentials (Pattern B)                                                                                                                                                        |
| **Token refresh**          | Yes -- **uses a separate refresh endpoint**; accepts scopes on refresh                                                                                                              |
| **Token revocation**       | No                                                                                                                                                                                  |
| **Scopes**                 | Optional (can be passed at both authorization and token validation time)                                                                                                            |
| **Special behavior**       | Authorization on `start.gg`, token on `api.start.gg`. Uses a **separate refresh endpoint** (`/oauth/refresh`). Scopes can be passed during `validate_authorization_code` (unusual). |

---

### 2.49 Strava

| Property                   | Value                                                                                                                |
| -------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| **Rust struct name**       | `Strava`                                                                                                             |
| **Authorization endpoint** | `https://www.strava.com/oauth/authorize`                                                                             |
| **Token endpoint**         | `https://www.strava.com/api/v3/oauth/token`                                                                          |
| **Revocation endpoint**    | None                                                                                                                 |
| **PKCE**                   | None                                                                                                                 |
| **Constructor**            | `(client_id, client_secret, redirect_uri)`                                                                           |
| **Auth method**            | Body credentials (Pattern B)                                                                                         |
| **Token refresh**          | Yes                                                                                                                  |
| **Token revocation**       | No                                                                                                                   |
| **Scopes**                 | Optional, but **comma-delimited** (not space-delimited)                                                              |
| **Special behavior**       | **Scopes use comma-delimited string** instead of spaces (like Withings). Token endpoint is at `/api/v3/oauth/token`. |

---

### 2.50 Synology

| Property                   | Value                                                                                                                                                                                  |
| -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Rust struct name**       | `Synology`                                                                                                                                                                             |
| **Authorization endpoint** | `{base_url}/webman/sso/SSOOauth.cgi`                                                                                                                                                   |
| **Token endpoint**         | `{base_url}/webman/sso/SSOAccessToken.cgi`                                                                                                                                             |
| **Revocation endpoint**    | None                                                                                                                                                                                   |
| **PKCE**                   | Required (S256)                                                                                                                                                                        |
| **Constructor**            | `(base_url, application_id, application_secret, redirect_uri)`                                                                                                                         |
| **Auth method**            | OAuth2Client (Pattern A) -- Basic Auth                                                                                                                                                 |
| **Token refresh**          | No                                                                                                                                                                                     |
| **Token revocation**       | No                                                                                                                                                                                     |
| **Scopes**                 | Optional                                                                                                                                                                               |
| **Special behavior**       | Self-hosted. All endpoints dynamic from `base_url`. Uses non-standard CGI paths. Constructor uses `application_id`/`application_secret` naming instead of `client_id`/`client_secret`. |

---

### 2.51 TikTok

| Property                   | Value                                                                                                                                                                                                                                                                                             |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Rust struct name**       | `TikTok`                                                                                                                                                                                                                                                                                          |
| **Authorization endpoint** | `https://www.tiktok.com/v2/auth/authorize/`                                                                                                                                                                                                                                                       |
| **Token endpoint**         | `https://open.tiktokapis.com/v2/oauth/token/`                                                                                                                                                                                                                                                     |
| **Revocation endpoint**    | `https://open.tiktokapis.com/v2/oauth/revoke/`                                                                                                                                                                                                                                                    |
| **PKCE**                   | Required (S256)                                                                                                                                                                                                                                                                                   |
| **Constructor**            | `(client_id, client_secret, redirect_uri)`                                                                                                                                                                                                                                                        |
| **Auth method**            | Body credentials (Pattern B) + Custom response parsing (Pattern C)                                                                                                                                                                                                                                |
| **Token refresh**          | Yes                                                                                                                                                                                                                                                                                               |
| **Token revocation**       | Yes                                                                                                                                                                                                                                                                                               |
| **Scopes**                 | Optional                                                                                                                                                                                                                                                                                          |
| **Special behavior**       | **Multiple deviations:** (1) Uses `client_key` instead of `client_id` in both authorization URL and token body. (2) Custom `sendTokenRequest` that checks for HTTP 200 with `error` field in body (like GitHub). (3) Scopes are always sent (no length check). (4) Trailing slashes on endpoints. |

---

### 2.52 Tiltify

| Property                   | Value                                       |
| -------------------------- | ------------------------------------------- |
| **Rust struct name**       | `Tiltify`                                   |
| **Authorization endpoint** | `https://v5api.tiltify.com/oauth/authorize` |
| **Token endpoint**         | `https://v5api.tiltify.com/oauth/token`     |
| **Revocation endpoint**    | None                                        |
| **PKCE**                   | None                                        |
| **Constructor**            | `(client_id, client_secret, redirect_uri)`  |
| **Auth method**            | Body credentials (Pattern B)                |
| **Token refresh**          | Yes                                         |
| **Token revocation**       | No                                          |
| **Scopes**                 | Optional                                    |
| **Special behavior**       | None                                        |

---

### 2.53 Tumblr

| Property                   | Value                                                         |
| -------------------------- | ------------------------------------------------------------- |
| **Rust struct name**       | `Tumblr`                                                      |
| **Authorization endpoint** | `https://www.tumblr.com/oauth2/authorize`                     |
| **Token endpoint**         | `https://api.tumblr.com/v2/oauth2/token`                      |
| **Revocation endpoint**    | None                                                          |
| **PKCE**                   | None                                                          |
| **Constructor**            | `(client_id, client_secret, redirect_uri)`                    |
| **Auth method**            | OAuth2Client (Pattern A) -- Basic Auth                        |
| **Token refresh**          | Yes                                                           |
| **Token revocation**       | No                                                            |
| **Scopes**                 | Optional                                                      |
| **Special behavior**       | Authorization on `www.tumblr.com`, token on `api.tumblr.com`. |

---

### 2.54 Twitch

| Property                   | Value                                                                                                                          |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| **Rust struct name**       | `Twitch`                                                                                                                       |
| **Authorization endpoint** | `https://id.twitch.tv/oauth2/authorize`                                                                                        |
| **Token endpoint**         | `https://id.twitch.tv/oauth2/token`                                                                                            |
| **Revocation endpoint**    | None                                                                                                                           |
| **PKCE**                   | None                                                                                                                           |
| **Constructor**            | `(client_id, client_secret, redirect_uri)`                                                                                     |
| **Auth method**            | Body credentials (Pattern B)                                                                                                   |
| **Token refresh**          | Yes                                                                                                                            |
| **Token revocation**       | No                                                                                                                             |
| **Scopes**                 | Optional                                                                                                                       |
| **Special behavior**       | Does not support HTTP Basic Auth. Token revocation explicitly omitted because Twitch's error responses are not spec-compliant. |

---

### 2.55 Twitter

| Property                   | Value                                                                                                                 |
| -------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| **Rust struct name**       | `Twitter`                                                                                                             |
| **Authorization endpoint** | `https://twitter.com/i/oauth2/authorize`                                                                              |
| **Token endpoint**         | `https://api.twitter.com/2/oauth2/token`                                                                              |
| **Revocation endpoint**    | `https://api.twitter.com/2/oauth2/revoke`                                                                             |
| **PKCE**                   | Required (S256)                                                                                                       |
| **Constructor**            | `(client_id, client_secret: Option, redirect_uri)`                                                                    |
| **Auth method**            | OAuth2Client (Pattern A) -- Basic Auth when secret present, body when public                                          |
| **Token refresh**          | Yes                                                                                                                   |
| **Token revocation**       | Yes                                                                                                                   |
| **Scopes**                 | Optional                                                                                                              |
| **Special behavior**       | Supports both confidential and public clients. Authorization on `twitter.com`, token/revocation on `api.twitter.com`. |

---

### 2.56 VK

| Property                   | Value                                      |
| -------------------------- | ------------------------------------------ |
| **Rust struct name**       | `VK`                                       |
| **Authorization endpoint** | `https://oauth.vk.com/authorize`           |
| **Token endpoint**         | `https://oauth.vk.com/access_token`        |
| **Revocation endpoint**    | None                                       |
| **PKCE**                   | None                                       |
| **Constructor**            | `(client_id, client_secret, redirect_uri)` |
| **Auth method**            | Body credentials (Pattern B)               |
| **Token refresh**          | No                                         |
| **Token revocation**       | No                                         |
| **Scopes**                 | Optional                                   |
| **Special behavior**       | None                                       |

---

### 2.57 Withings

| Property                   | Value                                                                                                                                                                                                                                                                                                                                                                                            |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Rust struct name**       | `Withings`                                                                                                                                                                                                                                                                                                                                                                                       |
| **Authorization endpoint** | `https://account.withings.com/oauth2_user/authorize2`                                                                                                                                                                                                                                                                                                                                            |
| **Token endpoint**         | `https://wbsapi.withings.net/v2/oauth2`                                                                                                                                                                                                                                                                                                                                                          |
| **Revocation endpoint**    | None                                                                                                                                                                                                                                                                                                                                                                                             |
| **PKCE**                   | None                                                                                                                                                                                                                                                                                                                                                                                             |
| **Constructor**            | `(client_id, client_secret, redirect_uri)`                                                                                                                                                                                                                                                                                                                                                       |
| **Auth method**            | Body credentials (Pattern B) + Custom response parsing (Pattern C)                                                                                                                                                                                                                                                                                                                               |
| **Token refresh**          | No                                                                                                                                                                                                                                                                                                                                                                                               |
| **Token revocation**       | No                                                                                                                                                                                                                                                                                                                                                                                               |
| **Scopes**                 | Optional, but **comma-delimited** (not space-delimited)                                                                                                                                                                                                                                                                                                                                          |
| **Special behavior**       | **Multiple deviations:** (1) Scopes use comma-delimited string instead of spaces. (2) Token request requires an extra `action=requesttoken` body parameter. (3) Returns errors with HTTP 200 status (like GitHub). (4) Successful response is wrapped: `{"status": 0, "body": {...}}` -- the actual token data is in the nested `body` field. Custom `sendTokenRequest` implementation required. |

---

### 2.58 WorkOS

| Property                   | Value                                                                                                                    |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| **Rust struct name**       | `WorkOS`                                                                                                                 |
| **Authorization endpoint** | `https://api.workos.com/sso/authorize`                                                                                   |
| **Token endpoint**         | `https://api.workos.com/sso/token`                                                                                       |
| **Revocation endpoint**    | None                                                                                                                     |
| **PKCE**                   | Optional (S256)                                                                                                          |
| **Constructor**            | `(client_id, client_secret: Option, redirect_uri)`                                                                       |
| **Auth method**            | Body credentials (Pattern B)                                                                                             |
| **Token refresh**          | No                                                                                                                       |
| **Token revocation**       | No                                                                                                                       |
| **Scopes**                 | Not supported -- no scopes parameter                                                                                     |
| **Special behavior**       | PKCE is optional. Supports both confidential and public clients. No scopes parameter. Uses SSO-specific paths (`/sso/`). |

---

### 2.59 Yahoo

| Property                   | Value                                                      |
| -------------------------- | ---------------------------------------------------------- |
| **Rust struct name**       | `Yahoo`                                                    |
| **Authorization endpoint** | `https://api.login.yahoo.com/oauth2/request_auth`          |
| **Token endpoint**         | `https://api.login.yahoo.com/oauth2/get_token`             |
| **Revocation endpoint**    | None                                                       |
| **PKCE**                   | None                                                       |
| **Constructor**            | `(client_id, client_secret, redirect_uri)`                 |
| **Auth method**            | OAuth2Client (Pattern A) -- Basic Auth                     |
| **Token refresh**          | Yes                                                        |
| **Token revocation**       | No                                                         |
| **Scopes**                 | Optional                                                   |
| **Special behavior**       | Non-standard endpoint paths (`request_auth`, `get_token`). |

---

### 2.60 Yandex

| Property                   | Value                                            |
| -------------------------- | ------------------------------------------------ |
| **Rust struct name**       | `Yandex`                                         |
| **Authorization endpoint** | `https://oauth.yandex.com/authorize`             |
| **Token endpoint**         | `https://oauth.yandex.com/token`                 |
| **Revocation endpoint**    | None                                             |
| **PKCE**                   | None                                             |
| **Constructor**            | `(client_id, client_secret, redirect_uri)`       |
| **Auth method**            | OAuth2Client (Pattern A) -- Basic Auth           |
| **Token refresh**          | Yes                                              |
| **Token revocation**       | No                                               |
| **Scopes**                 | Optional                                         |
| **Special behavior**       | None -- straightforward OAuth2Client delegation. |

---

### 2.61 Zoom

| Property                   | Value                                               |
| -------------------------- | --------------------------------------------------- |
| **Rust struct name**       | `Zoom`                                              |
| **Authorization endpoint** | `https://zoom.us/oauth/authorize`                   |
| **Token endpoint**         | `https://zoom.us/oauth/token`                       |
| **Revocation endpoint**    | `https://zoom.us/oauth/revoke`                      |
| **PKCE**                   | Required (S256)                                     |
| **Constructor**            | `(client_id, client_secret, redirect_uri)`          |
| **Auth method**            | OAuth2Client (Pattern A) -- Basic Auth              |
| **Token refresh**          | Yes                                                 |
| **Token revocation**       | Yes                                                 |
| **Scopes**                 | Optional                                            |
| **Special behavior**       | None -- standard OAuth2Client delegation with PKCE. |

---

## 3. Summary Tables

### 3.1 Providers by Implementation Pattern

#### Pattern A: Standard OAuth2Client (Basic Auth)

Simple delegation to `OAuth2Client`. Minimal custom code per provider.

| Provider      | PKCE            | Secret   | Refresh             | Revoke | Dynamic URLs                |
| ------------- | --------------- | -------- | ------------------- | ------ | --------------------------- |
| AmazonCognito | S256 (req)      | Optional | Yes (+ scopes)      | Yes    | `domain`                    |
| AniList       | None            | Required | No                  | No     | No                          |
| Auth0         | S256 (opt)      | Optional | Yes                 | Yes    | `domain`                    |
| Authentik     | S256 (req)      | Optional | Yes                 | Yes    | `base_url`                  |
| Autodesk      | S256 (req)      | Optional | Yes                 | Yes    | No                          |
| Bitbucket     | None            | Required | Yes                 | No     | No                          |
| Bungie        | None            | Optional | Yes                 | No     | No                          |
| Dropbox       | None            | Required | Yes                 | Yes    | No                          |
| EpicGames     | None            | Required | Yes                 | Yes    | No                          |
| Etsy          | S256 (req)      | **None** | Yes                 | No     | No                          |
| Figma         | None            | Required | Yes (sep. endpoint) | No     | No                          |
| Gitea         | S256 (req)      | Optional | Yes                 | No     | `base_url`                  |
| GitLab        | None            | Optional | Yes                 | Yes    | `base_url`                  |
| Intuit        | None            | Required | Yes                 | Yes    | No                          |
| KeyCloak      | S256 (req)      | Optional | Yes                 | Yes    | `realm_url`                 |
| Lichess       | S256 (req)      | **None** | No                  | No     | No                          |
| Mastodon      | S256 (req)      | Required | No                  | Yes    | `base_url`                  |
| MyAnimeList   | **Plain** (req) | Required | Yes                 | No     | No                          |
| Notion        | None            | Required | No                  | No     | No                          |
| Okta          | S256 (req)      | Required | Yes (+ scopes)      | Yes    | `domain` + `auth_server_id` |
| Reddit        | None            | Required | Yes                 | No     | No                          |
| Roblox        | S256 (req)      | Optional | Yes                 | Yes    | No                          |
| Salesforce    | S256 (req)      | Optional | Yes                 | Yes    | `domain`                    |
| Slack         | None            | Required | No                  | No     | No                          |
| Spotify       | S256 (opt)      | Optional | Yes                 | No     | No                          |
| Synology      | S256 (req)      | Required | No                  | No     | `base_url`                  |
| Tumblr        | None            | Required | Yes                 | No     | No                          |
| Twitter       | S256 (req)      | Optional | Yes                 | Yes    | No                          |
| Yahoo         | None            | Required | Yes                 | No     | No                          |
| Yandex        | None            | Required | Yes                 | No     | No                          |
| Zoom          | S256 (req)      | Required | Yes                 | Yes    | No                          |

#### Pattern B: Body Credentials (no Basic Auth)

Custom request construction. `client_id` and `client_secret` sent in POST body.

| Provider         | PKCE       | Secret   | Refresh                       | Revoke | Dynamic URLs |
| ---------------- | ---------- | -------- | ----------------------------- | ------ | ------------ |
| FortyTwo         | None       | Required | No                            | No     | No           |
| Atlassian        | None       | Required | Yes                           | No     | No           |
| BattleNet        | None       | Required | No                            | No     | No           |
| Box              | None       | Required | Yes                           | Yes    | No           |
| Coinbase         | None       | Required | Yes                           | Yes    | No           |
| DonationAlerts   | None       | Required | Yes (+ scopes)                | No     | No           |
| Dribbble         | None       | Required | No                            | No     | No           |
| Facebook         | None       | Required | No                            | No     | No           |
| Kakao            | None       | Required | Yes                           | No     | No           |
| Kick             | S256 (req) | Required | Yes                           | Yes    | No           |
| Line             | S256 (req) | Required | Yes                           | No     | No           |
| Linear           | None       | Required | No                            | No     | No           |
| LinkedIn         | None       | Required | Yes                           | No     | No           |
| MercadoLibre     | S256 (req) | Required | Yes                           | No     | No           |
| MercadoPago      | S256 (req) | Required | Yes                           | No     | No           |
| MicrosoftEntraId | S256 (req) | Optional | Yes (+ scopes)                | No     | `tenant`     |
| Naver            | None       | Required | Yes                           | No     | No           |
| Osu              | None       | Required | Yes                           | No     | No           |
| Patreon          | None       | Required | Yes                           | No     | No           |
| Polar            | S256 (req) | Optional | Yes                           | Yes    | No           |
| Shikimori        | None       | Required | Yes                           | No     | No           |
| StartGG          | None       | Required | Yes (sep. endpoint, + scopes) | No     | No           |
| Strava           | None       | Required | Yes                           | No     | No           |
| Tiltify          | None       | Required | Yes                           | No     | No           |
| Twitch           | None       | Required | Yes                           | No     | No           |
| VK               | None       | Required | No                            | No     | No           |
| WorkOS           | S256 (opt) | Optional | No                            | No     | No           |

#### Pattern C: Custom Response Parsing

Providers requiring non-standard response handling.

| Provider | Deviation                                                                                                                                |
| -------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| TikTok   | Errors returned with HTTP 200 (like GitHub); uses `client_key` instead of `client_id`                                                    |
| Withings | Errors with HTTP 200; response wrapped in `{"status": 0, "body": {...}}`; comma-delimited scopes; extra `action=requesttoken` body param |

#### Pattern D: JWT Client Authentication

| Provider | Mechanism                                                                             |
| -------- | ------------------------------------------------------------------------------------- |
| Apple    | ES256-signed JWT as `client_secret`; requires `team_id`, `key_id`, PKCS#8 private key |

### 3.2 Providers with Non-Standard Authorization URL Parameters

| Provider         | Extra Parameters                                                 |
| ---------------- | ---------------------------------------------------------------- |
| Atlassian        | `audience=api.atlassian.com`, `prompt=consent`                   |
| BattleNet        | Always sends `scope` (even empty)                                |
| DonationAlerts   | No `state` parameter                                             |
| MicrosoftEntraId | `Origin` header on public client requests                        |
| Naver            | No `state`, no `scopes` (takes no parameters)                    |
| Notion           | `owner=user`                                                     |
| Strava           | Comma-delimited scopes instead of space-delimited                |
| TikTok           | Uses `client_key` instead of `client_id`; comma-delimited scopes |
| Withings         | Comma-delimited scopes instead of space-delimited                |

### 3.3 Providers with Dynamic/Self-Hosted URLs

| Provider         | Config Parameter                     | Example Base                                      |
| ---------------- | ------------------------------------ | ------------------------------------------------- |
| AmazonCognito    | `domain`                             | `https://your-pool.auth.region.amazoncognito.com` |
| Auth0            | `domain`                             | `https://your-tenant.auth0.com`                   |
| Authentik        | `base_url`                           | `https://your-instance.example.com`               |
| Gitea            | `base_url`                           | `https://gitea.example.com`                       |
| GitLab           | `base_url`                           | `https://gitlab.example.com`                      |
| KeyCloak         | `realm_url`                          | `https://kc.example.com/realms/myrealm`           |
| Mastodon         | `base_url`                           | `https://mastodon.social`                         |
| MicrosoftEntraId | `tenant`                             | Tenant ID or `common`/`organizations`/`consumers` |
| Okta             | `domain` + `authorization_server_id` | `https://your-org.okta.com`                       |
| Salesforce       | `domain`                             | `https://login.salesforce.com`                    |
| Synology         | `base_url`                           | `https://your-synology.local:5001`                |

### 3.4 Public-Only and Optional-Secret Providers

| Provider         | Secret Model                  |
| ---------------- | ----------------------------- |
| Etsy             | Public only (no secret param) |
| Lichess          | Public only (no secret param) |
| AmazonCognito    | Optional secret               |
| Auth0            | Optional secret               |
| Authentik        | Optional secret               |
| Autodesk         | Optional secret               |
| Bungie           | Optional secret               |
| Gitea            | Optional secret               |
| GitLab           | Optional secret               |
| KeyCloak         | Optional secret               |
| MicrosoftEntraId | Optional secret               |
| Polar            | Optional secret               |
| Roblox           | Optional secret               |
| Salesforce       | Optional secret               |
| Spotify          | Optional secret               |
| Twitter          | Optional secret               |
| WorkOS           | Optional secret               |

---

## 4. Implementation Considerations

### 4.1 Naming Conflicts

- **`Box`**: Shadows `std::boxed::Box`. Recommend naming the struct `BoxProvider` or `BoxOAuth`.

### 4.2 Apple's ES256 Dependency

Apple requires ECDSA P-256 signing. This needs an additional dependency (e.g., `p256` + `ecdsa` crates, or `ring`). This should be gated behind the `apple` feature flag to avoid adding crypto dependencies for users who don't need Apple auth.

### 4.3 Providers Requiring Custom `send_token_request`

Three providers need custom token response parsing (beyond the standard `send_token_request`):

1. **GitHub** (already implemented) -- errors with HTTP 200
2. **TikTok** -- errors with HTTP 200, `client_key` instead of `client_id`
3. **Withings** -- errors with HTTP 200, wrapped response body `{"status": 0, "body": {...}}`, comma-delimited scopes, extra `action` param

### 4.4 Providers Without State Parameter

- **DonationAlerts**: No `state` in authorization URL
- **Naver**: No `state` and no `scopes` (method takes no parameters)

These providers skip CSRF protection at the OAuth level. The authorization URL methods should reflect this in their signatures.

### 4.5 Separate Refresh Endpoints

Two providers use a different endpoint for token refresh than for token exchange:

- **Figma**: Token exchange at `/token`, refresh at `/refresh`
- **Start.gg**: Token exchange at `/oauth/access_token`, refresh at `/oauth/refresh`

The implementation needs to store both endpoints for these providers.

### 4.6 Scopes on Refresh

Four providers accept scopes during token refresh:

- **AmazonCognito**: `refresh_access_token(http_client, refresh_token, scopes)`
- **DonationAlerts**: `refresh_access_token(http_client, refresh_token, scopes)`
- **MicrosoftEntraId**: `refresh_access_token(http_client, refresh_token, scopes)`
- **Okta**: `refresh_access_token(http_client, refresh_token, scopes)`
- **Start.gg**: `refresh_access_token(http_client, refresh_token, scopes)`

### 4.7 Optional Redirect URI

Three providers have an optional `redirect_uri`:

- **MyAnimeList**: `redirect_uri: Option<String>`
- **osu!**: `redirect_uri: Option<String>`
- **Slack**: `redirect_uri: Option<String>`

### 4.8 Comma-Delimited Scopes

Three providers deviate from RFC 6749 and use comma-delimited scopes instead of space-delimited:

- **Strava**
- **TikTok**
- **Withings**

### 4.9 Feature Flags

Each provider should get its own feature flag, consistent with the existing pattern:

```toml
[features]
forty-two = []
amazon-cognito = []
anilist = []
apple = ["dep:p256", "dep:ecdsa"]  # or ring
atlassian = []
auth0 = []
authentik = []
autodesk = []
battlenet = []
bitbucket = []
box-oauth = []        # Avoid shadowing std::boxed::Box
bungie = []
coinbase = []
donation-alerts = []
dribbble = []
dropbox = []
epic-games = []
etsy = []
facebook = []
figma = []
gitea = []
gitlab = []
intuit = []
kakao = []
keycloak = []
kick = []
lichess = []
line = []
linear = []
linkedin = []
mastodon = []
mercadolibre = []
mercadopago = []
microsoft-entra-id = []
myanimelist = []
naver = []
notion = []
okta = []
osu = []
patreon = []
polar = []
reddit = []
roblox = []
salesforce = []
shikimori = []
slack = []
spotify = []
startgg = []
strava = []
synology = []
tiktok = []
tiltify = []
tumblr = []
twitch = []
twitter = []
vk = []
withings = []
workos = []
yahoo = []
yandex = []
zoom = []

all-providers = [
    "google", "github", "discord",
    "forty-two", "amazon-cognito", "anilist", "apple", "atlassian",
    "auth0", "authentik", "autodesk", "battlenet", "bitbucket",
    "box-oauth", "bungie", "coinbase", "donation-alerts", "dribbble",
    "dropbox", "epic-games", "etsy", "facebook", "figma", "gitea",
    "gitlab", "intuit", "kakao", "keycloak", "kick", "lichess",
    "line", "linear", "linkedin", "mastodon", "mercadolibre",
    "mercadopago", "microsoft-entra-id", "myanimelist", "naver",
    "notion", "okta", "osu", "patreon", "polar", "reddit", "roblox",
    "salesforce", "shikimori", "slack", "spotify", "startgg",
    "strava", "synology", "tiktok", "tiltify", "tumblr", "twitch",
    "twitter", "vk", "withings", "workos", "yahoo", "yandex", "zoom",
]
```

---

## 5. Suggested Implementation Order

### Phase 1: Standard OAuth2Client Providers (No Deviations)

These require minimal code -- just endpoint configuration and OAuth2Client delegation.

1. Yandex, Yahoo, Reddit, Tiltify, Tumblr (simplest -- no PKCE, no revocation complexity)
2. Spotify, Roblox, Salesforce, Zoom (PKCE + revocation, fully standard)
3. Dropbox, EpicGames, Intuit (standard but different domains per endpoint)
4. Bitbucket, AniList (no scopes support -- signature difference)

### Phase 2: OAuth2Client with Dynamic URLs

5. GitLab, Gitea, KeyCloak, Mastodon, Authentik (self-hosted -- `base_url`/`realm_url`)
6. AmazonCognito, Auth0, Okta (multi-tenant with scopes-on-refresh)
7. Autodesk, Bungie, Twitter (optional secret)

### Phase 3: Body-Credential Providers (Simple)

8. FortyTwo, Dribbble, Linear, VK, Slack (simple body credential, no refresh)
9. Kakao, LinkedIn, Patreon, Shikimori, StartGG, Osu (body credentials + refresh)
10. Etsy, Lichess (public-only clients)
11. Coinbase, Box, Kick, Strava, Twitch, Polar (body credentials + revocation)

### Phase 4: Providers with Authorization URL Deviations

12. Atlassian (`audience`, `prompt` params)
13. Notion (`owner=user`)
14. BattleNet (always-send scope)
15. Facebook (versioned URLs)
16. DonationAlerts (no state, scopes on refresh)
17. Naver (no state, no scopes)
18. MyAnimeList (Plain PKCE, optional redirect_uri)

### Phase 5: Providers with Custom Response Parsing

19. Figma (separate refresh endpoint)
20. MicrosoftEntraId (complex -- confidential/public branching, Origin header)
21. Synology (self-hosted CGI paths)
22. MercadoLibre, MercadoPago (no scopes, body credentials)
23. Line (body credentials + PKCE)
24. WorkOS (optional PKCE, no scopes)

### Phase 6: Providers Requiring Custom Token Handling

25. TikTok (`client_key`, error-as-200)
26. Withings (wrapped response, comma scopes, `action` param, error-as-200)

### Phase 7: JWT Authentication

27. Apple (ES256 JWT client secret -- requires new dependency)
