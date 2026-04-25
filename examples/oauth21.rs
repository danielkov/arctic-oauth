//! Generic OAuth 2.1 + Dynamic Client Registration example.
//!
//! Probes the provider's resource URL, parses the
//! `WWW-Authenticate: Bearer ... resource_metadata="..."` hint to find the
//! protected-resource metadata (RFC 9728), discovers the authorization
//! server (RFC 8414), dynamically registers a public native client
//! (RFC 7591), and runs the authorization-code → refresh → revoke flow.
//!
//! ```sh
//! cargo run --example oauth2_1 --features oauth2_1 -- --provider linear
//! cargo run --example oauth2_1 --features oauth2_1 -- --provider notion
//! cargo run --example oauth2_1 --features oauth2_1 -- --provider asana
//! cargo run --example oauth2_1 --features oauth2_1 -- --provider cloudflare
//! cargo run --example oauth2_1 --features oauth2_1 -- --provider paypal
//! ```

use std::env;
use std::time::Duration;

use arctic_oauth::{
    AuthorizationCodeGrant, AuthorizationServerMetadata, ClientAuthenticationMethod,
    ClientRegistrationRequest, LoopbackHost, OAuth21Client, OAuth21Options,
    ProtectedResourceMetadata, RedirectUri, RefreshTokenGrant, register_client,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use url::Url;

struct Provider {
    name: &'static str,
    resource: &'static str,
}

static PROVIDERS: &[Provider] = &[
    Provider {
        name: "linear",
        resource: "https://mcp.linear.app/mcp",
    },
    Provider {
        name: "notion",
        resource: "https://mcp.notion.com/mcp",
    },
    Provider {
        name: "asana",
        resource: "https://mcp.asana.com/sse",
    },
    Provider {
        name: "cloudflare",
        resource: "https://bindings.mcp.cloudflare.com/sse",
    },
    Provider {
        name: "paypal",
        resource: "https://mcp.paypal.com/sse",
    },
];

fn lookup_provider(name: &str) -> Option<&'static Provider> {
    PROVIDERS.iter().find(|p| p.name == name)
}

fn print_help() {
    let names = PROVIDERS
        .iter()
        .map(|p| p.name)
        .collect::<Vec<_>>()
        .join(", ");
    println!("Usage: oauth2_1 --provider <name>\nProviders: {names}");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut argv = env::args().skip(1);
    let mut name: Option<String> = None;
    while let Some(flag) = argv.next() {
        match flag.as_str() {
            "--provider" => name = argv.next(),
            "-h" | "--help" => {
                print_help();
                return Ok(());
            }
            other => {
                eprintln!("unknown flag: {other}");
                print_help();
                std::process::exit(2);
            }
        }
    }

    let provider = name.as_deref().and_then(lookup_provider).ok_or_else(|| {
        print_help();
        "missing or unknown --provider"
    })?;

    let http = arctic_oauth::default_client();

    println!("== {} ==", provider.name);

    // Step 1: discover protected-resource metadata. Probes the resource for
    // the RFC 9728 §5.1 WWW-Authenticate hint, falling back to §3.1
    // well-known URL derivation.
    let prm = ProtectedResourceMetadata::discover(http, provider.resource).await?;
    let issuer = prm
        .authorization_servers
        .first()
        .cloned()
        .ok_or("protected-resource metadata had no authorization_servers")?;
    println!("issuer:   {issuer}");

    // Step 3: fetch RFC 8414 authorization-server metadata (OIDC fallback).
    let as_meta = match AuthorizationServerMetadata::fetch(http, &issuer).await {
        Ok(m) => m,
        Err(_) => AuthorizationServerMetadata::fetch_oidc(http, &issuer).await?,
    };
    let registration_endpoint = as_meta
        .registration_endpoint
        .clone()
        .ok_or("authorization server does not advertise a dynamic registration endpoint")?;

    // Step 4: bind a loopback listener; OS-assigned port goes into the
    // redirect_uri we register and authorize against.
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let redirect_uri_string = format!("http://127.0.0.1:{port}/callback");
    let redirect_uri = RedirectUri::Loopback {
        host: LoopbackHost::V4,
        port,
        path: "/callback".into(),
    };

    // Step 5: dynamic client registration (RFC 7591).
    let mut reg = ClientRegistrationRequest::public_native(vec![redirect_uri_string]);
    reg.client_name = Some("arctic-oauth example".into());
    let registered = register_client(http, &registration_endpoint, &reg).await?;
    println!("client_id: {}", registered.client_id);

    // Step 6: build the OAuth 2.1 client.
    let client_auth_method = if registered.client_secret.is_some() {
        ClientAuthenticationMethod::ClientSecretPost
    } else {
        ClientAuthenticationMethod::None
    };
    let client = OAuth21Client::from_options(OAuth21Options {
        issuer: as_meta.issuer.clone(),
        authorization_endpoint: as_meta.authorization_endpoint.clone(),
        token_endpoint: as_meta.token_endpoint.clone(),
        revocation_endpoint: as_meta.revocation_endpoint.clone(),
        introspection_endpoint: as_meta.introspection_endpoint.clone(),
        client_id: registered.client_id.clone(),
        client_secret: registered.client_secret.clone(),
        client_auth_method,
        issuer_policy: as_meta.issuer_policy(),
        redirect_uri,
        http_client: http,
    })?;

    // Step 7: authorization request, including RFC 8707 resource indicator.
    let resource = arctic_oauth::Resource::parse(&prm.resource)?;
    let authorization = client
        .authorization_request()
        .resource(resource.clone())
        .build();

    println!("listening on http://127.0.0.1:{port}/callback");
    println!("opening browser…");
    if let Err(e) = webbrowser::open(authorization.url.as_str()) {
        eprintln!("could not open browser ({e}); paste this URL manually:");
        eprintln!("{}", authorization.url);
    }

    // Step 8: accept the redirect, exchange code → tokens.
    let callback_url = accept_callback(&listener, port).await?;
    let callback = client.parse_callback(&callback_url, &authorization.state)?;
    println!("received code (state ok); exchanging…");

    let tokens = client
        .validate_authorization_code(AuthorizationCodeGrant {
            code: &callback.code,
            code_verifier: &authorization.code_verifier,
            resource: std::slice::from_ref(&resource),
        })
        .await?;
    println!("access_token: {}", truncate(tokens.access_token()?));
    if let Ok(s) = tokens.scopes() {
        println!("scope:        {}", s.join(" "));
    }
    if let Ok(secs) = tokens.access_token_expires_in_seconds() {
        println!("expires_in:   {secs}s");
    }

    // Step 9: refresh.
    let Ok(refresh_token) = tokens.refresh_token() else {
        println!("\nno refresh_token returned; skipping refresh + revoke.");
        return Ok(());
    };
    println!("\nsleeping 5s before refresh…");
    tokio::time::sleep(Duration::from_secs(5)).await;
    let refreshed = client
        .refresh_access_token(RefreshTokenGrant {
            refresh_token,
            scopes: &[],
            resource: std::slice::from_ref(&resource),
        })
        .await?;
    println!(
        "refreshed access_token: {}",
        truncate(refreshed.access_token()?)
    );

    // Step 10: revoke.
    if as_meta.revocation_endpoint.is_some() {
        println!("\nsleeping 5s before revoke…");
        tokio::time::sleep(Duration::from_secs(5)).await;
        let to_revoke = refreshed
            .refresh_token()
            .unwrap_or_else(|_| refreshed.access_token().unwrap_or(""));
        client.revoke_token(to_revoke).await?;
        println!("revoked.");
    } else {
        println!("\nno revocation_endpoint advertised; skipping revoke.");
    }

    Ok(())
}

fn truncate(token: &str) -> String {
    let prefix: String = token.chars().take(12).collect();
    format!("{prefix}…")
}

async fn accept_callback(
    listener: &TcpListener,
    port: u16,
) -> Result<Url, Box<dyn std::error::Error>> {
    let (mut sock, _peer) = listener.accept().await?;

    let mut buf = vec![0u8; 8192];
    let mut n = 0usize;
    loop {
        let read = sock.read(&mut buf[n..]).await?;
        if read == 0 {
            break;
        }
        n += read;
        if buf[..n].windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if n == buf.len() {
            return Err("callback request too large".into());
        }
    }

    let request = std::str::from_utf8(&buf[..n])?;
    let request_line = request.lines().next().ok_or("callback request was empty")?;
    let path_with_qs = request_line
        .split_whitespace()
        .nth(1)
        .ok_or("could not parse request line")?;

    let body = b"<!doctype html><meta charset=utf-8><title>arctic-oauth</title>\
        <h1>You can close this tab.</h1>";
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    sock.write_all(response.as_bytes()).await?;
    sock.write_all(body).await?;
    sock.shutdown().await.ok();

    Ok(Url::parse(&format!(
        "http://127.0.0.1:{port}{path_with_qs}"
    ))?)
}
