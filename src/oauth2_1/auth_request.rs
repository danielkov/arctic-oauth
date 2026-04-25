use url::Url;

use crate::error::Error;
use crate::http::HttpClient;
use crate::pkce::{CodeChallengeMethod, create_code_challenge, generate_code_verifier};
use crate::state::generate_state;

use super::client::OAuth21Client;
use super::resource::Resource;

/// Builder for the authorization request.
///
/// PKCE is always present on the wire and `S256` is the only challenge method
/// emitted. State and code verifier are generated automatically unless
/// supplied; the generated values are returned alongside the URL so callers
/// can persist them in session storage.
pub struct AuthorizationRequest<'a, H: HttpClient> {
    client: &'a OAuth21Client<'a, H>,
    scopes: Vec<String>,
    state: Option<String>,
    code_verifier: Option<String>,
    resource: Vec<Resource>,
    audience: Option<String>,
    prompt: Option<String>,
    login_hint: Option<String>,
    max_age: Option<u64>,
    acr_values: Vec<String>,
    ui_locales: Vec<String>,
    extra: Vec<(String, String)>,
}

/// Result of building an authorization request.
///
/// `state` and `code_verifier` should be persisted to the user's session
/// before redirecting them to `url`.
#[derive(Debug, Clone)]
pub struct AuthorizationUrl {
    pub url: Url,
    pub state: String,
    pub code_verifier: String,
}

impl<'a, H: HttpClient> AuthorizationRequest<'a, H> {
    pub(super) fn new(client: &'a OAuth21Client<'a, H>) -> Self {
        Self {
            client,
            scopes: Vec::new(),
            state: None,
            code_verifier: None,
            resource: Vec::new(),
            audience: None,
            prompt: None,
            login_hint: None,
            max_age: None,
            acr_values: Vec::new(),
            ui_locales: Vec::new(),
            extra: Vec::new(),
        }
    }

    pub fn scope(mut self, scope: impl Into<String>) -> Self {
        self.scopes.push(scope.into());
        self
    }

    pub fn scopes<I, S>(mut self, scopes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.scopes.extend(scopes.into_iter().map(Into::into));
        self
    }

    pub fn state(mut self, state: impl Into<String>) -> Self {
        self.state = Some(state.into());
        self
    }

    pub fn code_verifier(mut self, verifier: impl Into<String>) -> Self {
        self.code_verifier = Some(verifier.into());
        self
    }

    pub fn resource(mut self, resource: Resource) -> Self {
        self.resource.push(resource);
        self
    }

    pub fn resource_url(mut self, resource: &str) -> Result<Self, Error> {
        self.resource.push(Resource::parse(resource)?);
        Ok(self)
    }

    pub fn audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }

    pub fn prompt(mut self, prompt: impl Into<String>) -> Self {
        self.prompt = Some(prompt.into());
        self
    }

    pub fn login_hint(mut self, hint: impl Into<String>) -> Self {
        self.login_hint = Some(hint.into());
        self
    }

    pub fn max_age(mut self, seconds: u64) -> Self {
        self.max_age = Some(seconds);
        self
    }

    pub fn acr_value(mut self, value: impl Into<String>) -> Self {
        self.acr_values.push(value.into());
        self
    }

    pub fn ui_locale(mut self, locale: impl Into<String>) -> Self {
        self.ui_locales.push(locale.into());
        self
    }

    pub fn extra_param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra.push((key.into(), value.into()));
        self
    }

    pub fn build(self) -> AuthorizationUrl {
        let state = self.state.unwrap_or_else(generate_state);
        let code_verifier = self.code_verifier.unwrap_or_else(generate_code_verifier);
        let code_challenge = create_code_challenge(&code_verifier, CodeChallengeMethod::S256);

        let mut url = Url::parse(&self.client.authorization_endpoint)
            .expect("invalid authorization endpoint URL");

        {
            let mut q = url.query_pairs_mut();
            q.append_pair("response_type", "code");
            q.append_pair("client_id", &self.client.client_id);
            q.append_pair("state", &state);
            q.append_pair("code_challenge", &code_challenge);
            q.append_pair("code_challenge_method", "S256");
            q.append_pair("redirect_uri", &self.client.redirect_uri.to_uri_string());

            if !self.scopes.is_empty() {
                let joined = self
                    .scopes
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .join(" ");
                q.append_pair("scope", &joined);
            }

            for resource in &self.resource {
                q.append_pair("resource", resource.as_str());
            }

            if let Some(audience) = &self.audience {
                q.append_pair("audience", audience);
            }
            if let Some(prompt) = &self.prompt {
                q.append_pair("prompt", prompt);
            }
            if let Some(hint) = &self.login_hint {
                q.append_pair("login_hint", hint);
            }
            if let Some(max_age) = self.max_age {
                q.append_pair("max_age", &max_age.to_string());
            }
            if !self.acr_values.is_empty() {
                q.append_pair("acr_values", &self.acr_values.join(" "));
            }
            if !self.ui_locales.is_empty() {
                q.append_pair("ui_locales", &self.ui_locales.join(" "));
            }

            for (k, v) in &self.extra {
                q.append_pair(k, v);
            }
        }

        AuthorizationUrl {
            url,
            state,
            code_verifier,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{HttpRequest, HttpResponse};
    use crate::oauth2_1::client::{
        ClientAuthenticationMethod, IssuerPolicy, OAuth21Options, RedirectUri,
    };
    use std::sync::Mutex;

    struct Mock(Mutex<()>);
    impl Mock {
        fn new() -> Self {
            Self(Mutex::new(()))
        }
    }
    impl HttpClient for Mock {
        async fn send(
            &self,
            _: HttpRequest,
        ) -> Result<HttpResponse, Box<dyn std::error::Error + Send + Sync>> {
            unreachable!("auth request builder does not perform HTTP calls")
        }
    }

    fn make_client(http: &Mock) -> OAuth21Client<'_, Mock> {
        OAuth21Client::from_options(OAuth21Options {
            issuer: "https://as.example.com".into(),
            authorization_endpoint: "https://as.example.com/authorize".into(),
            token_endpoint: "https://as.example.com/token".into(),
            revocation_endpoint: None,
            introspection_endpoint: None,
            client_id: "cid".into(),
            client_secret: None,
            client_auth_method: ClientAuthenticationMethod::None,
            issuer_policy: IssuerPolicy::Optional,
            redirect_uri: RedirectUri::Exact("https://app/cb".into()),
            http_client: http,
        })
        .unwrap()
    }

    fn pairs(url: &Url) -> Vec<(String, String)> {
        url.query_pairs().into_owned().collect()
    }

    #[test]
    fn build_includes_required_params() {
        let http = Mock::new();
        let client = make_client(&http);
        let result = client
            .authorization_request()
            .state("st")
            .code_verifier("verifier-x")
            .scopes(["openid", "email"])
            .build();

        let p = pairs(&result.url);
        assert!(p.contains(&("response_type".into(), "code".into())));
        assert!(p.contains(&("client_id".into(), "cid".into())));
        assert!(p.contains(&("state".into(), "st".into())));
        assert!(p.contains(&("code_challenge_method".into(), "S256".into())));
        assert!(p.contains(&("redirect_uri".into(), "https://app/cb".into())));
        assert!(p.contains(&("scope".into(), "openid email".into())));
        assert_eq!(result.state, "st");
        assert_eq!(result.code_verifier, "verifier-x");
        // S256(verifier-x)
        let expected_challenge = create_code_challenge("verifier-x", CodeChallengeMethod::S256);
        assert!(p.contains(&("code_challenge".into(), expected_challenge)));
    }

    #[test]
    fn build_generates_state_and_verifier_when_unset() {
        let http = Mock::new();
        let client = make_client(&http);
        let result = client.authorization_request().build();
        assert_eq!(result.state.len(), 43);
        assert_eq!(result.code_verifier.len(), 43);
    }

    #[test]
    fn build_appends_repeated_resource_params() {
        let http = Mock::new();
        let client = make_client(&http);
        let result = client
            .authorization_request()
            .resource_url("https://api1.example.com")
            .unwrap()
            .resource_url("https://api2.example.com")
            .unwrap()
            .build();

        let resources: Vec<String> = result
            .url
            .query_pairs()
            .filter(|(k, _)| k == "resource")
            .map(|(_, v)| v.into_owned())
            .collect();
        assert_eq!(
            resources,
            vec![
                "https://api1.example.com/".to_string(),
                "https://api2.example.com/".to_string(),
            ]
        );
    }

    #[test]
    fn build_emits_oidc_params() {
        let http = Mock::new();
        let client = make_client(&http);
        let result = client
            .authorization_request()
            .prompt("login")
            .login_hint("user@example.com")
            .max_age(3600)
            .acr_value("urn:mace:incommon:iap:silver")
            .ui_locale("en-US")
            .audience("https://api")
            .build();

        let p = pairs(&result.url);
        assert!(p.contains(&("prompt".into(), "login".into())));
        assert!(p.contains(&("login_hint".into(), "user@example.com".into())));
        assert!(p.contains(&("max_age".into(), "3600".into())));
        assert!(p.contains(&("acr_values".into(), "urn:mace:incommon:iap:silver".into())));
        assert!(p.contains(&("ui_locales".into(), "en-US".into())));
        assert!(p.contains(&("audience".into(), "https://api".into())));
    }

    #[test]
    fn build_includes_extra_params() {
        let http = Mock::new();
        let client = make_client(&http);
        let result = client
            .authorization_request()
            .extra_param("nonce", "abc")
            .build();
        let p = pairs(&result.url);
        assert!(p.contains(&("nonce".into(), "abc".into())));
    }

    #[test]
    fn build_omits_scope_when_empty() {
        let http = Mock::new();
        let client = make_client(&http);
        let result = client.authorization_request().build();
        let p = pairs(&result.url);
        assert!(!p.iter().any(|(k, _)| k == "scope"));
    }
}
