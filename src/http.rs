use std::future::Future;

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
pub trait HttpClient: Send + Sync + Sized {
    fn send(
        &self,
        request: HttpRequest,
    ) -> impl Future<Output = Result<HttpResponse, Box<dyn std::error::Error + Send + Sync>>> + Send;
}

#[cfg(feature = "reqwest-client")]
static DEFAULT_CLIENT: std::sync::LazyLock<reqwest::Client> =
    std::sync::LazyLock::new(reqwest::Client::new);

#[cfg(feature = "reqwest-client")]
pub fn default_client() -> &'static reqwest::Client {
    &DEFAULT_CLIENT
}

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
