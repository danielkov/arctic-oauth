use std::future::Future;

/// A minimal HTTP request representation.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub method: http::Method,
}

/// A minimal HTTP response representation.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// Case-insensitive header lookup. Returns the first matching value.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
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
        let mut builder = self.request(req.method, &req.url);

        for (name, value) in &req.headers {
            builder = builder.header(name, value);
        }

        builder = builder.body(req.body);

        let response = builder.send().await?;
        let status = response.status().as_u16();
        let headers: Vec<(String, String)> = response
            .headers()
            .iter()
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|v| (k.as_str().to_string(), v.to_string()))
            })
            .collect();
        let body = response.bytes().await?.to_vec();

        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }
}
