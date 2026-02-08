use arctic_oauth::{HttpClient, HttpRequest, HttpResponse};
use std::sync::Mutex;

/// An `HttpClient` implementation that records requests and returns
/// pre-configured responses. Used for unit-testing provider logic
/// without a network server.
pub struct MockHttpClient {
    /// Pre-configured responses to return in order.
    responses: Mutex<Vec<HttpResponse>>,
    /// Recorded requests for assertion.
    recorded: Mutex<Vec<HttpRequest>>,
}

impl MockHttpClient {
    pub fn new() -> Self {
        Self {
            responses: Mutex::new(Vec::new()),
            recorded: Mutex::new(Vec::new()),
        }
    }

    /// Add a response to the queue. Responses are returned in FIFO order.
    pub fn enqueue_response(&self, response: HttpResponse) {
        self.responses.lock().unwrap().push(response);
    }

    /// Drain and return all recorded requests.
    pub fn take_requests(&self) -> Vec<HttpRequest> {
        self.recorded.lock().unwrap().drain(..).collect()
    }
}

impl HttpClient for MockHttpClient {
    async fn send(
        &self,
        request: HttpRequest,
    ) -> Result<HttpResponse, Box<dyn std::error::Error + Send + Sync>> {
        self.recorded.lock().unwrap().push(request);
        let response = self.responses.lock().unwrap().remove(0);
        Ok(response)
    }
}
