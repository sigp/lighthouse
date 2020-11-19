use crate::*;
use httpmock::{Method::POST, MockServer};
use tokio::time::Duration;

pub fn set_up_mock_server(status: u16, body: &str) -> MockServer {
    set_up_mock_server_with_timeout(status, body, 0)
}

pub fn set_up_mock_server_with_timeout(status: u16, body: &str, delay: u64) -> MockServer {
    let server = MockServer::start();

    server.mock(|when, then| {
        when.method(POST).path(format!("/sign/{}", PUBLIC_KEY_1));
        then.status(status)
            .delay(Duration::from_secs(delay))
            .body(body);
    });

    server
}
