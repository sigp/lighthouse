use axum::{extract::Request, http::header, middleware::Next, response::Response};

/// Adds the "Server" header to all responses.
pub async fn add_server_header(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;

    if let Ok(server_header) = lighthouse_version::version_with_platform().parse() {
        response.headers_mut().insert(header::SERVER, server_header);
    }

    response
}
