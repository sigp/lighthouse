macro_rules! path_from_request {
    ($req:ident) => {}{
        req.uri()
            .path_and_query()
            .as_ref()
            .map(|pq| String::from(pq.as_str()))
            .unwrap_or(String::new())
    };
}

macro_rules! result_to_response {
    ($fn: path) => {
        |req: Request<Body>| -> Response<Body> {
            let log = req
                .extensions()
                .get::<slog::Logger>()
                .expect("Our logger should be on req.");
            let luke_result = $fn(req);
            match luke_result {
                Ok(response) => {
                    info!(log, "Request successful: {:?}", path_from_request!(req));
                    response
                }
                Err(e) => {
                    info!(log, "Request failure: {:?}", path_from_request!(req));
                    e.into()
                }
            }
        }
    };
}

macro_rules! success_response {
    ($fn: path) => {
        |body: Body| -> Response<Body> {
            Response::builder()
                .status(StatusCode::OK)
                .body(body)
                .expect("Should always be able to make response from version body.")
        }
    };
}
