macro_rules! path_from_request {
    ($req: expr) => {
        $req.uri()
            .path_and_query()
            .as_ref()
            .map(|pq| String::from(pq.as_str()))
            .unwrap_or(String::new())
    };
}

macro_rules! result_to_response {
    ($handler: path) => {
        |req: Request<Body>| -> Response<Body> {
            let log = req
                .extensions()
                .get::<slog::Logger>()
                .expect("Our logger should be on req.")
                .clone();
            let path = path_from_request!(req);
            let result = $handler(req);
            match result {
                Ok(response) => {
                    info!(log, "Request successful: {:?}", path);
                    response
                }
                Err(e) => {
                    info!(log, "Request failure: {:?}", path);
                    e.into()
                }
            }
        }
    };
}

macro_rules! success_response {
    ($body: path) => {
        Response::builder()
            .status(StatusCode::OK)
            .body($body)
            .expect("Should always be able to make response from version body.")
    };
}
