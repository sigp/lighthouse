macro_rules! result_to_response {
    ($handler: path) => {
        |req: Request<Body>| -> Response<Body> {
            let log = req
                .extensions()
                .get::<slog::Logger>()
                .expect("Our logger should be on req.")
                .clone();
            let path = path_from_request(&req);
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
