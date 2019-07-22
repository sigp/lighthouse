macro_rules! wrappy {
    ($fn: path) => (
        |req: Request<Body>| -> Response<Body> {
            let luke_result = $fn(req);
            match luke_result {
                Ok(response) => response,
                Err(e) => e.into(),
            }
        }
    )
}
