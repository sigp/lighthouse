/// Add CORS headers to `reply` only if `allow_origin.is_some()`.
pub fn maybe_cors<T: warp::Reply + 'static>(
    reply: T,
    allow_origin: Option<&String>,
) -> Box<dyn warp::Reply> {
    if let Some(allow_origin) = allow_origin {
        Box::new(warp::reply::with_header(
            reply,
            "Access-Control-Allow-Origin",
            allow_origin,
        ))
    } else {
        Box::new(reply)
    }
}
