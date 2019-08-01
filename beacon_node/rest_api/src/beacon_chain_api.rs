use super::{success_response, ApiResult};
use crate::ApiRequest;
use hyper::{Body, Request};
use hyper_router::{Route, Router, RouterBuilder};

pub fn beacon_node_router() -> Router {
    RouterBuilder::new()
        .add(Route::get("/state").using(result_to_response!(get_state)))
        .build()
}

/// Read the version string from the current Lighthouse build.
pub fn get_state(req: Request<Body>) -> ApiResult {
    let req = ApiRequest::from_http_request(req);

    let query_params = ["root", "slot", "epoch"];

    let param = req.query().first_of(&query_params)?;

    dbg!(param);

    let body = Body::from(
        serde_json::to_string(&"cat pants")
            .expect("Version should always be serialializable as JSON."),
    );
    Ok(success_response(body))
}
