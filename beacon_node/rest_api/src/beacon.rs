use super::{success_response, ApiResult};
use crate::ApiRequest;
use hyper::Body;

/// Read the version string from the current Lighthouse build.
pub fn get_state(req: ApiRequest<Body>) -> ApiResult {
    let query_params = ["root", "slot", "epoch"];

    let param = req.query()?.first_of(&query_params)?;

    dbg!(param);

    let body = Body::from(
        serde_json::to_string(&"cat pants")
            .expect("Version should always be serialializable as JSON."),
    );
    Ok(success_response(body))
}
