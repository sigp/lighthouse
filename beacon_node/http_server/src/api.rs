use crate::{key::BeaconChainKey, map_persistent_err_to_500};
use beacon_chain::{BeaconChain, BeaconChainTypes};
use iron::prelude::*;
use iron::{
    headers::{CacheControl, CacheDirective, ContentType},
    status::Status,
    AfterMiddleware, Handler, IronResult, Request, Response,
};
use persistent::Read;
use router::Router;
use serde_json::json;
use std::sync::Arc;

/// Yields a handler for the HTTP API.
pub fn build_handler<T: BeaconChainTypes + 'static>(
    beacon_chain: Arc<BeaconChain<T>>,
) -> impl Handler {
    let mut router = Router::new();

    router.get("/node/fork", handle_fork::<T>, "fork");

    let mut chain = Chain::new(router);

    // Insert `BeaconChain` so it may be accessed in a request.
    chain.link(Read::<BeaconChainKey<T>>::both(beacon_chain.clone()));
    // Set the content-type headers.
    chain.link_after(SetJsonContentType);
    // Set the cache headers.
    chain.link_after(SetCacheDirectives);

    chain
}

/// Sets the `cache-control` headers on _all_ responses, unless they are already set.
struct SetCacheDirectives;
impl AfterMiddleware for SetCacheDirectives {
    fn after(&self, _req: &mut Request, mut resp: Response) -> IronResult<Response> {
        // This is run for every requests, AFTER all handlers have been executed
        if resp.headers.get::<CacheControl>() == None {
            resp.headers.set(CacheControl(vec![
                CacheDirective::NoCache,
                CacheDirective::NoStore,
            ]));
        }
        Ok(resp)
    }
}

/// Sets the `content-type` headers on _all_ responses, unless they are already set.
struct SetJsonContentType;
impl AfterMiddleware for SetJsonContentType {
    fn after(&self, _req: &mut Request, mut resp: Response) -> IronResult<Response> {
        if resp.headers.get::<ContentType>() == None {
            resp.headers.set(ContentType::json());
        }
        Ok(resp)
    }
}

fn handle_fork<T: BeaconChainTypes + 'static>(req: &mut Request) -> IronResult<Response> {
    let beacon_chain = req
        .get::<Read<BeaconChainKey<T>>>()
        .map_err(map_persistent_err_to_500)?;

    let response = json!({
        "fork": beacon_chain.head().beacon_state.fork,
        "network_id": beacon_chain.spec.network_id
    });

    Ok(Response::with((Status::Ok, response.to_string())))
}
