use eth2::types::{ErrorMessage, Failure, IndexedErrorMessage};
use std::convert::Infallible;
use std::error::Error;
use std::fmt;
use warp::{http::StatusCode, reject::Reject};

#[derive(Debug)]
pub struct ServerSentEventError(pub String);

impl Error for ServerSentEventError {}

impl fmt::Display for ServerSentEventError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub fn server_sent_event_error(s: String) -> ServerSentEventError {
    ServerSentEventError(s)
}

#[derive(Debug)]
pub struct BeaconChainError(pub beacon_chain::BeaconChainError);

impl Reject for BeaconChainError {}

pub fn beacon_chain_error(e: beacon_chain::BeaconChainError) -> warp::reject::Rejection {
    warp::reject::custom(BeaconChainError(e))
}

#[derive(Debug)]
pub struct BeaconStateError(pub types::BeaconStateError);

impl Reject for BeaconStateError {}

pub fn beacon_state_error(e: types::BeaconStateError) -> warp::reject::Rejection {
    warp::reject::custom(BeaconStateError(e))
}

#[derive(Debug)]
pub struct ArithError(pub safe_arith::ArithError);

impl Reject for ArithError {}

pub fn arith_error(e: safe_arith::ArithError) -> warp::reject::Rejection {
    warp::reject::custom(ArithError(e))
}

#[derive(Debug)]
pub struct SlotProcessingError(pub state_processing::SlotProcessingError);

impl Reject for SlotProcessingError {}

pub fn slot_processing_error(e: state_processing::SlotProcessingError) -> warp::reject::Rejection {
    warp::reject::custom(SlotProcessingError(e))
}

#[derive(Debug)]
pub struct BlockProductionError(pub beacon_chain::BlockProductionError);

impl Reject for BlockProductionError {}

pub fn block_production_error(e: beacon_chain::BlockProductionError) -> warp::reject::Rejection {
    warp::reject::custom(BlockProductionError(e))
}

#[derive(Debug)]
pub struct CustomNotFound(pub String);

impl Reject for CustomNotFound {}

pub fn custom_not_found(msg: String) -> warp::reject::Rejection {
    warp::reject::custom(CustomNotFound(msg))
}

#[derive(Debug)]
pub struct CustomBadRequest(pub String);

impl Reject for CustomBadRequest {}

pub fn custom_bad_request(msg: String) -> warp::reject::Rejection {
    warp::reject::custom(CustomBadRequest(msg))
}

#[derive(Debug)]
pub struct CustomServerError(pub String);

impl Reject for CustomServerError {}

pub fn custom_server_error(msg: String) -> warp::reject::Rejection {
    warp::reject::custom(CustomServerError(msg))
}

#[derive(Debug)]
pub struct BroadcastWithoutImport(pub String);

impl Reject for BroadcastWithoutImport {}

pub fn broadcast_without_import(msg: String) -> warp::reject::Rejection {
    warp::reject::custom(BroadcastWithoutImport(msg))
}

#[derive(Debug)]
pub struct ObjectInvalid(pub String);

impl Reject for ObjectInvalid {}

pub fn object_invalid(msg: String) -> warp::reject::Rejection {
    warp::reject::custom(ObjectInvalid(msg))
}

#[derive(Debug)]
pub struct NotSynced(pub String);

impl Reject for NotSynced {}

pub fn not_synced(msg: String) -> warp::reject::Rejection {
    warp::reject::custom(NotSynced(msg))
}

#[derive(Debug)]
pub struct InvalidAuthorization(pub String);

impl Reject for InvalidAuthorization {}

pub fn invalid_auth(msg: String) -> warp::reject::Rejection {
    warp::reject::custom(InvalidAuthorization(msg))
}

#[derive(Debug)]
pub struct IndexedBadRequestErrors {
    pub message: String,
    pub failures: Vec<Failure>,
}

impl Reject for IndexedBadRequestErrors {}

pub fn indexed_bad_request(message: String, failures: Vec<Failure>) -> warp::reject::Rejection {
    warp::reject::custom(IndexedBadRequestErrors { message, failures })
}

/// This function receives a `Rejection` and tries to return a custom
/// value, otherwise simply passes the rejection along.
pub async fn handle_rejection(err: warp::Rejection) -> Result<impl warp::Reply, Infallible> {
    let code;
    let message;

    if let Some(e) = err.find::<crate::reject::IndexedBadRequestErrors>() {
        message = format!("BAD_REQUEST: {}", e.message);
        code = StatusCode::BAD_REQUEST;

        let json = warp::reply::json(&IndexedErrorMessage {
            code: code.as_u16(),
            message,
            failures: e.failures.clone(),
        });

        return Ok(warp::reply::with_status(json, code));
    }

    if err.is_not_found() {
        code = StatusCode::NOT_FOUND;
        message = "NOT_FOUND".to_string();
    } else if let Some(e) = err.find::<warp::filters::body::BodyDeserializeError>() {
        message = format!("BAD_REQUEST: body deserialize error: {}", e);
        code = StatusCode::BAD_REQUEST;
    } else if let Some(e) = err.find::<warp::reject::InvalidQuery>() {
        code = StatusCode::BAD_REQUEST;
        message = format!("BAD_REQUEST: invalid query: {}", e);
    } else if let Some(e) = err.find::<crate::reject::BeaconChainError>() {
        code = StatusCode::INTERNAL_SERVER_ERROR;
        message = format!("UNHANDLED_ERROR: {:?}", e.0);
    } else if let Some(e) = err.find::<crate::reject::BeaconStateError>() {
        code = StatusCode::INTERNAL_SERVER_ERROR;
        message = format!("UNHANDLED_ERROR: {:?}", e.0);
    } else if let Some(e) = err.find::<crate::reject::SlotProcessingError>() {
        code = StatusCode::INTERNAL_SERVER_ERROR;
        message = format!("UNHANDLED_ERROR: {:?}", e.0);
    } else if let Some(e) = err.find::<crate::reject::BlockProductionError>() {
        code = StatusCode::INTERNAL_SERVER_ERROR;
        message = format!("UNHANDLED_ERROR: {:?}", e.0);
    } else if let Some(e) = err.find::<crate::reject::CustomNotFound>() {
        code = StatusCode::NOT_FOUND;
        message = format!("NOT_FOUND: {}", e.0);
    } else if let Some(e) = err.find::<crate::reject::CustomBadRequest>() {
        code = StatusCode::BAD_REQUEST;
        message = format!("BAD_REQUEST: {}", e.0);
    } else if let Some(e) = err.find::<crate::reject::CustomServerError>() {
        code = StatusCode::INTERNAL_SERVER_ERROR;
        message = format!("INTERNAL_SERVER_ERROR: {}", e.0);
    } else if let Some(e) = err.find::<crate::reject::BroadcastWithoutImport>() {
        code = StatusCode::ACCEPTED;
        message = format!(
            "ACCEPTED: the object was broadcast to the network without being \
            fully imported to the local database: {}",
            e.0
        );
    } else if let Some(e) = err.find::<crate::reject::ObjectInvalid>() {
        code = StatusCode::BAD_REQUEST;
        message = format!("BAD_REQUEST: Invalid object: {}", e.0);
    } else if let Some(e) = err.find::<crate::reject::NotSynced>() {
        code = StatusCode::SERVICE_UNAVAILABLE;
        message = format!("SERVICE_UNAVAILABLE: beacon node is syncing: {}", e.0);
    } else if let Some(e) = err.find::<crate::reject::InvalidAuthorization>() {
        code = StatusCode::FORBIDDEN;
        message = format!("FORBIDDEN: Invalid auth token: {}", e.0);
    } else if let Some(e) = err.find::<warp::reject::MissingHeader>() {
        if e.name().eq("Authorization") {
            code = StatusCode::UNAUTHORIZED;
            message = "UNAUTHORIZED: missing Authorization header".to_string();
        } else {
            code = StatusCode::BAD_REQUEST;
            message = format!("BAD_REQUEST: missing {} header", e.name());
        }
    } else if let Some(e) = err.find::<warp::reject::InvalidHeader>() {
        code = StatusCode::BAD_REQUEST;
        message = format!("BAD_REQUEST: invalid {} header", e.name());
    } else if err.find::<warp::reject::MethodNotAllowed>().is_some() {
        code = StatusCode::METHOD_NOT_ALLOWED;
        message = "METHOD_NOT_ALLOWED".to_string();
    } else {
        code = StatusCode::INTERNAL_SERVER_ERROR;
        message = "UNHANDLED_REJECTION".to_string();
    }

    let json = warp::reply::json(&ErrorMessage {
        code: code.as_u16(),
        message,
        stacktraces: vec![],
    });

    Ok(warp::reply::with_status(json, code))
}
