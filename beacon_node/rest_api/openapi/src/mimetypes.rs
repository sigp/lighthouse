/// mime types for requests and responses

pub mod responses {
    use hyper::mime::*;

    // The macro is called per-operation to beat the recursion limit
    /// Create Mime objects for the response content types for NodeGenesisTimeGet
    lazy_static! {
        pub static ref NODE_GENESIS_TIME_GET_REQUEST_SUCCESSFUL: Mime = "application/json".parse().unwrap();
    }
    /// Create Mime objects for the response content types for NodeSyncingGet
    lazy_static! {
        pub static ref NODE_SYNCING_GET_REQUEST_SUCCESSFUL: Mime = "application/json".parse().unwrap();
    }
    /// Create Mime objects for the response content types for NodeVersionGet
    lazy_static! {
        pub static ref NODE_VERSION_GET_REQUEST_SUCCESSFUL: Mime = "application/json".parse().unwrap();
    }
    /// Create Mime objects for the response content types for ValidatorAttestationGet
    lazy_static! {
        pub static ref VALIDATOR_ATTESTATION_GET_SUCCESS_RESPONSE: Mime = "application/json".parse().unwrap();
    }
    /// Create Mime objects for the response content types for ValidatorBlockGet
    lazy_static! {
        pub static ref VALIDATOR_BLOCK_GET_SUCCESS_RESPONSE: Mime = "application/json".parse().unwrap();
    }
    /// Create Mime objects for the response content types for ValidatorDutiesGet
    lazy_static! {
        pub static ref VALIDATOR_DUTIES_GET_SUCCESS_RESPONSE: Mime = "application/json".parse().unwrap();
    }
    /// Create Mime objects for the response content types for NodeForkGet
    lazy_static! {
        pub static ref NODE_FORK_GET_REQUEST_SUCCESSFUL: Mime = "application/json".parse().unwrap();
    }

}

pub mod requests {
    use hyper::mime::*;

}
