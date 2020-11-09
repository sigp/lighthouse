use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct UpcheckApiResponse {
    pub status: String,
}

/// Contains the response to the `get_keys` API.
#[derive(Deserialize, Serialize)]
pub struct KeysApiResponse {
    pub keys: Vec<String>,
}

/// Contains the response to the `sign_message` API.
#[derive(Deserialize, Serialize)]
pub struct SignatureApiResponse {
    pub signature: String,
}
