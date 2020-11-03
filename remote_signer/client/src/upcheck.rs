use crate::api_response::UpcheckApiResponse;

pub fn upcheck() -> UpcheckApiResponse {
    UpcheckApiResponse {
        status: "OK".to_string(),
    }
}
