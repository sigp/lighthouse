use super::{ApiError, ApiResult};
use http::header;
use hyper::{Body, Request, Response, StatusCode};
use serde::Serialize;
use ssz::Encode;

pub enum Encoding {
    JSON,
    SSZ,
    YAML,
}

pub struct ResponseBuilder {
    encoding: Encoding,
}

impl ResponseBuilder {
    pub fn new(req: &Request<Body>) -> Self {
        let encoding = match req.headers().get(header::CONTENT_TYPE) {
            Some(h) if h == "application/ssz" => Encoding::SSZ,
            Some(h) if h == "application/yaml" => Encoding::YAML,
            _ => Encoding::JSON,
        };

        Self { encoding }
    }

    pub fn body<T: Serialize + Encode>(self, item: &T) -> ApiResult {
        let (body, content_type) = match self.encoding {
            Encoding::JSON => (
                Body::from(serde_json::to_string(&item).map_err(|e| {
                    ApiError::ServerError(format!(
                        "Unable to serialize response body as JSON: {:?}",
                        e
                    ))
                })?),
                "application/json",
            ),
            Encoding::SSZ => (Body::from(item.as_ssz_bytes()), "application/ssz"),
            Encoding::YAML => (
                Body::from(serde_yaml::to_string(&item).map_err(|e| {
                    ApiError::ServerError(format!(
                        "Unable to serialize response body as YAML: {:?}",
                        e
                    ))
                })?),
                "application/ssz",
            ),
        };

        Response::builder()
            .status(StatusCode::OK)
            .header("content-type", content_type)
            .body(Body::from(body))
            .map_err(|e| ApiError::ServerError(format!("Failed to build response: {:?}", e)))
    }
}
