use super::{ApiError, ApiResult};
use crate::config::ApiEncodingFormat;
use http::header;
use hyper::{Body, Request, Response, StatusCode};
use serde::Serialize;
use ssz::Encode;

pub struct ResponseBuilder {
    encoding: ApiEncodingFormat,
}

impl ResponseBuilder {
    pub fn new(req: &Request<Body>) -> Result<Self, ApiError> {
        let accept_header: String = req
            .headers()
            .get(header::ACCEPT)
            .map_or(Ok(""), |h| h.to_str())
            .map_err(|e| {
                ApiError::BadRequest(format!(
                    "The Accept header contains invalid characters: {:?}",
                    e
                ))
            })
            .map(String::from)?;

        // JSON is our default encoding, unless something else is requested.
        let encoding = ApiEncodingFormat::from(accept_header.as_str());
        Ok(Self { encoding })
    }

    pub fn body<T: Serialize + Encode>(self, item: &T) -> ApiResult {
        match self.encoding {
            ApiEncodingFormat::SSZ => Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/ssz")
                .body(Body::from(item.as_ssz_bytes()))
                .map_err(|e| ApiError::ServerError(format!("Failed to build response: {:?}", e))),
            _ => self.body_no_ssz(item),
        }
    }

    pub fn body_no_ssz<T: Serialize>(self, item: &T) -> ApiResult {
        let (body, content_type) = match self.encoding {
            ApiEncodingFormat::JSON => (
                Body::from(serde_json::to_string(&item).map_err(|e| {
                    ApiError::ServerError(format!(
                        "Unable to serialize response body as JSON: {:?}",
                        e
                    ))
                })?),
                "application/json",
            ),
            ApiEncodingFormat::SSZ => {
                return Err(ApiError::UnsupportedType(
                    "Response cannot be encoded as SSZ.".into(),
                ));
            }
            ApiEncodingFormat::YAML => (
                Body::from(serde_yaml::to_string(&item).map_err(|e| {
                    ApiError::ServerError(format!(
                        "Unable to serialize response body as YAML: {:?}",
                        e
                    ))
                })?),
                "application/yaml",
            ),
        };

        Response::builder()
            .status(StatusCode::OK)
            .header("content-type", content_type)
            .body(body)
            .map_err(|e| ApiError::ServerError(format!("Failed to build response: {:?}", e)))
    }

    pub fn body_text(self, text: String) -> ApiResult {
        Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain; charset=utf-8")
            .body(Body::from(text))
            .map_err(|e| ApiError::ServerError(format!("Failed to build response: {:?}", e)))
    }
}
