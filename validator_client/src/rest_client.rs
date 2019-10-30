use crate::config::{ApiEncodingFormat, Config as ValidatorConfig};
use crate::error::{BeaconNodeError, PublishOutcome, ValidatorError};
use crate::service::BoxFut;
use hyper::client::connect::Connect;
use hyper::client::Builder;
use hyper::http::header;
use hyper::http::{Method, StatusCode};
use hyper::rt::{Future, Stream};
use hyper::{Body, Client, Request, Response};
use serde::Serialize;
use tokio::prelude::*;
use url::Url;

pub struct RestClient<T: Connect> {
    pub config: ValidatorConfig,
    base_url: Url,
    client: Client<T>,
}

impl<T: Connect> RestClient<T> {
    pub fn new(config: ValidatorConfig) -> Result<Self, ValidatorError> {
        //TODO: Make this generic, so it can take unix sockets
        let mut base_url = Url::parse(config.server.as_str())?;
        base_url.set_port(Some(config.server_http_port)).map_err(
            ValidatorError::InvalidConfiguration("Port number cannot be set.".into()),
        )?;
        base_url
            .set_scheme("http")
            .map_err(ValidatorError::InvalidConfiguration(
                "Server is not valid for a HTTP url scheme.".into(),
            ))?;
        let client = Client::builder().keep_alive(false).build_http();
        Ok(Self {
            config,
            base_url,
            client,
        })
    }

    pub fn make_get_request(
        &self,
        path: &str,
        params: Vec<(&str, &str)>,
    ) -> BoxFut<Response<Body>, BeaconNodeError> {
        let mut request = self
            .get_builder(Method::GET, path, params)
            .header(header::ACCEPT, self.config.api_encoding.get_content_type())
            .body(Body::empty());
        self.client.request(request)
    }

    pub fn make_get_request_with_timeout(
        &self,
        path: &str,
        params: Vec<(&str, &str)>,
    ) -> BoxFut<Response<Body>, BeaconNodeError> {
        let mut request = self
            .get_builder(Method::GET, path, params)
            .header(header::ACCEPT, self.config.api_encoding.get_content_type())
            .body(Body::empty());
        self.client
            .request(request)
            .and_then(|mut response| response.body_mut().concat2())
            .timeout(std::time::Duration::from_secs(30))
    }

    pub fn make_post_request<S: Serialize>(
        &self,
        path: &str,
        content: S,
    ) -> BoxFut<Response<Body>, BeaconNodeError> {
        let encoded_content_result = match self.config.api_encoding {
            ApiEncodingFormat::JSON => serde_json::to_string(&content),
            ApiEncodingFormat::YAML => serde_yaml::to_string(&content),
        };
        let content_type = self.config.api_encoding.get_content_type();
        let encoded_content = encoded_content_result.map_err(|e| {
            ValidatorError::SystemError(format!(
                "Unable to serialize the request body as {}: {:?}",
                content_type, e
            ))
        })?;
        let mut request = self
            .get_builder(Method::POST, path, Vec::new())
            .header("content-type", content_type)
            .body(Body::from(encoded_content));
        self.client.request(request)
    }

    fn get_builder(&self, method: Method, path: &str, params: Vec<(&str, &str)>) -> &mut Builder {
        let mut url = self.base_url.clone();
        url.set_path(path);
        url.query_pairs_mut()
            .clear()
            .extend_pairs(params.into_iter());
        Request::builder()
            .method(method)
            .uri(url)
            .header("Accept", self.config.api_encoding.get_content_type())
    }

    /// Handles the publication of both blocks and attestations
    pub fn handle_publication<S: Serialize>(
        &self,
        endpoint: &str,
        item: S,
    ) -> BoxFut<PublishOutcome, BeaconNodeError> {
        self.make_post_request(self.endpoint.as_str(), item)
            .and_then(|response| {
                let body_future = response
                    .into_body()
                    .fold(|mut acc, chunk| {
                        acc.extend_from_slice(&chunk);
                        Ok(acc)
                    })
                    .map_err(|e| {
                        BeaconNodeError::DecodeFailure("Unable to read response body.".into())
                    })
                    .and_then(|chunks| String::from_utf8(chunks))
                    .map_err(|e| {
                        BeaconNodeError::DecodeFailure(format!(
                            "Response body not valid UTF8: {:?}",
                            e
                        ))
                    });
                match response.status {
                    // If it's OK, it's all good.
                    StatusCode::OK => futures::future::ok(PublishOutcome::Valid),
                    // If it's ACCEPTED (202), there was a problem, but it was sent anyway
                    // The body of the response may have more information for us, so get it.
                    StatusCode::ACCEPTED => {
                        body_future.and_then(|body| PublishOutcome::Invalid(body))
                    }
                    StatusCode::BAD_REQUEST => {
                        body_future.and_then(|body| PublishOutcome::Rejected(body))
                    }
                    _ => body_future.and_then(|body| {
                        BeaconNodeError::RemoteFailure(format!(
                            "Error from beacon node: {:?}",
                            body
                        ))
                    }),
                }
            })
    }
}
