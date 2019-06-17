use std::rc::Rc;

use hyper;
use super::configuration::Configuration;

pub struct APIClient<C: hyper::client::Connect> {
    configuration: Rc<Configuration<C>>,
    minimal_set_api: Box<::apis::MinimalSetApi>,
    optional_set_api: Box<::apis::OptionalSetApi>,
}

impl<C: hyper::client::Connect> APIClient<C> {
    pub fn new(configuration: Configuration<C>) -> APIClient<C> {
        let rc = Rc::new(configuration);

        APIClient {
            configuration: rc.clone(),
            minimal_set_api: Box::new(::apis::MinimalSetApiClient::new(rc.clone())),
            optional_set_api: Box::new(::apis::OptionalSetApiClient::new(rc.clone())),
        }
    }

    pub fn minimal_set_api(&self) -> &::apis::MinimalSetApi{
        self.minimal_set_api.as_ref()
    }

    pub fn optional_set_api(&self) -> &::apis::OptionalSetApi{
        self.optional_set_api.as_ref()
    }

}
