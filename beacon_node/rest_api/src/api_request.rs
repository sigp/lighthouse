use crate::ApiError;
use hyper::Request;
use url::Url;

pub struct ApiRequest<T> {
    pub url: Url,
    pub req: Request<T>,
}

impl<T> ApiRequest<T> {
    pub fn from_http_request(req: Request<T>) -> Self {
        Self {
            url: Url::parse(&req.uri().to_string()).expect("TODO: return error"),
            req,
        }
    }

    pub fn query(&self) -> UrlQuery {
        UrlQuery(self.url.query_pairs())
    }
}

pub struct UrlQuery<'a>(url::form_urlencoded::Parse<'a>);

impl<'a> UrlQuery<'a> {
    pub fn first_of(&mut self, keys: &[&str]) -> Result<String, ApiError> {
        self.0
            .find(|(key, _value)| keys.contains(&&**key))
            .map(|(_key, value)| value.into_owned())
            .ok_or_else(|| ApiError::InvalidQueryParams {
                desc: format!(
                    "URL query must contain at least one of the following keys: {:?}",
                    keys
                ),
            })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn query_params_first_of() {
        let url = Url::parse("http://lighthouse.io/cats?a=42&b=12&c=100").unwrap();
        let get_query = || UrlQuery(url.query_pairs());

        assert_eq!(get_query().first_of(&["a"]), Ok("42".to_string()));
        assert_eq!(get_query().first_of(&["a", "b", "c"]), Ok("42".to_string()));
        assert_eq!(get_query().first_of(&["a", "a", "a"]), Ok("42".to_string()));
        assert_eq!(get_query().first_of(&["a", "b", "c"]), Ok("42".to_string()));
        assert_eq!(get_query().first_of(&["b", "c"]), Ok("12".to_string()));
        assert_eq!(get_query().first_of(&["c"]), Ok("100".to_string()));
        assert!(get_query().first_of(&["nothing"]).is_err());
    }
}
