use crate::helpers::{parse_committee_index, parse_epoch, parse_signature, parse_slot};
use crate::ApiError;
use hyper::Request;
use std::collections::{HashMap, HashSet};
use types::{CommitteeIndex, Epoch, Signature, Slot};

#[derive(Default)]
pub struct UrlParams {
    pub required: HashMap<String, String>,
    pub optional: HashMap<String, String>,
    pub all_of: HashMap<String, Vec<String>>,
    pub first_of: HashMap<String, String>,
}

#[derive(PartialEq, Debug)]
enum Necessity {
    Required,
    Optional,
    AllOf,
    FirstOf,
}

pub struct AskedParams {
    first_of: Vec<String>,
    map: HashMap<String, Necessity>,
}

pub struct AskedParamsBuilder {
    req: Vec<String>,
    opt: Vec<String>,
    all_of: Vec<String>,
    first_of: Vec<String>,
}

impl AskedParamsBuilder {
    pub fn build(self) -> Result<AskedParams, ApiError> {
        let total_length =
            self.req.len() + self.opt.len() + self.all_of.len() + self.first_of.len();
        let mut uniq = HashSet::new();
        for x in self.req.iter() {
            if x.is_empty() {
                return Err(ApiError::BadRequest(
                    "Requested parameter is empty".to_string(),
                ));
            }
            if !uniq.insert(x.clone()) {
                return Err(ApiError::BadRequest(format!(
                    "Duplicate parameter: {:?}",
                    x
                )));
            }
        }
        for x in self.opt.iter() {
            if x.is_empty() {
                return Err(ApiError::BadRequest(
                    "Requested parameter is empty".to_string(),
                ));
            }
            if !uniq.insert(x.clone()) {
                return Err(ApiError::BadRequest(format!(
                    "Duplicate parameter: {:?}",
                    x
                )));
            }
        }
        for x in self.all_of.iter() {
            if x.is_empty() {
                return Err(ApiError::BadRequest(
                    "Requested parameter is empty".to_string(),
                ));
            }
            if !uniq.insert(x.clone()) {
                return Err(ApiError::BadRequest(format!(
                    "Duplicate parameter: {:?}",
                    x
                )));
            }
        }
        for x in self.first_of.iter() {
            if x.is_empty() {
                return Err(ApiError::BadRequest(
                    "Requested parameter is empty".to_string(),
                ));
            }
            if !uniq.insert(x.clone()) {
                return Err(ApiError::BadRequest(format!(
                    "Duplicate parameter: {:?}",
                    x
                )));
            }
        }
        let mut map = HashMap::with_capacity(total_length);
        map.extend(
            self.req
                .iter()
                .map(|key| (key.to_string(), Necessity::Required)),
        );
        map.extend(
            self.opt
                .iter()
                .map(|key| (key.to_string(), Necessity::Optional)),
        );
        map.extend(
            self.all_of
                .iter()
                .map(|key| (key.to_string(), Necessity::AllOf)),
        );
        map.extend(
            self.first_of
                .iter()
                .map(|key| (key.to_string(), Necessity::FirstOf)),
        );
        Ok(AskedParams {
            first_of: vec![],
            map,
        })
    }

    pub fn required(mut self, req: &[&str]) -> Self {
        self.req = req.iter().map(|i| i.to_string()).collect();
        self
    }

    pub fn optional(mut self, opt: &[&str]) -> Self {
        self.opt = opt.iter().map(|i| i.to_string()).collect();
        self
    }

    pub fn all_of(mut self, all_of: &[&str]) -> Self {
        self.all_of = all_of.iter().map(|i| i.to_string()).collect();
        self
    }

    pub fn first_of(mut self, first_of: &[&str]) -> Self {
        self.first_of = first_of.iter().map(|i| i.to_string()).collect();
        self
    }

    pub fn new() -> Self {
        Self {
            req: vec![],
            opt: vec![],
            all_of: vec![],
            first_of: vec![],
        }
    }
}

/// Provides handy functions for parsing the query parameters of a URL.
#[derive(Clone, Copy)]
pub struct UrlQuery<'a>(url::form_urlencoded::Parse<'a>);

impl<'a> UrlQuery<'a> {
    /// Instantiate from an existing `Request`.
    ///
    /// Returns `Err` if `req` does not contain any query parameters.
    pub fn from_request<T>(req: &'a Request<T>) -> Result<Self, ApiError> {
        let query_str = req.uri().query().unwrap_or_else(|| "");

        Ok(UrlQuery(url::form_urlencoded::parse(query_str.as_bytes())))
    }

    /// Returns the first `(key, value)` pair found where the `key` is in `keys`.
    ///
    /// If no match is found, an `InvalidQueryParams` error is returned.
    pub fn first_of(mut self, keys: &[&str]) -> Result<(String, String), ApiError> {
        self.0
            .find(|(key, _value)| keys.contains(&&**key))
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .ok_or_else(|| {
                ApiError::BadRequest(format!(
                    "URL query must be valid and contain at least one of the following keys: {:?}",
                    keys
                ))
            })
    }

    pub fn get_params(mut self, asked: &mut AskedParams) -> Result<UrlParams, ApiError> {
        let mut params = UrlParams::default();

        for data in self.0 {
            let param_name = data.0.to_string();
            let param_value = data.1.to_string();
            match asked.map.get(&param_name) {
                Some(Necessity::Required) => {
                    assert_eq!(asked.map.remove(&param_name), Some(Necessity::Required));
                    params.required.insert(param_name, param_value);
                }
                Some(Necessity::Optional) => {
                    asked.map.remove(&param_name);
                    params.optional.insert(param_name, param_value);
                }
                Some(Necessity::AllOf) => {
                    asked.map.remove(&param_name);
                    params.all_of.insert(param_name, vec![param_value]);
                }
                Some(Necessity::FirstOf) => {
                    for asked in asked.first_of.iter() {
                        unimplemented!()
                    }
                    params.first_of.insert(param_name, param_value);
                }
                None => {
                    if let Some(v) = params.all_of.get_mut(&param_name) {
                        v.push(param_value);
                    } else {
                        return Err(ApiError::BadRequest(format!(
                            "Unexpected parameter: {:?}",
                            param_name
                        )));
                    }
                }
            }
        }

        if !asked.map.is_empty() && asked.map.values().any(|k| *k != Necessity::Optional) {
            return Err(ApiError::BadRequest(
                "The request is missing a required parameter".to_string(),
            ));
        }

        Ok(params)
    }

    /// Returns the first `(key, value)` pair found where the `key` is in `keys`, if any.
    ///
    /// Returns `None` if no match is found.
    pub fn first_of_opt(mut self, keys: &[&str]) -> Option<(String, String)> {
        self.0
            .find(|(key, _value)| keys.contains(&&**key))
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
    }

    /// Returns the value for `key`, if and only if `key` is the only key present in the query
    /// parameters.
    pub fn only_one(self, key: &str) -> Result<String, ApiError> {
        let queries: Vec<_> = self
            .0
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();

        if queries.len() == 1 {
            let (first_key, first_value) = &queries[0]; // Must have 0 index if len is 1.
            if first_key == key {
                Ok(first_value.to_string())
            } else {
                Err(ApiError::BadRequest(format!(
                    "Only the {} query parameter is supported",
                    key
                )))
            }
        } else {
            Err(ApiError::BadRequest(format!(
                "Only one query parameter is allowed, {} supplied",
                queries.len()
            )))
        }
    }

    /// Returns a vector of all values present where `key` is in `keys
    ///
    /// If no match is found, an `InvalidQueryParams` error is returned.
    pub fn all_of(self, key: &str) -> Result<Vec<String>, ApiError> {
        let queries: Vec<_> = self
            .0
            .filter_map(|(k, v)| {
                if k.eq(key) {
                    Some(v.into_owned())
                } else {
                    None
                }
            })
            .collect();
        Ok(queries)
    }

    /// Returns the value of the first occurrence of the `epoch` key.
    pub fn epoch(self) -> Result<Epoch, ApiError> {
        self.first_of(&["epoch"])
            .and_then(|(_key, value)| parse_epoch(&value))
    }

    /// Returns the value of the first occurrence of the `slot` key.
    pub fn slot(self) -> Result<Slot, ApiError> {
        self.first_of(&["slot"])
            .and_then(|(_key, value)| parse_slot(&value))
    }

    /// Returns the value of the first occurrence of the `committee_index` key.
    pub fn committee_index(self) -> Result<CommitteeIndex, ApiError> {
        self.first_of(&["committee_index"])
            .and_then(|(_key, value)| parse_committee_index(&value))
    }

    /// Returns the value of the first occurrence of the `randao_reveal` key.
    pub fn randao_reveal(self) -> Result<Signature, ApiError> {
        self.first_of(&["randao_reveal"])
            .and_then(|(_key, value)| parse_signature(&value))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn only_one() {
        let get_result = |addr: &str, key: &str| -> Result<String, ApiError> {
            UrlQuery(url::Url::parse(addr).unwrap().query_pairs()).only_one(key)
        };

        assert_eq!(get_result("http://cat.io/?a=42", "a"), Ok("42".to_string()));
        assert!(get_result("http://cat.io/?a=42", "b").is_err());
        assert!(get_result("http://cat.io/?a=42&b=12", "a").is_err());
        assert!(get_result("http://cat.io/", "").is_err());
    }

    #[test]
    fn first_of() {
        let url = url::Url::parse("http://lighthouse.io/cats?a=42&b=12&c=100").unwrap();
        let get_query = || UrlQuery(url.query_pairs());

        assert_eq!(
            get_query().first_of(&["a"]),
            Ok(("a".to_string(), "42".to_string()))
        );
        assert_eq!(
            get_query().first_of(&["a", "b", "c"]),
            Ok(("a".to_string(), "42".to_string()))
        );
        assert_eq!(
            get_query().first_of(&["a", "a", "a"]),
            Ok(("a".to_string(), "42".to_string()))
        );
        assert_eq!(
            get_query().first_of(&["a", "b", "c"]),
            Ok(("a".to_string(), "42".to_string()))
        );
        assert_eq!(
            get_query().first_of(&["b", "c"]),
            Ok(("b".to_string(), "12".to_string()))
        );
        assert_eq!(
            get_query().first_of(&["c"]),
            Ok(("c".to_string(), "100".to_string()))
        );
        assert!(get_query().first_of(&["nothing"]).is_err());
    }

    #[test]
    fn get_params_required_param() {
        let url = url::Url::parse("http://lighthouse.io/cats").unwrap();
        let get_query = || UrlQuery(url.query_pairs());
        let mut asked_params = AskedParamsBuilder::new()
            .build()
            .expect("should have built AskedParams");
        let res = get_query()
            .get_params(&mut asked_params)
            .expect("should have a value");
        assert_eq!(res.required, HashMap::new());
        assert!(res.optional.is_empty());
        assert!(res.all_of.is_empty());
        assert!(res.first_of.is_empty());

        let asked_params = AskedParamsBuilder::new().required(&[""]).build();
        assert!(asked_params.is_err());

        let mut asked_params = AskedParamsBuilder::new()
            .required(&["a"])
            .build()
            .expect("should have built AskedParams");
        let builder = AskedParamsBuilder::new();
        let res = get_query().get_params(&mut asked_params);
        assert!(res.is_err());

        let url = url::Url::parse("http://lighthouse.io/cats?a=42").unwrap();
        let get_query = || UrlQuery(url.query_pairs());

        let mut asked_params = AskedParamsBuilder::new()
            .required(&["a"])
            .build()
            .expect("should have built AskedParams");

        let res = get_query()
            .get_params(&mut asked_params)
            .expect("should have a value");

        let map: HashMap<String, String> = [("a".to_string(), "42".to_string())]
            .into_iter()
            .cloned()
            .collect();
        assert_eq!(res.required, map);
        assert!(res.optional.is_empty());
        assert!(res.all_of.is_empty());
        assert!(res.first_of.is_empty());

        let mut asked_params = AskedParamsBuilder::new()
            .required(&["a", "b"])
            .build()
            .expect("should have built AskedParams");

        let res = get_query().get_params(&mut asked_params);

        assert!(res.is_err());

        let mut asked_params = AskedParamsBuilder::new()
            .required(&["b", "a"])
            .build()
            .expect("should have built AskedParams");

        let res = get_query().get_params(&mut asked_params);

        assert!(res.is_err());

        let mut asked_params = AskedParamsBuilder::new()
            .required(&["b"])
            .build()
            .expect("should have built AskedParams");

        let res = get_query().get_params(&mut asked_params);

        assert!(res.is_err());

        let mut asked_params = AskedParamsBuilder::new().required(&["a", "a"]).build();
        assert!(asked_params.is_err());

        let url = url::Url::parse("http://lighthouse.io/cats?a=42&b=1337&c=0").unwrap();
        let get_query = || UrlQuery(url.query_pairs());

        let mut asked_params = AskedParamsBuilder::new()
            .required(&["c", "b", "a"])
            .build()
            .expect("should have built AskedParams");

        let res = get_query()
            .get_params(&mut asked_params)
            .expect("should have a value");

        let map: HashMap<String, String> = [
            ("a".to_string(), "42".to_string()),
            ("b".to_string(), "1337".to_string()),
            ("c".to_string(), "0".to_string()),
        ]
        .into_iter()
        .cloned()
        .collect();
        assert_eq!(res.required, map);
        assert!(res.optional.is_empty());
        assert!(res.all_of.is_empty());
        assert!(res.first_of.is_empty());
    }
}
