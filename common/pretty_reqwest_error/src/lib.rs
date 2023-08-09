use sensitive_url::SensitiveUrl;
use std::error::Error as StdError;
use std::fmt;

pub struct PrettyReqwestError(reqwest::Error);

impl PrettyReqwestError {
    pub fn inner(&self) -> &reqwest::Error {
        &self.0
    }
}

impl fmt::Debug for PrettyReqwestError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if let Some(url) = self.0.url() {
            if let Ok(url) = SensitiveUrl::new(url.clone()) {
                write!(f, "url: {}", url)?;
            } else {
                write!(f, "url: unable_to_parse")?;
            };
        }

        let kind = if self.0.is_builder() {
            "builder"
        } else if self.0.is_redirect() {
            "redirect"
        } else if self.0.is_status() {
            "status"
        } else if self.0.is_timeout() {
            "timeout"
        } else if self.0.is_request() {
            "request"
        } else if self.0.is_connect() {
            "connect"
        } else if self.0.is_body() {
            "body"
        } else if self.0.is_decode() {
            "decode"
        } else {
            "unknown"
        };
        write!(f, ", kind: {}", kind)?;

        if let Some(status) = self.0.status() {
            write!(f, ", status_code: {}", status)?;
        }

        if let Some(ref source) = self.0.source() {
            write!(f, ", detail: {}", source)?;
        } else {
            write!(f, ", source: unknown")?;
        }

        Ok(())
    }
}

impl From<reqwest::Error> for PrettyReqwestError {
    fn from(inner: reqwest::Error) -> Self {
        Self(inner)
    }
}
