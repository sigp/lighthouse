use crate::database::Error as DbError;
use warp::{http::Error as HttpError, Error as WarpError};

#[derive(Debug)]
pub enum Error {
    Warp(WarpError),
    Database(DbError),
    Http(HttpError),
    Other(String),
}

impl warp::reject::Reject for Error {}

impl From<WarpError> for Error {
    fn from(e: WarpError) -> Self {
        Error::Warp(e)
    }
}

impl From<DbError> for Error {
    fn from(e: DbError) -> Self {
        Error::Database(e)
    }
}

impl From<HttpError> for Error {
    fn from(e: HttpError) -> Self {
        Error::Http(e)
    }
}

impl From<String> for Error {
    fn from(e: String) -> Self {
        Error::Other(e)
    }
}
