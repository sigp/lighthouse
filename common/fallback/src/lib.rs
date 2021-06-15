use itertools::{join, zip};
use std::fmt::{Debug, Display};
use std::future::Future;

#[derive(Clone)]
pub struct Fallback<T> {
    pub servers: Vec<T>,
}

#[derive(Debug, PartialEq)]
pub enum FallbackError<E> {
    AllErrored(Vec<E>),
}

impl<T> Fallback<T> {
    pub fn new(servers: Vec<T>) -> Self {
        Self { servers }
    }

    /// Return the first successful result or all errors encountered.
    pub async fn first_success<'a, F, O, E, R>(&'a self, func: F) -> Result<O, FallbackError<E>>
    where
        F: Fn(&'a T) -> R,
        R: Future<Output = Result<O, E>>,
    {
        let mut errors = vec![];
        for server in &self.servers {
            match func(server).await {
                Ok(val) => return Ok(val),
                Err(e) => errors.push(e),
            }
        }
        Err(FallbackError::AllErrored(errors))
    }

    pub fn map_format_error<'a, E, F, S>(&'a self, f: F, error: &FallbackError<E>) -> String
    where
        F: FnMut(&'a T) -> &'a S,
        S: Display + 'a,
        E: Debug,
    {
        match error {
            FallbackError::AllErrored(v) => format!(
                "All fallback errored: {}",
                join(
                    zip(self.servers.iter().map(f), v.iter())
                        .map(|(server, error)| format!("{} => {:?}", server, error)),
                    ", "
                )
            ),
        }
    }
}

impl<T: Display> Fallback<T> {
    pub fn format_error<E: Debug>(&self, error: &FallbackError<E>) -> String {
        self.map_format_error(|s| s, error)
    }
}
