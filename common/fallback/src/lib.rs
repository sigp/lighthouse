use futures::future::select_all;
use futures::FutureExt;
use itertools::{join, zip};
use std::fmt::{Debug, Display};
use std::future::Future;
use std::slice::Iter;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock, RwLockWriteGuard};
use tokio::time::sleep;

#[derive(Clone)]
pub struct Fallback<T> {
    servers: Vec<T>,
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
        let mut errors = Vec::with_capacity(self.servers.len());
        for server in &self.servers {
            match func(server).await {
                Ok(val) => return Ok(val),
                Err(e) => errors.push(e),
            }
        }
        Err(FallbackError::AllErrored(errors))
    }

    pub async fn first_success_concurrent<'a, F, O, E, R>(
        &'a self,
        func: F,
    ) -> Result<O, FallbackError<(usize, E)>>
    where
        F: Fn(&'a T) -> R,
        R: Future<Output = Result<O, E>>,
    {
        let mut errors = Vec::with_capacity(self.servers.len());
        let mut open_futures: Vec<_> = self
            .servers
            .iter()
            .map(|s| Box::pin(func(s).fuse()))
            .collect();
        while !open_futures.is_empty() {
            let (output, index, rest) = select_all(open_futures.into_iter()).await;
            match output {
                Ok(result) => return Ok(result),
                Err(e) => {
                    errors.push((index, e));
                }
            }
            open_futures = rest;
        }
        Err(FallbackError::AllErrored(errors))
    }

    pub async fn first_success_concurrent_retry<'a, F, G, O, R, E>(
        &'a self,
        func: F,
        should_retry: G,
        retry_delay: Duration,
    ) -> Result<O, FallbackError<(usize, E)>>
    where
        F: Fn(&'a T) -> R,
        R: Future<Output = Result<O, E>>,
        G: Fn(&Result<O, E>) -> bool,
    {
        let func = &func;
        let should_retry = &should_retry;
        self.first_success_concurrent(|server| async move {
            loop {
                let result = func(server).await;
                if !should_retry(&result) {
                    return result;
                } else {
                    sleep(retry_delay).await;
                }
            }
        })
        .await
    }

    pub fn map_format_error<'a, E, F, S>(&'a self, f: F, error: &FallbackError<E>) -> String
    where
        F: FnMut(&'a T) -> &'a S,
        S: Display + 'a,
        E: Debug,
    {
        match error {
            FallbackError::AllErrored(v) => format!(
                "All fallbacks errored: {}",
                join(
                    zip(self.servers.iter().map(f), v.iter())
                        .map(|(server, error)| format!("{} => {:?}", server, error)),
                    ", "
                )
            ),
        }
    }

    pub fn iter_servers(&self) -> Iter<'_, T> {
        self.servers.iter()
    }
}

type InnerState<E> = Option<Result<(), E>>;
pub type ServerState<E> = Arc<RwLock<InnerState<E>>>;

pub async fn check_preconditions<'a, E, F, R>(s: &'a ServerState<E>, f: F) -> Result<(), E>
where
    E: Clone,
    F: Fn(RwLockWriteGuard<'a, InnerState<E>>) -> R,
    R: Future<Output = Result<(), E>>,
{
    if let Some(result) = &*s.read().await {
        return result.clone();
    }
    let value = s.write().await;
    if let Some(result) = &*value {
        result.clone()
    } else {
        f(value).await
    }
}
