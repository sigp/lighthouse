use beacon_processor::{BeaconProcessorSend, BlockingOrAsync, Work, WorkEvent};
use serde::Serialize;
use std::future::Future;
use tokio::sync::{mpsc::error::TrySendError, oneshot};
use types::EthSpec;
use warp::reply::{Reply, Response};

/// Maps a request to a queue in the `BeaconProcessor`.
#[derive(Clone, Copy)]
pub enum Priority {
    /// The highest priority.
    P0,
    /// The lowest priority.
    P1,
}

impl Priority {
    /// Wrap `self` in a `WorkEvent` with an appropriate priority.
    fn work_event<E: EthSpec>(&self, process_fn: BlockingOrAsync) -> WorkEvent<E> {
        let work = match self {
            Priority::P0 => Work::ApiRequestP0(process_fn),
            Priority::P1 => Work::ApiRequestP1(process_fn),
        };
        WorkEvent {
            drop_during_sync: false,
            work,
        }
    }
}

/// Spawns tasks on the `BeaconProcessor` or directly on the tokio executor.
pub struct TaskSpawner<E: EthSpec> {
    /// Used to send tasks to the `BeaconProcessor`. The tokio executor will be
    /// used if this is `None`.
    beacon_processor_send: Option<BeaconProcessorSend<E>>,
}

/// Convert a warp `Rejection` into a `Response`.
///
/// This function should *always* be used to convert rejections into responses. This prevents warp
/// from trying to backtrack in strange ways. See: https://github.com/sigp/lighthouse/issues/3404
pub async fn convert_rejection<T: Reply>(res: Result<T, warp::Rejection>) -> Response {
    match res {
        Ok(response) => response.into_response(),
        Err(e) => match warp_utils::reject::handle_rejection(e).await {
            Ok(reply) => reply.into_response(),
            Err(_) => warp::reply::with_status(
                warp::reply::json(&"unhandled error"),
                eth2::StatusCode::INTERNAL_SERVER_ERROR,
            )
            .into_response(),
        },
    }
}

impl<E: EthSpec> TaskSpawner<E> {
    pub fn new(beacon_processor_send: Option<BeaconProcessorSend<E>>) -> Self {
        Self {
            beacon_processor_send,
        }
    }

    /// Executes a "blocking" (non-async) task which returns a `Response`.
    pub async fn blocking_response_task<F, T>(self, priority: Priority, func: F) -> Response
    where
        F: FnOnce() -> Result<T, warp::Rejection> + Send + Sync + 'static,
        T: Reply + Send + 'static,
    {
        if let Some(beacon_processor_send) = &self.beacon_processor_send {
            // Create a closure that will execute `func` and send the result to
            // a channel held by this thread.
            let (tx, rx) = oneshot::channel();
            let process_fn = move || {
                // Execute the function, collect the return value.
                let func_result = func();
                // Send the result down the channel. Ignore any failures; the
                // send can only fail if the receiver is dropped.
                let _ = tx.send(func_result);
            };

            // Send the function to the beacon processor for execution at some arbitrary time.
            let result = send_to_beacon_processor(
                beacon_processor_send,
                priority,
                BlockingOrAsync::Blocking(Box::new(process_fn)),
                rx,
            )
            .await
            .and_then(|x| x);
            convert_rejection(result).await
        } else {
            // There is no beacon processor so spawn a task directly on the
            // tokio executor.
            convert_rejection(warp_utils::task::blocking_response_task(func).await).await
        }
    }

    /// Executes a "blocking" (non-async) task which returns a JSON-serializable
    /// object.
    pub async fn blocking_json_task<F, T>(self, priority: Priority, func: F) -> Response
    where
        F: FnOnce() -> Result<T, warp::Rejection> + Send + Sync + 'static,
        T: Serialize + Send + 'static,
    {
        let func = || func().map(|t| warp::reply::json(&t).into_response());
        self.blocking_response_task(priority, func).await
    }

    /// Executes an async task which may return a `Rejection`, which will be converted to a response.
    pub async fn spawn_async_with_rejection(
        self,
        priority: Priority,
        func: impl Future<Output = Result<Response, warp::Rejection>> + Send + Sync + 'static,
    ) -> Response {
        let result = self
            .spawn_async_with_rejection_no_conversion(priority, func)
            .await;
        convert_rejection(result).await
    }

    /// Same as `spawn_async_with_rejection` but returning a result with the unhandled rejection.
    ///
    /// If you call this function you MUST convert the rejection to a response and not let it
    /// propagate into Warp's filters. See `convert_rejection`.
    pub async fn spawn_async_with_rejection_no_conversion(
        self,
        priority: Priority,
        func: impl Future<Output = Result<Response, warp::Rejection>> + Send + Sync + 'static,
    ) -> Result<Response, warp::Rejection> {
        if let Some(beacon_processor_send) = &self.beacon_processor_send {
            // Create a wrapper future that will execute `func` and send the
            // result to a channel held by this thread.
            let (tx, rx) = oneshot::channel();
            let process_fn = async move {
                // Await the future, collect the return value.
                let func_result = func.await;
                // Send the result down the channel. Ignore any failures; the
                // send can only fail if the receiver is dropped.
                let _ = tx.send(func_result);
            };

            // Send the function to the beacon processor for execution at some arbitrary time.
            send_to_beacon_processor(
                beacon_processor_send,
                priority,
                BlockingOrAsync::Async(Box::pin(process_fn)),
                rx,
            )
            .await
            .and_then(|x| x)
        } else {
            // There is no beacon processor so spawn a task directly on the
            // tokio executor.
            tokio::task::spawn(func)
                .await
                .map_err(|_| {
                    warp_utils::reject::custom_server_error("Tokio failed to spawn task".into())
                })
                .and_then(|x| x)
        }
    }

    /// Executes an async task which always returns a `Response`.
    pub async fn spawn_async(
        self,
        priority: Priority,
        func: impl Future<Output = Response> + Send + Sync + 'static,
    ) -> Response {
        if let Some(beacon_processor_send) = &self.beacon_processor_send {
            // Create a wrapper future that will execute `func` and send the
            // result to a channel held by this thread.
            let (tx, rx) = oneshot::channel();
            let process_fn = async move {
                // Await the future, collect the return value.
                let func_result = func.await;
                // Send the result down the channel. Ignore any failures; the
                // send can only fail if the receiver is dropped.
                let _ = tx.send(func_result);
            };

            // Send the function to the beacon processor for execution at some arbitrary time.
            let result = send_to_beacon_processor(
                beacon_processor_send,
                priority,
                BlockingOrAsync::Async(Box::pin(process_fn)),
                rx,
            )
            .await;
            convert_rejection(result).await
        } else {
            // There is no beacon processor so spawn a task directly on the
            // tokio executor.
            tokio::task::spawn(func).await.unwrap_or_else(|e| {
                warp::reply::with_status(
                    warp::reply::json(&format!("Tokio did not execute task: {e:?}")),
                    eth2::StatusCode::INTERNAL_SERVER_ERROR,
                )
                .into_response()
            })
        }
    }
}

/// Send a task to the beacon processor and await execution.
///
/// If the task is not executed, return an `Err` with an error message
/// for the API consumer.
async fn send_to_beacon_processor<E: EthSpec, T>(
    beacon_processor_send: &BeaconProcessorSend<E>,
    priority: Priority,
    process_fn: BlockingOrAsync,
    rx: oneshot::Receiver<T>,
) -> Result<T, warp::Rejection> {
    let error_message = match beacon_processor_send.try_send(priority.work_event(process_fn)) {
        Ok(()) => {
            match rx.await {
                // The beacon processor executed the task and sent a result.
                Ok(func_result) => return Ok(func_result),
                // The beacon processor dropped the channel without sending a
                // result. The beacon processor dropped this task because its
                // queues are full or it's shutting down.
                Err(_) => "The task did not execute. The server is overloaded or shutting down.",
            }
        }
        Err(TrySendError::Full(_)) => "The task was dropped. The server is overloaded.",
        Err(TrySendError::Closed(_)) => "The task was dropped. The server is shutting down.",
    };

    Err(warp_utils::reject::custom_server_error(
        error_message.to_string(),
    ))
}
