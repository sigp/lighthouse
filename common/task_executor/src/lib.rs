mod metrics;

use futures::channel::mpsc::Sender;
use futures::prelude::*;
use slog::{debug, o, trace};
use std::sync::Weak;
use tokio::runtime::Runtime;

/// Provides a reason when Lighthouse is shut down.
#[derive(Copy, Clone, Debug)]
pub enum ShutdownReason {
    /// The node shut down successfully.
    Success(&'static str),
    /// The node shut down due to an error condition.
    Failure(&'static str),
}

impl ShutdownReason {
    pub fn message(&self) -> &'static str {
        match self {
            ShutdownReason::Success(msg) => msg,
            ShutdownReason::Failure(msg) => msg,
        }
    }
}

/// A wrapper over a runtime handle which can spawn async and blocking tasks.
#[derive(Clone)]
pub struct TaskExecutor {
    /// The handle to the runtime on which tasks are spawned
    runtime: Weak<Runtime>,
    /// The receiver exit future which on receiving shuts down the task
    exit: exit_future::Exit,
    /// Sender given to tasks, so that if they encounter a state in which execution cannot
    /// continue they can request that everything shuts down.
    ///
    /// The task must provide a reason for shutting down.
    signal_tx: Sender<ShutdownReason>,

    log: slog::Logger,
}

impl TaskExecutor {
    /// Create a new task executor.
    ///
    /// Note: this function is mainly useful in tests. A `TaskExecutor` should be normally obtained from
    /// a [`RuntimeContext`](struct.RuntimeContext.html)
    pub fn new(
        runtime: Weak<Runtime>,
        exit: exit_future::Exit,
        log: slog::Logger,
        signal_tx: Sender<ShutdownReason>,
    ) -> Self {
        Self {
            runtime,
            exit,
            signal_tx,
            log,
        }
    }

    /// Clones the task executor adding a service name.
    pub fn clone_with_name(&self, service_name: String) -> Self {
        TaskExecutor {
            runtime: self.runtime.clone(),
            exit: self.exit.clone(),
            signal_tx: self.signal_tx.clone(),
            log: self.log.new(o!("service" => service_name)),
        }
    }

    /// Spawn a future on the tokio runtime wrapped in an `exit_future::Exit`. The task is canceled
    /// when the corresponding exit_future `Signal` is fired/dropped.
    ///
    /// This function generates prometheus metrics on number of tasks and task duration.
    pub fn spawn(&self, task: impl Future<Output = ()> + Send + 'static, name: &'static str) {
        let exit = self.exit.clone();
        let log = self.log.clone();

        if let Some(int_gauge) = metrics::get_int_gauge(&metrics::ASYNC_TASKS_COUNT, &[name]) {
            // Task is shutdown before it completes if `exit` receives
            let int_gauge_1 = int_gauge.clone();
            let future = future::select(Box::pin(task), exit).then(move |either| {
                match either {
                    future::Either::Left(_) => trace!(log, "Async task completed"; "task" => name),
                    future::Either::Right(_) => {
                        debug!(log, "Async task shutdown, exit received"; "task" => name)
                    }
                }
                int_gauge_1.dec();
                futures::future::ready(())
            });

            int_gauge.inc();
            if let Some(runtime) = self.runtime.upgrade() {
                runtime.spawn(future);
            } else {
                debug!(self.log, "Couldn't spawn task. Runtime shutting down");
            }
        }
    }

    /// Spawn a future on the tokio runtime. This function does not wrap the task in an `exit_future::Exit`
    /// like [spawn](#method.spawn).
    /// The caller of this function is responsible for wrapping up the task with an `exit_future::Exit` to
    /// ensure that the task gets canceled appropriately.
    /// This function generates prometheus metrics on number of tasks and task duration.
    ///
    /// This is useful in cases where the future to be spawned needs to do additional cleanup work when
    /// the task is completed/canceled (e.g. writing local variables to disk) or the task is created from
    /// some framework which does its own cleanup (e.g. a hyper server).
    pub fn spawn_without_exit(
        &self,
        task: impl Future<Output = ()> + Send + 'static,
        name: &'static str,
    ) {
        if let Some(int_gauge) = metrics::get_int_gauge(&metrics::ASYNC_TASKS_COUNT, &[name]) {
            let int_gauge_1 = int_gauge.clone();
            let future = task.then(move |_| {
                int_gauge_1.dec();
                futures::future::ready(())
            });

            int_gauge.inc();
            if let Some(runtime) = self.runtime.upgrade() {
                runtime.spawn(future);
            } else {
                debug!(self.log, "Couldn't spawn task. Runtime shutting down");
            }
        }
    }

    /// Spawn a blocking task on a dedicated tokio thread pool wrapped in an exit future.
    /// This function generates prometheus metrics on number of tasks and task duration.
    pub fn spawn_blocking<F>(&self, task: F, name: &'static str)
    where
        F: FnOnce() + Send + 'static,
    {
        let log = self.log.clone();

        if let Some(metric) = metrics::get_histogram(&metrics::BLOCKING_TASKS_HISTOGRAM, &[name]) {
            if let Some(int_gauge) = metrics::get_int_gauge(&metrics::BLOCKING_TASKS_COUNT, &[name])
            {
                let int_gauge_1 = int_gauge.clone();
                let timer = metric.start_timer();
                let join_handle = if let Some(runtime) = self.runtime.upgrade() {
                    runtime.spawn_blocking(task)
                } else {
                    debug!(self.log, "Couldn't spawn task. Runtime shutting down");
                    return;
                };

                let future = async move {
                    match join_handle.await {
                        Ok(_) => trace!(log, "Blocking task completed"; "task" => name),
                        Err(e) => debug!(log, "Blocking task failed"; "error" => %e),
                    };
                    timer.observe_duration();
                    int_gauge_1.dec();
                };

                int_gauge.inc();
                if let Some(runtime) = self.runtime.upgrade() {
                    runtime.spawn(future);
                } else {
                    debug!(self.log, "Couldn't spawn task. Runtime shutting down");
                }
            }
        }
    }
    /// Spawn a future on the tokio runtime wrapped in an `exit_future::Exit` returning an optional
    /// join handle to the future.
    /// The task is canceled when the corresponding exit_future `Signal` is fired/dropped.
    ///
    /// This function generates prometheus metrics on number of tasks and task duration.
    pub fn spawn_handle<R: Send + 'static>(
        &self,
        task: impl Future<Output = R> + Send + 'static,
        name: &'static str,
    ) -> Option<tokio::task::JoinHandle<Option<R>>> {
        let exit = self.exit.clone();
        let log = self.log.clone();

        if let Some(int_gauge) = metrics::get_int_gauge(&metrics::ASYNC_TASKS_COUNT, &[name]) {
            // Task is shutdown before it completes if `exit` receives
            let int_gauge_1 = int_gauge.clone();
            let future = future::select(Box::pin(task), exit).then(move |either| {
                let result = match either {
                    future::Either::Left((task, _)) => {
                        trace!(log, "Async task completed"; "task" => name);
                        Some(task)
                    }
                    future::Either::Right(_) => {
                        debug!(log, "Async task shutdown, exit received"; "task" => name);
                        None
                    }
                };
                int_gauge_1.dec();
                futures::future::ready(result)
            });

            int_gauge.inc();
            if let Some(runtime) = self.runtime.upgrade() {
                Some(runtime.spawn(future))
            } else {
                debug!(self.log, "Couldn't spawn task. Runtime shutting down");
                None
            }
        } else {
            None
        }
    }

    /// Spawn a blocking task on a dedicated tokio thread pool wrapped in an exit future returning
    /// a join handle to the future.
    /// If the runtime doesn't exist, this will return None.
    /// The Future returned behaves like the standard JoinHandle which can return an error if the
    /// task failed.
    /// This function generates prometheus metrics on number of tasks and task duration.
    pub fn spawn_blocking_handle<F, R>(
        &self,
        task: F,
        name: &'static str,
    ) -> Option<impl Future<Output = Result<R, tokio::task::JoinError>>>
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        let log = self.log.clone();

        if let Some(metric) = metrics::get_histogram(&metrics::BLOCKING_TASKS_HISTOGRAM, &[name]) {
            if let Some(int_gauge) = metrics::get_int_gauge(&metrics::BLOCKING_TASKS_COUNT, &[name])
            {
                let int_gauge_1 = int_gauge;
                let timer = metric.start_timer();
                let join_handle = if let Some(runtime) = self.runtime.upgrade() {
                    runtime.spawn_blocking(task)
                } else {
                    debug!(self.log, "Couldn't spawn task. Runtime shutting down");
                    return None;
                };

                Some(async move {
                    let result = match join_handle.await {
                        Ok(result) => {
                            trace!(log, "Blocking task completed"; "task" => name);
                            Ok(result)
                        }
                        Err(e) => {
                            debug!(log, "Blocking task ended unexpectedly"; "error" => %e);
                            Err(e)
                        }
                    };
                    timer.observe_duration();
                    int_gauge_1.dec();
                    result
                })
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn runtime(&self) -> Weak<Runtime> {
        self.runtime.clone()
    }

    /// Returns a copy of the `exit_future::Exit`.
    pub fn exit(&self) -> exit_future::Exit {
        self.exit.clone()
    }

    /// Get a channel to request shutting down.
    pub fn shutdown_sender(&self) -> Sender<ShutdownReason> {
        self.signal_tx.clone()
    }

    /// Returns a reference to the logger.
    pub fn log(&self) -> &slog::Logger {
        &self.log
    }
}
