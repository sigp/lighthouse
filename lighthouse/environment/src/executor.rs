use crate::metrics;
use futures::prelude::*;
use slog::info;
use tokio::runtime::Handle;

/// A wrapper over a runtime handle which can spawn async and blocking tasks.
/// Spawned futures are wrapped in an exit_future which cancels the task
/// when the corresponding exit_future `Signal` is fired/dropped.
#[derive(Clone)]
pub struct TaskExecutor {
    /// The handle to the runtime on which tasks are spawned
    pub(crate) handle: Handle,
    /// The receiver exit future which on receiving shuts down the task
    pub(crate) exit: exit_future::Exit,
    pub(crate) log: slog::Logger,
}

impl TaskExecutor {
    /// Create a new task executor.
    ///
    /// Note: this is mainly useful in testing.
    pub fn new(handle: Handle, exit: exit_future::Exit, log: slog::Logger) -> Self {
        Self { handle, exit, log }
    }
    /// Spawn a future on the tokio runtime wrapped in an exit_future `Exit`. The task is canceled
    /// when the corresponding exit_future `Signal` is fired/dropped.
    ///
    /// This function also generates some metrics on number of tasks and task duration.
    pub fn spawn(&self, task: impl Future<Output = ()> + Send + 'static, name: &'static str) {
        let exit = self.exit.clone();
        let log = self.log.clone();

        // Start the timer for how long this task runs
        if let Some(metric) = metrics::get_histogram(&metrics::ASYNC_TASKS_HISTOGRAM, &[name]) {
            let timer = metric.start_timer();
            let future = async move {
                // Task is shutdown before it completes if `exit` receives
                if let future::Either::Right(_) = future::select(Box::pin(task), exit).await {
                    info!(log, "Async task shutdown"; "task" => name);
                }
                timer.observe_duration();
            };

            metrics::inc_counter(&metrics::ASYNC_TASKS_COUNT);
            self.handle.spawn(future);
        }
    }
    /// TODO: make docs better
    /// Spawn a blocking task on a dedicated tokio thread pool wrapped in an exit future.
    /// This function also generates some metrics on number of tasks and task duration.
    pub fn spawn_blocking<F>(&self, task: F, name: &'static str)
    where
        F: FnOnce() -> () + Send + 'static,
    {
        let exit = self.exit.clone();
        let log = self.log.clone();

        // Start the timer for how long this task runs
        if let Some(metric) = metrics::get_histogram(&metrics::BLOCKING_TASKS_HISTOGRAM, &[name]) {
            let timer = metric.start_timer();
            let join_handle = self.handle.spawn_blocking(task);

            let future = async move {
                // Task is shutdown before it completes if `exit` receives
                if let future::Either::Right(_) = future::select(Box::pin(join_handle), exit).await
                {
                    info!(log, "Blocking task shutdown"; "task" => name);
                }
                timer.observe_duration();
            };

            metrics::inc_counter(&metrics::BLOCKING_TASKS_COUNT);
            self.handle.spawn(future);
        }
    }

    /// Returns the underlying runtime handle.
    pub fn runtime_handle(&self) -> Handle {
        self.handle.clone()
    }

    /// Returns a copy of the `exit_future::Exit`.
    pub fn exit(&self) -> exit_future::Exit {
        self.exit.clone()
    }
}
