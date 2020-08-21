use crate::metrics;
use futures::channel::mpsc::Sender;
use futures::prelude::*;
use slog::{debug, trace};
use tokio::runtime::Handle;

/// A wrapper over a runtime handle which can spawn async and blocking tasks.
#[derive(Clone)]
pub struct TaskExecutor {
    /// The handle to the runtime on which tasks are spawned
    pub(crate) handle: Handle,
    /// The receiver exit future which on receiving shuts down the task
    pub(crate) exit: exit_future::Exit,
    /// Sender given to tasks, so that if they encounter a state in which execution cannot
    /// continue they can request that everything shuts down.
    ///
    /// The task must provide a reason for shutting down.
    pub(crate) signal_tx: Sender<&'static str>,

    pub(crate) log: slog::Logger,
}

impl TaskExecutor {
    /// Create a new task executor.
    ///
    /// Note: this function is mainly useful in tests. A `TaskExecutor` should be normally obtained from
    /// a [`RuntimeContext`](struct.RuntimeContext.html)
    pub fn new(
        handle: Handle,
        exit: exit_future::Exit,
        log: slog::Logger,
        signal_tx: Sender<&'static str>,
    ) -> Self {
        Self {
            handle,
            exit,
            signal_tx,
            log,
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
            self.handle.spawn(future);
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
            self.handle.spawn(future);
        }
    }

    /// Spawn a blocking task on a dedicated tokio thread pool wrapped in an exit future.
    /// This function generates prometheus metrics on number of tasks and task duration.
    pub fn spawn_blocking<F>(&self, task: F, name: &'static str)
    where
        F: FnOnce() + Send + 'static,
    {
        let exit = self.exit.clone();
        let log = self.log.clone();

        if let Some(metric) = metrics::get_histogram(&metrics::BLOCKING_TASKS_HISTOGRAM, &[name]) {
            if let Some(int_gauge) = metrics::get_int_gauge(&metrics::BLOCKING_TASKS_COUNT, &[name])
            {
                let int_gauge_1 = int_gauge.clone();
                let timer = metric.start_timer();
                let join_handle = self.handle.spawn_blocking(task);

                let future = future::select(join_handle, exit).then(move |either| {
                    match either {
                        future::Either::Left(_) => {
                            trace!(log, "Blocking task completed"; "task" => name)
                        }
                        future::Either::Right(_) => {
                            debug!(log, "Blocking task shutdown, exit received"; "task" => name)
                        }
                    }
                    timer.observe_duration();
                    int_gauge_1.dec();
                    futures::future::ready(())
                });

                int_gauge.inc();
                self.handle.spawn(future);
            }
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

    /// Get a channel to request shutting down.
    pub fn shutdown_sender(&self) -> Sender<&'static str> {
        self.signal_tx.clone()
    }

    /// Returns a reference to the logger.
    pub fn log(&self) -> &slog::Logger {
        &self.log
    }
}

impl discv5::Executor for TaskExecutor {
    fn spawn(&self, future: std::pin::Pin<Box<dyn Future<Output = ()> + Send>>) {
        self.spawn(future, "discv5")
    }
}
