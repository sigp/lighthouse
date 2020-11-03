use futures::channel::mpsc::Sender;
use futures::prelude::*;
use tokio::runtime::Handle;

/// A wrapper over a runtime handle which can spawn async and blocking tasks.
#[derive(Clone)]
pub struct TaskExecutor {
    /// The handle to the runtime on which tasks are spawned
    pub handle: Handle,
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
    pub fn spawn_without_exit(
        &self,
        task: impl Future<Output = ()> + Send + 'static,
        _name: &'static str,
    ) {
        let future = task.then(move |_| futures::future::ready(()));
        self.handle.spawn(future);
    }

    /// Returns a reference to the logger.
    pub fn log(&self) -> &slog::Logger {
        &self.log
    }

    /// Returns a copy of the `exit_future::Exit`.
    pub fn exit(&self) -> exit_future::Exit {
        self.exit.clone()
    }
}
