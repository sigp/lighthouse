use crate::TaskExecutor;
use slog::Logger;
use sloggers::{null::NullLoggerBuilder, Build};
use std::sync::Arc;

pub struct TestRuntime {
    pub runtime: Option<Arc<tokio::runtime::Runtime>>,
    pub _runtime_shutdown: exit_future::Signal,
    pub task_executor: TaskExecutor,
    pub log: Logger,
}

impl Default for TestRuntime {
    fn default() -> Self {
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap(),
        );
        let (runtime_shutdown, exit) = exit_future::signal();
        let (shutdown_tx, _) = futures::channel::mpsc::channel(1);
        let log = null_logger().unwrap();
        let task_executor =
            TaskExecutor::new(Arc::downgrade(&runtime), exit, log.clone(), shutdown_tx);

        Self {
            runtime: Some(runtime),
            _runtime_shutdown: runtime_shutdown,
            task_executor,
            log,
        }
    }
}

impl Drop for TestRuntime {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            Arc::try_unwrap(runtime).unwrap().shutdown_background()
        }
    }
}

pub fn null_logger() -> Result<Logger, String> {
    let log_builder = NullLoggerBuilder;
    log_builder
        .build()
        .map_err(|e| format!("Failed to start null logger: {:?}", e))
}
