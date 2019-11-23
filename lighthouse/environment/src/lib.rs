//! This crate aims to provide a common set of tools that can be used to create a "environment" to
//! run Lighthouse services like the `beacon_node` or `validator_client`. This allows for the
//! unification of creating tokio runtimes, loggers and eth2 specifications in production and in
//! testing.
//!
//! The idea is that the main thread creates an `Environment`, which is then used to spawn a
//! `Context` which can be handed to any service that wishes to start async tasks or perform
//! logging.

use eth2_config::Eth2Config;
use futures::{sync::oneshot, Future};
use slog::{info, o, Drain, Level, Logger};
use sloggers::{null::NullLoggerBuilder, Build};
use std::cell::RefCell;
use std::fs::OpenOptions;
use std::path::PathBuf;
use std::sync::Mutex;
use tokio::runtime::{Builder as RuntimeBuilder, Runtime, TaskExecutor};
use types::{EthSpec, InteropEthSpec, MainnetEthSpec, MinimalEthSpec};

/// Builds an `Environment`.
pub struct EnvironmentBuilder<E: EthSpec> {
    runtime: Option<Runtime>,
    log: Option<Logger>,
    eth_spec_instance: E,
    eth2_config: Eth2Config,
}

impl EnvironmentBuilder<MinimalEthSpec> {
    /// Creates a new builder using the `minimal` eth2 specification.
    pub fn minimal() -> Self {
        Self {
            runtime: None,
            log: None,
            eth_spec_instance: MinimalEthSpec,
            eth2_config: Eth2Config::minimal(),
        }
    }
}

impl EnvironmentBuilder<MainnetEthSpec> {
    /// Creates a new builder using the `mainnet` eth2 specification.
    pub fn mainnet() -> Self {
        Self {
            runtime: None,
            log: None,
            eth_spec_instance: MainnetEthSpec,
            eth2_config: Eth2Config::mainnet(),
        }
    }
}

impl EnvironmentBuilder<InteropEthSpec> {
    /// Creates a new builder using the `interop` eth2 specification.
    pub fn interop() -> Self {
        Self {
            runtime: None,
            log: None,
            eth_spec_instance: InteropEthSpec,
            eth2_config: Eth2Config::interop(),
        }
    }
}

impl<E: EthSpec> EnvironmentBuilder<E> {
    /// Specifies that a multi-threaded tokio runtime should be used. Ideal for production uses.
    ///
    /// The `Runtime` used is just the standard tokio runtime.
    pub fn multi_threaded_tokio_runtime(mut self) -> Result<Self, String> {
        self.runtime =
            Some(Runtime::new().map_err(|e| format!("Failed to start runtime: {:?}", e))?);
        Ok(self)
    }

    /// Specifies that a single-threaded tokio runtime should be used. Ideal for testing purposes
    /// where tests are already multi-threaded.
    ///
    /// This can solve problems if "too many open files" errors are thrown during tests.
    pub fn single_thread_tokio_runtime(mut self) -> Result<Self, String> {
        self.runtime = Some(
            RuntimeBuilder::new()
                .core_threads(1)
                .build()
                .map_err(|e| format!("Failed to start runtime: {:?}", e))?,
        );
        Ok(self)
    }

    /// Specifies that all logs should be sent to `null` (i.e., ignored).
    pub fn null_logger(mut self) -> Result<Self, String> {
        self.log = Some(null_logger()?);
        Ok(self)
    }

    /// Specifies that the `slog` asynchronous logger should be used. Ideal for production.
    ///
    /// The logger is "async" because it has a dedicated thread that accepts logs and then
    /// asynchronously flushes them to stdout/files/etc. This means the thread that raised the log
    /// does not have to wait for the logs to be flushed.
    pub fn async_logger(mut self, debug_level: &str) -> Result<Self, String> {
        // Build the initial logger.
        let decorator = slog_term::TermDecorator::new().build();
        let decorator = logging::AlignedTermDecorator::new(decorator, logging::MAX_MESSAGE_WIDTH);
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        let drain = slog_async::Async::new(drain).build();

        let drain = match debug_level {
            "info" => drain.filter_level(Level::Info),
            "debug" => drain.filter_level(Level::Debug),
            "trace" => drain.filter_level(Level::Trace),
            "warn" => drain.filter_level(Level::Warning),
            "error" => drain.filter_level(Level::Error),
            "crit" => drain.filter_level(Level::Critical),
            unknown => return Err(format!("Unknown debug-level: {}", unknown)),
        };

        self.log = Some(Logger::root(drain.fuse(), o!()));
        Ok(self)
    }

    /// Consumes the builder, returning an `Environment`.
    pub fn build(self) -> Result<Environment<E>, String> {
        Ok(Environment {
            runtime: self
                .runtime
                .ok_or_else(|| "Cannot build environment without runtime".to_string())?,
            log: self
                .log
                .ok_or_else(|| "Cannot build environment without log".to_string())?,
            eth_spec_instance: self.eth_spec_instance,
            eth2_config: self.eth2_config,
        })
    }
}

/// An execution context that can be used by a service.
///
/// Distinct from an `Environment` because a `Context` is not able to give a mutable reference to a
/// `Runtime`, instead it only has access to a `TaskExecutor`.
#[derive(Clone)]
pub struct RuntimeContext<E: EthSpec> {
    pub executor: TaskExecutor,
    pub log: Logger,
    pub eth_spec_instance: E,
    pub eth2_config: Eth2Config,
}

impl<E: EthSpec> RuntimeContext<E> {
    /// Returns a sub-context of this context.
    ///
    /// The generated service will have the `service_name` in all it's logs.
    pub fn service_context(&self, service_name: &'static str) -> Self {
        Self {
            executor: self.executor.clone(),
            log: self.log.new(o!("service" => service_name)),
            eth_spec_instance: self.eth_spec_instance.clone(),
            eth2_config: self.eth2_config.clone(),
        }
    }

    /// Returns the `eth2_config` for this service.
    pub fn eth2_config(&self) -> &Eth2Config {
        &self.eth2_config
    }
}

/// An environment where Lighthouse services can run. Used to start a production beacon node or
/// validator client, or to run tests that involve logging and async task execution.
pub struct Environment<E: EthSpec> {
    runtime: Runtime,
    log: Logger,
    eth_spec_instance: E,
    eth2_config: Eth2Config,
}

impl<E: EthSpec> Environment<E> {
    /// Returns a mutable reference to the `tokio` runtime.
    ///
    /// Useful in the rare scenarios where it's necessary to block the current thread until a task
    /// is finished (e.g., during testing).
    pub fn runtime(&mut self) -> &mut Runtime {
        &mut self.runtime
    }

    /// Returns a `Context` where no "service" has been added to the logger output.
    pub fn core_context(&mut self) -> RuntimeContext<E> {
        RuntimeContext {
            executor: self.runtime.executor(),
            log: self.log.clone(),
            eth_spec_instance: self.eth_spec_instance.clone(),
            eth2_config: self.eth2_config.clone(),
        }
    }

    /// Returns a `Context` where the `service_name` is added to the logger output.
    pub fn service_context(&mut self, service_name: &'static str) -> RuntimeContext<E> {
        RuntimeContext {
            executor: self.runtime.executor(),
            log: self.log.new(o!("service" => service_name)),
            eth_spec_instance: self.eth_spec_instance.clone(),
            eth2_config: self.eth2_config.clone(),
        }
    }

    /// Block the current thread until Ctrl+C is received.
    pub fn block_until_ctrl_c(&mut self) -> Result<(), String> {
        let (ctrlc_send, ctrlc_oneshot) = oneshot::channel();
        let ctrlc_send_c = RefCell::new(Some(ctrlc_send));
        ctrlc::set_handler(move || {
            if let Some(ctrlc_send) = ctrlc_send_c.try_borrow_mut().unwrap().take() {
                ctrlc_send.send(()).expect("Error sending ctrl-c message");
            }
        })
        .map_err(|e| format!("Could not set ctrlc handler: {:?}", e))?;

        // Block this thread until Crtl+C is pressed.
        self.runtime()
            .block_on(ctrlc_oneshot)
            .map_err(|e| format!("Ctrlc oneshot failed: {:?}", e))
    }

    /// Shutdown the `tokio` runtime when all tasks are idle.
    pub fn shutdown_on_idle(self) -> Result<(), String> {
        self.runtime
            .shutdown_on_idle()
            .wait()
            .map_err(|e| format!("Tokio runtime shutdown returned an error: {:?}", e))
    }

    /// Sets the logger (and all child loggers) to log to a file.
    pub fn log_to_json_file(&mut self, path: PathBuf) -> Result<(), String> {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&path)
            .map_err(|e| format!("Unable to open logfile: {:?}", e))?;

        let drain = Mutex::new(slog_json::Json::default(file)).fuse();
        let drain = slog_async::Async::new(drain).build().fuse();
        self.log = slog::Logger::root(drain, o!());

        info!(
            self.log,
            "Logging to JSON file";
            "path" => format!("{:?}", path)
        );

        Ok(())
    }

    pub fn eth_spec_instance(&self) -> &E {
        &self.eth_spec_instance
    }

    pub fn eth2_config(&self) -> &Eth2Config {
        &self.eth2_config
    }
}

pub fn null_logger() -> Result<Logger, String> {
    let log_builder = NullLoggerBuilder;
    log_builder
        .build()
        .map_err(|e| format!("Failed to start null logger: {:?}", e))
}
