use eth2_config::Eth2Config;
use futures::{sync::oneshot, Future};
use slog::{o, Drain, Level, Logger};
use sloggers::{null::NullLoggerBuilder, Build};
use std::cell::RefCell;
use tokio::runtime::{Runtime, TaskExecutor};
use types::{EthSpec, InteropEthSpec, MainnetEthSpec, MinimalEthSpec};

pub struct EnvironmentBuilder<E: EthSpec> {
    runtime: Option<Runtime>,
    log: Option<Logger>,
    eth_spec_instance: E,
    eth2_config: Eth2Config,
}

impl EnvironmentBuilder<MinimalEthSpec> {
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
    pub fn tokio_runtime(mut self) -> Result<Self, String> {
        self.runtime =
            Some(Runtime::new().map_err(|e| format!("Failed to start runtime: {:?}", e))?);
        Ok(self)
    }

    pub fn null_logger(mut self) -> Result<Self, String> {
        let log_builder = NullLoggerBuilder;
        self.log = Some(
            log_builder
                .build()
                .map_err(|e| format!("Failed to start null logger: {:?}", e))?,
        );
        Ok(self)
    }

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

pub struct Environment<E: EthSpec> {
    runtime: Runtime,
    log: Logger,
    eth_spec_instance: E,
    eth2_config: Eth2Config,
}

impl<E: EthSpec> Environment<E> {
    pub fn executor(&self) -> TaskExecutor {
        self.runtime.executor()
    }

    pub fn runtime(&mut self) -> &mut Runtime {
        &mut self.runtime
    }

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

    pub fn shutdown_on_idle(self) -> Result<(), String> {
        self.runtime
            .shutdown_on_idle()
            .wait()
            .map_err(|e| format!("Tokio runtime shutdown returned an error: {:?}", e))
    }

    pub fn eth_spec_instance(&self) -> &E {
        &self.eth_spec_instance
    }

    pub fn eth2_config(&self) -> &Eth2Config {
        &self.eth2_config
    }

    pub fn core_log(&self) -> Logger {
        self.log.clone()
    }

    pub fn beacon_node_log(&self) -> Logger {
        self.log.new(o!("client" => "beacon"))
    }

    pub fn validator_client_log(&self) -> Logger {
        self.log.new(o!("client" => "validator"))
    }
}
