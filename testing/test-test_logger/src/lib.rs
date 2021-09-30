use slog::{info, Logger};

pub struct Config {
    log: Logger,
}

pub fn fn_with_logging(config: &Config) {
    info!(&config.log, "hi");
}

#[cfg(test)]
mod tests {
    use super::*;
    use logging::test_logger;

    #[test]
    fn test_fn_with_logging() {
        let config = Config { log: test_logger() };

        fn_with_logging(&config);
    }
}
