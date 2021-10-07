use clap::ArgMatches;
use directory::{DEFAULT_ROOT_DIR, DEFAULT_HARDCODED_NETWORK};
use slog::{info, Logger};
use std::path::PathBuf;

/// Database manager context
#[Derive(Debug)]
pub struct Context {
    pub datadir: Option<PathBuf>,
    pub log: &Logger,
}

impl Default for Context {
    /// Build a new context
    fn default() -> Self {
        // WARNING: directory defaults should be always overwritten
        let datadir = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(DEFAULT_ROOT_DIR)
            .join(DEFAULT_HARDCODED_NETWORK);
        Self {
            datadir,
        }
    }
}

impl Context {
    /// Returns a `Default` implementation of `Self` with some parameters modified by the supplied
    /// `cli_args`.
    pub fn from_cli(cli_args: &ArgMatches, log: &Logger) -> Result<Config, String> {
        let mut context = Context::default();

        context.datadir = cli_args.value_of("datadir");
        context.log = log;

        info!("from_cli: context={:?}", context);
        Ok(context)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // Ensures the default context does not panic.
    fn default_context() {
        Context::default();
    }
}
