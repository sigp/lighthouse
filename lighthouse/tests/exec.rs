use serde::de::DeserializeOwned;
use serde_json::from_reader;
use std::fs::File;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::str::from_utf8;
use tempfile::TempDir;

pub trait CommandLineTestExec {
    type Config: DeserializeOwned;

    fn cmd_mut(&mut self) -> &mut Command;

    /// Adds a flag with optional value to the command.
    fn flag(&mut self, flag: &str, value: Option<&str>) -> &mut Self {
        self.cmd_mut().arg(format!("--{}", flag));
        if let Some(value) = value {
            self.cmd_mut().arg(value);
        }
        self
    }

    /// Executes the `Command` returned by `Self::cmd_mut` with temporary data directory, dumps
    /// the configuration and shuts down immediately.
    ///
    /// Options `--datadir`, `--dump-config` and `--immediate-shutdown` must not be set on the
    /// command.
    fn run(&mut self) -> CompletedTest<Self::Config> {
        // Setup temp directory.
        let tmp_dir = TempDir::new().expect("Unable to create temporary directory");
        let tmp_config_path: PathBuf = tmp_dir.path().join("config.json");

        // Add args --datadir <tmp_dir> --dump-config <tmp_config_path> --immediate-shutdown
        let cmd = self.cmd_mut();
        cmd.arg("--datadir")
            .arg(tmp_dir.path().as_os_str())
            .arg(format!("--{}", "--dump-config"))
            .arg(tmp_config_path.as_os_str())
            .arg("--immediate-shutdown");

        // Run the command.
        let output = output_result(cmd);
        if let Err(e) = output {
            panic!("{:?}", e);
        }

        // Grab the config.
        let config_file = File::open(tmp_config_path).expect("Unable to open dumped config");
        let config: Self::Config = from_reader(config_file).expect("Unable to deserialize config");

        CompletedTest::new(config, tmp_dir)
    }

    /// Executes the `Command` returned by `Self::cmd_mut` dumps the configuration and
    /// shuts down immediately.
    ///
    /// Options `--dump-config` and `--immediate-shutdown` must not be set on the command.
    fn run_with_no_datadir(&mut self) -> CompletedTest<Self::Config> {
        // Setup temp directory.
        let tmp_dir = TempDir::new().expect("Unable to create temporary directory");
        let tmp_config_path: PathBuf = tmp_dir.path().join("config.json");

        // Add args --datadir <tmp_dir> --dump-config <tmp_config_path> --immediate-shutdown
        let cmd = self.cmd_mut();
        cmd.arg(format!("--{}", "--dump-config"))
            .arg(tmp_config_path.as_os_str())
            .arg("--immediate-shutdown");

        // Run the command.
        let output = output_result(cmd);
        if let Err(e) = output {
            panic!("{:?}", e);
        }

        // Grab the config.
        let config_file = File::open(tmp_config_path).expect("Unable to open dumped config");
        let config: Self::Config = from_reader(config_file).expect("Unable to deserialize config");

        CompletedTest::new(config, tmp_dir)
    }
}

/// Executes a `Command`, returning a `Result` based upon the success exit code of the command.
fn output_result(cmd: &mut Command) -> Result<Output, String> {
    let output = cmd.output().expect("should run command");

    if output.status.success() {
        Ok(output)
    } else {
        Err(from_utf8(&output.stderr)
            .expect("stderr is not utf8")
            .to_string())
    }
}

pub struct CompletedTest<C> {
    config: C,
    dir: TempDir,
}

impl<C> CompletedTest<C> {
    fn new(config: C, dir: TempDir) -> Self {
        CompletedTest { config, dir }
    }

    pub fn with_config<F: Fn(&C)>(self, func: F) {
        func(&self.config);
    }

    pub fn with_config_and_dir<F: Fn(&C, &TempDir)>(self, func: F) {
        func(&self.config, &self.dir);
    }
}
