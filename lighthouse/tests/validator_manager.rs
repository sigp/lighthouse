use serde::de::DeserializeOwned;
use std::fs;
use std::marker::PhantomData;
use std::path::PathBuf;
use std::process::Command;
use tempfile::{tempdir, TempDir};
use validator_manager::validators::create_validators::CreateConfig;

struct CommandLineTest<T> {
    cmd: Command,
    dir: TempDir,
    config_path: PathBuf,
    _phantom: PhantomData<T>,
}

impl<T> Default for CommandLineTest<T> {
    fn default() -> Self {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("config.json");
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_lighthouse"));
        cmd.arg("--dump_config")
            .arg(format!("{:?}", config_path))
            .arg("validator-manager");
        Self {
            cmd,
            dir,
            config_path,
            _phantom: PhantomData,
        }
    }
}

impl<T> CommandLineTest<T> {
    fn flag(mut self, flag: &str, value: Option<&str>) -> Self {
        self.cmd.arg(flag);
        if let Some(value) = value {
            self.cmd.arg(value);
        }
        self
    }
}

impl<T: DeserializeOwned> CommandLineTest<T> {
    fn assert_success<F: Fn(T)>(mut self, func: F) {
        let output = self.cmd.output().expect("should run command");
        assert!(output.status.success(), "command should succeed");

        let contents = fs::read_to_string(self.config_path).unwrap();
        let config: T = serde_json::from_str(&contents).unwrap();
        func(config)
    }
}

impl CommandLineTest<CreateConfig> {
    fn validator_create() -> Self {
        Self::default().flag("validator", None).flag("create", None)
    }
}

#[test]
pub fn validator_create_defaults() {
    todo!()
}
