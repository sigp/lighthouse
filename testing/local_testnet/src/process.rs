use crate::config::Config;
use std::path::Path;
use std::process::{Child, Command, ExitStatus};

#[derive(thiserror::Error, Debug)]
pub enum ProcessError {
    #[error("command cannot be called twice")]
    DuplicateCall,
    #[error("process should be running")]
    ProcessNotRunning,
    #[error("process failed to start process")]
    IO(#[from] std::io::Error),
}

#[derive(Debug)]
pub struct TestnetProcess {
    cmd: Option<Command>,
    process: Option<Child>,
}

impl Drop for TestnetProcess {
    fn drop(&mut self) {
        if let Some(child) = self.process.as_mut() {
            // Can't panic here or the process won't get killed, so just ignore the error.
            let _ = child.kill();
        };
    }
}

impl TestnetProcess {
    pub fn new(base_cmd_name: &str, config: Config) -> TestnetProcess {
        let mut cmd = Command::new(base_cmd_name);
        for (k, v) in config.iter() {
            cmd.arg(format!("--{}", k));
            cmd.arg(v);
        }
        TestnetProcess {
            cmd: Some(cmd),
            process: None,
        }
    }

    pub fn new_lighthouse_process(
        lighthouse_bin: &Path,
        base_cmd_name: &str,
        config: &Config,
    ) -> TestnetProcess {
        let mut cmd = Command::new(lighthouse_bin);
        cmd.arg(base_cmd_name);
        dbg!(&base_cmd_name);
        dbg!(&config);
        for (k, v) in config.iter() {
            if v == "true" {
                cmd.arg(format!("--{}", k));
            } else {
                cmd.arg(format!("--{}", k));
                cmd.arg(v);
            }
        }
        TestnetProcess {
            cmd: Some(cmd),
            process: None,
        }
    }

    pub fn spawn_no_wait(mut self) -> Result<Self, ProcessError> {
        self.process = Some(
            self.cmd
                .take()
                .ok_or(ProcessError::DuplicateCall)?
                .spawn()?,
        );
        Ok(self)
    }

    pub fn spawn_and_wait(&mut self) -> Result<ExitStatus, ProcessError> {
        Ok(self
            .cmd
            .take()
            .ok_or(ProcessError::DuplicateCall)?
            .spawn()?
            .wait()?)
    }

    pub fn wait(&mut self) -> Result<ExitStatus, ProcessError> {
        Ok(self
            .process
            .as_mut()
            .ok_or(ProcessError::ProcessNotRunning)?
            .wait()?)
    }

    pub fn kill_process(&mut self) -> Result<(), ProcessError> {
        Ok(self
            .process
            .as_mut()
            .ok_or(ProcessError::ProcessNotRunning)?
            .kill()?)
    }
}
