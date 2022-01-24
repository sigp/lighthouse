use crate::config::Config;
use std::path::Path;
use std::process::{Child, Command, ExitStatus};

#[derive(Debug)]
pub struct SimProcess {
    cmd: Option<Command>,
    process: Option<Child>,
}

impl Drop for SimProcess {
    fn drop(&mut self) {
        if let Some(child) = self.process.as_mut() {
            child.kill().expect("unable to kill process");
        };
    }
}

impl SimProcess {
    pub fn new(base_cmd_name: &str, config: Config) -> SimProcess {
        let mut cmd = Command::new(base_cmd_name);
        for (k, v) in config.iter() {
            cmd.arg(format!("--{}", k));
            cmd.arg(v);
        }
        SimProcess {
            cmd: Some(cmd),
            process: None,
        }
    }

    pub fn new_lighthouse_process(
        lighthouse_bin: &Path,
        base_cmd_name: &str,
        config: &Config,
    ) -> SimProcess {
        let mut cmd = Command::new(lighthouse_bin);
        cmd.arg(base_cmd_name);
        for (k, v) in config.iter() {
            if v == "true" {
                cmd.arg(format!("--{}", k));
            } else {
                cmd.arg(format!("--{}", k));
                cmd.arg(v);
            }
        }
        SimProcess {
            cmd: Some(cmd),
            process: None,
        }
    }

    pub fn spawn_no_wait(mut self) -> Self {
        self.process = Some(
            self.cmd
                .take()
                .expect("command cannot be called twice")
                .spawn()
                .expect("should start process"),
        );
        self
    }

    pub fn spawn_and_wait(&mut self) -> ExitStatus {
        self.cmd
            .take()
            .expect("command cannot be called twice")
            .spawn()
            .expect("should start process")
            .wait()
            .expect("spawned process should be running")
    }

    pub fn wait(&mut self) -> ExitStatus {
        self.process
            .as_mut()
            .expect("simulator process should be running")
            .wait()
            .expect("child process should be running")
    }

    pub fn kill_process(&mut self) {
        self.process
            .as_mut()
            .expect("simulator process should be running")
            .kill()
            .expect("child process should be running")
    }
}
