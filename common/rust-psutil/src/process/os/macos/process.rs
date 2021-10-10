use std::collections::HashMap;

use crate::process::{Process, ProcessResult};

pub trait ProcessExt {
	fn environ(&self) -> ProcessResult<HashMap<String, String>>;
}

impl ProcessExt for Process {
	fn environ(&self) -> ProcessResult<HashMap<String, String>> {
		todo!()
	}
}
