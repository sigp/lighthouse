use std::collections::HashMap;

use crate::{Error, Result};

// TODO: should we only parse the ints that we need?
pub(crate) fn make_map<'a>(content: &'a str, path: &str) -> Result<HashMap<&'a str, u64>> {
	content
		.lines()
		.map(|line| {
			let fields = match line.split_whitespace().collect::<Vec<_>>() {
				fields if fields.len() >= 2 => Ok(fields),
				_ => Err(Error::MissingData {
					path: path.into(),
					contents: line.to_string(),
				}),
			}?;

			let mut parsed = fields[1].parse().map_err(|err| Error::ParseInt {
				path: path.into(),
				contents: line.to_string(),
				source: err,
			})?;
			// only needed for `/proc/meminfo`
			if fields.len() >= 3 && fields[2] == "kB" {
				parsed *= 1024;
			}

			// only needed for `/proc/meminfo`
			let name = fields[0].trim_end_matches(':');

			Ok((name, parsed))
		})
		.collect()
}
