use std::collections::HashMap;
use std::str::FromStr;

use crate::network::NetIoCounters;
use crate::{read_file, Error, Result};

const PROC_NET_DEV: &str = "/proc/net/dev";

impl FromStr for NetIoCounters {
	type Err = Error;

	fn from_str(line: &str) -> Result<Self> {
		let fields = match line.split_whitespace().collect::<Vec<_>>() {
			fields if fields.len() >= 17 => Ok(fields),
			_ => Err(Error::MissingData {
				path: PROC_NET_DEV.into(),
				contents: line.to_string(),
			}),
		}?;

		let parse = |s: &str| -> Result<u64> {
			s.parse().map_err(|err| Error::ParseInt {
				path: PROC_NET_DEV.into(),
				contents: line.to_string(),
				source: err,
			})
		};

		Ok(NetIoCounters {
			bytes_sent: parse(fields[9])?,
			bytes_recv: parse(fields[1])?,
			packets_sent: parse(fields[10])?,
			packets_recv: parse(fields[2])?,
			err_in: parse(fields[3])?,
			err_out: parse(fields[11])?,
			drop_in: parse(fields[4])?,
			drop_out: parse(fields[12])?,
		})
	}
}

pub(crate) fn net_io_counters_pernic() -> Result<HashMap<String, NetIoCounters>> {
	read_file(PROC_NET_DEV)?
		.lines()
		.skip(2)
		.map(|line| {
			let fields: Vec<&str> = line.split_whitespace().collect();

			if fields.len() < 17 {
				return Err(Error::MissingData {
					path: PROC_NET_DEV.into(),
					contents: line.to_string(),
				});
			}

			let mut net_name = String::from(fields[0]);
			// remove the trailing colon
			net_name.pop();

			Ok((net_name, NetIoCounters::from_str(&line)?))
		})
		.collect()
}
