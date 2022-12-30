use clap::error::ErrorKind;

#[derive(Clone, Debug)]
pub struct Range {
	pub start: u16,
	pub end: u16
}

impl std::fmt::Display for Range {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		write!(f, "{}-{}", self.start, self.end)
	}
}

#[derive(Clone, Debug)]
pub struct RangeArray(pub Vec<Range>);

impl std::fmt::Display for RangeArray {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		self.0.iter().fold(Ok(()), |result, range| {
			result.and_then(|_| write!(f, "{}", range))
		})
	}	
}

#[derive(Clone)]
pub struct RangeParser;

impl RangeParser {
	fn invalid_value(value: &str, cmd: &clap::Command) -> clap::Error {
		clap::Error::raw(ErrorKind::ValueValidation, format!("\"{}\" is not valid as a port number\n", value)).with_cmd(cmd)
	}
}

impl clap::builder::TypedValueParser for RangeParser {
	type Value = RangeArray;

	fn parse_ref(
		&self,
		cmd: &clap::Command,
		arg: Option<&clap::Arg>,
		raw_value: &std::ffi::OsStr
	) -> Result<Self::Value, clap::Error> {
		let inner = clap::builder::StringValueParser::new();
		let str = inner.parse_ref(cmd, arg, raw_value)?;

		let mut ports: RangeArray = RangeArray(Vec::new());
		for range in str.split(',') {
			let values: Vec<&str> = range.splitn(2, '-').collect();
			let mut r: [u16; 2] = [0, 0];

			for i in 0..values.len() {
				if let Ok(v) = values[i].parse::<u16>() {
					if v != 0 {
						r[i] = v;
						r[1] = v;
					} else {
						return Err(Self::invalid_value(values[i], cmd));
					}
				} else {
					return Err(Self::invalid_value(values[i], cmd));
				}
			}
			ports.0.push(Range { start: r[0], end: r[1] });
		}

		Ok(ports) // placeholder
	}
}

// #[derive(Clone)]
// enum Scan {
	// SYN, NULL, ACK, FIN, XMAS, UDP
// }
