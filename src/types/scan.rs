use clap::error::ErrorKind;

#[derive (Clone, Copy, Debug, PartialEq, Ord, PartialOrd, Eq)]
pub enum Scan { SYN, NULL, ACK, FIN, XMAS, UDP, NONE }

impl From<Scan> for String {
	fn from(scan: Scan) -> Self {
		String::from(match scan {
			Scan::SYN => "SYN",
			Scan::NULL => "NULL",
			Scan::ACK => "ACK",
			Scan::FIN => "FIN",
			Scan::XMAS => "XMAS",
			Scan::UDP => "UDP",
			_ => "INVALID SCAN TYPE"
		})
	}	
}

impl From<String> for Scan {
	fn from(str: String) -> Self {
		match str.as_str() {
			"SYN" => Self::SYN,
			"NULL" => Self::NULL,
			"ACK" => Self::ACK,
			"FIN" => Self::FIN,
			"XMAS" => Self::XMAS,
			"UDP" => Self::UDP,
			_ => Self::NONE
		}
	}
}

impl std::fmt::Display for Scan {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		write!(f, "{}", String::from(*self))
	}
}

#[derive (Clone, Debug)]
pub struct ScanArray(pub Vec<Scan>);

impl ScanArray {
	pub fn inner(&self) -> &Vec<Scan> {
		&self.0
	}

	pub fn inner_as_mut(&mut self) -> &mut Vec<Scan> {
		&mut self.0
	}
}

impl ScanArray {
	pub fn new() -> Self {
		ScanArray(vec![Scan::SYN, Scan::NULL, Scan::ACK, Scan::FIN, Scan::XMAS, Scan::UDP])
	}
}

impl std::fmt::Display for ScanArray {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		self.inner().iter().fold(Ok(()), |result, scan| {
			result.and_then(|_| write!(f, "{}{}", scan, match scan {
				Scan::UDP => "",
				_ => ",",
			}))
		})
	}
}

#[derive (Clone)]
pub struct ScanParser;

impl ScanParser {
	#[allow(non_snake_case)]
	fn InvalidValue(value: &str, cmd: &clap::Command) -> clap::Error {
		clap::Error::raw(ErrorKind::ValueValidation, format!("\"{}\" is not a valid type of scan\n", value)).with_cmd(cmd)
	}
}

impl clap::builder::TypedValueParser for ScanParser {
	type Value = ScanArray;

	fn parse_ref(
		&self,
		cmd: &clap::Command,
		arg: Option<&clap::Arg>,
		raw_value: &std::ffi::OsStr
	) -> Result<Self::Value, clap::Error> {
		let inner = clap::builder::StringValueParser::new();
		let str = inner.parse_ref(cmd, arg, raw_value)?;

		let mut scans: ScanArray = ScanArray(Vec::new());
		for scantype in str.split(',') {
			let s = Scan::from(scantype.trim().to_uppercase());

			if s != Scan::NONE {
				scans.inner_as_mut().push(s);
			} else {
				return Err(Self::InvalidValue(scantype, cmd));
			}
		}

		let inner = scans.inner_as_mut();
		inner.sort();
		inner.dedup();
		Ok(scans)
	}
}

