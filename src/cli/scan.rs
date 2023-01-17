use clap::error::ErrorKind;
use super::arg::ArgIterator;

#[derive (Clone, Copy, Debug, PartialEq, Ord, PartialOrd, Eq)]
pub enum Scan { SYN, NULL, ACK, FIN, XMAS, UDP }

impl From<Scan> for String {
	fn from(scan: Scan) -> Self {
		String::from(match scan {
			Scan::SYN => "SYN",
			Scan::NULL => "NULL",
			Scan::ACK => "ACK",
			Scan::FIN => "FIN",
			Scan::XMAS => "XMAS",
			Scan::UDP => "UDP"
		})
	}	
}

impl TryFrom<String> for Scan {
	type Error = ();

	fn try_from(str: String) -> Result<Self, <Self as TryFrom<String>>::Error> {
		match str.as_str() {
			"SYN"	=> Ok(Self::SYN),
			"NULL"	=> Ok(Self::NULL),
			"ACK"	=> Ok(Self::ACK),
			"FIN"	=> Ok(Self::FIN),
			"XMAS"	=> Ok(Self::XMAS),
			"UDP"	=> Ok(Self::UDP),
			_		=> Err(())
		}
	}
}

impl std::fmt::Display for Scan {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		write!(f, "{}", String::from(*self))
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
	type Value = ArgIterator<Scan>;

	fn parse_ref(
		&self,
		cmd: &clap::Command,
		arg: Option<&clap::Arg>,
		raw_value: &std::ffi::OsStr
	) -> Result<Self::Value, clap::Error> {
		let inner = clap::builder::StringValueParser::new();
		let str = inner.parse_ref(cmd, arg, raw_value)?;

		let mut scans = ArgIterator::<Scan>::new();
		for scan_name in str.split(',') {
			let scantype = Scan::try_from(scan_name.trim().to_uppercase());
			if let Ok(scantype) = scantype {
				scans.inner.push(scantype);
			} else {
				return Err(Self::InvalidValue(scan_name, cmd));
			}
		}

		scans.inner.sort();
		scans.inner.dedup();
		Ok(scans)
	}
}
