use super::LoopIterator;
use clap::error::ErrorKind;

#[derive (Clone, Copy, Debug, PartialEq, Ord, PartialOrd, Eq)]
pub enum Scan { SYN, NULL, ACK, FIN, XMAS, UDP }

impl From<Scan> for String {
	fn from(scan: Scan) -> Self {
		String::from(match scan {
			Scan::SYN	=> "SYN",
			Scan::NULL	=> "NULL",
			Scan::ACK	=> "ACK",
			Scan::FIN	=> "FIN",
			Scan::XMAS	=> "XMAS",
			Scan::UDP	=> "UDP"
		})
	}	
}

impl TryFrom<Scan> for u16 {
	type Error = ();

	fn try_from(scan: Scan) -> Result<Self, <Self as TryFrom<Scan>>::Error> {
		match scan {
			Scan::SYN	=> Ok(0b00_0010),
			Scan::NULL	=> Ok(0b00_0000),
			Scan::ACK	=> Ok(0b01_0000),
			Scan::FIN	=> Ok(0b00_0001),
			Scan::XMAS	=> Ok(0b10_1001),
			_			=> Err(())
		}
	}
}

impl TryFrom<&str> for Scan {
	type Error = ();

	fn try_from(str: &str) -> Result<Self, <Self as TryFrom<&str>>::Error> {
		match str {
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

impl Default for LoopIterator<Scan> {
	fn default() -> Self {
		Self::from(vec![Scan::SYN, Scan::NULL, Scan::ACK, Scan::FIN, Scan::XMAS, Scan::UDP])
	}
}

impl std::fmt::Display for LoopIterator<Scan> {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		self.inner.iter().fold(Ok(()), |result, scan| {
			result.and_then(|_| write!(f, "{}{}", scan, match scan != self.inner.last().unwrap() {
				true => ",",
				false => ""
			}))
		})
	}
}

#[derive (Clone)]
pub struct Parser;

impl Parser {
	#[allow(non_snake_case)]
	fn InvalidValue(value: &str, cmd: &clap::Command) -> clap::Error {
		clap::Error::raw(ErrorKind::ValueValidation, format!("\"{}\" is not a valid type of scan\n", value)).with_cmd(cmd)
	}
}

impl clap::builder::TypedValueParser for Parser {
	type Value = LoopIterator<Scan>;

	fn parse_ref(
		&self,
		cmd: &clap::Command,
		arg: Option<&clap::Arg>,
		raw_value: &std::ffi::OsStr
	) -> Result<Self::Value, clap::Error> {
		let inner = clap::builder::StringValueParser::new();
		let str = inner.parse_ref(cmd, arg, raw_value)?;

		let mut scans = LoopIterator::<Scan>::new();
		for scan_name in str.split(',') { // ',' separates scan names
			let scan_name = scan_name.trim().to_uppercase();
			if scan_name.is_empty() {
				continue ;
			}

			let scantype = Scan::try_from(scan_name.as_str());
			if let Ok(scantype) = scantype {
				scans.inner.push(scantype);
			} else {
				return Err(Self::InvalidValue(&scan_name, cmd));
			}
		}

		scans.inner.sort();
		scans.inner.dedup(); // remove duplicate scan types
		Ok(scans)
	}
}
