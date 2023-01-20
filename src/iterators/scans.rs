use super::ArgIterator;
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

impl Default for ArgIterator<Scan> {
	fn default() -> Self {
		Self { inner: vec![Scan::SYN, Scan::NULL, Scan::ACK, Scan::FIN, Scan::XMAS, Scan::UDP], next: 0 }
	}
}

impl std::fmt::Display for ArgIterator<Scan> {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		self.inner.iter().fold(Ok(()), |result, scan| {
			result.and_then(|_| write!(f, "{}{}", scan, match scan {
				Scan::UDP => "",
				_ => ",",
			}))
		})
	}
}

impl Iterator for ArgIterator<Scan> {
	type Item = Scan;

	fn next(&mut self) -> Option<Self::Item> {
		let value;
		if self.next < self.inner.len() {
			value = Some(self.inner[self.next]);
			self.next += 1;
		} else {
			value = None;
			self.next = 0;
		}

		value
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
