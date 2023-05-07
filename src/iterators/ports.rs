use super::ArgIterator;
use clap::error::ErrorKind;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Copy)]
pub struct Range {
	current: Option<u16>,
	end: u16
}

impl Range {
	pub fn new(start: u16, end: u16) -> Self {
		Range { current: Some(start), end }
	}
}

// Panics if the iterator is already consumed
// we don't really care because this impl is just for clap::Parser
impl std::fmt::Display for Range {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		write!(f, "{}-{}", self.current.unwrap(), self.end)
	}
}

impl Iterator for Range {
	type Item = u16;

	fn next(&mut self) -> Option<Self::Item> {
		match self.current {
			Some(port) => {
				if port < self.end {
					self.current = Some(port + 1);
				} else {
					self.current = None;
				}
				Some(port)
			},
			None => None
		}
	}
}

impl Default for ArgIterator<Range> {
	fn default() -> Self {
		Self::from(vec![Range::new(1, 1024)])
	}
}

impl std::fmt::Display for ArgIterator<Range> {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		self.inner.iter().fold(Ok(()), |result, range| {
			result.and_then(|_| write!(f, "{},", range))
		})
	}
}

#[derive(Clone)]
pub struct Parser;

impl Parser {
	#[allow(non_snake_case)]
	fn InvalidValue(value: &str, cmd: &clap::Command) -> clap::Error {
		clap::Error::raw(ErrorKind::ValueValidation, format!("\"{}\" is not valid as a port number\n", value)).with_cmd(cmd)
	}

	#[allow(non_snake_case)]
	fn RangeTooBig(cmd: &clap::Command) -> clap::Error {
		clap::Error::raw(ErrorKind::InvalidValue, format!("Cannot scan more than 1024 ports\n")).with_cmd(cmd)
	}

	fn validate(mut array: Vec<Range>, cmd: &clap::Command) -> Result<Vec<Range>, clap::Error> {
		let mut last: Option<Range> = None;
		let mut result: Vec<Range> = vec![];

		array.sort();
		for pair in array.windows(2) { // iterate over pairs of consecutive ranges
			if let Some(ref mut tmp) = last {
				if tmp.end >= pair[1].current.unwrap() { 
					if tmp.end < pair[1].end { // temporary range still overlaps with next one
						tmp.end = pair[1].end; // therefore extend it
					}
				} else { // no more overlaps
					result.push(*tmp); // save temp range
					last = None;
				}			
			} else {
				if pair[0].end >= pair[1].current.unwrap() { // overlapping ranges
					if pair[0].end >= pair[1].end { // create a temporary range that contains both
						last = Some(Range::new(pair[0].current.unwrap(), pair[0].end));
					} else {
						last = Some(Range::new(pair[0].current.unwrap(), pair[1].end));
					}
				} else { // no overlaps, do nothing
					result.push(pair[0]);
				}
			}
		}

		if let Some(last) = last {
			result.push(last);
		} else {
			result.push(*array.last().unwrap());
		}

		if result.iter().fold(0, |acc, r| acc + (r.end - r.current.unwrap()) + 1) > 1024 {
			return Err(Self::RangeTooBig(cmd)); // cannot scan more than 1024 ports at once
		}

		array = std::mem::take(&mut result);
		
		Ok(array)
	}
}

impl clap::builder::TypedValueParser for Parser {
	type Value = ArgIterator<Range>;
	
	fn parse_ref(
		&self,
		cmd: &clap::Command,
		arg: Option<&clap::Arg>,
		raw_value: &std::ffi::OsStr
	) -> Result<Self::Value, clap::Error> {
		let inner = clap::builder::StringValueParser::new();
		let str = inner.parse_ref(cmd, arg, raw_value)?;

		let mut ports = Vec::<Range>::new();
		for range in str.split(',') { // ',' separates ranges
			if range.is_empty() {
				continue ;
			}
			
			let values: Vec<&str> = range.splitn(2, '-').collect(); // '-' separates range bounds
			let mut r: [u16; 2] = [0, 0];

			for i in 0..values.len() {
				if let Ok(v) = values[i].trim().parse::<u16>() {
					if v != 0 {
						r[i] = v;
						r[1] = v;
					} else {
						return Err(Self::InvalidValue(values[i], cmd));
					}
				} else {
					return Err(Self::InvalidValue(values[i], cmd));
				}
			}

			if r[0] < r[1] {
				ports.push(Range::new(r[0], r[1]));
			} else {
				ports.push(Range::new(r[1], r[0]));
			}
		}

		ports = Self::validate(ports, cmd)?;
		Ok(ArgIterator::from(ports))
	}
}
