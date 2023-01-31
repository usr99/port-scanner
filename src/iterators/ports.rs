use super::ArgIterator;
use clap::error::ErrorKind;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Copy)]
pub struct Range {
	start: u16,
	next: Option<u16>,
	end: u16
}

impl Range {
	pub fn new(start: u16, end: u16) -> Self {
		Range {start, next: Some(start), end }
	}
}

impl std::fmt::Display for Range {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		write!(f, "{}-{}", self.start, self.end)
	}
}

impl Iterator for Range {
	type Item = u16;

	fn next(&mut self) -> Option<Self::Item> {
		match self.next {
			Some(port) => {
				if port < self.end {
					self.next = Some(port + 1);
				} else {
					self.next = None;
				}
				Some(port)
			},
			None => {
				self.next = Some(self.start); // loops back
				None
			}
		}
	}
}

impl Default for ArgIterator<Range> {
	fn default() -> Self {
		Self { inner: vec![Range::new(1, 1024)], next: 0 }
	}
}

impl std::fmt::Display for ArgIterator<Range> {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		self.inner.iter().fold(Ok(()), |result, range| {
			result.and_then(|_| write!(f, "{}", range))
		})
	}	
}

impl Iterator for ArgIterator<Range> {
	type Item = u16;

	fn next(&mut self) -> Option<Self::Item> {
		if self.next < self.inner.len() {
			let range = &mut self.inner[self.next];

			match range.next() { // iterate deeply into ranges
				Some(port) => Some(port),
				None => {
					self.next += 1;
					self.next()
				}
			}
		} else {
			self.next = 0; // loops back
			None
		}
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

	fn validate(mut array: ArgIterator<Range>, cmd: &clap::Command) -> Result<ArgIterator<Range>, clap::Error> {
		let mut last: Option<Range> = None;
		let mut result: Vec<Range> = vec![];

		array.inner.sort();
		for pair in array.inner.windows(2) { // iterate over pairs of consecutive ranges
			if let Some(ref mut tmp) = last {
				if tmp.end >= pair[1].start { 
					if tmp.end < pair[1].end { // temporary range still overlaps with next one
						tmp.end = pair[1].end; // therefore extend it
					}
				} else { // no more overlaps
					result.push(*tmp); // save temp range
					last = None;
				}			
			} else {
				if pair[0].end >= pair[1].start { // overlapping ranges
					if pair[0].end >= pair[1].end { // create a temporary range that contains both
						last = Some(Range::new(pair[0].start, pair[0].end));
					} else {
						last = Some(Range::new(pair[0].start, pair[1].end));
					}
				} else { // no overlaps, do nothing
					result.push(pair[0]);
				}
			}
		}

		if let Some(last) = last {
			result.push(last);
		} else {
			result.push(*array.inner.last().unwrap());
		}

		if result.iter().fold(0, |acc, r| acc + (r.end - r.start) + 1) > 1024 {
			return Err(Self::RangeTooBig(cmd)); // cannot scan more than 1024 ports at once
		}

		array.inner = std::mem::take(&mut result);
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

		let mut ports = ArgIterator::<Range>::new();
		for range in str.split(',') { // ',' separates ranges
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
				ports.inner.push(Range::new(r[0], r[1]));
			} else {
				ports.inner.push(Range::new(r[1], r[0]));
			}
		}

		Self::validate(ports, cmd) // merge overlaps, inverse reversed ranges, etc.
	}
}
