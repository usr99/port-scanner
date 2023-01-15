use clap::error::ErrorKind;
use super::args::ArgIterator;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Copy)]
pub struct Range {
	cur: u16,
	end: u16,
	done: bool
}

impl Range {
	pub fn new(start: u16, end: u16) -> Self {
		Range { cur: start, end, done: false }
	}
}

impl std::fmt::Display for Range {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		write!(f, "{}-{}", self.cur, self.end)
	}
}

impl Iterator for Range {
	type Item = u16;

	fn next(&mut self) -> Option<Self::Item> {
		if !self.done {
			if self.cur != self.end {
				let ret = Some(self.cur);
				self.cur += 1;
				return ret;
			} else {
				self.done = true;
				Some(self.end)
			}
		} else {
			None
		}
	}
}

#[derive(Clone)]
pub struct RangeParser;

impl RangeParser {
	#[allow(non_snake_case)]
	fn InvalidValue(value: &str, cmd: &clap::Command) -> clap::Error {
		clap::Error::raw(ErrorKind::ValueValidation, format!("\"{}\" is not valid as a port number\n", value)).with_cmd(cmd)
	}

	#[allow(non_snake_case)]
	fn RangeTooBig(cmd: &clap::Command) -> clap::Error {
		clap::Error::raw(ErrorKind::InvalidValue, format!("Cannot scan more than 1024 ports\n")).with_cmd(cmd)
	}

	fn validate(mut array: ArgIterator<Range>, cmd: &clap::Command) -> Result<ArgIterator<Range>, clap::Error> {

		let inner = array.inner_as_mut();
		inner.sort();

		let mut last: Option<Range> = None;
		let mut result: Vec<Range> = vec![];

		for pair in inner.windows(2) {
			if let Some(ref mut tmp) = last {
				if tmp.end >= pair[1].cur {
					if tmp.end < pair[1].end {
						tmp.end = pair[1].end;
					}
				} else {
					result.push(*tmp);
					last = None;
				}			
			} else {
				if pair[0].end >= pair[1].cur {
					if pair[0].end >= pair[1].end {
						last = Some(Range::new(pair[0].cur, pair[0].end));
					} else {
						last = Some(Range::new(pair[0].cur, pair[1].end));
					}
				} else {
					result.push(pair[0]);
				}
			}
		}

		if let Some(last) = last {
			result.push(last);
		} else {
			result.push(*inner.last().unwrap());
		}

		if result.iter().fold(0, |acc, r| acc + (r.end - r.cur) + 1) > 1024 {
			return Err(Self::RangeTooBig(cmd));
		}

		*inner = std::mem::take(&mut result);
		Ok(array)
	}
}

impl clap::builder::TypedValueParser for RangeParser {
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
		for range in str.split(',') {
			let values: Vec<&str> = range.splitn(2, '-').collect();
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
				ports.inner_as_mut().push(Range::new(r[0], r[1]));
			} else {
				ports.inner_as_mut().push(Range::new(r[1], r[0]));
			}
		}

		Self::validate(ports, cmd)
	}
}
