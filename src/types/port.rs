use clap::error::ErrorKind;

mod array;
use array::Array;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Copy)]
pub struct Range {
	pub start: u16,
	pub end: u16
}

impl std::fmt::Display for Range {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		write!(f, "{}-{}", self.start, self.end)
	}
}

impl Array<Range> {
	pub fn new() -> Self {
		Self (vec![Range { start: 1, end: 1024 }])
	}
}

// #[derive(Clone, Debug)]
// pub struct RangeArray(pub Vec<Range>);

// impl RangeArray {
// 	pub fn inner(&self) -> &Vec<Range> {
// 		&self.0
// 	}

// 	pub fn inner_as_mut(&mut self) -> &mut Vec<Range> {
// 		&mut self.0
// 	}
// }

// impl std::fmt::Display for RangeArray {
// 	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
// 		self.inner().iter().fold(Ok(()), |result, range| {
// 			result.and_then(|_| write!(f, "{}", range))
// 		})
// 	}	
// }

// #[derive(Clone)]
// pub struct RangeParser;

// impl RangeParser {
// 	#[allow(non_snake_case)]
// 	fn InvalidValue(value: &str, cmd: &clap::Command) -> clap::Error {
// 		clap::Error::raw(ErrorKind::ValueValidation, format!("\"{}\" is not valid as a port number\n", value)).with_cmd(cmd)
// 	}

// 	#[allow(non_snake_case)]
// 	fn RangeTooBig(cmd: &clap::Command) -> clap::Error {
// 		clap::Error::raw(ErrorKind::InvalidValue, format!("Cannot scan more than 1024 ports\n")).with_cmd(cmd)
// 	}

// 	fn validate(mut array: RangeArray, cmd: &clap::Command) -> Result<RangeArray, clap::Error> {

// 		let inner = array.inner_as_mut();

// 		// sort
// 		inner.sort();

// 		// merge overlapping ranges
// 		let mut last: Option<Range> = None;
// 		let mut result: Vec<Range> = vec![];

// 		for pair in inner.windows(2) {
// 			if let Some(ref mut tmp) = last {
// 				if tmp.end >= pair[1].start {
// 					if tmp.end < pair[1].end {
// 						tmp.end = pair[1].end;
// 					}
// 				} else {
// 					result.push(*tmp);
// 					last = None;
// 				}			
// 			} else {
// 				if pair[0].end >= pair[1].start {
// 					if pair[0].end >= pair[1].end {
// 						last = Some(Range { start: pair[0].start, end: pair[0].end });
// 					} else {
// 						last = Some(Range { start: pair[0].start, end: pair[1].end });
// 					}
// 				} else {
// 					result.push(pair[0]);
// 				}
// 			}
// 		}

// 		if let Some(last) = last {
// 			result.push(last);
// 		} else {
// 			result.push(*inner.last().unwrap());
// 		}

// 		if result.iter().fold(0, |acc, r| acc + (r.end - r.start) + 1) > 1024 {
// 			return Err(Self::RangeTooBig(cmd));
// 		}

// 		*inner = std::mem::take(&mut result);

// 		Ok(array)
// 	}
// }

// impl clap::builder::TypedValueParser for RangeParser {
// 	type Value = RangeArray;
	
// 	fn parse_ref(
// 		&self,
// 		cmd: &clap::Command,
// 		arg: Option<&clap::Arg>,
// 		raw_value: &std::ffi::OsStr
// 	) -> Result<Self::Value, clap::Error> {
// 		let inner = clap::builder::StringValueParser::new();
// 		let str = inner.parse_ref(cmd, arg, raw_value)?;

// 		let mut ports: RangeArray = RangeArray(Vec::new());
// 		for range in str.split(',') {
// 			let values: Vec<&str> = range.splitn(2, '-').collect();
// 			let mut r: [u16; 2] = [0, 0];

// 			for i in 0..values.len() {
// 				if let Ok(v) = values[i].trim().parse::<u16>() {
// 					if v != 0 {
// 						r[i] = v;
// 						r[1] = v;
// 					} else {
// 						return Err(Self::InvalidValue(values[i], cmd));
// 					}
// 				} else {
// 					return Err(Self::InvalidValue(values[i], cmd));
// 				}
// 			}

// 			if r[0] < r[1] {
// 				ports.inner_as_mut().push(Range { start: r[0], end: r[1] });
// 			} else {
// 				ports.inner_as_mut().push(Range { start: r[1], end: r[0] });
// 			}
// 		}

// 		Self::validate(ports, cmd)
// 	}
// }
