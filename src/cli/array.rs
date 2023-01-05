use std::fmt::Display;
use super::port::Range;
use super::scan::Scan;

#[derive(Clone, Debug)]
pub struct Array<T: Display>(Vec<T>);

impl<T: Display> Array<T>
{
	pub fn new() -> Self {
		Self (vec![])
	}

	pub fn inner(&self) -> &Vec<T> {
		&self.0
	}

	pub fn inner_as_mut(&mut self) -> &mut Vec<T> {
		&mut self.0
	}
}

impl Array<Range> {	
	pub fn default() -> Self {
		Self (vec![Range { start: 1, end: 1024 }])
	}
}

impl std::fmt::Display for Array<Range> {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		self.inner().iter().fold(Ok(()), |result, range| {
			result.and_then(|_| write!(f, "{}", range))
		})
	}	
}

impl Array<Scan> {
	pub fn default() -> Self {
		Self (vec![Scan::SYN, Scan::NULL, Scan::ACK, Scan::FIN, Scan::XMAS, Scan::UDP])
	}
}

impl std::fmt::Display for Array<Scan> {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		self.inner().iter().fold(Ok(()), |result, scan| {
			result.and_then(|_| write!(f, "{}{}", scan, match scan {
				Scan::UDP => "",
				_ => ",",
			}))
		})
	}
}
