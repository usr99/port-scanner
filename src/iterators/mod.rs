use std::{cmp::PartialEq, fmt::Display, net::Ipv4Addr};

pub mod ports;
pub mod scans;

pub use ports::Range as PortRange;
pub use scans::Scan as ScanType;

/*
** Structure to hold arguments for scanning
** implements Iterator trait
** loops back to the beginning after returning None
*/
#[derive(Clone, Debug)]
pub struct LoopIterator<T: Display> {
	inner: Vec<T>,
	next: usize
}

impl<T: Display> LoopIterator<T> {
	pub fn new() -> Self {
		Self { inner: vec![], next: 0 }
	}
}

impl<T: Display> From<Vec<T>> for LoopIterator<T> {
	fn from(value: Vec<T>) -> Self {
		Self { inner: value, next: 0 }
	}
}

impl<T: Display + PartialEq> PartialEq<Vec<T>> for LoopIterator<T> {
	fn eq(&self, other: &Vec<T>) -> bool {
		&self.inner == other
	}

	fn ne(&self, other: &Vec<T>) -> bool {
		!self.eq(other)
	}
}

macro_rules! generic_iter_impl {
	($generic:ty) => {
		impl Iterator for LoopIterator<$generic> {
			type Item = $generic;

			fn next(&mut self) -> Option<Self::Item> {
				let value;

				if self.next < self.inner.len() {
					value = Some(self.inner[self.next]);
					self.next += 1;
				} else {
					value = None;
					self.next = 0; // loops back
				}
		
				value
			}
		}
	};
}

generic_iter_impl!(Ipv4Addr);
generic_iter_impl!(ScanType);

impl Iterator for LoopIterator<PortRange> {
	type Item = u16;

	fn next(&mut self) -> Option<Self::Item> {
		let value;

		if self.next < self.inner.len() {
			value = match self.inner[self.next].next() {
				Some(port) => Some(port),
				None => {
					self.next += 1;
					self.next()
				}
			}
		} else {
			value = None;
			self.next = 0; // loops back
		}

		value
	}
}

#[cfg(test)]
mod test {
	use crate::iterators::ports::Range;
	use crate::iterators::scans::Scan;
	use super::LoopIterator;

	#[test]
	fn port_iterator_basic() {
		let mut ports = LoopIterator::from(vec![Range::new(1, 3), Range::new(7, 9)]);
	
		assert_eq!(Some(1), ports.next());
		assert_eq!(Some(2), ports.next());
		assert_eq!(Some(3), ports.next());
		assert_eq!(Some(7), ports.next());
		assert_eq!(Some(8), ports.next());
		assert_eq!(Some(9), ports.next());
		assert_eq!(None, ports.next());
		assert_eq!(None, ports.next());
	}
	
	#[test]
	fn port_iterator_one_elem() {
		const VALUE: u16 = u16::MAX;
		let mut oneshot = LoopIterator::from(vec![Range::new(VALUE, VALUE)]);
	
		assert_eq!(Some(VALUE), oneshot.next());
		assert_eq!(None, oneshot.next());
		assert_eq!(None, oneshot.next());
	}
	
	#[test]
	fn port_iterator_empty() {
		let mut empty = LoopIterator::<Range>::from(vec![]);
		assert_eq!(None, empty.next());
		assert_eq!(None, empty.next());
	}
	
	#[test]
	fn scan_iterator_basic() {
		let mut arr = LoopIterator::<Scan>::default();
		
		assert_eq!(Some(Scan::SYN), arr.next());
		assert_eq!(Some(Scan::NULL), arr.next());
		assert_eq!(Some(Scan::ACK), arr.next());
		assert_eq!(Some(Scan::FIN), arr.next());
		assert_eq!(Some(Scan::XMAS), arr.next());
		assert_eq!(Some(Scan::UDP), arr.next());
		assert_eq!(None, arr.next());
		assert_eq!(Some(Scan::SYN), arr.next());
	}
	
	#[test]
	fn scan_iterator_empty() {
		let mut arr = LoopIterator::<Scan>::new();
		assert_eq!(None, arr.next());
		assert_eq!(None, arr.next());
	}
}
