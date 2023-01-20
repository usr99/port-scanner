use std::fmt::Display;
use std::cmp::PartialEq;

pub mod ports;
pub mod scans;

pub use ports::Range as PortRange;
pub use scans::Scan as ScanType;

#[derive(Clone, Debug)]
pub struct ArgIterator<T: Display> {
	inner: Vec<T>,
	next: usize
}

impl<T: Display> ArgIterator<T>
{
	pub fn new() -> Self {
		Self { inner: vec![], next: 0 }
	}
}

impl<T: Display + PartialEq> PartialEq<Vec<T>> for ArgIterator<T> {
	fn eq(&self, other: &Vec<T>) -> bool {
		&self.inner == other
	}

	fn ne(&self, other: &Vec<T>) -> bool {
		!self.eq(other)
	}
}

#[test]
fn port_iterator_basic() {
	let mut arr = ArgIterator::<PortRange>::new();
	arr.inner.push(PortRange::new(1, 3));
	arr.inner.push(PortRange::new(7, 9));
	
	assert_eq!(Some(1), arr.next());
	assert_eq!(Some(2), arr.next());
	assert_eq!(Some(3), arr.next());
	assert_eq!(Some(7), arr.next());
	assert_eq!(Some(8), arr.next());
	assert_eq!(Some(9), arr.next());
	assert_eq!(None, arr.next());
	assert_eq!(Some(1), arr.next());
}

#[test]
fn port_iterator_one_elem() {
	const VALUE: u16 = u16::MAX;
	let mut range = PortRange::new(VALUE, VALUE);

	assert_eq!(Some(VALUE), range.next());
	assert_eq!(None, range.next());
	assert_eq!(Some(VALUE), range.next());
}

#[test]
fn port_iterator_empty() {
	let mut arr = ArgIterator::<ScanType>::new();
	assert_eq!(None, arr.next());
	assert_eq!(None, arr.next());
}


#[test]
fn scan_iterator_basic() {
	let mut arr = ArgIterator::<ScanType>::default();
	
	assert_eq!(Some(ScanType::SYN), arr.next());
	assert_eq!(Some(ScanType::NULL), arr.next());
	assert_eq!(Some(ScanType::ACK), arr.next());
	assert_eq!(Some(ScanType::FIN), arr.next());
	assert_eq!(Some(ScanType::XMAS), arr.next());
	assert_eq!(Some(ScanType::UDP), arr.next());
	assert_eq!(None, arr.next());
	assert_eq!(Some(ScanType::SYN), arr.next());
}

#[test]
fn scan_iterator_empty() {
	let mut arr = ArgIterator::<ScanType>::new();
	assert_eq!(None, arr.next());
	assert_eq!(None, arr.next());
}
