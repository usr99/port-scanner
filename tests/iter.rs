use port_scanner::cli::args::ArgIterator;
use port_scanner::cli::{port, scan};

#[test]
fn port_iterator_basic() {
	let mut arr = ArgIterator::<port::Range>::new();
	arr.inner_as_mut().push(port::Range::new(65533, 65535));
	arr.inner_as_mut().push(port::Range::new(4000, 	4000));
	arr.inner_as_mut().push(port::Range::new(25, 	27));
	arr.inner_as_mut().push(port::Range::new(1, 	5));
	
	let expected: Vec<u16> = vec![1, 2, 3, 4, 5, 25, 26, 27, 4000, 65533, 65534, 65535];

	assert_eq!(expected, arr.collect::<Vec<u16>>());
}

#[test]
fn port_iterator_one_elem() {
	const VALUE: u16 = 65535;
	let mut range = port::Range::new(VALUE, VALUE);

	assert_eq!(VALUE, range.next().unwrap());
	assert_eq!(None, range.next());
}

#[test]
fn port_iterator_empty() {
	let mut arr = ArgIterator::<scan::Scan>::new();
	assert_eq!(None, arr.next());
}


#[test]
fn scan_iterator_basic() {
	let arr = ArgIterator::<scan::Scan>::default();
	
	let expected: Vec<scan::Scan> = vec![
		scan::Scan::UDP,
		scan::Scan::XMAS,
		scan::Scan::FIN,
		scan::Scan::ACK,
		scan::Scan::NULL,
		scan::Scan::SYN
	];

	assert_eq!(expected, arr.collect::<Vec<scan::Scan>>());
}

#[test]
fn scan_iterator_empty() {
	let mut arr = ArgIterator::<scan::Scan>::new();
	assert_eq!(None, arr.next());
}

