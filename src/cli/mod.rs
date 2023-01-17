pub mod arg;
pub mod port;
pub mod scan;

#[allow(unused_imports)]
use clap::Parser;

#[test]
fn port_basic_usage() {
	let arguments = vec![clap::crate_name!(), "-p 10-50,12,1,80-80,20-45,1000-500,5-10,50-80"];
	let expected = vec![
		port::Range::new(1,   1   ),
		port::Range::new(5,   80  ),
		port::Range::new(500, 1000)
	];

	match arg::Args::try_parse_from(arguments) {
		Ok(args) => assert_eq!(&args.ports.inner, &expected),
		Err(_) => assert!(false, "Parsing failed !"),
	};
}

#[test]
fn port_duplicates() {
	let arguments = vec![clap::crate_name!(), "-p 1,1,10-15,10-15"];
	let expected = vec![
		port::Range::new(1,  1 ),
		port::Range::new(10, 15)
	];

	match arg::Args::try_parse_from(arguments) {
		Ok(args) => assert_eq!(&args.ports.inner, &expected),
		Err(_) => assert!(false, "Parsing failed !"),
	};
}

#[test]
fn port_range_overlap() {
	let arguments = vec![clap::crate_name!(), "-p 1-50,25-75"];
	let expected = vec![
		port::Range::new(1, 75),
	];

	match arg::Args::try_parse_from(arguments) {
		Ok(args) => assert_eq!(&args.ports.inner, &expected),
		Err(_) => assert!(false, "Parsing failed !"),
	};
}

#[test]
fn port_range_too_big() {
	let arguments = vec![clap::crate_name!(), "-p 1025-1"];

	match arg::Args::try_parse_from(arguments) {
		Ok(_) => assert!(false, "Parsing should have failed !"),
		Err(e) => assert_eq!(e.kind(), clap::error::ErrorKind::InvalidValue),
	};
}

#[test]
fn port_bad_format() {
	let arguments = vec![clap::crate_name!(), "-p 80-443-1024"];

	match arg::Args::try_parse_from(arguments) {
		Ok(_) => assert!(false, "Parsing should have failed !"),
		Err(e) => assert_eq!(e.kind(), clap::error::ErrorKind::ValueValidation),
	};
}

#[test]
fn port_invalid_value() {
	let arguments = vec![clap::crate_name!(), "-p 0-512"];

	match arg::Args::try_parse_from(arguments) {
		Ok(_) => assert!(false, "Parsing should have failed !"),
		Err(e) => assert_eq!(e.kind(), clap::error::ErrorKind::ValueValidation),
	};
}

#[test]
fn scan_basic_usage() {
	let arguments = vec![clap::crate_name!(), "-s SYN,null,XMAS,syn"];
	let expected = vec![
		scan::Scan::SYN,
		scan::Scan::NULL,
		scan::Scan::XMAS
	];

	match arg::Args::try_parse_from(arguments) {
		Ok(args) => assert_eq!(&args.scans.inner, &expected),
		Err(_) => assert!(false, "Parsing failed !"),
	};
}

#[test]
fn scan_whitespaces() {
	let arguments = vec![clap::crate_name!(), "-s SYN,null,XMAS,   UDP, ACK, fin"];
	let expected = vec![
		scan::Scan::SYN,
		scan::Scan::NULL,
		scan::Scan::ACK,
		scan::Scan::FIN,
		scan::Scan::XMAS,
		scan::Scan::UDP
	];

	match arg::Args::try_parse_from(arguments) {
		Ok(args) => assert_eq!(&args.scans.inner, &expected),
		Err(_) => assert!(false, "Parsing failed !"),
	};
}

#[test]
fn scan_bad_separator() {
	let arguments = vec![clap::crate_name!(), "-s SYN/UDP"];

	match arg::Args::try_parse_from(arguments) {
		Ok(_) => assert!(false, "Parsing should have failed !"),
		Err(e) => assert_eq!(e.kind(), clap::error::ErrorKind::ValueValidation),
	};
}

#[test]
fn scan_invalid_value() {
	let arguments = vec![clap::crate_name!(), "-s SYN,XXXMAS"];

	match arg::Args::try_parse_from(arguments) {
		Ok(_) => assert!(false, "Parsing should have failed !"),
		Err(e) => assert_eq!(e.kind(), clap::error::ErrorKind::ValueValidation),
	};
}

#[test]
fn port_iterator_basic() {
	let mut arr = arg::ArgIterator::<port::Range>::new();
	arr.inner.push(port::Range::new(1, 3));
	arr.inner.push(port::Range::new(7, 9));
	
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
	const VALUE: u16 = 65535;
	let mut range = port::Range::new(VALUE, VALUE);

	assert_eq!(Some(VALUE), range.next());
	assert_eq!(None, range.next());
	assert_eq!(Some(VALUE), range.next());
}

#[test]
fn port_iterator_empty() {
	let mut arr = arg::ArgIterator::<scan::Scan>::new();
	assert_eq!(None, arr.next());
	assert_eq!(None, arr.next());
}


#[test]
fn scan_iterator_basic() {
	let mut arr = arg::ArgIterator::<scan::Scan>::default();
	
	assert_eq!(Some(scan::Scan::SYN), arr.next());
	assert_eq!(Some(scan::Scan::NULL), arr.next());
	assert_eq!(Some(scan::Scan::ACK), arr.next());
	assert_eq!(Some(scan::Scan::FIN), arr.next());
	assert_eq!(Some(scan::Scan::XMAS), arr.next());
	assert_eq!(Some(scan::Scan::UDP), arr.next());
	assert_eq!(None, arr.next());
	assert_eq!(Some(scan::Scan::SYN), arr.next());
}

#[test]
fn scan_iterator_empty() {
	let mut arr = arg::ArgIterator::<scan::Scan>::new();
	assert_eq!(None, arr.next());
	assert_eq!(None, arr.next());
}
