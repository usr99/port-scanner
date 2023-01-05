use clap::Parser;
use port_scanner::cli;

#[test]
fn port_basic_usage() {
	let arguments = vec![clap::crate_name!(), "-p 10-50,12,1,80-80,20-45,1000-500,5-10,50-80"];
	let expected = vec![
		cli::port::Range { start: 1,    end: 1    },
		cli::port::Range { start: 5,    end: 80   },
		cli::port::Range { start: 500,  end: 1000 }
	];

	match cli::args::Args::try_parse_from(arguments) {
		Ok(args) => assert_eq!(args.ports.inner(), &expected),
		Err(_) => assert!(false, "Parsing failed !"),
	};
}

#[test]
fn port_duplicates() {
	let arguments = vec![clap::crate_name!(), "-p 1,1,10-15,10-15"];
	let expected = vec![
		cli::port::Range { start: 1,  end: 1  },
		cli::port::Range { start: 10, end: 15 }
	];

	match cli::args::Args::try_parse_from(arguments) {
		Ok(args) => assert_eq!(args.ports.inner(), &expected),
		Err(_) => assert!(false, "Parsing failed !"),
	};
}

#[test]
fn port_range_overlap() {
	let arguments = vec![clap::crate_name!(), "-p 1-50,25-75"];
	let expected = vec![
		cli::port::Range { start: 1, end: 75 },
	];

	match cli::args::Args::try_parse_from(arguments) {
		Ok(args) => assert_eq!(args.ports.inner(), &expected),
		Err(_) => assert!(false, "Parsing failed !"),
	};
}

#[test]
fn port_range_too_big() {
	let arguments = vec![clap::crate_name!(), "-p 1025-1"];

	match cli::args::Args::try_parse_from(arguments) {
		Ok(_) => assert!(false, "Parsing should have failed !"),
		Err(e) => assert_eq!(e.kind(), clap::error::ErrorKind::InvalidValue),
	};
}

#[test]
fn port_bad_format() {
	let arguments = vec![clap::crate_name!(), "-p 80-443-1024"];

	match cli::args::Args::try_parse_from(arguments) {
		Ok(_) => assert!(false, "Parsing should have failed !"),
		Err(e) => assert_eq!(e.kind(), clap::error::ErrorKind::ValueValidation),
	};
}

#[test]
fn port_invalid_value() {
	let arguments = vec![clap::crate_name!(), "-p 0-512"];

	match cli::args::Args::try_parse_from(arguments) {
		Ok(_) => assert!(false, "Parsing should have failed !"),
		Err(e) => assert_eq!(e.kind(), clap::error::ErrorKind::ValueValidation),
	};
}

#[test]
fn scan_basic_usage() {
	let arguments = vec![clap::crate_name!(), "-s SYN,null,XMAS,syn"];
	let expected = vec![
		cli::scan::Scan::SYN,
		cli::scan::Scan::NULL,
		cli::scan::Scan::XMAS
	];

	match cli::args::Args::try_parse_from(arguments) {
		Ok(args) => assert_eq!(args.scans.inner(), &expected),
		Err(_) => assert!(false, "Parsing failed !"),
	};
}

#[test]
fn scan_whitespaces() {
	let arguments = vec![clap::crate_name!(), "-s SYN,null,XMAS,   UDP, ACK, fin"];
	let expected = vec![
		cli::scan::Scan::SYN,
		cli::scan::Scan::NULL,
		cli::scan::Scan::ACK,
		cli::scan::Scan::FIN,
		cli::scan::Scan::XMAS,
		cli::scan::Scan::UDP
	];

	match cli::args::Args::try_parse_from(arguments) {
		Ok(args) => assert_eq!(args.scans.inner(), &expected),
		Err(_) => assert!(false, "Parsing failed !"),
	};
}

#[test]
fn scan_bad_separator() {
	let arguments = vec![clap::crate_name!(), "-s SYN/UDP"];

	match cli::args::Args::try_parse_from(arguments) {
		Ok(_) => assert!(false, "Parsing should have failed !"),
		Err(e) => assert_eq!(e.kind(), clap::error::ErrorKind::ValueValidation),
	};
}

#[test]
fn scan_invalid_value() {
	let arguments = vec![clap::crate_name!(), "-s SYN,XXXMAS"];

	match cli::args::Args::try_parse_from(arguments) {
		Ok(_) => assert!(false, "Parsing should have failed !"),
		Err(e) => assert_eq!(e.kind(), clap::error::ErrorKind::ValueValidation),
	};
}
