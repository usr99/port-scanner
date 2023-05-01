#[allow(unused_imports)]
use clap::Parser;

use crate::iterators::{ArgIterator, PortRange, ScanType};
use crate::iterators::{ports, scans};

#[derive(Parser, Debug)]
#[clap(author, version, about)]
#[command(arg_required_else_help(true))]
pub struct Args {
	/// Addresses to scan or path to a file containing those addresses (can be hostnames too)
	#[arg(short, long)]
	pub ip: Vec<String>,

	/// Range of ports to scan
	#[arg(short, long, default_value_t = ArgIterator::<PortRange>::default(), value_parser = ports::Parser)]
	pub ports: ArgIterator<PortRange>,

	/// Scan types
	#[arg(short, long, default_value_t = ArgIterator::<ScanType>::default(), value_parser = scans::Parser)]
	pub scans: ArgIterator<ScanType>,

	/// Number of scans to run concurrently
	#[arg(short, long, default_value_t = 1)]
	pub threads: u8
}

#[test]
fn port_basic_usage() {
	let arguments = vec![clap::crate_name!(), "-p 10-50,12,1,80-80,20-45,1000-500,5-10,50-80"];
	let expected = vec![
		PortRange::new(1,   1   ),
		PortRange::new(5,   80  ),
		PortRange::new(500, 1000)
	];

	match Args::try_parse_from(arguments) {
		Ok(args) => assert_eq!(&args.ports, &expected),
		Err(_) => assert!(false, "Parsing failed !"),
	};
}

#[test]
fn port_duplicates() {
	let arguments = vec![clap::crate_name!(), "-p 1,1,10-15,10-15"];
	let expected = vec![
		PortRange::new(1,  1 ),
		PortRange::new(10, 15)
	];

	match Args::try_parse_from(arguments) {
		Ok(args) => assert_eq!(&args.ports, &expected),
		Err(_) => assert!(false, "Parsing failed !"),
	};
}

#[test]
fn port_range_overlap() {
	let arguments = vec![clap::crate_name!(), "-p 1-50,25-75"];
	let expected = vec![
		PortRange::new(1, 75),
	];

	match Args::try_parse_from(arguments) {
		Ok(args) => assert_eq!(&args.ports, &expected),
		Err(_) => assert!(false, "Parsing failed !"),
	};
}

#[test]
fn port_range_too_big() {
	let arguments = vec![clap::crate_name!(), "-p 1025-1"];

	match Args::try_parse_from(arguments) {
		Ok(_) => assert!(false, "Parsing should have failed !"),
		Err(e) => assert_eq!(e.kind(), clap::error::ErrorKind::InvalidValue),
	};
}

#[test]
fn port_bad_format() {
	let arguments = vec![clap::crate_name!(), "-p 80-443-1024"];

	match Args::try_parse_from(arguments) {
		Ok(_) => assert!(false, "Parsing should have failed !"),
		Err(e) => assert_eq!(e.kind(), clap::error::ErrorKind::ValueValidation),
	};
}

#[test]
fn port_invalid_value() {
	let arguments = vec![clap::crate_name!(), "-p 0-512"];

	match Args::try_parse_from(arguments) {
		Ok(_) => assert!(false, "Parsing should have failed !"),
		Err(e) => assert_eq!(e.kind(), clap::error::ErrorKind::ValueValidation),
	};
}

#[test]
fn scan_basic_usage() {
	let arguments = vec![clap::crate_name!(), "-s SYN,null,XMAS,syn"];
	let expected = vec![
		ScanType::SYN,
		ScanType::NULL,
		ScanType::XMAS
	];

	match Args::try_parse_from(arguments) {
		Ok(args) => assert_eq!(&args.scans, &expected),
		Err(_) => assert!(false, "Parsing failed !"),
	};
}

#[test]
fn scan_whitespaces() {
	let arguments = vec![clap::crate_name!(), "-s SYN,null,XMAS,   UDP, ACK, fin"];
	let expected = vec![
		ScanType::SYN,
		ScanType::NULL,
		ScanType::ACK,
		ScanType::FIN,
		ScanType::XMAS,
		ScanType::UDP
	];

	match Args::try_parse_from(arguments) {
		Ok(args) => assert_eq!(&args.scans, &expected),
		Err(_) => assert!(false, "Parsing failed !"),
	};
}

#[test]
fn scan_bad_separator() {
	let arguments = vec![clap::crate_name!(), "-s SYN/UDP"];

	match Args::try_parse_from(arguments) {
		Ok(_) => assert!(false, "Parsing should have failed !"),
		Err(e) => assert_eq!(e.kind(), clap::error::ErrorKind::ValueValidation),
	};
}

#[test]
fn scan_invalid_value() {
	let arguments = vec![clap::crate_name!(), "-s SYN,XXXMAS"];

	match Args::try_parse_from(arguments) {
		Ok(_) => assert!(false, "Parsing should have failed !"),
		Err(e) => assert_eq!(e.kind(), clap::error::ErrorKind::ValueValidation),
	};
}
