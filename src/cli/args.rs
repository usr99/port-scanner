use clap::Parser;

use super::array::Array;
use super::port::{Range, RangeParser};
use super::scan::{Scan, ScanParser};

#[derive(Parser, Debug)]
#[clap(author, version, about)]
#[command(arg_required_else_help(true))]
pub struct Args {

	/// Ip address to scan
	#[arg(short, long)]
	pub ip: Vec<String>,

	/// Range of ports to scan
	#[arg(short, long, default_value_t = Array::<Range>::default(), value_parser = RangeParser)]
	pub ports: Array<Range>,

	/// Scan types
	#[arg(short, long, default_value_t = Array::<Scan>::default(), value_parser = ScanParser)]
	pub scans: Array<Scan>,

	/// File that contains ip addresses to scan
	#[arg(short = 'f', long = "file")]
	pub ip_file: Option<std::path::PathBuf>,

	/// Number of scans to run concurrently
	#[arg(short, long, default_value_t = 1)]
	pub threads: u8
}
