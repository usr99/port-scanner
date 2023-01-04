use clap::Parser;

pub mod port;
pub mod scan;

#[derive(Parser, Debug)]
#[clap(author, version, about)]
#[command(arg_required_else_help(true))]
pub struct Args {

	/// Ip address to scan
	#[arg(short, long)]
	pub ip: Vec<String>,

	/// Range of ports to scan
	#[arg(short, long, default_value_t = port::RangeArray(vec![port::Range { start: 1, end: 1024}]), value_parser = port::RangeParser)]
	pub ports: port::RangeArray,

	/// Scan types
	#[arg(short, long, default_value_t = scan::ScanArray::new(), value_parser = scan::ScanParser)]
	pub scans: scan::ScanArray,

	/// File that contains ip addresses to scan
	#[arg(short = 'f', long = "file")]
	pub ip_file: Option<std::path::PathBuf>,

	/// Number of scans to run concurrently
	#[arg(short, long, default_value_t = 1)]
	pub threads: u8
}
