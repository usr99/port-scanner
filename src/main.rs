use clap::{Parser};

mod types;
use types::port;

#[derive(Parser)]
#[clap(author, version, about)]
#[command(arg_required_else_help(true))]
struct Args {

	/// Ip address to scan
	#[arg(short, long)]
	ip: Vec<std::net::IpAddr>,

	/// Range of ports to scan
	#[arg(short, long, default_value_t = port::RangeArray(vec![port::Range { start: 1, end: 1024}]), value_parser = port::RangeParser)]
	ports: port::RangeArray,

	/// Scan types
	// #[arg(short, long, value_enum, default_value_t = Scan::SYN)]
	// scan: Vec<Scan>,

	/// File that contains ip addresses to scan
	#[arg(short = 'f', long = "file")]
	ip_file: Option<std::path::PathBuf>,

	/// Number of scans to run concurrently
	#[arg(short, long, default_value_t = 1)]
	threads: u8
}

// struct ScanParams {
// 	ip: Vec<std::net::IpAddr>,
// 	ports: Vec<u16>,
// 	scan_type: Vec<Scan>,
// 	threads: u8
// }

fn main() {
	let args = Args::parse();

	println!("{:?}", args.ports);
}
