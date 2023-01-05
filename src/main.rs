use clap::Parser;
use eyre::Result;

use port_scanner::cli;

fn main() -> Result<()> {
	color_eyre::install()?;

	let args = cli::args::Args::parse();

	println!("{:?}", args);

	Ok(())
}
