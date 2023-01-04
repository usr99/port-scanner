use clap::Parser;
use eyre::Result;

#[path = "types/cli.rs"]
mod cli;

fn main() -> Result<()> {
	color_eyre::install()?;

	let args = cli::Args::parse();

	println!("{:?}", args);

	Ok(())
}
