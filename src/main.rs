use clap::Parser;
use anyhow::{Result, Context};
use socket::{Socket, AF_INET, SOCK_RAW, IPPROTO_RAW};

use port_scanner::{cli, probes};

fn main() -> Result<()> {
	let args = cli::Args::parse();
	let mut probes = probes::ProbeBuilder::new(args)
		.with_context(|| "Failed to initialize scan parameters")?;

	let socket = Socket::new(AF_INET, SOCK_RAW, IPPROTO_RAW)?;
	while let Some(packet) = probes.next() {
		socket.sendto(&packet, 0, &probes.destination())?;
	}

	Ok(())
}
