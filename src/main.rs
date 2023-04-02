use clap::Parser;
use anyhow::{Result, Context};
use socket::{Socket, AF_INET, SOCK_RAW, IPPROTO_RAW};

use port_scanner::{cli, probes};

fn main() -> Result<()> {
	let args = cli::Args::parse();

	let (iface, source) = lookup_interfaces()?;
	println!("Capturing on {}:{}", iface.name, source);

	let mut probes = probes::ProbeBuilder::new(args, source)
		.with_context(|| "Failed to initialize scan parameters")?;

	let socket = Socket::new(AF_INET, SOCK_RAW, IPPROTO_RAW)?;
	while let Some(packet) = probes.next() {
		socket.sendto(&packet, 0, &probes.destination())?;
	}

	Ok(())
}

fn lookup_interfaces() -> Result<(NetworkInterface, Ipv4Addr)> {
	for ifa in datalink::interfaces().into_iter() {
		if !ifa.is_up() || ifa.is_loopback() {
			continue ;
		}
	
		if let Some(IpAddr::V4(ip)) = ifa.ips.iter().map(|net| net.ip()).find(|ip| ip.is_ipv4()) {
			return Ok((ifa, ip));
		}
	}

	Err(anyhow!("no suitable device found"))
}
