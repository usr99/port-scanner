use clap::Parser;
use anyhow::{Result, Context, anyhow};
use mio::{Poll, Events, Token, unix::SourceFd, Interest};
use std::{
	time::{Instant, Duration},
	net::{Ipv4Addr, IpAddr}
};
use pnet::datalink::{self, NetworkInterface};
use socket::{Socket, SOCK_RAW, htons};
use libc::{AF_PACKET, ETH_P_ALL, AF_INET, IPPROTO_RAW};

use port_scanner::{cli, probes::{self, report::Scanner}};

const DELAY: Duration = Duration::from_millis(250);

fn main() -> Result<()> {
	let args = cli::Args::parse();

	let (iface, source) = lookup_interfaces()?;
	println!("Capturing on {}:{}", iface.name, source);

	let mut probes = probes::ProbeBuilder::new(args, source)
		.with_context(|| "Failed to initialize scan parameters")?;

	// We create two sockets, one for sending and one for receiving
	// tx is AF_INET because no one wants to fill MAC addresses by hand
	// rx is AF_PACKET because we can't receive ICMP, TCP and UDP on a unique raw socket
	// and using three sockets would be harder to manage
	// this means we will receive more packets though
	const SOCKET: Token = Token(0);
	let tx = Socket::new(AF_INET, SOCK_RAW, IPPROTO_RAW)?;
	let rx = Socket::new(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL as u16).into())?;
	let buffer = &mut [0u8; 8192];

	let mut poll = Poll::new()?;
	let mut events = Events::with_capacity(1024);
	poll.registry().register(&mut SourceFd(&rx.fileno()), SOCKET, Interest::READABLE)?;

	let mut scanner = Scanner::new();
	let mut time = Instant::now();
	let mut wait = false;

	// First loop
	// send scanning probes while handling responses as they come
	// it ends when all probes were sent
	loop {
		if time.elapsed() > DELAY || !wait {
			if let Some(packet) = probes.next() {
				tx.sendto(&packet.data, 0, &packet.destination)?;
				scanner.add(packet);
			} else {
				break ;
			}
			time = Instant::now();
			wait = true; // avoid needlessly waiting DELAY for the first probe
		}

		let delay = DELAY - time.elapsed();
		poll.poll(&mut events, Some(delay))?;

		for ev in events.iter() {
			if ev.is_readable() {
				let bytes = rx.recv_into(buffer, 0)?;
				let packet = &buffer[..bytes];
				scanner.update(packet);
			}
		}
	}

	// Second loop
	// here we just wait for the last responses
	// ends when we caught'em all
	// or if they're all timed out
	while !scanner.is_complete() {
		poll.poll(&mut events, Some(DELAY))?;

		for ev in events.iter() {
			if ev.is_readable() {
				let bytes = rx.recv_into(buffer, 0)?;
				let packet = &buffer[..bytes];
				scanner.update(packet);
			}
		}	
	}

	scanner.print();

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
