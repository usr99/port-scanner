use std::io::{BufRead, BufReader};
use std::iter::Peekable;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::vec::IntoIter;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{MutableIpv4Packet, checksum};
use pnet::packet::tcp::{MutableTcpPacket, ipv4_checksum as tcp_checksum};
use pnet::packet::udp::{MutableUdpPacket, ipv4_checksum as udp_checksum};
use anyhow::{Result, Context, anyhow};
use rand::Rng;

use crate::cli;
use crate::iterators::{ArgIterator, PortRange, ScanType};

// enum ProbeStatus {
// 	Waiting(time::Instant),
// 	Open,
// 	Closed,
// 	Filtered,
// 	Timeout
// }

/*
** ProbeReport
	** implemented as HashMap<String, HashMap<u16, ProbeStatus>>
	** might be encapsulated in a struct for easier access
*/
#[derive(Debug)]
pub struct ProbeBuilder {
	hosts: Peekable<IntoIter<Ipv4Addr>>,
	ports: Peekable<ArgIterator<PortRange>>,
	scans: Peekable<ArgIterator<ScanType>>,
	source_addr: Ipv4Addr,
	source_port: u16,
	tcp_seq: u32
}

impl ProbeBuilder {
	pub fn new(mut options: cli::Args, source: Ipv4Addr) -> Result<Self> {
		/* Load ip addresses from file */
		if let Some(path) = &options.ip_file {
			let file = std::fs::File::open(path.trim()).with_context(|| format!("Cannot read \"{}\"", path))?;
			let buffer = BufReader::new(file);

			for line in buffer.lines() {
				let line = line?;
				if line.len() > 0 {
					options.ip.push(line);
				}
			}
		}

		/* Turn string representation into actual IPv4 addresses */
		let mut hosts: Vec<Ipv4Addr> = vec![];
		for addr in options.ip.into_iter() {
			match dns_lookup::lookup_host(addr.trim()) {
				Ok(array) => {
					match array.iter().filter(|addr| addr.is_ipv4()).next() {
						Some(IpAddr::V4(ip)) => hosts.push(*ip),
						_ => eprintln!("\"{addr}\": failed to resolve hostname")
					}
				},
				Err(e) => eprintln!("\"{addr}\": {e}")
			};
		}

		if hosts.len() == 0 {
			return Err(anyhow!("No valid target to scan"));
		}
		hosts.sort();
		hosts.dedup();

		/* Construct builder instance */
		Ok(Self {
			hosts: hosts.into_iter().peekable(),
			ports: options.ports.peekable(),
			scans: options.scans.peekable(),
			source_addr: source,
			source_port: rand::thread_rng().gen_range(1025..=u16::MAX),
			tcp_seq: rand::random()
		})
	}
}

pub struct Probe {
	pub data: [u8; 40],
	pub destination: SocketAddr,
	pub source_port: u16,
	pub scan: ScanType
}

impl Iterator for ProbeBuilder {
	type Item = Probe;

	fn next(&mut self) -> Option<Self::Item> {
		let scan;
		let port;
		let host;
		if let Some(s) = self.scans.next() {
			scan = s;
			port = *self.ports.peek().unwrap();
			host = *self.hosts.peek().unwrap();
		} else {
			scan = self.scans.next().unwrap();
			self.ports.next();
			if let Some(p) = self.ports.peek() {
				port = *p;
				host = *self.hosts.peek().unwrap();
			} else {
				self.ports.next();
				port = *self.ports.peek().unwrap();
				self.hosts.next();
				if let Some(h) = self.hosts.peek() {
					host = *h;
				} else {
					return None;
				}
			}
		}

		let packet = &mut [0u8; 40];
		let mut ip = MutableIpv4Packet::new(packet).unwrap();
		ip.set_version(4);
		ip.set_source(self.source_addr);
		ip.set_destination(host);
		ip.set_header_length(5);
		ip.set_ttl(64);

		let next_protocol_header = &mut [0u8; 20];
		match scan {
			ScanType::UDP => {
				let mut udp = MutableUdpPacket::new(next_protocol_header).unwrap();
				udp.set_source(self.source_port);
				udp.set_destination(port);
				udp.set_length(8);

				ip.set_total_length(28);
				ip.set_next_level_protocol(IpNextHeaderProtocols::Udp);
				udp.set_checksum(udp_checksum(&udp.to_immutable(), &self.source_addr, &host));
				ip.set_payload(&next_protocol_header[0..8]);
			},
			_ => {
				let mut tcp = MutableTcpPacket::new(next_protocol_header).unwrap();
				tcp.set_source(self.source_port);
				tcp.set_destination(port);
				tcp.set_data_offset(5);
				tcp.set_sequence(self.tcp_seq);
				tcp.set_flags(u16::try_from(scan).unwrap());
				
				ip.set_total_length(40);
				ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
				tcp.set_checksum(tcp_checksum(&tcp.to_immutable(), &self.source_addr, &host));
				ip.set_payload(next_protocol_header);
			}
		};
		ip.set_checksum(checksum(&ip.to_immutable()));

		Some(Probe {
			data: *packet,
			destination: (host, port).into(),
			source_port: self.source_port,
			scan
		})
	}
}

#[cfg(test)]
use assert_fs::prelude::*;
#[cfg(test)]
use clap::Parser;
#[cfg(test)]
use pnet::packet::Packet;
#[cfg(test)]
use pnet::packet::{ipv4::Ipv4Packet, tcp::TcpPacket};

#[test]
fn probe_builder_hosts_iter() -> Result<(), Box<dyn std::error::Error>> {
	const CONTENT: &str = "\t127.0.0.1\n  192.168.1.22\n\n10.13.250.188\n";
	let tmp = assert_fs::NamedTempFile::new("ip.tmp")?;
	tmp.write_str(CONTENT)?;
	
	let hosts = format!("-f {}", tmp.path().to_str().unwrap());
	let arguments = vec![clap::crate_name!(), "-i dns.google", "-s SYN", "-p80", hosts.as_str()];
	let builder = ProbeBuilder::new(cli::Args::try_parse_from(arguments).unwrap(), [127, 0, 0, 1].into())?;
	let probes: Vec<_> = builder.collect();
	
	let google_dns = Ipv4Packet::new(&probes[0].data).unwrap().get_destination();
	if google_dns != Ipv4Addr::new(8, 8, 8, 8) && google_dns != Ipv4Addr::new(8, 8, 4, 4){
		assert!(false, "dns.google should resolve to 8.8.8.8 or 8.8.4.4");
	}
	
	// Host addresses were sorted when parsing IP file
	assert_eq!(Ipv4Packet::new(&probes[1].data).unwrap().get_destination(), Ipv4Addr::new(10, 13, 250, 188));
	assert_eq!(Ipv4Packet::new(&probes[2].data).unwrap().get_destination(), Ipv4Addr::new(127, 0, 0, 1));
	assert_eq!(Ipv4Packet::new(&probes[3].data).unwrap().get_destination(), Ipv4Addr::new(192, 168, 1, 22));
	Ok(())
}


#[test]
fn probe_builder_ports_iter() -> Result<(), Box<dyn std::error::Error>> {
	let arguments = vec![clap::crate_name!(), "-i dns.google", "-s SYN", "-p80,443,1024-1026"];
	let builder = ProbeBuilder::new(cli::Args::try_parse_from(arguments).unwrap(), [127, 0, 0, 1].into())?;
	let probes: Vec<_> = builder.collect();
	
	assert_eq!(TcpPacket::new(Ipv4Packet::new(&probes[0].data).unwrap().payload()).unwrap().get_destination(), 80);
	assert_eq!(TcpPacket::new(Ipv4Packet::new(&probes[1].data).unwrap().payload()).unwrap().get_destination(), 443);
	assert_eq!(TcpPacket::new(Ipv4Packet::new(&probes[2].data).unwrap().payload()).unwrap().get_destination(), 1024);
	assert_eq!(TcpPacket::new(Ipv4Packet::new(&probes[3].data).unwrap().payload()).unwrap().get_destination(), 1025);
	assert_eq!(TcpPacket::new(Ipv4Packet::new(&probes[4].data).unwrap().payload()).unwrap().get_destination(), 1026);
	Ok(())
}


#[test]
fn probe_builder_scans_iter() -> Result<(), Box<dyn std::error::Error>> {
	let arguments = vec![clap::crate_name!(), "-i 127.0.0.1", "-p80"];
	let builder = ProbeBuilder::new(cli::Args::try_parse_from(arguments).unwrap(), [127, 0, 0, 1].into())?;
	let probes: Vec<_> = builder.collect();
	
	assert_eq!(TcpPacket::new(Ipv4Packet::new(&probes[0].data).unwrap().payload()).unwrap().get_flags(), u16::try_from(ScanType::SYN).unwrap());
	assert_eq!(TcpPacket::new(Ipv4Packet::new(&probes[1].data).unwrap().payload()).unwrap().get_flags(), u16::try_from(ScanType::NULL).unwrap());
	assert_eq!(TcpPacket::new(Ipv4Packet::new(&probes[2].data).unwrap().payload()).unwrap().get_flags(), u16::try_from(ScanType::ACK).unwrap());
	assert_eq!(TcpPacket::new(Ipv4Packet::new(&probes[3].data).unwrap().payload()).unwrap().get_flags(), u16::try_from(ScanType::FIN).unwrap());
	assert_eq!(TcpPacket::new(Ipv4Packet::new(&probes[4].data).unwrap().payload()).unwrap().get_flags(), u16::try_from(ScanType::XMAS).unwrap());
	assert_eq!(Ipv4Packet::new(&probes[5].data).unwrap().get_next_level_protocol(), IpNextHeaderProtocols::Udp);
	
	Ok(())	
}


#[test]
fn probe_builder_file_error() -> Result<(), Box<dyn std::error::Error>> {
	let arguments = vec![clap::crate_name!(), "-f non_existing_file.txt"];
	if let Ok(_) = ProbeBuilder::new(cli::Args::try_parse_from(arguments).unwrap(), [127, 0, 0, 1].into()) {
		assert!(false, "must complain about file existence");
	}
	
	Ok(())
}


#[test]
fn probe_builder_no_ip() -> Result<(), Box<dyn std::error::Error>> {
	const CONTENT: &str = "\t127.0.ff.1\n non.existing.domain\n\nHello, World!\n";
	let tmp = assert_fs::NamedTempFile::new("ip.tmp")?;
	tmp.write_str(CONTENT)?;
	
	let hosts = format!("-f {}", tmp.path().to_str().unwrap());
	let arguments = vec![clap::crate_name!(), "-i foobar", hosts.as_str()];
	
	if let Ok(_) = ProbeBuilder::new(cli::Args::try_parse_from(arguments).unwrap(), [127, 0, 0, 1].into()) {
		assert!(false, "must complain about not having addresses to scan");
	}
	
	Ok(())
}
