use std::io::{BufRead, BufReader};
use std::iter::Peekable;
// use std::time;
use std::net::{IpAddr, Ipv4Addr};
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
pub struct ProbeBuilder {
	hosts: Peekable<IntoIter<Ipv4Addr>>,
	ports: Peekable<ArgIterator<PortRange>>,
	scans: Peekable<ArgIterator<ScanType>>,
	source_addr: Ipv4Addr,
	source_port: u16,
	tcp_seq: u32
}

impl ProbeBuilder {
	pub fn new(mut options: cli::Args) -> Result<Self> {
		/* Load ip addresses from file */
		if let Some(path) = &options.ip_file {
			let file = std::fs::File::open(path).with_context(|| format!("Cannot read \"{}\"", path.display()))?;
			let buffer = BufReader::new(file);

			for line in buffer.lines() {
				options.ip.push(line?);
			}
		}
;
		/* Turn string representation into actual IPv4 addresses */
		let mut hosts: Vec<Ipv4Addr> = vec![];
		for addr in options.ip.into_iter() {
			match dns_lookup::lookup_host(&addr) {
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

		/* Find source IP address (needed to compute checksums) */
		let interfaces = pnet::datalink::interfaces();
		let device = match interfaces.iter()
			.find(|i| i.is_up() && !i.is_loopback() && !i.ips.is_empty()) {
				Some(dev) => dev,
				None => return Err(anyhow!("No source address found"))
		};
		
		let source_addr = match device.ips.iter().filter(|ip| ip.is_ipv4()).map(|ipnet| ipnet.ip()).next() {
			Some(IpAddr::V4(ip)) => ip,
			_ => return Err(anyhow!("No IPv4 source address found"))
		};

		/* Construct builder instance */
		Ok(Self {
			hosts: hosts.into_iter().peekable(),
			ports: options.ports.peekable(),
			scans: options.scans.peekable(),
			source_addr,
			source_port: rand::thread_rng().gen_range(1025..=u16::MAX),
			tcp_seq: rand::random()
		})
	}

	pub fn destination(&mut self) -> (Ipv4Addr, u16) {
		(*self.hosts.peek().unwrap(), *self.ports.peek().unwrap())
	}
}

impl Iterator for ProbeBuilder {
	type Item = [u8; 40];

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
				port = self.ports.next().unwrap();
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
			}
		};
		ip.set_payload(next_protocol_header);
		ip.set_checksum(checksum(&ip.to_immutable()));

		Some(*packet)
	}
}

#[test]
fn probe_builder_hosts_iter() {}

#[test]
fn probe_builder_ports_iter() {}

#[test]
fn probe_builder_scans_iter() {}

#[test]
fn probe_builder_file_error() {}

#[test]
fn probe_builder_ip_format_error() {}

#[test]
fn probe_builder_no_ip() {}

#[test]
fn probe_builder_network_interface_error() {
	// would need to mock pnet::datalink::interfaces()
}
