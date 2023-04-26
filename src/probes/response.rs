use anyhow::{Result, anyhow};
use std::{
	net::SocketAddr,
	time::Instant
};
use pnet::packet::{
	Packet,
	icmp::{IcmpType, IcmpCode, IcmpPacket},
	ipv4::Ipv4Packet,
	ip::IpNextHeaderProtocols,
	tcp::{TcpPacket, TcpFlags},
	udp::UdpPacket, ethernet::EthernetPacket
};

#[derive(Debug)]
pub struct Response {
	pub origin: SocketAddr,
	pub probe_id: u16,
	pub kind: ResponseKind,
	pub time: Instant
}

#[derive(Debug)]
pub enum ResponseKind {
	NoResponse, // unused, yet ?
	Tcp(u16),
	Icmp(IcmpType, IcmpCode),
	Udp
}

struct NextHeaderInfo {
	protocol: ResponseKind,
	destination: u16,
	source: u16
}

fn fetch_next_header_info(ip: &Ipv4Packet) -> Result<NextHeaderInfo> {
	let next = ip.payload();

	let info = match ip.get_next_level_protocol() {
		IpNextHeaderProtocols::Tcp => {
			let tcp = TcpPacket::new(next).ok_or(anyhow!("Packet too small."))?;

			(
				ResponseKind::Tcp(tcp.get_flags()),
				tcp.get_destination(),
				tcp.get_source()
			)
		},
		IpNextHeaderProtocols::Udp => {
			let udp = UdpPacket::new(next).ok_or(anyhow!("Packet too small."))?;

			(
				ResponseKind::Udp,
				udp.get_destination(),
				udp.get_source()
			)
		},
		IpNextHeaderProtocols::Icmp => {
			let icmp = IcmpPacket::new(next).ok_or(anyhow!("Packet too small."))?;
			let ip = Ipv4Packet::new(icmp.payload()).ok_or(anyhow!("Packet too small."))?;
			let origin_info = fetch_next_header_info(&ip)?;

			(
				ResponseKind::Icmp(icmp.get_icmp_type(), icmp.get_icmp_code()),
				// This is inverted here because ICMP payload contains
				// the original probe we sent earlier
				origin_info.source,
				origin_info.destination,
			)
		},
		_ => return Err(anyhow!("Unsupported protocol."))
	};

	Ok(NextHeaderInfo {
		protocol: info.0,
		destination: info.1,
		source: info.2
	})
}

impl TryFrom<&[u8]> for Response {
	type Error = anyhow::Error;

	fn try_from(buffer: &[u8]) -> Result<Self, <Self as TryFrom<&[u8]>>::Error> {
		let time = Instant::now();

		let eth = EthernetPacket::new(buffer).ok_or(anyhow!("Packet too small."))?;
		let ip = Ipv4Packet::new(eth.payload()).ok_or(anyhow!("Packet too small."))?;

		// let tcp = TcpPacket::new(ip.payload()).ok_or(anyhow!("Packet too small."))?;
		// println!("{}:{} -> {}:{} {}",
			// ip.get_source(), tcp.get_source(),
			// ip.get_destination(), tcp.get_destination(),
			// match tcp.get_flags() {
				// TcpFlags::SYN => "SYN",
				// TcpFlags::RST => "RST",
				// _ => "SYN, ACK"
			// });

		let info = fetch_next_header_info(&ip)?;

		Ok(Response {
			origin: (ip.get_source(), info.source).into(),
			probe_id: info.destination,
			kind: info.protocol,
			time
		})
	}
}
