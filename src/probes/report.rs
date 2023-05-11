use std::collections::HashMap;
use std::fmt::Display;
use std::net::SocketAddr;
use std::time::Instant;

use pnet::packet::icmp::destination_unreachable::IcmpCodes;
use pnet::packet::icmp::{IcmpTypes};
use pnet::packet::tcp::TcpFlags;

use num_enum::IntoPrimitive;

use crate::iterators::ScanType;
use super::Probe;
use super::response::{Response, ResponseKind};
use crate::{ACCEPTED_ICMP_CODES, DEFAULT_TIMEOUT};

#[derive(IntoPrimitive, PartialEq, PartialOrd)]
#[repr(u8)]
enum PortStatus {
	Filtered,
	Unfiltered,
	OpenOrFiltered,
	Closed,
	Open
}

impl TryFrom<(ResponseKind, ScanType)> for PortStatus {
	type Error = ();
	
	fn try_from(value: (ResponseKind, ScanType)) -> Result<Self, Self::Error> {
		match value.1 {
			ScanType::SYN => {
				match value.0 {
					ResponseKind::Tcp(flags) => {
						if flags & TcpFlags::RST != 0 {
							Ok(Self::Closed)
						} else if flags & TcpFlags::SYN != 0 && flags & TcpFlags::SYN != 0 {
							Ok(Self::Open)
						} else {
							Err(())
						}
					},
					ResponseKind::Icmp(IcmpTypes::DestinationUnreachable, code) => {
						if ACCEPTED_ICMP_CODES.contains(&code) {
							Ok(Self::Filtered)
						} else {
							Err(())
						}
					},
					ResponseKind::NoResponse => Ok(Self::Filtered),
					_ => Err(())
				}
			},
			ScanType::ACK => {
				match value.0 {
					ResponseKind::Tcp(flags) => {
						if flags & TcpFlags::RST != 0 {
							Ok(Self::Unfiltered)
						} else {
							Err(())
						}
					},
					ResponseKind::Icmp(IcmpTypes::DestinationUnreachable, code) => {
						if ACCEPTED_ICMP_CODES.contains(&code) {
							Ok(Self::Filtered)
						} else {
							Err(())
						}
					}
					ResponseKind::NoResponse => Ok(Self::Filtered),
					_ => Err(())
				}
			},
			ScanType::UDP => {
				match value.0 {
					ResponseKind::Udp => Ok(Self::Open),
					ResponseKind::Icmp(IcmpTypes::DestinationUnreachable, code) => {
						if ACCEPTED_ICMP_CODES.contains(&code) {
							match code {
								IcmpCodes::DestinationPortUnreachable => Ok(Self::Closed),
								_ => Ok(Self::Filtered)
							}
						} else {
							Err(())
						}
					},
					ResponseKind::NoResponse => Ok(Self::OpenOrFiltered),
					_ => Err(())
				}
			},
			_ => { // NULL, FIN or XMAS
				match value.0 {
					ResponseKind::Tcp(flags) => {
						if flags & TcpFlags::RST != 0 {
							Ok(Self::Closed)
						} else {
							Err(())
						}
					},
					ResponseKind::Icmp(IcmpTypes::DestinationUnreachable, code) => {
						if ACCEPTED_ICMP_CODES.contains(&code) {
							Ok(Self::Filtered)
						} else {
							Err(())
						}
					},
					ResponseKind::NoResponse => Ok(Self::OpenOrFiltered),
					_ => Err(())
				}
			}
		}
	}		
}

impl Display for PortStatus {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "{}", match self {
			PortStatus::Open => "open",
			PortStatus::OpenOrFiltered => "open | filtered",
			PortStatus::Closed => "closed",
			PortStatus::Unfiltered => "unfiltered",
			PortStatus::Filtered => "filtered"
		})
	}
}

enum ProbeStatus {
	Waiting(Instant),
	TimedOut,
	Done
}

struct Report {
	status: PortStatus,
	probes: HashMap<u16, (ProbeStatus, ScanType)>
}

pub struct Scanner {
	inner: HashMap<SocketAddr, Report>
}

impl Scanner {
	pub fn new() -> Self {
		Self { inner: HashMap::new() }
	}

	pub fn add(&mut self, packet: Probe) {
		match self.inner.get_mut(&packet.destination) {
			Some(report) => {
				report.probes.insert(packet.source_port, (ProbeStatus::Waiting(Instant::now()), packet.scan));
			},
			None => {
				// Default status is "Filtered" because
				// it has the least priority so it will be overwritten by any other value
				let mut report = Report {
					status: PortStatus::Filtered,
					probes: HashMap::new()
				};
				report.probes.insert(packet.source_port, (ProbeStatus::Waiting(Instant::now()), packet.scan));
				
				self.inner.insert(packet.destination, report);
			}
		};
	}

	pub fn update(&mut self, packet: &[u8]) {
		let response = match Response::try_from(packet) {
			Ok(r) => r,
			Err(_) => return
		};

		let report = match self.inner.get_mut(&response.origin) {
			Some(r) => r,
			None => return
		};

		let probe = match report.probes.get_mut(&response.probe_id) {
			Some(p) => p,
			None => return
		};
		
		// If the response does not give any information
		// about the port status, we keep waiting for new responses
		let scan = probe.1;
		let status = match PortStatus::try_from((response.kind, scan)) {
			Ok(st) => st,
			Err(_) => return
		};
		probe.0 = ProbeStatus::Done;

		// Port status can be represented as u8
		// they're ranked from least to most accurate
		if report.status < status {
			report.status = status;
		}
	}

	pub fn is_complete(&mut self) -> bool {
		let mut complete = true;

		for report in self.inner.values_mut() {
			for probe in report.probes.values_mut() {
				if let ProbeStatus::Waiting(time) = probe.0 {
					if time.elapsed() > DEFAULT_TIMEOUT {
						probe.0 = ProbeStatus::TimedOut;
						let status = PortStatus::try_from((ResponseKind::NoResponse, probe.1)).unwrap();
						if report.status < status {
							report.status = status;
						}
					} else {
						complete = false;
					}
				}
			}
		}

		complete
	}

	pub fn print(self) {
		for report in self.inner.iter() {
			println!("{} is {}", report.0, report.1.status);
		}
	}
}
