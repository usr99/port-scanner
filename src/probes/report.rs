use std::collections::HashMap;
use std::fmt::Display;
use std::net::SocketAddr;
use std::time::{Instant, Duration};

use pnet::packet::icmp::destination_unreachable::IcmpCodes;
use pnet::packet::icmp::{IcmpTypes, IcmpCode};
use pnet::packet::tcp::TcpFlags;

use num_enum::IntoPrimitive;

use crate::iterators::ScanType;
use super::Probe;
use super::response::{Response, ResponseKind};

#[derive(IntoPrimitive, PartialEq, PartialOrd)]
#[repr(u8)]
enum PortStatus {
	Unknown,
	Filtered,
	Unfiltered,
	Closed,
	OpenOrFiltered,
	Open
}

const ACCEPTED_ICMP_CODES: [IcmpCode; 6] = [
	IcmpCodes::DestinationHostUnreachable,
	IcmpCodes::DestinationProtocolUnreachable,
	IcmpCodes::DestinationPortUnreachable,
	IcmpCodes::NetworkAdministrativelyProhibited,
	IcmpCodes::HostAdministrativelyProhibited,
	IcmpCodes::CommunicationAdministrativelyProhibited
];

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

impl From<(ResponseKind, ScanType)> for PortStatus {
	fn from(value: (ResponseKind, ScanType)) -> Self {
		match value.1 {
			ScanType::SYN => {
				match value.0 {
					ResponseKind::Tcp(flags) => {
						if flags & TcpFlags::RST != 0 {
							PortStatus::Closed
						} else if flags & TcpFlags::SYN != 0 && flags & TcpFlags::SYN != 0 {
							PortStatus::Open
						} else {
							PortStatus::Unknown
						}
					},
					ResponseKind::Icmp(IcmpTypes::DestinationUnreachable, code) => {
						if ACCEPTED_ICMP_CODES.contains(&code) {
							PortStatus::Filtered
						} else {
							PortStatus::Unknown
						}
					},
					ResponseKind::NoResponse => PortStatus::Filtered,
					_ => PortStatus::Unknown
				}
			},
			ScanType::ACK => {
				match value.0 {
					ResponseKind::Tcp(flags) => {
						if flags & TcpFlags::RST != 0 {
							PortStatus::Unfiltered
						} else {
							PortStatus::Unknown
						}
					},
					ResponseKind::Icmp(IcmpTypes::DestinationUnreachable, code) => {
						if ACCEPTED_ICMP_CODES.contains(&code) {
							PortStatus::Filtered
						} else {
							PortStatus::Unknown
						}
					}
					ResponseKind::NoResponse => PortStatus::Filtered,
					_ => PortStatus::Unknown
				}
			},
			ScanType::UDP => {
				match value.0 {
					ResponseKind::Udp => PortStatus::Open,
					ResponseKind::Icmp(IcmpTypes::DestinationUnreachable, code) => {
						if ACCEPTED_ICMP_CODES.contains(&code) {
							match code {
								IcmpCodes::DestinationPortUnreachable => PortStatus::Closed,
								_ => PortStatus::Filtered
							}
						} else {
							PortStatus::Unknown
						}
					},
					ResponseKind::NoResponse => PortStatus::OpenOrFiltered,
					_ => PortStatus::Unknown
				}
			},
			_ => { // NULL, FIN or XMAS
				match value.0 {
					ResponseKind::Tcp(flags) => {
						if flags & TcpFlags::RST != 0 {
							PortStatus::Closed
						} else {
							PortStatus::Unknown
						}
					},
					ResponseKind::Icmp(IcmpTypes::DestinationUnreachable, code) => {
						if ACCEPTED_ICMP_CODES.contains(&code) {
							PortStatus::Filtered
						} else {
							PortStatus::Unknown
						}
					},
					ResponseKind::NoResponse => PortStatus::OpenOrFiltered,
					_ => PortStatus::Unknown
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
			PortStatus::Filtered => "filtered",
			PortStatus::Unknown => "unknown"
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
				let mut report = Report {
					status: PortStatus::Unknown,
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

		let scan = probe.1;
		let status = PortStatus::from((response.kind, scan));
		
		// If the response does not give any information
		// about the port status, we keep waiting for new responses
		if let PortStatus::Unknown = status {
			return ;
		}
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
						// all timedout probes should be updated as ResponseKind::NoResponse ===================================================================
						// implement tryfrom instead of from for PortStatus
						probe.0 = ProbeStatus::TimedOut;
						let status = PortStatus::from((ResponseKind::NoResponse, probe.1));
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

		// iter through all reports
			// sort same hosts together
		
		// sort each host by port
		// iter though everything
			// print PortStatus
	}
}

// PortStatus::TryFrom
	// remove PortStatus::Unknown
// Source port only changes for retransmission
// Function to update status
// test if all scans work
// nice print function
