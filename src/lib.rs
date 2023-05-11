pub mod cli;
pub mod iterators;
pub mod probes;

use std::time::Duration;
use pnet::packet::icmp::IcmpCode;
use pnet::packet::icmp::destination_unreachable::IcmpCodes;

const ACCEPTED_ICMP_CODES: [IcmpCode; 6] = [
	IcmpCodes::DestinationHostUnreachable,
	IcmpCodes::DestinationProtocolUnreachable,
	IcmpCodes::DestinationPortUnreachable,
	IcmpCodes::NetworkAdministrativelyProhibited,
	IcmpCodes::HostAdministrativelyProhibited,
	IcmpCodes::CommunicationAdministrativelyProhibited
];

const DEFAULT_TIMEOUT: Duration = Duration::from_millis(200);
pub const DELAY: Duration = Duration::from_millis(1);
pub const SCAN_NUM: u16 = 6;
