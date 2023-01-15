use clap::Parser;
use std::fmt::Display;

use super::port::{Range, RangeParser};
use super::scan::{Scan, ScanParser};

#[derive(Parser, Debug)]
#[clap(author, version, about)]
#[command(arg_required_else_help(true))]
pub struct Args {

	/// Ip address to scan
	#[arg(short, long)]
	pub ip: Vec<String>,

	/// Range of ports to scan
	#[arg(short, long, default_value_t = ArgIterator::<Range>::default(), value_parser = RangeParser)]
	pub ports: ArgIterator<Range>,

	/// Scan types
	#[arg(short, long, default_value_t = ArgIterator::<Scan>::default(), value_parser = ScanParser)]
	pub scans: ArgIterator<Scan>,

	/// File that contains ip addresses to scan
	#[arg(short = 'f', long = "file")]
	pub ip_file: Option<std::path::PathBuf>,

	/// Number of scans to run concurrently
	#[arg(short, long, default_value_t = 1)]
	pub threads: u8
}


#[derive(Clone, Debug)]
pub struct ArgIterator<T: Display> (pub Vec<T>);

impl<T: Display> ArgIterator<T>
{
	pub fn new() -> Self {
		Self (vec![])
	}

	pub fn inner(&self) -> &Vec<T> {
		&self.0
	}

	pub fn inner_as_mut(&mut self) -> &mut Vec<T> {
		&mut self.0
	}
}

impl ArgIterator<Range> {	
	pub fn default() -> Self {
		Self (vec![Range::new(1, 1024)])
	}
}

impl std::fmt::Display for ArgIterator<Range> {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		self.inner().iter().fold(Ok(()), |result, range| {
			result.and_then(|_| write!(f, "{}", range))
		})
	}	
}

impl Iterator for ArgIterator<Range> {
	type Item = u16;

	fn next(&mut self) -> Option<Self::Item> {
		let range = match self.inner_as_mut().last_mut() {
			Some(r) => r,
			None => return None
		};

		match range.next() {
			Some(port) => Some(port),
			None => {
				self.inner_as_mut().pop();
				self.next()
			}
		}
	}
}

impl ArgIterator<Scan> {
	pub fn default() -> Self {
		Self (vec![Scan::SYN, Scan::NULL, Scan::ACK, Scan::FIN, Scan::XMAS, Scan::UDP])
	}
}

impl std::fmt::Display for ArgIterator<Scan> {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		self.inner().iter().fold(Ok(()), |result, scan| {
			result.and_then(|_| write!(f, "{}{}", scan, match scan {
				Scan::UDP => "",
				_ => ",",
			}))
		})
	}
}

impl Iterator for ArgIterator<Scan> {
	type Item = Scan;

	fn next(&mut self) -> Option<Self::Item> {
		self.inner_as_mut().pop()
	}
}
