use std::fmt::{self, Display};

#[derive(Clone, Debug)]
pub struct Array<T: Display>(Vec<T>);

impl<T: Display> Array<T>
{
	pub fn inner(&self) -> &Vec<T> {
		&self.0
	}

	pub fn inner_as_mut(&mut self) -> &mut Vec<T> {
		&mut self.0
	}
}

impl<T: Display> fmt::Display for Array<T> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		self.inner().iter().fold(Ok(()), |result, x| {
			result.and_then(|_| write!(f, "{}", x))
		})
	}
}
