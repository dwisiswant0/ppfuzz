use std::{
	fs::File,
	io::{prelude::*, BufReader},
	path::Path, process
};

use crate::errors;

pub fn from_file(filepath: impl AsRef<Path>) -> Vec<String> {
	let filepath = filepath.as_ref();
	let open = match File::open(filepath) {
		Ok(file) => file,
		Err(err) => {
			errors::show(format!("Open '{}': {}.", filepath.display(), err));
			process::exit(1)
		}
	};
	let buf = BufReader::new(open);

	buf.lines().map(|l| l.unwrap_or_else(|err| {
		errors::show(format!("Open '{}': {}.", filepath.display(), err));
		process::exit(1)
	})).collect()
}