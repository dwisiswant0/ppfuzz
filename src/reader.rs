use {
	std::{
		fs::File,
		io::{prelude::*, BufReader},
		path::Path,
		process,
	},
	colored::*,
};

pub fn from_file(filepath: impl AsRef<Path>) -> Vec<String> {
	let filepath = filepath.as_ref();
	let open = match File::open(filepath) {
		Ok(file) => file,
		Err(err) => {
			let msg = format!("Open '{}': {}.", filepath.display(), err);
			eprintln!("{}", msg.red());
			process::exit(1);
		}
	};
	let buf = BufReader::new(open);

	buf.lines().map(|l| l.expect("Couldn't parse lines")).collect()
}