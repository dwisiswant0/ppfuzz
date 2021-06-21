use std::{
	fs::File,
	io::{prelude::*, BufReader},
	path::Path,
    process,
};

pub fn from_file(filepath: impl AsRef<Path> + std::fmt::Display + Copy) -> Vec<String> {
    let open = match File::open(filepath) {
        Ok(file) => file,
        Err(err) => {
            eprintln!("Open '{}': {}", filepath, err);
            process::exit(1);
        }
    };
	let buf = BufReader::new(open);

	buf.lines().map(|l| l.expect("Couldn't parse lines")).collect()
}