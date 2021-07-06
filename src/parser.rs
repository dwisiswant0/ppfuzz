use {
	atty::Stream,
	clap::{
		App,
		crate_authors,
		crate_description,
		crate_name,
		crate_version,
		load_yaml,
	},
	std::{
		io::{self, BufRead},
		process,
	},
};

use crate::{errors, reader};

pub struct Options {
	pub list: Option<String>,
	pub timeout: u64,
	pub concurrency: usize,
}

impl Options {
	pub fn get() -> Self {
		let yaml = load_yaml!("cli.yaml");
		let usage = format!(
			"{0} -l {1} {2}\n    cat {1} | {0} {2}",
			crate_name!(), "FILE", "[OPTIONS]"
		);
		let app = App::from(yaml)
			.author(crate_authors!())
			.about(crate_description!())
			.name(crate_name!())
			.version(crate_version!())
			.override_usage(&*usage);
		let matches = app.get_matches();

		Self {
			list: Some(
				matches
					.value_of("list")
					.unwrap_or("").to_owned()
				),
			timeout: matches
				.value_of_t("timeout")
				.unwrap_or(30),
			concurrency: matches
				.value_of_t("concurrency")
				.unwrap_or(15)
		}
	}

	pub fn urls(&mut self) -> Vec<String> {
		let mut urls: Vec<String> = vec![];

		if self.list == Some("".to_string()) {
			if atty::isnt(Stream::Stdin) {
				let stdin = io::stdin();
				urls.extend(stdin.lock().lines().map(|l| l.unwrap()))
			} else {
				errors::show("No input target provided!".to_string());
				process::exit(1)
			}
		} else {
			urls.extend(reader::from_file(self.list.as_ref().unwrap()))
		}

		urls
	}
}