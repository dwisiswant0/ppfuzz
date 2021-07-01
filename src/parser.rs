use {
	clap::{
		App,
		crate_authors,
		crate_description,
		crate_name,
		crate_version,
		load_yaml,
	}
};

pub struct Options {
	pub list: Option<String>,
	pub timeout: u64,
	pub concurrency: usize
}

pub fn get() -> Options {
	let yaml = load_yaml!("cli.yaml");
	let usage = format!("{} -l FILE [OPTIONS]", crate_name!());
	let app = App::from(yaml)
		.author(crate_authors!())
		.about(crate_description!())
		.name(crate_name!())
		.version(crate_version!())
		.override_usage(&*usage);
	let matches = app.get_matches();

	Options {
		list: Some(matches.value_of("list").unwrap_or("").to_owned()),
		timeout: matches.value_of_t("timeout").unwrap_or(30),
		concurrency: matches.value_of_t("concurrency").unwrap_or(5)
	}
}