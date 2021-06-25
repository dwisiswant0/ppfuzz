mod builder;
mod reader;
mod ppfuzz;

use {
	atty::Stream,
	chromiumoxide::browser::{Browser, BrowserConfig},
	clap::{App, load_yaml},
	std::{
		io::{self, BufRead},
		process,
		time::Duration
	},
	colored::*,
	futures::StreamExt
};

#[async_std::main]
async fn main() {
	let yaml = load_yaml!("cli.yaml");
	let matches = App::from(yaml).get_matches();
	let list = matches.value_of("list");
	let timeout: u64 = matches.value_of_t("timeout").unwrap_or(30);
	let concurrency: usize = matches.value_of_t("concurrency").unwrap_or(5);
	let mut urls: Vec<String> = vec![];

	if list.is_none() {
		if atty::isnt(Stream::Stdin) {
			let stdin = io::stdin();
			urls.extend(stdin.lock().lines().map(|l| l.unwrap()))
		} else {
			eprintln!("{}", "No input target provided!".red());
			process::exit(1)
		}
	} else {
		urls.extend(reader::from_file(list.unwrap()))
	}

	let coll: Vec<_> = urls
		.into_iter()
		.filter(|url| url
			.starts_with("http"))
		.flat_map(|url| builder::query(url))
		.collect();

	let (browser, mut handler) = Browser::launch(
		BrowserConfig::builder()
			.request_timeout(Duration::from_secs(timeout))
			.build()
			.unwrap()
		)
		.await
		.unwrap();

	let _handle = async_std::task::spawn(async move {
		loop {
			let _ = handler.next().await.unwrap();
		}
	});

	ppfuzz::check(coll, browser, concurrency).await;
}