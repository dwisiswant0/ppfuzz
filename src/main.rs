mod builder;
mod reader;
mod ppfuzz;
mod parser;

use {
	atty::Stream,
	chromiumoxide::browser::{Browser, BrowserConfig},
	std::{
		io::{self, BufRead},
		process, time::Duration
	},
	colored::*,
	futures::StreamExt
};

#[async_std::main]
async fn main() {
	let opt = parser::get();
	let mut urls: Vec<String> = vec![];

	if opt.list == Some("".to_string()) {
		if atty::isnt(Stream::Stdin) {
			let stdin = io::stdin();
			urls.extend(stdin.lock().lines().map(|l| l.unwrap()))
		} else {
			eprintln!("{}", "No input target provided!".red());
			process::exit(1)
		}
	} else {
		urls.extend(reader::from_file(opt.list.as_ref().unwrap()))
	}

	let (browser, mut handler) = Browser::launch(
		match BrowserConfig::builder()
			.request_timeout(Duration::from_secs(opt.timeout))
			.build() {
				Ok(res) => res,
				Err(err) => {
					eprintln!("{}.", err.red());
					process::exit(1)
				},
			})
		.await
		.unwrap();

	let _handle = async_std::task::spawn(async move {
		loop {
			let _ = handler.next().await.unwrap();
		}
	});

	ppfuzz::check(urls
		.into_iter()
		.filter(|url| url
			.starts_with("http"))
		.flat_map(builder::query)
		.collect(), browser, opt.concurrency, opt.timeout).await;
}