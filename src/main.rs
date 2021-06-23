mod builder;
mod reader;

use {
	atty::Stream,
	chromiumoxide::browser::{Browser, BrowserConfig},
	clap::{App, load_yaml},
	std::{
		io::{self, BufRead},
		process,
		sync::Arc
	},
	colored::*,
	futures::StreamExt
};

#[async_std::main]
async fn main() {
	let yaml = load_yaml!("cli.yaml");
	let matches = App::from(yaml).get_matches();
	let list = matches.value_of("list");
	let mut urls: Vec<String> = vec![String::new(); 0];

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

	let browser = Arc::new(browser);
	let check = "(window.ppfuzz || Object.prototype.ppfuzz) == 'reserved' && true || false";
	let mut stream = futures::stream::iter(coll.into_iter().map(|url| (url, Arc::clone(&browser))).map(|(url, browser)| async move {
		let page = browser.new_page(&url).await.unwrap();
		let vuln: bool = page.evaluate(check)
			.await
			.unwrap()
			.into_value()
			.unwrap();

		Ok::<_, Box<dyn std::error::Error>>((url, vuln, page))
	})).buffered(25);

	while let Some(res) = stream.next().await {
		if let Ok((ref url, vuln, page)) = res {
			if vuln {
				println!("[{}] {}", "VULN".green(), url)
			} else {
				eprintln!("[{}] {}", "ERRO".red(), url)
			}

			page.close().await.unwrap();
		}
	}
}