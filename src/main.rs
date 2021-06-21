mod builder;
mod reader;

use {
	atty::Stream,
	chromiumoxide::browser::{Browser, BrowserConfig},
	clap::{App, load_yaml},
	std::{
		io::{self, BufRead},
		process
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

	let mut coll: Vec<String> = vec![String::new(); 0];
	for url in urls {
		if url.starts_with("http") {
			coll.extend(builder::query(url))
		}
	}

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

	let check = "(window.ppfuzz || Object.prototype.ppfuzz) == 'reserved' && true || false";
	for c in coll {
		let page = browser.new_page(&c).await.unwrap();
		let vuln: bool = page.evaluate(check)
			.await
			.unwrap()
			.into_value()
			.unwrap();

		if vuln {
			println!("[{}] {}", "VULN".green(), c)
		}
	}
}