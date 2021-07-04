use {
	chromiumoxide::Browser,
	colored::*,
	futures::{StreamExt, stream},
	std::sync::Arc,
};

use crate::parser;

static CHECK_SCRIPT: &str = "(window.ppfuzz || Object.prototype.ppfuzz) == 'reserved' && true || false";

pub async fn new(urls: Vec<String>, browser: Browser, opt: parser::Options) {
	let browser = Arc::new(browser);
	let mut stream = stream::iter(urls.into_iter()
		.map(|url| (url, Arc::clone(&browser)))
		.map(|(url, browser)| async move {
			let is_err: bool = false;
			let mut detail: String = String::new();
			let page = match browser.new_page(&url).await {
				Ok(res) => res,
				Err(err) => {
					detail = err.to_string();
					return Ok((url, false, !is_err, detail))
				}
			};
			let vuln: bool = match page.evaluate(CHECK_SCRIPT).await {
				Ok(res) => {
					page.close().await.unwrap();
					res.into_value().unwrap()
				},
				Err(_) => false
			};

			Ok::<_, Box<dyn std::error::Error>>
			((url, vuln, is_err, detail))
		}
	)).buffer_unordered(opt.concurrency);

	while let Some(res) = stream.next().await {
		if let Ok((ref url, vuln, is_err, detail)) = res {
			if vuln {
				println!("[{}] {}", "VULN".green(), url)
			} else {
				let mut msg = format!("[{}] {}", "ERRO".red(), url);
				if is_err {
					let det = format!("({})", detail);
					msg = format!("{} {}", msg, det.yellow());
				}

				eprintln!("{}", msg)
			}
		}
	}
}