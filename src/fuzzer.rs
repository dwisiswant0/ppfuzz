use {
	chromiumoxide::Browser,
	colored::*,
	futures::{StreamExt, stream},
	std::{sync::Arc, time::Duration},
};

static CHECK_SCRIPT: &str = "(window.ppfuzz || Object.prototype.ppfuzz) == 'reserved' && true || false";

pub async fn new(
	urls: Vec<String>,
	browser: Browser,
	concurrency: usize,
	timeout: u64
) {
	let browser = Arc::new(browser);
	let mut stream = stream::iter(urls.into_iter()
		.map(|url| (url, Arc::clone(&browser)))
		.map(|(url, browser)| async move {
			let page = browser.new_page(&url).await.unwrap();
			let vuln = match page.evaluate(CHECK_SCRIPT).await {
				Ok(res) => res.into_value().unwrap(),
				Err(_) => false,
			};

			Ok::<_, Box<dyn std::error::Error>>((url, vuln, page))
		}
	)).buffer_unordered(concurrency);

	while let Ok(res) = async_std::future::timeout(
		Duration::from_secs(timeout), stream.next()
	).await {
		if let Some(Ok((ref url, vuln, page))) = res {
			if vuln {
				println!("[{}] {}", "VULN".green(), url)
			} else {
				eprintln!("[{}] {}", "ERRO".red(), url)
			}

			page.close().await.unwrap();
		}
	}
}