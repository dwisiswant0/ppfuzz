use {
	chromiumoxide::{
		Browser,
		cdp::js_protocol::runtime::{
			EvaluateParams,
			TimeDelta,
		},
	},
	std::sync::Arc,
	futures::StreamExt,
	colored::*,
};

pub async fn check(urls: Vec<String>, browser: Browser, concurrency: usize, timeout: u64) {
	let browser = Arc::new(browser);
	let check = "(window.ppfuzz || Object.prototype.ppfuzz) == 'reserved' && true || false";
	let mut stream = futures::stream::iter(urls.into_iter()
		.map(|url| (url, Arc::clone(&browser)))
		.map(|(url, browser)| async move {
			let eval = EvaluateParams::builder()
				.expression(check)
				.timeout(TimeDelta::new(timeout as f64));
			let page = browser.new_page(&url).await.unwrap();
			let vuln: bool = match page.evaluate(eval.clone().build().unwrap()).await {
				Ok(res) => res.into_value().unwrap(),
				Err(_err) => false,
			};

			page.close().await.unwrap();

			Ok::<_, Box<dyn std::error::Error>>((url, vuln))
		}
	)).buffer_unordered(concurrency);

	while let Some(res) = stream.next().await {
		if let Ok((ref url, vuln)) = res {
			if vuln {
				println!("[{}] {}", "VULN".green(), url)
			} else {
				eprintln!("[{}] {}", "ERRO".red(), url)
			}
		}
	}
}