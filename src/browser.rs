use {
	chromiumoxide::{
		browser::{Browser, BrowserConfig},
		handler::Handler,
	},
	colored::*,
	std::{process, time::Duration}
};

pub async fn config(timeout: u64) -> (Browser, Handler) {
	Browser::launch(
		match BrowserConfig::builder()
			.request_timeout(Duration::from_secs(timeout))
			.build() {
				Ok(res) => res,
				Err(err) => {
					eprintln!("{}.", err.red());
					process::exit(1)
				},
			})
		.await
		.unwrap()
}