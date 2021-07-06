use {
	chromiumoxide::{
		browser::{Browser, BrowserConfig},
		handler::Handler,
	},
	std::{process, time::Duration}
};

use crate::errors;

pub async fn config(timeout: u64) -> (Browser, Handler) {
	Browser::launch(
		match BrowserConfig::builder()
			.request_timeout(Duration::from_secs(timeout))
			.build() {
				Ok(res) => res,
				Err(err) => {
					errors::show(err);
					process::exit(1)
				},
			})
		.await
		.unwrap_or_else(|err| {
			errors::show(format!("Unable to launch browser: {}.", err));
			process::exit(1)
		})
}