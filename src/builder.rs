use url::Url;

use crate::payload;

pub fn query(url: String) -> Vec<String> {
	let payload = payload::get();

	payload.into_iter()
		.filter_map(|p| Url::parse_with_params(&url, &[(p, "reserved")])
			.ok())
		.map(|url| url
			.as_str()
			.to_string())
		.collect()
}