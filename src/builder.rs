use url::Url;

use crate::payload;

pub fn query(url: String) -> Vec<String> {
	let payload = payload::get();

	payload.into_iter()
		.filter_map(|(key, _)| Url::parse_with_params(&url, &[(key, "reserved")])
			.ok())
		.map(|url| url
			.as_str()
			.to_string())
		.collect()
}