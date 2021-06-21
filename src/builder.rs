mod payload;

use url::Url;

pub fn query(url: String) -> Vec<String> {
	let mut urls: Vec<String> = vec![String::new(); 0];
	let payload = payload::get();

	for p in payload {
		if let Ok(build) = Url::parse_with_params(&url, &[(p, "reserved")]) {
			urls.push(build.as_str().to_string())
		}
	}

	urls.into_iter().collect()
}