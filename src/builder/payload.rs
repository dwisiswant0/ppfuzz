static PROTO: &str = "__proto__";

pub fn get() -> Vec<String> {
	let suffixes: Vec<String> = vec![
		".ppfuzz".to_string(),
		"[ppfuzz]".to_string()
	];

	suffixes
		.into_iter()
		.map(|suffix| PROTO.to_owned() + &suffix)
		.collect()
}