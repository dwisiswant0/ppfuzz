pub fn get() -> Vec<String> {
	[get_object(), get_pointer()].concat()
}

fn get_object() -> Vec<String> {
	const PREFIX: &str = "__proto__";
	let suffixes = [
		".ppfuzz",
		"[ppfuzz]"
	];

	suffixes
		.iter()
		.map(|suffix| format!(
			"{}{}", PREFIX, suffix
		))
		.collect()
}

fn get_pointer() -> Vec<String> {
	const PREFIX: &str = "constructor";
	let suffixes = [
		".prototype.ppfuzz",
		"[prototype][ppfuzz]"
	];

	suffixes
		.iter()
		.map(|suffix| format!(
			"{}{}", PREFIX, suffix
		))
		.collect()
}