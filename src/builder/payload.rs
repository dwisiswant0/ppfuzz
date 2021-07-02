static PROTO: &str = "__proto__";

pub fn get() -> Vec<String> {
	let suffixes = [
		".ppfuzz",
		"[ppfuzz]"
	];

	suffixes
		.iter()
		.map(|suffix| PROTO.to_owned() + suffix)
		.collect()
}