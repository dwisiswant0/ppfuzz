pub fn get() -> Vec<String> {
	let mut payload = vec![];

	let object = get_object();
	let pointer = get_pointer();

	payload.extend(object);
	payload.extend(pointer);

	payload
}

fn get_object() -> Vec<String> {
	const PREFIX: &str = "__proto__";
	let suffixes = [
		".ppfuzz",
		"[ppfuzz]"
	];

	suffixes
		.iter()
		.map(|suffix| PREFIX.to_owned() + suffix)
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
		.map(|suffix| PREFIX.to_owned() + suffix)
		.collect()
}