pub fn get() -> Vec<String> {
	let queries: Vec<String> = vec!["__proto__.ppfuzz".to_string(), "__proto__[ppfuzz]".to_string()];

	queries
}