use colored::*;

pub fn show(msg: String) {
	eprintln!("[{}] {}", "ERROR".red(), msg);
	eprintln!("[{}] Use '-h' flag for more info about command.", "INFO".blue());
}
