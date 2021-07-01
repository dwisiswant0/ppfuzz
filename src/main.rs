extern crate ppfuzz;

use {
	clap::crate_description,
	futures::StreamExt,
};

use ppfuzz::{
	browser, builder,
	checker, parser,
};

#[async_std::main]
async fn main() {
	let opt = parser::get();
	
	println!("{}", crate_description!());

	let urls = parser::urls(opt.list);
	let (browser, mut handler) = browser::config(opt.timeout).await;

	let _handle = async_std::task::spawn(async move {
		loop {
			let _ = handler.next().await.unwrap();
		}
	});

	checker::new(urls
		.into_iter()
		.filter(|url| url
			.starts_with("http"))
		.flat_map(builder::query)
		.collect(), browser, opt.concurrency, opt.timeout).await;
}