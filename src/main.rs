extern crate ppfuzz;

use {
	clap::crate_description,
	futures::StreamExt,
};

use ppfuzz::{
	browser, builder,
	fuzzer, parser,
};

fn main() {
	smol::block_on(async {
		let mut opt = parser::Options::get();

		println!("{}", crate_description!());

		let urls = parser::Options::urls(&mut opt);
		let (browser, mut handler) = browser::config(opt.timeout).await;
		let _handle = smol::spawn(async move {
			loop {
				let _ = handler.next().await.unwrap();
			}
		});

		fuzzer::new(urls
			.into_iter()
			.filter(|url| url
				.starts_with("http"))
			.flat_map(builder::query)
			.collect(), browser, opt).await;
	})
}