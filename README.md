# ppfuzz

<p align="left">
	<a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/made%20with-Rust-red"></a>
	<a href="#"><img src="https://img.shields.io/badge/platform-osx%2Flinux%2Fwindows-blueviolet"></a>
	<a href="https://github.com/dwisiswant0/ppfuzz/releases"><img src="https://img.shields.io/github/release/dwisiswant0/ppfuzz?color=blue"></a>
	<a href="https://github.com/dwisiswant0/ppfuzz/issues"><img src="https://img.shields.io/github/issues/dwisiswant0/ppfuzz?color=yellow"></a>
</p>

Prototype Pollution Fuzzer

<img src="https://user-images.githubusercontent.com/25837540/124197070-f0ffb800-daf7-11eb-9d65-edda5d94633f.jpg" alt="ppfuzz, Prototype Pollution Fuzzer">

A fast tool to scan client-side prototype pollution vulnerability written in Rust. 🦀

- [Installation](#installation)
  - [Binary](#binary)
  - [Source](#source)
  - [Dependencies](#dependencies)
- [Demonstration](#demonstration)
- [Usage](#usage)
  - [Basic](#basic)
  - [Options](#options)
- [Usage](#usage)
- [Supporting Materials](#supporting-materials)
- [Contributing](#contributing)
- [Attribution](#attribution)
- [Acknowledments](#acknowledments)
- [License](#license)

---

## Installation

### Binary

Simply, download a pre-built binary from [releases page](https://github.com/dwisiswant0/ppfuzz/releases) and run!

### Source

<table>
	<td><b>NOTE:</b> <a href="https://www.rust-lang.org/tools/install">Rust</a> should be installed!</td>
</table>

Using `cargo`:

```bash
▶ cargo install ppfuzz
```

#### — or

Manual building executable from source code:

```bash
▶ git clone https://github.com/dwisiswant0/ppfuzz
▶ cd ppfuzz && cargo build --release
# binary file located at target/release/ppfuzz
```

### Dependencies

**ppfuzz** uses [chromiumoxide](https://github.com/mattsse/chromiumoxide), which requires Chrome or Chromium browser to be installed.
If the `CHROME` environment variable is set, then it'll use it as the default executable. Otherwise, the filenames `google-chrome-stable`, `chromium`, `chromium-browser`, `chrome` and `chrome-browser` are searched for in standard places. If that fails, `/Applications/Google Chrome.app/...` _(on MacOS)_ or the registry _(on Windows)_ is consulted.

## Demonstration

![ppfuzz-demonstration](https://user-images.githubusercontent.com/25837540/125734819-b4e53913-6f6b-4d3c-937a-e936526d6483.gif)

As you can see in the demo above _(click to view in high-quality)_, **ppfuzz** attempts to check for prototype-pollution vulnerabilities by adding an object & pointer queries, if it's indeed vulnerable: it'll fingerprinting the script gadgets used and then display additional payload info that could potentially escalate its impact to XSS, bypass or cookie injection.

## Usage

It's fairly simple to use **ppfuzz**!

```bash
▶ ppfuzz -l FILE [OPTIONS]
```

### Basic

Use `-l/--list` to provide input list:

```bash
▶ ppfuzz -l FILE
```

You can also provide the list using I/O redirection:

```bash
▶ ppfuzz < FILE
```

— or chain it from another command output:

```bash
▶ cat FILE | ppfuzz
```

Only show vulnerable targets/suppress an errors:

```bash
▶ ppfuzz -l FILE 2>/dev/null
```

### Options

Here are all the options it supports:

```bash
▶ ppfuzz -h
```

| **Flag**          	| **Description**                        	| **Default value** 	|
|-------------------	|----------------------------------------	|-------------------	|
| -l, --list        	| List of target URLs                    	|                   	|
| -c, --concurrency 	| Set the concurrency level              	| 5                 	|
| -t, --timeout     	| Max. time allowed for connection _(s)_ 	| 30                	|
| -h, --help        	| Prints help information                	|                   	|
| -V, --version     	| Prints version information             	|                   	|

## Supporting Materials

- [Nuclei templates](https://github.com/projectdiscovery/nuclei-templates/blob/master/headless/prototype-pollution-check.yaml)
- [PPScan](https://github.com/msrkp/PPScan)
- [Prototype Pollution and useful Script Gadgets](https://github.com/BlackFan/client-side-prototype-pollution)
- [JavaScript prototype pollution attack in NodeJS](https://github.com/HoLyVieR/prototype-pollution-nsec18/blob/master/paper/JavaScript_prototype_pollution_attack_in_NodeJS.pdf)
- [Prototype pollution – and bypassing client-side HTML sanitizers](https://research.securitum.com/prototype-pollution-and-bypassing-client-side-html-sanitizers/)

## Contributing

[![contributions](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/dwisiswant0/ppfuzz/issues)

When I started **ppfuzz**, I had very little or no knowledge on Rust and I believe there may be a lot of drawbacks/security vulnerabilities. So all contributions are welcome, of course — any bug reports & suggestions are appreciated, some environment have not been tested yet.

## Attribution

Besides being my learning medium, this tool was created because it was inspired by [@R0X4R](https://twitter.com/R0X4R/status/1402906185301323776)'s tip on [how to automate prototype pollution checking](https://twitter.com/R0X4R/status/1402906185301323776) using [page-fetch](https://github.com/detectify/page-fetch).

Cross-compile GitHub workflow inspired by [crodjer](https://github.com/crodjer)'s [sysit](https://github.com/crodjer/sysit/commit/160bdae51b2c90c3b6e8a0e6c4832506ebc55694).

## Acknowledments

Since this tool includes some contributions, I'll publically thank the following users for their helps and resources:

- [@mattsse](https://github.com/mattsse) - for his awesome [chromiumoxide](https://github.com/mattsse/chromiumoxide) & mentoring me which helped a lot to quickly adapt Rust!
- `Fourty2#4842` _(Discord)_ - for helpful workaround.
- [All contributors](https://github.com/dwisiswant0/ppfuzz/graphs/contributors).

## License

**ppfuzz** is distributed under MIT. See `LICENSE`.