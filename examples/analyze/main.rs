//! A small `strings`-style analyzer for binaries.
//!
//! Extract mode (the default) lists printable strings in UTF-8, UTF-16LE and
//! UTF-16BE, optionally after undoing a XOR key, along with their file offset and
//! section (ELF64 and WebAssembly files):
//!
//! ```sh
//! cargo run --release --example analyze -- target/release/examples/demo
//! cargo run --release --example analyze -- -e utf16le -n 8 -x 0x5a some.bin
//! ```
//!
//! Word mode (`-w` or `-W FILE`) searches for each word of a wordlist in every
//! encoding and under every XOR key, reports where each one was found, and exits
//! with status 1 if any word is missing:
//!
//! ```sh
//! cargo run --release --example analyze -- -w target/release/examples/hidden
//! ```

mod scan;

use contaminate::Encoding;
use scan::{ALL_ENCODINGS, Sections, label};
use std::collections::BTreeMap;
use std::process::ExitCode;
use std::{env, fs};

const USAGE: &str = "\
usage: analyze [OPTIONS] FILE...

Extract printable strings from binaries, or check them for a wordlist.

options:
  -n, --min-len N      minimum string length in characters (default 4)
  -e, --encoding ENC   utf8, utf16le, utf16be or all; comma-separated (default all)
  -x, --xor KEY        also decode with XOR key KEY (decimal or 0x-hex); repeatable
  -s, --summary        print only per-section and per-encoding counts
  -w, --words          check for the wordlist compiled into this analyzer
  -W, --wordlist FILE  check for the words in FILE (one per line, '#' comments)
  -h, --help           show this help

In word mode, words of at least 8 bytes are tried under all 256 XOR keys.
Shorter words are tried only with key 0 and any -x keys. ASCII UTF-16BE and
UTF-16LE look alike when shifted by one byte; such matches show as utf16le|be.
";

enum Wordlist {
    None,
    Builtin,
    File(String),
}

struct Opts {
    files: Vec<String>,
    min_len: usize,
    encodings: Vec<Encoding>,
    xor_keys: Vec<u8>,
    summary: bool,
    wordlist: Wordlist,
}

fn parse_args() -> Result<Opts, String> {
    let mut o = Opts {
        files: Vec::new(),
        min_len: 4,
        encodings: ALL_ENCODINGS.to_vec(),
        xor_keys: vec![0],
        summary: false,
        wordlist: Wordlist::None,
    };
    let mut args = env::args().skip(1);
    while let Some(a) = args.next() {
        let mut value = |name: &str| args.next().ok_or(format!("{name} needs a value"));
        match a.as_str() {
            "-h" | "--help" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            "-n" | "--min-len" => {
                let v = value(&a)?;
                o.min_len = v
                    .parse::<usize>()
                    .map_err(|_| format!("bad length: {v}"))?
                    .max(1);
            }
            "-e" | "--encoding" => {
                o.encodings.clear();
                for e in value(&a)?.split(',') {
                    match e {
                        "utf8" => o.encodings.push(Encoding::Utf8),
                        "utf16le" => o.encodings.push(Encoding::Utf16Le),
                        "utf16be" => o.encodings.push(Encoding::Utf16Be),
                        "all" => o.encodings.extend(ALL_ENCODINGS),
                        _ => return Err(format!("unknown encoding: {e}")),
                    }
                }
                o.encodings.sort();
                o.encodings.dedup();
            }
            "-x" | "--xor" => {
                let v = value(&a)?;
                let key = match v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")) {
                    Some(hex) => u8::from_str_radix(hex, 16),
                    None => v.parse(),
                }
                .map_err(|_| format!("bad XOR key (want 0..=255): {v}"))?;
                if !o.xor_keys.contains(&key) {
                    o.xor_keys.push(key);
                }
            }
            "-s" | "--summary" => o.summary = true,
            "-w" | "--words" => o.wordlist = Wordlist::Builtin,
            "-W" | "--wordlist" => o.wordlist = Wordlist::File(value(&a)?),
            s if s.starts_with('-') && s.len() > 1 => return Err(format!("unknown option: {s}")),
            _ => o.files.push(a),
        }
    }
    if o.files.is_empty() {
        return Err("no input files".into());
    }
    Ok(o)
}

fn main() -> ExitCode {
    let opts = match parse_args() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("analyze: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };

    let words: Option<Vec<String>> = match &opts.wordlist {
        Wordlist::None => None,
        Wordlist::Builtin => Some(contaminate::WORDS.map(String::from).to_vec()),
        Wordlist::File(path) => match fs::read_to_string(path) {
            Ok(text) => Some(
                contaminate::parse_wordlist(&text)
                    .map(String::from)
                    .collect(),
            ),
            Err(e) => {
                eprintln!("analyze: {path}: {e}");
                return ExitCode::from(2);
            }
        },
    };

    // 2 (an error) wins over 1 (a missing word), whatever the file order.
    let mut status: u8 = 0;
    for path in &opts.files {
        let data = match fs::read(path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("analyze: {path}: {e}");
                status = status.max(2);
                continue;
            }
        };
        if opts.files.len() > 1 {
            println!("==> {path} <==");
        }
        let sections = Sections::parse(&data);
        match &words {
            None => extract(&opts, &data, &sections),
            Some(words) => {
                if !check_words(&opts, words, &data, &sections) {
                    status = status.max(1);
                }
            }
        }
    }
    ExitCode::from(status)
}

// ---------------------------------------------------------------------------
// Extract mode

fn extract(opts: &Opts, data: &[u8], sections: &Sections) {
    let hits = scan::extract(
        data,
        sections,
        &opts.encodings,
        &opts.xor_keys,
        opts.min_len,
    );

    if opts.summary {
        let mut by_section: BTreeMap<&str, usize> = BTreeMap::new();
        let mut by_enc: BTreeMap<(&str, u8), usize> = BTreeMap::new();
        for h in &hits {
            *by_section.entry(h.section).or_default() += 1;
            *by_enc.entry((h.name(), h.key)).or_default() += 1;
        }
        println!("{} strings", hits.len());
        println!("\nby section:");
        for (s, n) in by_section {
            println!("  {s:<24} {n:>8}");
        }
        println!("\nby encoding:");
        for ((name, key), n) in by_enc {
            println!("  {:<24} {n:>8}", label(name, key));
        }
        return;
    }

    for h in &hits {
        println!(
            "{:#010x}  {:<20} {:<16} {}",
            h.offset,
            h.section,
            label(h.name(), h.key),
            h.text.escape_debug()
        );
    }
}

// ---------------------------------------------------------------------------
// Word mode

/// Returns true if every word was found at least once.
fn check_words(opts: &Opts, words: &[String], data: &[u8], sections: &Sections) -> bool {
    let by_word = scan::find_words(data, sections, words, &opts.encodings, &opts.xor_keys);

    let mut missing = Vec::new();
    println!("{:<42} {:<16} {:>5}  SECTIONS", "WORD", "ENCODING", "HITS");
    for (word, hits) in words.iter().zip(by_word) {
        // (encoding name, key) -> section -> count
        let mut found: BTreeMap<(&str, u8), BTreeMap<&str, usize>> = BTreeMap::new();
        for h in hits {
            *found
                .entry((h.name(), h.key))
                .or_default()
                .entry(h.section)
                .or_default() += 1;
        }
        if found.is_empty() {
            missing.push(word);
        }
        for ((name, key), secs) in found {
            let total: usize = secs.values().sum();
            let secs: Vec<String> = secs.iter().map(|(s, n)| format!("{s}×{n}")).collect();
            println!(
                "{:<42} {:<16} {:>5}  {}",
                truncate(&format!("{word:?}"), 42),
                label(name, key),
                total,
                secs.join(", ")
            );
        }
    }

    println!(
        "\n{} of {} words found",
        words.len() - missing.len(),
        words.len()
    );
    for w in &missing {
        println!("missing: {w:?}");
    }
    missing.is_empty()
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut t: String = s.chars().take(max - 1).collect();
        t.push('…');
        t
    }
}
