//! A small `strings`-style analyzer for binaries.
//!
//! Extract mode (the default) lists printable strings in UTF-8, UTF-16LE and
//! UTF-16BE, optionally after undoing a XOR key, along with their file offset and
//! ELF section:
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

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Enc {
    Utf8,
    Utf16Le,
    Utf16Be,
}

impl Enc {
    const ALL: [Enc; 3] = [Enc::Utf8, Enc::Utf16Le, Enc::Utf16Be];

    fn name(self) -> &'static str {
        match self {
            Enc::Utf8 => "utf8",
            Enc::Utf16Le => "utf16le",
            Enc::Utf16Be => "utf16be",
        }
    }

    fn encode(self, s: &str) -> Vec<u8> {
        match self {
            Enc::Utf8 => s.as_bytes().to_vec(),
            Enc::Utf16Le => s.encode_utf16().flat_map(u16::to_le_bytes).collect(),
            Enc::Utf16Be => s.encode_utf16().flat_map(u16::to_be_bytes).collect(),
        }
    }
}

enum Wordlist {
    None,
    Builtin,
    File(String),
}

struct Opts {
    files: Vec<String>,
    min_len: usize,
    encodings: Vec<Enc>,
    xor_keys: Vec<u8>,
    summary: bool,
    wordlist: Wordlist,
}

fn parse_args() -> Result<Opts, String> {
    let mut o = Opts {
        files: Vec::new(),
        min_len: 4,
        encodings: Enc::ALL.to_vec(),
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
                o.min_len = v.parse().map_err(|_| format!("bad length: {v}"))?;
                o.min_len = o.min_len.max(1);
            }
            "-e" | "--encoding" => {
                o.encodings.clear();
                for e in value(&a)?.split(',') {
                    match e {
                        "utf8" => o.encodings.push(Enc::Utf8),
                        "utf16le" => o.encodings.push(Enc::Utf16Le),
                        "utf16be" => o.encodings.push(Enc::Utf16Be),
                        "all" => o.encodings.extend(Enc::ALL),
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

    let words: Vec<String> = match &opts.wordlist {
        Wordlist::None => Vec::new(),
        Wordlist::Builtin => contaminate::WORDS.iter().map(|w| w.to_string()).collect(),
        Wordlist::File(path) => match fs::read_to_string(path) {
            Ok(text) => text
                .lines()
                .map(|l| l.strip_suffix('\r').unwrap_or(l))
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(str::to_owned)
                .collect(),
            Err(e) => {
                eprintln!("analyze: {path}: {e}");
                return ExitCode::from(2);
            }
        },
    };

    let mut status = ExitCode::SUCCESS;
    for path in &opts.files {
        let data = match fs::read(path) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("analyze: {path}: {e}");
                status = ExitCode::from(2);
                continue;
            }
        };
        if opts.files.len() > 1 {
            println!("==> {path} <==");
        }
        let sections = Sections::parse(&data);
        match opts.wordlist {
            Wordlist::None => extract(&opts, &data, &sections),
            _ => {
                if !check_words(&opts, &words, &data, &sections) {
                    status = ExitCode::FAILURE;
                }
            }
        }
    }
    status
}

// ---------------------------------------------------------------------------
// Extract mode

struct Hit {
    offset: usize,
    chars: usize,
    enc: Enc,
    key: u8,
    /// UTF-16 only: the bytes read the same as the other byte order, shifted by one.
    ambiguous: bool,
    text: String,
}

impl Hit {
    fn label(&self) -> String {
        let label = enc_label(self.enc, self.key);
        if self.ambiguous {
            label.replacen(self.enc.name(), "utf16le|be", 1)
        } else {
            label
        }
    }
}

fn extract(opts: &Opts, data: &[u8], sections: &Sections) {
    let cuts = sections.starts();
    let mut hits = Vec::new();
    for &key in &opts.xor_keys {
        let decoded: Vec<u8>;
        let bytes = if key == 0 {
            data
        } else {
            decoded = data.iter().map(|b| b ^ key).collect();
            &decoded
        };
        let mut wide = Vec::new();
        for &enc in &opts.encodings {
            match enc {
                Enc::Utf8 => scan_utf8(bytes, key, opts.min_len, &cuts, &mut hits),
                Enc::Utf16Le | Enc::Utf16Be => {
                    scan_utf16(bytes, enc, key, opts.min_len, &cuts, &mut wide)
                }
            }
        }
        hits.extend(dedup_wide(wide));
    }
    hits.sort_by_key(|h| (h.offset, h.enc, h.key));

    if opts.summary {
        let mut by_section: BTreeMap<&str, usize> = BTreeMap::new();
        let mut by_enc: BTreeMap<String, usize> = BTreeMap::new();
        for h in &hits {
            *by_section.entry(sections.name_at(h.offset)).or_default() += 1;
            *by_enc.entry(h.label()).or_default() += 1;
        }
        println!("{} strings", hits.len());
        println!("\nby section:");
        for (s, n) in by_section {
            println!("  {s:<24} {n:>8}");
        }
        println!("\nby encoding:");
        for (e, n) in by_enc {
            println!("  {e:<24} {n:>8}");
        }
        return;
    }

    for h in &hits {
        println!(
            "{:#010x}  {:<20} {:<16} {}",
            h.offset,
            sections.name_at(h.offset),
            h.label(),
            h.text.escape_debug()
        );
    }
}

fn enc_label(enc: Enc, key: u8) -> String {
    match key {
        0 => enc.name().to_string(),
        k => format!("{}^{k:#04x}", enc.name()),
    }
}

/// Tab and any non-control char count as text. Format chars like zero-width
/// spaces and bidi overrides are kept on purpose, and the output escapes them.
fn is_text(c: char) -> bool {
    c == '\t' || !c.is_control()
}

/// `cuts` are sorted section start offsets. A run never spans one, so the zero
/// padding between sections (which XOR turns into printable bytes) can't glue
/// unrelated data onto a string.
fn scan_utf8(data: &[u8], key: u8, min_len: usize, cuts: &[usize], hits: &mut Vec<Hit>) {
    let mut run = Run::default();
    let mut i = 0;
    while i < data.len() {
        let n = match data[i] {
            0x00..=0x7f => 1,
            0xc2..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf4 => 4,
            _ => 0,
        };
        let ch = data
            .get(i..i + n)
            .filter(|_| n > 0)
            .and_then(|b| std::str::from_utf8(b).ok())
            .and_then(|s| s.chars().next());
        match ch {
            Some(c) if is_text(c) => {
                if cuts.binary_search(&i).is_ok() {
                    run.flush(Enc::Utf8, key, min_len, hits);
                }
                run.push(i, c);
                i += n;
            }
            _ => {
                run.flush(Enc::Utf8, key, min_len, hits);
                i += 1;
            }
        }
    }
    run.flush(Enc::Utf8, key, min_len, hits);
}

/// Like `strings -e l` / `-e b`: only code units below U+0100 count as text
/// (ASCII plus Latin-1). Without that rule, any ASCII text read as UTF-16 decodes
/// to plausible-looking CJK. Both byte alignments are scanned.
fn scan_utf16(data: &[u8], enc: Enc, key: u8, min_len: usize, cuts: &[usize], hits: &mut Vec<Hit>) {
    for align in 0..2 {
        let mut run = Run::default();
        let mut i = align;
        while i + 1 < data.len() {
            let pair = [data[i], data[i + 1]];
            let unit = match enc {
                Enc::Utf16Be => u16::from_be_bytes(pair),
                _ => u16::from_le_bytes(pair),
            };
            match char::from_u32(unit as u32) {
                Some(c) if unit < 0x100 && is_text(c) => {
                    if cuts.binary_search(&i).is_ok() || cuts.binary_search(&(i + 1)).is_ok() {
                        run.flush(enc, key, min_len, hits);
                    }
                    run.push(i, c);
                }
                _ => run.flush(enc, key, min_len, hits),
            }
            i += 2;
        }
        run.flush(enc, key, min_len, hits);
    }
}

/// An ASCII UTF-16LE string at offset `x` is, byte for byte, a UTF-16BE string at
/// `x - 1` (and, minus its first char, at `x + 1`). For each such pair under the
/// same key, keep the longer hit. On a tie, keep the LE one and mark it ambiguous.
fn dedup_wide(mut wide: Vec<Hit>) -> Vec<Hit> {
    wide.sort_by_key(|h| (std::cmp::Reverse(h.chars), h.enc));
    let mut kept: Vec<Hit> = Vec::new();
    let mut by_pos: std::collections::HashMap<(usize, u8), usize> = Default::default();
    for h in wide {
        let twin = [h.offset.wrapping_sub(1), h.offset + 1]
            .iter()
            .filter_map(|&o| by_pos.get(&(o, h.key)).copied())
            .find(|&i| kept[i].enc != h.enc);
        match twin {
            Some(i) => kept[i].ambiguous |= kept[i].chars == h.chars,
            None => {
                by_pos.insert((h.offset, h.key), kept.len());
                kept.push(h);
            }
        }
    }
    kept
}

#[derive(Default)]
struct Run {
    start: usize,
    chars: usize,
    text: String,
}

impl Run {
    fn push(&mut self, at: usize, c: char) {
        if self.chars == 0 {
            self.start = at;
        }
        self.chars += 1;
        self.text.push(c);
    }

    fn flush(&mut self, enc: Enc, key: u8, min_len: usize, hits: &mut Vec<Hit>) {
        if self.chars >= min_len {
            hits.push(Hit {
                offset: self.start,
                chars: self.chars,
                enc,
                key,
                ambiguous: false,
                text: std::mem::take(&mut self.text),
            });
        }
        *self = Run::default();
    }
}

// ---------------------------------------------------------------------------
// Word mode

/// Returns true if every word was found at least once.
fn check_words(opts: &Opts, words: &[String], data: &[u8], sections: &Sections) -> bool {
    // (word index, encoding label) -> section -> count
    let mut found: BTreeMap<(usize, String), BTreeMap<&str, usize>> = BTreeMap::new();
    for (wi, word) in words.iter().enumerate() {
        let mut hits: Vec<(usize, Enc, u8)> = Vec::new();
        for &enc in &opts.encodings {
            let needle = enc.encode(word);
            let brute = needle.len() >= 8;
            hits.extend(
                find_xored(data, &needle, brute, &opts.xor_keys)
                    .into_iter()
                    .map(|(off, key)| (off, enc, key)),
            );
        }
        for (off, label) in collapse_utf16_pairs(hits) {
            *found
                .entry((wi, label))
                .or_default()
                .entry(sections.name_at(off))
                .or_default() += 1;
        }
    }

    let mut missing = Vec::new();
    println!("{:<42} {:<16} {:>5}  SECTIONS", "WORD", "ENCODING", "HITS");
    for (wi, word) in words.iter().enumerate() {
        let mut any = false;
        for ((_, label), secs) in found.range((wi, String::new())..(wi + 1, String::new())) {
            any = true;
            let total: usize = secs.values().sum();
            let secs: Vec<String> = secs.iter().map(|(s, n)| format!("{s}×{n}")).collect();
            println!(
                "{:<42} {:<16} {:>5}  {}",
                truncate(&format!("{word:?}"), 42),
                label,
                total,
                secs.join(", ")
            );
        }
        if !any {
            missing.push(word);
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

/// For ASCII text, UTF-16BE at offset `x` and UTF-16LE at `x + 1` are the same
/// bytes, so one wide copy often matches both. A BE hit at `x` paired with an LE hit
/// at `x + 1` under the same key is reported once, as `utf16le|be`, since the bytes
/// alone can't tell which one it is. Returns `(offset, label)` pairs.
fn collapse_utf16_pairs(hits: Vec<(usize, Enc, u8)>) -> Vec<(usize, String)> {
    let le: std::collections::HashSet<(usize, u8)> = hits
        .iter()
        .filter(|h| h.1 == Enc::Utf16Le)
        .map(|h| (h.0, h.2))
        .collect();
    let paired_le: std::collections::HashSet<(usize, u8)> = hits
        .iter()
        .filter(|h| h.1 == Enc::Utf16Be && le.contains(&(h.0 + 1, h.2)))
        .map(|h| (h.0 + 1, h.2))
        .collect();
    let mut out = Vec::new();
    for (off, enc, key) in hits {
        if enc == Enc::Utf16Le && paired_le.contains(&(off, key)) {
            continue;
        }
        let mut label = enc_label(enc, key);
        if enc == Enc::Utf16Be && paired_le.contains(&(off + 1, key)) {
            label = label.replacen("utf16be", "utf16le|be", 1);
        }
        out.push((off, label));
    }
    out
}

/// Finds every `(offset, key)` where `data[offset..]` equals `needle` XORed with
/// `key`. Each offset's first byte fixes the only possible key, so one pass covers
/// all 256 keys. With `brute == false`, only `keys` are accepted.
fn find_xored(data: &[u8], needle: &[u8], brute: bool, keys: &[u8]) -> Vec<(usize, u8)> {
    let mut hits = Vec::new();
    if needle.is_empty() || needle.len() > data.len() {
        return hits;
    }
    for i in 0..=data.len() - needle.len() {
        let key = data[i] ^ needle[0];
        if !brute && !keys.contains(&key) {
            continue;
        }
        if data[i + 1..i + needle.len()]
            .iter()
            .zip(&needle[1..])
            .all(|(b, n)| b ^ key == *n)
        {
            hits.push((i, key));
        }
    }
    hits
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

// ---------------------------------------------------------------------------
// Minimal ELF64 little-endian section table, used to label file offsets.

struct Sections(Vec<(String, usize, usize)>);

impl Sections {
    fn parse(d: &[u8]) -> Self {
        Self(Self::parse_elf64le(d).unwrap_or_default())
    }

    fn parse_elf64le(d: &[u8]) -> Option<Vec<(String, usize, usize)>> {
        if d.get(..6)? != b"\x7fELF\x02\x01" {
            return None;
        }
        let u16_at =
            |o: usize| Some(u16::from_le_bytes(d.get(o..o + 2)?.try_into().ok()?) as usize);
        let u32_at =
            |o: usize| Some(u32::from_le_bytes(d.get(o..o + 4)?.try_into().ok()?) as usize);
        let u64_at =
            |o: usize| Some(u64::from_le_bytes(d.get(o..o + 8)?.try_into().ok()?) as usize);

        let shoff = u64_at(0x28)?;
        let shentsize = u16_at(0x3a)?;
        let shnum = u16_at(0x3c)?;
        let shstrndx = u16_at(0x3e)?;
        let header = |i: usize| shoff + i * shentsize;
        let strtab = u64_at(header(shstrndx) + 0x18)?;

        let mut out = Vec::new();
        for i in 1..shnum {
            let h = header(i);
            const SHT_NOBITS: usize = 8;
            if u32_at(h + 4)? == SHT_NOBITS {
                continue;
            }
            let name_off = strtab + u32_at(h)?;
            let name_len = d.get(name_off..)?.iter().position(|&b| b == 0)?;
            let name = String::from_utf8_lossy(&d[name_off..name_off + name_len]).into_owned();
            let (offset, size) = (u64_at(h + 0x18)?, u64_at(h + 0x20)?);
            out.push((name, offset, offset + size));
        }
        Some(out)
    }

    fn starts(&self) -> Vec<usize> {
        let mut v: Vec<usize> = self.0.iter().map(|s| s.1).collect();
        v.sort_unstable();
        v.dedup();
        v
    }

    fn name_at(&self, offset: usize) -> &str {
        self.0
            .iter()
            .find(|(_, start, end)| (*start..*end).contains(&offset))
            .map_or("-", |(name, _, _)| name.as_str())
    }
}
