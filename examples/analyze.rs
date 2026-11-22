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

use contaminate::Encoding;
use std::collections::{BTreeMap, HashMap};
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

const ALL_ENCODINGS: [Encoding; 3] = [Encoding::Utf8, Encoding::Utf16Le, Encoding::Utf16Be];

/// Label for a match. ASCII UTF-16LE and UTF-16BE are the same bytes shifted by
/// one, so a match can be either; see [`merge_utf16_twins`].
fn enc_name(enc: Encoding, ambiguous: bool) -> &'static str {
    match (enc, ambiguous) {
        (Encoding::Utf8, _) => "utf8",
        (_, true) => "utf16le|be",
        (Encoding::Utf16Le, false) => "utf16le",
        (Encoding::Utf16Be, false) => "utf16be",
    }
}

fn label(name: &str, key: u8) -> String {
    match key {
        0 => name.to_string(),
        k => format!("{name}^{k:#04x}"),
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

/// A string found in extract mode, or a wordlist match in word mode (with empty
/// `text`).
struct Hit<'s> {
    offset: usize,
    chars: usize,
    enc: Encoding,
    key: u8,
    ambiguous: bool,
    section: &'s str,
    text: String,
}

impl Hit<'_> {
    fn name(&self) -> &'static str {
        enc_name(self.enc, self.ambiguous)
    }
}

/// An ASCII UTF-16LE string at offset `x` is, byte for byte, a UTF-16BE string at
/// `x - 1` (and, minus its first char, at `x + 1`). For each such pair under the
/// same key, keep the longer hit. On a tie, keep the LE one (the usual case, as in
/// Windows binaries) and mark it ambiguous. UTF-8 hits pass through unchanged.
fn merge_utf16_twins(mut hits: Vec<Hit<'_>>) -> Vec<Hit<'_>> {
    hits.sort_by_key(|h| (std::cmp::Reverse(h.chars), h.enc, h.offset));
    let mut kept: Vec<Hit> = Vec::with_capacity(hits.len());
    let mut by_pos: HashMap<(usize, u8, Encoding), usize> = HashMap::new();
    for h in hits {
        let other = match h.enc {
            Encoding::Utf8 => None,
            Encoding::Utf16Le => Some(Encoding::Utf16Be),
            Encoding::Utf16Be => Some(Encoding::Utf16Le),
        };
        let twin = other.and_then(|o| {
            [h.offset.wrapping_sub(1), h.offset + 1]
                .into_iter()
                .find_map(|off| by_pos.get(&(off, h.key, o)).copied())
        });
        match twin {
            Some(i) => kept[i].ambiguous |= kept[i].chars == h.chars,
            None => {
                by_pos.insert((h.offset, h.key, h.enc), kept.len());
                kept.push(h);
            }
        }
    }
    kept
}

// ---------------------------------------------------------------------------
// Extract mode

fn extract(opts: &Opts, data: &[u8], sections: &Sections) {
    let pieces = sections.pieces(data.len());
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
        for (range, section) in &pieces {
            let piece = &bytes[range.clone()];
            for &enc in &opts.encodings {
                let mut run = Run::new(enc, key, opts.min_len, section);
                match enc {
                    Encoding::Utf8 => scan_utf8(piece, range.start, &mut run, &mut hits),
                    _ => scan_utf16(piece, range.start, &mut run, &mut wide),
                }
            }
        }
        hits.extend(merge_utf16_twins(wide));
    }
    hits.sort_by_key(|h| (h.offset, h.enc, h.key));

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

/// Tab and any non-control char count as text. Format chars like zero-width
/// spaces and bidi overrides are kept on purpose, and the output escapes them.
fn is_text(c: char) -> bool {
    c == '\t' || !c.is_control()
}

/// Scans one section piece. `base` is the piece's file offset.
fn scan_utf8<'s>(piece: &[u8], base: usize, run: &mut Run<'s>, hits: &mut Vec<Hit<'s>>) {
    let mut off = base;
    for chunk in piece.utf8_chunks() {
        for (i, c) in chunk.valid().char_indices() {
            if is_text(c) {
                run.push(off + i, c);
            } else {
                run.flush(hits);
            }
        }
        if !chunk.invalid().is_empty() {
            run.flush(hits);
        }
        off += chunk.valid().len() + chunk.invalid().len();
    }
    run.flush(hits);
}

/// Like `strings -e l` / `-e b`: only code units below U+0100 count as text
/// (ASCII plus Latin-1). Without that rule, any ASCII text read as UTF-16 decodes
/// to plausible-looking CJK. Both byte alignments are scanned.
fn scan_utf16<'s>(piece: &[u8], base: usize, run: &mut Run<'s>, hits: &mut Vec<Hit<'s>>) {
    for align in 0..2 {
        let units = piece.get(align..).unwrap_or_default().chunks_exact(2);
        for (k, pair) in units.enumerate() {
            let pair = [pair[0], pair[1]];
            let unit = match run.enc {
                Encoding::Utf16Be => u16::from_be_bytes(pair),
                _ => u16::from_le_bytes(pair),
            };
            match u8::try_from(unit).map(char::from) {
                Ok(c) if is_text(c) => run.push(base + align + 2 * k, c),
                _ => run.flush(hits),
            }
        }
        run.flush(hits);
    }
}

/// The string being collected by a scanner. The buffer is reused across runs.
struct Run<'s> {
    enc: Encoding,
    key: u8,
    min_len: usize,
    section: &'s str,
    start: usize,
    chars: usize,
    text: String,
}

impl<'s> Run<'s> {
    fn new(enc: Encoding, key: u8, min_len: usize, section: &'s str) -> Self {
        Self {
            enc,
            key,
            min_len,
            section,
            start: 0,
            chars: 0,
            text: String::new(),
        }
    }

    fn push(&mut self, at: usize, c: char) {
        if self.chars == 0 {
            self.start = at;
        }
        self.chars += 1;
        self.text.push(c);
    }

    fn flush(&mut self, hits: &mut Vec<Hit<'s>>) {
        if self.chars >= self.min_len {
            hits.push(Hit {
                offset: self.start,
                chars: self.chars,
                enc: self.enc,
                key: self.key,
                ambiguous: false,
                section: self.section,
                text: std::mem::take(&mut self.text),
            });
        } else {
            self.text.clear();
        }
        self.chars = 0;
    }
}

// ---------------------------------------------------------------------------
// Word mode

struct Needle {
    word: usize,
    enc: Encoding,
    bytes: Vec<u8>,
    /// Try all 256 XOR keys, not just the `-x` ones.
    brute: bool,
}

/// Returns true if every word was found at least once.
fn check_words(opts: &Opts, words: &[String], data: &[u8], sections: &Sections) -> bool {
    let needles: Vec<Needle> = words
        .iter()
        .enumerate()
        .flat_map(|(word, w)| {
            opts.encodings.iter().map(move |&enc| {
                let bytes: Vec<u8> = enc.encode(w).collect();
                let brute = bytes.len() >= 8;
                Needle {
                    word,
                    enc,
                    bytes,
                    brute,
                }
            })
        })
        .collect();

    let mut by_word: Vec<Vec<Hit>> = (0..words.len()).map(|_| Vec::new()).collect();
    for (offset, n, key) in find_xored(data, &needles, &opts.xor_keys) {
        by_word[n.word].push(Hit {
            offset,
            chars: n.bytes.len(),
            enc: n.enc,
            key,
            ambiguous: false,
            section: sections.name_at(offset),
            text: String::new(),
        });
    }

    let mut missing = Vec::new();
    println!("{:<42} {:<16} {:>5}  SECTIONS", "WORD", "ENCODING", "HITS");
    for (word, hits) in words.iter().zip(by_word) {
        // (encoding name, key) -> section -> count
        let mut found: BTreeMap<(&str, u8), BTreeMap<&str, usize>> = BTreeMap::new();
        for h in merge_utf16_twins(hits) {
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

/// Finds every `(offset, needle, key)` where `data[offset..]` is a needle XORed
/// with `key`, in a single pass over `data` for all needles.
///
/// XOR doesn't change the XOR of neighbouring bytes. So the first three bytes of a
/// match have the same two "difference bytes" as the needle, whatever the key.
/// Needles are indexed by those, and each position only checks the needles whose
/// prefix fits. The first byte then fixes the only possible key. Needles shorter
/// than 3 bytes are checked at every position.
fn find_xored<'n>(data: &[u8], needles: &'n [Needle], keys: &[u8]) -> Vec<(usize, &'n Needle, u8)> {
    fn diff_key(b: &[u8]) -> usize {
        (((b[0] ^ b[1]) as usize) << 8) | (b[1] ^ b[2]) as usize
    }
    let mut index: Vec<Vec<&Needle>> = vec![Vec::new(); 1 << 16];
    let mut short: Vec<&Needle> = Vec::new();
    for n in needles.iter().filter(|n| !n.bytes.is_empty()) {
        match n.bytes.len() {
            1 | 2 => short.push(n),
            _ => index[diff_key(&n.bytes)].push(n),
        }
    }

    let mut hits = Vec::new();
    for i in 0..data.len() {
        let candidates = match data.get(i..i + 3) {
            Some(prefix) => index[diff_key(prefix)].as_slice(),
            None => &[],
        };
        for &n in candidates.iter().chain(&short) {
            let key = data[i] ^ n.bytes[0];
            if !n.brute && !keys.contains(&key) {
                continue;
            }
            let Some(window) = data.get(i..i + n.bytes.len()) else {
                continue;
            };
            if window.iter().zip(&n.bytes).all(|(b, x)| b ^ key == *x) {
                hits.push((i, n, key));
            }
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
        // Little-endian unsigned integer of `n` bytes at offset `o`.
        let at = |o: usize, n: usize| {
            let bytes = d.get(o..o.checked_add(n)?)?;
            Some(bytes.iter().rev().fold(0, |a, &b| (a << 8) | b as usize))
        };

        let shoff = at(0x28, 8)?;
        let shentsize = at(0x3a, 2)?;
        let shnum = at(0x3c, 2)?;
        let shstrndx = at(0x3e, 2)?;
        // The header fields come from the file, so all arithmetic on them is
        // checked: a malformed or hostile file just yields no section table.
        let header = |i: usize| shoff.checked_add(i.checked_mul(shentsize)?);
        let field = |i: usize, o: usize, n: usize| at(header(i)?.checked_add(o)?, n);
        let strtab = field(shstrndx, 0x18, 8)?;

        let mut out = Vec::new();
        for i in 1..shnum {
            const SHT_NOBITS: usize = 8;
            if field(i, 4, 4)? == SHT_NOBITS {
                continue;
            }
            let name_off = strtab.checked_add(field(i, 0, 4)?)?;
            let name_len = d.get(name_off..)?.iter().position(|&b| b == 0)?;
            let name = String::from_utf8_lossy(&d[name_off..name_off + name_len]).into_owned();
            let (offset, size) = (field(i, 0x18, 8)?, field(i, 0x20, 8)?);
            out.push((name, offset, offset.saturating_add(size)));
        }
        Some(out)
    }

    /// Splits `0..len` at every section start and end. Each piece lies inside at
    /// most one section, so a string never spans a boundary. That keeps the zero
    /// padding between sections, which XOR turns into printable bytes, from being
    /// glued onto a string. Gaps get the name "-".
    fn pieces(&self, len: usize) -> Vec<(std::ops::Range<usize>, &str)> {
        let mut cuts: Vec<usize> = self
            .0
            .iter()
            .flat_map(|s| [s.1, s.2])
            .chain([0, len])
            .filter(|&c| c <= len)
            .collect();
        cuts.sort_unstable();
        cuts.dedup();
        cuts.windows(2)
            .map(|w| (w[0]..w[1], self.name_at(w[0])))
            .collect()
    }

    fn name_at(&self, offset: usize) -> &str {
        self.0
            .iter()
            .find(|(_, start, end)| (*start..*end).contains(&offset))
            .map_or("-", |(name, _, _)| name.as_str())
    }
}
