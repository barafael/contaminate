//! The scanning core of the `analyze` example: string extraction, wordlist search
//! and section tables for ELF64 and WebAssembly files.
//!
//! The web demo (`web/`) includes this file via `#[path]`, so it must not refer
//! to anything in `main.rs` and must stay free of CLI concerns (printing, exit
//! codes, argument parsing).

// Each of the two users needs only part of this module.
#![allow(dead_code)]

use contaminate::Encoding;
use std::collections::HashMap;
use std::ops::Range;

pub const ALL_ENCODINGS: [Encoding; 3] = [Encoding::Utf8, Encoding::Utf16Le, Encoding::Utf16Be];

/// Label for a match. ASCII UTF-16LE and UTF-16BE are the same bytes shifted by
/// one, so a match can be either; see [`merge_utf16_twins`].
pub fn enc_name(enc: Encoding, ambiguous: bool) -> &'static str {
    match (enc, ambiguous) {
        (Encoding::Utf8, _) => "utf8",
        (_, true) => "utf16le|be",
        (Encoding::Utf16Le, false) => "utf16le",
        (Encoding::Utf16Be, false) => "utf16be",
    }
}

/// An encoding name plus its XOR key, such as `utf8` or `utf8^0x5a`.
pub fn label(name: &str, key: u8) -> String {
    match key {
        0 => name.to_string(),
        k => format!("{name}^{k:#04x}"),
    }
}

/// A string found by [`extract`], or a wordlist match from [`find_words`] (with
/// empty `text`).
pub struct Hit<'s> {
    pub offset: usize,
    pub chars: usize,
    pub enc: Encoding,
    pub key: u8,
    pub ambiguous: bool,
    pub section: &'s str,
    pub text: String,
}

impl Hit<'_> {
    pub fn name(&self) -> &'static str {
        enc_name(self.enc, self.ambiguous)
    }
}

/// An ASCII UTF-16LE string at offset `x` is, byte for byte, a UTF-16BE string at
/// `x - 1` (and, minus its first char, at `x + 1`). For each such pair under the
/// same key, keep the longer hit. On a tie, keep the LE one (the usual case, as in
/// Windows binaries) and mark it ambiguous. UTF-8 hits pass through unchanged.
pub fn merge_utf16_twins(mut hits: Vec<Hit<'_>>) -> Vec<Hit<'_>> {
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

/// Every printable string of at least `min_len` chars, in each of `encodings`,
/// under each of `xor_keys` (include `0` for the bytes as they are). Sorted by
/// offset.
pub fn extract<'s>(
    data: &[u8],
    sections: &'s Sections,
    encodings: &[Encoding],
    xor_keys: &[u8],
    min_len: usize,
) -> Vec<Hit<'s>> {
    let pieces = sections.pieces(data.len());
    let mut hits = Vec::new();
    for &key in xor_keys {
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
            for &enc in encodings {
                let mut run = Run::new(enc, key, min_len, section);
                match enc {
                    Encoding::Utf8 => scan_utf8(piece, range.start, &mut run, &mut hits),
                    _ => scan_utf16(piece, range.start, &mut run, &mut wide),
                }
            }
        }
        hits.extend(merge_utf16_twins(wide));
    }
    hits.sort_by_key(|h| (h.offset, h.enc, h.key));
    hits
}

/// Tab and any non-control char count as text. Format chars like zero-width
/// spaces and bidi overrides are kept on purpose; callers escape them on output.
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
    /// Try all 256 XOR keys, not just the given ones.
    brute: bool,
}

/// Searches `data` for every word in each of `encodings`. Words of at least 8
/// bytes (in a given encoding) are tried under all 256 XOR keys; shorter ones
/// only under `xor_keys`. Returns the hits for each word, in word order, with
/// UTF-16 twins merged.
pub fn find_words<'s, W: AsRef<str>>(
    data: &[u8],
    sections: &'s Sections,
    words: &[W],
    encodings: &[Encoding],
    xor_keys: &[u8],
) -> Vec<Vec<Hit<'s>>> {
    let needles: Vec<Needle> = words
        .iter()
        .enumerate()
        .flat_map(|(word, w)| {
            encodings.iter().map(move |&enc| {
                let bytes: Vec<u8> = enc.encode(w.as_ref()).collect();
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
    for (offset, n, key) in find_xored(data, &needles, xor_keys) {
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
    by_word.into_iter().map(merge_utf16_twins).collect()
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

// ---------------------------------------------------------------------------
// Section tables, used to label file offsets.

/// `(name, start, end)` file ranges of the sections of an ELF64 little-endian
/// or WebAssembly file. Empty for anything else.
pub struct Sections(pub Vec<(String, usize, usize)>);

impl Sections {
    pub fn parse(d: &[u8]) -> Self {
        Self(
            Self::parse_elf64le(d)
                .or_else(|| Self::parse_wasm(d))
                .unwrap_or_default(),
        )
    }

    /// The file format the table came from, for display.
    pub fn format(d: &[u8]) -> &'static str {
        if d.starts_with(b"\x7fELF\x02\x01") {
            "ELF64 LE"
        } else if d.starts_with(WASM_MAGIC) {
            "WebAssembly"
        } else {
            "unknown"
        }
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

    /// Standard sections are named after their kind (`code`, `export`, ...).
    /// Custom sections, which is where `#[link_section]` puts statics on wasm,
    /// become `custom:<name>`. The data section is split into its segments,
    /// `data[0]`, `data[1]`, ..., each covering just the segment's bytes.
    fn parse_wasm(d: &[u8]) -> Option<Vec<(String, usize, usize)>> {
        const NAMES: [&str; 14] = [
            "custom",
            "type",
            "import",
            "function",
            "table",
            "memory",
            "global",
            "export",
            "start",
            "element",
            "code",
            "data",
            "datacount",
            "tag",
        ];
        if !d.starts_with(WASM_MAGIC) {
            return None;
        }
        let mut out = Vec::new();
        let mut pos = WASM_MAGIC.len();
        while pos < d.len() {
            let id = d[pos];
            let (size, n) = leb128(d, pos + 1)?;
            let start = pos + 1 + n;
            let end = start.checked_add(size)?;
            let body = d.get(start..end)?;
            match id {
                0 => {
                    let (len, n) = leb128(body, 0)?;
                    let name = body.get(n..n.checked_add(len)?)?;
                    let name = String::from_utf8_lossy(name);
                    out.push((format!("custom:{name}"), start + n + len, end));
                }
                11 => match wasm_data_segments(body, start) {
                    Some(segments) => out.extend(segments),
                    None => out.push(("data".into(), start, end)),
                },
                _ => {
                    let name = NAMES.get(usize::from(id)).copied().unwrap_or("unknown");
                    out.push((name.into(), start, end));
                }
            }
            pos = end;
        }
        Some(out)
    }

    /// Splits `0..len` at every section start and end. Each piece lies inside at
    /// most one section, so a string never spans a boundary. That keeps the zero
    /// padding between sections, which XOR turns into printable bytes, from being
    /// glued onto a string. Gaps get the name "-".
    pub fn pieces(&self, len: usize) -> Vec<(Range<usize>, &str)> {
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

    pub fn name_at(&self, offset: usize) -> &str {
        self.0
            .iter()
            .find(|(_, start, end)| (*start..*end).contains(&offset))
            .map_or("-", |(name, _, _)| name.as_str())
    }
}

/// `\0asm`, version 1.
const WASM_MAGIC: &[u8] = b"\0asm\x01\0\0\0";

/// Byte ranges of the segments in a wasm data section whose contents start at
/// file offset `base`. `None` if the section uses anything unexpected.
fn wasm_data_segments(body: &[u8], base: usize) -> Option<Vec<(String, usize, usize)>> {
    let (count, mut p) = leb128(body, 0)?;
    let mut out = Vec::new();
    for i in 0..count {
        let (flags, n) = leb128(body, p)?;
        p += n;
        match flags {
            0 => p = skip_const_expr(body, p)?,
            1 => {}
            2 => {
                p += leb128_len(body, p)?; // memory index
                p = skip_const_expr(body, p)?;
            }
            _ => return None,
        }
        let (len, n) = leb128(body, p)?;
        p += n;
        let end = p.checked_add(len)?;
        body.get(p..end)?;
        out.push((format!("data[{i}]"), base + p, base + end));
        p = end;
    }
    Some(out)
}

/// Skips a constant expression (the offset of an active data segment) and its
/// `end` opcode. Handles `i32.const`, `i64.const`, `global.get` and the extended
/// constant arithmetic ops, which is all a linker emits there.
fn skip_const_expr(d: &[u8], mut p: usize) -> Option<usize> {
    loop {
        let op = *d.get(p)?;
        p += 1;
        match op {
            0x0b => return Some(p),
            // i32.const, i64.const (signed LEB, same length rules), global.get
            0x41 | 0x42 | 0x23 => p += leb128_len(d, p)?,
            // i32/i64 add, sub, mul
            0x6a | 0x6b | 0x6c | 0x7c | 0x7d | 0x7e => {}
            _ => return None,
        }
    }
}

/// Reads an unsigned LEB128 number at `d[p..]`. Returns the value and its length
/// in bytes, or `None` if it's truncated or doesn't fit a `usize`.
fn leb128(d: &[u8], p: usize) -> Option<(usize, usize)> {
    let len = leb128_len(d, p)?;
    let mut value: u64 = 0;
    for (i, &b) in d[p..p + len].iter().enumerate() {
        let bits = u64::from(b & 0x7f);
        let shifted = bits
            .checked_shl(7 * i as u32)
            .filter(|v| v >> (7 * i) == bits)?;
        value |= shifted;
    }
    Some((usize::try_from(value).ok()?, len))
}

/// Length in bytes of the LEB128 number (signed or unsigned) at `d[p..]`.
fn leb128_len(d: &[u8], p: usize) -> Option<usize> {
    for i in 0..10 {
        if *d.get(p + i)? & 0x80 == 0 {
            return Some(i + 1);
        }
    }
    None
}
