//! Browser demo for `contaminate`, published on GitHub Pages.
//!
//! This module is itself a contaminated binary: the four `contaminate!` copies
//! below end up in the `.wasm` file the browser downloads. The page fetches
//! those bytes and runs the `analyze` example's scanner (shared via `#[path]`)
//! on them.
//!
//! Results go to JavaScript as JSON strings, which keeps the bindings small.

use contaminate::{Encoding, Settings, WORDS, contaminate};
use serde::Serialize;
use std::collections::BTreeMap;
use wasm_bindgen::prelude::*;

#[path = "../../examples/analyze/scan.rs"]
mod scan;

use scan::Sections;

// copies:begin
/// Plain UTF-8, NUL after each word: what `strings` finds.
const PLAIN: Settings = Settings::DEFAULT;

/// Windows-style wide strings: `strings -e l` finds these.
const WIDE: Settings = Settings {
    encoding: Encoding::Utf16Le,
    ..Settings::DEFAULT
};

/// XORed and packed back to back: invisible to `strings`.
const HIDDEN: Settings = Settings {
    xor: 0x5a,
    terminator: None,
    ..Settings::DEFAULT
};

/// UTF-16BE, newline after each word, XORed. On wasm, `section = "..."`
/// makes a custom section: it's in the file but never loaded into memory.
const CUSTOM: Settings = Settings {
    encoding: Encoding::Utf16Be,
    terminator: Some('\n'),
    repeat: 1,
    xor: 0xa5,
};

contaminate!(settings = PLAIN);
contaminate!(settings = WIDE);
contaminate!(settings = HIDDEN);
contaminate!(settings = CUSTOM, section = "contaminate");
// copies:end

const COPIES: [(&str, Settings); 4] = [
    ("PLAIN", PLAIN),
    ("WIDE", WIDE),
    ("HIDDEN", HIDDEN),
    ("CUSTOM", CUSTOM),
];

fn json(value: &impl Serialize) -> String {
    serde_json::to_string(value).expect("serializing plain data can't fail")
}

fn enc_label(e: Encoding) -> &'static str {
    scan::enc_name(e, false)
}

fn parse_encodings(list: &str) -> Result<Vec<Encoding>, JsError> {
    let mut out = Vec::new();
    for e in list.split(',').filter(|e| !e.is_empty()) {
        out.push(match e {
            "utf8" => Encoding::Utf8,
            "utf16le" => Encoding::Utf16Le,
            "utf16be" => Encoding::Utf16Be,
            _ => return Err(JsError::new(&format!("unknown encoding: {e}"))),
        });
    }
    out.sort();
    out.dedup();
    Ok(out)
}

/// Key 0 (no XOR) always comes first, then the given keys.
fn with_zero(keys: &[u8]) -> Vec<u8> {
    let mut out = vec![0];
    out.extend(keys.iter().filter(|&&k| k != 0));
    out.dedup();
    out
}

/// The Rust source of the copies above, for display next to the results.
#[wasm_bindgen]
pub fn copies_source() -> String {
    let src = include_str!("lib.rs");
    // The first markers in the file are the real ones; these literals come later.
    let Some(begin) = src.find("// copies:begin\n").map(|i| i + 16) else {
        return String::new();
    };
    let end = src[begin..]
        .find("// copies:end")
        .map_or(begin, |e| begin + e);
    src[begin..end].trim_end().to_string()
}

/// The words compiled into this module, as a JSON array.
#[wasm_bindgen]
pub fn embedded_words() -> String {
    json(&WORDS.as_slice())
}

#[derive(Serialize)]
struct SettingsJson {
    encoding: &'static str,
    terminator: Option<u32>,
    repeat: usize,
    xor: u8,
}

impl From<Settings> for SettingsJson {
    fn from(s: Settings) -> Self {
        Self {
            encoding: enc_label(s.encoding),
            terminator: s.terminator.map(u32::from),
            repeat: s.repeat,
            xor: s.xor,
        }
    }
}

#[derive(Serialize)]
struct Location<'a> {
    offset: usize,
    section: &'a str,
}

#[derive(Serialize)]
struct CopyJson<'a> {
    name: &'static str,
    settings: SettingsJson,
    bytes: usize,
    found: Vec<Location<'a>>,
}

#[derive(Serialize)]
struct CopiesReport<'a> {
    format: &'static str,
    size: usize,
    sections: Vec<(&'a str, usize, usize)>,
    copies: Vec<CopyJson<'a>>,
}

/// Looks for the exact bytes of each `contaminate!` copy in `module`, which
/// should be this module's own `.wasm` file, the way the `selfcheck` example
/// does for native executables.
#[wasm_bindgen]
pub fn locate_copies(module: &[u8]) -> String {
    let sections = Sections::parse(module);
    let copies = COPIES
        .iter()
        .map(|&(name, settings)| {
            // `black_box` keeps the optimizer from folding the expected bytes into
            // a constant, which would put another copy into this module.
            let blob: Vec<u8> = std::hint::black_box(settings).encode(&WORDS).collect();
            let found = find_all(module, &blob)
                .map(|offset| Location {
                    offset,
                    section: sections.name_at(offset),
                })
                .collect();
            CopyJson {
                name,
                settings: settings.into(),
                bytes: blob.len(),
                found,
            }
        })
        .collect();
    json(&CopiesReport {
        format: Sections::format(module),
        size: module.len(),
        sections: sections
            .0
            .iter()
            .map(|(n, s, e)| (n.as_str(), *s, *e))
            .collect(),
        copies,
    })
}

fn find_all<'a>(hay: &'a [u8], needle: &'a [u8]) -> impl Iterator<Item = usize> + 'a {
    let first = needle.first().copied();
    hay.windows(needle.len().max(1))
        .enumerate()
        .filter(move |(_, w)| Some(w[0]) == first && *w == needle)
        .map(|(i, _)| i)
}

/// The bytes `contaminate!(settings = ...)` would embed for the words in
/// `words_text` (wordlist file format). `terminator` is a Unicode code point,
/// or `undefined` for none.
#[wasm_bindgen]
pub fn encode(
    words_text: &str,
    encoding: &str,
    terminator: Option<u32>,
    repeat: usize,
    xor: u8,
) -> Result<Vec<u8>, JsError> {
    let encoding = match parse_encodings(encoding)?.as_slice() {
        [e] => *e,
        _ => return Err(JsError::new("pick exactly one encoding")),
    };
    let terminator = match terminator {
        None => None,
        Some(t) => Some(char::from_u32(t).ok_or_else(|| JsError::new("bad terminator"))?),
    };
    let words: Vec<&str> = contaminate::parse_wordlist(words_text).collect();
    let settings = Settings {
        encoding,
        terminator,
        repeat: repeat.clamp(1, 64),
        xor,
    };
    Ok(settings.encode(&words).collect())
}

#[derive(Serialize)]
struct HitJson<'a> {
    offset: usize,
    section: &'a str,
    encoding: String,
    text: String,
}

#[derive(Serialize)]
struct ExtractReport<'a> {
    format: &'static str,
    total: usize,
    by_section: BTreeMap<&'a str, usize>,
    by_encoding: BTreeMap<String, usize>,
    hits: Vec<HitJson<'a>>,
}

/// Like `analyze FILE`: every printable string, with offset, section and
/// encoding. Counts cover all strings; `hits` holds at most `limit` of them.
#[wasm_bindgen]
pub fn extract(
    data: &[u8],
    min_len: usize,
    encodings: &str,
    xor_keys: &[u8],
    limit: usize,
) -> Result<String, JsError> {
    let sections = Sections::parse(data);
    let encodings = parse_encodings(encodings)?;
    let hits = scan::extract(
        data,
        &sections,
        &encodings,
        &with_zero(xor_keys),
        min_len.max(1),
    );
    let mut by_section = BTreeMap::new();
    let mut by_encoding = BTreeMap::new();
    for h in &hits {
        *by_section.entry(h.section).or_default() += 1;
        *by_encoding.entry(scan::label(h.name(), h.key)).or_default() += 1;
    }
    let total = hits.len();
    let hits = hits
        .into_iter()
        .take(limit)
        .map(|h| HitJson {
            offset: h.offset,
            section: h.section,
            encoding: scan::label(h.name(), h.key),
            text: h.text,
        })
        .collect();
    Ok(json(&ExtractReport {
        format: Sections::format(data),
        total,
        by_section,
        by_encoding,
        hits,
    }))
}

#[derive(Serialize)]
struct WordFound<'a> {
    encoding: String,
    count: usize,
    sections: BTreeMap<&'a str, usize>,
    first_offset: usize,
}

#[derive(Serialize)]
struct WordJson<'a> {
    word: &'a str,
    found: Vec<WordFound<'a>>,
}

#[derive(Serialize)]
struct WordsReport<'a> {
    format: &'static str,
    words: Vec<WordJson<'a>>,
}

/// Like `analyze -W`: searches for each word in every encoding, under every XOR
/// key for words of 8+ bytes, and under `xor_keys` for shorter ones.
#[wasm_bindgen]
pub fn find_words(data: &[u8], words_text: &str, xor_keys: &[u8]) -> String {
    let sections = Sections::parse(data);
    let words: Vec<&str> = contaminate::parse_wordlist(words_text).collect();
    let by_word = scan::find_words(
        data,
        &sections,
        &words,
        &scan::ALL_ENCODINGS,
        &with_zero(xor_keys),
    );
    let words = words
        .iter()
        .zip(by_word)
        .map(|(&word, hits)| {
            let mut found: BTreeMap<String, WordFound> = BTreeMap::new();
            for h in hits {
                let label = scan::label(h.name(), h.key);
                let f = found.entry(label.clone()).or_insert(WordFound {
                    encoding: label,
                    count: 0,
                    sections: BTreeMap::new(),
                    first_offset: h.offset,
                });
                f.count += 1;
                f.first_offset = f.first_offset.min(h.offset);
                *f.sections.entry(h.section).or_default() += 1;
            }
            WordJson {
                word,
                found: found.into_values().collect(),
            }
        })
        .collect();
    json(&WordsReport {
        format: Sections::format(data),
        words,
    })
}
