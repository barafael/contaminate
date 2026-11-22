//! Collects the wordlist and generates `$OUT_DIR/words.rs`.
//!
//! Sources, all combined in this order:
//! 1. Bundled `wordlists/<name>.txt` for every enabled `wordlist-<name>` feature.
//! 2. Every file in `CONTAMINATE_WORDLIST` (one or more paths, separated like `PATH`).
//!
//! The generated file defines `BLOB`: every word as bytes, each one followed by a
//! NUL, so tools like `strings` report each word on its own line.

use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

const ENV_VAR: &str = "CONTAMINATE_WORDLIST";

fn main() {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let bundled_dir = manifest_dir.join("wordlists");

    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-changed={}", bundled_dir.display());
    println!("cargo::rerun-if-env-changed={ENV_VAR}");

    let mut words: Vec<String> = Vec::new();

    // 1. Bundled lists selected by features.
    let mut bundled: Vec<PathBuf> = fs::read_dir(&bundled_dir)
        .map(|rd| rd.filter_map(|e| Some(e.ok()?.path())).collect())
        .unwrap_or_default();
    bundled.sort();
    for path in bundled {
        if path.extension().is_none_or(|e| e != "txt") {
            continue;
        }
        let name = path.file_stem().unwrap().to_string_lossy();
        let feature_env = format!(
            "CARGO_FEATURE_WORDLIST_{}",
            name.to_uppercase().replace('-', "_")
        );
        if env::var_os(&feature_env).is_some() {
            words.extend(read_wordlist(&path));
        }
    }

    // 2. User-provided files.
    if let Some(paths) = env::var_os(ENV_VAR) {
        for path in env::split_paths(&paths).filter(|p| !p.as_os_str().is_empty()) {
            // Relative paths resolve against this crate's directory (the build script's
            // working directory). Use `[env] ... relative = true` in .cargo/config.toml
            // to have Cargo make them absolute for you.
            let path = if path.is_relative() {
                manifest_dir.join(path)
            } else {
                path
            };
            println!("cargo::rerun-if-changed={}", path.display());
            words.extend(read_wordlist(&path));
        }
    }

    if words.is_empty() {
        println!(
            "cargo::warning=contaminate: wordlist is empty; enable a `wordlist-*` feature or set {ENV_VAR}"
        );
    }

    let mut blob: Vec<u8> = Vec::new();
    for w in &words {
        blob.extend_from_slice(w.as_bytes());
        blob.push(0);
    }

    let mut out = String::new();
    writeln!(out, "/// Number of words embedded per `contaminate!()` invocation.").unwrap();
    writeln!(out, "pub const COUNT: usize = {};", words.len()).unwrap();
    writeln!(out, "/// Length of [`BLOB`] in bytes.").unwrap();
    writeln!(out, "pub const LEN: usize = {};", blob.len()).unwrap();
    writeln!(out, "/// All words, each followed by a NUL byte.").unwrap();
    writeln!(out, "pub const BLOB: [u8; LEN] = *{};", byte_str_literal(&blob)).unwrap();
    writeln!(out, "/// The words as string slices (for tests and introspection).").unwrap();
    writeln!(out, "pub const WORDS: [&str; COUNT] = {words:?};").unwrap();

    let out_path = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("words.rs");
    fs::write(out_path, out).unwrap();
}

/// One word per line. Blank lines and lines starting with `#` are skipped.
/// Leading and trailing whitespace is kept (it may be significant for a test).
/// Only a trailing `\r` is stripped.
fn read_wordlist(path: &Path) -> Vec<String> {
    let text = fs::read_to_string(path).unwrap_or_else(|e| {
        panic!("contaminate: cannot read wordlist {}: {e}", path.display())
    });
    text.lines()
        .map(|l| l.strip_suffix('\r').unwrap_or(l))
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_owned)
        .collect()
}

fn byte_str_literal(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() + 3);
    s.push_str("b\"");
    for &b in bytes {
        match b {
            b'"' => s.push_str("\\\""),
            b'\\' => s.push_str("\\\\"),
            0x20..=0x7e => s.push(b as char),
            _ => write!(s, "\\x{b:02x}").unwrap(),
        }
    }
    s.push('"');
    s
}
