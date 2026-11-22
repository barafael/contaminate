//! Collects the wordlist and generates `$OUT_DIR/words.rs`.
//!
//! Sources, all combined in this order:
//! 1. Bundled `wordlists/<name>.txt` for every enabled `wordlist-<name>` feature.
//! 2. Every file in `CONTAMINATE_WORDLIST` (one or more paths, separated like `PATH`).
//!
//! The generated file defines `WORDS`. Encoding (see `Settings`) happens at compile
//! time in each `contaminate!` invocation.

use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

#[path = "src/wordlist.rs"]
mod wordlist;

const ENV_VAR: &str = "CONTAMINATE_WORDLIST";

fn main() {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let bundled_dir = manifest_dir.join("wordlists");

    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-changed=src/wordlist.rs");
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

    let mut out = String::new();
    writeln!(out, "/// Number of words in the wordlist.").unwrap();
    writeln!(out, "pub const COUNT: usize = {};", words.len()).unwrap();
    writeln!(out, "/// The wordlist, in source order.").unwrap();
    writeln!(out, "pub const WORDS: [&str; COUNT] = {words:?};").unwrap();

    let out_path = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("words.rs");
    fs::write(out_path, out).unwrap();
}

fn read_wordlist(path: &Path) -> Vec<String> {
    let text = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("contaminate: cannot read wordlist {}: {e}", path.display()));
    wordlist::parse_wordlist(&text).map(str::to_owned).collect()
}
