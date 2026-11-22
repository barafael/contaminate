//! The wordlist file format. `build.rs` includes this file too, via `#[path]`, so
//! the build and the runtime parse lists the same way. Keep it free of crate items.

/// Parses wordlist text: one word per line. Blank lines and lines starting with `#`
/// are skipped. A leading UTF-8 byte order mark is ignored. Line endings (`\n` or
/// `\r\n`) are stripped, but all other whitespace is kept, because it may be
/// significant for a test.
pub fn parse_wordlist(text: &str) -> impl Iterator<Item = &str> {
    text.strip_prefix('\u{feff}')
        .unwrap_or(text)
        .lines()
        .map(|l| l.strip_suffix('\r').unwrap_or(l))
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
}
