//! Sprinkle static strings from a wordlist into a binary, for testing tools that
//! inspect binaries (`strings`, secret scanners, YARA rules, and so on).
//!
//! Each [`contaminate!`] invocation embeds its own copy of the whole wordlist as a
//! `#[used]` static. The copy survives dead-code elimination, `--gc-sections`, LTO,
//! and symbol stripping, even when the invocation sits in a function that's never
//! called. It costs nothing at runtime.
//!
//! # Wordlist sources
//!
//! All sources are combined:
//! - Bundled lists, one per `wordlist-<name>` Cargo feature (see `wordlists/`).
//!   `wordlist-canary` is on by default. Use `default-features = false` to drop it.
//! - Files named in the `CONTAMINATE_WORDLIST` env var at build time (several paths
//!   may be separated like `PATH`).
//!
//! Format: one word per line. Blank lines and lines starting with `#` are ignored.

#![no_std]

#[doc(hidden)]
pub mod __private {
    include!(concat!(env!("OUT_DIR"), "/words.rs"));
}

pub use __private::{COUNT, WORDS};

/// Embed one copy of the wordlist at this spot.
///
/// Works both at module level and inside function bodies.
///
/// ```
/// contaminate::contaminate!();
///
/// fn f() {
///     contaminate::contaminate!();
///     // Put the bytes in a specific section, e.g. writable data:
///     contaminate::contaminate!(section = ".data");
/// }
/// ```
///
/// Each copy holds every word followed by a NUL byte, inline in the static. With no
/// `section`, the copy goes to `.rodata`.
#[macro_export]
macro_rules! contaminate {
    () => {
        const _: () = {
            #[used]
            static CONTAMINATE: [u8; $crate::__private::LEN] = $crate::__private::BLOB;
        };
    };
    (section = $section:literal) => {
        const _: () = {
            #[used]
            #[unsafe(link_section = $section)]
            static CONTAMINATE: [u8; $crate::__private::LEN] = $crate::__private::BLOB;
        };
    };
}

#[cfg(test)]
mod tests {
    use super::__private::{BLOB, COUNT, LEN, WORDS};

    #[test]
    fn blob_matches_words() {
        assert_eq!(WORDS.len(), COUNT);
        let parts: [&[u8]; COUNT] = {
            let mut it = BLOB[..LEN.saturating_sub(1)].split(|&b| b == 0);
            core::array::from_fn(|_| it.next().unwrap())
        };
        for (p, w) in parts.iter().zip(WORDS) {
            assert_eq!(*p, w.as_bytes());
        }
    }

    #[cfg(feature = "wordlist-canary")]
    #[test]
    fn canary_list_included() {
        assert!(WORDS.contains(&"CONTAMINATE_CANARY_7f3a9c21"));
    }
}
