//! Sprinkle static strings from a wordlist into a binary, for testing tools that
//! inspect binaries (`strings`, secret scanners, YARA rules, and so on).
//!
//! Each [`contaminate!`] invocation embeds its own copy of the whole wordlist as a
//! `#[used]` static. The copy survives dead-code elimination, `--gc-sections`, LTO,
//! and symbol stripping, even when the invocation sits in a function that's never
//! called. It costs nothing at runtime: [`Settings`] are applied at compile time.
//!
//! # Wordlist sources
//!
//! All sources are combined:
//! - Bundled lists, one per `wordlist-<name>` Cargo feature (see `wordlists/`).
//!   `wordlist-canary` is on by default. Use `default-features = false` to drop it,
//!   or `all-wordlists` to enable every bundled list.
//! - Files named in the `CONTAMINATE_WORDLIST` env var at build time (several paths
//!   may be separated like `PATH`).
//!
//! Format: one word per line. Blank lines and lines starting with `#` are ignored
//! (see [`parse_wordlist`]).

#![no_std]

mod settings;
mod wordlist;

pub use settings::{Encoding, Settings};
pub use wordlist::parse_wordlist;

#[doc(hidden)]
pub mod __private {
    include!(concat!(env!("OUT_DIR"), "/words.rs"));
    pub use crate::settings::{encode, encoded_len};
}

pub use __private::{COUNT, WORDS};

/// Embed one copy of the wordlist at this spot.
///
/// Works both at module level and inside function bodies. Both arguments are
/// optional and may come in either order:
///
/// - `settings = <const expr>`: a [`Settings`] value. Defaults to [`Settings::DEFAULT`].
/// - `section = "<literal>"`: link section for the bytes. Defaults to `.rodata`.
///   This one can't be part of `Settings` because `#[link_section]` only accepts
///   a string literal. Mach-O targets (macOS, iOS) need the `segment,section`
///   form, such as `"__DATA,__contaminate"`; ELF-style names like `".data"` are a
///   compile error there.
///
/// ```
/// use contaminate::{contaminate, Encoding, Settings};
///
/// contaminate!();
///
/// const HIDDEN: Settings = Settings { xor: 0x5a, terminator: None, ..Settings::DEFAULT };
///
/// fn f() {
///     #[cfg(not(target_vendor = "apple"))]
///     contaminate!(section = ".data");
///     contaminate!(settings = HIDDEN);
///     #[cfg(not(target_vendor = "apple"))]
///     contaminate!(
///         settings = Settings { encoding: Encoding::Utf16Le, repeat: 3, ..Settings::DEFAULT },
///         section = ".contaminate",
///     );
///     #[cfg(target_vendor = "apple")]
///     contaminate!(section = "__DATA,__contaminate");
/// }
/// ```
#[macro_export]
macro_rules! contaminate {
    (@emit $settings:expr; $($section:literal)?) => {
        // `macro_rules!` hygiene doesn't cover items, so `$settings` sees the names
        // declared in this block. Keep them unlikely to clash with user constants.
        // Big wordlists legitimately take a while to encode in const eval.
        #[allow(long_running_const_eval)]
        const _: () = {
            const __CONTAMINATE_SETTINGS: $crate::Settings = $settings;
            const __CONTAMINATE_LEN: usize = $crate::__private::encoded_len(
                &$crate::__private::WORDS,
                &__CONTAMINATE_SETTINGS,
            );
            #[used]
            $(#[unsafe(link_section = $section)])?
            static __CONTAMINATE: [u8; __CONTAMINATE_LEN] =
                $crate::__private::encode::<__CONTAMINATE_LEN>(
                    &$crate::__private::WORDS,
                    &__CONTAMINATE_SETTINGS,
                );
        };
    };
    () => {
        $crate::contaminate!(@emit $crate::Settings::DEFAULT;);
    };
    (settings = $settings:expr $(,)?) => {
        $crate::contaminate!(@emit $settings;);
    };
    (section = $section:literal $(,)?) => {
        $crate::contaminate!(@emit $crate::Settings::DEFAULT; $section);
    };
    (settings = $settings:expr, section = $section:literal $(,)?) => {
        $crate::contaminate!(@emit $settings; $section);
    };
    (section = $section:literal, settings = $settings:expr $(,)?) => {
        $crate::contaminate!(@emit $settings; $section);
    };
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::__private::{encode, encoded_len};
    use super::{COUNT, Encoding, Settings, WORDS};
    use std::{string::String, vec::Vec};

    const W: &[&str] = &["ab", "Grüße", "🦀"];

    fn enc<const N: usize>(s: Settings) -> [u8; N] {
        assert_eq!(encoded_len(W, &s), N);
        encode::<N>(W, &s)
    }

    #[test]
    fn default_is_nul_separated_utf8() {
        assert_eq!(&enc::<16>(Settings::DEFAULT), "ab\0Grüße\0🦀\0".as_bytes());
    }

    #[test]
    fn no_terminator_and_custom_terminator() {
        let none = Settings {
            terminator: None,
            ..Settings::DEFAULT
        };
        assert_eq!(&enc::<13>(none), "abGrüße🦀".as_bytes());
        let nl = Settings {
            terminator: Some('\n'),
            ..Settings::DEFAULT
        };
        assert_eq!(&enc::<16>(nl), "ab\nGrüße\n🦀\n".as_bytes());
    }

    #[test]
    fn utf16_both_endiannesses() {
        let expected: Vec<u16> = "ab\0Grüße\0🦀\0".encode_utf16().collect();
        let le: Vec<u8> = expected.iter().flat_map(|u| u.to_le_bytes()).collect();
        let be: Vec<u8> = expected.iter().flat_map(|u| u.to_be_bytes()).collect();
        let s = Settings {
            encoding: Encoding::Utf16Le,
            ..Settings::DEFAULT
        };
        assert_eq!(enc::<24>(s).as_slice(), le);
        let s = Settings {
            encoding: Encoding::Utf16Be,
            ..Settings::DEFAULT
        };
        assert_eq!(enc::<24>(s).as_slice(), be);
    }

    #[test]
    fn repeat_and_xor() {
        let s = Settings {
            repeat: 2,
            xor: 0xA5,
            ..Settings::DEFAULT
        };
        let got: Vec<u8> = enc::<32>(s).iter().map(|b| b ^ 0xA5).collect();
        assert_eq!(got, "ab\0Grüße\0🦀\0".repeat(2).into_bytes());
        let zero = Settings {
            repeat: 0,
            ..Settings::DEFAULT
        };
        assert_eq!(enc::<0>(zero), []);
    }

    #[test]
    fn real_wordlist_default_roundtrips() {
        const LEN: usize = encoded_len(&WORDS, &Settings::DEFAULT);
        let blob = encode::<LEN>(&WORDS, &Settings::DEFAULT);
        let joined: String = WORDS.iter().flat_map(|w| [*w, "\0"]).collect();
        assert_eq!(blob.as_slice(), joined.as_bytes());
        assert_eq!(WORDS.len(), COUNT);
    }

    #[test]
    fn runtime_encoder_matches_const() {
        macro_rules! check {
            ($($s:expr),* $(,)?) => {$({
                const S: Settings = $s;
                const LEN: usize = encoded_len(W, &S);
                let runtime: Vec<u8> = S.encode(W).collect();
                assert_eq!(runtime, encode::<LEN>(W, &S), "{S:?}");
            })*};
        }
        check!(
            Settings::DEFAULT,
            Settings {
                terminator: None,
                xor: 0x5a,
                ..Settings::DEFAULT
            },
            Settings {
                encoding: Encoding::Utf16Le,
                repeat: 3,
                ..Settings::DEFAULT
            },
            Settings {
                encoding: Encoding::Utf16Be,
                terminator: Some('🦀'),
                xor: 0xa5,
                repeat: 2
            },
        );
    }

    #[test]
    fn wordlist_format() {
        let text = "# comment\r\nalpha\r\n\n  spaced  \nbeta\r";
        let words: Vec<&str> = super::parse_wordlist(text).collect();
        assert_eq!(words, ["alpha", "  spaced  ", "beta"]);
    }

    #[test]
    fn wordlist_bom_is_skipped() {
        let text = "\u{feff}# comment\nalpha\n";
        let words: Vec<&str> = super::parse_wordlist(text).collect();
        assert_eq!(words, ["alpha"]);
    }

    #[test]
    fn settings_named_like_macro_internals() {
        #[allow(dead_code)]
        const SETTINGS: Settings = Settings {
            xor: 1,
            ..Settings::DEFAULT
        };
        #[allow(dead_code)]
        const LEN: Settings = SETTINGS;
        crate::contaminate!(settings = SETTINGS);
        crate::contaminate!(settings = LEN);
    }

    #[cfg(feature = "wordlist-canary")]
    #[test]
    fn canary_list_included() {
        assert!(WORDS.contains(&"CONTAMINATE_CANARY_7f3a9c21"));
    }
}
