//! Contamination settings and the compile-time encoder that applies them.

/// How a `contaminate!` invocation encodes the wordlist.
///
/// All fields are public, so a settings value can be built in a `const` with
/// struct update syntax:
///
/// ```
/// use contaminate::{Encoding, Settings};
///
/// const WIDE: Settings = Settings {
///     encoding: Encoding::Utf16Le,
///     ..Settings::DEFAULT
/// };
/// contaminate::contaminate!(settings = WIDE);
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Settings {
    /// Character encoding of the words (and of the terminator).
    pub encoding: Encoding,
    /// Character appended after every word, encoded like the word itself.
    /// `None` packs words back to back, the way rustc lays out string literals.
    pub terminator: Option<char>,
    /// How many times the whole wordlist is repeated inside one invocation.
    pub repeat: usize,
    /// Every output byte is XORed with this key. `0` leaves the bytes as they are.
    pub xor: u8,
}

impl Settings {
    /// UTF-8, NUL after each word, one copy, no XOR. Each word shows up as its
    /// own line in `strings`.
    pub const DEFAULT: Self = Self {
        encoding: Encoding::Utf8,
        terminator: Some('\0'),
        repeat: 1,
        xor: 0,
    };
}

impl Default for Settings {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Character encoding of the embedded words.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Encoding {
    /// Plain UTF-8, as in Rust and most Unix programs.
    #[default]
    Utf8,
    /// UTF-16 little endian, i.e. Windows "wide" strings (`strings -e l`).
    Utf16Le,
    /// UTF-16 big endian (`strings -e b`).
    Utf16Be,
}

/// Total byte length of the wordlist encoded with `s`.
#[doc(hidden)]
pub const fn encoded_len(words: &[&str], s: &Settings) -> usize {
    let mut per_copy = 0;
    let mut w = 0;
    while w < words.len() {
        let bytes = words[w].as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let (c, n) = decode_utf8(bytes, i);
            per_copy += char_len(c, s.encoding);
            i += n;
        }
        if let Some(t) = s.terminator {
            per_copy += char_len(t as u32, s.encoding);
        }
        w += 1;
    }
    per_copy * s.repeat
}

/// The wordlist encoded with `s`. `N` must equal [`encoded_len`]. A mismatch is a
/// compile error when this runs in a const context.
#[doc(hidden)]
pub const fn encode<const N: usize>(words: &[&str], s: &Settings) -> [u8; N] {
    let mut out = [0u8; N];
    let mut pos = 0;
    let mut copy = 0;
    while copy < s.repeat {
        let mut w = 0;
        while w < words.len() {
            let bytes = words[w].as_bytes();
            let mut i = 0;
            while i < bytes.len() {
                let (c, n) = decode_utf8(bytes, i);
                pos = put_char(&mut out, pos, c, s);
                i += n;
            }
            if let Some(t) = s.terminator {
                pos = put_char(&mut out, pos, t as u32, s);
            }
            w += 1;
        }
        copy += 1;
    }
    assert!(pos == N, "contaminate: encoded length mismatch");
    out
}

/// Decodes the char starting at `bytes[i]`. The input is a `&str`, so it's valid
/// UTF-8. Returns the code point and its length in bytes.
const fn decode_utf8(bytes: &[u8], i: usize) -> (u32, usize) {
    let b0 = bytes[i] as u32;
    if b0 < 0x80 {
        (b0, 1)
    } else if b0 < 0xE0 {
        (((b0 & 0x1F) << 6) | (bytes[i + 1] as u32 & 0x3F), 2)
    } else if b0 < 0xF0 {
        (
            ((b0 & 0x0F) << 12)
                | ((bytes[i + 1] as u32 & 0x3F) << 6)
                | (bytes[i + 2] as u32 & 0x3F),
            3,
        )
    } else {
        (
            ((b0 & 0x07) << 18)
                | ((bytes[i + 1] as u32 & 0x3F) << 12)
                | ((bytes[i + 2] as u32 & 0x3F) << 6)
                | (bytes[i + 3] as u32 & 0x3F),
            4,
        )
    }
}

const fn char_len(c: u32, e: Encoding) -> usize {
    match e {
        Encoding::Utf8 => match c {
            0..0x80 => 1,
            0x80..0x800 => 2,
            0x800..0x10000 => 3,
            _ => 4,
        },
        Encoding::Utf16Le | Encoding::Utf16Be => {
            if c < 0x10000 {
                2
            } else {
                4
            }
        }
    }
}

const fn put_char<const N: usize>(
    out: &mut [u8; N],
    mut pos: usize,
    c: u32,
    s: &Settings,
) -> usize {
    match s.encoding {
        Encoding::Utf8 => {
            let mut buf = [0u8; 4];
            let n = match char::from_u32(c) {
                Some(ch) => ch.encode_utf8(&mut buf).len(),
                None => panic!("invalid char"),
            };
            let mut k = 0;
            while k < n {
                out[pos] = buf[k] ^ s.xor;
                pos += 1;
                k += 1;
            }
        }
        Encoding::Utf16Le | Encoding::Utf16Be => {
            let mut units = [0u16; 2];
            let n = match char::from_u32(c) {
                Some(ch) => ch.encode_utf16(&mut units).len(),
                None => panic!("invalid char"),
            };
            let mut k = 0;
            while k < n {
                let b = match s.encoding {
                    Encoding::Utf16Be => units[k].to_be_bytes(),
                    _ => units[k].to_le_bytes(),
                };
                out[pos] = b[0] ^ s.xor;
                out[pos + 1] = b[1] ^ s.xor;
                pos += 2;
                k += 1;
            }
        }
    }
    pos
}
