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
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Encoding {
    /// Plain UTF-8, as in Rust and most Unix programs.
    #[default]
    Utf8,
    /// UTF-16 little endian, i.e. Windows "wide" strings (`strings -e l`).
    Utf16Le,
    /// UTF-16 big endian (`strings -e b`).
    Utf16Be,
}

impl Encoding {
    /// Encodes `s` at runtime, byte for byte the way `contaminate!` does at compile
    /// time.
    pub fn encode(self, s: &str) -> impl Iterator<Item = u8> + '_ {
        s.chars().flat_map(move |c| self.char_bytes(c))
    }

    fn char_bytes(self, c: char) -> impl Iterator<Item = u8> {
        let mut buf = [0u8; 4];
        let n = encode_char(c, self, &mut buf);
        buf.into_iter().take(n)
    }
}

impl Settings {
    /// The bytes that `contaminate!(settings = self)` embeds for `words`, computed at
    /// runtime. Tools that search for an embedded copy can use this.
    pub fn encode<'a>(self, words: &'a [&'a str]) -> impl Iterator<Item = u8> + 'a {
        let Self {
            encoding,
            terminator,
            repeat,
            xor,
        } = self;
        (0..repeat)
            .flat_map(move |_| words.iter())
            .flat_map(move |w| {
                let term = terminator
                    .into_iter()
                    .flat_map(move |t| encoding.char_bytes(t));
                encoding.encode(w).chain(term)
            })
            .map(move |b| b ^ xor)
    }
}

/// Total byte length of the wordlist encoded with `s`.
#[doc(hidden)]
pub const fn encoded_len(words: &[&str], s: &Settings) -> usize {
    write(words, s, None)
}

/// The wordlist encoded with `s`. `N` must equal [`encoded_len`]. A mismatch is a
/// compile error when this runs in a const context.
#[doc(hidden)]
pub const fn encode<const N: usize>(words: &[&str], s: &Settings) -> [u8; N] {
    let mut out = [0u8; N];
    let len = write(words, s, Some(&mut out));
    assert!(len == N, "contaminate: encoded length mismatch");
    out
}

/// Encodes `words` with `s` into `out` and returns the length. With `out == None`,
/// it only measures.
const fn write(words: &[&str], s: &Settings, mut out: Option<&mut [u8]>) -> usize {
    let mut buf = [0u8; 4];
    let mut pos = 0;
    let mut copy = 0;
    while copy < s.repeat {
        let mut w = 0;
        while w < words.len() {
            let bytes = words[w].as_bytes();
            let mut i = 0;
            while i < bytes.len() {
                let (c, n) = decode_utf8(bytes, i);
                let len = encode_char(c, s.encoding, &mut buf);
                pos = put(&mut out, pos, &buf, len, s.xor);
                i += n;
            }
            if let Some(t) = s.terminator {
                let len = encode_char(t, s.encoding, &mut buf);
                pos = put(&mut out, pos, &buf, len, s.xor);
            }
            w += 1;
        }
        copy += 1;
    }
    pos
}

const fn put(out: &mut Option<&mut [u8]>, pos: usize, buf: &[u8; 4], len: usize, xor: u8) -> usize {
    if let Some(out) = out {
        let mut k = 0;
        while k < len {
            out[pos + k] = buf[k] ^ xor;
            k += 1;
        }
    }
    pos + len
}

/// Writes `c` in encoding `e` to the start of `buf` and returns the byte count.
const fn encode_char(c: char, e: Encoding, buf: &mut [u8; 4]) -> usize {
    match e {
        Encoding::Utf8 => c.encode_utf8(buf).len(),
        Encoding::Utf16Le | Encoding::Utf16Be => {
            let mut units = [0u16; 2];
            let n = c.encode_utf16(&mut units).len();
            let mut k = 0;
            while k < n {
                let b = match e {
                    Encoding::Utf16Be => units[k].to_be_bytes(),
                    _ => units[k].to_le_bytes(),
                };
                buf[2 * k] = b[0];
                buf[2 * k + 1] = b[1];
                k += 1;
            }
            2 * n
        }
    }
}

/// Decodes the char starting at `bytes[i]`. The input is a `&str`, so it's valid
/// UTF-8. Returns the char and its length in bytes. (`str::chars` isn't const.)
const fn decode_utf8(bytes: &[u8], i: usize) -> (char, usize) {
    let b0 = bytes[i] as u32;
    let (c, n) = if b0 < 0x80 {
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
    };
    match char::from_u32(c) {
        Some(c) => (c, n),
        None => panic!("invalid UTF-8"),
    }
}
