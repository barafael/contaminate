# contaminate

Sprinkle static strings from a wordlist into a binary, for testing tools that
inspect binaries: `strings`, secret scanners, YARA rules, AV, threat-intel
extractors, and LLM-based analysis agents.

Each `contaminate!()` invocation embeds its own copy of the whole wordlist as
a `#[used]` static. The copy survives dead-code elimination, `--gc-sections`,
LTO, and symbol stripping — even when the invocation sits in a function that
is never called. Encoding happens at compile time, so it costs nothing at
runtime. `no_std`, no dependencies.

## Quick start

```toml
[dependencies]
contaminate = "0.1"
```

```rust
contaminate::contaminate!();
```

Build in release mode and look for the words:

```sh
cargo build --release
strings target/release/your-binary | grep CONTAMINATE
```

The default feature embeds the `canary` list: a handful of unique markers that
are easy to grep for. Enable more lists with features, or every list at once:

```toml
contaminate = { version = "0.1", features = ["all-wordlists"] }
```

## Wordlist sources

All sources are combined, in this order:

1. **Bundled lists** — one per `wordlist-<name>` Cargo feature (see the table
   below). `wordlist-canary` is on by default; `default-features = false`
   drops it.
2. **Your own files** — set `CONTAMINATE_WORDLIST` at build time to one or
   more file paths, separated like `PATH`. Relative paths resolve against the
   `contaminate` crate directory; use `[env] ... relative = true` in
   `.cargo/config.toml` to have Cargo make them absolute for you.

File format: one word per line. Blank lines and lines starting with `#` are
ignored; everything else, including leading and trailing whitespace, is kept
verbatim.

## Bundled lists

| Feature | Words | Contents |
| --- | --- | --- |
| `wordlist-canary` | 4 | Unique markers that are easy to grep for (default) |
| `wordlist-artifacts` | 16 | CI workspace paths, PDB paths, compiler banners |
| `wordlist-chembio` | 73 | Chem/bio agent names, treaty designations, incident names |
| `wordlist-crypto` | 15 | Cryptocurrency addresses from spec test vectors |
| `wordlist-cve` | 22 | Famous CVE IDs, nicknames, probe formats |
| `wordlist-edge-cases` | 17 | Boundary probes: short/long strings, whitespace, format specifiers |
| `wordlist-evade` | 47 | Sandbox/VM detection artifacts, anti-debug APIs |
| `wordlist-hashes` | 15 | Known file hashes and the EICAR test signature |
| `wordlist-llm-tripwire` | 31 | Fictional shape-only CBRN text; see [Notes](#notes) |
| `wordlist-network` | 15 | IOCs using only RFC-reserved names and ranges |
| `wordlist-paths` | 15 | Filesystem paths and registry keys |
| `wordlist-phishing` | 21 | Spoofed display names, lookalike domains, lure phrases |
| `wordlist-pii` | 24 | Test card numbers, fictional phone numbers, example IBANs |
| `wordlist-secrets` | 15 | Documented example credentials and key headers |
| `wordlist-suspicious` | 22 | Injection APIs and malicious-looking command lines |
| `wordlist-unicode` | 15 | Non-ASCII UTF-8, invisible characters, RTL override |
| `all-wordlists` | 367 | Everything above |

## Encoding

A `const Settings` controls how each copy is encoded:

```rust
use contaminate::{contaminate, Encoding, Settings};

/// Windows-style wide strings: find with `strings -e l`.
const WIDE: Settings = Settings {
    encoding: Encoding::Utf16Le, // Utf8 (default), Utf16Le, Utf16Be
    ..Settings::DEFAULT
};

/// Invisible to plain `strings`: no terminator, XOR-obfuscated.
const XORED: Settings = Settings {
    xor: 0x5a,
    terminator: None, // Some('\0') (default), any char, or None
    repeat: 1,        // copies of the whole list inside one invocation
    ..Settings::DEFAULT
};

contaminate!(settings = WIDE);
contaminate!(settings = XORED, section = ".data");
```

`section = "..."` puts the bytes in a specific link section (default
`.rodata`). It must stay a string literal — `#[link_section]` requires one —
which is why it is a macro argument rather than a `Settings` field.

## Examples

| Example | What it shows |
|---|---|
| `minimal` | One `contaminate!()` with default settings |
| `demo` | Four copies with different settings and sections in one binary |
| `hidden` | Only XOR'd and UTF-16 copies; plain `strings` finds none of them |
| `selfcheck` | Reads its own executable and exits non-zero if its copy didn't survive the build |
| `analyze` | A `strings`-style analyzer: UTF-8/UTF-16LE/UTF-16BE, XOR keys, ELF section labels, and a wordlist check mode |

```sh
cargo build --release --examples
E=target/release/examples

strings $E/demo | grep CANARY_                # UTF-8 copies
$E/analyze $E/demo | grep -i canary          # every copy, with offset, section and encoding
$E/analyze -x 0x5a $E/hidden                  # also decode with XOR key 0x5a
$E/analyze -s $E/demo                         # counts per section and encoding
$E/analyze -w $E/hidden                       # find every word under any encoding/XOR key; exit 1 if any is missing
RUSTFLAGS="-C lto=fat -C strip=symbols" cargo run --release --example selfcheck
```

`analyze -W FILE` checks for the words in any wordlist file instead of the one
compiled in. ASCII UTF-16LE and UTF-16BE are the same bytes shifted by one,
so `analyze` reports such matches as `utf16le|be`.

## Notes

- **All list content is inert text.** Entries are public constants, spec test
  vectors, documented example values, RFC-reserved names, and encyclopedic
  facts. Nothing points at a real host, credential, or person, and no entry
  contains procedural information.
- `wordlist-hashes` embeds the **EICAR test signature**, so binaries built
  with it may be quarantined by local AV.
- `wordlist-llm-tripwire` embeds fictional agents, compounds and scenarios
  written in the *shape* of real procedures and classified documents. It
  carries zero real information; it exists to test whether LLM-based
  inspection agents over-refuse when `strings` output looks alarming, plus a
  few prompt-injection probes for agents that treat binary strings as trusted
  text.
- `strings` only shows ASCII by default; for the unicode and UTF-16 lists try
  `strings -e S`, `strings -e l`, or `grep -a`.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <http://opensource.org/licenses/MIT>)

at your option.
