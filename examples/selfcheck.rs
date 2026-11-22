//! Reads its own executable and checks that its embedded copy of the wordlist
//! survived compilation, linking and stripping. Exits non-zero if it didn't.
//!
//! Handy for trying out profiles and linker flags:
//!
//! ```sh
//! RUSTFLAGS="-C lto=fat -C strip=symbols" cargo run --release --example selfcheck
//! ```
//!
//! The copy uses distinctive settings (UTF-16BE, XOR, newline terminator). That way
//! the check can't be fooled by the plain `WORDS` strings this program also contains.
//! Any `CHECK` works: the expected bytes come from `Settings::encode`.

use contaminate::{Encoding, Settings, WORDS, contaminate};
use std::process::ExitCode;

const CHECK: Settings = Settings {
    encoding: Encoding::Utf16Be,
    terminator: Some('\n'),
    repeat: 1,
    xor: 0xa5,
};

/// Never called. The copy inside must survive anyway.
#[allow(dead_code)]
fn unreachable_copy() {
    contaminate!(settings = CHECK);
}

/// Recomputes at runtime the bytes the macro produced at compile time.
/// `black_box` keeps the optimizer from folding the result into a constant, which
/// would put a second copy of the expected bytes into the binary.
fn expected_blob() -> Vec<u8> {
    std::hint::black_box(CHECK).encode(&WORDS).collect()
}

fn main() -> ExitCode {
    let exe = match std::env::current_exe().and_then(std::fs::read) {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("selfcheck: cannot read own executable: {e}");
            return ExitCode::from(2);
        }
    };
    let blob = expected_blob();
    if blob.is_empty() {
        eprintln!("selfcheck: wordlist is empty, nothing to check");
        return ExitCode::from(2);
    }
    match exe.windows(blob.len()).position(|w| w == blob) {
        Some(off) => {
            println!(
                "selfcheck: OK, {} words ({} bytes) found at offset {off:#x}",
                WORDS.len(),
                blob.len()
            );
            ExitCode::SUCCESS
        }
        None => {
            println!("selfcheck: FAILED, embedded wordlist not found in executable");
            ExitCode::FAILURE
        }
    }
}
