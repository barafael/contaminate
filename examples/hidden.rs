//! Copies that plain `strings` won't show: XOR-obfuscated, UTF-16 without
//! terminators, and both combined. A tool has to try other encodings and brute-force
//! XOR keys to find them.
//!
//! ```sh
//! cargo build --release --example hidden --example analyze
//! strings target/release/examples/hidden | grep -c CANARY_              # 0
//! target/release/examples/analyze -w target/release/examples/hidden    # finds all
//! ```

use contaminate::{Encoding, Settings, contaminate};

contaminate!(
    settings = Settings {
        xor: 0x5a,
        terminator: None,
        ..Settings::DEFAULT
    }
);

contaminate!(
    settings = Settings {
        encoding: Encoding::Utf16Be,
        terminator: None,
        ..Settings::DEFAULT
    }
);

contaminate!(
    settings = Settings {
        encoding: Encoding::Utf16Le,
        xor: 0xc3,
        terminator: None,
        ..Settings::DEFAULT
    }
);

fn main() {
    println!("nothing to see here");
}
