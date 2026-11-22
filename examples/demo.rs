//! Build in release mode, then look for the words:
//!
//! ```sh
//! cargo build --release --example demo
//! strings target/release/examples/demo | grep CANARY_            # UTF-8 copies
//! strings -e l target/release/examples/demo | grep CANARY_       # UTF-16LE copy
//! ```

use contaminate::{Encoding, Settings, contaminate};

/// Windows-style wide strings.
const WIDE: Settings = Settings {
    encoding: Encoding::Utf16Le,
    ..Settings::DEFAULT
};

/// Invisible to plain `strings`; needs an XOR-aware tool to find.
const XORED: Settings = Settings {
    xor: 0x5a,
    terminator: None,
    ..Settings::DEFAULT
};

contaminate!();

// Mach-O section names need the `segment,section` form.
#[cfg(not(target_vendor = "apple"))]
mod nested {
    contaminate::contaminate!(section = ".data", settings = super::WIDE);
}
#[cfg(target_vendor = "apple")]
mod nested {
    contaminate::contaminate!(section = "__DATA,__data", settings = super::WIDE);
}

#[allow(dead_code)]
fn never_called() {
    contaminate!(settings = XORED);
}

fn main() {
    #[cfg(not(target_vendor = "apple"))]
    contaminate!(section = ".contaminate");
    #[cfg(target_vendor = "apple")]
    contaminate!(section = "__DATA,__contaminate");
    println!("demo: {} words per copy", contaminate::COUNT);
}
