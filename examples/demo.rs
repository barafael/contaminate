//! Build in release mode, then look for the words:
//!
//! ```sh
//! cargo build --release --example demo
//! strings target/release/examples/demo | grep CONTAMINATE
//! ```

use contaminate::contaminate;

contaminate!();

mod nested {
    contaminate::contaminate!(section = ".data");
}

#[allow(dead_code)]
fn never_called() {
    contaminate!();
}

fn main() {
    contaminate!(section = ".contaminate");
    println!("demo: {} words per copy", contaminate::COUNT);
}
