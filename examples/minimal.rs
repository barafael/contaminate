//! The smallest possible use: one copy of the wordlist with default settings.
//!
//! ```sh
//! cargo build --release --example minimal
//! strings target/release/examples/minimal | grep CANARY_
//! ```

contaminate::contaminate!();

fn main() {
    println!("hello from a contaminated binary");
}
