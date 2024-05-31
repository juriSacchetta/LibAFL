mod fuzzer;
mod client;
mod options;
mod version;
mod instance;
mod harness;

use crate::fuzzer::Fuzzer;

pub fn main() {
    Fuzzer::new().fuzz().unwrap();
}