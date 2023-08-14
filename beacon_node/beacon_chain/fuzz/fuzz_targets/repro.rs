#![cfg(feature = "repro")]

mod fuzzer;
fn main() {
    fuzzer::main_func();
}
