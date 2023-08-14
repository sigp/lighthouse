#![cfg(feature = "afl")]

mod fuzzer;
fn main() {
    fuzzer::main_func();
}
