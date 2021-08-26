#[cfg(test)]
mod tests {
    use std::env;

    #[test]
    fn it_works() {
        let out_dir = env::var("OUT_DIR").unwrap();
        panic!(out_dir);
    }
}
