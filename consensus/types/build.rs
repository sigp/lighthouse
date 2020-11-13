use std::env;
use std::io::Write;
use std::path::Path;

fn main() {
    let mut file =
        std::fs::File::create(&Path::new(&env::var("OUT_DIR").unwrap()).join("subnet_id_map.rs"))
            .expect("creating source file failed");
    file.write_all(b"pub fn int_to_str(i: u64) -> &'static str { match i {")
        .expect("Writing source file failed");
    for i in 0..64 {
        file.write_all(i.to_string().as_bytes())
            .expect("Writing source file failed");
        file.write_all(b" => \"")
            .expect("Writing source file failed");
        file.write_all(i.to_string().as_bytes())
            .expect("Writing source file failed");
        file.write_all(b"\",").expect("Writing source file failed");
    }
    file.write_all(b"_ => \"out of range\" }}")
        .expect("Writing source file failed");
}
