extern crate protoc_grpcio;

use std::path::Path;

fn main() {
    let proto_root = Path::new("src");
    println!("cargo:rerun-if-changed={}", proto_root.display());
    protoc_grpcio::compile_grpc_protos(&["services.proto"], &[proto_root], &proto_root)
        .expect("Failed to compile gRPC definitions!");
}
