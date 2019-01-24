extern crate protoc_grpcio;

fn main() {
    let proto_root = &format!("{}{}", "src", std::path::MAIN_SEPARATOR);
    println!("cargo:rerun-if-changed={}", proto_root);
    protoc_grpcio::compile_grpc_protos(&["services.proto"], &[proto_root], &proto_root)
        .expect("Failed to compile gRPC definitions!");
}
