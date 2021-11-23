#[allow(dead_code)]
const PROTOS: [&str; 4] = [
    "proto/messages.proto",
    "proto/messages-common.proto",
    "proto/messages-management.proto",
    "proto/messages-bitcoin.proto",
];

fn main() {
    // for proto in PROTOS.iter() {
    //     // rerun this build script if the given files changes
    //     println!("cargo:rerun-if-changed={}", proto);
    // }
    //
    // protoc_rust::Codegen::new()
    //     .out_dir("src/proto")
    //     .inputs(&PROTOS)
    //     .include("proto")
    //     .run()
    //     .expect("protoc");
}
