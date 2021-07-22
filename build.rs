use std::io::Result;

fn main() -> Result<()> {
    prost_build::compile_protos(
        &[
            "src/proto/handshake.proto",
            "src/proto/packet.proto",
            "src/proto/message.proto",
        ],
        &["src/"],
    )?;
    Ok(())
}
