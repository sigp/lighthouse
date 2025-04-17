pub const TRUSTED_SETUP_BYTES: &[u8] = include_bytes!("../trusted_setup.json");

pub fn get_trusted_setup() -> Vec<u8> {
    TRUSTED_SETUP_BYTES.into()
}
