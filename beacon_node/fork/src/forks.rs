///! List of known forks

// Add known forks to this mapping in slot order.
/// List of known forks. The format is (Fork Name, Slot to be activated, Fork Version).
pub const KNOWN_FORKS: [(&'static str, u64, [u8; 4]); 1] = [("genesis", 0, [0, 0, 0, 0])];
