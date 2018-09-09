pub enum WireMessageType {
    Status,
    NewBlockHashes,
    GetBlockHashes,
    BlockHashes,
    GetBlocks,
    Blocks,
    NewBlock,
}


/// Determines the message type of some given
/// message.
///
/// Does not check the validity of the message data,
/// it just reads the first byte.
pub fn message_type(message: &Vec<u8>)
    -> Option<WireMessageType>
{
    match message.get(0) {
        Some(0x06) => Some(WireMessageType::Blocks),
        _ => None
    }
}
