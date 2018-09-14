pub enum WireMessageDecodeError {
    TooShort,
    UnknownType,
}

pub enum WireMessageHeader {
    Status,
    NewBlockHashes,
    GetBlockHashes,
    BlockHashes,
    GetBlocks,
    Blocks,
    NewBlock,
}

pub struct WireMessage<'a> {
    pub header: WireMessageHeader,
    pub body: &'a [u8],
}

impl<'a> WireMessage<'a> {
    pub fn decode(bytes: &'a Vec<u8>)
        -> Result<Self, WireMessageDecodeError>
    {
        if let Some((header_byte, body)) = bytes.split_first() {
            let header = match header_byte {
                0x06 => Some(WireMessageHeader::Blocks),
                _ => None
            };
            match header {
                Some(header) => Ok(Self{header, body}),
                None => Err(WireMessageDecodeError::UnknownType)
            }
        } else {
            Err(WireMessageDecodeError::TooShort)
        }
    }
}

/*
pub fn decode_wire_message(bytes: &[u8])
    -> Result<WireMessage, WireMessageDecodeError>
{
    if let Some((header_byte, body)) = bytes.split_first() {
        let header = match header_byte {
            0x06 => Some(WireMessageType::Blocks),
            _ => None
        };
        match header {
            Some(header) => Ok((header, body)),
            None => Err(WireMessageDecodeError::UnknownType)
        }
    } else {
        Err(WireMessageDecodeError::TooShort)
    }
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

pub fn identify_wire_protocol_message(message: &Vec<u8>)
    -> Result<(WireMessageType, &[u8]), WireMessageDecodeError>
{
    fn strip_header(v: &Vec<u8>) -> &[u8] {
        match v.get(1..v.len()) {
            None => &vec![],
            Some(s) => s
        }
    }

    match message.get(0) {
        Some(0x06) => Ok((WireMessageType::Blocks, strip_header(message))),
        None => Err(WireMessageDecodeError::TooShort),
        _ => Err(WireMessageDecodeError::UnknownType),
    }
}
*/
