pub enum SyncEventType {
    Invalid,
    PeerConnect,
    PeerDrop,
    ReceiveBlocks,
    ReceiveAttestationRecords,
}

pub struct SyncEvent {
    event: SyncEventType,
    data: Option<Vec<u8>>
}
