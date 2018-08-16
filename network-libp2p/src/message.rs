#[derive(Debug)]
pub enum NetworkEventType {
    PeerConnect,
    PeerDrop,
    Message,
}

#[derive(Debug)]
pub struct NetworkEvent {
    pub event: NetworkEventType,
    pub data: Option<Vec<u8>>,
}

#[derive(Debug)]
pub struct OutgoingMessage {
    pub peer: Option<String>,
    pub data: Vec<u8>,
}
