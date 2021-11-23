#[derive(Debug)]
pub enum Error {
    Postgres(tokio_postgres::Error),
    MissingParameter(&'static str),
    InvalidSlot,
    InvalidRoot,
    SensitiveUrl(eth2::SensitiveError),
    BeaconNode(eth2::Error),
    RemoteHeadUnknown,
}

impl From<tokio_postgres::Error> for Error {
    fn from(e: tokio_postgres::Error) -> Self {
        Error::Postgres(e)
    }
}

impl From<eth2::Error> for Error {
    fn from(e: eth2::Error) -> Self {
        Error::BeaconNode(e)
    }
}
