use crate::{
    engine_api::{http::ENGINE_GET_BLOBS_V1, Error},
    BlobTransactionId, GetBlobsResponse,
};
use jsonrpsee::{
    core::client::{Client, ClientT},
    rpc_params,
};
use reth_ipc::client::IpcClientBuilder;
use types::EthSpec;

pub struct Ipc {
    client: Client,
}

impl Ipc {
    pub async fn new(path: &str) -> Result<Self, Error> {
        let client = IpcClientBuilder::default().build(path).await?;
        Ok(Self { client })
    }

    pub async fn get_blobs<E: EthSpec>(
        &self,
        blob_ids: Vec<BlobTransactionId>,
    ) -> Result<GetBlobsResponse<E>, Error> {
        let params = rpc_params!([blob_ids]);

        let response = self.client.request(ENGINE_GET_BLOBS_V1, params).await?;
        Ok(response)
    }
}
