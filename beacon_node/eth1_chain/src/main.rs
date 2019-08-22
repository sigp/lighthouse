use std::marker::Send;
use std::sync::Arc;
use std::time::Duration;
use tokio::prelude::*;
use web3::futures::Future;
use web3::transports::WebSocket;
use web3::types::*;
use web3::Web3;

/// Wrapper around web3 api.
/// Transport hardcoded to ws since its needed for subscribing to logs.
#[derive(Clone, Debug)]
pub struct Web3DataFetcher {
    event_loop: Arc<web3::transports::EventLoopHandle>,
    web3: Arc<web3::api::Web3<web3::transports::ws::WebSocket>>,
}

impl Web3DataFetcher {
    /// Create a new Web3 object.
    pub fn new(endpoint: &str) -> Web3DataFetcher {
        let (event_loop, transport) = WebSocket::new(endpoint).unwrap();
        let web3 = Web3::new(transport);
        Web3DataFetcher {
            event_loop: Arc::new(event_loop),
            web3: Arc::new(web3),
        }
    }
    pub fn get_current_block_number(&self) -> Box<dyn Future<Item = U256, Error = ()> + Send> {
        Box::new(
            self.web3
                .eth()
                .block_number()
                .timeout(Duration::from_secs(10))
                .map_err(|e| println!("Error getting block number {:?}", e)),
        )
    }
}

fn main() {
    let mut runtime = tokio::runtime::Runtime::new().unwrap();
    let w3 = Web3DataFetcher::new("ws://localhost:8545");
    let task = w3.get_current_block_number().and_then(move |d| {
        println!("{:?}", d);
        w3.get_current_block_number().and_then(move |d| {
            println!("{:?}", d);
            Ok(())
        })
    });
    let _ = runtime.block_on(task);
}
