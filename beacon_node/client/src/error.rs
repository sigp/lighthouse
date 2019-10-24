use network;

use common::error_chain::error_chain;

error_chain! {
   links  {
       Network(network::error::Error, network::error::ErrorKind);
   }
}
