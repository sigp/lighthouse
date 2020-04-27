// generates error types
use error_chain::error_chain;

error_chain! {
   links  {
       Libp2p(eth2_libp2p::error::Error, eth2_libp2p::error::ErrorKind);
   }
}
