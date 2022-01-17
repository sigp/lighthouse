// generates error types
use error_chain::error_chain;

error_chain! {
   links  {
       Libp2p(lighthouse_network::error::Error, lighthouse_network::error::ErrorKind);
   }
}
