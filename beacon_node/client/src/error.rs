// generates error types
use network;

use error_chain::{
    error_chain, error_chain_processing, impl_error_chain_kind, impl_error_chain_processed,
    impl_extract_backtrace,
};

error_chain! {
   links  {
       Network(network::error::Error, network::error::ErrorKind);
   }

}
