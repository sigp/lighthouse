// generates error types
use eth2_libp2p;

use error_chain::{
    error_chain, error_chain_processing, impl_error_chain_kind, impl_error_chain_processed,
    impl_extract_backtrace,
};

error_chain! {
   links  {
       Libp2p(eth2_libp2p::error::Error, eth2_libp2p::error::ErrorKind);
   }
}
