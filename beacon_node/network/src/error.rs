// generates error types
use libp2p;

use error_chain::{
    error_chain, error_chain_processing, impl_error_chain_kind, impl_error_chain_processed,
    impl_extract_backtrace,
};

error_chain! {
   links  {
       Libp2p(libp2p::error::Error, libp2p::error::ErrorKind);
   }
}
