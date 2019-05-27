use beacon_chain::{BeaconChain, BeaconChainTypes};
use iron::typemap::Key;
use std::marker::PhantomData;
use std::sync::Arc;

pub struct BeaconChainKey<T> {
    _phantom: PhantomData<T>,
}

impl<T: BeaconChainTypes + 'static> Key for BeaconChainKey<T> {
    type Value = Arc<BeaconChain<T>>;
}
