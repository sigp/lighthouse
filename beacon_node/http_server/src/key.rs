use crate::metrics::LocalMetrics;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use iron::typemap::Key;
use prometheus::Registry;
use std::marker::PhantomData;
use std::path::PathBuf;
use std::sync::Arc;

pub struct BeaconChainKey<T> {
    _phantom: PhantomData<T>,
}

impl<T: BeaconChainTypes + 'static> Key for BeaconChainKey<T> {
    type Value = Arc<BeaconChain<T>>;
}

pub struct MetricsRegistryKey;

impl Key for MetricsRegistryKey {
    type Value = Registry;
}

pub struct LocalMetricsKey;

impl Key for LocalMetricsKey {
    type Value = LocalMetrics;
}

pub struct DBPathKey;

impl Key for DBPathKey {
    type Value = PathBuf;
}
