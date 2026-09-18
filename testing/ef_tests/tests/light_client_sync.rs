#![cfg(feature = "ef_tests")]

use ef_tests::{Handler, LightClientSyncHandler};
use types::MinimalEthSpec;

#[test]
fn light_client_sync() {
    // The official sync generator only emits minimal-preset cases.
    LightClientSyncHandler::<MinimalEthSpec>::default().run();
}
