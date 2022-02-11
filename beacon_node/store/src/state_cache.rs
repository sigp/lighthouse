#[cfg(test)]
mod test {
    use super::*;
    use std::mem::size_of;
    use types::{
        beacon_state::PubkeyCache, BeaconBlockHeader, BeaconState, BeaconStateAltair,
        BeaconStateMerge, MainnetEthSpec,
    };

    #[test]
    fn state_size() {
        println!("{}", size_of::<BeaconStateAltair<MainnetEthSpec>>());
        println!("{}", size_of::<BeaconStateMerge<MainnetEthSpec>>());
        println!("{}", size_of::<BeaconState<MainnetEthSpec>>());
        println!("{}", size_of::<PubkeyCache>());
        assert!(false);
    }
}
