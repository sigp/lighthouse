mod common;
use common::behaviour::{CallTraceBehaviour, MockBehaviour};
use lighthouse_network::PeerManager;
use types::MinimalEthSpec as E;


struct Behaviour {
    pm_call_trace: CallTraceBehaviour<PeerManager<E>>,
    sibling: MockBehaviour,
}

fn doa() {
    PeerManager;
}
