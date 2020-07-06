pub use lighthouse_metrics::*;

lazy_static! {
    /*
     * Gossip Rx
     */
    pub static ref GOSSIP_BLOCKS_RX: Result<IntCounter> = try_create_int_counter(
        "network_gossip_blocks_rx_total",
        "Count of gossip blocks received"
    );
    pub static ref GOSSIP_UNAGGREGATED_ATTESTATIONS_RX: Result<IntCounter> = try_create_int_counter(
        "network_gossip_unaggregated_attestations_rx_total",
        "Count of gossip unaggregated attestations received"
    );
    pub static ref GOSSIP_UNAGGREGATED_ATTESTATIONS_IGNORED: Result<IntCounter> = try_create_int_counter(
        "network_gossip_unaggregated_attestations_ignored_total",
        "Count of gossip unaggregated attestations ignored by attestation service"
    );
    pub static ref GOSSIP_AGGREGATED_ATTESTATIONS_RX: Result<IntCounter> = try_create_int_counter(
        "network_gossip_aggregated_attestations_rx_total",
        "Count of gossip aggregated attestations received"
    );

    /*
     * Gossip Tx
     */
    pub static ref GOSSIP_BLOCKS_TX: Result<IntCounter> = try_create_int_counter(
        "network_gossip_blocks_tx_total",
        "Count of gossip blocks transmitted"
    );
    pub static ref GOSSIP_UNAGGREGATED_ATTESTATIONS_TX: Result<IntCounter> = try_create_int_counter(
        "network_gossip_unaggregated_attestations_tx_total",
        "Count of gossip unaggregated attestations transmitted"
    );
    pub static ref GOSSIP_AGGREGATED_ATTESTATIONS_TX: Result<IntCounter> = try_create_int_counter(
        "network_gossip_aggregated_attestations_tx_total",
        "Count of gossip aggregated attestations transmitted"
    );

    /*
     * Attestation subnet subscriptions
     */
    pub static ref SUBNET_SUBSCRIPTION_REQUESTS: Result<IntCounter> = try_create_int_counter(
        "network_subnet_subscriptions_total",
        "Count of validator subscription requests."
    );
    pub static ref SUBNET_SUBSCRIPTION_AGGREGATOR_REQUESTS: Result<IntCounter> = try_create_int_counter(
        "network_subnet_subscriptions_aggregator_total",
        "Count of validator subscription requests where the subscriber is an aggregator."
    );
}
