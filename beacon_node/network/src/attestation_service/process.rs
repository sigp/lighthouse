
    /// Process a gossip message declaring a new attestation.
    ///
    /// Not currently implemented.
    pub fn on_attestation_gossip(&mut self, _peer_id: PeerId, _msg: Attestation<T::EthSpec>) {
        // TODO: Handle subnet gossip
        /*
        match self.chain.process_attestation(msg.clone()) {
            Ok(outcome) => match outcome {
                AttestationProcessingOutcome::Processed => {
                    debug!(
                        self.log,
                        "Processed attestation";
                        "source" => "gossip",
                        "peer" => format!("{:?}",peer_id),
                        "block_root" => format!("{}", msg.data.beacon_block_root),
                        "slot" => format!("{}", msg.data.slot),
                    );
                }
                AttestationProcessingOutcome::UnknownHeadBlock { beacon_block_root } => {
                    // TODO: Maintain this attestation and re-process once sync completes
                    trace!(
                    self.log,
                    "Attestation for unknown block";
                    "peer_id" => format!("{:?}", peer_id),
                    "block" => format!("{}", beacon_block_root)
                    );
                    // we don't know the block, get the sync manager to handle the block lookup
                    self.send_to_sync(SyncMessage::UnknownBlockHash(peer_id, beacon_block_root));
                }
                AttestationProcessingOutcome::FutureEpoch { .. }
                | AttestationProcessingOutcome::PastEpoch { .. }
                | AttestationProcessingOutcome::UnknownTargetRoot { .. }
                | AttestationProcessingOutcome::FinalizedSlot { .. } => {} // ignore the attestation
                AttestationProcessingOutcome::Invalid { .. }
                | AttestationProcessingOutcome::EmptyAggregationBitfield { .. }
                | AttestationProcessingOutcome::AttestsToFutureBlock { .. }
                | AttestationProcessingOutcome::InvalidSignature
                | AttestationProcessingOutcome::NoCommitteeForSlotAndIndex { .. }
                | AttestationProcessingOutcome::BadTargetEpoch { .. } => {
                    // the peer has sent a bad attestation. Remove them.
                    self.network.disconnect(peer_id, GoodbyeReason::Fault);
                }
            },
            Err(_) => {
                // error is logged during the processing therefore no error is logged here
                trace!(
                    self.log,
                    "Erroneous gossip attestation ssz";
                    "ssz" => format!("0x{}", hex::encode(msg.as_ssz_bytes())),
                );
            }
        };
        */
    }
