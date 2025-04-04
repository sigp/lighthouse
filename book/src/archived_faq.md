# Archived FAQ

Note: The following FAQ is valid for mainnet before Electra. After Electra, [EIP6110 Supply validator deposits on chain](Supply validator deposits on chain) is implemented and the time taken to activate a validator can be as fast as 13 minutes.

## Why does it take so long for a validator to be activated?

After validators create their execution layer deposit transaction there are two waiting
periods before they can start producing blocks and attestations:

1. Waiting for the beacon chain to recognise the execution layer block containing the
   deposit (generally takes ~13.6 hours).
1. Waiting in the queue for validator activation.

Detailed answers below:

### 1. Waiting for the beacon chain to detect the execution layer deposit

Since the beacon chain uses the execution layer for validator on-boarding, beacon chain
validators must listen to event logs from the deposit contract. Since the
latest blocks of the execution chain are vulnerable to re-orgs due to minor network
partitions, beacon nodes follow the execution chain at a distance of 2048 blocks
(~6.8 hours) (see
[`ETH1_FOLLOW_DISTANCE`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/validator.md#process-deposit)).
This follow distance protects the beacon chain from on-boarding validators that
are likely to be removed due to an execution chain re-org.

Now we know there's a 6.8 hours delay before the beacon nodes even _consider_ an
execution layer block. Once they _are_ considering these blocks, there's a voting period
where beacon validators vote on which execution block hash to include in the beacon chain. This
period is defined as 64 epochs (~6.8 hours, see
[`ETH1_VOTING_PERIOD`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#time-parameters)).
During this voting period, each beacon block producer includes an
[`Eth1Data`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#eth1data)
in their block which counts as a vote towards what that validator considers to
be the head of the execution chain at the start of the voting period (with respect
to `ETH1_FOLLOW_DISTANCE`, of course). You can see the exact voting logic
[here](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/validator.md#eth1-data).

These two delays combined represent the time between an execution layer deposit being
included in an execution data vote and that validator appearing in the beacon chain.
The `ETH1_FOLLOW_DISTANCE` delay causes a minimum delay of ~6.8 hours and
`ETH1_VOTING_PERIOD` means that if a validator deposit happens just _before_
the start of a new voting period then they might not notice this delay at all.
However, if the validator deposit happens just _after_ the start of the new
voting period the validator might have to wait ~6.8 hours for next voting
period. In times of very severe network issues, the network may even fail
to vote in new execution layer blocks, thus stopping all new validator deposits and causing the wait to be longer.

### 2. Waiting for a validator to be activated

If a validator has provided an invalid public key or signature, they will
_never_ be activated.
They will simply be forgotten by the beacon chain! But, if those parameters were
correct, once the execution layer delays have elapsed and the validator appears in the
beacon chain, there's _another_ delay before the validator becomes "active"
(canonical definition
[here](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#is_active_validator)) and can start producing blocks and attestations.

Firstly, the validator won't become active until their beacon chain balance is
equal to or greater than
[`MAX_EFFECTIVE_BALANCE`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#gwei-values)
(32 ETH on mainnet, usually 3.2 ETH on testnets). Once this balance is reached,
the validator must wait until the start of the next epoch (up to 6.4 minutes)
for the
[`process_registry_updates`](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#registry-updates)
routine to run. This routine activates validators with respect to a [churn
limit](https://github.com/ethereum/consensus-specs/blob/v1.3.0/specs/phase0/beacon-chain.md#get_validator_churn_limit);
it will only allow the number of validators to increase (churn) by a certain
amount. If a new validator isn't within the churn limit from the front of the queue,
they will need to wait another epoch (6.4 minutes) for their next chance. This
repeats until the queue is cleared. The churn limit for validators joining the beacon chain is capped at 8 per epoch or 1800 per day. If, for example, there are 9000 validators waiting to be activated, this means that the waiting time can take up to 5 days.

Once a validator has been activated, congratulations! It's time to
produce blocks and attestations!
