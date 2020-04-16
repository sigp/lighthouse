# Frequently Asked Questions

## Why does it take so long for a validator to be activated?

After validators create their Eth1 deposit transaction there are two waiting
periods before they can start producing blocks and attestations:

1. Waiting for the beacon chain to recognise the Eth1 block containing the
   deposit (generally 4 to 7.4 hours).
1. Waiting in the queue for validator activation (generally 6.4 minutes for
   every 4 validators in the queue).

Detailed answers below:

### 1. Waiting for the beacon chain to detect the Eth1 deposit

Since the beacon chain uses Eth1 for validator on-boarding, beacon chain
validators must listen to event logs from the deposit contract. Since the
latest blocks of the Eth1 chain are vulnerable to re-orgs due to minor network
partitions, beacon nodes follow the Eth1 chain at a distance of 1,024 blocks
(~4 hours) (see
[`ETH1_FOLLOW_DISTANCE`](https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/specs/phase0/validator.md#misc)).
This follow distance protects the beacon chain from on-boarding validators that
are likely to be removed due to an Eth1 re-org.

Now we know there's a 4 hours delay before the beacon nodes even _consider_ an
Eth1 block. Once they _are_ considering these blocks, there's a voting period
where beacon validators vote on which Eth1 to include in the beacon chain. This
period is defined as 32 epochs (~3.4 hours, see
[`ETH1_VOTING_PERIOD`](https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/specs/phase0/beacon-chain.md#time-parameters)).
During this voting period, each beacon block producer includes an
[`Eth1Data`](https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/specs/phase0/beacon-chain.md#eth1data)
in their block which counts as a vote towards what that validator considers to
be the head of the Eth1 chain at the start of the voting period (with respect
to `ETH1_FOLLOW_DISTANCE`, of course). You can see the exact voting logic
[here](https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/specs/phase0/validator.md#eth1-data).

These two delays combined represent the time between an Eth1 deposit being
included in an Eth1 data vote and that validator appearing in the beacon chain.
The `ETH1_FOLLOW_DISTANCE` delay causes a minimum delay of ~4 hours and
`ETH1_VOTING_PERIOD` means that if a validator deposit happens just _before_
the start of a new voting period then they might not notice this delay at all.
However, if the validator deposit happens just _after_ the start of the new
voting period the validator might have to wait ~3.4 hours for next voting
period. In times of very, very severe network issues, the network may even fail
to vote in new Eth1 blocks, stopping all new validator deposits!

> Note: you can see the list of validators included in the beacon chain using
> our REST API: [/beacon/validators/all](./http_beacon.md#beaconvalidatorsall)

### 2. Waiting for a validator to be activated

If a validator has provided an invalid public key or signature, they will
_never_ be activated or even show up in
[/beacon/validators/all](https://lighthouse-book.sigmaprime.io/http_beacon.html#beaconvalidatorsall).
They will simply be forgotten by the beacon chain! But, if those parameters were
correct, once the Eth1 delays have elapsed and the validator appears in the
beacon chain, there's _another_ delay before the validator becomes "active"
(canonical definition
[here](https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/specs/phase0/beacon-chain.md#is_active_validator)) and can start producing blocks and attestations.

Firstly, the validator won't become active until their beacon chain balance is
equal to or greater than
[`MAX_EFFECTIVE_BALANCE`](https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/specs/phase0/beacon-chain.md#gwei-values)
(32 ETH on mainnet, usually 3.2 ETH on testnets). Once this balance is reached,
the validator must wait until the start of the next epoch (up to 6.4 minutes)
for the
[`process_registry_updates`](https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/specs/phase0/beacon-chain.md#registry-updates)
routine to run. This routine activates validators with respect to a [churn
limit](https://github.com/ethereum/eth2.0-specs/blob/v0.11.1/specs/phase0/beacon-chain.md#get_validator_churn_limit);
it will only allow the number of validators to increase (churn) by a certain
amount. Up until there are about 330,000 validators this churn limit is set to
4 and it starts to very slowly increase as the number of validators increases
from there.

If a new validator isn't within the churn limit from the front of the queue,
they will need to wait another epoch (6.4 minutes) for their next chance. This
repeats until the queue is cleared.

Once a validator has been activated, there's no more waiting! It's time to
produce blocks and attestations!
