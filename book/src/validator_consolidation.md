# Consolidation

With the [Pectra](https://ethereum.org/en/history/#pectra) upgrade, a validator can hold a stake of up to 2048 ETH. This is done by updating the validator withdrawal credentials to type 0x02. With 0x02 withdrawal credentials, it is possible to consolidate two or more validators into a single validator with a higher stake.

Let's take a look at an example: Initially, validators A and B are both with 0x01 withdrawal credentials with 32 ETH. Let's say we want to consolidate the balance of validator B to validator A, so that the balance of validator A becomes 64 ETH. These are the steps:

1. Update the withdrawal credentials of validator A to 0x02. You can do this using [Siren](./ui.md) or the [staking launchpad](https://launchpad.ethereum.org/en/). Select:
    - source validator: validator A
    - target validator: validator A
    > Note: After the update, the withdrawal credential type 0x02 cannot be reverted to 0x01, unless the validator exits and makes a fresh deposit.

2. Perform consolidation by selecting:
    - source validator: validator B
    - target validator: validator A

   and then execute the transaction.

    Depending on the exit queue and pending consolidations, the process could take from a day to weeks. The outcome is:
    - validator A has 64 ETH
    - validator B has 0 ETH (i.e., validator B has exited the beacon chain)

The consolidation process can be repeated to consolidate more validators into validator A. The request is made by signing a transaction using the **withdrawal address** of the source validator. The withdrawal credential of the target validator can be different from the source validator.

It is important to note that there are some conditions required to perform consolidation, a few common ones are:

- both source and target validator **must be active** (i.e., not exiting or slashed).
- the _target validator_ **must** have a withdrawal credential **type 0x02**. The source validator could have a 0x01 or 0x02 withdrawal credential.
- the source validator must be active for at least 256 epochs to be able to perform consolidation.

Note that if a user were to send a consolidation transaction that does not meet the conditions, the transaction can still be accepted by the execution layer. However, the consolidation will fail once it reaches the consensus layer (where the checks are performed). Therefore, it is recommended to check that the conditions are fulfilled before sending a consolidation transaction.
