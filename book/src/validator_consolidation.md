# Consolidation

With [Pectra](https://ethereum.org/en/history/#pectra) upgrade, the effective balance of a validator can be up to 2048 ETH. This is done by updating the validator withdrawal credential to type 0x02.

With 0x02 withdrawal credential, it is therefore possible to consolidate two or more validators into a single validator with a higher effective balance. Let's take a look at an example: Initially, validators A and B are both with 0x01 withdrawal credentials with 32 ETH. Say we want to consolidate the balance of validator B to the balance of validator A, so that the balance of validator A becomes 64 ETH. These are the steps:

1. Update the withdrawal credential of validator A to 0x02. You can do this using [Siren](./ui.md) or the staking launchpad. Select:
    - source validator: validator A
    - target validator: validator A
    > Note: A validator with withdrawal credential type 0x02 cannot be reverted to 0x01, except that the validator exits and make a fresh deposit.

2. Perform consolidation by selecting:
    - source validator: validator B
    - target validator: validator A
   and then execute the transaction.

    Depending on the exit and deposit queue, the process could take from a day to weeks. The outcome is:
    - validator A has 64 ETH
    - validator B has 0 ETH (i.e., validator B has exited the beacon chain)

The consolidation process can be repeated to consolidate more validators into validator A.

It is important to note that there are some conditions required to perform consolidation, a few common ones are:

- the **withdrawal address** of the source and target validators **must be the same**.
- the _target validator_ **must** have a withdrawal credential **type 0x02**. The source validator could have a 0x01 or 0x02 withdrawal credential.
- the source validator must be active for at least 256 epochs to be able to perform consolidation.

Note that if a user were to send a consolidation transaction that does not meet one or more of the conditions, the transaction can still be accepted by the execution layer. However, the consolidation will fail once it reaches the consensus layer (where the checks are performed). Therefore, it is recommended to check that the conditions are fulfilled before sending a consolidation transaction.
