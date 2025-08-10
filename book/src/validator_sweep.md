# Validator "Sweeping" (Automatic Partial Withdrawals)

After the [Capella](https://ethereum.org/en/history/#capella) upgrade on 12<sup>th</sup> April 2023:

- if a validator has a withdrawal credential type `0x00`, the rewards will continue to accumulate and will be locked in the beacon chain.
- if a validator has a withdrawal credential type `0x01`, any rewards above 32ETH will be periodically withdrawn to the withdrawal address. This is also known as the "validator sweep", i.e., once the "validator sweep" reaches your validator's index, your rewards will be withdrawn to the withdrawal address.  The validator sweep is automatic and it does not incur any fees to withdraw.

## Partial withdrawals via the execution layer

With the [Pectra](https://ethereum.org/en/history/#pectra) upgrade, validators with 0x02 withdrawal credentials can partially withdraw staked funds via the execution layer by sending a transaction using the withdrawal address. You can withdraw down to a validator balance of 32 ETH. For example, if the validator balance is 40 ETH, you can withdraw up to 8 ETH. You can use [Siren](./ui.md) or the [staking launchpad](https://launchpad.ethereum.org/en/) to execute partial withdrawals.

## FAQ

1. How to know if I have the withdrawal credentials type `0x00` or `0x01`?

   Refer [here](./validator_voluntary_exit.md#1-how-to-know-if-i-have-the-withdrawal-credentials-type-0x01).

2. My validator has withdrawal credentials type `0x00`, is there a deadline to update my withdrawal credentials?

   No.  You can update your withdrawal credentials **anytime**. The catch is that as long as you do not update your withdrawal credentials, your rewards in the beacon chain will continue to be locked in the beacon chain. Only after you update the withdrawal credentials, will the rewards be withdrawn to the withdrawal address.

3. Do I have to do anything to get my rewards after I update the withdrawal credentials to type `0x01`?

    No. The "validator sweep" occurs automatically and you can expect to receive the rewards every *n* days, [more information here](./validator_voluntary_exit.md#4-when-will-i-get-my-staked-fund-after-voluntary-exit-if-my-validator-is-of-type-0x01).

    Figure below summarizes partial withdrawals.

    ![partial](./imgs/partial-withdrawal.png)
