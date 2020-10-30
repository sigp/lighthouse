# Voluntary exits

A validator may chose to voluntarily stop performing duties (proposing blocks and attesting to blocks) by submitting
a voluntary exit transaction to the beacon chain.

A validator can initiate a voluntary exit provided that the validator is currently active, has not been slashed and has been active for at least 256 epochs (~27 hours) since it has been activated.

> Note: After initiating a voluntary exit, the validator will have to keep performing duties until it has successfully exited to avoid penalties.

It takes at a minimum 5 epochs (32 minutes) for a validator to exit after initiating a voluntary exit.
This number can be much higher depending on how many other validators are queued to exit.

## Withdrawal of exited funds

Even though users can perform a voluntary exit in phase 0, they **cannot withdraw their exited funds at this point in time**.
This implies that the staked funds are effectively **frozen** until withdrawals are enabled in future phases.

To understand the phased rollout strategy for Eth2, please visit <https://ethereum.org/en/eth2/#roadmap>.



## Initiating a voluntary exit

In order to initiate an exit, users can use the `lighthouse account validator exit` command.

- The `--keystore` flag is used to specify the path to the EIP-2335 voting keystore for the validator.

- The `--beacon-node` flag is used to specify a beacon chain HTTP endpoint that confirms to the [Eth2.0 Standard API](https://ethereum.github.io/eth2.0-APIs/) specifications. That beacon node will be used to validate and propagate the voluntary exit. The default value for this flag is `http://localhost:5052`.

- The `--testnet` flag is used to specify a particular testnet (default is `medalla`).

- The `--password-file` flag is used to specify the path to the file containing the password for the voting keystore. If this flag is not provided, the user will be prompted to enter the password.


After validating the password, the user will be prompted to enter a special exit phrase as a final confirmation after which the voluntary exit will be published to the beacon chain.

The exit phrase is the following:
> Exit my validator



Below is an example for initiating a voluntary exit on the zinken testnet.

```
$ lighthouse --testnet zinken account validator exit --keystore /path/to/keystore --beacon-node http://localhost:5052

Running account manager for zinken testnet
validator-dir path: ~/.lighthouse/zinken/validators

Enter the keystore password for validator in 0xabcd

Password is correct

Publishing a voluntary exit for validator 0xabcd

WARNING: WARNING: THIS IS AN IRREVERSIBLE OPERATION

WARNING: WITHDRAWING STAKED ETH WILL NOT BE POSSIBLE UNTIL ETH1/ETH2 MERGE.

PLEASE VISIT https://lighthouse-book.sigmaprime.io/voluntary-exit.html
TO MAKE SURE YOU UNDERSTAND THE IMPLICATIONS OF A VOLUNTARY EXIT.

Enter the exit phrase from the above URL to confirm the voluntary exit:
Exit my validator

Successfully published voluntary exit for validator 0xabcd
```

