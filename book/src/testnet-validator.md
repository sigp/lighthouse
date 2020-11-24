# Become a Testnet Validator

[mainnet-validator]: ./mainnet-validator.md

Joining an Eth2 testnet is a great way to get familiar with staking in Phase 0.  All users should
experiment with a testnet prior to staking mainnet ETH.

To join a testnet, you can follow the [Become an Eth2 Mainnet Validator][mainnet-validator]
instructions but with a few differences:

1. Use the appropriate Eth2 launchpad website:
    - [Medalla](https://github.com/goerli/medalla/tree/master/medalla)
    - [Pyrmont](https://github.com/protolambda/pyrmont)
1. Instead of `--network mainnet`, use the appropriate network flag:
   - `--network pyrmont`: Pyrmont.
   - `--testnet medalla`: Medalla.
1. Use a Goeli Eth1 node instead of a mainnet one:
   - For Geth, this means using `geth --goerli --http`.
1. Notice that Lighthouse will sort its files in a different directory by default:
   - `~/.lighthouse/pyrmont`: Pyrmont.
   - `~/.lighthouse/medalla`: Medalla.

>
> **Never use real ETH to join a testnet!** All of the testnets listed here use Goerli ETH which is
> basically worthless. This allows experimentation without real-world costs.
