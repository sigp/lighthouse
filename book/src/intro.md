# Lighthouse Documentation

[![Build Status]][Build Link] [![Doc Status]][Doc Link] [![Chat Badge]][Chat Link]

[Build Status]: https://gitlab.sigmaprime.io/sigp/lighthouse/badges/master/build.svg
[Build Link]: https://gitlab.sigmaprime.io/sigp/lighthouse/pipelines
[Chat Badge]: https://img.shields.io/badge/chat-discord-%237289da
[Chat Link]: https://discord.gg/cyAszAh
[Doc Status]:https://img.shields.io/badge/rust--docs-master-orange
[Doc Link]: http://lighthouse-docs.sigmaprime.io/

Lighthouse is an **Ethereum 2.0 client** that connects to other Ethereum 2.0
clients to form a resilient and decentralized proof-of-stake blockchain.

It is written in Rust, maintained by Sigma Prime and funded by the Ethereum
Foundation, Consensys and other individuals and organisations.

## Developer Resources

Documentation is provided for **researchers and developers** working on
Ethereum 2.0 and assumes prior knowledge on the topic.

- Get started with [development environment setup](setup.html).
- [Run a simple testnet](testnets.html) in Only Three CLI Commands™.
- Read about our interop workflow.
- API?

## Release

Ethereum 2.0 is not fully specified or implemented and as such, Lighthouse is
still **under development**.

We are on-track to provide a public, multi-client testnet in late-2019 and an
initial production-grade blockchain in 2020.

## Features

Lighthouse has been in development since mid-2018 and has an extensive feature
set:

- Libp2p networking stack, featuring Discovery v5.
- Optimized `BeaconChain` state machine, up-to-date and
	passing all tests.
- RESTful HTTP API.
- Documented and feature-rich CLI interface.
- Capable of running small, local testnets with 250ms slot times.
- Detailed metrics exposed in the Prometheus format.
