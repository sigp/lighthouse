# Lighthouse: Ethereum 2.0

An open-source Ethereum 2.0 client, written in Rust and maintained by Sigma Prime.

[![Build Status]][Build Link] [![Book Status]][Book Link] [![Chat Badge]][Chat Link]

[Build Status]: https://github.com/sigp/lighthouse/workflows/test-suite/badge.svg?branch=master
[Build Link]: https://github.com/sigp/lighthouse/actions
[Chat Badge]: https://img.shields.io/badge/chat-discord-%237289da
[Chat Link]: https://discord.gg/cyAszAh
[Book Status]:https://img.shields.io/badge/user--docs-master-informational
[Book Link]: https://lighthouse-book.sigmaprime.io

[Documentation](https://lighthouse-book.sigmaprime.io)

![Banner](https://i.postimg.cc/hjdTGKPd/photo-2020-10-23-09-52-16.jpg)

**🚨🚨🚨 Note: Lighthouse is not *yet* ready to produce mainnet deposits. The developers will require some
time to test against the mainnet deposit contract, once it is released. DO NOT SUBMIT VALIDATOR
DEPOSITS WITH LIGHTHOUSE. 🚨🚨🚨**

## Overview

Lighthouse is:

- Fully open-source, licensed under Apache 2.0.
- Security-focused. Fuzzing has begun and security reviews are underway.
- Built in [Rust](https://www.rust-lang.org), a modern language providing unique safety guarantees and
	excellent performance (comparable to C++).
- Funded by various organisations, including Sigma Prime, the
	Ethereum Foundation, ConsenSys and private individuals.
- Actively involved in the specification and security analysis of the
	Ethereum 2.0 specification.

Like all Ethereum 2.0 clients, Lighthouse is a work-in-progress.

## Eth2 Deposit Contract

The Lighthouse team acknowledges
[`0x00000000219ab540356cBB839Cbe05303d7705Fa`](https://etherscan.io/address/0x00000000219ab540356cbb839cbe05303d7705fa)
as the canonical Eth2 deposit contract address.

## Development Status

Current development overview:

- Specification `v1.0.0` implemented, optimized and passing test vectors.
- Rust-native libp2p with Gossipsub and Discv5.
- RESTful JSON API via HTTP server.
- Events via WebSocket.
- Metrics via Prometheus.

### Roadmap

- ~~**April 2019**: Inital single-client testnets.~~
- ~~**September 2019**: Inter-operability with other Ethereum 2.0 clients.~~
- ~~**Q1 2020**: `lighthouse-0.1.0` release: All major phase 0 features implemented.~~
- ~~**Q2 2020**: Public, multi-client testnet with user-facing functionality.~~
- ~~**Q2 2020**: Third-party security review.~~
- ~~**Q4 2020**: Long-lived, multi-client Beacon Chain testnet~~
- **Q4 2020**: Additional third-party security reviews.
- **Q4 2020**: Production Beacon Chain (tentative).


## Documentation

The [Lighthouse Book](https://lighthouse-book.sigmaprime.io) contains information
for testnet users and developers.

If you'd like some background on Sigma Prime, please see the [Lighthouse Update
\#00](https://lighthouse.sigmaprime.io/update-00.html) blog post or
[sigmaprime.io](https://sigmaprime.io).

## Contributing

Lighthouse welcomes contributors.

If you are looking to contribute, please head to the
[Contributing](https://lighthouse-book.sigmaprime.io/contributing.html) section
of the Lighthouse book.

## Contact

The best place for discussion is the [Lighthouse Discord
server](https://discord.gg/cyAszAh). Alternatively, you may use the
[sigp/lighthouse gitter](https://gitter.im/sigp/lighthouse).

Sign up to the [Lighthouse Development Updates](https://mailchi.mp/3d9df0417779/lighthouse-dev-updates)
mailing list for email notifications about releases, network status and other important information.

Encrypt sensitive messages using our [PGP
key](https://keybase.io/sigp/pgp_keys.asc?fingerprint=dcf37e025d6c9d42ea795b119e7c6cf9988604be).

## Donations

Lighthouse is an open-source project and a public good. Funding public goods is
hard and we're grateful for the donations we receive from the community via:

- [Gitcoin Grants](https://gitcoin.co/grants/25/lighthouse-ethereum-20-client).
- Ethereum address: `0x25c4a76E7d118705e7Ea2e9b7d8C59930d8aCD3b` (donation.sigmaprime.eth).
