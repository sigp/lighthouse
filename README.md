# Lighthouse: Ethereum 2.0

An open-source Ethereum 2.0 client, written in Rust and maintained by Sigma Prime.

[![Build Status]][Build Link] [![Book Status]][Book Link] [![RustDoc Status]][RustDoc Link] [![Chat Badge]][Chat Link] [![Swagger Badge]][Swagger Link]

[Build Status]: https://gitlab.sigmaprime.io/sigp/lighthouse/badges/master/build.svg
[Build Link]: https://gitlab.sigmaprime.io/sigp/lighthouse/pipelines
[Chat Badge]: https://img.shields.io/badge/chat-discord-%237289da
[Chat Link]: https://discord.gg/cyAszAh
[Book Status]:https://img.shields.io/badge/user--docs-master-informational
[Book Link]: http://lighthouse-book.sigmaprime.io/
[RustDoc Status]:https://img.shields.io/badge/code--docs-master-orange
[RustDoc Link]: http://lighthouse-docs.sigmaprime.io/
[Swagger Badge]: https://img.shields.io/badge/Open%20API-0.2.0-success
[Swagger Link]: https://app.swaggerhub.com/apis-docs/spble/lighthouse_rest_api/0.2.0

![terminalize](https://i.postimg.cc/Y0BQ0z3R/terminalize.gif)

## Overview

Lighthouse is:

- Fully open-source, licensed under Apache 2.0.
- Security-focused. Fuzzing has begun and security reviews are planned
	for late-2019.
- Built in [Rust](https://www.rust-lang.org/), a modern language providing unique safety guarantees and
	excellent performance (comparable to C++).
- Funded by various organisations, including Sigma Prime, the
	Ethereum Foundation, ConsenSys and private individuals.
- Actively involved in the specification and security analysis of the emerging
    Ethereum 2.0 specification.

Like all Ethereum 2.0 clients, Lighthouse is a work-in-progress.

## Development Status

Current development overview:

- Specification `v0.8.3` implemented, optimized and passing test vectors.
- Rust-native libp2p with Gossipsub and Discv5.
- RESTful JSON API via HTTP server.
- Events via WebSocket.
- Metrics via Prometheus.

### Roadmap

- ~~**April 2019**: Inital single-client testnets.~~
- ~~**September 2019**: Inter-operability with other Ethereum 2.0 clients.~~
- **Early-October 2019**: `lighthouse-0.0.1` release: All major phase 0
     features implemented.
- **Q4 2019**: Public, multi-client testnet with user-facing functionality.
- **Q4 2019**: Third-party security review.
- **Q1 2020**: Production Beacon Chain testnet (tentative).


## Documentation

The [Lighthouse Book](http://lighthouse-book.sigmaprime.io/) contains information
for testnet users and developers.

Code documentation is generated via `cargo doc` and hosted at
[lighthouse-docs.sigmaprime.io](http://lighthouse-docs.sigmaprime.io/).

If you'd like some background on Sigma Prime, please see the [Lighthouse Update
\#00](https://lighthouse.sigmaprime.io/update-00.html) blog post or
[sigmaprime.io](https://sigmaprime.io).

## Contributing

Lighthouse welcomes contributors.

If you are looking to contribute, please head to the
[Contributing](http://lighthouse-book.sigmaprime.io/contributing.html) section
of the Lighthouse book.

## Contact

The best place for discussion is the [Lighthouse Discord
server](https://discord.gg/cyAszAh). Alternatively, you may use the
[sigp/lighthouse gitter](https://gitter.im/sigp/lighthouse).

Encrypt sensitive messages using our [PGP
key](https://keybase.io/sigp/pgp_keys.asc?fingerprint=dcf37e025d6c9d42ea795b119e7c6cf9988604be).

## Donations

Lighthouse is an open-source project and a public good. Funding public goods is
hard and we're grateful for the donations we receive from the community via:

- [Gitcoin Grants](https://gitcoin.co/grants/25/lighthouse-ethereum-20-client).
- Ethereum address: `0x25c4a76E7d118705e7Ea2e9b7d8C59930d8aCD3b` (donation.sigmaprime.eth).
