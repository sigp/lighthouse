# Lighthouse: Ethereum consensus client

An open-source Ethereum consensus client, written in Rust and maintained by Sigma Prime.

[![Book Status]][Book Link] [![Chat Badge]][Chat Link]

[Chat Badge]: https://img.shields.io/badge/chat-discord-%237289da
[Chat Link]: https://discord.gg/cyAszAh
[Book Status]:https://img.shields.io/badge/user--docs-unstable-informational
[Book Link]: https://lighthouse-book.sigmaprime.io
[stable]: https://github.com/sigp/lighthouse/tree/stable
[unstable]: https://github.com/sigp/lighthouse/tree/unstable
[blog]: https://lighthouse.sigmaprime.io

[Documentation](https://lighthouse-book.sigmaprime.io)

![Banner](https://i.postimg.cc/hjdTGKPd/photo-2020-10-23-09-52-16.jpg)

## Overview

Lighthouse is:

- Ready for use on Ethereum consensus mainnet.
- Fully open-source, licensed under Apache 2.0.
- Security-focused. Fuzzing techniques have been continuously applied and several external security reviews have been performed.
- Built in [Rust](https://www.rust-lang.org), a modern language providing unique safety guarantees and
	excellent performance (comparable to C++).
- Funded by various organisations, including Sigma Prime, the
	Ethereum Foundation, ConsenSys, the Decentralization Foundation and private individuals.
- Actively involved in the specification and security analysis of the
	Ethereum proof-of-stake consensus specification.

## Staking Deposit Contract

The Lighthouse team acknowledges
[`0x00000000219ab540356cBB839Cbe05303d7705Fa`](https://etherscan.io/address/0x00000000219ab540356cbb839cbe05303d7705fa)
as the canonical staking deposit contract address.

## Documentation

The [Lighthouse Book](https://lighthouse-book.sigmaprime.io) contains information for users and
developers.

The Lighthouse team maintains a blog at [lighthouse-blog.sigmaprime.io][blog] which contains periodical
progress updates, roadmap insights and interesting findings.

## Branches

Lighthouse maintains two permanent branches:

- [`stable`][stable]: Always points to the latest stable release.
  - This is ideal for most users.
- [`unstable`][unstable]: Used for development, contains the latest PRs.
  - Developers should base their PRs on this branch.

## Contributing

Lighthouse welcomes contributors.

If you are looking to contribute, please head to the
[Contributing](https://lighthouse-book.sigmaprime.io/contributing.html) section
of the Lighthouse book.

## Contact

The best place for discussion is the [Lighthouse Discord
server](https://discord.gg/cyAszAh).

Sign up to the [Lighthouse Development Updates](https://eepurl.com/dh9Lvb/) mailing list for email
notifications about releases, network status and other important information.

Encrypt sensitive messages using our [PGP
key](https://keybase.io/sigp/pgp_keys.asc?fingerprint=15e66d941f697e28f49381f426416dc3f30674b0).

## Donations

Lighthouse is an open-source project and a public good. Funding public goods is
hard and we're grateful for the donations we receive from the community via:

- [Gitcoin Grants](https://gitcoin.co/grants/25/lighthouse-ethereum-20-client).
- Ethereum address: `0x25c4a76E7d118705e7Ea2e9b7d8C59930d8aCD3b` (donation.sigmaprime.eth).
