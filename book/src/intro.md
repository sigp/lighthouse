# Lighthouse Book

_Documentation for Lighthouse users and developers._

[![Doc Status]][Doc Link] [![Chat Badge]][Chat Link]

[Chat Badge]: https://img.shields.io/badge/chat-discord-%237289da
[Chat Link]: https://discord.gg/cyAszAh
[Doc Status]:https://img.shields.io/badge/rust--docs-master-orange
[Doc Link]: http://lighthouse-docs.sigmaprime.io/

Lighthouse is an **Ethereum 2.0 client** that connects to other Ethereum 2.0
clients to form a resilient and decentralized proof-of-stake blockchain.

We implement the specification as defined in the
[ethereum/eth2.0-specs](https://github.com/ethereum/eth2.0-specs) repository.

## Topics

You may read this book from start to finish, or jump to some of these topics:

- Get started with [development environment setup](./setup.md).
- Utilize the whole stack by starting a [simple local testnet](./simple-testnet.md).
- Query the [RESTful HTTP API](./http.md) using `curl`.
- Listen to events with the [JSON WebSocket API](./websockets.md).
- View the [Rust code docs](http://lighthouse-docs.sigmaprime.io/).


Prospective contributors can read the [Contributing](./contributing.md) section
to understand how we develop and test Lighthouse.

## About this Book

This book is open source, contribute at
[github.com/sigp/lighthouse/book](https://github.com/sigp/lighthouse/tree/master/book).

The Lighthouse CI/CD system maintains a hosted version of the `master` branch
at [lighthouse-book.sigmaprime.io](http://lighthouse-book.sigmaprime.io).
