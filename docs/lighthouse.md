# About Lighthouse

## Goals

The purpose of this project is to work alongside the Ethereum community to
implement a secure, trustworthy, open-source Ethereum Serenity client in Rust.

* **Security**: Lighthouse's main goal is to implement everything with a
security-first mindset. The goal is to ensure that all components of lighthouse
are thoroughly tested, checked and secure.

* **Trust** : As Ethereum Serenity is a Proof-of-Stake system, which
involves the interaction of the Ethereum protocol and user funds. Thus, a goal
of Lighthouse is to provide a client that is trustworthy.

  All code can be tested and verified the goal of Lighthouse is to provide code
that is trusted.

* **Transparency**: Lighthouse aims at being as transparent as possible. This
goal is for Lighthouse to embrace the open-source community and allow for all
to understand the decisions, direction and changes in all aspects.

* **Error Resilience**: As Lighthouse embraces the "never `panic`" mindset, the
goal is to be resilient to errors that may occur. Providing a client that has
tolerance against errors provides further properties for a secure, trustworthy
client that Lighthouse aims to provide.

In addition to implementing a new client, the project seeks to maintain and
improve the Ethereum protocol wherever possible.

## Ideology

### Never Panic

Lighthouse will be the gateway interacting with the Proof-of-Stake system
employed by Ethereum. This requires the validation and proposal of blocks
and extremely timely responses. As part of this, Lighthouse aims to ensure
the most uptime as possible, meaning minimising the amount of
exceptions and gracefully handling any issues.

Rust's `panic` provides the ability to throw an exception and exit, this
will terminate the running processes. Thus, Lighthouse aims to use `panic`
as little as possible to minimise the possible termination cases.

### Security First Mindset

Lighthouse aims to provide a safe, secure Serenity client for the Ethereum
ecosystem. At each step of development, the aim is to have a security-first
mindset and always ensure you are following the safe, secure mindset. When
contributing to any part of the Lighthouse client, through any development,
always ensure you understand each aspect thoroughly and cover all potential
security considerations of your code.

### Functions aren't completed until they are tested

As part of the Security First mindset, we want to aim to cover as many distinct
cases. A function being developed is not considered "completed" until tests
exist for that function. The tests not only help show the correctness of the
function, but also provide a way for new developers to understand how the
function is to be called and how it works.


## Engineering Ethos

Lighthouse aims to produce many small easily-tested components, each separated
into individual crates wherever possible.

Generally, tests can be kept in the same file, as is typical in Rust.
Integration tests should be placed in the `tests` directory in the crate's
root.  Particularly large (line-count) tests should be placed into a separate
file.

A function is not considered complete until a test exists for it. We produce
tests to protect against regression (accidentally breaking things) and to
provide examples that help readers of the code base understand how functions
should (or should not) be used.

Each pull request is to be reviewed by at least one "core developer" (i.e.,
someone with write-access to the repository). This helps to ensure bugs are
detected, consistency is maintained, and responsibility of errors is dispersed.

Discussion must be respectful and intellectual. Have fun and make jokes, but
always respect the limits of other people.
