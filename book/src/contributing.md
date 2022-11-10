# Contributing to Lighthouse

[![Chat Badge]][Chat Link]
[![GitPOAP Badge](https://public-api.gitpoap.io/v1/repo/sigp/lighthouse/badge)](https://www.gitpoap.io/gh/sigp/lighthouse)

[Chat Badge]: https://img.shields.io/badge/chat-discord-%237289da
[Chat Link]: https://discord.gg/cyAszAh
[stable]: https://github.com/sigp/lighthouse/tree/stable
[unstable]: https://github.com/sigp/lighthouse/tree/unstable


Lighthouse welcomes contributions. If you are interested in contributing to the
Ethereum ecosystem, and you want to learn Rust, Lighthouse is a great project
to work on.

To start contributing,

1. Read our [how to contribute](https://github.com/sigp/lighthouse/blob/unstable/CONTRIBUTING.md) document.
2. Setup a [development environment](./setup.md).
3. Browse through the [open issues](https://github.com/sigp/lighthouse/issues)
   (tip: look for the [good first
   issue](https://github.com/sigp/lighthouse/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
   tag).
4. Comment on an issue before starting work.
5. Share your work via a pull-request.

If you have questions, please reach out via
[Discord](https://discord.gg/cyAszAh).

## Branches

Lighthouse maintains two permanent branches:

- [`stable`][stable]: Always points to the latest stable release.
  - This is ideal for most users.
- [`unstable`][unstable]: Used for development, contains the latest PRs.
  - Developers should base their PRs on this branch.

## Ethereum consensus client

Lighthouse is an implementation of the Ethereum proof-of-stake consensus specification, as defined
in the  [ethereum/consensus-specs](https://github.com/ethereum/consensus-specs)
repository.

We recommend reading Danny Ryan's (incomplete) [Phase 0 for
Humans](https://notes.ethereum.org/@djrtwo/Bkn3zpwxB?type=view) before diving
into the canonical spec.

## Rust

Lighthouse adheres to Rust code conventions as outlined in the [**Rust
Styleguide**](https://github.com/rust-dev-tools/fmt-rfcs/blob/master/guide/guide.md).

Please use [clippy](https://github.com/rust-lang/rust-clippy) and
[rustfmt](https://github.com/rust-lang/rustfmt) to detect common mistakes and
inconsistent code formatting:

```bash
$ cargo clippy --all
$ cargo fmt --all --check
```

### Panics

Generally, **panics should be avoided at all costs**. Lighthouse operates in an
adversarial environment (the Internet) and it's a severe vulnerability if
people on the Internet can cause Lighthouse to crash via a panic.

Always prefer returning a `Result` or `Option` over causing a panic. For
example, prefer `array.get(1)?` over `array[1]`.

If you know there won't be a panic but can't express that to the compiler,
use `.expect("Helpful message")` instead of `.unwrap()`. Always provide
detailed reasoning in a nearby comment when making assumptions about panics.

### TODOs

All `TODO` statements should be accompanied by a GitHub issue.

```rust
pub fn my_function(&mut self, _something &[u8]) -> Result<String, Error> {
  // TODO: something_here
  // https://github.com/sigp/lighthouse/issues/XX
}
```

### Comments

**General Comments**

* Prefer line (``//``) comments to block comments (``/* ... */``)
* Comments can appear on the line prior to the item or after a trailing space.
```rust
// Comment for this struct
struct Lighthouse {}
fn make_blockchain() {} // A comment on the same line after a space
```

**Doc Comments**

* The ``///`` is used to generate comments for Docs.
* The comments should come before attributes.

```rust
/// Stores the core configuration for this Lighthouse instance.
/// This struct is general, other components may implement more
/// specialized config structs.
#[derive(Clone)]
pub struct LighthouseConfig {
    pub data_dir: PathBuf,
    pub p2p_listen_port: u16,
}
```

### Rust Resources

Rust is an extremely powerful, low-level programming language that provides
freedom and performance to create powerful projects. The [Rust
Book](https://doc.rust-lang.org/stable/book/) provides insight into the Rust
language and some of the coding style to follow (As well as acting as a great
introduction and tutorial for the language).

Rust has a steep learning curve, but there are many resources to help. We
suggest:

* [Rust Book](https://doc.rust-lang.org/stable/book/)
* [Rust by example](https://doc.rust-lang.org/stable/rust-by-example/)
* [Learning Rust With Entirely Too Many Linked Lists](http://cglab.ca/~abeinges/blah/too-many-lists/book/)
* [Rustlings](https://github.com/rustlings/rustlings)
* [Rust Exercism](https://exercism.io/tracks/rust)
* [Learn X in Y minutes - Rust](https://learnxinyminutes.com/docs/rust/)
