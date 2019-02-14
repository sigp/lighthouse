# Contributing to Lighthouse

[![Gitter](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/sigp/lighthouse?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)

Lighthouse is an open-source Ethereum Serenity client built in
[Rust](https://www.rust-lang.org/).

Lighthouse welcomes all contributions with open arms. If you are interested in
contributing to the Ethereum ecosystem, and you want to learn Rust, Lighthouse
is a great project to work on.

This documentation aims to provide a smooth on-boarding for all who wish to
help contribute to Lighthouse. Whether it is helping with the mountain of
documentation, writing extra tests or developing components, all help is
appreciated and your contributions will help not only the community but all
the contributors.

We've bundled up our Goals, Ethos and Ideology into one document for you to
read through, please read our [About Lighthouse](lighthouse.md) docs. :smile:

Layer-1 infrastructure is a critical component for the ecosystem and relies
heavily on contributions from the community. Building Ethereum Serenity is a
huge task and we refuse to conduct an inappropriate ICO or charge licensing
fees.  Instead, we fund development through grants and support from Sigma
Prime.

If you have any additional questions, please feel free to jump on the
[gitter](https://gitter.im/sigp/lighthouse) and have a chat with all of us.

**Pre-reading Materials:**

* [About Lighthouse](lighthouse.md)
* [Ethereum Serenity](serenity.md)

**Repository**

If you'd like to contribute, try having a look through the [open
issues](https://github.com/sigp/lighthouse/issues) (tip: look for the [good
first
issue](https://github.com/sigp/lighthouse/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22)
tag) and ping us on the [gitter](https://gitter.im/sigp/lighthouse) channel. We need
your support!

## Understanding Serenity

Ethereum's Serenity is based on a Proof-of-Stake based sharded beacon chain.

(*If you don't know what that is, don't `panic`, that's what this documentation
is for!* :smile:)

Read through our [Understanding
Serenity](https://github.com/sigp/lighthouse/blob/master/docs/serenity.md) docs
to learn more! :smile: (*unless you've already read it.*)

The document explains the necessary fundamentals for understanding Ethereum,
Proof-of-Stake and the Serenity we are working towards.

## Development Onboarding

If you would like to contribute and develop Lighthouse, there are only a few
things to go through (and then you're on your way!).

### Understanding Rust

Rust is an extremely powerful, low-level programming language that provides
freedom and performance to create powerful projects. The [Rust 
Book](https://doc.rust-lang.org/stable/book/) provides insight into the Rust
language and some of the coding style to follow (As well as acting as a great
introduction and tutorial for the language.)

Rust has a steep learning curve, but there are many resources to help you!

* [Rust Book](https://doc.rust-lang.org/stable/book/)
* [Rust by example](https://doc.rust-lang.org/stable/rust-by-example/)
* [Learning Rust With Entirely Too Many Linked Lists](http://cglab.ca/~abeinges/blah/too-many-lists/book/)
* [Rustlings](https://github.com/rustlings/rustlings)
* [Rust Exercism](https://exercism.io/tracks/rust)
* [Learn X in Y minutes - Rust](https://learnxinyminutes.com/docs/rust/)


#### Getting Started and installing Rust

We recommend installing Rust using [**rustup**](https://rustup.rs/). Rustup
allows you to easily install versions of rust.

**Linux/Unix/Mac:**

```
$ curl https://sh.rustup.rs -sSf | sh
```

**Windows (You need a bit more):**
* Install the Visual Studio 2015 with C++ support
* Install Rustup using: https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe
* You can then use the ``VS2015 x64 Native Tools Command Prompt`` and run:

```
rustup default stable-x86-64-pc-windows-msvc
```

#### Getting ready with Cargo

[Cargo](https://doc.rust-lang.org/cargo/) is the package manager for Rust, and
allows to extend to a number of packages and external libraries. It's also extremely
handy for handling dependencies and helping to modularise your project better.

*Note: If you've installed rust through rustup, you should have ``cargo``
installed.*

#### Rust Terminology

When developing rust, you'll come across some terminology that differs to
other programming languages you may have used.

* **Trait**: A trait is a collection of methods defined for a type, they can be
implemented for any data type.
* **Struct**: A custom data type that lets us name and package together
multiple related values that make a meaninguful group.
* **Crate**: A crate is synonymous with a *library* or *package* in other
languages. They can produce an executable or library depending on the
project.
* **Module**: A collection of items: functions, structs, traits, and even other
modules. Modules allow you to hierarchically split code into logical units
and manage visibility.
* **Attribute**: Metadaata applied to some module, crate or item.
* **Macros**: Macros are powerful meta-programming statements that get expanded
into source code that gets compiled with the rest of the code (Unlike `C`
macros that are pre-processed, Rust macros form an Abstract Syntax Tree).


Other good appendix resources:

* [Keywords](https://doc.rust-lang.org/book/appendix-01-keywords.html)
* [Operators/Symbols](https://doc.rust-lang.org/book/appendix-02-operators.html)
* [Traits](https://doc.rust-lang.org/book/appendix-03-derivable-traits.html)


### Understanding the Git Workflow

Lighthouse utilises git as the primary open-source development tool. To help
with your contributions, it is great to understand the processes used to ensure
everything remains in sync and there's as little conflict as possible when
working on similar files.

Lighthouse uses the **feature branch** workflow, where each issue, or each
feature, is developed on its own branch and then merged in via a pull-request.

* [Feature Branch Tutorial](https://www.atlassian.com/git/tutorials/comparing-workflows/feature-branch-workflow)

## Code Conventions/Styleguide and Ethos

### Ethos

**Pull Requests**

Pull requests should be reviewed by **at least** one "*core developer*"
(someone with write-access to the repo). This should ensure bugs are caught and
the code is kept in a consistent state that follows all conventions and style.

All discussion (whether in PRs or Issues or in the Gitter) should be respectful
and intellectual. Have fun, but always respect the limits of other people.

**Testing**

*"A function is not considered complete until tests exist for it."*

Generally, tests can be self-contained in the same file. Integration tests
should be added into the ``tests/`` directory in the crate's **root**.

Large line-count tests should be in a separate file.

### Rust StyleGuide

Lighthouse adheres to Rust code conventions as outlined in the [**Rust
Styleguide**](https://github.com/rust-dev-tools/fmt-rfcs/blob/master/guide/guide.md).

Ensure you use [Clippy](https://github.com/rust-lang/rust-clippy) to lint and
check your code.

| Code Aspect         | Guideline Format               |
|:--------------------|:-------------------------------|
| Types               | ``UpperCamelCase``             |
| Enums/Enum Variants | ``UpperCamelCase``             |
| Struct Fields       | ``snake_case``                 |
| Function / Method   | ``snake_case``                 |
| Macro Names         | ``snake_case``                 |
| Constants           | ``SCREAMING_SNAKE_CASE``       |
| Forbidden name      | Trialing Underscore: ``name_`` |

Other general rust docs:

* [Rust Other Style Advice](https://github.com/rust-dev-tools/fmt-rfcs/blob/master/guide/advice.md)
* [Cargo.toml Conventions](https://github.com/rust-dev-tools/fmt-rfcs/blob/master/guide/cargo.md)

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
