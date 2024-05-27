# Homebrew package

Lighthouse is available on Linux and macOS via the [Homebrew package manager](https://brew.sh).

Please note that this installation method is maintained by the Homebrew community.
It is not officially supported by the Lighthouse team.

## Installation

Install the latest version of the [`lighthouse`][formula] formula with:

```bash
brew install lighthouse
```

## Usage

If Homebrew is installed to your `PATH` (default), simply run:

```bash
lighthouse --help
```

Alternatively, you can find the `lighthouse` binary at:

```bash
"$(brew --prefix)/bin/lighthouse" --help
```

## Maintenance

The [formula][] is kept up-to-date by the Homebrew community and a bot that lists for new releases.

The package source can be found in the [homebrew-core](https://github.com/Homebrew/homebrew-core/blob/master/Formula/l/lighthouse.rb) repo.

  [formula]: https://formulae.brew.sh/formula/lighthouse
