VERSION:=$(shell git describe --tags)

check:
	cargo run --manifest-path schema_validator/Cargo.toml --release -- schema.json tests/generated

# Build a tarball for a release.
# To make a new release: `git tag -s vX.Y.Z`
release:
	tar -czvf eip-3076-tests-$(VERSION).tar.gz tests/
