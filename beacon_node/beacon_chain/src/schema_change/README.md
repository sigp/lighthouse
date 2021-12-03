Database Schema Migrations
====

This document is an attempt to record some best practices and design conventions for applying
database schema migrations within Lighthouse.

## General Structure

If you make a breaking change to an on-disk data structure you need to increment the
`SCHEMA_VERSION` in `beacon_node/store/src/metadata.rs` and add a migration from the previous
version to the new version.

The entry-point for database migrations is in `schema_change.rs`, _not_ `migrate.rs` (which deals
with finalization). Supporting code for a specific migration may be added in
`schema_change/migration_schema_vX.rs`, where `X` is the version being migrated _to_.

## Combining Schema Changes

Schema changes may be combined if they are part of the same pull request to
`unstable`. Once a schema version is defined in `unstable` we should not apply changes to it
without incrementing the version. This prevents conflicts between versions that appear to be the
same. This allows us to deploy `unstable` to nodes without having to worry about needing to resync
because of a sneaky schema change.

Changing the on-disk structure for a version _before_ it is merged to `unstable` is OK. You will
just have to handle manually resyncing any test nodes (use checkpoint sync).

## Naming Conventions

Prefer to name versions of structs by _the version at which the change was introduced_. For example
if you add a field to `Foo` in v9, call the previous version `FooV1` (assuming this is `Foo`'s first
migration) and write a schema change that migrates from `FooV1` to `FooV9`.

Prefer to use explicit version names in `schema_change.rs` and the `schema_change` module. To
interface with the outside either:

1. Define a type alias to the latest version, e.g. `pub type Foo = FooV9`, or
2. Define a mapping from the latest version to the version used elsewhere, e.g.
   ```rust
   impl From<FooV9> for Foo {}
   ```

Avoid names like:

* `LegacyFoo`
* `OldFoo`
* `FooWithoutX`

## First-version vs Last-version

Previously the schema migration code would name types by the _last_ version at which they were
valid. For example if `Foo` changed in `V9` then we would name the two variants `FooV8` and `FooV9`.
The problem with this scheme is that if `Foo` changes again in the future at say v12 then `FooV9` would
need to be renamed to `FooV11`, which is annoying. Using the _first_ valid version as described
above does not have this issue.

## Using SuperStruct

If possible, consider using [`superstruct`](https://crates.io/crates/superstruct) to handle data
structure changes between versions.

* Use `superstruct(no_enum)` to avoid generating an unnecessary top-level enum.

## Example

A field is added to `Foo` in v9, and there are two variants: `FooV1` and `FooV9`. There is a
migration from `FooV1` to `FooV9`. `Foo` is aliased to `FooV9`.

Some time later another field is added to `Foo` in v12. A new `FooV12` is created, along with a
migration from `FooV9` to `FooV12`. The primary `Foo` type gets re-aliased to `FooV12`. The previous
migration from V1 to V9 shouldn't break because the schema migration refers to `FooV9` explicitly
rather than `Foo`. Due to the re-aliasing (or re-mapping) the compiler will check every usage
of `Foo` to make sure that it still makes sense with `FooV12`.

