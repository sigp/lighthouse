# Tree hashing

Provides both cached and non-cached tree hashing methods.

## Standard Tree Hash

```rust
use tree_hash_derive::TreeHash;

#[derive(TreeHash)]
struct Foo {
	a: u64,
	b: Vec<u64>,
}

fn main() {
	let foo = Foo {
		a: 42,
		b: vec![1, 2, 3]
	};

	println!("root: {}", foo.tree_hash_root());
}
```

## Cached Tree Hash


```rust
use tree_hash_derive::{TreeHash, CachedTreeHash};

#[derive(TreeHash, CachedTreeHash)]
struct Foo {
	a: u64,
	b: Vec<u64>,
}

#[derive(TreeHash, CachedTreeHash)]
struct Bar {
	a: Vec<Foo>,
	b: u64,
}

fn main() {
	let bar = Bar {
		a: vec![
			Foo {
				a: 42,
				b: vec![1, 2, 3]
			}
		],
		b: 42
	};

	let modified_bar = Bar {
		a: vec![
			Foo {
				a: 100,
				b: vec![1, 2, 3, 4, 5, 6]
			}
			Foo {
				a: 42,
				b: vec![]
			}
		],
		b: 99
	};


    let mut hasher = CachedTreeHasher::new(&bar).unwrap();
	hasher.update(&modified_bar).unwrap();

	// Assert that the cached tree hash matches a standard tree hash.
	assert_eq!(hasher.tree_hash_root(), modified_bar.tree_hash_root());
}
```
