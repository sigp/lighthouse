//! 
//! ```rust
//! extern crate ethbloom;
//! #[macro_use] extern crate hex_literal;
//! use ethbloom::{Bloom, Input};
//!
//! fn main() {
//! 	let bloom: Bloom = "00000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002020000000000000000000000000000000000000000000008000000001000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".into();
//! 	let address = hex!("ef2d6d194084c2de36e0dabfce45d046b37d1106");
//! 	let topic = hex!("02c69be41d0b7e40352fc85be1cd65eb03d40ef8427a0ca4596b1ead9a00e9fc");
//! 	
//! 	let mut my_bloom = Bloom::default();
//! 	assert!(!my_bloom.contains_input(Input::Raw(&address)));
//! 	assert!(!my_bloom.contains_input(Input::Raw(&topic)));
//!
//! 	my_bloom.accrue(Input::Raw(&address));
//! 	assert!(my_bloom.contains_input(Input::Raw(&address)));
//! 	assert!(!my_bloom.contains_input(Input::Raw(&topic)));
//! 	
//! 	my_bloom.accrue(Input::Raw(&topic));
//! 	assert!(my_bloom.contains_input(Input::Raw(&address)));
//! 	assert!(my_bloom.contains_input(Input::Raw(&topic)));
//! 	assert_eq!(my_bloom, bloom);
//! 	}
//! ```
//!

#![cfg_attr(not(feature="std"), no_std)]

#[cfg(feature="std")]
extern crate core;

extern crate tiny_keccak;
#[macro_use]
extern crate crunchy;

#[macro_use]
extern crate fixed_hash;

#[cfg(feature="serialize")]
extern crate ethereum_types_serialize;

#[cfg(feature="serialize")]
extern crate serde;

#[cfg(test)]
#[macro_use]
extern crate hex_literal;

#[cfg(feature="serialize")]
use serde::{Serialize, Serializer, Deserialize, Deserializer};

use core::{ops, mem};
use tiny_keccak::keccak256;

#[cfg(feature="std")]
use core::str;

// 3 according to yellowpaper
const BLOOM_BITS: u32 = 3;
const BLOOM_SIZE: usize = 256;

construct_hash!(Bloom, BLOOM_SIZE);

/// Returns log2.
fn log2(x: usize) -> u32 {
	if x <= 1 {
		return 0;
	}

	let n = x.leading_zeros();
	mem::size_of::<usize>() as u32 * 8 - n
}

pub enum Input<'a> {
	Raw(&'a [u8]),
	Hash(&'a [u8; 32]),
}

enum Hash<'a> {
	Ref(&'a [u8; 32]),
	Owned([u8; 32]),
}

impl<'a> From<Input<'a>> for Hash<'a> {
	fn from(input: Input<'a>) -> Self {
		match input {
			Input::Raw(raw) => Hash::Owned(keccak256(raw)),
			Input::Hash(hash) => Hash::Ref(hash),
		}
	}
}

impl<'a> ops::Index<usize> for Hash<'a> {
	type Output = u8;

	fn index(&self, index: usize) -> &u8 {
		match *self {
			Hash::Ref(r) => &r[index],
			Hash::Owned(ref hash) => &hash[index],
		}
	}
}

impl<'a> Hash<'a> {
	fn len(&self) -> usize {
		match *self {
			Hash::Ref(r) => r.len(),
			Hash::Owned(ref hash) => hash.len(),
		}
	}
}

impl<'a> PartialEq<BloomRef<'a>> for Bloom {
	fn eq(&self, other: &BloomRef<'a>) -> bool {
		let s_ref: &[u8] = &self.0;
		let o_ref: &[u8] = other.0;
		s_ref.eq(o_ref)
	}
}

impl<'a> From<Input<'a>> for Bloom {
	fn from(input: Input<'a>) -> Bloom {
		let mut bloom = Bloom::default();
		bloom.accrue(input);
		bloom
	}
}

impl Bloom {
	pub fn is_empty(&self) -> bool {
		self.0.iter().all(|x| *x == 0)
	}

	pub fn contains_input<'a>(&self, input: Input<'a>) -> bool {
		let bloom: Bloom = input.into();
		self.contains_bloom(&bloom)
	}

	pub fn contains_bloom<'a, B>(&self, bloom: B) -> bool where BloomRef<'a>: From<B> {
		let bloom_ref: BloomRef = bloom.into();
		// workaround for https://github.com/rust-lang/rust/issues/43644
		self.contains_bloom_ref(bloom_ref)
	}

	fn contains_bloom_ref(&self, bloom: BloomRef) -> bool {
		let self_ref: BloomRef = self.into();
		self_ref.contains_bloom(bloom)
	}

	pub fn accrue<'a>(&mut self, input: Input<'a>) {
		let p = BLOOM_BITS;

		let m = self.0.len();
		let bloom_bits = m * 8;
		let mask = bloom_bits - 1;
		let bloom_bytes = (log2(bloom_bits) + 7) / 8;

		let hash: Hash = input.into();

		// must be a power of 2
		assert_eq!(m & (m - 1), 0);
		// out of range
		assert!(p * bloom_bytes <= hash.len() as u32);

		let mut ptr = 0;

		assert_eq!(BLOOM_BITS, 3);
		unroll! {
			for i in 0..3 {
				let _ = i;
				let mut index = 0 as usize;
				for _ in 0..bloom_bytes {
					index = (index << 8) | hash[ptr] as usize;
					ptr += 1;
				}
				index &= mask;
				self.0[m - 1 - index / 8] |= 1 << (index % 8);
			}
		}
	}

	pub fn accrue_bloom<'a, B>(&mut self, bloom: B) where BloomRef<'a>: From<B> {
		let bloom_ref: BloomRef = bloom.into();
		assert_eq!(self.0.len(), BLOOM_SIZE);
		assert_eq!(bloom_ref.0.len(), BLOOM_SIZE);
		for i in 0..BLOOM_SIZE {
			self.0[i] |= bloom_ref.0[i];
		}
	}

	pub fn data(&self) -> &[u8; BLOOM_SIZE] {
		&self.0
	}
}

#[derive(Clone, Copy)]
pub struct BloomRef<'a>(&'a [u8; BLOOM_SIZE]);

impl<'a> BloomRef<'a> {
	pub fn is_empty(&self) -> bool {
		self.0.iter().all(|x| *x == 0)
	}

	pub fn contains_input<'b>(&self, input: Input<'b>) -> bool {
		let bloom: Bloom = input.into();
		self.contains_bloom(&bloom)
	}
	
	pub fn contains_bloom<'b, B>(&self, bloom: B) -> bool where BloomRef<'b>: From<B> {
		let bloom_ref: BloomRef = bloom.into();
		assert_eq!(self.0.len(), BLOOM_SIZE);
		assert_eq!(bloom_ref.0.len(), BLOOM_SIZE);
		for i in 0..BLOOM_SIZE {
			let a = self.0[i];
			let b = bloom_ref.0[i];
			if (a & b) != b {
				return false;
			}
		}
		true
	}

	pub fn data(&self) -> &'a [u8; BLOOM_SIZE] {
		self.0
	}
}

impl<'a> From<&'a [u8; BLOOM_SIZE]> for BloomRef<'a> {
	fn from(data: &'a [u8; BLOOM_SIZE]) -> Self {
		BloomRef(data)
	}
}

impl<'a> From<&'a Bloom> for BloomRef<'a> {
	fn from(bloom: &'a Bloom) -> Self {
		BloomRef(&bloom.0)
	}
}

#[cfg(feature="serialize")]
impl Serialize for Bloom {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
		let mut slice = [0u8; 2 + 2 * BLOOM_SIZE];
		ethereum_types_serialize::serialize(&mut slice, &self.0, serializer)
	}
}

#[cfg(feature="serialize")]
impl<'de> Deserialize<'de> for Bloom {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'de> {
		let mut bytes = [0; BLOOM_SIZE];
		ethereum_types_serialize::deserialize_check_len(deserializer, ethereum_types_serialize::ExpectedLen::Exact(&mut bytes))?;
		Ok(Bloom(bytes))
	}
}

#[cfg(test)]
mod tests {
	use {Bloom, Input};

	#[test]
	fn it_works() {
		let bloom: Bloom = "00000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002020000000000000000000000000000000000000000000008000000001000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".into();
		let address = hex!("ef2d6d194084c2de36e0dabfce45d046b37d1106");
		let topic = hex!("02c69be41d0b7e40352fc85be1cd65eb03d40ef8427a0ca4596b1ead9a00e9fc");

		let mut my_bloom = Bloom::default();
		assert!(!my_bloom.contains_input(Input::Raw(&address)));
		assert!(!my_bloom.contains_input(Input::Raw(&topic)));

		my_bloom.accrue(Input::Raw(&address));
		assert!(my_bloom.contains_input(Input::Raw(&address)));
		assert!(!my_bloom.contains_input(Input::Raw(&topic)));

		my_bloom.accrue(Input::Raw(&topic));
		assert!(my_bloom.contains_input(Input::Raw(&address)));
		assert!(my_bloom.contains_input(Input::Raw(&topic)));
		assert_eq!(my_bloom, bloom);
	}
}
