#![feature(test)]

extern crate test;
extern crate rustc_hex;
extern crate tiny_keccak;
extern crate ethbloom;

use test::Bencher;
use rustc_hex::FromHex;
use tiny_keccak::keccak256;
use ethbloom::{Bloom, Input};

fn test_bloom() -> Bloom {
	"00000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002020000000000000000000000000000000000000000000008000000001000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".into()
}

fn test_topic() -> Vec<u8> {
	"02c69be41d0b7e40352fc85be1cd65eb03d40ef8427a0ca4596b1ead9a00e9fc".from_hex().unwrap()
}

fn test_address() -> Vec<u8> {
	"ef2d6d194084c2de36e0dabfce45d046b37d1106".from_hex().unwrap()
}

fn test_dummy() -> Vec<u8> {
	b"123456".to_vec()
}

fn test_dummy2() -> Vec<u8> {
	b"654321".to_vec()
}

#[bench]
fn accrue_raw(b: &mut Bencher) {
	let mut bloom = Bloom::default();
	let topic = test_topic();
	let address = test_address();
	b.iter(|| {
		bloom.accrue(Input::Raw(&topic));
		bloom.accrue(Input::Raw(&address));
	});
}

#[bench]
fn accrue_hash(b: &mut Bencher) {
	let mut bloom = Bloom::default();
	let topic = keccak256(&test_topic());
	let address = keccak256(&test_address());
	b.iter(|| {
		bloom.accrue(Input::Hash(&topic));
		bloom.accrue(Input::Hash(&address));
	});
}

#[bench]
fn contains_input_raw(b: &mut Bencher) {
	let bloom = test_bloom();
	let topic = test_topic();
	let address = test_address();
	b.iter(|| {
		assert!(bloom.contains_input(Input::Raw(&topic)));
		assert!(bloom.contains_input(Input::Raw(&address)));
	});
}

#[bench]
fn does_not_contain_raw(b: &mut Bencher) {
	let bloom = test_bloom();
	let dummy = test_dummy();
	let dummy2 = test_dummy2();
	b.iter(|| {
		assert!(!bloom.contains_input(Input::Raw(&dummy)));
		assert!(!bloom.contains_input(Input::Raw(&dummy2)));
	});
}

#[bench]
fn contains_input_hash(b: &mut Bencher) {
	let bloom = test_bloom();
	let topic = keccak256(&test_topic());
	let address = keccak256(&test_address());
	b.iter(|| {
		assert!(bloom.contains_input(Input::Hash(&topic)));
		assert!(bloom.contains_input(Input::Hash(&address)));
	});
}

#[bench]
fn does_not_contain_hash(b: &mut Bencher) {
	let bloom = test_bloom();
	let dummy = keccak256(&test_dummy());
	let dummy2 = keccak256(&test_dummy2());
	b.iter(|| {
		assert!(!bloom.contains_input(Input::Hash(&dummy)));
		assert!(!bloom.contains_input(Input::Hash(&dummy2)));
	});
}

#[bench]
fn does_not_contain_random_hash(b: &mut Bencher) {
	let bloom = test_bloom();
	let dummy: Vec<_> = (0..255u8).into_iter().map(|i| keccak256(&[i])).collect();
	b.iter(|| {
		for d in &dummy {
			assert!(!bloom.contains_input(Input::Hash(d)));
		}
	});
}
