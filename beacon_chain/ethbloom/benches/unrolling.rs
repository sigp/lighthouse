#![feature(test)]

extern crate test;
extern crate rand;

#[macro_use]
extern crate crunchy;

use test::{Bencher, black_box};
use rand::Rng;

fn random_data() -> [u8; 256] {
	let mut res = [0u8; 256];
	rand::thread_rng().fill_bytes(&mut res);
	res
}

#[bench]
fn forwards_with_crunchy(b: &mut Bencher) {
	let mut data = random_data();
	b.iter(|| {
		let other_data = random_data();
		unroll! {
			for i in 0..255 {
				data[i] |= other_data[i];
			}
		}
	});

	black_box(data);
}

#[bench]
fn backwards_with_crunchy(b: &mut Bencher) {
	let mut data = random_data();
	b.iter(|| {
		let other_data = random_data();
		unroll! {
			for i in 0..255 {
				data[255-i] |= other_data[255-i];
			}
		}
	});

	black_box(data);
}


#[bench]
fn forwards_without_crunchy(b: &mut Bencher) {
	let mut data = random_data();
	b.iter(|| {
		let other_data = random_data();
		for i in 0..255 {
			data[i] |= other_data[i];
		}
	});

	black_box(data);
}

#[bench]
fn backwards_without_crunchy(b: &mut Bencher) {
	let mut data = random_data();
	b.iter(|| {
		let other_data = random_data();
		for i in 0..255 {
			data[255-i] |= other_data[255-i];
		}
	});

	black_box(data);
}
