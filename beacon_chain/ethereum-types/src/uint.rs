#[cfg(feature="serialize")]
use serde::{Serialize, Serializer, Deserialize, Deserializer};

#[cfg(feature="serialize")]
use ethereum_types_serialize;

macro_rules! impl_serde {
	($name: ident, $len: expr) => {
		#[cfg(feature="serialize")]
		impl Serialize for $name {
			fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
				let mut slice = [0u8; 2 + 2 * $len * 8];
				let mut bytes = [0u8; $len * 8];
				self.to_big_endian(&mut bytes);
				ethereum_types_serialize::serialize_uint(&mut slice, &bytes, serializer)
			}
		}

		#[cfg(feature="serialize")]
		impl<'de> Deserialize<'de> for $name {
			fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'de> {
				let mut bytes = [0u8; $len * 8];
				let wrote = ethereum_types_serialize::deserialize_check_len(deserializer, ethereum_types_serialize::ExpectedLen::Between(0, &mut bytes))?;
				Ok(bytes[0..wrote].into())
			}
		}
	}
}

construct_uint!(U64, 1);
construct_uint!(U128, 2);
construct_uint!(U256, 4);
construct_uint!(U512, 8);

impl_serde!(U64, 1);
impl_serde!(U128, 2);
impl_serde!(U256, 4);
impl_serde!(U512, 8);

impl U256 {
	/// Multiplies two 256-bit integers to produce full 512-bit integer
	/// No overflow possible
	#[inline(always)]
	pub fn full_mul(self, other: U256) -> U512 {
		U512(uint_full_mul_reg!(U256, 4, self, other))
	}
}

impl From<U256> for U512 {
	fn from(value: U256) -> U512 {
		let U256(ref arr) = value;
		let mut ret = [0; 8];
		ret[0] = arr[0];
		ret[1] = arr[1];
		ret[2] = arr[2];
		ret[3] = arr[3];
		U512(ret)
	}
}

impl From<U512> for U256 {
	fn from(value: U512) -> U256 {
		let U512(ref arr) = value;
		if arr[4] | arr[5] | arr[6] | arr[7] != 0 {
			panic!("Overflow");
		}
		let mut ret = [0; 4];
		ret[0] = arr[0];
		ret[1] = arr[1];
		ret[2] = arr[2];
		ret[3] = arr[3];
		U256(ret)
	}
}

impl<'a> From<&'a U256> for U512 {
	fn from(value: &'a U256) -> U512 {
		let U256(ref arr) = *value;
		let mut ret = [0; 8];
		ret[0] = arr[0];
		ret[1] = arr[1];
		ret[2] = arr[2];
		ret[3] = arr[3];
		U512(ret)
	}
}

impl<'a> From<&'a U512> for U256 {
	fn from(value: &'a U512) -> U256 {
		let U512(ref arr) = *value;
		if arr[4] | arr[5] | arr[6] | arr[7] != 0 {
			panic!("Overflow");
		}
		let mut ret = [0; 4];
		ret[0] = arr[0];
		ret[1] = arr[1];
		ret[2] = arr[2];
		ret[3] = arr[3];
		U256(ret)
	}
}

impl From<U256> for U128 {
	fn from(value: U256) -> U128 {
		let U256(ref arr) = value;
		if arr[2] | arr[3] != 0 {
			panic!("Overflow");
		}
		let mut ret = [0; 2];
		ret[0] = arr[0];
		ret[1] = arr[1];
		U128(ret)
	}
}

impl From<U512> for U128 {
	fn from(value: U512) -> U128 {
		let U512(ref arr) = value;
		if arr[2] | arr[3] | arr[4] | arr[5] | arr[6] | arr[7] != 0 {
			panic!("Overflow");
		}
		let mut ret = [0; 2];
		ret[0] = arr[0];
		ret[1] = arr[1];
		U128(ret)
	}
}

impl From<U128> for U512 {
	fn from(value: U128) -> U512 {
		let U128(ref arr) = value;
		let mut ret = [0; 8];
		ret[0] = arr[0];
		ret[1] = arr[1];
		U512(ret)
	}
}

impl From<U128> for U256 {
	fn from(value: U128) -> U256 {
		let U128(ref arr) = value;
		let mut ret = [0; 4];
		ret[0] = arr[0];
		ret[1] = arr[1];
		U256(ret)
	}
}

impl From<U256> for u64 {
	fn from(value: U256) -> u64 {
		value.as_u64()
	}
}

impl From<U256> for u32 {
	fn from(value: U256) -> u32 {
		value.as_u32()
	}
}

#[cfg(test)]
mod tests {
	use super::{U256, U512};
	use std::u64::MAX;
	use serde_json as ser;

	macro_rules! test_serialize {
		($name: ident, $test_name: ident) => {
			#[test]
			fn $test_name() {
				let tests = vec![
					($name::from(0), "0x0"),
					($name::from(1), "0x1"),
					($name::from(2), "0x2"),
					($name::from(10), "0xa"),
					($name::from(15), "0xf"),
					($name::from(15), "0xf"),
					($name::from(16), "0x10"),
					($name::from(1_000), "0x3e8"),
					($name::from(100_000), "0x186a0"),
					($name::from(u64::max_value()), "0xffffffffffffffff"),
					($name::from(u64::max_value()) + 1, "0x10000000000000000"),
				];

				for (number, expected) in tests {
					assert_eq!(format!("{:?}", expected), ser::to_string_pretty(&number).unwrap());
					assert_eq!(number, ser::from_str(&format!("{:?}", expected)).unwrap());
				}

				// Invalid examples
				assert!(ser::from_str::<$name>("\"0x\"").unwrap_err().is_data());
				assert!(ser::from_str::<$name>("\"0xg\"").unwrap_err().is_data());
				assert!(ser::from_str::<$name>("\"\"").unwrap_err().is_data());
				assert!(ser::from_str::<$name>("\"10\"").unwrap_err().is_data());
				assert!(ser::from_str::<$name>("\"0\"").unwrap_err().is_data());
			}
		}
	}

	test_serialize!(U256, test_u256);
	test_serialize!(U512, test_u512);

	#[test]
	fn test_serialize_large_values() {
		assert_eq!(
			ser::to_string_pretty(&!U256::zero()).unwrap(),
			"\"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\""
		);
		assert!(
			ser::from_str::<U256>("\"0x1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\"").unwrap_err().is_data()
		);
	}

	#[test]
	fn fixed_arrays_roundtrip() {
		let raw: U256 = "7094875209347850239487502394881".into();
		let array: [u8; 32] = raw.into();
		let new_raw = array.into();

		assert_eq!(raw, new_raw);
	}

	#[test]
	fn u256_multi_full_mul() {
		let result = U256([0, 0, 0, 0]).full_mul(U256([0, 0, 0, 0]));
		assert_eq!(U512([0, 0, 0, 0, 0, 0, 0, 0]), result);

		let result = U256([1, 0, 0, 0]).full_mul(U256([1, 0, 0, 0]));
		assert_eq!(U512([1, 0, 0, 0, 0, 0, 0, 0]), result);

		let result = U256([5, 0, 0, 0]).full_mul(U256([5, 0, 0, 0]));
		assert_eq!(U512([25, 0, 0, 0, 0, 0, 0, 0]), result);

		let result = U256([0, 5, 0, 0]).full_mul(U256([0, 5, 0, 0]));
		assert_eq!(U512([0, 0, 25, 0, 0, 0, 0, 0]), result);

		let result = U256([0, 0, 0, 4]).full_mul(U256([4, 0, 0, 0]));
		assert_eq!(U512([0, 0, 0, 16, 0, 0, 0, 0]), result);

		let result = U256([0, 0, 0, 5]).full_mul(U256([2, 0, 0, 0]));
		assert_eq!(U512([0, 0, 0, 10, 0, 0, 0, 0]), result);

		let result = U256([0, 0, 2, 0]).full_mul(U256([0, 5, 0, 0]));
		assert_eq!(U512([0, 0, 0, 10, 0, 0, 0, 0]), result);

		let result = U256([0, 3, 0, 0]).full_mul(U256([0, 0, 3, 0]));
		assert_eq!(U512([0, 0, 0, 9, 0, 0, 0, 0]), result);

		let result = U256([0, 0, 8, 0]).full_mul(U256([0, 0, 6, 0]));
		assert_eq!(U512([0, 0, 0, 0, 48, 0, 0, 0]), result);

		let result = U256([9, 0, 0, 0]).full_mul(U256([0, 3, 0, 0]));
		assert_eq!(U512([0, 27, 0, 0, 0, 0, 0, 0]), result);

		let result = U256([MAX, 0, 0, 0]).full_mul(U256([MAX, 0, 0, 0]));
		assert_eq!(U512([1, MAX-1, 0, 0, 0, 0, 0, 0]), result);

		let result = U256([0, MAX, 0, 0]).full_mul(U256([MAX, 0, 0, 0]));
		assert_eq!(U512([0, 1, MAX-1, 0, 0, 0, 0, 0]), result);

		let result = U256([MAX, MAX, 0, 0]).full_mul(U256([MAX, 0, 0, 0]));
		assert_eq!(U512([1, MAX, MAX-1, 0, 0, 0, 0, 0]), result);

		let result = U256([MAX, 0, 0, 0]).full_mul(U256([MAX, MAX, 0, 0]));
		assert_eq!(U512([1, MAX, MAX-1, 0, 0, 0, 0, 0]), result);

		let result = U256([MAX, MAX, 0, 0]).full_mul(U256([MAX, MAX, 0, 0]));
		assert_eq!(U512([1, 0, MAX-1, MAX, 0, 0, 0, 0]), result);

		let result = U256([MAX, 0, 0, 0]).full_mul(U256([MAX, MAX, MAX, 0]));
		assert_eq!(U512([1, MAX, MAX, MAX-1, 0, 0, 0, 0]), result);

		let result = U256([MAX, MAX, MAX, 0]).full_mul(U256([MAX, 0, 0, 0]));
		assert_eq!(U512([1, MAX, MAX, MAX-1, 0, 0, 0, 0]), result);

		let result = U256([MAX, 0, 0, 0]).full_mul(U256([MAX, MAX, MAX, MAX]));
		assert_eq!(U512([1, MAX, MAX, MAX, MAX-1, 0, 0, 0]), result);

		let result = U256([MAX, MAX, MAX, MAX]).full_mul(U256([MAX, 0, 0, 0]));
		assert_eq!(U512([1, MAX, MAX, MAX, MAX-1, 0, 0, 0]), result);

		let result = U256([MAX, MAX, MAX, 0]).full_mul(U256([MAX, MAX, 0, 0]));
		assert_eq!(U512([1, 0, MAX, MAX-1, MAX, 0, 0, 0]), result);

		let result = U256([MAX, MAX, 0, 0]).full_mul(U256([MAX, MAX, MAX, 0]));
		assert_eq!(U512([1, 0, MAX, MAX-1, MAX, 0, 0, 0]), result);

		let result = U256([MAX, MAX, MAX, MAX]).full_mul(U256([MAX, MAX, 0, 0]));
		assert_eq!(U512([1, 0, MAX, MAX, MAX-1, MAX, 0, 0]), result);

		let result = U256([MAX, MAX, 0, 0]).full_mul(U256([MAX, MAX, MAX, MAX]));
		assert_eq!(U512([1, 0, MAX, MAX, MAX-1, MAX, 0, 0]), result);

		let result = U256([MAX, MAX, MAX, 0]).full_mul(U256([MAX, MAX, MAX, 0]));
		assert_eq!(U512([1, 0, 0, MAX-1, MAX, MAX, 0, 0]), result);

		let result = U256([MAX, MAX, MAX, 0]).full_mul(U256([MAX, MAX, MAX, MAX]));
		assert_eq!(U512([1, 0, 0, MAX,	MAX-1, MAX, MAX, 0]), result);

		let result = U256([MAX, MAX, MAX, MAX]).full_mul(U256([MAX, MAX, MAX, 0]));
		assert_eq!(U512([1, 0, 0, MAX,	MAX-1, MAX, MAX, 0]), result);

		let result = U256([MAX, MAX, MAX, MAX]).full_mul(U256([MAX, MAX, MAX, MAX]));
		assert_eq!(U512([1, 0, 0, 0, MAX-1, MAX, MAX, MAX]), result);

		let result = U256([0, 0, 0, MAX]).full_mul(U256([0, 0, 0, MAX]));
		assert_eq!(U512([0, 0, 0, 0, 0, 0, 1, MAX-1]), result);

		let result = U256([1, 0, 0, 0]).full_mul(U256([0, 0, 0, MAX]));
		assert_eq!(U512([0, 0, 0, MAX, 0, 0, 0, 0]), result);

		let result = U256([1, 2, 3, 4]).full_mul(U256([5, 0, 0, 0]));
		assert_eq!(U512([5, 10, 15, 20, 0, 0, 0, 0]), result);

		let result = U256([1, 2, 3, 4]).full_mul(U256([0, 6, 0, 0]));
		assert_eq!(U512([0, 6, 12, 18, 24, 0, 0, 0]), result);

		let result = U256([1, 2, 3, 4]).full_mul(U256([0, 0, 7, 0]));
		assert_eq!(U512([0, 0, 7, 14, 21, 28, 0, 0]), result);

		let result = U256([1, 2, 3, 4]).full_mul(U256([0, 0, 0, 8]));
		assert_eq!(U512([0, 0, 0, 8, 16, 24, 32, 0]), result);

		let result = U256([1, 2, 3, 4]).full_mul(U256([5, 6, 7, 8]));
		assert_eq!(U512([5, 16, 34, 60, 61, 52, 32, 0]), result);
	}
}