use {U64, U128, U256, U512};

#[cfg(feature="serialize")]
use serde::{Serialize, Serializer, Deserialize, Deserializer};

#[cfg(feature="serialize")]
use ethereum_types_serialize;

macro_rules! impl_serde {
	($name: ident, $len: expr) => {
		#[cfg(feature="serialize")]
		impl Serialize for $name {
			fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
				let mut slice = [0u8; 2 + 2 * $len];
				ethereum_types_serialize::serialize(&mut slice, &self.0, serializer)
			}
		}

		#[cfg(feature="serialize")]
		impl<'de> Deserialize<'de> for $name {
			fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: Deserializer<'de> {
				let mut bytes = [0u8; $len];
				ethereum_types_serialize::deserialize_check_len(deserializer, ethereum_types_serialize::ExpectedLen::Exact(&mut bytes))?;
				Ok($name(bytes))
			}
		}
	}
}

macro_rules! impl_uint_conversions {
	($hash: ident, $uint: ident) => {
		impl From<$uint> for $hash {
			fn from(value: $uint) -> Self {
				let mut ret = $hash::new();
				value.to_big_endian(&mut ret);
				ret
			}
		}

		impl<'a> From<&'a $uint> for $hash {
			fn from(value: &'a $uint) -> Self {
				let mut ret = $hash::new();
				value.to_big_endian(&mut ret);
				ret
			}
		}

		impl From<$hash> for $uint {
			fn from(value: $hash) -> Self {
				Self::from(&value)
			}
		}

		impl<'a> From<&'a $hash> for $uint {
			fn from(value: &'a $hash) -> Self {
				Self::from(value.as_ref() as &[u8])
			}
		}
	}
}

impl_serde!(H32, 4);
impl_serde!(H64, 8);
impl_serde!(H128, 16);
impl_serde!(H160, 20);
impl_serde!(H256, 32);
impl_serde!(H264, 33);
impl_serde!(H512, 64);
impl_serde!(H520, 65);

construct_hash!(H32, 4);
construct_hash!(H64, 8);
construct_hash!(H128, 16);
construct_hash!(H160, 20);
construct_hash!(H256, 32);
construct_hash!(H264, 33);
construct_hash!(H512, 64);
construct_hash!(H520, 65);

impl_uint_conversions!(H64, U64);
impl_uint_conversions!(H128, U128);
impl_uint_conversions!(H256, U256);
impl_uint_conversions!(H512, U512);

#[deprecated]
impl From<H256> for H160 {
	fn from(value: H256) -> H160 {
		let mut ret = H160::new();
		ret.0.copy_from_slice(&value[12..32]);
		ret
	}
}

#[deprecated]
impl From<H256> for H64 {
	fn from(value: H256) -> H64 {
		let mut ret = H64::new();
		ret.0.copy_from_slice(&value[20..28]);
		ret
	}
}

impl From<H160> for H256 {
	fn from(value: H160) -> H256 {
		let mut ret = H256::new();
		ret.0[12..32].copy_from_slice(&value);
		ret
	}
}

impl<'a> From<&'a H160> for H256 {
	fn from(value: &'a H160) -> H256 {
		let mut ret = H256::new();
		ret.0[12..32].copy_from_slice(value);
		ret
	}
}

#[cfg(test)]
mod tests {
	use super::{H160, H256};
	use serde_json as ser;

	#[test]
	fn test_serialize_h160() {
		let tests = vec![
			(H160::from(0), "0x0000000000000000000000000000000000000000"),
			(H160::from(2), "0x0000000000000000000000000000000000000002"),
			(H160::from(15), "0x000000000000000000000000000000000000000f"),
			(H160::from(16), "0x0000000000000000000000000000000000000010"),
			(H160::from(1_000), "0x00000000000000000000000000000000000003e8"),
			(H160::from(100_000), "0x00000000000000000000000000000000000186a0"),
			(H160::from(u64::max_value()), "0x000000000000000000000000ffffffffffffffff"),
		];

		for (number, expected) in tests {
			assert_eq!(format!("{:?}", expected), ser::to_string_pretty(&number).unwrap());
			assert_eq!(number, ser::from_str(&format!("{:?}", expected)).unwrap());
		}
	}

	#[test]
	fn test_serialize_h256() {
		let tests = vec![
			(H256::from(0), "0x0000000000000000000000000000000000000000000000000000000000000000"),
			(H256::from(2), "0x0000000000000000000000000000000000000000000000000000000000000002"),
			(H256::from(15), "0x000000000000000000000000000000000000000000000000000000000000000f"),
			(H256::from(16), "0x0000000000000000000000000000000000000000000000000000000000000010"),
			(H256::from(1_000), "0x00000000000000000000000000000000000000000000000000000000000003e8"),
			(H256::from(100_000), "0x00000000000000000000000000000000000000000000000000000000000186a0"),
			(H256::from(u64::max_value()), "0x000000000000000000000000000000000000000000000000ffffffffffffffff"),
		];

		for (number, expected) in tests {
			assert_eq!(format!("{:?}", expected), ser::to_string_pretty(&number).unwrap());
			assert_eq!(number, ser::from_str(&format!("{:?}", expected)).unwrap());
		}
	}

	#[test]
	fn test_serialize_invalid() {
		assert!(ser::from_str::<H256>("\"0x000000000000000000000000000000000000000000000000000000000000000\"").unwrap_err().is_data());
		assert!(ser::from_str::<H256>("\"0x000000000000000000000000000000000000000000000000000000000000000g\"").unwrap_err().is_data());
		assert!(ser::from_str::<H256>("\"0x00000000000000000000000000000000000000000000000000000000000000000\"").unwrap_err().is_data());
		assert!(ser::from_str::<H256>("\"\"").unwrap_err().is_data());
		assert!(ser::from_str::<H256>("\"0\"").unwrap_err().is_data());
		assert!(ser::from_str::<H256>("\"10\"").unwrap_err().is_data());
	}
}