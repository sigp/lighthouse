macro_rules! impl_from_into_u64 {
    ($main: ident) => {
        impl From<u64> for $main {
            fn from(n: u64) -> $main {
                $main(n)
            }
        }

        impl Into<u64> for $main {
            fn into(self) -> u64 {
                self.0
            }
        }

        impl $main {
            pub fn as_u64(&self) -> u64 {
                self.0
            }
        }
    };
}

macro_rules! impl_from_into_usize {
    ($main: ident) => {
        impl From<usize> for $main {
            fn from(n: usize) -> $main {
                $main(n as u64)
            }
        }

        impl Into<usize> for $main {
            fn into(self) -> usize {
                self.0 as usize
            }
        }

        impl $main {
            pub fn as_usize(&self) -> usize {
                self.0 as usize
            }
        }
    };
}

macro_rules! impl_math_between {
    ($main: ident, $other: ident) => {
        impl PartialOrd<$other> for $main {
            /// Utilizes `partial_cmp` on the underlying `u64`.
            fn partial_cmp(&self, other: &$other) -> Option<Ordering> {
                Some(self.0.cmp(&(*other).into()))
            }
        }

        impl PartialEq<$other> for $main {
            fn eq(&self, other: &$other) -> bool {
                let other: u64 = (*other).into();
                self.0 == other
            }
        }

        impl Add<$other> for $main {
            type Output = $main;

            fn add(self, other: $other) -> $main {
                $main::from(self.0.saturating_add(other.into()))
            }
        }

        impl AddAssign<$other> for $main {
            fn add_assign(&mut self, other: $other) {
                self.0 = self.0.saturating_add(other.into());
            }
        }

        impl Sub<$other> for $main {
            type Output = $main;

            fn sub(self, other: $other) -> $main {
                $main::from(self.0.saturating_sub(other.into()))
            }
        }

        impl SubAssign<$other> for $main {
            fn sub_assign(&mut self, other: $other) {
                self.0 = self.0.saturating_sub(other.into());
            }
        }

        impl Mul<$other> for $main {
            type Output = $main;

            fn mul(self, rhs: $other) -> $main {
                let rhs: u64 = rhs.into();
                $main::from(self.0.saturating_mul(rhs))
            }
        }

        impl MulAssign<$other> for $main {
            fn mul_assign(&mut self, rhs: $other) {
                let rhs: u64 = rhs.into();
                self.0 = self.0.saturating_mul(rhs)
            }
        }

        impl Div<$other> for $main {
            type Output = $main;

            fn div(self, rhs: $other) -> $main {
                let rhs: u64 = rhs.into();
                if rhs == 0 {
                    panic!("Cannot divide by zero-valued Slot/Epoch")
                }
                $main::from(self.0 / rhs)
            }
        }

        impl DivAssign<$other> for $main {
            fn div_assign(&mut self, rhs: $other) {
                let rhs: u64 = rhs.into();
                if rhs == 0 {
                    panic!("Cannot divide by zero-valued Slot/Epoch")
                }
                self.0 = self.0 / rhs
            }
        }

        impl Rem<$other> for $main {
            type Output = $main;

            fn rem(self, modulus: $other) -> $main {
                let modulus: u64 = modulus.into();
                $main::from(self.0 % modulus)
            }
        }
    };
}

macro_rules! impl_math {
    ($type: ident) => {
        impl $type {
            pub fn saturating_sub<T: Into<$type>>(&self, other: T) -> $type {
                *self - other.into()
            }

            pub fn saturating_add<T: Into<$type>>(&self, other: T) -> $type {
                *self + other.into()
            }

            pub fn checked_div<T: Into<$type>>(&self, rhs: T) -> Option<$type> {
                let rhs: $type = rhs.into();
                if rhs == 0 {
                    None
                } else {
                    Some(*self / rhs)
                }
            }

            pub fn is_power_of_two(&self) -> bool {
                self.0.is_power_of_two()
            }
        }

        impl Ord for $type {
            fn cmp(&self, other: &$type) -> Ordering {
                let other: u64 = (*other).into();
                self.0.cmp(&other)
            }
        }
    };
}

macro_rules! impl_display {
    ($type: ident) => {
        impl fmt::Display for $type {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl slog::Value for $type {
            fn serialize(
                &self,
                record: &slog::Record,
                key: slog::Key,
                serializer: &mut dyn slog::Serializer,
            ) -> slog::Result {
                slog::Value::serialize(&self.0, record, key, serializer)
            }
        }
    };
}

macro_rules! impl_ssz {
    ($type: ident) => {
        impl Encode for $type {
            fn is_ssz_fixed_len() -> bool {
                <u64 as Encode>::is_ssz_fixed_len()
            }

            fn ssz_fixed_len() -> usize {
                <u64 as Encode>::ssz_fixed_len()
            }

            fn ssz_bytes_len(&self) -> usize {
                0_u64.ssz_bytes_len()
            }

            fn ssz_append(&self, buf: &mut Vec<u8>) {
                self.0.ssz_append(buf)
            }
        }

        impl Decode for $type {
            fn is_ssz_fixed_len() -> bool {
                <u64 as Decode>::is_ssz_fixed_len()
            }

            fn ssz_fixed_len() -> usize {
                <u64 as Decode>::ssz_fixed_len()
            }

            fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, DecodeError> {
                Ok($type(u64::from_ssz_bytes(bytes)?))
            }
        }

        impl tree_hash::TreeHash for $type {
            fn tree_hash_type() -> tree_hash::TreeHashType {
                tree_hash::TreeHashType::Basic
            }

            fn tree_hash_packed_encoding(&self) -> Vec<u8> {
                ssz_encode(self)
            }

            fn tree_hash_packing_factor() -> usize {
                32 / 8
            }

            fn tree_hash_root(&self) -> Vec<u8> {
                int_to_bytes::int_to_bytes32(self.0)
            }
        }

        impl TestRandom for $type {
            fn random_for_test(rng: &mut impl RngCore) -> Self {
                $type::from(u64::random_for_test(rng))
            }
        }
    };
}

macro_rules! impl_hash {
    ($type: ident) => {
        // Implemented to stop clippy lint:
        // https://rust-lang.github.io/rust-clippy/master/index.html#derive_hash_xor_eq
        impl Hash for $type {
            fn hash<H: Hasher>(&self, state: &mut H) {
                ssz_encode(self).hash(state)
            }
        }
    };
}

macro_rules! impl_common {
    ($type: ident) => {
        impl_from_into_u64!($type);
        impl_from_into_usize!($type);
        impl_math_between!($type, $type);
        impl_math_between!($type, u64);
        impl_math!($type);
        impl_display!($type);
        impl_ssz!($type);
        impl_hash!($type);
    };
}

// test macros
#[cfg(test)]
macro_rules! new_tests {
    ($type: ident) => {
        #[test]
        fn new() {
            assert_eq!($type(0), $type::new(0));
            assert_eq!($type(3), $type::new(3));
            assert_eq!($type(u64::max_value()), $type::new(u64::max_value()));
        }
    };
}

#[cfg(test)]
macro_rules! from_into_tests {
    ($type: ident, $other: ident) => {
        #[test]
        fn into() {
            let x: $other = $type(0).into();
            assert_eq!(x, 0);

            let x: $other = $type(3).into();
            assert_eq!(x, 3);

            let x: $other = $type(u64::max_value()).into();
            // Note: this will fail on 32 bit systems. This is expected as we don't have a proper
            // 32-bit system strategy in place.
            assert_eq!(x, $other::max_value());
        }

        #[test]
        fn from() {
            assert_eq!($type(0), $type::from(0_u64));
            assert_eq!($type(3), $type::from(3_u64));
            assert_eq!($type(u64::max_value()), $type::from($other::max_value()));
        }
    };
}

#[cfg(test)]
macro_rules! math_between_tests {
    ($type: ident, $other: ident) => {
        #[test]
        fn partial_ord() {
            let assert_partial_ord = |a: u64, partial_ord: Ordering, b: u64| {
                let other: $other = $type(b).into();
                assert_eq!($type(a).partial_cmp(&other), Some(partial_ord));
            };

            assert_partial_ord(1, Ordering::Less, 2);
            assert_partial_ord(2, Ordering::Greater, 1);
            assert_partial_ord(0, Ordering::Less, u64::max_value());
            assert_partial_ord(u64::max_value(), Ordering::Greater, 0);
        }

        #[test]
        fn partial_eq() {
            let assert_partial_eq = |a: u64, b: u64, is_equal: bool| {
                let other: $other = $type(b).into();
                assert_eq!($type(a).eq(&other), is_equal);
            };

            assert_partial_eq(0, 0, true);
            assert_partial_eq(0, 1, false);
            assert_partial_eq(1, 0, false);
            assert_partial_eq(1, 1, true);

            assert_partial_eq(u64::max_value(), u64::max_value(), true);
            assert_partial_eq(0, u64::max_value(), false);
            assert_partial_eq(u64::max_value(), 0, false);
        }

        #[test]
        fn add_and_add_assign() {
            let assert_add = |a: u64, b: u64, result: u64| {
                let other: $other = $type(b).into();
                assert_eq!($type(a) + other, $type(result));

                let mut add_assigned = $type(a);
                add_assigned += other;

                assert_eq!(add_assigned, $type(result));
            };

            assert_add(0, 1, 1);
            assert_add(1, 0, 1);
            assert_add(1, 2, 3);
            assert_add(2, 1, 3);
            assert_add(7, 7, 14);

            // Addition should be saturating.
            assert_add(u64::max_value(), 1, u64::max_value());
            assert_add(u64::max_value(), u64::max_value(), u64::max_value());
        }

        #[test]
        fn sub_and_sub_assign() {
            let assert_sub = |a: u64, b: u64, result: u64| {
                let other: $other = $type(b).into();
                assert_eq!($type(a) - other, $type(result));

                let mut sub_assigned = $type(a);
                sub_assigned -= other;

                assert_eq!(sub_assigned, $type(result));
            };

            assert_sub(1, 0, 1);
            assert_sub(2, 1, 1);
            assert_sub(14, 7, 7);
            assert_sub(u64::max_value(), 1, u64::max_value() - 1);
            assert_sub(u64::max_value(), u64::max_value(), 0);

            // Subtraction should be saturating
            assert_sub(0, 1, 0);
            assert_sub(1, 2, 0);
        }

        #[test]
        fn mul_and_mul_assign() {
            let assert_mul = |a: u64, b: u64, result: u64| {
                let other: $other = $type(b).into();
                assert_eq!($type(a) * other, $type(result));

                let mut mul_assigned = $type(a);
                mul_assigned *= other;

                assert_eq!(mul_assigned, $type(result));
            };

            assert_mul(2, 2, 4);
            assert_mul(1, 2, 2);
            assert_mul(0, 2, 0);

            // Multiplication should be saturating.
            assert_mul(u64::max_value(), 2, u64::max_value());
        }

        #[test]
        fn div_and_div_assign() {
            let assert_div = |a: u64, b: u64, result: u64| {
                let other: $other = $type(b).into();
                assert_eq!($type(a) / other, $type(result));

                let mut div_assigned = $type(a);
                div_assigned /= other;

                assert_eq!(div_assigned, $type(result));
            };

            assert_div(0, 2, 0);
            assert_div(2, 2, 1);
            assert_div(100, 50, 2);
            assert_div(128, 2, 64);
            assert_div(u64::max_value(), 2, 2_u64.pow(63) - 1);
        }

        #[test]
        #[should_panic]
        fn div_panics_with_divide_by_zero() {
            let other: $other = $type(0).into();
            let _ = $type(2) / other;
        }

        #[test]
        #[should_panic]
        fn div_assign_panics_with_divide_by_zero() {
            let other: $other = $type(0).into();
            let mut assigned = $type(2);
            assigned /= other;
        }

        #[test]
        fn rem() {
            let assert_rem = |a: u64, b: u64, result: u64| {
                let other: $other = $type(b).into();
                assert_eq!($type(a) % other, $type(result));
            };

            assert_rem(3, 2, 1);
            assert_rem(40, 2, 0);
            assert_rem(10, 100, 10);
            assert_rem(302042, 3293, 2379);
        }
    };
}

#[cfg(test)]
macro_rules! math_tests {
    ($type: ident) => {
        #[test]
        fn saturating_sub() {
            let assert_saturating_sub = |a: u64, b: u64, result: u64| {
                assert_eq!($type(a).saturating_sub($type(b)), $type(result));
            };

            assert_saturating_sub(1, 0, 1);
            assert_saturating_sub(2, 1, 1);
            assert_saturating_sub(14, 7, 7);
            assert_saturating_sub(u64::max_value(), 1, u64::max_value() - 1);
            assert_saturating_sub(u64::max_value(), u64::max_value(), 0);

            // Subtraction should be saturating
            assert_saturating_sub(0, 1, 0);
            assert_saturating_sub(1, 2, 0);
        }

        #[test]
        fn saturating_add() {
            let assert_saturating_add = |a: u64, b: u64, result: u64| {
                assert_eq!($type(a).saturating_add($type(b)), $type(result));
            };

            assert_saturating_add(0, 1, 1);
            assert_saturating_add(1, 0, 1);
            assert_saturating_add(1, 2, 3);
            assert_saturating_add(2, 1, 3);
            assert_saturating_add(7, 7, 14);

            // Addition should be saturating.
            assert_saturating_add(u64::max_value(), 1, u64::max_value());
            assert_saturating_add(u64::max_value(), u64::max_value(), u64::max_value());
        }

        #[test]
        fn checked_div() {
            let assert_checked_div = |a: u64, b: u64, result: Option<u64>| {
                let division_result_as_u64 = match $type(a).checked_div($type(b)) {
                    None => None,
                    Some(val) => Some(val.as_u64()),
                };
                assert_eq!(division_result_as_u64, result);
            };

            assert_checked_div(0, 2, Some(0));
            assert_checked_div(2, 2, Some(1));
            assert_checked_div(100, 50, Some(2));
            assert_checked_div(128, 2, Some(64));
            assert_checked_div(u64::max_value(), 2, Some(2_u64.pow(63) - 1));

            assert_checked_div(2, 0, None);
            assert_checked_div(0, 0, None);
            assert_checked_div(u64::max_value(), 0, None);
        }

        #[test]
        fn is_power_of_two() {
            let assert_is_power_of_two = |a: u64, result: bool| {
                assert_eq!(
                    $type(a).is_power_of_two(),
                    result,
                    "{}.is_power_of_two() != {}",
                    a,
                    result
                );
            };

            assert_is_power_of_two(0, false);
            assert_is_power_of_two(1, true);
            assert_is_power_of_two(2, true);
            assert_is_power_of_two(3, false);
            assert_is_power_of_two(4, true);

            assert_is_power_of_two(2_u64.pow(4), true);
            assert_is_power_of_two(u64::max_value(), false);
        }

        #[test]
        fn ord() {
            let assert_ord = |a: u64, ord: Ordering, b: u64| {
                assert_eq!($type(a).cmp(&$type(b)), ord);
            };

            assert_ord(1, Ordering::Less, 2);
            assert_ord(2, Ordering::Greater, 1);
            assert_ord(0, Ordering::Less, u64::max_value());
            assert_ord(u64::max_value(), Ordering::Greater, 0);
        }
    };
}

#[cfg(test)]
macro_rules! all_tests {
    ($type: ident) => {
        new_tests!($type);
        math_between_tests!($type, $type);
        math_tests!($type);
        ssz_tests!($type);

        mod u64_tests {
            use super::*;

            from_into_tests!($type, u64);
            math_between_tests!($type, u64);

            #[test]
            pub fn as_64() {
                let x = $type(0).as_u64();
                assert_eq!(x, 0);

                let x = $type(3).as_u64();
                assert_eq!(x, 3);

                let x = $type(u64::max_value()).as_u64();
                assert_eq!(x, u64::max_value());
            }
        }

        mod usize_tests {
            use super::*;

            from_into_tests!($type, usize);

            #[test]
            pub fn as_usize() {
                let x = $type(0).as_usize();
                assert_eq!(x, 0);

                let x = $type(3).as_usize();
                assert_eq!(x, 3);

                let x = $type(u64::max_value()).as_usize();
                assert_eq!(x, usize::max_value());
            }
        }
    };
}
