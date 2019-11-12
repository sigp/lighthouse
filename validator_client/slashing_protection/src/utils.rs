pub fn u64_to_i64(x: u64) -> i64 {
    x.wrapping_sub(2u64.pow(63)) as i64
}

pub fn i64_to_u64(x: i64) -> u64 {
    (x as u64).wrapping_add(2u64.pow(63))
}

#[cfg(test)]
mod conv_tests {
    use super::*;

    #[test]
    fn u_zero() {
        let k = 0;
        let i = u64_to_i64(k);
        assert_eq!(i, i64::min_value());

        let u = i64_to_u64(i);
        assert_eq!(u, k);
    }

    #[test]
    fn u_one() {
        let k = 1;
        let i = u64_to_i64(k);
        assert_eq!(i, i64::min_value() + 1);

        let u = i64_to_u64(i);
        assert_eq!(u, k);
    }

    #[test]
    fn i_max() {
        let i = i64::max_value();

        let u = i64_to_u64(i);
        assert_eq!(u, u64::max_value());
    }

    #[test]
    fn i_zero() {
        let i = 0;

        let u = i64_to_u64(i);
        assert_eq!(u, u64::max_value() / 2 + 1);
    }
}
