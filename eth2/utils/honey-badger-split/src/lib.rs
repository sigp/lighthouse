/// A function for splitting a list into N pieces.
///
/// We have titled it the "honey badger split" because of its robustness. It don't care.

/// Iterator for the honey_badger_split function
pub struct Split<'a, T: 'a> {
    n: usize,
    current_pos: usize,
    list: &'a [T],
    list_length: usize,
}

impl<'a, T> Iterator for Split<'a, T> {
    type Item = &'a [T];

    fn next(&mut self) -> Option<Self::Item> {
        self.current_pos += 1;
        if self.current_pos <= self.n {
            match self.list.get(
                self.list_length * (self.current_pos - 1) / self.n
                    ..self.list_length * self.current_pos / self.n,
            ) {
                Some(v) => Some(v),
                None => unreachable!(),
            }
        } else {
            None
        }
    }
}

/// Splits a slice into chunks of size n. All postive n values are applicable,
/// hence the honey_badger prefix.
///
/// Returns an iterator over the original list.
pub trait SplitExt<T> {
    fn honey_badger_split(&self, n: usize) -> Split<T>;
}

impl<T> SplitExt<T> for [T] {
    fn honey_badger_split(&self, n: usize) -> Split<T> {
        Split {
            n,
            current_pos: 0,
            list: &self,
            list_length: self.len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_honey_badger_split() {
        /*
         * These test cases are generated from the eth2.0 spec `split()`
         * function at commit cbd254a.
         */
        let input: Vec<usize> = vec![0, 1, 2, 3];
        let output: Vec<&[usize]> = input.honey_badger_split(2).collect();
        assert_eq!(output, vec![&[0, 1], &[2, 3]]);

        let input: Vec<usize> = vec![0, 1, 2, 3];
        let output: Vec<&[usize]> = input.honey_badger_split(6).collect();
        let expected: Vec<&[usize]> = vec![&[], &[0], &[1], &[], &[2], &[3]];
        assert_eq!(output, expected);

        let input: Vec<usize> = vec![0, 1, 2, 3];
        let output: Vec<&[usize]> = input.honey_badger_split(10).collect();
        let expected: Vec<&[usize]> = vec![&[], &[], &[0], &[], &[1], &[], &[], &[2], &[], &[3]];
        assert_eq!(output, expected);

        let input: Vec<usize> = vec![0];
        let output: Vec<&[usize]> = input.honey_badger_split(5).collect();
        let expected: Vec<&[usize]> = vec![&[], &[], &[], &[], &[0]];
        assert_eq!(output, expected);

        let input: Vec<usize> = vec![0, 1, 2];
        let output: Vec<&[usize]> = input.honey_badger_split(2).collect();
        let expected: Vec<&[usize]> = vec![&[0], &[1, 2]];
        assert_eq!(output, expected);
    }
}
