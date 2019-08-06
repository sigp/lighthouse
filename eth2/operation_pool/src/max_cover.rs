/// Trait for types that we can compute a maximum cover for.
///
/// Terminology:
/// * `item`: something that implements this trait
/// * `element`: something contained in a set, and covered by the covering set of an item
/// * `object`: something extracted from an item in order to comprise a solution
/// See: https://en.wikipedia.org/wiki/Maximum_coverage_problem
pub trait MaxCover {
    /// The result type, of which we would eventually like a collection of maximal quality.
    type Object;
    /// The type used to represent sets.
    type Set: Clone;

    /// Extract an object for inclusion in a solution.
    fn object(&self) -> Self::Object;

    /// Get the set of elements covered.
    fn covering_set(&self) -> &Self::Set;
    /// Update the set of items covered, for the inclusion of some object in the solution.
    fn update_covering_set(&mut self, max_obj: &Self::Object, max_set: &Self::Set);
    /// The quality of this item's covering set, usually its cardinality.
    fn score(&self) -> usize;
}

/// Helper struct to track which items of the input are still available for inclusion.
/// Saves removing elements from the work vector.
struct MaxCoverItem<T> {
    item: T,
    available: bool,
}

impl<T> MaxCoverItem<T> {
    fn new(item: T) -> Self {
        MaxCoverItem {
            item,
            available: true,
        }
    }
}

/// Compute an approximate maximum cover using a greedy algorithm.
///
/// * Time complexity: `O(limit * items_iter.len())`
/// * Space complexity: `O(item_iter.len())`
pub fn maximum_cover<I, T>(items_iter: I, limit: usize) -> Vec<T::Object>
where
    I: IntoIterator<Item = T>,
    T: MaxCover,
{
    // Construct an initial vec of all items, marked available.
    let mut all_items: Vec<_> = items_iter
        .into_iter()
        .map(MaxCoverItem::new)
        .filter(|x| x.item.score() != 0)
        .collect();

    let mut result = vec![];

    for _ in 0..limit {
        // Select the item with the maximum score.
        let (best_item, best_cover) = match all_items
            .iter_mut()
            .filter(|x| x.available && x.item.score() != 0)
            .max_by_key(|x| x.item.score())
        {
            Some(x) => {
                x.available = false;
                (x.item.object(), x.item.covering_set().clone())
            }
            None => return result,
        };

        // Update the covering sets of the other items, for the inclusion of the selected item.
        // Items covered by the selected item can't be re-covered.
        all_items
            .iter_mut()
            .filter(|x| x.available && x.item.score() != 0)
            .for_each(|x| x.item.update_covering_set(&best_item, &best_cover));

        result.push(best_item);
    }

    result
}

#[cfg(test)]
mod test {
    use super::*;
    use std::iter::FromIterator;
    use std::{collections::HashSet, hash::Hash};

    impl<T> MaxCover for HashSet<T>
    where
        T: Clone + Eq + Hash,
    {
        type Object = Self;
        type Set = Self;

        fn object(&self) -> Self {
            self.clone()
        }

        fn covering_set(&self) -> &Self {
            &self
        }

        fn update_covering_set(&mut self, _: &Self, other: &Self) {
            let mut difference = &*self - other;
            std::mem::swap(self, &mut difference);
        }

        fn score(&self) -> usize {
            self.len()
        }
    }

    fn example_system() -> Vec<HashSet<usize>> {
        vec![
            HashSet::from_iter(vec![3]),
            HashSet::from_iter(vec![1, 2, 4, 5]),
            HashSet::from_iter(vec![1, 2, 4, 5]),
            HashSet::from_iter(vec![1]),
            HashSet::from_iter(vec![2, 4, 5]),
        ]
    }

    #[test]
    fn zero_limit() {
        let cover = maximum_cover(example_system(), 0);
        assert_eq!(cover.len(), 0);
    }

    #[test]
    fn one_limit() {
        let sets = example_system();
        let cover = maximum_cover(sets.clone(), 1);
        assert_eq!(cover.len(), 1);
        assert_eq!(cover[0], sets[1]);
    }

    // Check that even if the limit provides room, we don't include useless items in the soln.
    #[test]
    fn exclude_zero_score() {
        let sets = example_system();
        for k in 2..10 {
            let cover = maximum_cover(sets.clone(), k);
            assert_eq!(cover.len(), 2);
            assert_eq!(cover[0], sets[1]);
            assert_eq!(cover[1], sets[0]);
        }
    }

    fn quality<T: Eq + Hash>(solution: &[HashSet<T>]) -> usize {
        solution.iter().map(HashSet::len).sum()
    }

    // Optimal solution is the first three sets (quality 15) but our greedy algorithm
    // will select the last three (quality 11). The comment at the end of each line
    // shows that set's score at each iteration, with a * indicating that it will be chosen.
    #[test]
    fn suboptimal() {
        let sets = vec![
            HashSet::from_iter(vec![0, 1, 8, 11, 14]), // 5, 3, 2
            HashSet::from_iter(vec![2, 3, 7, 9, 10]),  // 5, 3, 2
            HashSet::from_iter(vec![4, 5, 6, 12, 13]), // 5, 4, 2
            HashSet::from_iter(vec![9, 10]),           // 4, 4, 2*
            HashSet::from_iter(vec![5, 6, 7, 8]),      // 4, 4*
            HashSet::from_iter(vec![0, 1, 2, 3, 4]),   // 5*
        ];
        let cover = maximum_cover(sets.clone(), 3);
        assert_eq!(quality(&cover), 11);
    }

    #[test]
    fn intersecting_ok() {
        let sets = vec![
            HashSet::from_iter(vec![1, 2, 3, 4, 5, 6, 7, 8]),
            HashSet::from_iter(vec![1, 2, 3, 9, 10, 11]),
            HashSet::from_iter(vec![4, 5, 6, 12, 13, 14]),
            HashSet::from_iter(vec![7, 8, 15, 16, 17, 18]),
            HashSet::from_iter(vec![1, 2, 9, 10]),
            HashSet::from_iter(vec![1, 5, 6, 8]),
            HashSet::from_iter(vec![1, 7, 11, 19]),
        ];
        let cover = maximum_cover(sets.clone(), 5);
        assert_eq!(quality(&cover), 19);
        assert_eq!(cover.len(), 5);
    }
}
