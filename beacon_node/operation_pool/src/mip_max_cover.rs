use std::collections::HashMap;
use std::hash::Hash;
use std::iter::Sum;
use std::ops::Mul;

use good_lp::{constraint, default_solver, variable, variables, Expression, Solution, SolverModel};
use itertools::Itertools;

struct MipMaxCoverSet<'b, RawSet>
where
    RawSet: for<'a> MipMaxCover<'a>,
{
    raw_set: &'b RawSet,
    mapped_set: Vec<usize>,
}

pub struct MipMaxCoverProblemInstance<'b, RawSet>
where
    RawSet: for<'a> MipMaxCover<'a>,
{
    sets: Vec<MipMaxCoverSet<'b, RawSet>>,
    weights: Vec<f64>,
    limit: usize,
}

pub trait MipMaxCover<'a> {
    type Element: Clone + Hash + Ord;

    fn covering_set(&'a self) -> &'a Vec<Self::Element>;

    fn element_weight(&self, element: &Self::Element) -> Option<f64>;
}

impl<'b, RawSet> MipMaxCoverProblemInstance<'b, RawSet>
where
    RawSet: for<'a> MipMaxCover<'a>,
{
    const SOLUTION_LENGTH_SCALING_FACTOR: f64 = 0.0001f64;

    pub fn new(raw_sets: &Vec<RawSet>, limit: usize) -> Option<MipMaxCoverProblemInstance<RawSet>> {
        let ordered_elements: Vec<&RawSet::Element> = raw_sets
            .iter()
            .map(|s| s.covering_set())
            .flatten()
            .sorted_unstable()
            .dedup()
            .collect();

        let element_to_index: HashMap<&RawSet::Element, usize> = ordered_elements
            .iter()
            .enumerate()
            .map(|(idx, element)| (*element, idx))
            .collect();

        let mut element_to_weight = HashMap::new();

        raw_sets.iter().for_each(|s| {
            s.covering_set().iter().for_each(|e| {
                element_to_weight.insert(e, s.element_weight(&e).unwrap());
            });
        });

        let weights = ordered_elements
            .iter()
            .map(|e| *(element_to_weight.get(e).unwrap()))
            .collect();

        let sets = raw_sets
            .iter()
            .map(|s| MipMaxCoverSet {
                raw_set: s,
                mapped_set: s
                    .covering_set()
                    .iter()
                    .map(|e| *element_to_index.get(e).unwrap())
                    .collect(),
            })
            .collect();

        Some(MipMaxCoverProblemInstance {
            sets,
            weights,
            limit,
        })
    }

    pub fn max_cover(&self) -> Result<Vec<&RawSet>, &'static str> {
        // produce lists of sets containing a given element
        let mut sets_with: Vec<Vec<usize>> = vec![];
        sets_with.resize_with(self.weights.len(), Vec::new);
        for i in 0..self.sets.len() {
            for &j in &self.sets[i].mapped_set {
                sets_with[j].push(i);
            }
        }

        let mut vars = variables!();

        // initialise set variables
        let xs = vars.add_vector(variable().binary(), self.sets.len());

        // initialise element variables
        let ys = vars.add_vector(variable().min(0.0).max(1.0), self.weights.len());

        // define objective function as linear combination of element variables and weights
        let objective =
            Expression::sum((0..self.weights.len()).map(|yi| ys[yi].mul(self.weights[yi])))
                - Expression::sum((0..xs.len()).map(|xi| xs[xi]))
                    * Self::SOLUTION_LENGTH_SCALING_FACTOR;
        let mut problem = vars.maximise(objective).using(default_solver);

        // limit solution size to k sets
        problem = problem.with(Expression::sum(xs.iter()).leq(self.limit as f64));

        // add constraint allowing to cover an element only if one of the sets containing it is included
        for j in 0..self.weights.len() {
            problem = problem.with(constraint! {
                Expression::sum(sets_with[j].iter().map(|i| xs[*i])) >= ys[j]
            });
        }

        // tell CBC not to log
        problem.set_parameter("log", "0");

        // TODO: Verify this under the new assumptions
        // should be safe to `unwrap` since the problem is under-constrained
        let solution = problem.solve().unwrap();

        // report solution
        Ok(xs
            .iter()
            .enumerate()
            .filter(|(_, &x)| solution.value(x) > 0.0)
            .map(|(i, _)| self.sets[i].raw_set)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq)]
    struct RawSet {
        covering_set: Vec<u64>,
        weights: HashMap<u64, f64>,
    }

    impl<'a> MipMaxCover<'a> for RawSet {
        type Element = u64;

        fn covering_set(&'a self) -> &'a Vec<Self::Element> {
            &self.covering_set
        }

        fn element_weight(&self, element: &Self::Element) -> Option<f64> {
            self.weights.get(element).map(|w| *w)
        }
    }

    fn total_quality(sets: &Vec<&RawSet>) -> f64 {
        let covering_set: Vec<&u64> = sets
            .iter()
            .map(|s| s.covering_set())
            .flatten()
            .sorted_unstable()
            .dedup()
            .collect();
        covering_set.len() as f64
    }

    fn example_system() -> Vec<RawSet> {
        vec![
            RawSet {
                covering_set: vec![3],
                weights: vec![(3, 1.0)].into_iter().collect(),
            },
            RawSet {
                covering_set: vec![1, 2, 4, 5],
                weights: vec![(1, 1.0), (2, 1.0), (4, 1.0), (5, 1.0)]
                    .into_iter()
                    .collect(),
            },
            RawSet {
                covering_set: vec![1, 2, 4, 5],
                weights: vec![(1, 1.0), (2, 1.0), (4, 1.0), (5, 1.0)]
                    .into_iter()
                    .collect(),
            },
            RawSet {
                covering_set: vec![1],
                weights: vec![(1, 1.0)].into_iter().collect(),
            },
            RawSet {
                covering_set: vec![2, 4, 5],
                weights: vec![(2, 1.0), (4, 1.0), (5, 1.0)].into_iter().collect(),
            },
        ]
    }

    #[test]
    fn zero_limit() {
        let sets = example_system();
        let instance = MipMaxCoverProblemInstance::new(&sets, 0).unwrap();
        let cover = instance.max_cover().unwrap();
        assert_eq!(cover.len(), 0);
    }

    #[test]
    fn one_limit() {
        let sets = example_system();
        let instance = MipMaxCoverProblemInstance::new(&sets, 1).unwrap();
        let cover = instance.max_cover().unwrap();
        assert_eq!(cover.len(), 1);
        assert_eq!(*cover[0], sets[1]);
    }

    // Check that even if the limit provides room, we don't include useless items in the soln.
    #[test]
    // TODO: This test fails
    fn exclude_zero_score() {
        let sets = example_system();
        for k in 2..10 {
            let instance = MipMaxCoverProblemInstance::new(&sets, k).unwrap();
            let cover = instance.max_cover().unwrap();
            assert_eq!(
                cover.len(),
                2,
                "length of the solution must be 2 at k={}. Proposed solutions={:?}",
                k,
                cover
            );
            assert_eq!(*cover[0], sets[0]);
            assert_eq!(*cover[1], sets[1]);
        }
    }

    #[test]
    fn optimality() {
        let sets = vec![
            vec![0, 1, 8, 11, 14],
            vec![2, 3, 7, 9, 10],
            vec![4, 5, 6, 12, 13],
            vec![9, 10],
            vec![5, 6, 7, 8],
            vec![0, 1, 2, 3, 4],
        ]
        .into_iter()
        .map(|v| RawSet {
            weights: v.iter().map(|e| (*e, 1.0)).collect(),
            covering_set: v,
        })
        .collect();
        let instance = MipMaxCoverProblemInstance::new(&sets, 3).unwrap();
        let cover = instance.max_cover().unwrap();
        assert_eq!(total_quality(&cover), 15.0);
    }

    #[test]
    fn intersecting_ok() {
        let sets = vec![
            vec![1, 2, 3, 4, 5, 6, 7, 8],
            vec![1, 2, 3, 9, 10, 11],
            vec![4, 5, 6, 12, 13, 14],
            vec![7, 8, 15, 16, 17, 18],
            vec![1, 2, 9, 10],
            vec![1, 5, 6, 8],
            vec![1, 7, 11, 19],
        ]
        .into_iter()
        .map(|v| RawSet {
            weights: v.iter().map(|e| (*e, 1.0)).collect(),
            covering_set: v,
        })
        .collect();
        let instance = MipMaxCoverProblemInstance::new(&sets, 5).unwrap();
        let cover = instance.max_cover().unwrap();
        assert_eq!(total_quality(&cover), 19.0);
        assert_eq!(cover.len(), 4);
    }
}
