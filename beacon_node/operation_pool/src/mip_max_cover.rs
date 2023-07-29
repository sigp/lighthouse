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
            Expression::sum((0..self.weights.len()).map(|yi| ys[yi].mul(self.weights[yi])));
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
    // use super::max_cover;
    //
    // #[test]
    // fn small_coverage() {
    //     let sets = vec![
    //         vec![0, 1, 2],
    //         vec![0, 3],
    //         vec![1, 2],
    //         vec![3, 2],
    //         vec![0, 4],
    //         vec![2, 3, 0],
    //     ];
    //     let weights = vec![12.1, 11.3, 3.9, 2.3, 8.2];
    //     let k = 2;
    //
    //     let result = max_cover(sets, weights, k).unwrap();
    //     assert_eq!(result, vec![0, 4]);
    // }
}
