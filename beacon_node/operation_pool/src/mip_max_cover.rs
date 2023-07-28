use std::collections::HashMap;
use std::iter::Sum;
use std::ops::Mul;

use good_lp::{constraint, default_solver, variable, variables, Expression, Solution, SolverModel};
use itertools::Itertools;
use state_processing::common::base;
use types::{BeaconState, ChainSpec, EthSpec};

use crate::AttestationRef;

struct MaxCoverAttestation<'a, T: EthSpec> {
    attn: AttestationRef<'a, T>,
    mapped_attesting_indices: Vec<usize>,
}

pub struct MaxCoverProblemInstance<'a, T: EthSpec> {
    attestations: Vec<MaxCoverAttestation<'a, T>>,
    weights: Vec<u64>,
    limit: usize,
}

// TODO: check if clones can be reduced

impl<'a, T: EthSpec> MaxCoverProblemInstance<'a, T> {
    pub fn new(
        attestations: &Vec<AttestationRef<'a, T>>,
        state: &BeaconState<T>,
        total_active_balance: u64,
        spec: &ChainSpec,
        limit: usize,
    ) -> MaxCoverProblemInstance<'a, T> {
        let mapped_index_to_attestor_index: Vec<u64> = attestations
            .iter()
            .map(|attn| &(attn.indexed.attesting_indices))
            .flatten()
            .sorted_unstable()
            .dedup()
            .map(|attestor_index| attestor_index.clone())
            .collect();

        let attestor_index_to_mapped_index: HashMap<u64, usize> = mapped_index_to_attestor_index
            .iter()
            .enumerate()
            .map(|(idx, attestor_index)| (*attestor_index, idx))
            .collect();

        let weights = mapped_index_to_attestor_index
            .iter()
            .flat_map(|validator_index| {
                let reward = base::get_base_reward(
                    state,
                    *validator_index as usize,
                    total_active_balance,
                    spec,
                )
                .ok()?
                .checked_div(spec.proposer_reward_quotient)?;
                Some(reward)
            })
            .collect();

        let attestations = attestations
            .iter()
            .map(|attn| MaxCoverAttestation {
                attn: attn.clone(),
                mapped_attesting_indices: attn
                    .indexed
                    .attesting_indices
                    .iter()
                    .flat_map(|validator_index| {
                        let mapped_index =
                            attestor_index_to_mapped_index.get(validator_index)?.clone();
                        Some(mapped_index)
                    })
                    .collect(),
            })
            .collect();

        MaxCoverProblemInstance {
            attestations,
            weights,
            limit,
        }
    }

    pub fn max_cover(&self) -> Result<Vec<AttestationRef<'a, T>>, &'static str> {
        // produce lists of sets containing a given element
        let mut sets_with: Vec<Vec<usize>> = vec![];
        sets_with.resize_with(self.weights.len(), Vec::new);
        for i in 0..self.attestations.len() {
            for &j in &self.attestations[i].mapped_attesting_indices {
                sets_with[j].push(i);
            }
        }

        let mut vars = variables!();

        // initialise set variables
        let xs = vars.add_vector(variable().binary(), self.attestations.len());

        // initialise element variables
        let ys = vars.add_vector(variable().min(0.0).max(1.0), self.weights.len());

        // define objective function as linear combination of element variables and weights
        let objective =
            Expression::sum((0..self.weights.len()).map(|yi| ys[yi].mul(self.weights[yi] as f64)));
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
            .map(|(i, _)| self.attestations[i].attn.clone())
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
