use good_lp::{constraint, default_solver, variable, variables, Expression, Solution, SolverModel};
use std::iter::Sum;
use std::ops::Mul;

pub fn max_cover(
    sets: Vec<Vec<usize>>,
    weights: Vec<f64>,
    k: usize,
) -> Result<Vec<usize>, &'static str> {
    // produce lists of sets containing a given element
    let mut sets_with: Vec<Vec<usize>> = vec![];
    sets_with.resize_with(weights.len(), Vec::new);
    for i in 0..sets.len() {
        for &j in &sets[i] {
            sets_with[j].push(i);
        }
    }

    let mut vars = variables!();

    // initialise set variables
    let xs = vars.add_vector(variable().binary(), sets.len());

    // initialise element variables
    let ys = vars.add_vector(variable().min(0.0).max(1.0), weights.len());

    // define objective function as linear combination of element variables and weights
    let objective = Expression::sum((0..weights.len()).map(|yi| ys[yi].mul(weights[yi])));
    let mut problem = vars.maximise(objective).using(default_solver);

    // limit solution size to k sets
    problem = problem.with(Expression::sum(xs.iter()).leq(k as f64));

    // add constraint allowing to cover an element only if one of the sets containing it is included
    for j in 0..weights.len() {
        problem = problem.with(constraint! {
            Expression::sum(sets_with[j].iter().map(|i| xs[*i])) >= ys[j]
        });
    }

    // tell CBC not to log
    problem.set_parameter("log", "0");

    // TODO: Verify this under the new assumptions
    // should be safe to `unwrap` since the problem is underconstrained
    let solution = problem.solve().unwrap();

    // report solution
    let mut coverage = Vec::with_capacity(weights.len());
    xs.iter()
        .enumerate()
        .filter(|(_, &x)| solution.value(x) > 0.0)
        .for_each(|(i, _)| coverage.push(i));

    Ok(coverage)
}

#[cfg(test)]
mod tests {
    use super::max_cover;

    #[test]
    fn small_coverage() {
        let sets = vec![
            vec![0, 1, 2],
            vec![0, 3],
            vec![1, 2],
            vec![3, 2],
            vec![0, 4],
            vec![2, 3, 0],
        ];
        let weights = vec![12.1, 11.3, 3.9, 2.3, 8.2];
        let k = 2;

        let result = max_cover(sets, weights, k).unwrap();
        assert_eq!(result, vec![0, 4]);
    }
}
