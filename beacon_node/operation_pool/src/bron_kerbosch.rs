use crate::OpPoolError as Error;
use rpds::HashTrieSet;

/// Entry point for the Bron-Kerbosh algorithm. Takes a vector of `vertices` of type
/// `T : Compatible<T>`. Returns all the maximal cliques (as a matrix of indices) for the graph
/// `G = (V,E)` where `V` is `vertices` and `E` encodes the `is_compatible` relationship.
pub fn bron_kerbosch<T, F: Fn(&T, &T) -> bool>(
    vertices: &[T],
    is_compatible: F,
) -> Result<Vec<HashTrieSet<usize>>, Error> {
    // create empty vector to store cliques
    let mut cliques: Vec<HashTrieSet<usize>> = vec![];

    if !vertices.is_empty() {
        // build neighbourhoods and degeneracy ordering, also move to index-based reasoning
        let neighbourhoods =
            compute_neighbourhoods(vertices, is_compatible).ok_or(Error::BronKerboschLogicError)?;
        let ordering = degeneracy_order(vertices.len(), &neighbourhoods);

        let mut publish_clique = |c| cliques.push(c);

        for (i, &vi) in ordering.iter().enumerate() {
            let vi_neighbourhood = neighbourhoods
                .get(vi)
                .ok_or(Error::BronKerboschLogicError)?;
            let p = ordering
                .get(i + 1..ordering.len())
                .ok_or(Error::BronKerboschLogicError)?
                .iter()
                .filter(|pj| vi_neighbourhood.contains(pj))
                .copied()
                .collect();
            let r = HashTrieSet::default().insert(vi);
            let x = ordering
                .get(0..i)
                .ok_or(Error::BronKerboschLogicError)?
                .iter()
                .filter(|xj| vi_neighbourhood.contains(xj))
                .copied()
                .collect();
            bron_kerbosch_aux(r, p, x, &neighbourhoods, &mut publish_clique)?;
        }
    }

    Ok(cliques)
}

/// A function to the neighbourhoods for all nodes in the list. The neighbourhood `N(a)` of a
/// vertex `a` in `vertices` is the set of vertices `b` in `vertices` such that
/// `is_compatible(&a, &b) == true`. The function assumes that `is_compatible` is symmetric,
/// and returns a symmetric matrix (`Vec<Vec<usize>>`) of indices, where each index corresponds
/// to the relative vertex in `vertices`.
fn compute_neighbourhoods<T, F: Fn(&T, &T) -> bool>(
    vertices: &[T],
    is_compatible: F,
) -> Option<Vec<Vec<usize>>> {
    let mut neighbourhoods = vec![];
    neighbourhoods.resize_with(vertices.len(), Vec::new);
    for (i, vi) in vertices.get(0..vertices.len() - 1)?.iter().enumerate() {
        for (j, vj) in vertices.iter().enumerate().skip(i + 1) {
            if is_compatible(vi, vj) {
                neighbourhoods.get_mut(i)?.push(j);
                neighbourhoods.get_mut(j)?.push(i);
            }
        }
    }
    Some(neighbourhoods)
}

/// Produces a degeneracy ordering of a set of vertices.
fn degeneracy_order(num_vertices: usize, neighbourhoods: &[Vec<usize>]) -> Vec<usize> {
    let mut v: Vec<usize> = (0..num_vertices).collect();
    v.sort_unstable_by_key(|i| neighbourhoods.get(*i).map(|n| n.len()).unwrap_or(0));
    v
}

/// Auxiliary function to be used in the recursive call of the Bron-Kerbosh algorithm.
/// Parameters
///  * `r` - a working clique that is being built
///  * `p` - a set of candidate vertices to be added to r
///  * `x` - a set of vertices that have been explored and shouldn't be added to r
///  * `neighbourhoods` - a data structure to hold the neighbourhoods of each vertex
///  * `publish_clique` - a callback function to call whenever a clique has been produced
fn bron_kerbosch_aux<F>(
    r: HashTrieSet<usize>,
    mut p: HashTrieSet<usize>,
    mut x: HashTrieSet<usize>,
    neighbourhoods: &Vec<Vec<usize>>,
    publish_clique: &mut F,
) -> Result<(), Error>
where
    F: FnMut(HashTrieSet<usize>),
{
    if p.is_empty() && x.is_empty() {
        publish_clique(r);
        return Ok(());
    }

    let pivot = find_pivot(&p, &x, neighbourhoods)?;
    let pivot_neighbours = neighbourhoods
        .get(pivot)
        .ok_or(Error::BronKerboschLogicError)?;

    let ip = hash_set_filter(&p, |e| !pivot_neighbours.contains(e));

    for v in ip.iter() {
        let n_set = neighbourhoods
            .get(*v)
            .ok_or(Error::BronKerboschLogicError)?;

        let nr = r.insert(*v);
        let np = hash_set_filter(&p, |e| n_set.contains(e));
        let nx = hash_set_filter(&x, |e| n_set.contains(e));

        bron_kerbosch_aux(nr, np, nx, neighbourhoods, publish_clique)?;

        p.remove_mut(v);
        x.insert_mut(*v);
    }
    Ok(())
}

/// Identifies pivot for Bron-Kerbosh pivoting technique.
fn find_pivot(
    p: &HashTrieSet<usize>,
    x: &HashTrieSet<usize>,
    neighbourhoods: &[Vec<usize>],
) -> Result<usize, Error> {
    p.iter()
        .chain(x.iter())
        .min_by_key(|&e| {
            p.iter()
                .filter(|ee| {
                    neighbourhoods
                        .get(*e)
                        .map(|n| n.contains(ee))
                        .unwrap_or(false)
                })
                .count()
        })
        .copied()
        .ok_or(Error::BronKerboschLogicError)
}

/// Store the members of `set` matching `predicate` in a new set.
fn hash_set_filter<P>(set: &HashTrieSet<usize>, predicate: P) -> HashTrieSet<usize>
where
    P: Fn(&usize) -> bool,
{
    let mut new_set = set.clone();
    for e in set.iter() {
        if !predicate(e) {
            new_set.remove_mut(e);
        }
    }
    new_set
}

#[cfg(test)]
mod tests {
    use super::*;
    use quickcheck::quickcheck;
    use std::collections::HashSet;
    #[test]
    fn bron_kerbosch_small_test() {
        let vertices: Vec<usize> = (0..7).collect();
        let edges = [
            (0, 1),
            (0, 2),
            (0, 3),
            (1, 2),
            (1, 3),
            (2, 3),
            (0, 4),
            (4, 5),
            (4, 6),
            (1, 6),
            (0, 6),
            (4, 6),
        ];

        let is_compatible = |first: &usize, second: &usize| -> bool {
            edges.contains(&(*first, *second)) || edges.contains(&(*first, *second))
        };

        println!("{:?}", bron_kerbosch(&vertices, is_compatible).unwrap());
    }

    quickcheck! {
        fn no_panic(vertices: Vec<usize>, adjacencies: HashSet<(usize, usize)>) -> bool {
            let is_compatible = |i: &usize, j: &usize| adjacencies.contains(&(*i, *j)) || adjacencies.contains(&(*j, *i));
            bron_kerbosch(&vertices, is_compatible).unwrap();
            true
        }

        fn at_least_one_clique_returned(vertices: Vec<usize>, adjacencies: HashSet<(usize, usize)>) -> bool {
            if vertices.is_empty() {
                return true;
            }
            let is_compatible = |i: &usize, j: &usize| adjacencies.contains(&(*i, *j)) || adjacencies.contains(&(*j, *i));
            let res = bron_kerbosch(&vertices, is_compatible).unwrap();
            !res.is_empty()
        }

        fn no_clique_is_empty(vertices: Vec<usize>, adjacencies: HashSet<(usize, usize)>) -> bool {
            if vertices.is_empty() {
                return true;
            }
            let is_compatible = |i: &usize, j: &usize| adjacencies.contains(&(*i, *j)) || adjacencies.contains(&(*j, *i));
            let res = bron_kerbosch(&vertices, is_compatible).unwrap();
            for clique in res.iter() {
                if clique.is_empty() {
                    return false;
                }
            }
            true
        }

        fn all_claimed_cliques_are_cliques(vertices: Vec<usize>, adjacencies: HashSet<(usize, usize)>) -> bool {
            let is_compatible = |i: &usize, j: &usize| adjacencies.contains(&(*i, *j)) || adjacencies.contains(&(*j, *i));
            let claimed_cliques = bron_kerbosch(&vertices, is_compatible).unwrap();
            for clique in claimed_cliques {
                for (ind1, vertex) in clique.iter().enumerate() {
                    for (ind2, other_vertex) in clique.iter().enumerate() {
                        if ind1 == ind2 {
                            continue
                        }
                        if !is_compatible(&vertices[*vertex], &vertices[*other_vertex]) {
                            return false;
                        }
                    }
                }
            }
            true
        }

        fn no_clique_is_a_subset_of_other_clique(vertices: Vec<usize>, adjacencies: HashSet<(usize, usize)>) -> bool {
            let is_compatible = |i: &usize, j: &usize| adjacencies.contains(&(*i, *j)) || adjacencies.contains(&(*j, *i));
            let claimed_cliques = bron_kerbosch(&vertices, is_compatible).unwrap();
            let is_subset = |set1: HashTrieSet<usize>, set2: HashTrieSet<usize>| -> bool {
                for vertex in set1.iter() {
                    if !set2.contains(vertex) {
                        return false;
                    }
                }
                true
            };
            for (ind1, clique) in claimed_cliques.iter().enumerate() {
                for (ind2, other_clique) in claimed_cliques.iter().enumerate() {
                    if ind1 == ind2 {
                        continue;
                    }
                    if is_subset(clique.clone(), other_clique.clone()) {
                        return false;
                    }
                }
            }
            true
        }
    }
}
