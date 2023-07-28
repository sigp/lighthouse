/// Entry point for the Bron-Kerbosh algorithm. Takes a vector of `vertices` of type
/// `T : Compatible<T>`. Returns all the maximal cliques (as a matrix of indices) for the graph
/// `G = (V,E)` where `V` is `vertices` and `E` encodes the `is_compatible` relationship.
pub fn bron_kerbosch<T, F: Fn(&T, &T) -> bool>(
    vertices: &Vec<T>,
    is_compatible: F,
) -> Vec<Vec<usize>> {
    // build neighbourhoods and degeneracy ordering, also move to index-based reasoning
    let neighbourhoods = compute_neigbourhoods(vertices, is_compatible);
    let ordering = degeneracy_order(vertices.len(), &neighbourhoods);

    // create empty vector to store cliques
    let mut cliques: Vec<Vec<usize>> = vec![];
    let mut publish_clique = |c| cliques.push(c);

    for i in 0..ordering.len() {
        let vi = ordering[i];
        let p = (i + 1..ordering.len())
            .filter(|j| neighbourhoods[vi].contains(&ordering[*j]))
            .map(|j| ordering[j])
            .collect();
        let r = vec![vi];
        let x = (0..i)
            .filter(|j| neighbourhoods[vi].contains(&ordering[*j]))
            .map(|j| ordering[j])
            .collect();
        bron_kerbosch_aux(r, p, x, &neighbourhoods, &mut publish_clique)
    }

    cliques
}

/// A function to the neighbourhoods for all nodes in the list. The neighbourhood `N(a)` of a
/// vertex `a` in `vertices` is the set of vertices `b` in `vertices` such that
/// `is_compatible(&a, &b) == true`. The function assumes that `is_compatible` is symmetric,
/// and returns a symmetric matrix (`Vec<Vec<usize>>`) of indices, where each index corresponds
/// to the relative vertex in `vertices`.
fn compute_neigbourhoods<T, F: Fn(&T, &T) -> bool>(
    vertices: &Vec<T>,
    is_compatible: F,
) -> Vec<Vec<usize>> {
    let mut neighbourhoods = vec![];
    neighbourhoods.resize_with(vertices.len(), Vec::new);
    for i in 0..vertices.len() - 1 {
        for j in i + 1..vertices.len() {
            if is_compatible(&vertices[i], &vertices[j]) {
                neighbourhoods[i].push(j);
                neighbourhoods[j].push(i);
            }
        }
    }
    neighbourhoods
}

/// Produces a degeneracy ordering of a set of vertices.
fn degeneracy_order(num_vertices: usize, neighbourhoods: &[Vec<usize>]) -> Vec<usize> {
    let mut v: Vec<usize> = (0..num_vertices).collect();
    let mut o = vec![];
    // move vertices from v to o in order of minimum degree
    while !v.is_empty() {
        let m: Option<usize> = (0..v.len()).min_by_key(|i| neighbourhoods[*i].len());
        if let Some(i) = m {
            o.push(v[i]);
            v.remove(i);
        } else {
            break;
        }
    }
    o
}

/// Auxiliary function to be used in the recursive call of the Bron-Kerbosh algorithm.
/// Parameters
///  * `r` - a working clique that is being built
///  * `p` - a set of candidate vertices to be added to r
///  * `x` - a set of vertices that have been explored and shouldn't be added to r
///  * `neighbourhoods` - a data structure to hold the neighbourhoods of each vertex
///  * `publish_clique` - a callback function to call whenever a clique has been produced
fn bron_kerbosch_aux<F>(
    r: Vec<usize>,
    p: Vec<usize>,
    x: Vec<usize>,
    neighbourhoods: &Vec<Vec<usize>>,
    publish_clique: &mut F,
) where
    F: FnMut(Vec<usize>),
{
    if p.is_empty() && x.is_empty() {
        publish_clique(r);
        return;
    }

    // modified p (p \ neighbourhood(pivot)), modified x
    let (mut ip, mut mp, mut mx) = (p.clone(), p.clone(), x.clone());
    let pivot = find_pivot(&p, &x, neighbourhoods);
    ip.retain(|e| !neighbourhoods[pivot].contains(e));

    // while !mp.is_empty() {
    while !ip.is_empty() {
        // v
        let v = ip[0];

        let n = &neighbourhoods[v];

        let (mut nr, mut np, mut nx) = (r.clone(), mp.clone(), mx.clone());

        // r U { v }
        nr.push(v);

        // p intersect neighbourhood { v }
        np.retain(|e| n.contains(e));

        // x intersect neighbourhood { v }
        nx.retain(|e| n.contains(e));

        // recursive call
        bron_kerbosch_aux(nr, np, nx, neighbourhoods, publish_clique);

        // p \ { v }, x U { v }
        mp.remove(mp.iter().position(|x| *x == v).unwrap());
        ip = mp.clone();
        ip.retain(|e| !neighbourhoods[pivot].contains(e));
        mx.push(v);
    }
}

/// Identifies pivot for Bron-Kerbosh pivoting technique.
fn find_pivot(p: &[usize], x: &[usize], neighbourhoods: &[Vec<usize>]) -> usize {
    let mut px = p.to_vec();
    px.append(&mut x.to_vec());
    *px.iter()
        .min_by_key(|&e| {
            let pp = p.to_vec();
            pp.iter()
                .filter(|ee| neighbourhoods[*e].contains(ee))
                .count()
        })
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bron_kerbosch_small_test() {
        let vertices: Vec<usize> = (0..7).collect();
        let edges = vec![
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

        println!("{:?}", bron_kerbosch(&vertices, is_compatible));
    }
}
