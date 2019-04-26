use super::*;
use crate::merkleize::{merkleize, num_sanitized_leaves, sanitise_bytes};

impl<T> CachedTreeHash<Vec<T>> for Vec<T>
where
    T: CachedTreeHash<T> + TreeHash,
{
    fn new_tree_hash_cache(&self, depth: usize) -> Result<TreeHashCache, Error> {
        let (mut cache, schema) = new_tree_hash_cache(self, depth)?;

        cache.add_length_nodes(schema.into_overlay(0).chunk_range(), self.len())?;

        Ok(cache)
    }

    fn num_tree_hash_cache_chunks(&self) -> usize {
        // Add two extra nodes to cater for the node before and after to allow mixing-in length.
        BTreeOverlay::new(self, 0, 0).num_chunks() + 2
    }

    fn tree_hash_cache_schema(&self, depth: usize) -> BTreeSchema {
        produce_schema(self, depth)
    }

    fn update_tree_hash_cache(&self, cache: &mut TreeHashCache) -> Result<(), Error> {
        // Skip the length-mixed-in root node.
        cache.chunk_index += 1;

        // Update the cache, returning the new overlay.
        let new_overlay = update_tree_hash_cache(self, cache)?;

        // Mix in length
        cache.mix_in_length(new_overlay.chunk_range(), self.len())?;

        // Skip an extra node to clear the length node.
        cache.chunk_index = new_overlay.next_node() + 1;

        Ok(())
    }
}

pub fn new_tree_hash_cache<T: CachedTreeHash<T>>(
    vec: &Vec<T>,
    depth: usize,
) -> Result<(TreeHashCache, BTreeSchema), Error> {
    let schema = vec.tree_hash_cache_schema(depth);

    let cache = match T::tree_hash_type() {
        TreeHashType::Basic => TreeHashCache::from_bytes(
            merkleize(get_packed_leaves(vec)?),
            false,
            Some(schema.clone()),
        ),
        TreeHashType::Container | TreeHashType::List | TreeHashType::Vector => {
            let subtrees = vec
                .iter()
                .map(|item| TreeHashCache::new(item, depth + 1))
                .collect::<Result<Vec<TreeHashCache>, _>>()?;

            TreeHashCache::from_leaves_and_subtrees(vec, subtrees, depth)
        }
    }?;

    Ok((cache, schema))
}

pub fn produce_schema<T: CachedTreeHash<T>>(vec: &Vec<T>, depth: usize) -> BTreeSchema {
    let lengths = match T::tree_hash_type() {
        TreeHashType::Basic => {
            // Ceil division.
            let num_leaves =
                (vec.len() + T::tree_hash_packing_factor() - 1) / T::tree_hash_packing_factor();

            // Disallow zero-length as an empty list still has one all-padding node.
            vec![1; std::cmp::max(1, num_leaves)]
        }
        TreeHashType::Container | TreeHashType::List | TreeHashType::Vector => {
            let mut lengths = vec![];

            for item in vec {
                lengths.push(item.num_tree_hash_cache_chunks())
            }

            lengths
        }
    };

    BTreeSchema::from_lengths(depth, lengths)
}

pub fn update_tree_hash_cache<T: CachedTreeHash<T>>(
    vec: &Vec<T>,
    cache: &mut TreeHashCache,
) -> Result<BTreeOverlay, Error> {
    let old_overlay = cache.get_overlay(cache.schema_index, cache.chunk_index)?;
    let new_overlay = BTreeOverlay::new(vec, cache.chunk_index, old_overlay.depth);

    dbg!(cache.schema_index);
    dbg!(cache.schemas.len());
    dbg!(&old_overlay);
    dbg!(&new_overlay);

    cache.replace_overlay(cache.schema_index, cache.chunk_index, new_overlay.clone())?;

    cache.schema_index += 1;

    match T::tree_hash_type() {
        TreeHashType::Basic => {
            let mut buf = vec![0; HASHSIZE];
            let item_bytes = HASHSIZE / T::tree_hash_packing_factor();

            // Iterate through each of the leaf nodes.
            for i in 0..new_overlay.num_leaf_nodes() {
                // Iterate through the number of items that may be packing into the leaf node.
                for j in 0..T::tree_hash_packing_factor() {
                    // Create a mut slice that can be filled with either a serialized item or
                    // padding.
                    let buf_slice = &mut buf[j * item_bytes..(j + 1) * item_bytes];

                    // Attempt to get the item for this portion of the chunk. If it exists,
                    // update `buf` with it's serialized bytes. If it doesn't exist, update
                    // `buf` with padding.
                    match vec.get(i * T::tree_hash_packing_factor() + j) {
                        Some(item) => {
                            buf_slice.copy_from_slice(&item.tree_hash_packed_encoding());
                        }
                        None => buf_slice.copy_from_slice(&vec![0; item_bytes]),
                    }
                }

                // Update the chunk if the generated `buf` is not the same as the cache.
                let chunk = new_overlay.first_leaf_node() + i;
                cache.maybe_update_chunk(chunk, &buf)?;
            }
        }
        TreeHashType::Container | TreeHashType::List | TreeHashType::Vector => {
            for i in 0..new_overlay.num_leaf_nodes() {
                // Adjust `i` so it is a leaf node for each of the overlays.
                let old_i = i + old_overlay.num_internal_nodes();
                let new_i = i + new_overlay.num_internal_nodes();

                match (
                    old_overlay.get_leaf_node(old_i)?,
                    new_overlay.get_leaf_node(new_i)?,
                ) {
                    // The item existed in the previous list and exists in the current list.
                    (Some(_old), Some(new)) => {
                        cache.chunk_index = new.start;

                        vec[i].update_tree_hash_cache(cache)?;
                    }
                    // The item did not exist in the previous list but does exist in this list.
                    //
                    // Viz., the list has been lengthened.
                    (None, Some(new)) => {
                        let (bytes, mut bools, schemas) =
                            TreeHashCache::new(&vec[i], new_overlay.depth + 1)?.into_components();

                        // Record the number of schemas, this will be used later in the fn.
                        let num_schemas = schemas.len();

                        // Flag the root node of the new tree as dirty.
                        bools[0] = true;

                        cache.splice(new.start..new.start + 1, bytes, bools);
                        cache
                            .schemas
                            .splice(cache.schema_index..cache.schema_index, schemas);

                        cache.schema_index += num_schemas;
                    }
                    // The item existed in the previous list but does not exist in this list.
                    //
                    // Viz., the list has been shortened.
                    (Some(old), None) => {
                        if vec.len() == 0 {
                            // In this case, the list has been made empty and we should make
                            // this node padding.
                            cache.maybe_update_chunk(new_overlay.root(), &[0; HASHSIZE])?;
                        } else {
                            // In this case, there are some items in the new list and we should
                            // splice out the entire tree of the removed node, replacing it
                            // with a single padding node.
                            cache.splice(old, vec![0; HASHSIZE], vec![true]);
                        }
                    }
                    // The item didn't exist in the old list and doesn't exist in the new list,
                    // nothing to do.
                    (None, None) => {}
                }
            }

            // Clean out any excess schemas that may or may not be remaining if the list was
            // shortened.
            cache.remove_proceeding_child_schemas(cache.schema_index, new_overlay.depth);
        }
    }

    cache.update_internal_nodes(&new_overlay)?;

    Ok(new_overlay)
}

fn get_packed_leaves<T>(vec: &Vec<T>) -> Result<Vec<u8>, Error>
where
    T: CachedTreeHash<T>,
{
    let num_packed_bytes = (BYTES_PER_CHUNK / T::tree_hash_packing_factor()) * vec.len();
    let num_leaves = num_sanitized_leaves(num_packed_bytes);

    let mut packed = Vec::with_capacity(num_leaves * HASHSIZE);

    for item in vec {
        packed.append(&mut item.tree_hash_packed_encoding());
    }

    Ok(sanitise_bytes(packed))
}
