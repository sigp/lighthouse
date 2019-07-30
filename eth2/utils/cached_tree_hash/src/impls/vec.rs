use super::*;
use crate::btree_overlay::LeafNode;
use crate::merkleize::{merkleize, num_sanitized_leaves, sanitise_bytes};

macro_rules! impl_for_list {
    ($type: ty) => {
        impl<T> CachedTreeHash for $type
        where
            T: CachedTreeHash + TreeHash,
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
                let new_overlay = update_tree_hash_cache(&self, cache)?;

                // Mix in length
                cache.mix_in_length(new_overlay.chunk_range(), self.len())?;

                // Skip an extra node to clear the length node.
                cache.chunk_index += 1;

                Ok(())
            }
        }
    };
}

impl_for_list!(Vec<T>);
impl_for_list!(&[T]);

/// Build a new tree hash cache for some slice.
///
/// Valid for both variable- and fixed-length slices. Does _not_ mix-in the length of the list,
/// the caller must do this.
pub fn new_tree_hash_cache<T: CachedTreeHash>(
    vec: &[T],
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
                .map(|item| TreeHashCache::new_at_depth(item, depth + 1))
                .collect::<Result<Vec<TreeHashCache>, _>>()?;

            TreeHashCache::from_subtrees(&vec, subtrees, depth)
        }
    }?;

    Ok((cache, schema))
}

/// Produce a schema for some slice.
///
/// Valid for both variable- and fixed-length slices. Does _not_ add the mix-in length nodes, the
/// caller must do this.
pub fn produce_schema<T: CachedTreeHash>(vec: &[T], depth: usize) -> BTreeSchema {
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

/// Updates the cache for some slice.
///
/// Valid for both variable- and fixed-length slices. Does _not_ cater for the mix-in length nodes,
/// the caller must do this.
#[allow(clippy::range_plus_one)] // Minor readability lint requiring structural changes; not worth it.
pub fn update_tree_hash_cache<T: CachedTreeHash>(
    vec: &[T],
    cache: &mut TreeHashCache,
) -> Result<BTreeOverlay, Error> {
    let old_overlay = cache.get_overlay(cache.schema_index, cache.chunk_index)?;
    let new_overlay = BTreeOverlay::new(&vec, cache.chunk_index, old_overlay.depth);

    cache.replace_overlay(cache.schema_index, cache.chunk_index, new_overlay.clone())?;

    cache.schema_index += 1;

    match T::tree_hash_type() {
        TreeHashType::Basic => {
            let mut buf = vec![0; HASHSIZE];
            let item_bytes = HASHSIZE / T::tree_hash_packing_factor();

            // If the number of leaf nodes has changed, resize the cache.
            if new_overlay.num_leaf_nodes() < old_overlay.num_leaf_nodes() {
                let start = new_overlay.next_node();
                let end = start + (old_overlay.num_leaf_nodes() - new_overlay.num_leaf_nodes());

                cache.splice(start..end, vec![], vec![]);
            } else if new_overlay.num_leaf_nodes() > old_overlay.num_leaf_nodes() {
                let start = old_overlay.next_node();
                let new_nodes = new_overlay.num_leaf_nodes() - old_overlay.num_leaf_nodes();

                cache.splice(
                    start..start,
                    vec![0; new_nodes * HASHSIZE],
                    vec![true; new_nodes],
                );
            }

            // Iterate through each of the leaf nodes in the new list.
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
            let longest_len =
                std::cmp::max(new_overlay.num_leaf_nodes(), old_overlay.num_leaf_nodes());

            let old_leaf_nodes = old_overlay.get_leaf_nodes(longest_len);
            let new_leaf_nodes = if old_overlay == new_overlay {
                old_leaf_nodes.clone()
            } else {
                new_overlay.get_leaf_nodes(longest_len)
            };

            for i in 0..longest_len {
                match (&old_leaf_nodes[i], &new_leaf_nodes[i]) {
                    // The item existed in the previous list and exists in the current list.
                    //
                    // Update the item.
                    (LeafNode::Exists(_old), LeafNode::Exists(new)) => {
                        cache.chunk_index = new.start;

                        vec[i].update_tree_hash_cache(cache)?;
                    }
                    // The list has been lengthened and this is a new item that did not exist in
                    // the previous list.
                    //
                    // Splice the tree for the new item into the current chunk_index.
                    (LeafNode::DoesNotExist, LeafNode::Exists(new)) => {
                        splice_in_new_tree(
                            &vec[i],
                            new.start..new.start,
                            new_overlay.depth + 1,
                            cache,
                        )?;

                        cache.chunk_index = new.end;
                    }
                    // The list has been lengthened and this is a new item that was previously a
                    // padding item.
                    //
                    // Splice the tree for the new item over the padding chunk.
                    (LeafNode::Padding, LeafNode::Exists(new)) => {
                        splice_in_new_tree(
                            &vec[i],
                            new.start..new.start + 1,
                            new_overlay.depth + 1,
                            cache,
                        )?;

                        cache.chunk_index = new.end;
                    }
                    // The list has been shortened and this item was removed from the list and made
                    // into padding.
                    //
                    // Splice a padding node over the number of nodes the previous item occupied,
                    // starting at the current chunk_index.
                    (LeafNode::Exists(old), LeafNode::Padding) => {
                        let num_chunks = old.end - old.start;

                        cache.splice(
                            cache.chunk_index..cache.chunk_index + num_chunks,
                            vec![0; HASHSIZE],
                            vec![true],
                        );

                        cache.chunk_index += 1;
                    }
                    // The list has been shortened and the item for this leaf existed in the
                    // previous list, but does not exist in this list.
                    //
                    // Remove the number of nodes the previous item occupied, starting at the
                    // current chunk_index.
                    (LeafNode::Exists(old), LeafNode::DoesNotExist) => {
                        let num_chunks = old.end - old.start;

                        cache.splice(
                            cache.chunk_index..cache.chunk_index + num_chunks,
                            vec![],
                            vec![],
                        );
                    }
                    // The list has been shortened and this leaf was padding in the previous list,
                    // however it should not exist in this list.
                    //
                    // Remove one node, starting at the current `chunk_index`.
                    (LeafNode::Padding, LeafNode::DoesNotExist) => {
                        cache.splice(cache.chunk_index..cache.chunk_index + 1, vec![], vec![]);
                    }
                    // The list has been lengthened and this leaf did not exist in the previous
                    // list, but should be padding for this list.
                    //
                    // Splice in a new padding node at the current chunk_index.
                    (LeafNode::DoesNotExist, LeafNode::Padding) => {
                        cache.splice(
                            cache.chunk_index..cache.chunk_index,
                            vec![0; HASHSIZE],
                            vec![true],
                        );

                        cache.chunk_index += 1;
                    }
                    // This leaf was padding in both lists, there's nothing to do.
                    (LeafNode::Padding, LeafNode::Padding) => (),
                    // As we are looping through the larger of the lists of leaf nodes, it should
                    // be impossible for either leaf to be non-existent.
                    (LeafNode::DoesNotExist, LeafNode::DoesNotExist) => unreachable!(),
                }
            }

            // Clean out any excess schemas that may or may not be remaining if the list was
            // shortened.
            cache.remove_proceeding_child_schemas(cache.schema_index, new_overlay.depth);
        }
    }

    cache.update_internal_nodes(&new_overlay)?;

    cache.chunk_index = new_overlay.next_node();

    Ok(new_overlay)
}

/// Create a new `TreeHashCache` from `item` and splice it over the `chunks_to_replace` chunks of
/// the given `cache`.
///
/// Useful for the case where a new element is added to a list.
///
/// The schemas created for `item` will have the given `depth`.
fn splice_in_new_tree<T>(
    item: &T,
    chunks_to_replace: Range<usize>,
    depth: usize,
    cache: &mut TreeHashCache,
) -> Result<(), Error>
where
    T: CachedTreeHash,
{
    let (bytes, mut bools, schemas) = TreeHashCache::new_at_depth(item, depth)?.into_components();

    // Record the number of schemas, this will be used later in the fn.
    let num_schemas = schemas.len();

    // Flag the root node of the new tree as dirty.
    bools[0] = true;

    cache.splice(chunks_to_replace, bytes, bools);
    cache
        .schemas
        .splice(cache.schema_index..cache.schema_index, schemas);

    cache.schema_index += num_schemas;

    Ok(())
}

/// Packs all of the leaves of `vec` into a single byte-array, appending `0` to ensure the number
/// of chunks in the byte-array is a power-of-two.
fn get_packed_leaves<T>(vec: &[T]) -> Result<Vec<u8>, Error>
where
    T: CachedTreeHash,
{
    let num_packed_bytes = (BYTES_PER_CHUNK / T::tree_hash_packing_factor()) * vec.len();
    let num_leaves = num_sanitized_leaves(num_packed_bytes);

    let mut packed = Vec::with_capacity(num_leaves * HASHSIZE);

    for item in vec {
        packed.append(&mut item.tree_hash_packed_encoding());
    }

    Ok(sanitise_bytes(packed))
}
