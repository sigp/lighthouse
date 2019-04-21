use super::*;

impl<T> CachedTreeHashSubTree<Vec<T>> for Vec<T>
where
    T: CachedTreeHashSubTree<T> + TreeHash,
{
    fn new_tree_hash_cache(&self) -> Result<TreeHashCache, Error> {
        let overlay = self.tree_hash_cache_overlay(0)?;

        let mut cache = match T::tree_hash_type() {
            TreeHashType::Basic => TreeHashCache::from_bytes(
                merkleize(get_packed_leaves(self)?),
                false,
                overlay.clone(),
            ),
            TreeHashType::Container | TreeHashType::List | TreeHashType::Vector => {
                let subtrees = self
                    .iter()
                    .map(|item| TreeHashCache::new(item))
                    .collect::<Result<Vec<TreeHashCache>, _>>()?;

                TreeHashCache::from_leaves_and_subtrees(self, subtrees)
            }
        }?;

        // Mix in the length of the list.
        let root_node = overlay.root();
        cache.modify_chunk(root_node, &cache.mix_in_length(root_node, self.len())?)?;

        Ok(cache)
    }

    fn tree_hash_cache_overlay(&self, chunk_offset: usize) -> Result<BTreeOverlay, Error> {
        let lengths = match T::tree_hash_type() {
            TreeHashType::Basic => {
                // Ceil division.
                let num_leaves = (self.len() + T::tree_hash_packing_factor() - 1)
                    / T::tree_hash_packing_factor();

                // Disallow zero-length as an empty list still has one all-padding node.
                vec![1; std::cmp::max(1, num_leaves)]
            }
            TreeHashType::Container | TreeHashType::List | TreeHashType::Vector => {
                let mut lengths = vec![];

                for item in self {
                    lengths.push(BTreeOverlay::new(item, 0)?.num_nodes())
                }

                lengths
            }
        };

        BTreeOverlay::from_lengths(chunk_offset, self.len(), lengths)
    }

    fn update_tree_hash_cache(&self, cache: &mut TreeHashCache) -> Result<(), Error> {
        let new_overlay = BTreeOverlay::new(self, cache.chunk_index)?;
        let old_overlay = cache
            .get_overlay(cache.overlay_index, cache.chunk_index)?
            .clone();

        // If the merkle tree required to represent the new list is of a different size to the one
        // required for the previous list, then update our cache.
        //
        // This grows/shrinks the bytes to accomodate the new tree, preserving as much of the tree
        // as possible.
        if new_overlay.num_leaf_nodes() != old_overlay.num_leaf_nodes() {
            cache.replace_overlay(cache.overlay_index, cache.chunk_index, new_overlay.clone())?;
        }

        match T::tree_hash_type() {
            TreeHashType::Basic => {
                let mut buf = vec![0; HASHSIZE];
                let item_bytes = HASHSIZE / T::tree_hash_packing_factor();

                // Iterate through each of the leaf nodes.
                for i in 0..new_overlay.num_leaf_nodes() {
                    // Iterate through the number of items that may be packing into the leaf node.
                    for j in 0..T::tree_hash_packing_factor() {
                        // Create a mut slice that can either be filled with a serialized item or
                        // padding.
                        let buf_slice = &mut buf[j * item_bytes..(j + 1) * item_bytes];

                        // Attempt to get the item for this portion of the chunk. If it exists,
                        // update `buf` with it's serialized bytes. If it doesn't exist, update
                        // `buf` with padding.
                        match self.get(i * T::tree_hash_packing_factor() + j) {
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
                for i in (0..new_overlay.num_leaf_nodes()).rev() {
                    match (old_overlay.get_leaf_node(i)?, new_overlay.get_leaf_node(i)?) {
                        // The item existed in the previous list and exists in the current list.
                        (Some(_old), Some(new)) => {
                            cache.chunk_index = new.start;
                            self[i].update_tree_hash_cache(cache)?;
                        }
                        // The item existed in the previous list but does not exist in this list.
                        //
                        // Viz., the list has been shortened.
                        (Some(old), None) => {
                            // Splice out the entire tree of the removed node, replacing it with a
                            // single padding node.
                            cache.splice(old, vec![0; HASHSIZE], vec![true]);
                        }
                        // The item did not exist in the previous list but does exist in this list.
                        //
                        // Viz., the list has been lengthened.
                        (None, Some(new)) => {
                            let bytes: Vec<u8> = TreeHashCache::new(&self[i])?.into();
                            let bools = vec![true; bytes.len() / HASHSIZE];

                            cache.splice(new.start..new.start + 1, bytes, bools);
                        }
                        // The item didn't exist in the old list and doesn't exist in the new list,
                        // nothing to do.
                        (None, None) => {}
                    }
                }
            }
        }

        cache.update_internal_nodes(&new_overlay)?;

        // Mix in length.
        let root_node = new_overlay.root();
        if cache.changed(root_node)? {
            dbg!(cache.get_chunk(12));
            cache.modify_chunk(root_node, &cache.mix_in_length(root_node, self.len())?)?;
        } else if old_overlay.num_items != new_overlay.num_items {
            if new_overlay.num_internal_nodes() == 0 {
                cache.modify_chunk(root_node, &cache.mix_in_length(root_node, self.len())?)?;
            } else {
                let children = new_overlay.child_chunks(0);
                cache.modify_chunk(root_node, &cache.hash_children(children)?)?;
                cache.modify_chunk(root_node, &cache.mix_in_length(root_node, self.len())?)?;
            }
        }

        cache.chunk_index = new_overlay.next_node();

        Ok(())
    }
}

fn get_packed_leaves<T>(vec: &Vec<T>) -> Result<Vec<u8>, Error>
where
    T: CachedTreeHashSubTree<T>,
{
    let num_packed_bytes = (BYTES_PER_CHUNK / T::tree_hash_packing_factor()) * vec.len();
    let num_leaves = num_sanitized_leaves(num_packed_bytes);

    let mut packed = Vec::with_capacity(num_leaves * HASHSIZE);

    for item in vec {
        packed.append(&mut item.tree_hash_packed_encoding());
    }

    Ok(sanitise_bytes(packed))
}
