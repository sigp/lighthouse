use super::*;

impl<T> CachedTreeHashSubtree<Vec<T>> for Vec<T>
where
    T: CachedTreeHashSubtree<T>,
{
    fn item_type() -> ItemType {
        ItemType::List
    }

    fn new_cache(&self) -> Result<TreeHashCache, Error> {
        match T::item_type() {
            ItemType::Basic => {
                TreeHashCache::from_bytes(merkleize(get_packed_leaves(self)?), false)
            }
            ItemType::Composite | ItemType::List => {
                let subtrees = self
                    .iter()
                    .map(|item| TreeHashCache::new(item))
                    .collect::<Result<Vec<TreeHashCache>, _>>()?;

                TreeHashCache::from_leaves_and_subtrees(self, subtrees)
            }
        }
    }

    fn btree_overlay(&self, chunk_offset: usize) -> Result<BTreeOverlay, Error> {
        let lengths = match T::item_type() {
            ItemType::Basic => vec![1; self.len() / T::packing_factor()],
            ItemType::Composite | ItemType::List => {
                let mut lengths = vec![];

                for item in self {
                    lengths.push(BTreeOverlay::new(item, 0)?.total_nodes())
                }

                lengths
            }
        };

        BTreeOverlay::from_lengths(chunk_offset, lengths)
    }

    fn packed_encoding(&self) -> Result<Vec<u8>, Error> {
        Err(Error::ShouldNeverBePacked(Self::item_type()))
    }

    fn packing_factor() -> usize {
        1
    }

    fn update_cache(
        &self,
        other: &Vec<T>,
        cache: &mut TreeHashCache,
        chunk: usize,
    ) -> Result<usize, Error> {
        let offset_handler = BTreeOverlay::new(self, chunk)?;
        let old_offset_handler = BTreeOverlay::new(other, chunk)?;

        if offset_handler.num_leaf_nodes != old_offset_handler.num_leaf_nodes {
            let old_offset_handler = BTreeOverlay::new(other, chunk)?;

            // Get slices of the exsiting tree from the cache.
            let (old_bytes, old_flags) = cache
                .slices(old_offset_handler.chunk_range())
                .ok_or_else(|| Error::UnableToObtainSlices)?;

            let (new_bytes, new_flags) =
                if offset_handler.num_leaf_nodes > old_offset_handler.num_leaf_nodes {
                    grow_merkle_cache(
                        old_bytes,
                        old_flags,
                        old_offset_handler.height(),
                        offset_handler.height(),
                    )
                    .ok_or_else(|| Error::UnableToGrowMerkleTree)?
                } else {
                    shrink_merkle_cache(
                        old_bytes,
                        old_flags,
                        old_offset_handler.height(),
                        offset_handler.height(),
                        offset_handler.total_chunks(),
                    )
                    .ok_or_else(|| Error::UnableToShrinkMerkleTree)?
                };

            // Create a `TreeHashCache` from the raw elements.
            let modified_cache = TreeHashCache::from_elems(new_bytes, new_flags);

            // Splice the newly created `TreeHashCache` over the existing elements.
            cache.splice(old_offset_handler.chunk_range(), modified_cache);
        }

        match T::item_type() {
            ItemType::Basic => {
                let leaves = get_packed_leaves(self)?;

                for (i, chunk) in offset_handler.iter_leaf_nodes().enumerate() {
                    if let Some(latest) = leaves.get(i * HASHSIZE..(i + 1) * HASHSIZE) {
                        cache.maybe_update_chunk(*chunk, latest)?;
                    }
                }
                let first_leaf_chunk = offset_handler.first_leaf_node()?;

                cache.splice(
                    first_leaf_chunk..offset_handler.next_node,
                    TreeHashCache::from_bytes(leaves, true)?,
                );
            }
            ItemType::Composite | ItemType::List => {
                let mut i = offset_handler.num_leaf_nodes;
                for &start_chunk in offset_handler.iter_leaf_nodes().rev() {
                    i -= 1;
                    match (other.get(i), self.get(i)) {
                        // The item existed in the previous list and exsits in the current list.
                        (Some(old), Some(new)) => {
                            new.update_cache(old, cache, start_chunk)?;
                        }
                        // The item existed in the previous list but does not exist in this list.
                        //
                        // I.e., the list has been shortened.
                        (Some(old), None) => {
                            // Splice out the entire tree of the removed node, replacing it with a
                            // single padding node.
                            let end_chunk = BTreeOverlay::new(old, start_chunk)?.next_node;

                            cache.splice(
                                start_chunk..end_chunk,
                                TreeHashCache::from_bytes(vec![0; HASHSIZE], true)?,
                            );
                        }
                        // The item existed in the previous list but does exist in this list.
                        //
                        // I.e., the list has been lengthened.
                        (None, Some(new)) => {
                            let bytes: Vec<u8> = TreeHashCache::new(new)?.into();

                            cache.splice(
                                start_chunk..start_chunk + 1,
                                TreeHashCache::from_bytes(bytes, true)?,
                            );
                        }
                        // The item didn't exist in the old list and doesn't exist in the new list,
                        // nothing to do.
                        (None, None) => {}
                    };
                }
            }
        }

        for (&parent, children) in offset_handler.iter_internal_nodes().rev() {
            if cache.either_modified(children)? {
                cache.modify_chunk(parent, &cache.hash_children(children)?)?;
            }
        }

        // If the root node or the length has changed, mix in the length of the list.
        let root_node = offset_handler.root();
        if cache.changed(root_node)? | (self.len() != other.len()) {
            cache.modify_chunk(root_node, &cache.mix_in_length(root_node, self.len())?)?;
        }

        Ok(offset_handler.next_node)
    }
}

fn get_packed_leaves<T>(vec: &Vec<T>) -> Result<Vec<u8>, Error>
where
    T: CachedTreeHashSubtree<T>,
{
    let num_packed_bytes = (BYTES_PER_CHUNK / T::packing_factor()) * vec.len();
    let num_leaves = num_sanitized_leaves(num_packed_bytes);

    let mut packed = Vec::with_capacity(num_leaves * HASHSIZE);

    for item in vec {
        packed.append(&mut item.packed_encoding()?);
    }

    Ok(sanitise_bytes(packed))
}
