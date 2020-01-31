use ssz::{Decode, Encode};
use ssz_derive::{Decode, Encode};
use std::marker::PhantomData;
use std::ops::Range;

#[derive(Debug, PartialEq, Clone)]
pub enum Error {
    UnknownArenaId(usize),
    OffsetOverflow,
    OffsetUnderflow,
    RangeOverFlow,
}

#[derive(Debug, PartialEq, Clone, Default, Encode, Decode)]
pub struct VecArena<T: Encode + Decode> {
    backing: Vec<T>,
    offsets: Vec<usize>,
}

impl<T: Encode + Decode> VecArena<T> {
    pub fn alloc(&mut self) -> SubVecArena<T> {
        let arena_id = self.offsets.len();
        self.offsets.push(self.backing.len());

        SubVecArena {
            arena_id,
            _phantom: PhantomData,
        }
    }

    fn grow(&mut self, arena_id: usize, grow_by: usize) -> Result<(), Error> {
        if arena_id < self.offsets.len() {
            self.offsets
                .iter_mut()
                .skip(arena_id + 1)
                .try_for_each(|offset| {
                    *offset = offset
                        .checked_add(grow_by)
                        .ok_or_else(|| Error::OffsetOverflow)?;

                    Ok(())
                })
        } else {
            Err(Error::UnknownArenaId(arena_id))
        }
    }

    fn shrink(&mut self, arena_id: usize, shrink_by: usize) -> Result<(), Error> {
        if arena_id < self.offsets.len() {
            self.offsets
                .iter_mut()
                .skip(arena_id + 1)
                .try_for_each(|offset| {
                    *offset = offset
                        .checked_sub(shrink_by)
                        .ok_or_else(|| Error::OffsetUnderflow)?;

                    Ok(())
                })
        } else {
            Err(Error::UnknownArenaId(arena_id))
        }
    }

    fn splice_forgetful<I: IntoIterator<Item = T>>(
        &mut self,
        arena_id: usize,
        range: Range<usize>,
        replace_with: I,
    ) -> Result<(), Error> {
        let offset = *self
            .offsets
            .get(arena_id)
            .ok_or_else(|| Error::UnknownArenaId(arena_id))?;
        let start = range
            .start
            .checked_add(offset)
            .ok_or_else(|| Error::RangeOverFlow)?;
        let end = range
            .end
            .checked_add(offset)
            .ok_or_else(|| Error::RangeOverFlow)?;

        let prev_len = self.backing.len();

        self.backing.splice(start..end, replace_with);

        if prev_len < self.backing.len() {
            self.grow(arena_id, self.backing.len() - prev_len)?;
        } else if prev_len > self.backing.len() {
            self.shrink(arena_id, prev_len - self.backing.len())?;
        }

        Ok(())
    }

    fn len(&self, arena_id: usize) -> Result<usize, Error> {
        let start = self
            .offsets
            .get(arena_id)
            .ok_or_else(|| Error::UnknownArenaId(arena_id))?;
        let end = self
            .offsets
            .get(arena_id + 1)
            .copied()
            .unwrap_or_else(|| self.backing.len());

        Ok(end - start)
    }

    fn get(&self, arena_id: usize, i: usize) -> Result<Option<&T>, Error> {
        if i < self.len(arena_id)? {
            let offset = self
                .offsets
                .get(arena_id)
                .ok_or_else(|| Error::UnknownArenaId(arena_id))?;
            Ok(self.backing.get(i + offset))
        } else {
            Ok(None)
        }
    }

    fn get_mut(&mut self, arena_id: usize, i: usize) -> Result<Option<&mut T>, Error> {
        if i < self.len(arena_id)? {
            let offset = self
                .offsets
                .get(arena_id)
                .ok_or_else(|| Error::UnknownArenaId(arena_id))?;
            Ok(self.backing.get_mut(i + offset))
        } else {
            Ok(None)
        }
    }

    fn range(&self, arena_id: usize) -> Range<usize> {
        let start = self.offsets[arena_id];
        let end = self
            .offsets
            .get(arena_id + 1)
            .copied()
            .unwrap_or_else(|| self.backing.len());

        start..end
    }

    fn iter(&self, arena_id: usize) -> impl Iterator<Item = &T> {
        self.backing[self.range(arena_id)].iter()
    }

    fn iter_mut(&mut self, arena_id: usize) -> impl Iterator<Item = &mut T> {
        let range = self.range(arena_id);
        self.backing[range].iter_mut()
    }

    pub fn backing_len(&self) -> usize {
        self.backing.len()
    }
}

#[derive(Debug, PartialEq, Clone, Default, Encode, Decode)]
pub struct SubVecArena<T> {
    arena_id: usize,
    #[ssz(skip_serializing)]
    #[ssz(skip_deserializing)]
    _phantom: PhantomData<T>,
}

impl<T: Encode + Decode> SubVecArena<T> {
    pub fn extend_with_vec(&mut self, arena: &mut VecArena<T>, vec: Vec<T>) -> Result<(), Error> {
        let len = arena.len(self.arena_id)?;
        arena.splice_forgetful(self.arena_id, len..len, vec)?;
        Ok(())
    }

    pub fn push(&mut self, arena: &mut VecArena<T>, item: T) -> Result<(), Error> {
        let len = arena.len(self.arena_id)?;
        arena.splice_forgetful(self.arena_id, len..len, vec![item])?;
        Ok(())
    }

    pub fn get<'a>(&self, arena: &'a VecArena<T>, i: usize) -> Result<Option<&'a T>, Error> {
        arena.get(self.arena_id, i)
    }

    pub fn get_mut<'a>(
        &mut self,
        arena: &'a mut VecArena<T>,
        i: usize,
    ) -> Result<Option<&'a mut T>, Error> {
        arena.get_mut(self.arena_id, i)
    }

    pub fn iter<'a>(&self, arena: &'a VecArena<T>) -> impl Iterator<Item = &'a T> {
        arena.iter(self.arena_id)
    }

    pub fn iter_mut<'a>(&mut self, arena: &'a mut VecArena<T>) -> impl Iterator<Item = &'a mut T> {
        arena.iter_mut(self.arena_id)
    }

    pub fn len(&self, arena: &VecArena<T>) -> Result<usize, Error> {
        arena.len(self.arena_id)
    }

    pub fn is_empty(&self, arena: &VecArena<T>) -> Result<bool, Error> {
        self.len(arena).map(|len| len == 0)
    }
}

#[cfg(test)]
mod tests {
    use crate::Hash256;

    type VecArena = super::VecArena<Hash256>;
    type SubVecArena = super::SubVecArena<Hash256>;

    fn hash(i: usize) -> Hash256 {
        Hash256::from_low_u64_be(i as u64)
    }

    fn test_routine(arena: &mut VecArena, sub: &mut SubVecArena) {
        let mut len = sub.len(arena).expect("should exist");

        sub.push(arena, hash(len)).expect("should push");
        len += 1;

        assert_eq!(
            sub.len(arena).expect("should exist"),
            len,
            "after first push sub should have len {}",
            len
        );
        assert_eq!(
            sub.is_empty(arena).expect("should exist"),
            false,
            "new sub should not be empty"
        );

        sub.push(arena, hash(len)).expect("should push again");
        len += 1;

        assert_eq!(
            sub.len(arena).expect("should exist"),
            len,
            "after second push sub should have len {}",
            len
        );

        sub.extend_with_vec(arena, vec![hash(len), hash(len + 1)])
            .expect("should extend with vec");
        len += 2;

        assert_eq!(
            sub.len(arena).expect("should exist"),
            len,
            "after extend sub should have len {}",
            len
        );

        let collected = sub.iter(arena).cloned().collect::<Vec<_>>();
        let collected_mut = sub.iter_mut(arena).map(|v| *v).collect::<Vec<_>>();

        for i in 0..len {
            assert_eq!(
                *sub.get(arena, i)
                    .expect("should exist")
                    .expect("should get sub index"),
                hash(i),
                "get({}) should be hash({})",
                i,
                i
            );

            assert_eq!(
                collected[i],
                hash(i),
                "collected[{}] should be hash({})",
                i,
                i
            );

            assert_eq!(
                collected_mut[i],
                hash(i),
                "collected_mut[{}] should be hash({})",
                i,
                i
            );
        }
    }

    #[test]
    fn single() {
        let arena = &mut VecArena::default();

        assert_eq!(arena.backing.len(), 0, "should start with an empty backing");
        assert_eq!(arena.offsets.len(), 0, "should start without any offsets");

        let mut sub = arena.alloc();

        assert_eq!(
            sub.len(arena).expect("should exist"),
            0,
            "new sub should have len 0"
        );
        assert_eq!(
            sub.is_empty(arena).expect("should exist"),
            true,
            "new sub should be empty"
        );

        test_routine(arena, &mut sub);
    }

    #[test]
    fn double() {
        let arena = &mut VecArena::default();

        assert_eq!(arena.backing.len(), 0, "should start with an empty backing");
        assert_eq!(arena.offsets.len(), 0, "should start without any offsets");

        let mut sub_01 = arena.alloc();
        assert_eq!(
            sub_01.len(arena).expect("should exist"),
            0,
            "new sub should have len 0"
        );
        assert_eq!(
            sub_01.is_empty(arena).expect("should exist"),
            true,
            "new sub should be empty"
        );

        let mut sub_02 = arena.alloc();
        assert_eq!(
            sub_02.len(arena).expect("should exist"),
            0,
            "new sub should have len 0"
        );
        assert_eq!(
            sub_02.is_empty(arena).expect("should exist"),
            true,
            "new sub should be empty"
        );

        test_routine(arena, &mut sub_01);
        test_routine(arena, &mut sub_02);
    }

    #[test]
    fn one_then_other() {
        let arena = &mut VecArena::default();

        assert_eq!(arena.backing.len(), 0, "should start with an empty backing");
        assert_eq!(arena.offsets.len(), 0, "should start without any offsets");

        let mut sub_01 = arena.alloc();
        assert_eq!(
            sub_01.len(arena).expect("should exist"),
            0,
            "new sub should have len 0"
        );
        assert_eq!(
            sub_01.is_empty(arena).expect("should exist"),
            true,
            "new sub should be empty"
        );

        test_routine(arena, &mut sub_01);

        let mut sub_02 = arena.alloc();
        assert_eq!(
            sub_02.len(arena).expect("should exist"),
            0,
            "new sub should have len 0"
        );
        assert_eq!(
            sub_02.is_empty(arena).expect("should exist"),
            true,
            "new sub should be empty"
        );

        test_routine(arena, &mut sub_02);
        test_routine(arena, &mut sub_01);
        test_routine(arena, &mut sub_02);
    }

    #[test]
    fn many() {
        let arena = &mut VecArena::default();

        assert_eq!(arena.backing.len(), 0, "should start with an empty backing");
        assert_eq!(arena.offsets.len(), 0, "should start without any offsets");

        let mut subs = vec![];

        for i in 0..50 {
            if i == 0 {
                let sub = arena.alloc();
                assert_eq!(
                    sub.len(arena).expect("should exist"),
                    0,
                    "new sub should have len 0"
                );
                assert_eq!(
                    sub.is_empty(arena).expect("should exist"),
                    true,
                    "new sub should be empty"
                );
                subs.push(sub);

                continue;
            } else if i % 2 == 0 {
                test_routine(arena, &mut subs[i - 1]);
            }

            let sub = arena.alloc();
            assert_eq!(
                sub.len(arena).expect("should exist"),
                0,
                "new sub should have len 0"
            );
            assert_eq!(
                sub.is_empty(arena).expect("should exist"),
                true,
                "new sub should be empty"
            );
            subs.push(sub);
        }

        for mut sub in subs.iter_mut() {
            test_routine(arena, &mut sub);
        }
    }
}
