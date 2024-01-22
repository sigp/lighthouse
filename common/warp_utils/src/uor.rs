use warp::{
    filters::BoxedFilter,
    generic::{Combine, CombinedTuples, Tuple},
    reject::sealed::CombineRejection,
    Filter, Rejection,
};

/// Mixin trait for `Filter` providing the unifying-or method.
pub trait UnifyingOrFilter: Filter + Sized + Send + Sync + 'static
where
    Self::Extract: Send,
{
    /// Unifying `or`.
    ///
    /// This is a shorthand for `self.or(other).unify().boxed()`, which is useful because it keeps
    /// the filter type simple and prevents type-checker explosions.
    fn uor<F>(self, other: F) -> BoxedFilter<Self::Extract>
    where
        Self: Filter<Error = Rejection>,
        F: Filter<Extract = Self::Extract, Error = Rejection> + Clone + Send + Sync + 'static,
    {
        self.or(other).unify().boxed()
    }

    /// Boxed and.
    fn band<F>(self, other: F) -> BoxedFilter<CombinedTuples<Self::Extract, F::Extract>>
    where
        Self::Extract: Send + Sync + 'static,
        F: Filter + Clone + Send + Sync + 'static,
        <Self::Extract as Tuple>::HList: Combine<<F::Extract as Tuple>::HList> + Send + 'static,
        CombinedTuples<Self::Extract, F::Extract>: Send + Sync,
        F::Error: CombineRejection<Self::Error>,
    {
        self.and(other).boxed()
    }
}

impl<F> UnifyingOrFilter for F
where
    F: Filter + Sized + Send + Sync + 'static,
    F::Extract: Send,
{
}
