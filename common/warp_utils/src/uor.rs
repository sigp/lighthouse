use warp::{filters::BoxedFilter, Filter, Rejection};

/// Mixin trait for `Filter` providing the unifying-or method.
pub trait UnifyingOrFilter: Filter<Error = Rejection> + Sized + Send + Sync + 'static
where
    Self::Extract: Send,
{
    /// Unifying `or`.
    ///
    /// This is a shorthand for `self.or(other).unify().boxed()`, which is useful because it keeps
    /// the filter type simple and prevents type-checker explosions.
    fn uor<F>(self, other: F) -> BoxedFilter<Self::Extract>
    where
        F: Filter<Extract = Self::Extract, Error = Rejection> + Clone + Send + Sync + 'static,
    {
        self.or(other).unify().boxed()
    }
}

impl<F> UnifyingOrFilter for F
where
    F: Filter<Error = Rejection> + Sized + Send + Sync + 'static,
    F::Extract: Send,
{
}
