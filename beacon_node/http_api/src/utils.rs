use warp::filters::BoxedFilter;

pub type ResponseFilter = BoxedFilter<(warp::reply::Response,)>;
