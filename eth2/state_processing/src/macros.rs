macro_rules! verify {
    ($condition: expr, $result: expr) => {
        if !$condition {
            return Err(Error::Invalid($result));
        }
    };
}

macro_rules! invalid {
    ($result: expr) => {
        return Err(Error::Invalid($result));
    };
}
