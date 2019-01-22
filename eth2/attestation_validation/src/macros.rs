macro_rules! verify_or {
    ($condition: expr, $result: expr) => {
        if !$condition {
            $result
        }
    };
}

macro_rules! reject {
    ($result: expr) => {
        return Ok(Outcome::Invalid($result));
    };
}

macro_rules! accept {
    () => {
        Ok(Outcome::Valid)
    };
}
