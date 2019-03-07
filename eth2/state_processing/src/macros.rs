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

macro_rules! safe_add_assign {
    ($a: expr, $b: expr) => {
        $a = $a.saturating_add($b);
    };
}
macro_rules! safe_sub_assign {
    ($a: expr, $b: expr) => {
        $a = $a.saturating_sub($b);
    };
}
