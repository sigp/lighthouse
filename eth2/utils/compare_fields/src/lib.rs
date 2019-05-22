#[derive(Debug, PartialEq, Clone)]
pub struct FieldComparison {
    pub equal: bool,
    pub field_name: String,
    pub a: String,
    pub b: String,
}

pub trait CompareFields {
    fn compare_fields(&self, b: &Self) -> Vec<FieldComparison>;
}
