#[derive(Debug, PartialEq, Clone)]
pub struct FieldComparison {
    pub field_name: String,
    pub equal: bool,
    pub a: String,
    pub b: String,
}

pub trait CompareFields {
    fn compare_fields(&self, b: &Self) -> Vec<FieldComparison>;
}
