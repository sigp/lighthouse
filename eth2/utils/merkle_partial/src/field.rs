use super::NodeIndex;

/// Defines the necessary attributes for a struct's field to determine its generalized index and
/// its children if it is also a struct.
pub struct Field {
    pub ident: &'static str,
    pub index: NodeIndex,
    pub children: Vec<Box<Field>>,
}
