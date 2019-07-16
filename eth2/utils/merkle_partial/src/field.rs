use super::NodeIndex;

/// Represents any valid node value.
#[derive(Debug, PartialEq)]
pub enum Node {
    Intermediate(NodeIndex),
    Composite(Composite),
    Leaf(Leaf),
    Unattached(NodeIndex),
}

/// Represents all valid leaf values.
#[derive(Debug, PartialEq)]
pub enum Leaf {
    Primitive(Vec<Primitive>),
    Length(Primitive),
    Padding(),
}

/// Describes the identifier, size, and offset of a primitive SSZ type associated with `index`.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Primitive {
    pub index: NodeIndex,
    pub ident: String,
    pub size: u8,
    pub offset: u8,
}

/// Describes the identifier and height of a composite SSZ type associated with `index`.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Composite {
    pub index: NodeIndex,
    pub ident: String,
    pub height: u8,
}
