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

/// Describes a true
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Primitive {
    pub ident: String,
    pub index: NodeIndex,
    pub size: u8,
    pub offset: u8,
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Composite {
    pub ident: String,
    pub index: NodeIndex,
    pub height: u8,
}
