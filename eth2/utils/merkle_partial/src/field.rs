use super::NodeIndex;

/// Represents any valid node value.
#[derive(Clone, Debug, PartialEq)]
pub enum Node {
    Composite(Composite),
    Leaf(Leaf),
}

impl Node {
    pub fn get_index(&self) -> NodeIndex {
        match self {
            Node::Composite(c) => c.index,
            Node::Leaf(Leaf::Primitive(l)) => l[0].index,
            Node::Leaf(Leaf::Length(l)) => l.index,
            // TODO: this should have an index
        }
    }
}

/// Represents all valid leaf values.
#[derive(Clone, Debug, PartialEq)]
pub enum Leaf {
    Primitive(Vec<Primitive>),
    Length(Primitive),
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
