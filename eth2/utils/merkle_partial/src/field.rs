use super::NodeIndex;

/// Defines the necessary attributes for a struct's field to determine its generalized index and
/// its children if it is also a struct.
#[derive(Debug, PartialEq)]
pub enum Node {
    Intermediate(NodeIndex),
    Composite(Composite),
    Leaf(Leaf),
    Unattached(NodeIndex),
}

#[derive(Debug, PartialEq)]
pub enum Leaf {
    Basic(Vec<Basic>),
    Length(Basic),
    Padding(),
}

#[derive(Debug, PartialEq)]
pub struct Basic {
    pub ident: String,
    pub index: NodeIndex,
    pub size: u8,
    pub offset: u8,
}

#[derive(Debug, PartialEq)]
pub struct Composite {
    pub ident: &'static str,
    pub index: NodeIndex,
    pub height: u8,
}
