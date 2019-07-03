use super::NodeIndex;

/// Defines the necessary attributes for a struct's field to determine its generalized index and
/// its children if it is also a struct.
pub enum Node {
    Root(Value),
    Intermediate(Value),
    Container(Container),
    Leaf(Leaf),
}

pub enum Leaf {
    Basic(Vec<Basic>),
    Length(Basic),
    Padding(),
}

pub struct Basic {
    pub ident: &'static str,
    pub index: NodeIndex,
    pub size: usize,
    pub offset: u8,
}

pub struct Container {
    pub ident: &'static str,
    pub index: NodeIndex,
}

pub struct Value {
    pub index: NodeIndex,
}
