use crate::NodeIndex;

/// An identifier for the location of a distinct value in a partial.
#[derive(Clone, Debug, PartialEq)]
pub enum Path {
    /// An identifier for a member of a container object or for the length of a list.
    Ident(String),
    /// An identifier for the position of a value in a homogeneous collection.
    Index(NodeIndex),
}

impl std::fmt::Display for Path {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Path::Ident(s) => fmt.write_str(s),
            Path::Index(i) => fmt.write_str(&i.to_string()),
        }?;

        Ok(())
    }
}
