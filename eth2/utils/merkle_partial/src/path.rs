use crate::NodeIndex;

#[derive(Clone, Debug, PartialEq)]
pub enum Path {
    Ident(String),
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
