//! Provides field-by-field comparisons for structs and vecs.
//!
//! Returns comparisons as data, without making assumptions about the desired equality (e.g.,
//! does not `panic!` on inequality).
//!
//! Note: `compare_fields_derive` requires `PartialEq` and `Debug` implementations.
//!
//! ## Example
//!
//! ```rust
//! use compare_fields::{CompareFields, Comparison, FieldComparison};
//! use compare_fields_derive::CompareFields;
//!
//! #[derive(PartialEq, Debug, CompareFields)]
//! pub struct Bar {
//!     a: u64,
//!     b: u16,
//!     #[compare_fields(as_slice)]
//!     c: Vec<Foo>
//! }
//!
//! #[derive(Clone, PartialEq, Debug, CompareFields)]
//! pub struct Foo {
//!     d: String
//! }
//!
//! let cat = Foo {d: "cat".to_string()};
//! let dog = Foo {d: "dog".to_string()};
//! let chicken = Foo {d: "chicken".to_string()};
//!
//! let mut bar_a = Bar {
//!     a: 42,
//!     b: 12,
//!     c: vec![ cat.clone(), dog.clone() ],
//! };
//!
//! let mut bar_b = Bar {
//!     a: 42,
//!     b: 99,
//!     c: vec![ chicken.clone(), dog.clone()]
//! };
//!
//! let cat_dog = Comparison::Child(FieldComparison {
//!     field_name: "d".to_string(),
//!     equal: false,
//!     a: "\"cat\"".to_string(),
//!     b: "\"dog\"".to_string(),
//! });
//! assert_eq!(cat.compare_fields(&dog), vec![cat_dog]);
//!
//! let bar_a_b = vec![
//!     Comparison::Child(FieldComparison {
//!         field_name: "a".to_string(),
//!         equal: true,
//!         a: "42".to_string(),
//!         b: "42".to_string(),
//!     }),
//!     Comparison::Child(FieldComparison {
//!         field_name: "b".to_string(),
//!         equal: false,
//!         a: "12".to_string(),
//!         b: "99".to_string(),
//!     }),
//!     Comparison::Parent{
//!         field_name: "c".to_string(),
//!         equal: false,
//!         children: vec![
//!             FieldComparison {
//!                 field_name: "0".to_string(),
//!                 equal: false,
//!                 a: "Some(Foo { d: \"cat\" })".to_string(),
//!                 b: "Some(Foo { d: \"chicken\" })".to_string(),
//!             },
//!             FieldComparison {
//!                 field_name: "1".to_string(),
//!                 equal: true,
//!                 a: "Some(Foo { d: \"dog\" })".to_string(),
//!                 b: "Some(Foo { d: \"dog\" })".to_string(),
//!             }
//!         ]
//!     }
//! ];
//! assert_eq!(bar_a.compare_fields(&bar_b), bar_a_b);
//!
//!
//!
//! // TODO:
//! ```
use std::fmt::Debug;

#[derive(Debug, PartialEq, Clone)]
pub enum Comparison {
    Child(FieldComparison),
    Parent {
        field_name: String,
        equal: bool,
        children: Vec<FieldComparison>,
    },
}

impl Comparison {
    pub fn child<T: Debug + PartialEq<T>>(field_name: String, a: &T, b: &T) -> Self {
        Comparison::Child(FieldComparison::new(field_name, a, b))
    }

    pub fn parent(field_name: String, equal: bool, children: Vec<FieldComparison>) -> Self {
        Comparison::Parent {
            field_name,
            equal,
            children,
        }
    }

    pub fn from_slice<T: Debug + PartialEq<T>>(field_name: String, a: &[T], b: &[T]) -> Self {
        let mut children = vec![];

        for i in 0..std::cmp::max(a.len(), b.len()) {
            children.push(FieldComparison::new(
                format!("{:}", i),
                &a.get(i),
                &b.get(i),
            ));
        }

        Self::parent(field_name, a == b, children)
    }

    pub fn retain_children<F>(&mut self, f: F)
    where
        F: FnMut(&FieldComparison) -> bool,
    {
        match self {
            Comparison::Child(_) => (),
            Comparison::Parent { children, .. } => children.retain(f),
        }
    }

    pub fn equal(&self) -> bool {
        match self {
            Comparison::Child(fc) => fc.equal,
            Comparison::Parent { equal, .. } => *equal,
        }
    }

    pub fn not_equal(&self) -> bool {
        !self.equal()
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct FieldComparison {
    pub field_name: String,
    pub equal: bool,
    pub a: String,
    pub b: String,
}

pub trait CompareFields {
    fn compare_fields(&self, b: &Self) -> Vec<Comparison>;
}

impl FieldComparison {
    pub fn new<T: Debug + PartialEq<T>>(field_name: String, a: &T, b: &T) -> Self {
        Self {
            field_name,
            equal: a == b,
            a: format!("{:?}", a),
            b: format!("{:?}", b),
        }
    }

    pub fn equal(&self) -> bool {
        self.equal
    }

    pub fn not_equal(&self) -> bool {
        !self.equal()
    }
}
