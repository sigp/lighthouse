use compare_fields::{CompareFields, FieldComparison};
use compare_fields_derive::CompareFields;

#[derive(Clone, Debug, CompareFields)]
pub struct Simple {
    a: u64,
    b: u16,
    c: Vec<u8>,
}

#[test]
fn compare() {
    let foo = Simple {
        a: 42,
        b: 12,
        c: vec![1, 2],
    };

    let mut bar = foo.clone();

    let comparisons = foo.compare_fields(&bar);

    assert!(!comparisons.iter().any(|c| c.equal == false));

    assert_eq!(
        comparisons[0],
        FieldComparison {
            equal: true,
            field_name: "a".to_string(),
            a: "42".to_string(),
            b: "42".to_string(),
        }
    );

    bar.a = 30;

    assert_eq!(
        foo.compare_fields(&bar)[0],
        FieldComparison {
            equal: false,
            field_name: "a".to_string(),
            a: "42".to_string(),
            b: "30".to_string(),
        }
    );
}
