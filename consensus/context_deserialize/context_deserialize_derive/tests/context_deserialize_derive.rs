use context_deserialize::{context_deserialize, ContextDeserialize};
use serde::{Deserialize, Serialize};

#[test]
fn test_context_deserialize_derive() {
    type TestContext = ();

    #[context_deserialize(TestContext)]
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Test {
        field: String,
    }

    let test = Test {
        field: "test".to_string(),
    };
    let serialized = serde_json::to_string(&test).unwrap();
    let deserialized =
        Test::context_deserialize(&mut serde_json::Deserializer::from_str(&serialized), ())
            .unwrap();
    assert_eq!(test, deserialized);
}

#[test]
fn test_context_deserialize_derive_multiple_types() {
    #[allow(dead_code)]
    struct TestContext1(u64);
    #[allow(dead_code)]
    struct TestContext2(String);

    // This will derive:
    // - ContextDeserialize<TestContext1> for Test
    // - ContextDeserialize<TestContext2> for Test
    // by just leveraging the Deserialize impl
    #[context_deserialize(TestContext1, TestContext2)]
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Test {
        field: String,
    }

    let test = Test {
        field: "test".to_string(),
    };
    let serialized = serde_json::to_string(&test).unwrap();
    let deserialized = Test::context_deserialize(
        &mut serde_json::Deserializer::from_str(&serialized),
        TestContext1(1),
    )
    .unwrap();
    assert_eq!(test, deserialized);

    let deserialized = Test::context_deserialize(
        &mut serde_json::Deserializer::from_str(&serialized),
        TestContext2("2".to_string()),
    )
    .unwrap();

    assert_eq!(test, deserialized);
}

#[test]
fn test_context_deserialize_derive_bound() {
    use std::fmt::Debug;

    struct TestContext;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Inner {
        value: u64,
    }

    #[context_deserialize(
        TestContext,
        bound = "T: Serialize + for<'a> Deserialize<'a> + Debug + PartialEq"
    )]
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Wrapper<T> {
        inner: T,
    }

    let val = Wrapper {
        inner: Inner { value: 42 },
    };

    let serialized = serde_json::to_string(&val).unwrap();
    let deserialized = Wrapper::<Inner>::context_deserialize(
        &mut serde_json::Deserializer::from_str(&serialized),
        TestContext,
    )
    .unwrap();

    assert_eq!(val, deserialized);
}
