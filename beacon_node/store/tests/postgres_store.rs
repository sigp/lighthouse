use store::database::postgres_impl::PostgresDB;
use store::{AsyncKeyValueStore, DBColumn};
use types::MainnetEthSpec;

#[tokio::test]
async fn test_postgres_store() {
    dotenvy::dotenv().ok();

    let db_url = std::env::var("DATABASE_URL").expect("DATABASE_URL must be set");

    let db = PostgresDB::<MainnetEthSpec>::new(&db_url)
        .await
        .expect("failed to connect");

    let key = b"test_key";
    let value = b"test_value";

    db.put_bytes(DBColumn::BeaconBlock, key, value)
        .await
        .expect("put failed");

    let result = db.get_bytes(DBColumn::BeaconBlock, key)
        .await
        .expect("get failed");

    assert_eq!(result, Some(value.to_vec()));
}