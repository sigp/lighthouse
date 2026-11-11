//! Differential tests for the database backends.
//!
//! Apply the same random operations to each backend and to an in-memory model, and check that
//! every read agrees with the model.

use rand::{Rng, SeedableRng, rngs::SmallRng};
use std::collections::{BTreeMap, HashSet};
use std::path::Path;
use store::config::DatabaseBackend;
use store::database::interface::BeaconNodeBackend;
use store::{DBColumn, KeyValueStore, KeyValueStoreOp, StoreConfig};
use tempfile::tempdir;

/// Columns with each key size.
const COLUMNS: [DBColumn; 3] = [
    DBColumn::BeaconBlockRoots,
    DBColumn::BeaconBlock,
    DBColumn::BeaconDataColumn,
];
const NUM_SEEDS: u64 = 4;
const NUM_OPS: usize = 2_000;
const FULL_CHECK_INTERVAL: usize = 100;

type Model = BTreeMap<(&'static str, Vec<u8>), Vec<u8>>;

fn backends() -> Vec<DatabaseBackend> {
    vec![
        #[cfg(feature = "leveldb")]
        DatabaseBackend::LevelDb,
        #[cfg(feature = "redb")]
        DatabaseBackend::Redb,
    ]
}

fn open(backend: DatabaseBackend, path: &Path) -> BeaconNodeBackend {
    let config = StoreConfig {
        backend,
        ..StoreConfig::default()
    };
    BeaconNodeBackend::open(&config, path).unwrap()
}

fn random_column(rng: &mut SmallRng) -> DBColumn {
    COLUMNS[rng.random_range(0..COLUMNS.len())]
}

/// Keys are drawn from a small space so that operations frequently hit existing keys.
fn random_key(rng: &mut SmallRng, column: DBColumn) -> Vec<u8> {
    let mut key = vec![0; column.key_size()];
    key[0] = rng.random_range(0..4);
    *key.last_mut().unwrap() = rng.random_range(0..64);
    key
}

/// Mostly small values, with some large ones so that tables span many pages.
fn random_value(rng: &mut SmallRng) -> Vec<u8> {
    let len = if rng.random_bool(0.1) {
        rng.random_range(1024..16 * 1024)
    } else {
        rng.random_range(0..64)
    };
    (0..len).map(|_| rng.random()).collect()
}

fn delete_predicate(value: &[u8]) -> bool {
    value.first().is_some_and(|byte| byte % 4 == 0)
}

fn model_column(model: &Model, column: DBColumn, from: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let name: &'static str = column.into();
    model
        .range((name, from.to_vec())..)
        .take_while(|((col, _), _)| *col == name)
        .map(|((_, key), value)| (key.clone(), value.clone()))
        .collect()
}

fn check_point(db: &BeaconNodeBackend, model: &Model, column: DBColumn, key: &[u8], ctx: &str) {
    let expected = model.get(&(column.into(), key.to_vec())).cloned();
    assert_eq!(db.get_bytes(column, key).unwrap(), expected, "get {ctx}");
    assert_eq!(
        db.key_exists(column, key).unwrap(),
        expected.is_some(),
        "key_exists {ctx}"
    );
}

fn check_iteration(db: &BeaconNodeBackend, model: &Model, rng: &mut SmallRng, ctx: &str) {
    for column in COLUMNS {
        let expected = model_column(model, column, &vec![0; column.key_size()]);
        let actual = db
            .iter_column::<Vec<u8>>(column)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(actual, expected, "iter_column {column:?} {ctx}");

        let from = random_key(rng, column);
        let expected = model_column(model, column, &from);
        let actual = db
            .iter_column_from::<Vec<u8>>(column, &from)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(actual, expected, "iter_column_from {column:?} {ctx}");

        let expected_keys = expected.into_iter().map(|(key, _)| key).collect::<Vec<_>>();
        let actual_keys = db
            .iter_column_keys_from::<Vec<u8>>(column, &from)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(
            actual_keys, expected_keys,
            "iter_column_keys_from {column:?} {ctx}"
        );
    }
}

fn run(backend: DatabaseBackend, seed: u64) {
    let dir = tempdir().unwrap();
    let mut db = open(backend, dir.path());
    let mut model = Model::new();
    let mut rng = SmallRng::seed_from_u64(seed);

    for i in 0..NUM_OPS {
        let ctx = format!("backend={backend:?} seed={seed} op={i}");
        let column = random_column(&mut rng);
        match rng.random_range(0..100) {
            0..25 => {
                let (key, value) = (random_key(&mut rng, column), random_value(&mut rng));
                if rng.random_bool(0.1) {
                    db.put_bytes_sync(column, &key, &value).unwrap();
                } else {
                    db.put_bytes(column, &key, &value).unwrap();
                }
                model.insert((column.into(), key), value);
            }
            25..35 => {
                let key = random_key(&mut rng, column);
                db.key_delete(column, &key).unwrap();
                model.remove(&(column.into(), key));
            }
            35..55 => {
                let mut batch = vec![];
                for _ in 0..rng.random_range(1..16) {
                    let column = random_column(&mut rng);
                    let key = random_key(&mut rng, column);
                    if rng.random_bool(0.7) {
                        let value = random_value(&mut rng);
                        model.insert((column.into(), key.clone()), value.clone());
                        batch.push(KeyValueStoreOp::PutKeyValue(column, key, value));
                    } else {
                        model.remove(&(column.into(), key.clone()));
                        batch.push(KeyValueStoreOp::DeleteKey(column, key));
                    }
                }
                db.do_atomically(batch).unwrap();
            }
            55..60 => {
                let keys = (0..rng.random_range(1..8))
                    .map(|_| random_key(&mut rng, column))
                    .collect::<Vec<_>>();
                for key in &keys {
                    model.remove(&(column.into(), key.clone()));
                }
                db.delete_batch(
                    column,
                    keys.iter().map(Vec::as_slice).collect::<HashSet<_>>(),
                )
                .unwrap();
            }
            60..62 => {
                let name: &'static str = column.into();
                model.retain(|(col, _), value| *col != name || !delete_predicate(value));
                db.delete_if(column, |value| Ok(delete_predicate(value)))
                    .unwrap();
            }
            62 => db.compact().unwrap(),
            63 => {
                drop(db);
                db = open(backend, dir.path());
            }
            _ => {
                let key = random_key(&mut rng, column);
                check_point(&db, &model, column, &key, &ctx);
            }
        }

        if i % FULL_CHECK_INTERVAL == 0 {
            check_iteration(&db, &model, &mut rng, &ctx);
        }
    }

    // Everything must survive a clean reopen.
    drop(db);
    let db = open(backend, dir.path());
    check_iteration(
        &db,
        &model,
        &mut rng,
        &format!("backend={backend:?} seed={seed} final"),
    );
}

#[test]
fn backends_match_model() {
    for backend in backends() {
        for seed in 0..NUM_SEEDS {
            run(backend, seed);
        }
    }
}
