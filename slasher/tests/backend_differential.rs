#![cfg(any(feature = "mdbx", feature = "lmdb", feature = "redb"))]

//! Differential tests for the database backends.
//!
//! Apply the same random operations to each backend and to an in-memory model, and check that
//! every read agrees with the model.

use rand::{Rng, SeedableRng, rngs::SmallRng};
use slasher::{Config, Database, DatabaseBackend, Environment, Error, RwTransaction};
use std::collections::BTreeMap;
use tempfile::tempdir;

const NUM_TABLES: usize = 3;
const NUM_SEEDS: u64 = 8;
const NUM_SESSIONS: usize = 4;
const TXNS_PER_SESSION: usize = 25;

type Model = BTreeMap<(usize, Vec<u8>), Vec<u8>>;

fn backends() -> Vec<DatabaseBackend> {
    vec![
        #[cfg(feature = "mdbx")]
        DatabaseBackend::Mdbx,
        #[cfg(feature = "lmdb")]
        DatabaseBackend::Lmdb,
        #[cfg(feature = "redb")]
        DatabaseBackend::Redb,
    ]
}

/// Keys are drawn from a small space so that operations frequently hit existing keys.
fn random_key(rng: &mut SmallRng) -> Vec<u8> {
    let len = rng.random_range(1..=8);
    (0..len).map(|_| rng.random_range(0..4)).collect()
}

fn random_value(rng: &mut SmallRng) -> Vec<u8> {
    let len = rng.random_range(0..32);
    (0..len).map(|_| rng.random()).collect()
}

fn model_table(model: &Model, table: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
    model
        .range((table, vec![])..(table + 1, vec![]))
        .map(|((_, key), value)| (key.clone(), value.clone()))
        .collect()
}

fn random_existing_key(model: &Model, table: usize, rng: &mut SmallRng) -> Option<Vec<u8>> {
    let entries = model_table(model, table);
    (!entries.is_empty()).then(|| entries[rng.random_range(0..entries.len())].0.clone())
}

/// Read a whole table using the cursor's `first_key` and `next_key`.
fn scan(txn: &mut RwTransaction<'_>, db: &Database<'_>) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut keys = vec![];
    {
        let mut cursor = txn.cursor(db).unwrap();
        let mut key = cursor.first_key().unwrap().map(|key| key.to_vec());
        while let Some(current) = key {
            keys.push(current);
            key = cursor.next_key().unwrap().map(|key| key.to_vec());
        }
    }
    keys.into_iter()
        .map(|key| {
            let value = txn.get(db, &key).unwrap().unwrap().to_vec();
            (key, value)
        })
        .collect()
}

fn check(
    txn: &mut RwTransaction<'_>,
    tables: &[&Database<'_>; NUM_TABLES],
    model: &Model,
    rng: &mut SmallRng,
    ctx: &str,
) {
    for (table, db) in tables.iter().enumerate() {
        let expected = model_table(model, table);
        assert_eq!(scan(txn, db), expected, "scan table={table} {ctx}");

        let last_key = txn
            .cursor(db)
            .unwrap()
            .last_key()
            .unwrap()
            .map(|key| key.to_vec());
        assert_eq!(
            last_key,
            expected.last().map(|(key, _)| key.clone()),
            "last_key table={table} {ctx}"
        );

        let key = random_key(rng);
        assert_eq!(
            txn.get(db, &key).unwrap().map(|value| value.to_vec()),
            model.get(&(table, key.clone())).cloned(),
            "get table={table} {ctx}"
        );
    }
}

fn run(backend: DatabaseBackend, seed: u64) {
    let dir = tempdir().unwrap();
    let mut config = Config::new(dir.path().into());
    config.backend = backend;
    let mut model = Model::new();
    let mut rng = SmallRng::seed_from_u64(seed);

    for session in 0..NUM_SESSIONS {
        let env = Environment::new(&config).unwrap();
        let dbs = env.create_databases().unwrap();
        let tables = [
            &dbs.indexed_attestation_db,
            &dbs.proposers_db,
            &dbs.metadata_db,
        ];

        for i in 0..TXNS_PER_SESSION {
            let ctx = format!("backend={backend:?} seed={seed} session={session} txn={i}");
            let mut txn = env.begin_rw_txn().unwrap();
            check(&mut txn, &tables, &model, &mut rng, &ctx);

            let mut pending = model.clone();
            // Set when an operation failed, after which the transaction must be abandoned.
            let mut failed = false;
            for _ in 0..rng.random_range(1..32) {
                let table = rng.random_range(0..NUM_TABLES);
                let db = tables[table];
                match rng.random_range(0..100) {
                    0..40 => {
                        let (key, value) = (random_key(&mut rng), random_value(&mut rng));
                        txn.put(db, &key, &value).unwrap();
                        pending.insert((table, key), value);
                    }
                    40..50 => {
                        let (key, value) = (random_key(&mut rng), random_value(&mut rng));
                        txn.cursor(db).unwrap().put(&key, &value).unwrap();
                        pending.insert((table, key), value);
                    }
                    // Deleting a missing key is an error for LMDB and MDBX.
                    50..70 => {
                        if let Some(key) = random_existing_key(&pending, table, &mut rng) {
                            txn.del(db, &key).unwrap();
                            pending.remove(&(table, key));
                        }
                    }
                    70..80 => {
                        let entries = model_table(&pending, table);
                        if entries.is_empty() {
                            continue;
                        }
                        let start = rng.random_range(0..entries.len());

                        // A threshold predicate, as the slasher uses when pruning, or one that
                        // isn't monotone in key order, which distinguishes deleting while the
                        // predicate holds from deleting every matching key.
                        let threshold = random_key(&mut rng);
                        let monotone = rng.random_bool(0.5);
                        let predicate = |key: &[u8]| {
                            if monotone {
                                key < threshold.as_slice()
                            } else {
                                key.last().is_some_and(|byte| byte % 3 != 0)
                            }
                        };
                        let error_key = rng
                            .random_bool(0.1)
                            .then(|| entries[rng.random_range(start..entries.len())].0.clone());

                        let result = {
                            let mut cursor = txn.cursor(db).unwrap();
                            cursor.first_key().unwrap();
                            for _ in 0..start {
                                cursor.next_key().unwrap();
                            }
                            cursor
                                .delete_while(|key| {
                                    if error_key.as_deref() == Some(key) {
                                        Err(Error::MissingKey)
                                    } else {
                                        Ok(predicate(key))
                                    }
                                })
                                .map(|values| {
                                    values
                                        .into_iter()
                                        .map(|value| value.to_vec())
                                        .collect::<Vec<_>>()
                                })
                        };

                        let mut expected_values = vec![];
                        let mut expected_error = false;
                        for (key, value) in &entries[start..] {
                            if error_key.as_ref() == Some(key) {
                                expected_error = true;
                                break;
                            }
                            if !predicate(key) {
                                break;
                            }
                            pending.remove(&(table, key.clone()));
                            expected_values.push(value.clone());
                        }

                        if expected_error {
                            assert!(result.is_err(), "delete_while error {ctx}");
                            failed = true;
                            break;
                        }
                        assert_eq!(result.unwrap(), expected_values, "delete_while {ctx}");
                    }
                    _ => {
                        let key = random_key(&mut rng);
                        assert_eq!(
                            txn.get(db, &key).unwrap().map(|value| value.to_vec()),
                            pending.get(&(table, key.clone())).cloned(),
                            "get in txn {ctx}"
                        );
                    }
                }
            }

            if !failed && rng.random_bool(0.8) {
                txn.commit().unwrap();
                model = pending;
            } else {
                drop(txn);
            }
        }
    }

    let env = Environment::new(&config).unwrap();
    let dbs = env.create_databases().unwrap();
    let tables = [
        &dbs.indexed_attestation_db,
        &dbs.proposers_db,
        &dbs.metadata_db,
    ];
    let mut txn = env.begin_rw_txn().unwrap();
    check(
        &mut txn,
        &tables,
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
