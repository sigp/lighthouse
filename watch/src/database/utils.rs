#![allow(dead_code)]
use crate::database::config::Config;
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel_migrations::{FileBasedMigrations, MigrationHarness};

/// Sets `config.dbname` to `config.default_dbname` and returns `(new_config, old_dbname)`.
///
/// This is useful for creating or dropping databases, since these actions must be done by
/// logging into another database.
pub fn get_config_using_default_db(config: &Config) -> (Config, String) {
    let mut config = config.clone();
    let new_dbname = std::mem::replace(&mut config.dbname, config.default_dbname.clone());
    (config, new_dbname)
}

/// Runs the set of migrations as detected in the local directory.
/// Equivalent to `diesel migration run`.
///
/// Contains `unwrap`s so is only suitable for test code.
/// TODO(mac) refactor to return Result<PgConnection, Error>
pub fn run_migrations(config: &Config) -> PgConnection {
    let database_url = config.clone().build_database_url();
    let mut conn = PgConnection::establish(&database_url).unwrap();
    let migrations = FileBasedMigrations::find_migrations_directory().unwrap();
    conn.run_pending_migrations(migrations).unwrap();
    conn.begin_test_transaction().unwrap();
    conn
}
