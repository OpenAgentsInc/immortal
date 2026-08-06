use std::collections::BTreeMap;

use sha2::{Digest, Sha256};
use tokio_postgres::Client;

use super::ProviderStoreError;

const BOOTSTRAP_SQL: &str = r#"
SELECT pg_advisory_xact_lock(1229802832, 1297109840);

CREATE TABLE IF NOT EXISTS provider_schema_migrations (
    version bigint PRIMARY KEY,
    name text COLLATE "C" NOT NULL UNIQUE,
    sha256 text COLLATE "C" NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT provider_schema_migrations_sha256 CHECK (sha256 ~ '^[0-9a-f]{64}$')
);
"#;
const SELECT_MIGRATIONS_SQL: &str =
    "SELECT version, name, sha256 FROM provider_schema_migrations ORDER BY version";
const INSERT_MIGRATION_SQL: &str =
    "INSERT INTO provider_schema_migrations (version, name, sha256) VALUES ($1, $2, $3)";

struct Migration {
    version: i64,
    name: &'static str,
    sql: &'static str,
}

const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        name: "provider_store",
        sql: include_str!("../../../../migrations/provider/0001_provider_store.sql"),
    },
    Migration {
        version: 2,
        name: "boltz_invoice_binding",
        sql: include_str!("../../../../migrations/provider/0002_boltz_invoice_binding.sql"),
    },
    Migration {
        version: 3,
        name: "restore_safe_public_json",
        sql: include_str!("../../../../migrations/provider/0003_restore_safe_public_json.sql"),
    },
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderMigrationReport {
    pub applied_versions: Vec<i64>,
}

pub(super) async fn apply(
    client: &mut Client,
) -> Result<ProviderMigrationReport, ProviderStoreError> {
    let transaction = client.transaction().await?;
    transaction.batch_execute(BOOTSTRAP_SQL).await?;
    let select = transaction.prepare(SELECT_MIGRATIONS_SQL).await?;
    let insert = transaction.prepare(INSERT_MIGRATION_SQL).await?;
    let rows = transaction.query(&select, &[]).await?;
    let applied = collect(rows);
    validate(&applied)?;

    let mut applied_versions = Vec::new();
    for migration in MIGRATIONS {
        if applied.contains_key(&migration.version) {
            continue;
        }
        transaction.batch_execute(migration.sql).await?;
        let hash = digest(migration.sql.as_bytes());
        transaction
            .execute(&insert, &[&migration.version, &migration.name, &hash])
            .await?;
        applied_versions.push(migration.version);
    }
    transaction.commit().await?;
    Ok(ProviderMigrationReport { applied_versions })
}

pub(super) async fn verify(client: &Client) -> Result<ProviderMigrationReport, ProviderStoreError> {
    let select = client.prepare(SELECT_MIGRATIONS_SQL).await?;
    let applied = collect(client.query(&select, &[]).await?);
    validate(&applied)?;
    for migration in MIGRATIONS {
        if !applied.contains_key(&migration.version) {
            return Err(ProviderStoreError::MigrationDrift(format!(
                "provider database is missing version {} ({})",
                migration.version, migration.name
            )));
        }
    }
    Ok(ProviderMigrationReport {
        applied_versions: Vec::new(),
    })
}

fn collect(rows: Vec<tokio_postgres::Row>) -> BTreeMap<i64, (String, String)> {
    rows.into_iter()
        .map(|row| {
            (
                row.get::<_, i64>(0),
                (row.get::<_, String>(1), row.get::<_, String>(2)),
            )
        })
        .collect()
}

fn validate(applied: &BTreeMap<i64, (String, String)>) -> Result<(), ProviderStoreError> {
    for (version, (name, hash)) in applied {
        let expected = MIGRATIONS
            .iter()
            .find(|migration| migration.version == *version)
            .ok_or_else(|| {
                ProviderStoreError::MigrationDrift(format!(
                    "provider database has unknown version {version} ({name})"
                ))
            })?;
        if expected.name != name || digest(expected.sql.as_bytes()) != *hash {
            return Err(ProviderStoreError::MigrationDrift(format!(
                "provider migration {version} does not match the compiled ledger"
            )));
        }
    }
    Ok(())
}

fn digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}
