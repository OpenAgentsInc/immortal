#[test]
fn m2_migration_contains_the_required_store_contract() {
    let sql = include_str!("../migrations/0001_store.sql");
    for required in [
        "CREATE TABLE nostr_event",
        "CREATE TABLE nostr_indexed_tag",
        "CREATE TABLE replaceable_head",
        "CREATE TABLE deletion_tombstone",
        "CREATE TABLE relay_policy",
        "CREATE TABLE relay_allowed_pubkey",
        "CREATE TABLE relay_allowed_kind",
        "CREATE TABLE relay_member_pubkey",
        "GENERATED ALWAYS AS IDENTITY",
        "GENERATED ALWAYS AS (",
        "USING gin (search_vector)",
        "nostr_event_no_ephemeral",
    ] {
        assert!(sql.contains(required), "migration is missing {required:?}");
    }
}

#[test]
fn m6_migration_contains_group_and_management_state() {
    let sql = include_str!("../migrations/0002_nip_expansion.sql");
    for required in [
        "CREATE TABLE relay_group",
        "CREATE TABLE relay_group_member",
        "CREATE TABLE relay_group_invite",
        "CREATE TABLE management_request",
    ] {
        assert!(sql.contains(required), "migration is missing {required:?}");
    }
}

#[test]
fn m7_migration_contains_media_ownership_and_replay_state() {
    let sql = include_str!("../migrations/0003_media.sql");
    for required in [
        "CREATE TABLE media_blob",
        "CREATE TABLE media_owner",
        "CREATE TABLE media_auth_request",
        "storage_key text COLLATE \"C\" NOT NULL",
        "REFERENCES media_blob(sha256) ON DELETE CASCADE",
    ] {
        assert!(sql.contains(required), "migration is missing {required:?}");
    }
}

#[test]
fn block_migrations_contain_identity_and_derived_state() {
    let identity = include_str!("../migrations/0004_agent_identity_turns.sql");
    for required in [
        "CREATE TABLE agent_owner",
        "agent_pubkey text COLLATE \"C\" PRIMARY KEY",
        "WHEN kind = 44200",
    ] {
        assert!(
            identity.contains(required),
            "identity migration is missing {required:?}"
        );
    }

    let handlers = include_str!("../migrations/0005_block_server_handlers.sql");
    for required in [
        "CREATE TABLE block_command",
        "CREATE TABLE workspace_profile",
        "CREATE TABLE archived_identity",
        "CREATE TABLE dm_hidden",
        "kind IN (30078, 30174, 30175, 30178, 30300, 30350, 30622, 44200)",
    ] {
        assert!(
            handlers.contains(required),
            "Block handler migration is missing {required:?}"
        );
    }
}

#[test]
fn legacy_import_migration_contains_a_bounded_idempotency_ledger() {
    let sql = include_str!("../migrations/0006_nostr_effect_import.sql");
    for required in [
        "CREATE TABLE nostr_effect_import_ledger",
        "event_id text COLLATE \"C\" PRIMARY KEY",
        "outcome IN ('stored', 'duplicate', 'ephemeral', 'rejected')",
    ] {
        assert!(
            sql.contains(required),
            "import migration is missing {required:?}"
        );
    }
}

#[test]
fn legacy_expiration_migration_adds_a_terminal_outcome() {
    let sql = include_str!("../migrations/0007_legacy_expiration.sql");
    assert!(sql.contains("'expired'"));
    assert!(sql.contains("DROP CONSTRAINT nostr_effect_import_outcome"));
}

#[test]
fn mkt_immutable_migration_keeps_coordinates_after_event_removal() {
    let sql = include_str!("../migrations/0008_mkt_immutable.sql");
    for required in [
        "CREATE TABLE mkt_immutable_coordinate",
        "PRIMARY KEY (pubkey, kind, identifier)",
        "kind BETWEEN 39604 AND 39609",
        "event_id text COLLATE \"C\" NOT NULL UNIQUE",
        "sig text COLLATE \"C\" NOT NULL",
        "INSERT INTO mkt_immutable_coordinate",
        "DELETE FROM replaceable_head",
    ] {
        assert!(sql.contains(required), "migration is missing {required:?}");
    }
    assert!(
        !sql.contains("REFERENCES nostr_event"),
        "coordinate binding must survive NIP-09 deletion and NIP-40 cleanup"
    );
}

#[test]
fn mkt_gateway_privacy_migration_excludes_gift_wraps_from_search() {
    let sql = include_str!("../migrations/0009_mkt_gateway_privacy.sql");
    for required in [
        "DROP INDEX nostr_event_search_idx",
        "ALTER TABLE nostr_event DROP COLUMN search_vector",
        "kind = 1059",
        "kind BETWEEN 39604 AND 39609",
        "USING gin (search_vector)",
    ] {
        assert!(sql.contains(required), "migration is missing {required:?}");
    }
}

#[test]
fn mkt_gateway_query_acl_hides_private_rows_and_requires_one_wrap_recipient() {
    let statements = include_str!("../src/store/statements.rs");
    assert_eq!(
        statements
            .matches("e.kind NOT BETWEEN 39604 AND 39609")
            .count(),
        2
    );
    assert_eq!(
        statements.matches("recipient_count.tag_name = 'p'").count(),
        2
    );
}
