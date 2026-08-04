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
