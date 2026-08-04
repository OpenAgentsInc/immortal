//! Nostr protocol primitives owned by Immortal.
//!
//! These types implement the pinned NIP specifications in `nips/`. They do
//! not perform storage or network I/O, which keeps protocol decisions
//! deterministic and fixture-testable.

mod agent;
mod block;
mod deletion;
mod error;
mod event;
mod expanded;
mod filter;
mod hex;
mod mkt;
mod openagents;
mod replacement;
mod timestamp;

pub use agent::{
    AGENT_OBSERVER_KIND, AGENT_TURN_METRIC_KIND, AgentObserverDirection, AgentObserverRoute,
    OwnerAttestation, agent_observer_route, agent_turn_metric_owner, validate_nip44_v2_content,
    verify_agent_auth_attestation, verify_owner_attestation, verify_owner_binding,
};
pub use block::{
    AGENT_ENGRAM_KIND, AGENT_PERSONA_KIND, BLOCK_GLOBAL_ONLY_KINDS, DM_HIDE_KIND, DM_OPEN_KIND,
    DM_VISIBILITY_KIND, EVENT_REMINDER_KIND, IDENTITY_ARCHIVE_LIST_KIND,
    IDENTITY_ARCHIVE_REQUEST_KIND, IDENTITY_ARCHIVED_KIND, IDENTITY_UNARCHIVE_REQUEST_KIND,
    IDENTITY_UNARCHIVED_KIND, IdentityArchiveRequest, MAX_REMINDER_HORIZON_SECONDS, PROJECT_KIND,
    PUSH_LEASE_KIND, READ_STATE_KIND, RELAY_ONLY_BLOCK_KINDS, TEAM_CATALOG_KIND,
    THREAD_SUMMARY_KIND, WINDOW_BOUNDS_KIND, WORKSPACE_PROFILE_KIND, dm_visibility_channel,
    parse_identity_archive_request, validate_block_ingest, workspace_icon,
};
pub use deletion::{DeletionRequest, DeletionTombstone};
pub use error::DomainError;
pub use event::{Event, Tag};
pub use expanded::{
    GroupAction, GroupMetadata, HttpAuth, RelaySigner, parse_http_authorization,
    parse_http_authorization_hash,
};
pub use filter::{Filter, matches_any, search_terms};
pub use mkt::{
    MKT_CANCEL_ACTIONS, MKT_CANCEL_KIND, MKT_CLOSE_KIND, MKT_DESCRIPTOR_STATUSES,
    MKT_ENVELOPE_SCHEMA, MKT_EXECUTABLE_PROFILES, MKT_IDENTIFIER_MAX_BYTES, MKT_IDENTIFIER_PATTERN,
    MKT_MAX_COUNTERPARTIES, MKT_MAX_DISCOVERY_CONTENT_BYTES, MKT_MAX_HINTS,
    MKT_MAX_PRIVATE_EVENT_BYTES, MKT_MAX_PROFILES, MKT_MAX_RECEIPT_CONTENT_BYTES,
    MKT_MAX_REFERENCES, MKT_MAX_TAGS, MKT_OFFERING_KIND, MKT_OFFERING_STATUSES, MKT_ORDER_KIND,
    MKT_OUTCOMES, MKT_PROFILE_DESCRIPTOR_KIND, MKT_PROVIDER_PROFILE_KIND, MKT_PROVIDER_STATUSES,
    MKT_PUBLIC_RECEIPT_KIND, MKT_PUBLIC_RECEIPT_OUTCOMES, MKT_QUOTE_CLASSES, MKT_QUOTE_KIND,
    MKT_RESERVATION_CLASSES, MKT_RFQ_KIND, MKT_STATUS_KIND, MKT_STATUS_STATES,
    MktImmutableDecision, MktPrivateEnvelope, MktProfileSupport, MktValidatedPrivateRecord,
    MktValidationCode, MktValidationError, decide_mkt_immutable_admission, is_mkt_private_kind,
    validate_mkt_private_base, validate_mkt_private_raw, validate_mkt_private_with_profiles,
    validate_mkt_public_event,
};
pub use openagents::{
    NostrAddress, OPENAGENTS_ORGANIZATION_KIND, OPENAGENTS_PROJECT_KIND,
    OPENAGENTS_PROJECT_STATUS_KIND, OPENAGENTS_PROJECT_UPDATE_KIND, OpenAgentsOrganization,
    OpenAgentsProject, OpenAgentsProjectEvent, OpenAgentsProjectStatus, OpenAgentsProjectUpdate,
    parse_address, references_project, validate_openagents_project_event,
};
pub use replacement::{
    EventClass, ReplacementAddress, ReplacementDecision, compare_replacement,
    compare_replacement_order,
};
pub use timestamp::TimestampPolicy;
