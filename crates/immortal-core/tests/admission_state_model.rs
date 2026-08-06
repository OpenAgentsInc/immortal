use std::collections::{BTreeMap, BTreeSet};

use immortal_core::domain::{
    DeletionRequest, DeletionTombstone, Event, EventClass, ReplacementAddress, ReplacementDecision,
    Tag, compare_replacement,
};
use serde::Deserialize;

const FIXTURE_SCHEMA: &str = "openagents.immortal.admission-state-model.v1";

#[test]
fn bounded_admission_state_model_matches_reference() -> Result<(), String> {
    let fixture = fixture()?;
    if fixture.schema != FIXTURE_SCHEMA {
        return Err(format!(
            "unexpected fixture schema {:?}, expected {FIXTURE_SCHEMA:?}",
            fixture.schema
        ));
    }
    let actions = fixture
        .bounded_model
        .actions
        .iter()
        .map(|action| Action::parse(action))
        .collect::<Result<Vec<_>, _>>()?;
    let mut histories_checked = 0_usize;
    for length in 0..=fixture.bounded_model.maximum_sequence_length {
        exhaust_histories(
            &actions,
            length,
            &mut Vec::with_capacity(length),
            &mut |history| {
                histories_checked = histories_checked.saturating_add(1);
                check_history(history)
            },
        )?;
    }
    if histories_checked != fixture.bounded_model.histories_checked {
        return Err(format!(
            "checked {histories_checked} histories, fixture requires {}",
            fixture.bounded_model.histories_checked
        ));
    }
    Ok(())
}

#[test]
fn admission_counterexamples_remain_fixed() -> Result<(), String> {
    let fixture = fixture()?;
    for counterexample in fixture.counterexamples {
        let history = counterexample
            .history
            .iter()
            .map(|action| Action::parse(action))
            .collect::<Result<Vec<_>, _>>()?;
        let (outcomes, state) = run_implementation(&history)?;
        if outcomes != counterexample.outcomes {
            return Err(format!(
                "counterexample {:?} produced {outcomes:?}, expected {:?}",
                counterexample.name, counterexample.outcomes
            ));
        }
        let actual = state.snapshot()?;
        if actual != counterexample.final_state {
            return Err(format!(
                "counterexample {:?} ended in {actual:#?}, expected {:#?}",
                counterexample.name, counterexample.final_state
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct Fixture {
    schema: String,
    bounded_model: BoundedModel,
    counterexamples: Vec<Counterexample>,
}

#[derive(Debug, Deserialize)]
struct BoundedModel {
    actions: Vec<String>,
    maximum_sequence_length: usize,
    histories_checked: usize,
}

#[derive(Debug, Deserialize)]
struct Counterexample {
    name: String,
    history: Vec<String>,
    outcomes: Vec<String>,
    final_state: Snapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct Snapshot {
    visible_events: Vec<String>,
    replacement_heads: Vec<String>,
    tombstones: Vec<String>,
    durable_ingests: usize,
    ephemeral_deliveries: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    AdmitRegular,
    AdmitEphemeral,
    AdmitReplaceableOld,
    AdmitReplaceableNew,
    AdmitReplaceableTieLower,
    DeleteRegularOwner,
    DeleteRegularOther,
    DeleteAddressThroughOld,
    DeleteDeletionRequest,
    Restart,
}

impl Action {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "admit-regular" => Ok(Self::AdmitRegular),
            "admit-ephemeral" => Ok(Self::AdmitEphemeral),
            "admit-replaceable-old" => Ok(Self::AdmitReplaceableOld),
            "admit-replaceable-new" => Ok(Self::AdmitReplaceableNew),
            "admit-replaceable-tie-lower" => Ok(Self::AdmitReplaceableTieLower),
            "delete-regular-owner" => Ok(Self::DeleteRegularOwner),
            "delete-regular-other" => Ok(Self::DeleteRegularOther),
            "delete-address-through-old" => Ok(Self::DeleteAddressThroughOld),
            "delete-deletion-request" => Ok(Self::DeleteDeletionRequest),
            "restart" => Ok(Self::Restart),
            _ => Err(format!("unknown model action {value:?}")),
        }
    }

    fn event(self) -> Result<Option<Event>, String> {
        let alice = repeated_hex("a1", 32);
        let bob = repeated_hex("b2", 32);
        let regular_id = repeated_hex("11", 32);
        let deletion_id = repeated_hex("31", 32);
        let event = match self {
            Self::AdmitRegular => event("11", &alice, 10, 1, Vec::new()),
            Self::AdmitEphemeral => event("22", &alice, 11, 20_001, Vec::new()),
            Self::AdmitReplaceableOld => event("dd", &alice, 10, 10_000, Vec::new()),
            Self::AdmitReplaceableNew => event("bb", &alice, 20, 10_000, Vec::new()),
            Self::AdmitReplaceableTieLower => event("aa", &alice, 20, 10_000, Vec::new()),
            Self::DeleteRegularOwner => event(
                "31",
                &alice,
                12,
                5,
                vec![Tag::new(vec!["e".to_owned(), regular_id.clone()])],
            ),
            Self::DeleteRegularOther => event(
                "32",
                &bob,
                12,
                5,
                vec![Tag::new(vec!["e".to_owned(), regular_id])],
            ),
            Self::DeleteAddressThroughOld => event(
                "33",
                &alice,
                15,
                5,
                vec![Tag::new(vec!["a".to_owned(), format!("10000:{alice}:")])],
            ),
            Self::DeleteDeletionRequest => event(
                "34",
                &alice,
                16,
                5,
                vec![Tag::new(vec!["e".to_owned(), deletion_id])],
            ),
            Self::Restart => return Ok(None),
        };
        Ok(Some(event))
    }

    fn name(self) -> &'static str {
        match self {
            Self::AdmitRegular => "admit-regular",
            Self::AdmitEphemeral => "admit-ephemeral",
            Self::AdmitReplaceableOld => "admit-replaceable-old",
            Self::AdmitReplaceableNew => "admit-replaceable-new",
            Self::AdmitReplaceableTieLower => "admit-replaceable-tie-lower",
            Self::DeleteRegularOwner => "delete-regular-owner",
            Self::DeleteRegularOther => "delete-regular-other",
            Self::DeleteAddressThroughOld => "delete-address-through-old",
            Self::DeleteDeletionRequest => "delete-deletion-request",
            Self::Restart => "restart",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    Stored,
    Duplicate,
    Deleted,
    Superseded,
    Ephemeral,
    Restarted,
}

impl Outcome {
    fn name(self) -> &'static str {
        match self {
            Self::Stored => "stored",
            Self::Duplicate => "duplicate",
            Self::Deleted => "deleted",
            Self::Superseded => "superseded",
            Self::Ephemeral => "ephemeral",
            Self::Restarted => "restarted",
        }
    }
}

#[derive(Debug, Default)]
struct ImplementationState {
    events: BTreeMap<String, Event>,
    heads: BTreeMap<ReplacementAddress, String>,
    event_tombstones: BTreeMap<(String, String), DeletionTombstone>,
    address_tombstones: BTreeMap<ReplacementAddress, DeletionTombstone>,
    durable_ingests: usize,
    ephemeral_deliveries: usize,
}

impl ImplementationState {
    fn transition(&mut self, action: Action) -> Result<Outcome, String> {
        let Some(event) = action.event()? else {
            return Ok(Outcome::Restarted);
        };
        if self.events.contains_key(&event.id) {
            return Ok(Outcome::Duplicate);
        }
        if event.kind != 5 && self.is_deleted(&event) {
            return Ok(Outcome::Deleted);
        }
        let replacement = event.replacement_address();
        if let Some(address) = &replacement {
            if let Some(current_id) = self.heads.get(address) {
                let current = self.events.get(current_id).ok_or_else(|| {
                    format!("replacement head {address} points to missing event {current_id}")
                })?;
                match compare_replacement(current, &event).map_err(|error| error.to_string())? {
                    ReplacementDecision::KeepCurrent => return Ok(Outcome::Superseded),
                    ReplacementDecision::Duplicate => return Ok(Outcome::Duplicate),
                    ReplacementDecision::ReplaceCurrent => {
                        self.events.remove(current_id);
                    }
                }
            }
        }
        if event.class() == EventClass::Ephemeral {
            self.ephemeral_deliveries = self.ephemeral_deliveries.saturating_add(1);
            return Ok(Outcome::Ephemeral);
        }
        self.durable_ingests = self.durable_ingests.saturating_add(1);
        if let Some(address) = replacement {
            self.heads.insert(address, event.id.clone());
        }
        let deletion = (event.kind == 5)
            .then(|| DeletionRequest::from_event(&event).map_err(|error| error.to_string()))
            .transpose()?;
        self.events.insert(event.id.clone(), event);
        if let Some(deletion) = deletion {
            self.apply_deletion(&deletion)?;
        }
        self.check_invariants()?;
        Ok(Outcome::Stored)
    }

    fn is_deleted(&self, event: &Event) -> bool {
        self.event_tombstones
            .values()
            .chain(self.address_tombstones.values())
            .any(|tombstone| tombstone.deletes(event))
    }

    fn apply_deletion(&mut self, request: &DeletionRequest) -> Result<(), String> {
        for tombstone in request.tombstones() {
            match &tombstone {
                DeletionTombstone::Event {
                    event_id, author, ..
                } => {
                    self.event_tombstones
                        .entry((event_id.clone(), author.clone()))
                        .or_insert(tombstone);
                }
                DeletionTombstone::Address {
                    address, through, ..
                } => {
                    let replace = self
                        .address_tombstones
                        .get(address)
                        .and_then(|existing| match existing {
                            DeletionTombstone::Address { through, .. } => Some(*through),
                            DeletionTombstone::Event { .. } => None,
                        })
                        .is_none_or(|existing_through| *through > existing_through);
                    if replace {
                        self.address_tombstones.insert(address.clone(), tombstone);
                    }
                }
            }
        }
        let deleted = self
            .events
            .iter()
            .filter(|(_, event)| self.is_deleted(event))
            .map(|(event_id, _)| event_id.clone())
            .collect::<Vec<_>>();
        for event_id in deleted {
            self.events.remove(&event_id);
        }
        self.heads
            .retain(|_, event_id| self.events.contains_key(event_id));
        self.check_invariants()
    }

    fn check_invariants(&self) -> Result<(), String> {
        for event in self.events.values() {
            if event.class() == EventClass::Ephemeral {
                return Err(format!("ephemeral event {} became durable", event.id));
            }
            if event.kind != 5 && self.is_deleted(event) {
                return Err(format!("deleted event {} remains visible", event.id));
            }
        }
        for (address, event_id) in &self.heads {
            let event = self.events.get(event_id).ok_or_else(|| {
                format!("replacement head {address} points to missing event {event_id}")
            })?;
            if event.replacement_address().as_ref() != Some(address) {
                return Err(format!(
                    "replacement head {address} points to event {} at a different address",
                    event.id
                ));
            }
        }
        Ok(())
    }

    fn snapshot(&self) -> Result<Snapshot, String> {
        let mut visible_events = self
            .events
            .keys()
            .map(|event_id| event_label(event_id).map(str::to_owned))
            .collect::<Result<Vec<_>, _>>()?;
        visible_events.sort();
        let mut replacement_heads = self
            .heads
            .iter()
            .map(|(address, event_id)| {
                Ok(format!(
                    "{}:{}:{}->{}",
                    address.kind,
                    author_label(&address.pubkey)?,
                    address.identifier,
                    event_label(event_id)?
                ))
            })
            .collect::<Result<Vec<_>, String>>()?;
        replacement_heads.sort();
        let mut tombstones = self
            .event_tombstones
            .keys()
            .map(|(event_id, author)| {
                Ok(format!(
                    "event:{}:{}",
                    event_label(event_id)?,
                    author_label(author)?
                ))
            })
            .collect::<Result<Vec<_>, String>>()?;
        tombstones.extend(
            self.address_tombstones
                .values()
                .map(|tombstone| match tombstone {
                    DeletionTombstone::Address {
                        address, through, ..
                    } => Ok(format!(
                        "address:{}:{}:{}:{}",
                        address.kind,
                        author_label(&address.pubkey)?,
                        address.identifier,
                        through
                    )),
                    DeletionTombstone::Event { .. } => {
                        Err("address tombstone map contains an event tombstone".to_owned())
                    }
                })
                .collect::<Result<Vec<_>, String>>()?,
        );
        tombstones.sort();
        Ok(Snapshot {
            visible_events,
            replacement_heads,
            tombstones,
            durable_ingests: self.durable_ingests,
            ephemeral_deliveries: self.ephemeral_deliveries,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ReferenceAddress {
    kind: u16,
    pubkey: String,
    identifier: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum ReferenceTombstone {
    Event {
        event_id: String,
        author: String,
    },
    Address {
        address: ReferenceAddress,
        through: u64,
    },
}

impl ReferenceTombstone {
    fn deletes(&self, event: &Event) -> bool {
        if event.kind == 5 {
            return false;
        }
        match self {
            Self::Event { event_id, author } => event.id == *event_id && event.pubkey == *author,
            Self::Address { address, through } => {
                event.created_at <= *through && reference_address(event).as_ref() == Some(address)
            }
        }
    }
}

#[derive(Debug, Default)]
struct ReferenceState {
    events: BTreeMap<String, Event>,
    heads: BTreeMap<ReferenceAddress, String>,
    event_tombstones: BTreeSet<ReferenceTombstone>,
    address_tombstones: BTreeMap<ReferenceAddress, ReferenceTombstone>,
    durable_ingests: usize,
    ephemeral_deliveries: usize,
}

impl ReferenceState {
    fn transition(&mut self, action: Action) -> Result<Outcome, String> {
        let Some(event) = action.event()? else {
            return Ok(Outcome::Restarted);
        };
        if self.events.contains_key(&event.id) {
            return Ok(Outcome::Duplicate);
        }
        if event.kind != 5 && self.is_deleted(&event) {
            return Ok(Outcome::Deleted);
        }
        let replacement = reference_address(&event);
        if let Some(address) = &replacement {
            if let Some(current_id) = self.heads.get(address) {
                let current = self.events.get(current_id).ok_or_else(|| {
                    format!("reference head points to missing event {current_id}")
                })?;
                if event.created_at < current.created_at
                    || (event.created_at == current.created_at && event.id > current.id)
                {
                    return Ok(Outcome::Superseded);
                }
                if event.id == current.id {
                    return Ok(Outcome::Duplicate);
                }
                self.events.remove(current_id);
            }
        }
        if reference_class(event.kind) == ReferenceClass::Ephemeral {
            self.ephemeral_deliveries = self.ephemeral_deliveries.saturating_add(1);
            return Ok(Outcome::Ephemeral);
        }
        self.durable_ingests = self.durable_ingests.saturating_add(1);
        if let Some(address) = replacement {
            self.heads.insert(address, event.id.clone());
        }
        let tombstones = reference_deletion_tombstones(&event)?;
        self.events.insert(event.id.clone(), event);
        for tombstone in tombstones {
            match &tombstone {
                ReferenceTombstone::Event { .. } => {
                    self.event_tombstones.insert(tombstone);
                }
                ReferenceTombstone::Address { address, through } => {
                    let replace = self
                        .address_tombstones
                        .get(address)
                        .and_then(|existing| match existing {
                            ReferenceTombstone::Address { through, .. } => Some(*through),
                            ReferenceTombstone::Event { .. } => None,
                        })
                        .is_none_or(|existing_through| *through > existing_through);
                    if replace {
                        self.address_tombstones.insert(address.clone(), tombstone);
                    }
                }
            }
        }
        let deleted = self
            .events
            .iter()
            .filter(|(_, event)| self.is_deleted(event))
            .map(|(event_id, _)| event_id.clone())
            .collect::<Vec<_>>();
        for event_id in deleted {
            self.events.remove(&event_id);
        }
        self.heads
            .retain(|_, event_id| self.events.contains_key(event_id));
        Ok(Outcome::Stored)
    }

    fn is_deleted(&self, event: &Event) -> bool {
        self.event_tombstones
            .iter()
            .chain(self.address_tombstones.values())
            .any(|tombstone| tombstone.deletes(event))
    }

    fn snapshot(&self) -> Result<Snapshot, String> {
        let mut visible_events = self
            .events
            .keys()
            .map(|event_id| event_label(event_id).map(str::to_owned))
            .collect::<Result<Vec<_>, _>>()?;
        visible_events.sort();
        let mut replacement_heads = self
            .heads
            .iter()
            .map(|(address, event_id)| {
                Ok(format!(
                    "{}:{}:{}->{}",
                    address.kind,
                    author_label(&address.pubkey)?,
                    address.identifier,
                    event_label(event_id)?
                ))
            })
            .collect::<Result<Vec<_>, String>>()?;
        replacement_heads.sort();
        let mut tombstones = self
            .event_tombstones
            .iter()
            .map(reference_tombstone_label)
            .collect::<Result<Vec<_>, _>>()?;
        tombstones.extend(
            self.address_tombstones
                .values()
                .map(reference_tombstone_label)
                .collect::<Result<Vec<_>, _>>()?,
        );
        tombstones.sort();
        Ok(Snapshot {
            visible_events,
            replacement_heads,
            tombstones,
            durable_ingests: self.durable_ingests,
            ephemeral_deliveries: self.ephemeral_deliveries,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReferenceClass {
    Regular,
    Replaceable,
    Ephemeral,
    Addressable,
}

fn reference_class(kind: u16) -> ReferenceClass {
    match kind {
        0 | 3 | 10_000..=19_999 => ReferenceClass::Replaceable,
        20_000..=29_999 => ReferenceClass::Ephemeral,
        30_000..=39_999 => ReferenceClass::Addressable,
        _ => ReferenceClass::Regular,
    }
}

fn reference_address(event: &Event) -> Option<ReferenceAddress> {
    let identifier = match reference_class(event.kind) {
        ReferenceClass::Replaceable => String::new(),
        ReferenceClass::Addressable => event
            .tags
            .iter()
            .find(|tag| tag.name() == Some("d"))
            .and_then(Tag::value)
            .unwrap_or("")
            .to_owned(),
        ReferenceClass::Regular | ReferenceClass::Ephemeral => return None,
    };
    Some(ReferenceAddress {
        kind: event.kind,
        pubkey: event.pubkey.clone(),
        identifier,
    })
}

fn reference_deletion_tombstones(event: &Event) -> Result<Vec<ReferenceTombstone>, String> {
    if event.kind != 5 {
        return Ok(Vec::new());
    }
    let mut tombstones = BTreeSet::new();
    for tag in &event.tags {
        match (tag.name(), tag.value()) {
            (Some("e"), Some(event_id)) if is_lower_hex_32(event_id) => {
                tombstones.insert(ReferenceTombstone::Event {
                    event_id: event_id.to_owned(),
                    author: event.pubkey.clone(),
                });
            }
            (Some("a"), Some(value)) => {
                if let Some(address) = parse_reference_address(value) {
                    if address.pubkey == event.pubkey {
                        tombstones.insert(ReferenceTombstone::Address {
                            address,
                            through: event.created_at,
                        });
                    }
                }
            }
            _ => {}
        }
    }
    Ok(tombstones.into_iter().collect())
}

fn parse_reference_address(value: &str) -> Option<ReferenceAddress> {
    let mut parts = value.splitn(3, ':');
    let kind = parts.next()?.parse::<u16>().ok()?;
    let pubkey = parts.next()?;
    let identifier = parts.next()?;
    if !is_lower_hex_32(pubkey) {
        return None;
    }
    match reference_class(kind) {
        ReferenceClass::Replaceable if identifier.is_empty() => {}
        ReferenceClass::Addressable => {}
        ReferenceClass::Regular | ReferenceClass::Ephemeral | ReferenceClass::Replaceable => {
            return None;
        }
    }
    Some(ReferenceAddress {
        kind,
        pubkey: pubkey.to_owned(),
        identifier: identifier.to_owned(),
    })
}

fn is_lower_hex_32(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn reference_tombstone_label(tombstone: &ReferenceTombstone) -> Result<String, String> {
    match tombstone {
        ReferenceTombstone::Event { event_id, author } => Ok(format!(
            "event:{}:{}",
            event_label(event_id)?,
            author_label(author)?
        )),
        ReferenceTombstone::Address { address, through } => Ok(format!(
            "address:{}:{}:{}:{}",
            address.kind,
            author_label(&address.pubkey)?,
            address.identifier,
            through
        )),
    }
}

fn check_history(history: &[Action]) -> Result<(), String> {
    let mut implementation = ImplementationState::default();
    let mut reference = ReferenceState::default();
    let mut prefix = Vec::with_capacity(history.len());
    for action in history {
        prefix.push(action.name());
        let implementation_outcome = implementation.transition(*action)?;
        let reference_outcome = reference.transition(*action)?;
        if implementation_outcome != reference_outcome {
            return Err(format!(
                "history {prefix:?}: implementation outcome {implementation_outcome:?} differs from reference {reference_outcome:?}"
            ));
        }
        let implementation_snapshot = implementation.snapshot()?;
        let reference_snapshot = reference.snapshot()?;
        if implementation_snapshot != reference_snapshot {
            return Err(format!(
                "history {prefix:?}: implementation state {implementation_snapshot:#?} differs from reference {reference_snapshot:#?}"
            ));
        }
    }
    Ok(())
}

fn run_implementation(history: &[Action]) -> Result<(Vec<String>, ImplementationState), String> {
    let mut state = ImplementationState::default();
    let outcomes = history
        .iter()
        .map(|action| {
            state
                .transition(*action)
                .map(|outcome| outcome.name().to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok((outcomes, state))
}

fn exhaust_histories(
    actions: &[Action],
    remaining: usize,
    history: &mut Vec<Action>,
    check: &mut impl FnMut(&[Action]) -> Result<(), String>,
) -> Result<(), String> {
    if remaining == 0 {
        return check(history);
    }
    for action in actions {
        history.push(*action);
        exhaust_histories(actions, remaining - 1, history, check)?;
        history.pop();
    }
    Ok(())
}

fn event(id_byte: &str, pubkey: &str, created_at: u64, kind: u16, tags: Vec<Tag>) -> Event {
    Event {
        id: repeated_hex(id_byte, 32),
        pubkey: pubkey.to_owned(),
        created_at,
        kind,
        tags,
        content: String::new(),
        sig: repeated_hex("00", 64),
    }
}

fn repeated_hex(byte: &str, count: usize) -> String {
    byte.repeat(count)
}

fn event_label(event_id: &str) -> Result<&'static str, String> {
    let label = if event_id == repeated_hex("11", 32) {
        "regular"
    } else if event_id == repeated_hex("22", 32) {
        "ephemeral"
    } else if event_id == repeated_hex("dd", 32) {
        "replaceable-old"
    } else if event_id == repeated_hex("bb", 32) {
        "replaceable-new"
    } else if event_id == repeated_hex("aa", 32) {
        "replaceable-tie-lower"
    } else if event_id == repeated_hex("31", 32) {
        "delete-regular-owner"
    } else if event_id == repeated_hex("32", 32) {
        "delete-regular-other"
    } else if event_id == repeated_hex("33", 32) {
        "delete-address-through-old"
    } else if event_id == repeated_hex("34", 32) {
        "delete-deletion-request"
    } else {
        return Err(format!("unknown model event id {event_id}"));
    };
    Ok(label)
}

fn author_label(pubkey: &str) -> Result<&'static str, String> {
    if pubkey == repeated_hex("a1", 32) {
        Ok("alice")
    } else if pubkey == repeated_hex("b2", 32) {
        Ok("bob")
    } else {
        Err(format!("unknown model author {pubkey}"))
    }
}

fn fixture() -> Result<Fixture, String> {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/nip01/admission-state-model.json"
    ))
    .map_err(|error| format!("invalid admission model fixture: {error}"))
}
