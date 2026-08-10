//! Transport-neutral multi-relay state for NIP-MKT clients.

use std::collections::{BTreeMap, BTreeSet};

use immortal_core::domain::{
    Event, MKT_NETWORK_MAX_MERGED_EVENTS, MKT_NETWORK_MAX_RELAYS, MKT_NETWORK_MIN_RELAYS,
    MktEventIdAdmission, MktEventIdDeduplicator, MktNetworkChainError, MktRelaySet,
    validate_mkt_relay_origin,
};
use serde_json::{Value, json};

const MAX_SUBSCRIPTION_ID_BYTES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MktRelayConnectionState {
    Connecting,
    Ready,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MktRelayFrame {
    pub relay_url: String,
    pub frame: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MktRelaySetClient {
    relay_set: MktRelaySet,
    states: BTreeMap<String, MktRelayConnectionState>,
    publication_acks: BTreeMap<String, BTreeSet<String>>,
    deduplicator: MktEventIdDeduplicator,
}

impl MktRelaySetClient {
    pub fn new(relay_set: MktRelaySet) -> Result<Self, String> {
        validate_runtime_relay_set(&relay_set)?;
        let states = relay_set
            .relays
            .iter()
            .map(|relay| (relay.clone(), MktRelayConnectionState::Connecting))
            .collect();
        Ok(Self {
            relay_set,
            states,
            publication_acks: BTreeMap::new(),
            deduplicator: MktEventIdDeduplicator::default(),
        })
    }

    pub fn relay_set(&self) -> &MktRelaySet {
        &self.relay_set
    }

    pub fn relay_state(&self, relay_url: &str) -> Option<MktRelayConnectionState> {
        self.states.get(relay_url).copied()
    }

    pub fn subscription_frames(
        &self,
        subscription_id: &str,
        filters: &[Value],
    ) -> Result<Vec<MktRelayFrame>, String> {
        if subscription_id.is_empty()
            || subscription_id.len() > MAX_SUBSCRIPTION_ID_BYTES
            || subscription_id.chars().any(char::is_control)
            || filters.is_empty()
            || filters.len() > 8
            || filters.iter().any(|filter| !filter.is_object())
        {
            return Err("MKT relay subscription is outside its closed bounds".to_owned());
        }
        let mut frame = vec![
            Value::String("REQ".to_owned()),
            Value::String(subscription_id.to_owned()),
        ];
        frame.extend_from_slice(filters);
        let frame = serde_json::to_string(&frame)
            .map_err(|error| format!("could not serialize MKT subscription: {error}"))?;
        Ok(self
            .relay_set
            .relays
            .iter()
            .map(|relay_url| MktRelayFrame {
                relay_url: relay_url.clone(),
                frame: frame.clone(),
            })
            .collect())
    }

    pub fn publication_frames(&self, event: &Event) -> Result<Vec<MktRelayFrame>, String> {
        event
            .validate_structure()
            .and_then(|()| event.validate_crypto())
            .map_err(|error| format!("MKT publication event is invalid: {error}"))?;
        let frame = json!(["EVENT", event]).to_string();
        Ok(self
            .relay_set
            .relays
            .iter()
            .map(|relay_url| MktRelayFrame {
                relay_url: relay_url.clone(),
                frame: frame.clone(),
            })
            .collect())
    }

    pub fn mark_read_ready(&mut self, relay_url: &str) -> Result<bool, String> {
        self.set_state(relay_url, MktRelayConnectionState::Ready)?;
        Ok(self.read_available())
    }

    pub fn mark_unavailable(&mut self, relay_url: &str) -> Result<(), String> {
        self.set_state(relay_url, MktRelayConnectionState::Unavailable)
    }

    pub fn begin_reconnect(&mut self, relay_url: &str) -> Result<(), String> {
        self.set_state(relay_url, MktRelayConnectionState::Connecting)
    }

    pub fn read_available(&self) -> bool {
        self.states
            .values()
            .filter(|state| **state == MktRelayConnectionState::Ready)
            .count()
            >= self.relay_set.read_minimum
    }

    pub fn is_degraded(&self) -> bool {
        self.states
            .values()
            .any(|state| *state == MktRelayConnectionState::Unavailable)
    }

    pub fn record_publication_ack(
        &mut self,
        relay_url: &str,
        event_id: &str,
        accepted: bool,
    ) -> Result<bool, String> {
        self.require_relay(relay_url)?;
        if !accepted {
            return Ok(self.publication_available(event_id));
        }
        if !self.publication_acks.contains_key(event_id)
            && self.publication_acks.len() >= MKT_NETWORK_MAX_MERGED_EVENTS
        {
            return Err("MKT publication acknowledgment bound reached".to_owned());
        }
        self.publication_acks
            .entry(event_id.to_owned())
            .or_default()
            .insert(relay_url.to_owned());
        Ok(self.publication_available(event_id))
    }

    pub fn publication_available(&self, event_id: &str) -> bool {
        self.publication_acks
            .get(event_id)
            .is_some_and(|relays| relays.len() >= self.relay_set.publish_minimum)
    }

    pub fn observe_event(
        &mut self,
        relay_url: &str,
        event: &Event,
    ) -> Result<MktEventIdAdmission, MktNetworkChainError> {
        if !self.states.contains_key(relay_url) {
            return Err(MktNetworkChainError {
                code: immortal_core::domain::MktNetworkChainErrorCode::Invalid,
                detail: "event arrived from a relay outside the signed set".to_owned(),
            });
        }
        self.deduplicator.observe(event)
    }

    fn set_state(&mut self, relay_url: &str, state: MktRelayConnectionState) -> Result<(), String> {
        let current = self
            .states
            .get_mut(relay_url)
            .ok_or_else(|| "relay is outside the signed MKT set".to_owned())?;
        *current = state;
        Ok(())
    }

    fn require_relay(&self, relay_url: &str) -> Result<(), String> {
        self.states
            .contains_key(relay_url)
            .then_some(())
            .ok_or_else(|| "relay is outside the signed MKT set".to_owned())
    }
}

fn validate_runtime_relay_set(relay_set: &MktRelaySet) -> Result<(), String> {
    if !(MKT_NETWORK_MIN_RELAYS..=MKT_NETWORK_MAX_RELAYS).contains(&relay_set.relays.len())
        || relay_set.publish_minimum == 0
        || relay_set.publish_minimum > relay_set.relays.len()
        || relay_set.read_minimum == 0
        || relay_set.read_minimum > relay_set.relays.len()
    {
        return Err("MKT relay set thresholds or bounds are invalid".to_owned());
    }
    let mut prior = None;
    for relay in &relay_set.relays {
        validate_mkt_relay_origin(relay)?;
        if prior.is_some_and(|value: &str| value >= relay.as_str()) {
            return Err("MKT relay set must be distinct and byte-sorted".to_owned());
        }
        prior = Some(relay.as_str());
    }
    Ok(())
}
