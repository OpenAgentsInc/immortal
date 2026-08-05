//! Blocking relay transport and recovery for provider modes.

use std::{
    collections::BTreeMap,
    fs::File,
    io::{ErrorKind, Read},
    net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use immortal_client::mkt_swp_client::{MktSigningRequest, SwapClientConfig};
use immortal_core::{
    domain::{
        Event, MKT_CANCEL_KIND, MKT_CLOSE_KIND, MKT_ORDER_KIND, MKT_QUOTE_KIND, MKT_RFQ_KIND,
        MKT_STATUS_KIND, MKT_SWP_PROFILE_ID, MKT_SWP_PROFILE_VERSION, MKT_SWP_SWAP_CONTRACT_KIND,
        MktProfileSupport,
    },
    market::{MarketSigner, WrapMaterial, unwrap_mkt_record, wrap_mkt_record},
};
use serde_json::{Value, json};
use tokio_tungstenite::tungstenite::{
    Error as WebSocketError, Message, WebSocket, client::client_with_config,
    protocol::WebSocketConfig,
};

use crate::{ProviderDiscoveryFactory, ProviderSession};

const SUBSCRIPTION_ID: &str = "immortal-provider-inbox";
const MAX_RELAY_URL_BYTES: usize = 2_048;
pub(crate) const MAX_RELAY_MESSAGE_BYTES: usize = 512 * 1024;
pub(crate) const MAX_HISTORY_WRAPS: usize = 120;
pub(crate) const MAX_SESSIONS: usize = 12;
pub(crate) const MAX_SESSIONS_PER_REQUESTER: usize = 4;
const MAX_DURABLE_RECOVERY_RECORDS: usize = MAX_SESSIONS * 512;
pub(crate) const MAX_RECONNECT_ATTEMPTS: usize = 8;
pub(crate) const MAX_ACTIONS_PER_ADVANCE: usize = 16;
const IO_TIMEOUT: Duration = Duration::from_secs(5);

type RelaySocket = WebSocket<TcpStream>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecordOrigin {
    Recovery,
    Live,
    Authored,
}

pub(crate) struct DurableRecovery {
    pub records: Vec<Event>,
    pub has_prior_records: bool,
}

pub(crate) trait ProviderMode {
    fn mode_name(&self) -> &'static str;
    fn provider_id(&self) -> &str;
    fn offering_id(&self) -> &str;
    fn discovery_metadata(&self) -> Value;
    fn offering(&self) -> Value;

    fn tick(&mut self) -> Result<(), String> {
        Ok(())
    }

    fn durable_recovery(&mut self, _limit: usize) -> Result<DurableRecovery, String> {
        Ok(DurableRecovery {
            records: Vec::new(),
            has_prior_records: false,
        })
    }

    fn prepare_recovered_record(
        &mut self,
        _session: &mut ProviderSession,
        _record: &Event,
    ) -> Result<(), String> {
        Ok(())
    }

    fn dispose_stalled_session(
        &mut self,
        _session: &ProviderSession,
        _requester_pubkey: &str,
        _observed_at: u64,
    ) -> Result<Option<&'static str>, String> {
        Ok(None)
    }

    fn reject_session(
        &mut self,
        _session: &ProviderSession,
        _requester_pubkey: &str,
        _observed_at: u64,
    ) -> Result<(), String> {
        Ok(())
    }

    fn construct_quote(
        &mut self,
        session: &mut ProviderSession,
        requester_pubkey: &str,
        created_at: u64,
    ) -> Result<Option<MktSigningRequest>, String>;

    fn observe_durable_signed_record(
        &mut self,
        session_id: &str,
        record: &Event,
        origin: RecordOrigin,
        provider_authored: bool,
    ) -> Result<(), String>;

    fn observe_durable_signed_session_record(
        &mut self,
        session: &ProviderSession,
        record: &Event,
        origin: RecordOrigin,
        provider_authored: bool,
    ) -> Result<(), String> {
        self.observe_durable_signed_record(
            &session.config().session_id,
            record,
            origin,
            provider_authored,
        )
    }

    fn next_after_contract_or_status(
        &mut self,
        session: &mut ProviderSession,
        requester_pubkey: &str,
        created_at: u64,
    ) -> Result<Option<MktSigningRequest>, String>;
}

struct RelayClient {
    websocket: RelaySocket,
    challenge: String,
}

struct RelayHistory {
    wraps: Vec<Event>,
    truncated: bool,
}

struct SessionActor {
    session: ProviderSession,
    requester_pubkey: String,
}

enum SessionAdvance {
    Action(Option<MktSigningRequest>),
    Removed,
}

struct RelayActor<M> {
    relay_url: String,
    signer: MarketSigner,
    offering_address: String,
    sessions: BTreeMap<String, SessionActor>,
    mode: M,
}

pub(crate) fn run_with_mode<M: ProviderMode>(
    relay_url: String,
    signer: MarketSigner,
    mode: M,
) -> Result<(), String> {
    let offering_address = format!("39601:{}:{}", signer.pubkey(), mode.offering_id());
    let mut actor = RelayActor {
        relay_url,
        signer,
        offering_address,
        sessions: BTreeMap::new(),
        mode,
    };
    actor.run_persistent()
}

pub(crate) fn validate_relay_url(relay_url: &str, mode_name: &str) -> Result<(), String> {
    loopback_addresses(relay_url, mode_name).map(|_| ())
}

impl<M: ProviderMode> RelayActor<M> {
    fn run_persistent(&mut self) -> Result<(), String> {
        let mut failures = 0_usize;
        loop {
            match self.run_connection() {
                Ok(()) => return Ok(()),
                Err(error) => {
                    failures = failures.saturating_add(1);
                    if failures > MAX_RECONNECT_ATTEMPTS {
                        return Err(format!(
                            "{} provider exhausted {MAX_RECONNECT_ATTEMPTS} relay reconnects: {error}",
                            self.mode.mode_name()
                        ));
                    }
                    let exponent = u32::try_from(failures.saturating_sub(1).min(5))
                        .map_err(|_| "relay reconnect counter overflowed".to_owned())?;
                    let delay = Duration::from_secs(1_u64 << exponent);
                    eprintln!(
                        "immortal-provider: relay connection failed ({error}); retrying in {}s ({failures}/{MAX_RECONNECT_ATTEMPTS})",
                        delay.as_secs()
                    );
                    thread::sleep(delay);
                }
            }
        }
    }

    fn run_connection(&mut self) -> Result<(), String> {
        let now = unix_now()?;
        let mut reader = connect(&self.relay_url, self.mode.mode_name())?;
        authenticate(&mut reader, &self.signer, &self.relay_url, now)?;
        let mut publisher = connect(&self.relay_url, self.mode.mode_name())?;
        authenticate(&mut publisher, &self.signer, &self.relay_url, now)?;
        self.publish_discovery(&mut publisher, now)?;
        subscribe(&mut reader, self.signer.pubkey())?;

        let history = read_history(&mut reader)?;
        self.rebuild(history)?;
        self.republish_provider_history(&mut publisher)?;
        self.advance_all(&mut publisher)?;
        println!(
            "immortal-provider: {} ready relay={} pubkey={} recovered_sessions={}",
            self.mode.mode_name(),
            self.relay_url,
            self.signer.pubkey(),
            self.sessions.len()
        );

        loop {
            match read_json(&mut reader.websocket) {
                Ok(message) => {
                    if let Some(wrap) = subscription_event(&message)? {
                        self.receive_wrap(wrap, &mut publisher)?;
                    }
                }
                Err(ReadError::Idle) => {
                    self.mode.tick()?;
                    self.advance_all(&mut publisher)?;
                    reader
                        .websocket
                        .send(Message::Ping(Vec::new().into()))
                        .map_err(|error| format!("could not send relay heartbeat: {error}"))?;
                }
                Err(ReadError::Closed(error)) => return Err(error),
            }
        }
    }

    fn publish_discovery(
        &self,
        publisher: &mut RelayClient,
        created_at: u64,
    ) -> Result<(), String> {
        let discovery = ProviderDiscoveryFactory::new(self.signer.pubkey())
            .map_err(|error| format!("could not initialize provider discovery: {error}"))?;
        let profile_request = discovery
            .profile(
                created_at,
                self.mode.provider_id(),
                "active",
                self.mode.discovery_metadata(),
            )
            .map_err(|error| format!("could not create provider profile: {error}"))?;
        let profile = self.sign_public(profile_request)?;
        publish(publisher, &profile)?;

        let offering_request = discovery
            .offering(
                created_at,
                self.mode.provider_id(),
                self.mode.offering_id(),
                "active",
                self.mode.offering(),
            )
            .map_err(|error| {
                format!(
                    "could not create {} Offering: {error}",
                    self.mode.mode_name()
                )
            })?;
        let offering = self.sign_public(offering_request)?;
        publish(publisher, &offering)
    }

    fn sign_public(&self, request: crate::MktPublicSigningRequest) -> Result<Event, String> {
        let event = self.signer.sign(
            request.created_at,
            request.kind,
            request.tags.clone(),
            request.content.clone(),
        );
        request
            .verify_signed(event)
            .map_err(|error| format!("provider discovery signature failed: {error}"))
    }

    fn rebuild(&mut self, history: RelayHistory) -> Result<(), String> {
        let durable = self.mode.durable_recovery(MAX_DURABLE_RECOVERY_RECORDS)?;
        if durable.records.len() > MAX_DURABLE_RECOVERY_RECORDS {
            return Err(format!(
                "durable recovery exceeded record bound {MAX_DURABLE_RECOVERY_RECORDS}"
            ));
        }
        if !durable.has_prior_records && !durable.records.is_empty() {
            return Err("durable recovery records lack prior-history proof".to_owned());
        }
        if history.truncated && !durable.has_prior_records {
            return Err(format!(
                "relay history exceeded provider bound {MAX_HISTORY_WRAPS} without durable prior history"
            ));
        }

        let mut records = BTreeMap::new();
        for record in durable.records {
            insert_recovery_record(&mut records, record)?;
        }
        for wrap in history.wraps {
            let delivered = match unwrap_mkt_record(&wrap, &self.signer, &swp_profiles()) {
                Ok(delivered) => delivered,
                Err(error) => {
                    eprintln!(
                        "immortal-provider: ignoring unreadable historical wrap {}: {error}",
                        wrap.id
                    );
                    continue;
                }
            };
            insert_recovery_record(&mut records, delivered.record.event)?;
        }

        let mut sessions = BTreeMap::<String, Vec<Event>>::new();
        for record in records.into_values() {
            let provider_authored = record.pubkey == self.signer.pubkey();
            let session_id = match session_id(&record) {
                Ok(session_id) => session_id.to_owned(),
                Err(error) if provider_authored => {
                    return Err(format!(
                        "provider-authored recovery history is incomplete or invalid: {error}"
                    ));
                }
                Err(error) => {
                    eprintln!(
                        "immortal-provider: isolating invalid requester recovery record: {error}"
                    );
                    continue;
                }
            };
            sessions.entry(session_id).or_default().push(record);
        }

        self.sessions.clear();
        for (session_id, mut records) in sessions {
            records.sort_by(|left, right| {
                recovery_rank(left, self.signer.pubkey())
                    .cmp(&recovery_rank(right, self.signer.pubkey()))
                    .then_with(|| left.created_at.cmp(&right.created_at))
                    .then_with(|| left.id.cmp(&right.id))
            });
            let Some(actor) = self.recover_session_group(&session_id, records)? else {
                continue;
            };
            if self.sessions.len() >= MAX_SESSIONS {
                return Err(format!(
                    "provider active session bound {MAX_SESSIONS} reached during recovery"
                ));
            }
            if self
                .sessions
                .values()
                .filter(|current| current.requester_pubkey == actor.requester_pubkey)
                .count()
                >= MAX_SESSIONS_PER_REQUESTER
            {
                return Err(format!(
                    "provider requester session bound {MAX_SESSIONS_PER_REQUESTER} reached during recovery"
                ));
            }
            self.sessions.insert(session_id, actor);
        }
        Ok(())
    }

    fn recover_session_group(
        &mut self,
        session_id: &str,
        records: Vec<Event>,
    ) -> Result<Option<SessionActor>, String> {
        let provider_pubkey = self.signer.pubkey().to_owned();
        let mut actor = None::<SessionActor>;
        let mut closed = false;
        for record in records {
            let provider_authored = record.pubkey == provider_pubkey;
            let mut created_actor = false;
            if actor.is_none() {
                if record.kind != MKT_RFQ_KIND {
                    if provider_authored {
                        return Err(format!(
                            "provider-authored recovery history is incomplete or invalid: session {session_id} has no recoverable RFQ before kind {}",
                            record.kind
                        ));
                    }
                    eprintln!(
                        "immortal-provider: isolating requester recovery record for session {session_id} without an RFQ"
                    );
                    continue;
                }
                let offering_address = match offering_reference(&record) {
                    Ok(offering_address) => offering_address,
                    Err(error) if provider_authored => {
                        return Err(format!(
                            "provider-authored recovery history is incomplete or invalid: {error}"
                        ));
                    }
                    Err(error) => {
                        eprintln!(
                            "immortal-provider: isolating invalid requester recovery record: {error}"
                        );
                        continue;
                    }
                };
                if offering_address != self.offering_address {
                    eprintln!(
                        "immortal-provider: isolating requester recovery RFQ for another provider Offering"
                    );
                    continue;
                }
                let config = SwapClientConfig {
                    session_id: session_id.to_owned(),
                    requester_pubkey: record.pubkey.clone(),
                    provider_pubkey: provider_pubkey.clone(),
                    offering_address,
                };
                let session = ProviderSession::new(config).map_err(|error| {
                    format!("could not initialize session {session_id}: {error}")
                })?;
                actor = Some(SessionActor {
                    session,
                    requester_pubkey: record.pubkey.clone(),
                });
                created_actor = true;
            }
            let session_actor = actor
                .as_mut()
                .ok_or_else(|| "provider recovery session disappeared".to_owned())?;
            self.mode
                .prepare_recovered_record(&mut session_actor.session, &record)
                .map_err(|error| {
                    format!(
                        "provider could not restore session {session_id} before kind {}: {error}",
                        record.kind
                    )
                })?;
            let ingest = session_actor.session.ingest_signed(record.clone());
            if let Err(error) = ingest {
                if provider_authored {
                    return Err(format!(
                        "provider-authored recovery history is incomplete or invalid: session {session_id} rejected signed history: {error}"
                    ));
                }
                eprintln!(
                    "immortal-provider: isolating invalid requester recovery record: session {session_id} rejected signed history: {error}"
                );
                if created_actor {
                    actor = None;
                }
                continue;
            }
            self.observe_record(session_id, &record, RecordOrigin::Recovery)?;
            closed |= provider_authored_close(&record, &provider_pubkey);
        }
        if closed {
            return Ok(None);
        }
        let Some(actor) = actor else {
            return Ok(None);
        };
        let observed_at = unix_now()?;
        if let Some(reason) = self.mode.dispose_stalled_session(
            &actor.session,
            &actor.requester_pubkey,
            observed_at,
        )? {
            eprintln!(
                "immortal-provider: disposed recovered {} session {session_id}: {reason}",
                self.mode.mode_name()
            );
            return Ok(None);
        }
        Ok(Some(actor))
    }

    fn receive_wrap(&mut self, wrap: Event, publisher: &mut RelayClient) -> Result<(), String> {
        let delivered = match unwrap_mkt_record(&wrap, &self.signer, &swp_profiles()) {
            Ok(delivered) => delivered,
            Err(error) => {
                eprintln!(
                    "immortal-provider: ignoring unreadable live wrap {}: {error}",
                    wrap.id
                );
                return Ok(());
            }
        };
        let record = delivered.record.event;
        let session_id = session_id(&record)?.to_owned();
        let provider_authored = record.pubkey == self.signer.pubkey();
        if provider_authored && !self.sessions.contains_key(&session_id) {
            eprintln!(
                "immortal-provider: ignoring delayed provider echo for inactive session {session_id}"
            );
            self.observe_record(&session_id, &record, RecordOrigin::Live)?;
            return Ok(());
        }
        if let Err(error) = self.ingest_record(record.clone()) {
            if provider_authored {
                return Err(format!(
                    "provider-authored live recovery record is invalid: {error}"
                ));
            }
            eprintln!("immortal-provider: rejecting session {session_id} record: {error}");
            return Ok(());
        }
        self.observe_record(&session_id, &record, RecordOrigin::Live)?;
        if provider_authored_close(&record, self.signer.pubkey()) {
            self.sessions.remove(&session_id);
            return Ok(());
        }
        self.advance_session(&session_id, publisher)
    }

    fn ingest_record(&mut self, record: Event) -> Result<String, String> {
        let session_id = session_id(&record)?.to_owned();
        let mut inserted_session = false;
        if !self.sessions.contains_key(&session_id) {
            if record.kind != MKT_RFQ_KIND {
                return Err(format!(
                    "session {session_id} has no recoverable RFQ before kind {}",
                    record.kind
                ));
            }
            self.prune_stalled_sessions(unix_now()?)?;
            if self.sessions.len() >= MAX_SESSIONS {
                return Err(format!("provider session bound {MAX_SESSIONS} reached"));
            }
            if self
                .sessions
                .values()
                .filter(|current| current.requester_pubkey == record.pubkey)
                .count()
                >= MAX_SESSIONS_PER_REQUESTER
            {
                return Err(format!(
                    "provider requester session bound {MAX_SESSIONS_PER_REQUESTER} reached"
                ));
            }
            let offering_address = offering_reference(&record)?;
            if offering_address != self.offering_address {
                return Err("RFQ references another provider Offering".to_owned());
            }
            let config = SwapClientConfig {
                session_id: session_id.clone(),
                requester_pubkey: record.pubkey.clone(),
                provider_pubkey: self.signer.pubkey().to_owned(),
                offering_address,
            };
            let session = ProviderSession::new(config)
                .map_err(|error| format!("could not initialize session {session_id}: {error}"))?;
            self.sessions.insert(
                session_id.clone(),
                SessionActor {
                    session,
                    requester_pubkey: record.pubkey.clone(),
                },
            );
            inserted_session = true;
        }
        let result = self
            .sessions
            .get_mut(&session_id)
            .ok_or_else(|| "provider session disappeared".to_owned())?
            .session
            .ingest_signed(record)
            .map(|_| session_id.clone())
            .map_err(|error| format!("session {session_id} rejected signed history: {error}"));
        if result.is_err() && inserted_session {
            self.sessions.remove(&session_id);
        }
        result
    }

    fn observe_record(
        &mut self,
        session_id: &str,
        record: &Event,
        origin: RecordOrigin,
    ) -> Result<(), String> {
        let provider_authored = record.pubkey == self.signer.pubkey();
        let observed = match self.sessions.get(session_id) {
            Some(actor) => self.mode.observe_durable_signed_session_record(
                &actor.session,
                record,
                origin,
                provider_authored,
            ),
            None => self.mode.observe_durable_signed_record(
                session_id,
                record,
                origin,
                provider_authored,
            ),
        };
        observed.map_err(|error| {
            format!("provider could not durably observe session {session_id} record: {error}")
        })
    }

    fn republish_provider_history(&self, publisher: &mut RelayClient) -> Result<(), String> {
        for actor in self.sessions.values() {
            for record in actor
                .session
                .signed_records()
                .iter()
                .filter(|record| record.pubkey == self.signer.pubkey())
            {
                self.publish_to_counterparty(record, &actor.requester_pubkey, publisher)?;
            }
        }
        Ok(())
    }

    fn advance_all(&mut self, publisher: &mut RelayClient) -> Result<(), String> {
        self.prune_stalled_sessions(unix_now()?)?;
        let sessions = self.sessions.keys().cloned().collect::<Vec<_>>();
        for session_id in sessions {
            self.advance_session(&session_id, publisher)?;
        }
        Ok(())
    }

    fn advance_session(
        &mut self,
        session_id: &str,
        publisher: &mut RelayClient,
    ) -> Result<(), String> {
        for _ in 0..MAX_ACTIONS_PER_ADVANCE {
            let observed_at = unix_now()?;
            let action = match self.prepare_session_advance(session_id, observed_at)? {
                SessionAdvance::Action(action) => action,
                SessionAdvance::Removed => return Ok(()),
            };
            let Some(request) = action else {
                return Ok(());
            };
            let event = self.sign_private(request)?;
            let terminal = event.kind == MKT_CLOSE_KIND;
            let requester = self
                .sessions
                .get(session_id)
                .ok_or_else(|| "provider session disappeared before publication".to_owned())?
                .requester_pubkey
                .clone();
            self.sessions
                .get_mut(session_id)
                .ok_or_else(|| "provider session disappeared before ingestion".to_owned())?
                .session
                .ingest_signed(event.clone())
                .map_err(|error| format!("provider response failed local validation: {error}"))?;
            self.observe_record(session_id, &event, RecordOrigin::Authored)?;
            self.publish_record(&event, &requester, publisher)?;
            if terminal {
                self.sessions.remove(session_id);
                return Ok(());
            }
        }
        Err(format!(
            "provider session {session_id} exceeded the per-tick action bound {MAX_ACTIONS_PER_ADVANCE}"
        ))
    }

    fn prepare_session_advance(
        &mut self,
        session_id: &str,
        observed_at: u64,
    ) -> Result<SessionAdvance, String> {
        let disposition = {
            let actor = self
                .sessions
                .get(session_id)
                .ok_or_else(|| format!("unknown provider session {session_id}"))?;
            self.mode.dispose_stalled_session(
                &actor.session,
                &actor.requester_pubkey,
                observed_at,
            )?
        };
        if let Some(reason) = disposition {
            eprintln!(
                "immortal-provider: disposed stalled {} session {session_id}: {reason}",
                self.mode.mode_name()
            );
            self.sessions.remove(session_id);
            return Ok(SessionAdvance::Removed);
        }

        let (action, rejection) = {
            let actor = self
                .sessions
                .get_mut(session_id)
                .ok_or_else(|| format!("unknown provider session {session_id}"))?;
            let awaiting_quote = !has_kind_by_author(
                actor.session.signed_records(),
                MKT_QUOTE_KIND,
                &actor.session.config().provider_pubkey,
            );
            let created_at = next_created_at(&actor.session)?;
            let action = if awaiting_quote {
                self.mode
                    .construct_quote(&mut actor.session, &actor.requester_pubkey, created_at)
            } else {
                self.mode.next_after_contract_or_status(
                    &mut actor.session,
                    &actor.requester_pubkey,
                    created_at,
                )
            };
            match action {
                Ok(action) => (action, None),
                Err(error) if awaiting_quote => {
                    let reason = bounded_rejection_reason(&error);
                    self.mode.reject_session(
                        &actor.session,
                        &actor.requester_pubkey,
                        observed_at,
                    )?;
                    (None, Some(reason))
                }
                Err(error) => return Err(error),
            }
        };
        if let Some(reason) = rejection {
            eprintln!(
                "immortal-provider: rejecting incompatible {} session {session_id}: {reason}",
                self.mode.mode_name()
            );
            self.sessions.remove(session_id);
            return Ok(SessionAdvance::Removed);
        }
        Ok(SessionAdvance::Action(action))
    }

    fn prune_stalled_sessions(&mut self, observed_at: u64) -> Result<(), String> {
        let session_ids = self.sessions.keys().cloned().collect::<Vec<_>>();
        for session_id in session_ids {
            let disposition = {
                let actor = self
                    .sessions
                    .get(&session_id)
                    .ok_or_else(|| "provider session disappeared during pruning".to_owned())?;
                self.mode.dispose_stalled_session(
                    &actor.session,
                    &actor.requester_pubkey,
                    observed_at,
                )?
            };
            if let Some(reason) = disposition {
                eprintln!(
                    "immortal-provider: disposed stalled {} session {session_id}: {reason}",
                    self.mode.mode_name()
                );
                self.sessions.remove(&session_id);
            }
        }
        Ok(())
    }

    fn sign_private(&self, request: MktSigningRequest) -> Result<Event, String> {
        let event = self.signer.sign(
            request.created_at,
            request.kind,
            request.tags.clone(),
            request.content.clone(),
        );
        request
            .verify_signed(event)
            .map_err(|error| format!("provider private signature failed: {error}"))
    }

    fn publish_record(
        &self,
        record: &Event,
        requester_pubkey: &str,
        publisher: &mut RelayClient,
    ) -> Result<(), String> {
        let raw = serde_json::to_vec(record)
            .map_err(|error| format!("could not serialize provider record: {error}"))?;
        let recovery = wrap_mkt_record(
            &raw,
            &self.signer,
            self.signer.pubkey(),
            random_wrap_material()?,
        )?;
        publish(publisher, &recovery.event)?;
        self.publish_to_counterparty(record, requester_pubkey, publisher)
    }

    fn publish_to_counterparty(
        &self,
        record: &Event,
        requester_pubkey: &str,
        publisher: &mut RelayClient,
    ) -> Result<(), String> {
        let raw = serde_json::to_vec(record)
            .map_err(|error| format!("could not serialize provider record: {error}"))?;
        let delivery = wrap_mkt_record(
            &raw,
            &self.signer,
            requester_pubkey,
            random_wrap_material()?,
        )?;
        publish(publisher, &delivery.event)
    }
}

fn next_created_at(session: &ProviderSession) -> Result<u64, String> {
    let newest = session
        .signed_records()
        .iter()
        .map(|record| record.created_at)
        .max()
        .unwrap_or(unix_now()?);
    Ok(unix_now()?.max(newest.saturating_add(1)))
}

fn connect(relay_url: &str, mode_name: &str) -> Result<RelayClient, String> {
    let addresses = loopback_addresses(relay_url, mode_name)?;
    let mut last_error = None;
    for address in addresses {
        match TcpStream::connect_timeout(&address, IO_TIMEOUT) {
            Ok(stream) => {
                stream
                    .set_read_timeout(Some(IO_TIMEOUT))
                    .map_err(|error| format!("could not set relay read timeout: {error}"))?;
                stream
                    .set_write_timeout(Some(IO_TIMEOUT))
                    .map_err(|error| format!("could not set relay write timeout: {error}"))?;
                let config = WebSocketConfig::default()
                    .read_buffer_size(16 * 1024)
                    .write_buffer_size(0)
                    .max_write_buffer_size(MAX_RELAY_MESSAGE_BYTES)
                    .max_message_size(Some(MAX_RELAY_MESSAGE_BYTES))
                    .max_frame_size(Some(MAX_RELAY_MESSAGE_BYTES));
                let (mut websocket, _) = client_with_config(relay_url, stream, Some(config))
                    .map_err(|error| format!("could not open relay WebSocket: {error}"))?;
                let challenge_message = read_json(&mut websocket).map_err(read_error_string)?;
                let challenge = challenge_message
                    .as_array()
                    .filter(|message| message.first() == Some(&Value::String("AUTH".into())))
                    .and_then(|message| message.get(1))
                    .and_then(Value::as_str)
                    .filter(|challenge| !challenge.is_empty() && challenge.len() <= 512)
                    .ok_or_else(|| "relay did not send a bounded NIP-42 challenge".to_owned())?
                    .to_owned();
                return Ok(RelayClient {
                    websocket,
                    challenge,
                });
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(format!(
        "could not connect to loopback relay: {}",
        last_error.map_or_else(
            || "no resolved address".to_owned(),
            |error| error.to_string()
        )
    ))
}

fn authenticate(
    client: &mut RelayClient,
    signer: &MarketSigner,
    relay_url: &str,
    now: u64,
) -> Result<(), String> {
    let event = signer.sign(
        now,
        22_242,
        vec![
            immortal_core::domain::Tag::new(vec!["relay".into(), relay_url.into()]),
            immortal_core::domain::Tag::new(vec!["challenge".into(), client.challenge.clone()]),
        ],
        String::new(),
    );
    send_json(&mut client.websocket, json!(["AUTH", event]))?;
    expect_ok(&mut client.websocket, &event.id)
}

fn subscribe(client: &mut RelayClient, recipient: &str) -> Result<(), String> {
    send_json(
        &mut client.websocket,
        json!(["REQ", SUBSCRIPTION_ID, {"kinds":[1059],"#p":[recipient],"limit":MAX_HISTORY_WRAPS + 1}]),
    )
}

fn read_history(client: &mut RelayClient) -> Result<RelayHistory, String> {
    let mut wraps = Vec::new();
    let mut received = 0_usize;
    let mut truncated = false;
    loop {
        let message = read_json(&mut client.websocket).map_err(read_error_string)?;
        if message == json!(["EOSE", SUBSCRIPTION_ID]) {
            return Ok(RelayHistory { wraps, truncated });
        }
        let wrap = subscription_event(&message)?
            .ok_or_else(|| format!("unexpected history response: {message}"))?;
        received = received.saturating_add(1);
        if received > MAX_HISTORY_WRAPS + 1 {
            return Err(format!(
                "relay exceeded requested provider history bound {}",
                MAX_HISTORY_WRAPS + 1
            ));
        }
        if wraps.len() < MAX_HISTORY_WRAPS {
            wraps.push(wrap);
        } else {
            truncated = true;
        }
    }
}

fn subscription_event(message: &Value) -> Result<Option<Event>, String> {
    let Some(fields) = message.as_array() else {
        return Err(format!("relay message is not an array: {message}"));
    };
    if fields.first().and_then(Value::as_str) != Some("EVENT") {
        return Ok(None);
    }
    if fields.get(1).and_then(Value::as_str) != Some(SUBSCRIPTION_ID) {
        return Err("relay delivered an event for another subscription".to_owned());
    }
    let event: Event = serde_json::from_value(fields.get(2).cloned().unwrap_or(Value::Null))
        .map_err(|error| format!("relay subscription payload is not an event: {error}"))?;
    Ok(Some(event))
}

fn publish(client: &mut RelayClient, event: &Event) -> Result<(), String> {
    send_json(&mut client.websocket, json!(["EVENT", event]))?;
    expect_ok(&mut client.websocket, &event.id)
}

fn expect_ok(websocket: &mut RelaySocket, event_id: &str) -> Result<(), String> {
    let response = read_json(websocket).map_err(read_error_string)?;
    let fields = response
        .as_array()
        .ok_or_else(|| format!("relay response is not an array: {response}"))?;
    if fields.first().and_then(Value::as_str) == Some("OK")
        && fields.get(1).and_then(Value::as_str) == Some(event_id)
        && fields.get(2).and_then(Value::as_bool) == Some(true)
    {
        Ok(())
    } else {
        Err(format!("relay rejected event {event_id}: {response}"))
    }
}

fn send_json(websocket: &mut RelaySocket, value: Value) -> Result<(), String> {
    let text = value.to_string();
    if text.len() > MAX_RELAY_MESSAGE_BYTES {
        return Err("outbound relay message exceeds its byte bound".to_owned());
    }
    websocket
        .send(Message::text(text))
        .map_err(|error| format!("could not write relay message: {error}"))
}

enum ReadError {
    Idle,
    Closed(String),
}

fn read_json(websocket: &mut RelaySocket) -> Result<Value, ReadError> {
    loop {
        match websocket.read() {
            Ok(Message::Text(text)) => {
                if text.len() > MAX_RELAY_MESSAGE_BYTES {
                    return Err(ReadError::Closed(
                        "relay text message exceeds its byte bound".to_owned(),
                    ));
                }
                return serde_json::from_str(text.as_str()).map_err(|error| {
                    ReadError::Closed(format!("relay message is invalid JSON: {error}"))
                });
            }
            Ok(Message::Ping(payload)) => {
                websocket.send(Message::Pong(payload)).map_err(|error| {
                    ReadError::Closed(format!("could not answer relay ping: {error}"))
                })?
            }
            Ok(Message::Pong(_)) => {}
            Ok(Message::Close(_)) => {
                return Err(ReadError::Closed("relay closed the WebSocket".to_owned()));
            }
            Ok(message) => {
                return Err(ReadError::Closed(format!(
                    "unexpected relay frame: {message:?}"
                )));
            }
            Err(WebSocketError::Io(error))
                if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
            {
                return Err(ReadError::Idle);
            }
            Err(error) => {
                return Err(ReadError::Closed(format!(
                    "could not read relay message: {error}"
                )));
            }
        }
    }
}

fn read_error_string(error: ReadError) -> String {
    match error {
        ReadError::Idle => "relay read timed out".to_owned(),
        ReadError::Closed(error) => error,
    }
}

fn loopback_addresses(relay_url: &str, mode_name: &str) -> Result<Vec<SocketAddr>, String> {
    if relay_url.is_empty()
        || relay_url.len() > MAX_RELAY_URL_BYTES
        || relay_url.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(format!(
            "{mode_name} provider relay URL exceeds its byte bound or contains control bytes"
        ));
    }
    let authority = relay_url
        .strip_prefix("ws://")
        .ok_or_else(|| format!("{mode_name} provider accepts only ws:// loopback URLs"))?
        .split('/')
        .next()
        .unwrap_or_default();
    if authority.is_empty()
        || authority.contains('@')
        || relay_url.contains('?')
        || relay_url.contains('#')
    {
        return Err(format!("{mode_name} provider relay URL is invalid"));
    }
    let authority = if authority.contains(':') {
        authority.to_owned()
    } else {
        format!("{authority}:80")
    };
    let addresses = authority
        .to_socket_addrs()
        .map_err(|error| format!("could not resolve {mode_name} relay: {error}"))?
        .filter(|address| is_loopback(address.ip()))
        .collect::<Vec<_>>();
    if addresses.is_empty() {
        return Err(format!(
            "{mode_name} provider refuses non-loopback relay addresses"
        ));
    }
    Ok(addresses)
}

fn is_loopback(address: IpAddr) -> bool {
    address.is_loopback()
}

fn swp_profiles() -> [MktProfileSupport<'static>; 1] {
    [MktProfileSupport {
        profile_id: MKT_SWP_PROFILE_ID,
        version: MKT_SWP_PROFILE_VERSION,
        critical_members: &[],
        understood_members: &[],
    }]
}

pub(crate) fn session_id(event: &Event) -> Result<&str, String> {
    exactly_one_tag(event, "session")
}

fn offering_reference(event: &Event) -> Result<String, String> {
    let matches = event
        .tags
        .iter()
        .filter(|tag| {
            tag.name() == Some("a") && tag.as_slice().get(3).map(String::as_str) == Some("offering")
        })
        .collect::<Vec<_>>();
    if matches.len() != 1 {
        return Err("RFQ requires exactly one Offering reference".to_owned());
    }
    matches[0]
        .value()
        .map(str::to_owned)
        .ok_or_else(|| "RFQ Offering reference has no address".to_owned())
}

fn exactly_one_tag<'a>(event: &'a Event, name: &'a str) -> Result<&'a str, String> {
    let values = event.tag_values(name).collect::<Vec<_>>();
    if values.len() != 1 {
        return Err(format!("event requires exactly one {name} tag"));
    }
    Ok(values[0])
}

pub(crate) fn tag_value<'a>(event: &'a Event, name: &'a str) -> Option<&'a str> {
    event.tag_values(name).next()
}

pub(crate) fn has_kind_by_author(records: &[Event], kind: u16, author: &str) -> bool {
    records
        .iter()
        .any(|record| record.kind == kind && record.pubkey == author)
}

fn provider_authored_close(record: &Event, provider_pubkey: &str) -> bool {
    record.kind == MKT_CLOSE_KIND && record.pubkey == provider_pubkey
}

pub(crate) fn stalled_session_disposition(
    session: &ProviderSession,
    requester_pubkey: &str,
    observed_at: u64,
) -> Result<Option<&'static str>, String> {
    let records = session.signed_records();
    let provider_pubkey = &session.config().provider_pubkey;
    if has_kind_by_author(records, MKT_SWP_SWAP_CONTRACT_KIND, requester_pubkey)
        && has_kind_by_author(records, MKT_SWP_SWAP_CONTRACT_KIND, provider_pubkey)
    {
        return Ok(None);
    }
    let provider_quote = records
        .iter()
        .find(|record| record.kind == MKT_QUOTE_KIND && record.pubkey == *provider_pubkey);
    let deadline_record = match provider_quote {
        Some(quote) => quote,
        None => records
            .iter()
            .find(|record| record.kind == MKT_RFQ_KIND && record.pubkey == requester_pubkey)
            .ok_or_else(|| "provider session has no requester RFQ".to_owned())?,
    };
    let expiration = exactly_one_tag(deadline_record, "expiration")?
        .parse::<u64>()
        .map_err(|_| "provider session expiration is invalid".to_owned())?;
    if observed_at < expiration {
        return Ok(None);
    }
    if provider_quote.is_none() {
        return Ok(Some("rfq_expired"));
    }
    if has_kind_by_author(records, MKT_ORDER_KIND, requester_pubkey) {
        Ok(Some("contract_stalled"))
    } else {
        Ok(Some("quote_expired"))
    }
}

fn bounded_rejection_reason(error: &str) -> String {
    error.chars().take(256).collect()
}

fn insert_recovery_record(
    records: &mut BTreeMap<String, Event>,
    record: Event,
) -> Result<(), String> {
    match records.get(&record.id) {
        Some(existing) if existing != &record => Err(format!(
            "recovery event {} has conflicting signed bytes",
            record.id
        )),
        Some(_) => Ok(()),
        None => {
            records.insert(record.id.clone(), record);
            Ok(())
        }
    }
}

fn recovery_rank(event: &Event, provider_pubkey: &str) -> (u8, u64) {
    match event.kind {
        MKT_RFQ_KIND => (0, 0),
        MKT_QUOTE_KIND => (1, 0),
        MKT_ORDER_KIND => (2, 0),
        MKT_SWP_SWAP_CONTRACT_KIND if event.pubkey != provider_pubkey => (3, 0),
        MKT_SWP_SWAP_CONTRACT_KIND => (4, 0),
        MKT_STATUS_KIND => (
            5,
            tag_value(event, "seq")
                .and_then(|sequence| sequence.parse::<u64>().ok())
                .unwrap_or(u64::MAX),
        ),
        MKT_CANCEL_KIND => match tag_value(event, "action") {
            Some("request") => (6, 0),
            Some("accepted" | "rejected") => (7, 0),
            Some("effective") => (8, 0),
            _ => (9, 0),
        },
        MKT_CLOSE_KIND => (10, 0),
        _ => (u8::MAX, 0),
    }
}

fn random_wrap_material() -> Result<WrapMaterial, String> {
    let now = unix_now()?;
    Ok(WrapMaterial {
        seal_created_at: now.saturating_sub(u64::from(random_32()?[0]) * 10),
        wrap_created_at: now.saturating_sub(u64::from(random_32()?[0]) * 10),
        seal_nonce: random_32()?,
        wrap_nonce: random_32()?,
        wrap_secret: random_secret_bytes()?,
    })
}

fn random_secret_bytes() -> Result<[u8; 32], String> {
    for _ in 0..32 {
        let bytes = random_32()?;
        if MarketSigner::from_secret_bytes(bytes).is_ok() {
            return Ok(bytes);
        }
    }
    Err("could not generate a valid one-time wrapping key".to_owned())
}

fn random_32() -> Result<[u8; 32], String> {
    let mut bytes = [0_u8; 32];
    File::open("/dev/urandom")
        .and_then(|mut file| file.read_exact(&mut bytes))
        .map_err(|error| format!("could not read operating-system randomness: {error}"))?;
    Ok(bytes)
}

fn unix_now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| format!("system clock is before the Unix epoch: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ReservationConfirmation, ReservationRequest};
    use immortal_client::mkt_swp_client::SwapRecordFactory;

    #[test]
    fn relay_url_is_bounded_plaintext_and_loopback_only() {
        assert!(validate_relay_url("ws://127.0.0.1:8080", "test").is_ok());
        assert!(validate_relay_url("wss://127.0.0.1:8080", "test").is_err());
        assert!(validate_relay_url("ws://192.0.2.1:8080", "test").is_err());
        assert!(validate_relay_url(&format!("ws://{}", "a".repeat(2_048)), "test").is_err());
    }

    #[test]
    fn only_provider_authored_close_is_actor_terminal() {
        let provider = MarketSigner::from_secret_bytes([31; 32]).expect("provider signer");
        let requester = MarketSigner::from_secret_bytes([32; 32]).expect("requester signer");
        let requester_close = requester.sign(1, MKT_CLOSE_KIND, Vec::new(), "{}".to_owned());
        let provider_close = provider.sign(2, MKT_CLOSE_KIND, Vec::new(), "{}".to_owned());
        assert!(!provider_authored_close(
            &requester_close,
            provider.pubkey()
        ));
        assert!(provider_authored_close(&provider_close, provider.pubkey()));
    }

    struct RecoveryMode {
        records: Vec<Event>,
        has_prior_records: bool,
        reservation_confirmation: Option<ReservationConfirmation>,
        prune_stalled: bool,
    }

    impl ProviderMode for RecoveryMode {
        fn mode_name(&self) -> &'static str {
            "recovery-test"
        }

        fn provider_id(&self) -> &str {
            "recovery-test"
        }

        fn offering_id(&self) -> &str {
            "recovery-test"
        }

        fn discovery_metadata(&self) -> Value {
            json!({})
        }

        fn offering(&self) -> Value {
            json!({})
        }

        fn durable_recovery(&mut self, _limit: usize) -> Result<DurableRecovery, String> {
            Ok(DurableRecovery {
                records: std::mem::take(&mut self.records),
                has_prior_records: self.has_prior_records,
            })
        }

        fn prepare_recovered_record(
            &mut self,
            session: &mut ProviderSession,
            record: &Event,
        ) -> Result<(), String> {
            let Some(confirmation) = self.reservation_confirmation.as_ref() else {
                return Ok(());
            };
            if record.kind != MKT_QUOTE_KIND
                || record.pubkey != session.config().provider_pubkey
                || tag_value(record, "reservation") != Some("hard")
                || session.reservation().is_some()
            {
                return Ok(());
            }
            let mut profile = serde_json::from_str::<Value>(&record.content)
                .map_err(|error| format!("recovery Quote content is invalid: {error}"))?
                .get("mkt_swp")
                .cloned()
                .ok_or_else(|| "recovery Quote has no MKT-SWP profile".to_owned())?;
            profile
                .as_object_mut()
                .ok_or_else(|| "recovery Quote profile is not an object".to_owned())?
                .remove("reservation_terms");
            let distinct = exactly_one_tag(record, "d")?;
            let expiration = exactly_one_tag(record, "expiration")?
                .parse::<u64>()
                .map_err(|_| "recovery Quote expiration is invalid".to_owned())?;
            let request = session
                .hard_quote_with_reserve(
                    record.created_at,
                    distinct,
                    expiration,
                    ReservationRequest {
                        reservation_id: confirmation.reservation_id.clone(),
                        capacity_bucket_id: confirmation.capacity_bucket_id.clone(),
                        reserved_asset_id: confirmation.reserved_asset_id.clone(),
                        reserved_amount: confirmation.reserved_amount.clone(),
                        reservation_expires_at: confirmation.reservation_expires_at,
                    },
                    profile,
                    |_| Ok(confirmation.clone()),
                )
                .map_err(|error| format!("could not seed hard Quote recovery: {error}"))?;
            request
                .verify_signed(record.clone())
                .map_err(|error| format!("recovered hard Quote differs: {error}"))?;
            Ok(())
        }

        fn dispose_stalled_session(
            &mut self,
            session: &ProviderSession,
            requester_pubkey: &str,
            observed_at: u64,
        ) -> Result<Option<&'static str>, String> {
            if self.prune_stalled {
                stalled_session_disposition(session, requester_pubkey, observed_at)
            } else {
                Ok(None)
            }
        }

        fn construct_quote(
            &mut self,
            _session: &mut ProviderSession,
            _requester_pubkey: &str,
            _created_at: u64,
        ) -> Result<Option<MktSigningRequest>, String> {
            Err("not used by recovery test".to_owned())
        }

        fn observe_durable_signed_record(
            &mut self,
            _session_id: &str,
            _record: &Event,
            _origin: RecordOrigin,
            _provider_authored: bool,
        ) -> Result<(), String> {
            Ok(())
        }

        fn next_after_contract_or_status(
            &mut self,
            _session: &mut ProviderSession,
            _requester_pubkey: &str,
            _created_at: u64,
        ) -> Result<Option<MktSigningRequest>, String> {
            Ok(None)
        }
    }

    #[test]
    fn relay_truncation_requires_durable_prior_history() {
        let signer = MarketSigner::from_secret_bytes([41; 32]).expect("test signer");
        let offering_address = format!("39601:{}:recovery-test", signer.pubkey());
        let mut without_history = RelayActor {
            relay_url: "ws://127.0.0.1:1".to_owned(),
            signer: signer.clone(),
            offering_address: offering_address.clone(),
            sessions: BTreeMap::new(),
            mode: RecoveryMode {
                records: Vec::new(),
                has_prior_records: false,
                reservation_confirmation: None,
                prune_stalled: false,
            },
        };
        let error = without_history
            .rebuild(RelayHistory {
                wraps: Vec::new(),
                truncated: true,
            })
            .expect_err("truncated relay-only recovery must fail closed");
        assert!(error.contains("without durable prior history"));

        let mut with_history = RelayActor {
            relay_url: "ws://127.0.0.1:1".to_owned(),
            signer,
            offering_address,
            sessions: BTreeMap::new(),
            mode: RecoveryMode {
                records: Vec::new(),
                has_prior_records: true,
                reservation_confirmation: None,
                prune_stalled: false,
            },
        };
        with_history
            .rebuild(RelayHistory {
                wraps: Vec::new(),
                truncated: true,
            })
            .expect("durable history proof permits a bounded relay delta");
    }

    #[test]
    fn recovery_deduplicates_exact_events_and_rejects_conflicting_bytes() {
        let signer = MarketSigner::from_secret_bytes([42; 32]).expect("test signer");
        let event = signer.sign(
            1,
            MKT_RFQ_KIND,
            vec![immortal_core::domain::Tag::new(vec![
                "session".to_owned(),
                "ab".repeat(32),
            ])],
            json!({"mkt_swp":{}}).to_string(),
        );
        let mut records = BTreeMap::new();
        insert_recovery_record(&mut records, event.clone()).expect("first event");
        insert_recovery_record(&mut records, event.clone()).expect("exact replay");
        assert_eq!(records.len(), 1);

        let mut conflicting = event;
        conflicting.content = json!({"mkt_swp":{"changed":true}}).to_string();
        assert!(
            insert_recovery_record(&mut records, conflicting)
                .expect_err("changed signed bytes must conflict")
                .contains("conflicting signed bytes")
        );
    }

    #[test]
    fn recovery_enforces_the_active_session_bound() {
        let provider = MarketSigner::from_secret_bytes([43; 32]).expect("provider signer");
        let offering_address = format!("39601:{}:recovery-test", provider.pubkey());
        let records: Vec<Event> = (0..=MAX_SESSIONS)
            .map(|index| {
                let secret_byte = u8::try_from(44 + index).expect("requester secret byte");
                let requester =
                    MarketSigner::from_secret_bytes([secret_byte; 32]).expect("requester signer");
                let session_id = format!("{:02x}", 0x60 + index).repeat(32);
                let config = SwapClientConfig {
                    session_id,
                    requester_pubkey: requester.pubkey().to_owned(),
                    provider_pubkey: provider.pubkey().to_owned(),
                    offering_address: offering_address.clone(),
                };
                let factory = SwapRecordFactory::new(config).expect("record factory");
                let fixtures: Value = serde_json::from_str(include_str!(
                    "../../../tests/fixtures/nipmkt/swp-full-sessions-v1.json"
                ))
                .expect("full-session fixture");
                let fixture_record =
                    &fixtures["flows"]["submarine"]["snapshot"]["signed_records"][0];
                let fixture_content: Value = serde_json::from_str(
                    fixture_record["content"].as_str().expect("fixture content"),
                )
                .expect("fixture content JSON");
                let request = factory
                    .rfq(
                        100 + u64::try_from(index).expect("session index"),
                        &format!("{:02x}", 0x80 + index).repeat(32),
                        300,
                        fixture_content["mkt_swp"].clone(),
                    )
                    .expect("RFQ request");
                let event = requester.sign(
                    request.created_at,
                    request.kind,
                    request.tags.clone(),
                    request.content.clone(),
                );
                request.verify_signed(event).expect("signed RFQ")
            })
            .collect();
        let mut actor = RelayActor {
            relay_url: "ws://127.0.0.1:1".to_owned(),
            signer: provider.clone(),
            offering_address: offering_address.clone(),
            sessions: BTreeMap::new(),
            mode: RecoveryMode {
                records: records.clone(),
                has_prior_records: true,
                reservation_confirmation: None,
                prune_stalled: false,
            },
        };
        let error = actor
            .rebuild(RelayHistory {
                wraps: Vec::new(),
                truncated: false,
            })
            .expect_err("thirteen active sessions must exceed the bound");
        assert!(error.contains("active session bound 12"));

        let mut pruned = RelayActor {
            relay_url: "ws://127.0.0.1:1".to_owned(),
            signer: provider.clone(),
            offering_address: offering_address.clone(),
            sessions: BTreeMap::new(),
            mode: RecoveryMode {
                records: records.clone(),
                has_prior_records: true,
                reservation_confirmation: None,
                prune_stalled: true,
            },
        };
        pruned
            .rebuild(RelayHistory {
                wraps: Vec::new(),
                truncated: false,
            })
            .expect("expired sessions must be pruned before enforcing the active bound");
        assert!(pruned.sessions.is_empty());

        let mut rejected = RelayActor {
            relay_url: "ws://127.0.0.1:1".to_owned(),
            signer: provider,
            offering_address,
            sessions: BTreeMap::new(),
            mode: RecoveryMode {
                records: Vec::new(),
                has_prior_records: false,
                reservation_confirmation: None,
                prune_stalled: false,
            },
        };
        for record in records {
            let session_id = session_id(&record).expect("RFQ session").to_owned();
            rejected
                .ingest_record(record)
                .expect("valid RFQ must enter the actor");
            assert!(matches!(
                rejected.prepare_session_advance(&session_id, 200),
                Ok(SessionAdvance::Removed)
            ));
            assert!(rejected.sessions.is_empty());
        }
    }

    #[test]
    fn one_requester_cannot_occupy_every_provider_session() {
        let provider = MarketSigner::from_secret_bytes([57; 32]).expect("provider signer");
        let requester = MarketSigner::from_secret_bytes([58; 32]).expect("requester signer");
        let offering_address = format!("39601:{}:recovery-test", provider.pubkey());
        let fixtures: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/nipmkt/swp-full-sessions-v1.json"
        ))
        .expect("full-session fixture");
        let fixture_record = &fixtures["flows"]["submarine"]["snapshot"]["signed_records"][0];
        let fixture_content: Value =
            serde_json::from_str(fixture_record["content"].as_str().expect("fixture content"))
                .expect("fixture content JSON");
        let now = unix_now().expect("current time");
        let mut actor = RelayActor {
            relay_url: "ws://127.0.0.1:1".to_owned(),
            signer: provider.clone(),
            offering_address: offering_address.clone(),
            sessions: BTreeMap::new(),
            mode: RecoveryMode {
                records: Vec::new(),
                has_prior_records: false,
                reservation_confirmation: None,
                prune_stalled: false,
            },
        };

        for index in 0..=MAX_SESSIONS_PER_REQUESTER {
            let session_id = format!("{:02x}", 0xa0 + index).repeat(32);
            let config = SwapClientConfig {
                session_id,
                requester_pubkey: requester.pubkey().to_owned(),
                provider_pubkey: provider.pubkey().to_owned(),
                offering_address: offering_address.clone(),
            };
            let factory = SwapRecordFactory::new(config).expect("record factory");
            let request = factory
                .rfq(
                    now + u64::try_from(index).expect("created-at offset"),
                    &format!("{:02x}", 0xb0 + index).repeat(32),
                    now + 3_600,
                    fixture_content["mkt_swp"].clone(),
                )
                .expect("RFQ request");
            let record = requester.sign(
                request.created_at,
                request.kind,
                request.tags.clone(),
                request.content.clone(),
            );
            if index < MAX_SESSIONS_PER_REQUESTER {
                actor
                    .ingest_record(request.verify_signed(record).expect("signed RFQ"))
                    .expect("requester session within the bound");
            } else {
                let error = actor
                    .ingest_record(request.verify_signed(record).expect("signed RFQ"))
                    .expect_err("fifth requester session must exceed the bound");
                assert!(error.contains("provider requester session bound 4 reached"));
            }
        }
        assert_eq!(actor.sessions.len(), MAX_SESSIONS_PER_REQUESTER);
    }

    #[test]
    fn hard_quote_recovery_requires_and_accepts_durable_reservation_state() {
        let provider = MarketSigner::from_secret_bytes([45; 32]).expect("provider signer");
        let requester = MarketSigner::from_secret_bytes([46; 32]).expect("requester signer");
        let offering_address = format!("39601:{}:recovery-test", provider.pubkey());
        let config = SwapClientConfig {
            session_id: "ba".repeat(32),
            requester_pubkey: requester.pubkey().to_owned(),
            provider_pubkey: provider.pubkey().to_owned(),
            offering_address: offering_address.clone(),
        };
        let fixtures: Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/nipmkt/swp-full-sessions-v1.json"
        ))
        .expect("full-session fixture");
        let fixture_records = fixtures["flows"]["submarine"]["snapshot"]["signed_records"]
            .as_array()
            .expect("fixture records");
        let profile = |kind: u16| {
            let content = fixture_records
                .iter()
                .find(|record| record["kind"] == u64::from(kind))
                .and_then(|record| record["content"].as_str())
                .expect("fixture record");
            serde_json::from_str::<Value>(content).expect("fixture content")["mkt_swp"].clone()
        };
        let factory = SwapRecordFactory::new(config.clone()).expect("record factory");
        let rfq_request = factory
            .rfq(100, &"71".repeat(32), 1_100, profile(MKT_RFQ_KIND))
            .expect("RFQ request");
        let rfq = requester.sign(
            rfq_request.created_at,
            rfq_request.kind,
            rfq_request.tags.clone(),
            rfq_request.content.clone(),
        );
        let rfq = rfq_request.verify_signed(rfq).expect("signed RFQ");
        let confirmation = ReservationConfirmation {
            reservation_id: "72".repeat(32),
            capacity_bucket_id: "restart-test".to_owned(),
            reserved_asset_id: "swp:1:bip122:00000000000000000000000000000000:btc:lightning"
                .to_owned(),
            reserved_amount: "1000".to_owned(),
            committed_capacity: "1000".to_owned(),
            reservation_expires_at: 900,
            allocation_sequence: "1".to_owned(),
            proof_class: "handler_accounted".to_owned(),
            proof_ref: "restart-test:reservation".to_owned(),
            capacity_commitment_sha256: "73".repeat(32),
        };
        let mut quote_profile = profile(MKT_QUOTE_KIND);
        quote_profile
            .as_object_mut()
            .expect("Quote profile")
            .remove("reservation_terms");
        let mut original = ProviderSession::new(config).expect("provider session");
        original.ingest_signed(rfq.clone()).expect("ingest RFQ");
        let quote_request = original
            .hard_quote_with_reserve(
                101,
                &"74".repeat(32),
                1_000,
                ReservationRequest {
                    reservation_id: confirmation.reservation_id.clone(),
                    capacity_bucket_id: confirmation.capacity_bucket_id.clone(),
                    reserved_asset_id: confirmation.reserved_asset_id.clone(),
                    reserved_amount: confirmation.reserved_amount.clone(),
                    reservation_expires_at: confirmation.reservation_expires_at,
                },
                quote_profile,
                |_| Ok(confirmation.clone()),
            )
            .expect("hard Quote request");
        let quote = provider.sign(
            quote_request.created_at,
            quote_request.kind,
            quote_request.tags.clone(),
            quote_request.content.clone(),
        );
        let quote = quote_request
            .verify_signed(quote)
            .expect("signed hard Quote");

        let actor = |reservation_confirmation| RelayActor {
            relay_url: "ws://127.0.0.1:1".to_owned(),
            signer: provider.clone(),
            offering_address: offering_address.clone(),
            sessions: BTreeMap::new(),
            mode: RecoveryMode {
                records: vec![rfq.clone(), quote.clone()],
                has_prior_records: true,
                reservation_confirmation,
                prune_stalled: false,
            },
        };
        let mut missing = actor(None);
        let error = missing
            .rebuild(RelayHistory {
                wraps: Vec::new(),
                truncated: false,
            })
            .expect_err("hard Quote without durable reserve state must fail closed");
        assert!(error.contains("provider-authored recovery history"));

        let mut recovered = actor(Some(confirmation.clone()));
        recovered
            .rebuild(RelayHistory {
                wraps: Vec::new(),
                truncated: false,
            })
            .expect("hard Quote must recover with durable reserve state");
        let session = &recovered
            .sessions
            .values()
            .next()
            .expect("active recovered session")
            .session;
        assert_eq!(session.reservation(), Some(&confirmation));
        assert_eq!(session.signed_records(), [rfq, quote]);
    }
}
