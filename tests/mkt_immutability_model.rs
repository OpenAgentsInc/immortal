use immortal::domain::{
    EventClass, MktImmutableDecision, decide_mkt_immutable_admission, is_mkt_private_kind,
};
use serde_json::Value;

#[test]
fn nipmkt_immutable_fixture_anchor_sequences() {
    let fixture = fixture();
    for sequence in fixture["anchor_sequences"].as_array().unwrap() {
        let mut stored = None;
        let actual = sequence["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .map(|candidate| implementation_transition(&mut stored, candidate.as_str().unwrap()))
            .collect::<Vec<_>>();
        let expected = sequence["outcomes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|outcome| outcome.as_str().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(actual, expected);
    }
}

#[test]
fn nipmkt_bounded_model_exhausts_admission_and_removal_histories() {
    let fixture = fixture();
    let actions = fixture["bounded_model"]["actions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|action| Action::from_fixture(action.as_str().unwrap()))
        .collect::<Vec<_>>();
    let maximum_length = usize::try_from(
        fixture["bounded_model"]["maximum_sequence_length"]
            .as_u64()
            .unwrap(),
    )
    .unwrap();
    let mut histories_checked = 0;

    for length in 0..=maximum_length {
        exhaust_histories(&actions, length, &mut Vec::new(), &mut |history| {
            histories_checked += 1;
            check_reference_history(history);
        });
    }

    assert_eq!(histories_checked, 19_531);
}

#[test]
fn nipmkt_entire_reserved_block_is_addressable() {
    let fixture = fixture();
    let private_kinds = fixture["private_kinds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|kind| u16::try_from(kind.as_u64().unwrap()).unwrap())
        .collect::<Vec<_>>();

    for kind in 39_600..=39_699 {
        assert_eq!(EventClass::from_kind(kind), EventClass::Addressable);
        assert_eq!(is_mkt_private_kind(kind), private_kinds.contains(&kind));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Candidate {
    A,
    B,
}

#[derive(Debug, Clone, Copy)]
enum Action {
    Admit(Candidate),
    Delete,
    Expire,
    Restart,
}

impl Action {
    fn from_fixture(value: &str) -> Self {
        match value {
            "admit-a" => Self::Admit(Candidate::A),
            "admit-b" => Self::Admit(Candidate::B),
            "delete" => Self::Delete,
            "expire" => Self::Expire,
            "restart" => Self::Restart,
            _ => panic!("unknown model action {value}"),
        }
    }
}

#[derive(Debug, Default)]
struct ReferenceState {
    binding: Option<Candidate>,
    visible: Option<Candidate>,
    stored_notifications: usize,
}

fn check_reference_history(history: &[Action]) {
    let mut state = ReferenceState::default();
    for action in history {
        let old_binding = state.binding;
        let old_visible = state.visible;
        let old_notifications = state.stored_notifications;
        match action {
            Action::Admit(candidate) if state.binding.is_none() => {
                state.binding = Some(*candidate);
                state.visible = Some(*candidate);
                state.stored_notifications += 1;
            }
            Action::Admit(candidate) if state.binding == Some(*candidate) => {
                assert_eq!(
                    state.visible, old_visible,
                    "replay resurrected a removed row"
                );
                assert_eq!(state.stored_notifications, old_notifications);
            }
            Action::Admit(_) => {
                assert_eq!(state.visible, old_visible, "conflict changed visible state");
                assert_eq!(state.stored_notifications, old_notifications);
            }
            Action::Delete | Action::Expire => state.visible = None,
            Action::Restart => {}
        }
        if old_binding.is_some() {
            assert_eq!(state.binding, old_binding, "durable binding changed");
        }
        assert!(
            state.visible.is_none() || state.visible == state.binding,
            "more than the bound event became visible"
        );
        assert!(state.stored_notifications <= 1);
    }
}

fn implementation_transition<'a>(
    stored: &mut Option<(&'a str, &'a str)>,
    candidate: &'a str,
) -> &'static str {
    let (event_id, signature) = candidate_parts(candidate);
    match decide_mkt_immutable_admission(*stored, event_id, signature) {
        MktImmutableDecision::StoreFirst => {
            *stored = Some((event_id, signature));
            "stored"
        }
        MktImmutableDecision::Replay => "duplicate",
        MktImmutableDecision::Conflict => "idempotency-conflict",
    }
}

fn candidate_parts(candidate: &str) -> (&str, &str) {
    match candidate {
        "event-a" => ("event-a", "signature-a"),
        "event-a-alt-signature" => ("event-a", "signature-b"),
        "event-b" => ("event-b", "signature-b"),
        _ => panic!("unknown implementation candidate {candidate}"),
    }
}

fn exhaust_histories(
    actions: &[Action],
    remaining: usize,
    history: &mut Vec<Action>,
    check: &mut impl FnMut(&[Action]),
) {
    if remaining == 0 {
        check(history);
        return;
    }
    for action in actions {
        history.push(*action);
        exhaust_histories(actions, remaining - 1, history, check);
        history.pop();
    }
}

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/nipmkt/immutability.json")).unwrap()
}
