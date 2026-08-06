use std::collections::BTreeMap;

use immortal_core::domain::{Event, Filter, Tag};
use serde::Deserialize;

const FIXTURE_SCHEMA: &str = "openagents.immortal.deterministic-fuzz.v1";

#[derive(Deserialize)]
struct Fixture {
    schema: String,
    seed: String,
    filter_iterations: usize,
    filter_seeds: Vec<String>,
    expected: Expected,
}

#[derive(Deserialize)]
struct Expected {
    structured_filter_matches: usize,
    structured_filter_valid: usize,
    raw_filters_parsed: usize,
}

#[test]
fn deterministic_filter_generation_matches_independent_reference() -> Result<(), String> {
    let fixture = fixture()?;
    validate_fixture(&fixture)?;
    let seed = parse_seed(&fixture.seed)? ^ 0xd1b5_4a32_d192_ed03;
    let mut random = DeterministicRandom::new(seed);
    let mut structured_matches = 0_usize;
    let mut structured_valid = 0_usize;
    let mut raw_filters_parsed = 0_usize;

    for iteration in 0..fixture.filter_iterations {
        let event = random_event(&mut random)?;
        let filter = random_filter(&mut random, &event)?;
        let actual = filter.matches(&event);
        let expected = reference_matches(&filter, &event);
        if actual != expected {
            return Err(format!(
                "filter matcher diverged at iteration {iteration}: filter {filter:?}, event {event:?}, actual {actual}, expected {expected}"
            ));
        }
        if actual {
            structured_matches = structured_matches.saturating_add(1);
        }
        if filter.validate().is_ok() {
            structured_valid = structured_valid.saturating_add(1);
        }

        let seed_index = random.bounded(fixture.filter_seeds.len());
        let raw_seed = fixture
            .filter_seeds
            .get(seed_index)
            .ok_or_else(|| format!("filter seed index {seed_index} is out of bounds"))?;
        let operation = random.bounded(8);
        let raw = mutate_ascii(raw_seed, operation, &mut random, 4_096)?;
        if let Ok(parsed) = serde_json::from_str::<Filter>(&raw) {
            raw_filters_parsed = raw_filters_parsed.saturating_add(1);
            let first = parsed.matches(&event);
            let second = parsed.matches(&event);
            if first != second {
                return Err(format!(
                    "filter matcher was nondeterministic at iteration {iteration}: {raw:?}"
                ));
            }
            let reference = reference_matches(&parsed, &event);
            if first != reference {
                return Err(format!(
                    "parsed filter matcher diverged at iteration {iteration}: {raw:?}"
                ));
            }
        }
    }

    let actual = (structured_matches, structured_valid, raw_filters_parsed);
    let expected = (
        fixture.expected.structured_filter_matches,
        fixture.expected.structured_filter_valid,
        fixture.expected.raw_filters_parsed,
    );
    if actual != expected {
        return Err(format!(
            "filter fuzz summary changed: actual {actual:?}, expected {expected:?}"
        ));
    }
    Ok(())
}

fn validate_fixture(fixture: &Fixture) -> Result<(), String> {
    if fixture.schema != FIXTURE_SCHEMA {
        return Err(format!(
            "unexpected fuzz fixture schema {:?}",
            fixture.schema
        ));
    }
    if fixture.filter_seeds.is_empty() {
        return Err("filter fuzz corpus must have at least one seed".to_owned());
    }
    if !(1..=100_000).contains(&fixture.filter_iterations) {
        return Err("filter fuzz iteration count is outside the bounded range".to_owned());
    }
    Ok(())
}

fn random_event(random: &mut DeterministicRandom) -> Result<Event, String> {
    let id = random_hex(random, 32)?;
    let pubkey = random_hex(random, 32)?;
    let created_at = random.next() % 10_000;
    let kind = match random.bounded(6) {
        0 => 0,
        1 => 1,
        2 => 5,
        3 => 10_000,
        4 => 20_001,
        _ => 30_001,
    };
    let mut tags = Vec::new();
    for _ in 0..random.bounded(8) {
        let name = match random.bounded(6) {
            0 => "e",
            1 => "p",
            2 => "E",
            3 => "t",
            4 => "work",
            _ => "alt",
        };
        let value = match random.bounded(4) {
            0 => "alpha".to_owned(),
            1 => "beta".to_owned(),
            2 => random_hex(random, 4)?,
            _ => String::new(),
        };
        tags.push(Tag::new(vec![name.to_owned(), value]));
    }
    let content = match random.bounded(6) {
        0 => "alpha beta".to_owned(),
        1 => "ALPHA gamma".to_owned(),
        2 => "beta extension:value".to_owned(),
        3 => "punctuation,alpha".to_owned(),
        4 => String::new(),
        _ => format!("word-{}", random.next() % 32),
    };
    Ok(Event {
        id,
        pubkey,
        created_at,
        kind,
        tags,
        content,
        sig: random_hex(random, 64)?,
    })
}

fn random_filter(random: &mut DeterministicRandom, event: &Event) -> Result<Filter, String> {
    let ids = random
        .chance(2)
        .then(|| random_hex_list(random, &event.id))
        .transpose()?;
    let authors = random
        .chance(2)
        .then(|| random_hex_list(random, &event.pubkey))
        .transpose()?;
    let kinds = random.chance(2).then(|| {
        let mut values = Vec::new();
        for _ in 0..random.bounded(4) {
            values.push(if random.chance(2) {
                event.kind
            } else {
                u16::try_from(random.next() % 65_536).unwrap_or(0)
            });
        }
        values
    });
    let mut tags = BTreeMap::new();
    for _ in 0..random.bounded(4) {
        let name = match random.bounded(5) {
            0 => "e",
            1 => "p",
            2 => "E",
            3 => "t",
            _ => "work",
        };
        let matching = event
            .tags
            .iter()
            .find(|tag| tag.name() == Some(name))
            .and_then(Tag::value)
            .map(str::to_owned);
        let mut values = Vec::new();
        for _ in 0..random.bounded(4) {
            values.push(if random.chance(2) {
                matching.clone().unwrap_or_else(|| "missing".to_owned())
            } else {
                random_hex(random, 3)?
            });
        }
        tags.insert(name.to_owned(), values);
    }
    let since = random.chance(2).then(|| {
        if random.chance(2) {
            event.created_at.saturating_sub(random.next() % 3)
        } else {
            event.created_at.saturating_add(random.next() % 3)
        }
    });
    let until = random.chance(2).then(|| {
        if random.chance(2) {
            event.created_at.saturating_add(random.next() % 3)
        } else {
            event.created_at.saturating_sub(random.next() % 3)
        }
    });
    let search = random.chance(2).then(|| match random.bounded(6) {
        0 => "alpha".to_owned(),
        1 => "beta".to_owned(),
        2 => "alpha beta".to_owned(),
        3 => "extension:value".to_owned(),
        4 => "ALPHA extension:value".to_owned(),
        _ => "missing".to_owned(),
    });
    Ok(Filter {
        ids,
        authors,
        kinds,
        tags,
        since,
        until,
        limit: random.chance(2).then(|| random.bounded(256)),
        search,
    })
}

fn random_hex_list(
    random: &mut DeterministicRandom,
    matching: &str,
) -> Result<Vec<String>, String> {
    let mut values = Vec::new();
    for _ in 0..random.bounded(4) {
        values.push(if random.chance(2) {
            matching.to_owned()
        } else {
            random_hex(random, 32)?
        });
    }
    Ok(values)
}

fn reference_matches(filter: &Filter, event: &Event) -> bool {
    list_matches(filter.ids.as_deref(), &event.id)
        && list_matches(filter.authors.as_deref(), &event.pubkey)
        && filter
            .kinds
            .as_ref()
            .is_none_or(|kinds| kinds.contains(&event.kind))
        && filter.since.is_none_or(|since| event.created_at >= since)
        && filter.until.is_none_or(|until| event.created_at <= until)
        && filter.tags.iter().all(|(selector, values)| {
            event.tags.iter().any(|tag| {
                let Some(name) = tag.name() else {
                    return false;
                };
                let indexed = (name.len() == 1
                    && name.as_bytes().first().is_some_and(u8::is_ascii_alphabetic))
                    || name == "work";
                indexed
                    && name == selector
                    && tag
                        .value()
                        .is_some_and(|value| values.iter().any(|candidate| candidate == value))
            })
        })
        && filter.search.as_ref().is_none_or(|search| {
            let terms = search
                .split_whitespace()
                .filter(|term| !term.contains(':'))
                .map(str::to_lowercase)
                .collect::<Vec<_>>();
            let content = event.content.to_lowercase();
            !terms.is_empty() && terms.iter().all(|term| content.contains(term))
        })
}

fn list_matches(values: Option<&[String]>, actual: &str) -> bool {
    values.is_none_or(|values| values.iter().any(|value| value == actual))
}

fn random_hex(random: &mut DeterministicRandom, bytes: usize) -> Result<String, String> {
    let mut value = String::with_capacity(bytes.saturating_mul(2));
    for _ in 0..bytes.saturating_mul(2) {
        let digit = u8::try_from(random.next() & 0x0f)
            .map_err(|error| format!("hex digit conversion failed: {error}"))?;
        value.push(char::from(if digit < 10 {
            b'0'.saturating_add(digit)
        } else {
            b'a'.saturating_add(digit.saturating_sub(10))
        }));
    }
    Ok(value)
}

fn mutate_ascii(
    seed: &str,
    operation: usize,
    random: &mut DeterministicRandom,
    maximum_bytes: usize,
) -> Result<String, String> {
    let mut bytes = seed.as_bytes().to_vec();
    match operation {
        0 => {
            let position = random.bounded(bytes.len().max(1));
            if let Some(byte) = bytes.get_mut(position) {
                *byte = mutation_byte(random.bounded(16));
            } else {
                bytes.push(mutation_byte(random.bounded(16)));
            }
        }
        1 => {
            let position = random.bounded(bytes.len().saturating_add(1));
            bytes.insert(position, mutation_byte(random.bounded(16)));
        }
        2 => {
            if !bytes.is_empty() {
                let start = random.bounded(bytes.len());
                let maximum = bytes.len().saturating_sub(start).min(16);
                let length = random.bounded(maximum).saturating_add(1);
                bytes.drain(start..start.saturating_add(length));
            }
        }
        3 => {
            if !bytes.is_empty() {
                let start = random.bounded(bytes.len());
                let maximum = bytes.len().saturating_sub(start).min(16);
                let length = random.bounded(maximum).saturating_add(1);
                let end = start.saturating_add(length);
                let duplicate = bytes
                    .get(start..end)
                    .ok_or_else(|| "filter duplicate range is invalid".to_owned())?
                    .to_vec();
                let position = random.bounded(bytes.len().saturating_add(1));
                bytes.splice(position..position, duplicate);
            }
        }
        4 => bytes.truncate(random.bounded(bytes.len().saturating_add(1))),
        5 => {
            let token = mutation_token(random.bounded(8));
            let position = random.bounded(bytes.len().saturating_add(1));
            bytes.splice(position..position, token.bytes());
        }
        6 => {
            let original = bytes.clone();
            for _ in 0..random.bounded(4).saturating_add(1) {
                bytes.extend_from_slice(&original);
            }
        }
        7 => {
            let length = random.bounded(256);
            bytes.clear();
            for _ in 0..length {
                bytes.push(mutation_byte(random.bounded(16)));
            }
        }
        _ => return Err(format!("unknown filter mutation operation {operation}")),
    }
    bytes.truncate(maximum_bytes);
    String::from_utf8(bytes).map_err(|error| format!("mutation produced non-UTF-8: {error}"))
}

fn mutation_byte(index: usize) -> u8 {
    match index {
        0 => b'{',
        1 => b'}',
        2 => b'[',
        3 => b']',
        4 => b'"',
        5 => b'\\',
        6 => b',',
        7 => b':',
        8 => b'0',
        9 => b'9',
        10 => b'n',
        11 => b't',
        12 => b'f',
        13 => b' ',
        14 => b'\n',
        _ => b'x',
    }
}

fn mutation_token(index: usize) -> &'static str {
    match index {
        0 => "null",
        1 => "true",
        2 => "false",
        3 => "{}",
        4 => "[]",
        5 => "\"x\"",
        6 => "18446744073709551616",
        _ => "\\u0000",
    }
}

struct DeterministicRandom(u64);

impl DeterministicRandom {
    fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }

    fn next(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }

    fn bounded(&mut self, upper: usize) -> usize {
        if upper == 0 {
            return 0;
        }
        usize::try_from(self.next() % u64::try_from(upper).unwrap_or(u64::MAX)).unwrap_or(0)
    }

    fn chance(&mut self, denominator: u64) -> bool {
        denominator > 0 && self.next() % denominator == 0
    }
}

fn parse_seed(seed: &str) -> Result<u64, String> {
    u64::from_str_radix(seed, 16).map_err(|error| format!("invalid fuzz seed {seed:?}: {error}"))
}

fn fixture() -> Result<Fixture, String> {
    serde_json::from_str(include_str!(
        "../../../tests/fixtures/nip01/fuzz-corpus.json"
    ))
    .map_err(|error| format!("invalid filter fuzz fixture: {error}"))
}
