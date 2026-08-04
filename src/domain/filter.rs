use std::collections::BTreeMap;

use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    ser::{Error as _, SerializeMap},
};
use serde_json::Value;

use super::hex::decode_lower_hex;
use super::{DomainError, Event};

/// A single NIP-01 filter. Populated fields are ANDed; values within one
/// field are ORed. Multiple filters are ORed with [`matches_any`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Filter {
    pub ids: Option<Vec<String>>,
    pub authors: Option<Vec<String>>,
    pub kinds: Option<Vec<u16>>,
    pub tags: BTreeMap<char, Vec<String>>,
    pub since: Option<u64>,
    pub until: Option<u64>,
    pub limit: Option<usize>,
    pub search: Option<String>,
}

impl Filter {
    /// Validate exact NIP-01 ID and author selectors. Prefix selectors are
    /// intentionally rejected because current NIP-01 removed prefix matching.
    pub fn validate(&self) -> Result<(), DomainError> {
        if let Some(ids) = &self.ids {
            for id in ids {
                decode_lower_hex::<32>(id, "filter id").map_err(|_| {
                    DomainError::InvalidFilter(
                        "every id must be exactly 64 lowercase hexadecimal characters".to_owned(),
                    )
                })?;
            }
        }
        if let Some(authors) = &self.authors {
            for author in authors {
                decode_lower_hex::<32>(author, "filter author").map_err(|_| {
                    DomainError::InvalidFilter(
                        "every author must be exactly 64 lowercase hexadecimal characters"
                            .to_owned(),
                    )
                })?;
            }
        }
        if self.tags.keys().any(|key| !key.is_ascii_alphabetic()) {
            return Err(DomainError::InvalidFilter(
                "tag selectors must be one ASCII letter".to_owned(),
            ));
        }
        if let Some(search) = &self.search {
            if search.chars().count() > 256 {
                return Err(DomainError::InvalidFilter(
                    "search must contain at most 256 characters".to_owned(),
                ));
            }
            if search_terms(search).is_empty() {
                return Err(DomainError::InvalidFilter(
                    "search must contain at least one non-extension term".to_owned(),
                ));
            }
        }
        Ok(())
    }

    pub fn matches(&self, event: &Event) -> bool {
        list_matches(self.ids.as_deref(), &event.id)
            && list_matches(self.authors.as_deref(), &event.pubkey)
            && self
                .kinds
                .as_ref()
                .is_none_or(|kinds| kinds.contains(&event.kind))
            && self.since.is_none_or(|since| event.created_at >= since)
            && self.until.is_none_or(|until| event.created_at <= until)
            && self.tags.iter().all(|(key, values)| {
                event.indexed_tags().any(|(event_key, event_value)| {
                    event_key == *key && values.iter().any(|v| v == event_value)
                })
            })
            && self.search.as_ref().is_none_or(|search| {
                let content = event.content.to_lowercase();
                let terms = search_terms(search);
                !terms.is_empty() && terms.iter().all(|term| content.contains(term))
            })
    }
}

fn list_matches(values: Option<&[String]>, actual: &str) -> bool {
    values.is_none_or(|values| values.iter().any(|value| value == actual))
}

pub fn matches_any(filters: &[Filter], event: &Event) -> bool {
    filters.iter().any(|filter| filter.matches(event))
}

#[derive(Deserialize)]
struct RawFilter {
    #[serde(default)]
    ids: Option<Vec<String>>,
    #[serde(default)]
    authors: Option<Vec<String>>,
    #[serde(default)]
    kinds: Option<Vec<u16>>,
    #[serde(default)]
    since: Option<u64>,
    #[serde(default)]
    until: Option<u64>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    search: Option<String>,
    #[serde(flatten)]
    extra: BTreeMap<String, Value>,
}

impl<'de> Deserialize<'de> for Filter {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawFilter::deserialize(deserializer)?;
        let mut tags = BTreeMap::new();
        for (field, value) in raw.extra {
            let bytes = field.as_bytes();
            if bytes.len() != 2 || bytes[0] != b'#' || !bytes[1].is_ascii_alphabetic() {
                return Err(serde::de::Error::custom(format!(
                    "unsupported filter field {field:?}"
                )));
            }
            let values =
                serde_json::from_value::<Vec<String>>(value).map_err(serde::de::Error::custom)?;
            tags.insert(char::from(bytes[1]), values);
        }
        Ok(Self {
            ids: raw.ids,
            authors: raw.authors,
            kinds: raw.kinds,
            tags,
            since: raw.since,
            until: raw.until,
            limit: raw.limit,
            search: raw.search,
        })
    }
}

impl Serialize for Filter {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let field_count = usize::from(self.ids.is_some())
            + usize::from(self.authors.is_some())
            + usize::from(self.kinds.is_some())
            + usize::from(self.since.is_some())
            + usize::from(self.until.is_some())
            + usize::from(self.limit.is_some())
            + usize::from(self.search.is_some())
            + self.tags.len();
        let mut map = serializer.serialize_map(Some(field_count))?;
        if let Some(ids) = &self.ids {
            map.serialize_entry("ids", ids)?;
        }
        if let Some(authors) = &self.authors {
            map.serialize_entry("authors", authors)?;
        }
        if let Some(kinds) = &self.kinds {
            map.serialize_entry("kinds", kinds)?;
        }
        for (key, values) in &self.tags {
            if !key.is_ascii_alphabetic() {
                return Err(S::Error::custom("tag selector must be one ASCII letter"));
            }
            map.serialize_entry(&format!("#{key}"), values)?;
        }
        if let Some(since) = self.since {
            map.serialize_entry("since", &since)?;
        }
        if let Some(until) = self.until {
            map.serialize_entry("until", &until)?;
        }
        if let Some(limit) = self.limit {
            map.serialize_entry("limit", &limit)?;
        }
        if let Some(search) = &self.search {
            map.serialize_entry("search", search)?;
        }
        map.end()
    }
}

/// NIP-50 extension tokens are ignored; remaining words are matched using
/// Postgres' simple text-search configuration by the store.
pub fn search_terms(search: &str) -> Vec<String> {
    search
        .split_whitespace()
        .filter(|term| !term.contains(':'))
        .map(str::to_lowercase)
        .collect()
}
