//! Detectors find candidate spans; the engine resolves overlaps between them.

mod card;
mod custom;
mod dictionary;
mod email;
mod iban;
mod ip;
mod natid;
#[cfg(feature = "phone")]
mod phone;
mod secret;
mod url;

use std::sync::Arc;

use crate::kind::EntityKind;
use crate::rules::{RulesError, RulesFile};

/// Where a match came from.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Source {
    /// A [`DictionaryEntry`](crate::DictionaryEntry) in the rules.
    Dictionary,
    /// One of the built-in detectors, such as email or card numbers.
    BuiltIn,
    /// A [`RegexRule`](crate::RegexRule); holds the rule's name.
    Regex(Arc<str>),
    /// The name-detection model.
    Ner,
}

#[derive(Clone, Debug)]
pub(crate) struct Candidate {
    pub start: usize,
    pub end: usize,
    pub kind: EntityKind,
    pub source: Source,
    /// Breaks ties between equal-length overlapping spans: lower wins.
    pub priority: u8,
}

pub(crate) trait Detector: Send + Sync {
    fn find(&self, text: &str, out: &mut Vec<Candidate>);
}

// Priorities: the dictionary beats custom regex rules, which beat built-ins.
pub(crate) const P_DICTIONARY: u8 = 0;
pub(crate) const P_CUSTOM: u8 = 5;
pub(crate) const P_SECRET: u8 = 10;
pub(crate) const P_CARD: u8 = 11;
pub(crate) const P_IBAN: u8 = 12;
pub(crate) const P_NATID: u8 = 13;
pub(crate) const P_EMAIL: u8 = 14;
pub(crate) const P_URL: u8 = 15;
pub(crate) const P_IP: u8 = 16;
#[cfg(feature = "phone")]
pub(crate) const P_PHONE: u8 = 17;
pub(crate) const P_NER: u8 = 20;

pub(crate) fn build(rules: &RulesFile) -> Result<Vec<Box<dyn Detector>>, RulesError> {
    let d = &rules.detectors;
    let mut out: Vec<Box<dyn Detector>> = Vec::new();
    if !rules.dictionary.is_empty() {
        out.push(Box::new(dictionary::Dictionary::new(&rules.dictionary)?));
    }
    for rule in &rules.regex {
        out.push(Box::new(custom::Custom::new(rule)?));
    }
    if d.secret.enabled {
        out.push(Box::new(secret::Secret));
    }
    if d.card.enabled {
        out.push(Box::new(card::Card));
    }
    if d.iban.enabled {
        out.push(Box::new(iban::Iban));
    }
    if d.natid.enabled {
        out.push(Box::new(natid::NatId::new(&d.natid.options.locales)?));
    }
    if d.email.enabled {
        out.push(Box::new(email::Email));
    }
    if d.url.enabled {
        out.push(Box::new(url::Url));
    }
    if d.ip.enabled {
        out.push(Box::new(ip::Ip { include_private: d.ip.options.include_private }));
    }
    if d.phone.enabled {
        #[cfg(feature = "phone")]
        out.push(Box::new(phone::Phone::new(&d.phone.options.regions)?));
        #[cfg(not(feature = "phone"))]
        return Err(RulesError::NotBuiltIn("phone"));
    }
    Ok(out)
}

/// Keeps the longest span where candidates overlap; on equal length the lower
/// priority wins. Returns the kept spans in text order.
pub(crate) fn resolve(mut candidates: Vec<Candidate>) -> Vec<Candidate> {
    candidates.sort_by(|a, b| {
        (b.end - b.start).cmp(&(a.end - a.start)).then(a.priority.cmp(&b.priority)).then(a.start.cmp(&b.start))
    });
    let mut kept: Vec<Candidate> = Vec::new();
    for c in candidates {
        if c.start < c.end && kept.iter().all(|k| c.end <= k.start || c.start >= k.end) {
            kept.push(c);
        }
    }
    kept.sort_by_key(|k| k.start);
    kept
}

/// True if the character before `start` and the one at `end` are not
/// letters, digits or `_`, i.e. the span is a whole word.
pub(crate) fn word_bounded(text: &str, start: usize, end: usize) -> bool {
    let before = text[..start].chars().next_back();
    let after = text[end..].chars().next();
    let is_word = |c: char| c.is_alphanumeric() || c == '_';
    !before.is_some_and(is_word) && !after.is_some_and(is_word)
}

pub(crate) fn builtin(start: usize, end: usize, kind: &'static str, priority: u8) -> Candidate {
    Candidate { start, end, kind: EntityKind::builtin(kind), source: Source::BuiltIn, priority }
}

/// Luhn checksum over a string of ASCII digits.
pub(crate) fn luhn(digits: &str) -> bool {
    let mut sum = 0;
    for (i, b) in digits.bytes().rev().enumerate() {
        let mut d = u32::from(b - b'0');
        if i % 2 == 1 {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
    }
    sum % 10 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(start: usize, end: usize, priority: u8) -> Candidate {
        builtin(start, end, "EMAIL", priority)
    }

    #[test]
    fn longest_wins_then_priority() {
        let kept = resolve(vec![c(0, 5, 1), c(3, 12, 9), c(12, 14, 1), c(12, 14, 0)]);
        let spans: Vec<_> = kept.iter().map(|k| (k.start, k.end, k.priority)).collect();
        assert_eq!(spans, [(3, 12, 9), (12, 14, 0)]);
    }

    #[test]
    fn luhn_checks() {
        assert!(luhn("4111111111111111"));
        assert!(!luhn("4111111111111112"));
        assert!(luhn("378282246310005"));
    }

    #[test]
    fn word_bounds() {
        assert!(word_bounded("a acme b", 2, 6));
        assert!(!word_bounded("a acmes b", 2, 6));
        assert!(word_bounded("acme", 0, 4));
        assert!(word_bounded("(acme)", 1, 5));
    }
}
