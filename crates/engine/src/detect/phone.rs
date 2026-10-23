use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use phonenumber::country::Id;
use regex::Regex;

use super::{builtin, Candidate, Detector, P_PHONE};
use crate::kind::kinds::PHONE;
use crate::rules::RulesError;

static PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[+(]?\d[\d .()/\-]{5,22}\d").expect("valid phone regex"));

static DATE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:\d{4}[-/.]\d{1,2}[-/.]\d{1,2}|\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4})$").expect("valid date regex")
});

/// An ISO date at the start, e.g. the `2026-10-08 14` of a log timestamp.
static DATE_PREFIX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\d{4}-\d{2}-\d{2}(?:[ T]|$)").expect("valid date regex"));

pub(super) struct Phone {
    regions: Vec<Id>,
    /// Validation results by candidate text. Checking a number costs about
    /// 15 µs and clients resend the whole conversation on every request.
    seen: Mutex<HashMap<String, bool>>,
}

const SEEN_MAX: usize = 4096;

impl Phone {
    pub fn new(regions: &[String]) -> Result<Self, RulesError> {
        let regions = regions
            .iter()
            .map(|r| r.to_uppercase().parse::<Id>().map_err(|_| RulesError::Region(r.clone())))
            .collect::<Result<_, _>>()?;
        Ok(Phone { regions, seen: Mutex::default() })
    }

    fn valid(&self, s: &str) -> bool {
        if let Some(&v) = self.seen.lock().unwrap_or_else(|e| e.into_inner()).get(s) {
            return v;
        }
        let v = self.check(s);
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        if seen.len() >= SEEN_MAX {
            seen.clear();
        }
        seen.insert(s.to_owned(), v);
        v
    }

    fn check(&self, s: &str) -> bool {
        let digits = s.bytes().filter(u8::is_ascii_digit).count();
        if !(7..=15).contains(&digits) {
            return false;
        }
        // Dates and decimal numbers have the right shape but aren't numbers to dial.
        if DATE.is_match(s)
            || DATE_PREFIX.is_match(s)
            || (s.bytes().filter(|&b| b == b'.').count() == 1 && s.bytes().all(|b| b.is_ascii_digit() || b == b'.'))
        {
            return false;
        }
        let international = s.starts_with('+') || s.starts_with("00");
        let has_separator = s.bytes().any(|b| matches!(b, b' ' | b'-' | b'.' | b'(' | b')' | b'/'));
        // Bare digit runs are only phone numbers when they look dialled:
        // a leading 0 or an international prefix. Others are order numbers etc.
        if !international && !has_separator && !s.starts_with('0') {
            return false;
        }
        if international {
            let normalised = match s.strip_prefix("00") {
                Some(rest) => format!("+{rest}"),
                None => s.to_owned(),
            };
            return phonenumber::parse(None, &normalised).is_ok_and(|n| phonenumber::is_valid(&n));
        }
        // Version strings such as 2.1.294.611 have one-digit groups; dotted
        // phone numbers don't.
        if s.contains('.') && s.split(['.', ' ', '-']).any(|g| g.len() == 1) {
            return false;
        }
        let trunk = s.trim_start_matches('(').starts_with('0');
        self.regions.iter().any(|&r| {
            // Outside North America a nationally written number starts with
            // the trunk prefix 0. This keeps cron lines, dates and counts out.
            let plausible = match r {
                Id::US | Id::CA => digits == 10 || (digits == 11 && s.trim_start_matches('(').starts_with('1')),
                _ => trunk,
            };
            plausible && phonenumber::parse(Some(r), s).is_ok_and(|n| phonenumber::is_valid(&n))
        })
    }
}

impl Detector for Phone {
    fn find(&self, text: &str, out: &mut Vec<Candidate>) {
        for m in PATTERN.find_iter(text) {
            let (mut start, end) = (m.start(), m.end());
            let mut s = m.as_str();
            // An opening parenthesis is only part of the number if it closes inside it.
            if s.starts_with('(') && !s.contains(')') {
                start += 1;
                s = &s[1..];
            }
            let before = text[..start].chars().next_back();
            let after = text[end..].chars().next();
            if before.is_some_and(|c| c.is_alphanumeric() || matches!(c, '.' | '/' | '-' | '_' | '+'))
                || after.is_some_and(|c| c.is_alphanumeric() || c == '_')
                || (after == Some('.') && text[end + 1..].starts_with(|c: char| c.is_ascii_digit()))
            {
                continue;
            }
            if self.valid(s) {
                out.push(builtin(start, end, PHONE, P_PHONE));
            }
        }
    }
}
