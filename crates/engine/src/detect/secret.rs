use std::collections::HashMap;
use std::sync::LazyLock;

use regex::{Regex, RegexSet};

use super::{builtin, Candidate, Detector, P_SECRET};
use crate::kind::kinds::SECRET;

/// Tokens with a recognisable prefix or shape.
const PATTERNS: &[&str] = &[
    r"sk-ant-[A-Za-z0-9_\-]{20,}",
    r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}",
    r"\bgh[pousr]_[A-Za-z0-9]{36,}",
    r"\bgithub_pat_[A-Za-z0-9_]{40,}",
    r"\bglpat-[A-Za-z0-9_\-]{20,}",
    r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
    r"\bxox[abposr]-[A-Za-z0-9\-]{10,}",
    r"\bAIza[0-9A-Za-z_\-]{35}",
    r"\b[rs]k_(?:live|test)_[0-9A-Za-z]{16,}",
    r"\bnpm_[A-Za-z0-9]{36}\b",
    r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}",
    r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z]+ )*PRIVATE KEY-----",
    r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+",
];

static SET: LazyLock<RegexSet> = LazyLock::new(|| RegexSet::new(PATTERNS).expect("valid secret regexes"));
static EACH: LazyLock<Vec<Regex>> =
    LazyLock::new(|| PATTERNS.iter().map(|p| Regex::new(p).expect("valid secret regex")).collect());

/// `key = value` assignments where the key names a secret. Only the value is redacted.
static ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?i)\b(?:api[_-]?key|secret(?:[_-]?key)?|access[_-]?key|client[_-]?secret|auth[_-]?token|token|passw(?:or)?d|pwd)["']?\s*[:=]\s*["']?([A-Za-z0-9_\-+/=.!@#$%^&*]{12,})"#,
    )
    .expect("valid assignment regex")
});

pub(super) struct Secret;

impl Detector for Secret {
    fn find(&self, text: &str, out: &mut Vec<Candidate>) {
        for i in SET.matches(text).iter() {
            for m in EACH[i].find_iter(text) {
                out.push(builtin(m.start(), m.end(), SECRET, P_SECRET));
            }
        }
        for c in ASSIGNMENT.captures_iter(text) {
            let v = c.get(1).expect("group 1 always matches");
            let value = v.as_str().trim_end_matches(['.', ',']);
            if value.len() >= 12 && entropy(value) >= 3.0 && !looks_like_placeholder(value) {
                out.push(builtin(v.start(), v.start() + value.len(), SECRET, P_SECRET));
            }
        }
    }
}

/// Template values such as `YOUR_API_KEY` or `<changeme>` are not secrets.
fn looks_like_placeholder(v: &str) -> bool {
    let lower = v.to_lowercase();
    v.bytes().all(|b| b.is_ascii_uppercase() || b == b'_')
        || ["your", "example", "changeme", "placeholder", "xxxx", "redacted"].iter().any(|w| lower.contains(w))
}

/// Shannon entropy in bits per character.
fn entropy(s: &str) -> f64 {
    let mut counts: HashMap<char, usize> = HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_default() += 1;
    }
    let n = s.chars().count() as f64;
    counts.values().map(|&c| c as f64 / n).map(|p| -p * p.log2()).sum()
}
