use std::sync::LazyLock;

use regex::Regex;

use super::{builtin, Candidate, Detector, P_EMAIL};
use crate::kind::kinds::EMAIL;

static PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\b[a-z0-9._%+-]+@[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,24}\b",
    )
    .expect("valid email regex")
});

pub(super) struct Email;

impl Detector for Email {
    fn find(&self, text: &str, out: &mut Vec<Candidate>) {
        for m in PATTERN.find_iter(text) {
            out.push(builtin(m.start(), m.end(), EMAIL, P_EMAIL));
        }
    }
}
