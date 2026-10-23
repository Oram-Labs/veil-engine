use std::sync::Arc;

use regex::{Regex, RegexBuilder};

use super::{Candidate, Detector, Source, P_CUSTOM};
use crate::kind::EntityKind;
use crate::rules::{kind, RegexRule, RulesError};

/// A user-defined regex rule.
pub(super) struct Custom {
    regex: Regex,
    kind: EntityKind,
    name: Arc<str>,
}

impl Custom {
    pub fn new(rule: &RegexRule) -> Result<Self, RulesError> {
        let regex = RegexBuilder::new(&rule.pattern)
            .size_limit(1 << 20)
            .build()
            .map_err(|e| RulesError::Regex { name: rule.name.clone(), error: e.to_string() })?;
        if regex.is_match("") {
            return Err(RulesError::Regex { name: rule.name.clone(), error: "the pattern matches empty text".into() });
        }
        Ok(Custom { regex, kind: kind(&rule.kind)?, name: rule.name.as_str().into() })
    }
}

impl Detector for Custom {
    fn find(&self, text: &str, out: &mut Vec<Candidate>) {
        for m in self.regex.find_iter(text) {
            out.push(Candidate {
                start: m.start(),
                end: m.end(),
                kind: self.kind.clone(),
                source: Source::Regex(self.name.clone()),
                priority: P_CUSTOM,
            });
        }
    }
}
