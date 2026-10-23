use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};

use super::{word_bounded, Candidate, Detector, Source, P_DICTIONARY};
use crate::kind::EntityKind;
use crate::rules::{kind, DictionaryEntry, RulesError};

/// Exact terms such as client names and project codenames, matched as whole words.
///
/// Terms that ignore case are matched in one of two ways: ASCII terms on the
/// text as it is, and other terms (`Ștefan`, `Müller`) on a lowercased copy
/// of the text, so `ȘTEFAN` and `MÜLLER` match too.
pub(super) struct Dictionary {
    sensitive: Option<Automaton>,
    ascii_insensitive: Option<Automaton>,
    unicode_insensitive: Option<Automaton>,
}

struct Automaton {
    ac: AhoCorasick,
    kinds: Vec<EntityKind>,
}

impl Automaton {
    fn build(terms: Vec<String>, kinds: Vec<EntityKind>, ascii_case_insensitive: bool) -> Option<Self> {
        (!terms.is_empty()).then(|| Automaton {
            ac: AhoCorasickBuilder::new()
                .ascii_case_insensitive(ascii_case_insensitive)
                .match_kind(MatchKind::Standard)
                .build(&terms)
                .expect("dictionary automaton builds"),
            kinds,
        })
    }
}

impl Dictionary {
    pub fn new(entries: &[DictionaryEntry]) -> Result<Self, RulesError> {
        let mut sensitive = (Vec::new(), Vec::new());
        let mut ascii = (Vec::new(), Vec::new());
        let mut unicode = (Vec::new(), Vec::new());
        for (i, e) in entries.iter().enumerate() {
            let term = e.term.trim();
            if term.is_empty() {
                return Err(RulesError::EmptyTerm(i));
            }
            let (target, term) = match (e.match_case, term.is_ascii()) {
                (true, _) => (&mut sensitive, term.to_owned()),
                (false, true) => (&mut ascii, term.to_owned()),
                (false, false) => (&mut unicode, fold(term)),
            };
            target.0.push(term);
            target.1.push(kind(&e.kind)?);
        }
        Ok(Dictionary {
            sensitive: Automaton::build(sensitive.0, sensitive.1, false),
            ascii_insensitive: Automaton::build(ascii.0, ascii.1, true),
            unicode_insensitive: Automaton::build(unicode.0, unicode.1, false),
        })
    }
}

fn fold(s: &str) -> String {
    s.chars().flat_map(char::to_lowercase).collect()
}

fn push(text: &str, start: usize, end: usize, kind: &EntityKind, out: &mut Vec<Candidate>) {
    if word_bounded(text, start, end) {
        out.push(Candidate { start, end, kind: kind.clone(), source: Source::Dictionary, priority: P_DICTIONARY });
    }
}

impl Detector for Dictionary {
    fn find(&self, text: &str, out: &mut Vec<Candidate>) {
        for a in self.sensitive.iter().chain(self.ascii_insensitive.iter()) {
            for m in a.ac.find_overlapping_iter(text) {
                push(text, m.start(), m.end(), &a.kinds[m.pattern().as_usize()], out);
            }
        }
        if let Some(a) = &self.unicode_insensitive {
            // Lowercase the text, remembering where each folded byte came from.
            let mut folded = String::with_capacity(text.len());
            let mut origin: Vec<u32> = Vec::with_capacity(text.len() + 1);
            for (i, c) in text.char_indices() {
                if c.is_ascii() {
                    folded.push(c.to_ascii_lowercase());
                    origin.push(i as u32);
                    continue;
                }
                for l in c.to_lowercase() {
                    folded.push(l);
                    origin.extend(std::iter::repeat_n(i as u32, l.len_utf8()));
                }
            }
            origin.push(text.len() as u32);
            for m in a.ac.find_overlapping_iter(&folded) {
                let (start, end) = (origin[m.start()] as usize, origin[m.end()] as usize);
                // A match must cover whole characters of the original text.
                let starts_char = m.start() == 0 || origin[m.start() - 1] != origin[m.start()];
                if starts_char && start < end {
                    push(text, start, end, &a.kinds[m.pattern().as_usize()], out);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn find(entries: &[(&str, bool)], text: &str) -> Vec<String> {
        let entries: Vec<_> = entries
            .iter()
            .map(|&(t, c)| DictionaryEntry { term: t.into(), kind: "NAME".into(), match_case: c })
            .collect();
        let mut out = Vec::new();
        Dictionary::new(&entries).unwrap().find(text, &mut out);
        out.sort_by_key(|c| c.start);
        out.iter().map(|c| text[c.start..c.end].to_owned()).collect()
    }

    #[test]
    fn case_options() {
        assert_eq!(find(&[("Acme", false)], "ACME, acme and Acmes"), ["ACME", "acme"]);
        assert_eq!(find(&[("Acme", true)], "ACME, acme and Acme"), ["Acme"]);
        // Non-ASCII terms ignore case too, and offsets stay right.
        assert_eq!(
            find(&[("Ștefan Müller", false)], "Dear ȘTEFAN MÜLLER and ștefan müller,"),
            ["ȘTEFAN MÜLLER", "ștefan müller"]
        );
        assert_eq!(find(&[("Øresund", false)], "the ØRESUND bridge"), ["ØRESUND"]);
        assert_eq!(find(&[("straße", false)], "STRASSE oder Straße"), ["Straße"]);
        assert_eq!(find(&[("Ștefan", true)], "ȘTEFAN Ștefan"), ["Ștefan"]);
        assert_eq!(find(&[("Ana", false)], "Anaïs, ANA"), ["ANA"]);
    }
}
