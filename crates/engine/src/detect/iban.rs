use std::sync::LazyLock;

use regex::Regex;

use super::{builtin, Candidate, Detector, P_IBAN};
use crate::kind::kinds::IBAN;

static PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[A-Z]{2}[0-9]{2}(?: ?[A-Z0-9]){10,32}").expect("valid IBAN regex"));

/// IBAN length per country (ISO 13616 registry).
#[rustfmt::skip]
const LENGTHS: &[(&str, usize)] = &[
    ("AD", 24), ("AE", 23), ("AL", 28), ("AT", 20), ("AZ", 28), ("BA", 20), ("BE", 16), ("BG", 22),
    ("BH", 22), ("BI", 27), ("BR", 29), ("BY", 28), ("CH", 21), ("CR", 22), ("CY", 28), ("CZ", 24),
    ("DE", 22), ("DJ", 27), ("DK", 18), ("DO", 28), ("EE", 20), ("EG", 29), ("ES", 24), ("FI", 18),
    ("FK", 18), ("FO", 18), ("FR", 27), ("GB", 22), ("GE", 22), ("GI", 23), ("GL", 18), ("GR", 27),
    ("GT", 28), ("HR", 21), ("HU", 28), ("IE", 22), ("IL", 23), ("IQ", 23), ("IS", 26), ("IT", 27),
    ("JO", 30), ("KW", 30), ("KZ", 20), ("LB", 28), ("LC", 32), ("LI", 21), ("LT", 20), ("LU", 20),
    ("LV", 21), ("LY", 25), ("MC", 27), ("MD", 24), ("ME", 22), ("MK", 19), ("MN", 20), ("MR", 27),
    ("MT", 31), ("MU", 30), ("NI", 28), ("NL", 18), ("NO", 15), ("OM", 23), ("PK", 24), ("PL", 28),
    ("PS", 29), ("PT", 25), ("QA", 29), ("RO", 24), ("RS", 22), ("RU", 33), ("SA", 24), ("SC", 31),
    ("SD", 18), ("SE", 24), ("SI", 19), ("SK", 24), ("SM", 27), ("SO", 23), ("ST", 25), ("SV", 28),
    ("TL", 23), ("TN", 24), ("TR", 26), ("UA", 29), ("VA", 22), ("VG", 24), ("XK", 20), ("YE", 30),
];

pub(super) struct Iban;

impl Detector for Iban {
    fn find(&self, text: &str, out: &mut Vec<Candidate>) {
        for m in PATTERN.find_iter(text) {
            let s = m.as_str();
            let Some(&(_, len)) = LENGTHS.iter().find(|(c, _)| s.starts_with(c)) else {
                continue;
            };
            // Take exactly `len` characters (spaces don't count), so a following word isn't swallowed.
            let mut compact = String::with_capacity(len);
            let mut end = m.start();
            for (i, c) in s.char_indices() {
                if c == ' ' {
                    continue;
                }
                compact.push(c);
                end = m.start() + i + 1;
                if compact.len() == len {
                    break;
                }
            }
            let next = text[end..].chars().next();
            if compact.len() != len || next.is_some_and(|c| c.is_alphanumeric()) || !mod97(&compact) {
                continue;
            }
            out.push(builtin(m.start(), end, IBAN, P_IBAN));
        }
    }
}

fn mod97(iban: &str) -> bool {
    let rearranged = iban[4..].chars().chain(iban[..4].chars());
    let mut rem: u32 = 0;
    for c in rearranged {
        let v = match c {
            '0'..='9' => c as u32 - '0' as u32,
            'A'..='Z' => c as u32 - 'A' as u32 + 10,
            _ => return false,
        };
        rem = if v >= 10 { (rem * 100 + v) % 97 } else { (rem * 10 + v) % 97 };
    }
    rem == 1
}

#[cfg(test)]
mod tests {
    #[test]
    fn mod97_examples() {
        assert!(super::mod97("GB82WEST12345698765432"));
        assert!(!super::mod97("GB82WEST12345698765433"));
    }
}
