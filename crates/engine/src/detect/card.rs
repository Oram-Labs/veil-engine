use std::sync::LazyLock;

use regex::Regex;

use super::{builtin, luhn, word_bounded, Candidate, Detector, P_CARD};
use crate::kind::kinds::CARD;

static PATTERN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\d(?:[ \-]?\d){12,18}").expect("valid card regex"));

pub(super) struct Card;

impl Detector for Card {
    fn find(&self, text: &str, out: &mut Vec<Candidate>) {
        for m in PATTERN.find_iter(text) {
            if !word_bounded(text, m.start(), m.end()) {
                continue;
            }
            let digits: String = m.as_str().chars().filter(char::is_ascii_digit).collect();
            if luhn(&digits) && known_issuer(&digits) {
                out.push(builtin(m.start(), m.end(), CARD, P_CARD));
            }
        }
    }
}

/// Checks the issuer prefix and length against the major card networks.
fn known_issuer(d: &str) -> bool {
    let n = d.len();
    let p = |k: usize| d[..k].parse::<u32>().unwrap_or(0);
    let visa = d.starts_with('4') && matches!(n, 13 | 16 | 19);
    let mastercard = ((51..=55).contains(&p(2)) || (2221..=2720).contains(&p(4))) && n == 16;
    let amex = matches!(p(2), 34 | 37) && n == 15;
    let discover =
        (d.starts_with("6011") || d.starts_with("65") || (644..=649).contains(&p(3))) && (16..=19).contains(&n);
    let jcb = (3528..=3589).contains(&p(4)) && (16..=19).contains(&n);
    let diners = (matches!(p(2), 36 | 38 | 39) || (300..=305).contains(&p(3))) && (14..=19).contains(&n);
    let unionpay = d.starts_with("62") && (16..=19).contains(&n);
    let maestro =
        matches!(p(4), 5018 | 5020 | 5038 | 5893 | 6304 | 6759 | 6761 | 6762 | 6763) && (12..=19).contains(&n);
    visa || mastercard || amex || discover || jcb || diners || unionpay || maestro
}
