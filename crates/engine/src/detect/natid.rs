//! National identity numbers, per locale.

use std::sync::LazyLock;

use regex::Regex;

use super::{builtin, word_bounded, Candidate, Detector, P_NATID};
use crate::kind::kinds::NATID;
use crate::rules::RulesError;

/// UK National Insurance number, e.g. `QQ 12 34 56 C`.
static GB: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z] ?\d{2} ?\d{2} ?\d{2} ?[A-D]\b").expect("valid NINO regex")
});
/// Romanian personal numeric code (CNP), 13 digits.
static RO: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b[1-9]\d{12}\b").expect("valid CNP regex"));
/// German tax identification number (Steuer-ID), 11 digits, optionally grouped 2-3-3-3.
static DE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b[1-9]\d(?: ?\d{3}){3}\b").expect("valid Steuer-ID regex"));

/// French social security number (NIR): 13 characters and a 2-digit key,
/// usually grouped `1 85 05 78 006 084 91`. Corsica uses 2A and 2B.
static FR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[12] ?\d{2} ?(?:0[1-9]|1[0-2]|[2-9]\d) ?(?:\d{2}|2[AB]) ?\d{3} ?\d{3} ?\d{2}\b")
        .expect("valid NIR regex")
});
/// Spanish DNI (8 digits and a letter) and NIE (X, Y or Z, 7 digits and a letter).
static ES: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(?:\d{8}|[XYZ]-?\d{7})-?[A-Z]\b").expect("valid DNI regex"));
/// Italian codice fiscale.
static IT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b[A-Z]{6}\d{2}[A-EHLMPR-T]\d{2}[A-Z]\d{3}[A-Z]\b").expect("valid codice fiscale regex")
});
/// Dutch citizen service number (BSN), 9 digits, optionally grouped 4.2.3.
static NL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b\d{4}\.?\d{2}\.?\d{3}\b").expect("valid BSN regex"));
/// Polish PESEL, 11 digits.
static PL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b\d{11}\b").expect("valid PESEL regex"));
/// US Social Security number, written with dashes only: bare 9-digit runs
/// are too often something else.
static US: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").expect("valid SSN regex"));

#[derive(Clone, Copy)]
enum Locale {
    Gb,
    Ro,
    De,
    Fr,
    Es,
    It,
    Nl,
    Pl,
    Us,
}

pub(super) struct NatId {
    locales: Vec<Locale>,
}

impl NatId {
    pub fn new(locales: &[String]) -> Result<Self, RulesError> {
        let locales = locales
            .iter()
            .map(|l| match l.to_uppercase().as_str() {
                "GB" | "UK" => Ok(Locale::Gb),
                "RO" => Ok(Locale::Ro),
                "DE" => Ok(Locale::De),
                "FR" => Ok(Locale::Fr),
                "ES" => Ok(Locale::Es),
                "IT" => Ok(Locale::It),
                "NL" => Ok(Locale::Nl),
                "PL" => Ok(Locale::Pl),
                "US" => Ok(Locale::Us),
                _ => Err(RulesError::Locale(l.clone())),
            })
            .collect::<Result<_, _>>()?;
        Ok(NatId { locales })
    }
}

impl Detector for NatId {
    fn find(&self, text: &str, out: &mut Vec<Candidate>) {
        for locale in &self.locales {
            let (re, check): (&Regex, fn(&str) -> bool) = match locale {
                Locale::Gb => (&GB, nino),
                Locale::Ro => (&RO, cnp),
                Locale::De => (&DE, steuer_id),
                Locale::Fr => (&FR, nir),
                Locale::Es => (&ES, dni),
                Locale::It => (&IT, codice_fiscale),
                Locale::Nl => (&NL, bsn),
                Locale::Pl => (&PL, pesel),
                Locale::Us => (&US, ssn),
            };
            for m in re.find_iter(text) {
                // 00000000T and the like pass some checksums but are dummies.
                let d = digits(m.as_str());
                if d.len() > 3 && d.iter().all(|&x| x == d[0]) {
                    continue;
                }
                if word_bounded(text, m.start(), m.end()) && check(m.as_str()) {
                    out.push(builtin(m.start(), m.end(), NATID, P_NATID));
                }
            }
        }
    }
}

fn nino(s: &str) -> bool {
    !matches!(&s[..2], "BG" | "GB" | "NK" | "KN" | "TN" | "NT" | "ZZ")
}

fn cnp(s: &str) -> bool {
    let d: Vec<u32> = s.bytes().map(|b| u32::from(b - b'0')).collect();
    let month = d[3] * 10 + d[4];
    let day = d[5] * 10 + d[6];
    let county = d[7] * 10 + d[8];
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || !(1..=52).contains(&county) && county != 70 {
        return false;
    }
    const WEIGHTS: [u32; 12] = [2, 7, 9, 1, 4, 6, 3, 5, 8, 2, 7, 9];
    let sum: u32 = d.iter().zip(WEIGHTS).map(|(a, w)| a * w).sum();
    let check = match sum % 11 {
        10 => 1,
        r => r,
    };
    check == d[12]
}

fn steuer_id(s: &str) -> bool {
    let d: Vec<u32> = s.bytes().filter(u8::is_ascii_digit).map(|b| u32::from(b - b'0')).collect();
    if d.len() != 11 {
        return false;
    }
    // In the first ten digits exactly one digit repeats (twice or three times).
    let mut counts = [0u8; 10];
    for &x in &d[..10] {
        counts[x as usize] += 1;
    }
    let repeated = counts.iter().filter(|&&c| c >= 2).count();
    if repeated != 1 || counts.iter().any(|&c| c > 3) {
        return false;
    }
    // ISO 7064 MOD 11,10.
    let mut product = 10;
    for &x in &d[..10] {
        let mut sum = (x + product) % 10;
        if sum == 0 {
            sum = 10;
        }
        product = (sum * 2) % 11;
    }
    let check = match 11 - product {
        10 => 0,
        c => c,
    };
    check == d[10]
}

fn digits(s: &str) -> Vec<u32> {
    s.bytes().filter(u8::is_ascii_digit).map(|b| u32::from(b - b'0')).collect()
}

fn nir(s: &str) -> bool {
    let compact: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    // Corsican departments 2A and 2B count as 19 and 18 for the key.
    let numeric = compact[..13].replace("2A", "19").replace("2B", "18");
    let (Ok(n), Ok(key)) = (numeric.parse::<u64>(), compact[13..].parse::<u64>()) else { return false };
    key == 97 - n % 97
}

fn dni(s: &str) -> bool {
    const LETTERS: &[u8; 23] = b"TRWAGMYFPDXBNJZSQVHLCKE";
    let compact: String = s.chars().filter(|&c| c != '-').collect();
    let (body, letter) = compact.split_at(compact.len() - 1);
    let body = match body.as_bytes()[0] {
        b'X' => format!("0{}", &body[1..]),
        b'Y' => format!("1{}", &body[1..]),
        b'Z' => format!("2{}", &body[1..]),
        _ => body.to_owned(),
    };
    body.parse::<usize>().is_ok_and(|n| LETTERS[n % 23] == letter.as_bytes()[0])
}

fn codice_fiscale(s: &str) -> bool {
    const ODD: [u32; 36] = [
        1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 2, 4, 18, 20, 11, 3, 6, 8, 12, 14, 16,
        10, 22, 25, 24, 23,
    ];
    // Characters in odd positions (1st, 3rd, ...) use the table; in even
    // positions digits count as 0-9 and letters as 0-25.
    let b = s.as_bytes();
    let sum: u32 = b[..15]
        .iter()
        .enumerate()
        .map(|(i, &c)| match (i % 2 == 0, c.is_ascii_digit()) {
            (true, true) => ODD[usize::from(c - b'0')],
            (true, false) => ODD[usize::from(c - b'A') + 10],
            (false, true) => u32::from(c - b'0'),
            (false, false) => u32::from(c - b'A'),
        })
        .sum();
    b[15] == b'A' + (sum % 26) as u8
}

fn bsn(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 9 || d.iter().all(|&x| x == d[0]) {
        return false;
    }
    let sum: i64 = d[..8].iter().enumerate().map(|(i, &x)| (9 - i as i64) * x as i64).sum::<i64>() - d[8] as i64;
    sum % 11 == 0
}

fn pesel(s: &str) -> bool {
    let d = digits(s);
    // Month carries the century: +80 for 1800s, +0, +20, +40, +60 after.
    let month = (d[2] * 10 + d[3]) % 20;
    let day = d[4] * 10 + d[5];
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return false;
    }
    const W: [u32; 10] = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3];
    let sum: u32 = d.iter().zip(W).map(|(a, w)| a * w).sum();
    (10 - sum % 10) % 10 == d[10]
}

fn ssn(s: &str) -> bool {
    let area = &s[..3];
    area != "000" && area != "666" && !area.starts_with('9') && &s[4..6] != "00" && &s[7..] != "0000"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_locales() {
        assert!(nir("185057800608491") && nir("1 85 05 78 006 084 91") && nir("285052A00608482"));
        assert!(!nir("185057800608492"));
        assert!(dni("12345678Z") && dni("12345678-Z") && dni("X1234567L") && dni("Y7654321G"));
        assert!(!dni("12345678A"));
        assert!(codice_fiscale("RSSMRA85T10A562S") && codice_fiscale("BNCGLI90A41H501E"));
        assert!(!codice_fiscale("RSSMRA85T10A562T"));
        assert!(bsn("111222333") && bsn("123456782") && bsn("1234.56.782"));
        assert!(!bsn("123456789") && !bsn("000000000"));
        assert!(pesel("44051401359") && pesel("02070803628"));
        assert!(!pesel("44051401358") && !pesel("44151401359"));
        assert!(ssn("536-22-1234"));
        assert!(!ssn("000-22-1234") && !ssn("666-22-1234") && !ssn("912-22-1234") && !ssn("536-00-1234"));
    }

    #[test]
    fn checksums() {
        assert!(cnp("1800101420010"));
        assert!(!cnp("1800101420011"));
        assert!(steuer_id("86095742719"));
        assert!(!steuer_id("86095742718"));
        assert!(nino("QQ123456C") && !nino("GB123456A"));
    }
}
