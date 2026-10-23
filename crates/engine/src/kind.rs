//! Entity kinds: the `TYPE` in a placeholder such as `[EMAIL_1]`.

use std::fmt;
use std::sync::Arc;

/// A kind of sensitive value. Built-in kinds are listed in [`kinds`]; custom
/// rules can define their own, such as `CLIENT` or `TICKET`.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EntityKind(Arc<str>);

/// Names of the built-in kinds.
pub mod kinds {
    /// Email addresses.
    pub const EMAIL: &str = "EMAIL";
    /// Phone numbers.
    pub const PHONE: &str = "PHONE";
    /// Payment card numbers.
    pub const CARD: &str = "CARD";
    /// International bank account numbers (IBANs).
    pub const IBAN: &str = "IBAN";
    /// API keys, tokens and similar secrets.
    pub const SECRET: &str = "SECRET";
    /// IPv4 and IPv6 addresses.
    pub const IP: &str = "IP";
    /// URLs.
    pub const URL: &str = "URL";
    /// National ID numbers, such as US Social Security numbers.
    pub const NATID: &str = "NATID";
    /// People's names, from name detection.
    pub const PERSON: &str = "PERSON";
    /// Organisation names, from name detection.
    pub const ORG: &str = "ORG";
    /// Place names, from name detection.
    pub const LOCATION: &str = "LOCATION";
}

/// A name that isn't a valid [`EntityKind`]. Holds the name.
#[derive(Debug, thiserror::Error)]
#[error("invalid type name {0:?}: use 1 to 32 characters A-Z, 0-9 and _, starting with a letter")]
pub struct InvalidKind(pub String);

impl EntityKind {
    /// Checks and wraps a kind name: 1 to 32 characters `A`-`Z`, `0`-`9` and `_`,
    /// starting with a letter.
    pub fn new(name: &str) -> Result<Self, InvalidKind> {
        let valid = (1..=32).contains(&name.len())
            && name.starts_with(|c: char| c.is_ascii_uppercase())
            && name.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
        if valid {
            Ok(EntityKind(name.into()))
        } else {
            Err(InvalidKind(name.to_owned()))
        }
    }

    pub(crate) fn builtin(name: &'static str) -> Self {
        EntityKind(name.into())
    }

    /// The kind's name, such as `EMAIL`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EntityKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_names() {
        assert!(EntityKind::new("EMAIL").is_ok());
        assert!(EntityKind::new("NATIONAL_ID2").is_ok());
        for bad in ["", "email", "1A", "A-B", "A B", &"A".repeat(33)] {
            assert!(EntityKind::new(bad).is_err(), "{bad}");
        }
    }
}
