//! The value-to-placeholder mapping. The engine only needs this trait; the
//! encrypted on-disk implementation lives in the `veil-vault` crate.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

use crate::{EntityKind, ScopeId, VaultError};

/// Where the engine keeps which value each placeholder stands for.
///
/// These are the only three operations redaction and restoration need.
/// Storage, expiry and admin operations belong to the implementation; the
/// `veil-vault` crate has an encrypted one on disk.
pub trait Vault: Send + Sync {
    /// Returns the placeholder number for `value`, creating one if needed. The
    /// same value of the same kind in the same scope always gets the same number.
    fn get_or_create(&self, scope: &ScopeId, kind: &EntityKind, value: &str) -> Result<u64, VaultError>;
    /// Returns the value behind placeholder number `n`, if this scope knows it.
    fn lookup(&self, scope: &ScopeId, kind: &EntityKind, n: u64) -> Result<Option<String>, VaultError>;
    /// Makes sure number `n` is never handed out for a new value. Used for
    /// placeholder-shaped text the user wrote themselves.
    fn reserve(&self, scope: &ScopeId, kind: &EntityKind, n: u64) -> Result<(), VaultError>;
}

/// RAM-only vault: nothing touches disk and everything is lost on restart.
#[derive(Default)]
pub struct MemoryVault {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    by_value: HashMap<(ScopeId, EntityKind, String), u64>,
    by_number: HashMap<(ScopeId, EntityKind, u64), String>,
    counters: HashMap<(ScopeId, EntityKind), u64>,
    created: Vec<i64>,
}

impl MemoryVault {
    /// How many values it holds.
    pub fn len(&self) -> usize {
        self.lock().by_number.len()
    }

    /// True if it holds no values.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Unix seconds when the oldest value it holds was added.
    pub fn oldest_created_at(&self) -> Option<i64> {
        self.lock().created.iter().min().copied()
    }

    /// Forgets every value. Numbers already handed out are never given to
    /// another value, so an old placeholder can't restore to the wrong one.
    pub fn clear(&self) {
        let mut inner = self.lock();
        inner.by_value.clear();
        inner.by_number.clear();
        inner.created.clear();
    }

    /// Copies every value of `from` into `into` under the same numbers, so
    /// placeholders made in `from` mean the same in `into`. Only done while
    /// `into` has never handed out or reserved a number; otherwise copies
    /// nothing and returns false.
    pub fn adopt(&self, from: &ScopeId, into: &ScopeId) -> bool {
        let mut inner = self.lock();
        if from == into || inner.counters.keys().any(|(scope, _)| scope == into) {
            return false;
        }
        let counters: Vec<_> =
            inner.counters.iter().filter(|((s, _), _)| s == from).map(|((_, k), n)| (k.clone(), *n)).collect();
        let values: Vec<_> = inner
            .by_number
            .iter()
            .filter(|((s, _, _), _)| s == from)
            .map(|((_, k, n), v)| (k.clone(), *n, v.clone()))
            .collect();
        for (kind, n) in counters {
            inner.counters.insert((into.clone(), kind), n);
        }
        let now = now();
        for (kind, n, value) in values {
            inner.by_value.insert((into.clone(), kind.clone(), value.clone()), n);
            inner.by_number.insert((into.clone(), kind, n), value);
            inner.created.push(now);
        }
        true
    }

    /// A panic while holding the lock leaves the maps consistent (each
    /// change is a few inserts), so a poisoned lock is still usable.
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Vault for MemoryVault {
    fn get_or_create(&self, scope: &ScopeId, kind: &EntityKind, value: &str) -> Result<u64, VaultError> {
        let mut inner = self.lock();
        let key = (scope.clone(), kind.clone(), value.to_owned());
        if let Some(&n) = inner.by_value.get(&key) {
            return Ok(n);
        }
        let counter = inner.counters.entry((scope.clone(), kind.clone())).or_insert(0);
        *counter += 1;
        let n = *counter;
        inner.by_number.insert((scope.clone(), kind.clone(), n), value.to_owned());
        inner.by_value.insert(key, n);
        inner.created.push(now());
        Ok(n)
    }

    fn lookup(&self, scope: &ScopeId, kind: &EntityKind, n: u64) -> Result<Option<String>, VaultError> {
        Ok(self.lock().by_number.get(&(scope.clone(), kind.clone(), n)).cloned())
    }

    fn reserve(&self, scope: &ScopeId, kind: &EntityKind, n: u64) -> Result<(), VaultError> {
        let mut inner = self.lock();
        let counter = inner.counters.entry((scope.clone(), kind.clone())).or_insert(0);
        *counter = (*counter).max(n);
        Ok(())
    }
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clear_keeps_numbers_used() {
        let v = MemoryVault::default();
        let (scope, kind) = (ScopeId::new("s"), EntityKind::new("EMAIL").unwrap());
        assert_eq!(v.get_or_create(&scope, &kind, "a@example.com").unwrap(), 1);
        assert_eq!((v.len(), v.oldest_created_at().is_some()), (1, true));
        v.clear();
        assert!(v.is_empty() && v.oldest_created_at().is_none());
        assert_eq!(v.lookup(&scope, &kind, 1).unwrap(), None);
        assert_eq!(v.get_or_create(&scope, &kind, "a@example.com").unwrap(), 2);
    }

    #[test]
    fn adopt_copies_a_scope_into_an_unused_one() {
        let v = MemoryVault::default();
        let (draft, chat, other) = (ScopeId::new("draft"), ScopeId::new("chat"), ScopeId::new("other"));
        let email = EntityKind::new("EMAIL").unwrap();
        assert_eq!(v.get_or_create(&draft, &email, "ana@example.org").unwrap(), 1);
        assert_eq!(v.get_or_create(&draft, &email, "bob@example.org").unwrap(), 2);
        assert!(v.adopt(&draft, &chat));
        assert_eq!(v.lookup(&chat, &email, 2).unwrap().as_deref(), Some("bob@example.org"));
        // The same values keep their numbers, and new ones come after.
        assert_eq!(v.get_or_create(&chat, &email, "ana@example.org").unwrap(), 1);
        assert_eq!(v.get_or_create(&chat, &email, "cy@example.org").unwrap(), 3);
        // A scope that has handed out numbers is never written over.
        v.get_or_create(&other, &email, "cy@example.org").unwrap();
        assert!(!v.adopt(&draft, &other));
        assert_eq!(v.lookup(&other, &email, 2).unwrap(), None);
        assert!(!v.adopt(&draft, &chat));
        assert!(!v.adopt(&draft, &draft));
    }
}
