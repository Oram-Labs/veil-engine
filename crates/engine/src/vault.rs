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
}
