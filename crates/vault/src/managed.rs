//! What an application needs from a vault besides redaction and restoration:
//! conversation scopes, scopes bound to IDs, and admin operations.

use std::collections::HashMap;
use std::sync::Mutex;

use veil_engine::{EntityKind, MemoryVault, ScopeId, Vault, VaultError};

use crate::{random_key, Error};

/// Counts for an admin screen. Never holds values.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VaultInfo {
    /// How many values it holds.
    pub entries: u64,
    /// Unix seconds of the oldest entry, if any.
    pub oldest_created_at: Option<i64>,
    /// True if entries survive a restart.
    pub persistent: bool,
}

/// A [`Vault`] an application manages. The engine only uses the [`Vault`]
/// part; these are the operations around it.
pub trait ManagedVault: Vault {
    /// A scope for a conversation, derived from `hint` with this vault's
    /// secret key (see [`ScopeId::keyed`]), so the scope reveals nothing
    /// about the conversation. The same hint gives the same scope for as
    /// long as the vault keeps its key.
    fn conversation_scope(&self, hint: &str) -> ScopeId;
    /// Remembers that `id` belongs to `scope`, for example a response the
    /// provider stores and the client later refers to by ID.
    fn bind_scope(&self, id: &str, scope: &ScopeId) -> Result<(), Error>;
    /// The scope `id` was bound to, if any.
    fn bound_scope(&self, id: &str) -> Result<Option<ScopeId>, Error>;
    /// Counts for an admin screen.
    fn info(&self) -> Result<VaultInfo, Error>;
    /// Deletes every entry and binding. Numbers already handed out are never
    /// given to another value.
    fn clear(&self) -> Result<(), Error>;
    /// Deletes entries not used within the time-to-live. Returns how many.
    fn purge_expired(&self) -> Result<u64, Error>;
    /// Copies every value of `from` into `into` under the same numbers, so
    /// placeholders made in `from` mean the same in `into`: for example a
    /// document redacted before its conversation had an ID. Only done while
    /// `into` has never handed out or reserved a number; otherwise copies
    /// nothing and returns false. The default copies nothing.
    fn adopt(&self, from: &ScopeId, into: &ScopeId) -> Result<bool, Error> {
        let _ = (from, into);
        Ok(false)
    }
}

/// A [`ManagedVault`] in memory: nothing touches disk and everything is lost
/// on restart. Its key for conversation scopes is new each time.
pub struct RamVault {
    vault: MemoryVault,
    key: [u8; 32],
    bound: Mutex<HashMap<String, ScopeId>>,
}

impl Default for RamVault {
    fn default() -> Self {
        RamVault { vault: MemoryVault::default(), key: random_key(), bound: Mutex::default() }
    }
}

impl Vault for RamVault {
    fn get_or_create(&self, scope: &ScopeId, kind: &EntityKind, value: &str) -> Result<u64, VaultError> {
        self.vault.get_or_create(scope, kind, value)
    }

    fn lookup(&self, scope: &ScopeId, kind: &EntityKind, n: u64) -> Result<Option<String>, VaultError> {
        self.vault.lookup(scope, kind, n)
    }

    fn reserve(&self, scope: &ScopeId, kind: &EntityKind, n: u64) -> Result<(), VaultError> {
        self.vault.reserve(scope, kind, n)
    }
}

impl ManagedVault for RamVault {
    fn conversation_scope(&self, hint: &str) -> ScopeId {
        ScopeId::keyed(&self.key, hint)
    }

    fn bind_scope(&self, id: &str, scope: &ScopeId) -> Result<(), Error> {
        self.bound.lock().map_err(|_| Error::Poisoned)?.insert(id.to_owned(), scope.clone());
        Ok(())
    }

    fn bound_scope(&self, id: &str) -> Result<Option<ScopeId>, Error> {
        Ok(self.bound.lock().map_err(|_| Error::Poisoned)?.get(id).cloned())
    }

    fn info(&self) -> Result<VaultInfo, Error> {
        Ok(VaultInfo {
            entries: self.vault.len() as u64,
            oldest_created_at: self.vault.oldest_created_at(),
            persistent: false,
        })
    }

    fn clear(&self) -> Result<(), Error> {
        self.vault.clear();
        self.bound.lock().map_err(|_| Error::Poisoned)?.clear();
        Ok(())
    }

    /// Entries in memory last only until restart, so none expire.
    fn purge_expired(&self) -> Result<u64, Error> {
        Ok(0)
    }

    fn adopt(&self, from: &ScopeId, into: &ScopeId) -> Result<bool, Error> {
        Ok(self.vault.adopt(from, into))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ram_vault() {
        let v = RamVault::default();
        let conv = v.conversation_scope("first message");
        assert!(conv.as_str().starts_with("conv:") && !conv.as_str().contains("first"));
        assert_eq!(conv, v.conversation_scope("first message"));
        assert_ne!(conv, RamVault::default().conversation_scope("first message"), "each has its own key");

        let kind = EntityKind::new("EMAIL").unwrap();
        v.get_or_create(&conv, &kind, "a@example.com").unwrap();
        v.bind_scope("resp_1", &conv).unwrap();
        assert_eq!(v.bound_scope("resp_1").unwrap(), Some(conv.clone()));
        let info = v.info().unwrap();
        assert_eq!((info.entries, info.persistent), (1, false));

        v.clear().unwrap();
        assert_eq!(v.info().unwrap().entries, 0);
        assert_eq!(v.bound_scope("resp_1").unwrap(), None);
        assert_eq!(v.get_or_create(&conv, &kind, "a@example.com").unwrap(), 2, "numbers are not reused");
    }

    #[test]
    fn ram_vault_adopt() {
        let v = RamVault::default();
        let (draft, chat) = (v.conversation_scope("draft"), v.conversation_scope("chat"));
        let kind = EntityKind::new("EMAIL").unwrap();
        v.get_or_create(&draft, &kind, "ana@example.org").unwrap();
        assert!(v.adopt(&draft, &chat).unwrap());
        assert_eq!(v.lookup(&chat, &kind, 1).unwrap().as_deref(), Some("ana@example.org"));
        assert!(!v.adopt(&draft, &chat).unwrap());
    }
}
