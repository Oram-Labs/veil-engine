//! Remembers where the matches are in text the engine has scanned before.
//!
//! Chat clients resend the whole conversation on every turn, so almost all of
//! a request was scanned on the previous turn. Scanning depends only on the
//! rules and the text, not on the scope or the vault, so the result can be
//! reused for any conversation; placeholder numbers still come from the vault
//! on every request. Entries are keyed by a SHA-256 of the rules' identity and
//! the text, and hold only offsets and kinds: no text is kept.

use std::mem::size_of;
use std::sync::{Arc, Mutex};

use lru::LruCache;
use sha2::{Digest, Sha256};

use crate::{EntityKind, Match, Source};

/// Shorter text is scanned again: hashing it costs about as much.
pub(crate) const MIN_LEN: usize = 256;

/// Memory for cached scans, by default.
pub const DEFAULT_BUDGET: usize = 32 * 1024 * 1024;

/// What scanning one text found.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Scanned {
    pub matches: Vec<Match>,
    /// Placeholder-shaped text the user wrote: (kind, number).
    pub tokens: Vec<(EntityKind, u64)>,
}

impl Scanned {
    /// Roughly what the entry costs in memory, for the budget.
    fn cost(&self) -> usize {
        let names: usize = self
            .matches
            .iter()
            .map(|m| match &m.source {
                Source::Regex(name) => name.len(),
                _ => 0,
            })
            .sum();
        96 + self.matches.len() * size_of::<Match>() + names + self.tokens.len() * size_of::<(EntityKind, u64)>()
    }
}

/// How the cache is doing, for tests and diagnostics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ScanCacheStats {
    /// Scans held.
    pub entries: usize,
    /// Roughly how much memory they use, in bytes.
    pub bytes: usize,
    /// Scans answered from the cache.
    pub hits: u64,
    /// Scans that had to run in full.
    pub misses: u64,
}

pub(crate) struct ScanCache {
    budget: usize,
    inner: Mutex<Inner>,
}

struct Inner {
    map: LruCache<[u8; 32], (Arc<Scanned>, usize)>,
    bytes: usize,
    hits: u64,
    misses: u64,
}

impl ScanCache {
    /// A cache using up to `budget` bytes; 0 turns it off.
    pub fn new(budget: usize) -> Self {
        ScanCache { budget, inner: Mutex::new(Inner { map: LruCache::unbounded(), bytes: 0, hits: 0, misses: 0 }) }
    }

    pub fn enabled(&self) -> bool {
        self.budget > 0
    }

    pub fn key(rules_id: u64, text: &str) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(rules_id.to_le_bytes());
        h.update(text.as_bytes());
        h.finalize().into()
    }

    pub fn get(&self, key: &[u8; 32]) -> Option<Arc<Scanned>> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let found = g.map.get(key).map(|(s, _)| s.clone());
        match found {
            Some(_) => g.hits += 1,
            None => g.misses += 1,
        }
        found
    }

    pub fn put(&self, key: [u8; 32], scanned: Arc<Scanned>) {
        let cost = scanned.cost();
        if cost > self.budget {
            return;
        }
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((_, old)) = g.map.put(key, (scanned, cost)) {
            g.bytes -= old;
        }
        g.bytes += cost;
        while g.bytes > self.budget {
            match g.map.pop_lru() {
                Some((_, (_, c))) => g.bytes -= c,
                None => break,
            }
        }
    }

    pub fn clear(&self) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.map.clear();
        g.bytes = 0;
    }

    pub fn stats(&self) -> ScanCacheStats {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        ScanCacheStats { entries: g.map.len(), bytes: g.bytes, hits: g.hits, misses: g.misses }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kinds;

    fn scanned(n: usize) -> Arc<Scanned> {
        let kind = EntityKind::new(kinds::EMAIL).unwrap();
        let matches =
            (0..n).map(|i| Match { start: i, end: i + 1, kind: kind.clone(), source: Source::BuiltIn }).collect();
        Arc::new(Scanned { matches, tokens: Vec::new() })
    }

    #[test]
    fn keys_depend_on_the_rules_and_the_text() {
        assert_eq!(ScanCache::key(1, "abc"), ScanCache::key(1, "abc"));
        assert_ne!(ScanCache::key(1, "abc"), ScanCache::key(2, "abc"));
        assert_ne!(ScanCache::key(1, "abc"), ScanCache::key(1, "abd"));
    }

    #[test]
    fn counts_hits_and_misses() {
        let c = ScanCache::new(DEFAULT_BUDGET);
        let k = ScanCache::key(1, "x");
        assert!(c.get(&k).is_none());
        c.put(k, scanned(2));
        assert_eq!(c.get(&k).unwrap().matches.len(), 2);
        let s = c.stats();
        assert_eq!((s.entries, s.hits, s.misses), (1, 1, 1));
        assert_eq!(s.bytes, scanned(2).cost());
    }

    #[test]
    fn stays_within_the_budget_and_drops_the_least_recently_used() {
        let one = scanned(10).cost();
        let c = ScanCache::new(one * 3);
        let keys: Vec<_> = (0..3).map(|i| ScanCache::key(1, &i.to_string())).collect();
        for k in &keys {
            c.put(*k, scanned(10));
        }
        // Use the first, so the second is the least recently used.
        assert!(c.get(&keys[0]).is_some());
        c.put(ScanCache::key(1, "new"), scanned(10));
        assert!(c.stats().bytes <= one * 3);
        assert!(c.get(&keys[1]).is_none(), "least recently used goes first");
        assert!(c.get(&keys[0]).is_some());
        assert!(c.get(&keys[2]).is_some());
    }

    #[test]
    fn an_entry_larger_than_the_budget_is_not_kept() {
        let c = ScanCache::new(scanned(1).cost());
        c.put(ScanCache::key(1, "big"), scanned(1000));
        assert_eq!(c.stats().entries, 0);
    }

    #[test]
    fn replacing_an_entry_keeps_the_byte_count_right() {
        let c = ScanCache::new(DEFAULT_BUDGET);
        let k = ScanCache::key(1, "x");
        c.put(k, scanned(5));
        c.put(k, scanned(1));
        assert_eq!(c.stats().bytes, scanned(1).cost());
        c.clear();
        assert_eq!(c.stats(), ScanCacheStats { entries: 0, bytes: 0, hits: 0, misses: 0 });
    }
}
