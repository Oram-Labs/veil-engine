#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

use std::fs::OpenOptions;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use lru::LruCache;
use rusqlite::{params, Connection, OptionalExtension};
use sha2::Sha256;
use veil_engine::{EntityKind, ScopeId, Vault};

mod managed;
pub use managed::{ManagedVault, RamVault, VaultInfo};

/// This crate's version as compiled in, such as `"0.2.0"`, so an application
/// can show which release of it is running.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The 256-bit key everything in a vault is derived from.
pub type MasterKey = [u8; 32];

/// Why a vault operation failed.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The SQLite database failed.
    #[error("database: {0}")]
    Db(#[from] rusqlite::Error),
    /// The key file couldn't be read or written.
    #[error("key file {path}: {error}")]
    KeyFile {
        /// The key file.
        path: PathBuf,
        /// What went wrong.
        error: std::io::Error,
    },
    /// The key file isn't 32 bytes or 64 hex characters.
    #[error("key file {0} must hold 32 bytes or 64 hex characters")]
    KeyFormat(PathBuf),
    /// The OS keychain failed.
    #[error("keychain: {0}")]
    Keychain(String),
    /// The vault was created with another key.
    #[error("the vault was created with a different key; refusing to open it")]
    WrongKey,
    /// An entry didn't decrypt: it was damaged, or moved to another slot.
    #[error("decryption failed for a vault entry")]
    Decrypt,
    /// A file operation failed.
    #[error("{0}")]
    Io(#[from] std::io::Error),
    /// A thread panicked while holding the vault's lock.
    #[error("internal lock poisoned")]
    Poisoned,
}

impl From<Error> for veil_engine::VaultError {
    fn from(e: Error) -> Self {
        veil_engine::VaultError::new(e)
    }
}

/// Where the master key comes from.
#[derive(Clone, Debug)]
pub enum KeySource {
    /// The OS keychain: Keychain on macOS, Credential Manager on Windows,
    /// Secret Service (GNOME Keyring, KWallet) on Linux.
    Keychain {
        /// The item's service name, which the OS shows when it asks for access.
        service: String,
        /// The item's account name.
        account: String,
    },
    /// A file holding the key, for servers and containers. Created with
    /// owner-only permissions if missing.
    File(PathBuf),
}

/// The keychain item's service name, shown by the OS when it asks for access.
pub const KEYCHAIN_SERVICE: &str = "Veil";

impl KeySource {
    /// The keychain item Veil uses.
    pub fn default_keychain() -> Self {
        KeySource::Keychain { service: KEYCHAIN_SERVICE.into(), account: "vault-master-key".into() }
    }

    /// Reads the key, creating and storing a new random one on first use.
    pub fn load_or_create(&self) -> Result<MasterKey, Error> {
        match self {
            KeySource::Keychain { service, account } => {
                let entry = keyring::Entry::new(service, account).map_err(|e| Error::Keychain(e.to_string()))?;
                match entry.get_password() {
                    Ok(hex) => parse_hex(hex.trim()).ok_or_else(|| Error::Keychain("stored key is malformed".into())),
                    Err(keyring::Error::NoEntry) => {
                        let key = random_key();
                        entry.set_password(&to_hex(&key)).map_err(|e| Error::Keychain(e.to_string()))?;
                        Ok(key)
                    }
                    Err(e) => Err(Error::Keychain(e.to_string())),
                }
            }
            KeySource::File(path) => {
                let io = |error| Error::KeyFile { path: path.clone(), error };
                match std::fs::read(path) {
                    Ok(bytes) => {
                        if let Ok(key) = <MasterKey>::try_from(bytes.as_slice()) {
                            return Ok(key);
                        }
                        std::str::from_utf8(&bytes)
                            .ok()
                            .and_then(|s| parse_hex(s.trim()))
                            .ok_or_else(|| Error::KeyFormat(path.clone()))
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        let key = random_key();
                        if let Some(dir) = path.parent() {
                            std::fs::create_dir_all(dir).map_err(io)?;
                        }
                        let mut f = private_file(path).map_err(io)?;
                        std::io::Write::write_all(&mut f, to_hex(&key).as_bytes()).map_err(io)?;
                        Ok(key)
                    }
                    Err(e) => Err(io(e)),
                }
            }
        }
    }
}

struct Keys {
    enc: Aes256Gcm,
    mac: [u8; 32],
    scope: [u8; 32],
}

impl Keys {
    fn derive(master: &MasterKey) -> Self {
        let hk = Hkdf::<Sha256>::new(None, master);
        let mut enc = [0u8; 32];
        let mut mac = [0u8; 32];
        let mut scope = [0u8; 32];
        hk.expand(b"veil vault encryption v1", &mut enc).expect("32 bytes is a valid HKDF length");
        hk.expand(b"veil vault lookup v1", &mut mac).expect("32 bytes is a valid HKDF length");
        hk.expand(b"veil scope v1", &mut scope).expect("32 bytes is a valid HKDF length");
        Keys { enc: Aes256Gcm::new_from_slice(&enc).expect("32-byte key"), mac, scope }
    }

    fn mac(&self, parts: &[&[u8]]) -> Vec<u8> {
        let mut m = <Hmac<Sha256> as Mac>::new_from_slice(&self.mac).expect("HMAC accepts any key length");
        for p in parts {
            m.update(&(p.len() as u64).to_le_bytes());
            m.update(p);
        }
        m.finalize().into_bytes().to_vec()
    }
}

type ValueKey = (ScopeId, EntityKind, Vec<u8>);
type NumberKey = (ScopeId, EntityKind, u64);

struct Caches {
    by_value: LruCache<ValueKey, (u64, i64)>,
    by_number: LruCache<NumberKey, (String, i64)>,
}

/// How often `last_used_at` is written for an entry that keeps being used.
const TOUCH_INTERVAL: i64 = 3600;

/// An encrypted vault in a SQLite file. See the crate documentation for how
/// values are protected.
pub struct SqliteVault {
    conn: Mutex<Connection>,
    caches: Mutex<Caches>,
    keys: Keys,
    ttl: Duration,
    path: PathBuf,
}

impl SqliteVault {
    /// Opens or creates the vault at `path`. Fails if it was created with a
    /// different key, so a wrong key can never silently start a fresh mapping.
    pub fn open(path: &Path, master: &MasterKey, ttl: Duration) -> Result<Self, Error> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        if !path.exists() {
            private_file(path)?;
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA secure_delete = ON;
             CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value BLOB NOT NULL);
             CREATE TABLE IF NOT EXISTS entries (
               scope TEXT NOT NULL, kind TEXT NOT NULL, n INTEGER NOT NULL,
               value_mac BLOB NOT NULL, value_ct BLOB NOT NULL,
               created_at INTEGER NOT NULL, last_used_at INTEGER NOT NULL,
               PRIMARY KEY (scope, kind, value_mac));
             CREATE UNIQUE INDEX IF NOT EXISTS entries_n ON entries (scope, kind, n);
             CREATE INDEX IF NOT EXISTS entries_used ON entries (last_used_at);
             CREATE TABLE IF NOT EXISTS counters (
               scope TEXT NOT NULL, kind TEXT NOT NULL, last INTEGER NOT NULL, PRIMARY KEY (scope, kind));
             CREATE TABLE IF NOT EXISTS responses (
               id_mac BLOB PRIMARY KEY, scope TEXT NOT NULL, created_at INTEGER NOT NULL);",
        )?;
        let keys = Keys::derive(master);
        let check = keys.mac(&[b"veil key check"]);
        let stored: Option<Vec<u8>> =
            conn.query_row("SELECT value FROM meta WHERE key = 'key_check'", [], |r| r.get(0)).optional()?;
        match stored {
            Some(s) if s != check => return Err(Error::WrongKey),
            Some(_) => {}
            None => {
                conn.execute("INSERT INTO meta (key, value) VALUES ('key_check', ?1)", params![check])?;
            }
        }
        let cap = NonZeroUsize::new(4096).expect("non-zero");
        Ok(SqliteVault {
            conn: Mutex::new(conn),
            caches: Mutex::new(Caches { by_value: LruCache::new(cap), by_number: LruCache::new(cap) }),
            keys,
            ttl,
            path: path.to_owned(),
        })
    }

    /// The database file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn conn(&self) -> Result<MutexGuard<'_, Connection>, Error> {
        self.conn.lock().map_err(|_| Error::Poisoned)
    }

    fn caches(&self) -> Result<MutexGuard<'_, Caches>, Error> {
        self.caches.lock().map_err(|_| Error::Poisoned)
    }

    fn aad(scope: &ScopeId, kind: &EntityKind, n: u64) -> Vec<u8> {
        format!("{}\0{}\0{}", scope.as_str(), kind.as_str(), n).into_bytes()
    }

    fn encrypt(&self, scope: &ScopeId, kind: &EntityKind, n: u64, value: &str) -> Result<Vec<u8>, Error> {
        let mut nonce = [0u8; 12];
        getrandom::fill(&mut nonce).map_err(|e| Error::Io(std::io::Error::other(e.to_string())))?;
        let aad = Self::aad(scope, kind, n);
        let ct = self
            .keys
            .enc
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: value.as_bytes(), aad: &aad })
            .map_err(|_| Error::Decrypt)?;
        Ok([nonce.as_slice(), &ct].concat())
    }

    fn decrypt(&self, scope: &ScopeId, kind: &EntityKind, n: u64, blob: &[u8]) -> Result<String, Error> {
        if blob.len() < 12 {
            return Err(Error::Decrypt);
        }
        let aad = Self::aad(scope, kind, n);
        let plain = self
            .keys
            .enc
            .decrypt(Nonce::from_slice(&blob[..12]), Payload { msg: &blob[12..], aad: &aad })
            .map_err(|_| Error::Decrypt)?;
        String::from_utf8(plain).map_err(|_| Error::Decrypt)
    }

    fn touch(&self, conn: &Connection, scope: &ScopeId, kind: &EntityKind, n: u64, now: i64) -> Result<(), Error> {
        conn.execute(
            "UPDATE entries SET last_used_at = ?4 WHERE scope = ?1 AND kind = ?2 AND n = ?3 AND last_used_at < ?4 - ?5",
            params![scope.as_str(), kind.as_str(), n as i64, now, TOUCH_INTERVAL],
        )?;
        Ok(())
    }

    fn get_or_create_inner(&self, scope: &ScopeId, kind: &EntityKind, value: &str) -> Result<u64, Error> {
        let mac = self.keys.mac(&[scope.as_str().as_bytes(), kind.as_str().as_bytes(), value.as_bytes()]);
        let key = (scope.clone(), kind.clone(), mac.clone());
        let now = now();
        if let Some(&(n, touched)) = self.caches()?.by_value.get(&key) {
            if now - touched < TOUCH_INTERVAL {
                return Ok(n);
            }
        }
        let mut conn = self.conn()?;
        let tx = conn.transaction()?;
        let existing: Option<i64> = tx
            .query_row(
                "SELECT n FROM entries WHERE scope = ?1 AND kind = ?2 AND value_mac = ?3",
                params![scope.as_str(), kind.as_str(), mac],
                |r| r.get(0),
            )
            .optional()?;
        let n = match existing {
            Some(n) => {
                self.touch(&tx, scope, kind, n as u64, now)?;
                n as u64
            }
            None => {
                let n: i64 = tx.query_row(
                    "INSERT INTO counters (scope, kind, last) VALUES (?1, ?2, 1)
                     ON CONFLICT (scope, kind) DO UPDATE SET last = last + 1 RETURNING last",
                    params![scope.as_str(), kind.as_str()],
                    |r| r.get(0),
                )?;
                let ct = self.encrypt(scope, kind, n as u64, value)?;
                tx.execute(
                    "INSERT INTO entries (scope, kind, n, value_mac, value_ct, created_at, last_used_at)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
                    params![scope.as_str(), kind.as_str(), n, mac, ct, now],
                )?;
                n as u64
            }
        };
        tx.commit()?;
        let mut caches = self.caches()?;
        caches.by_value.put(key, (n, now));
        caches.by_number.put((scope.clone(), kind.clone(), n), (value.to_owned(), now));
        Ok(n)
    }

    fn lookup_inner(&self, scope: &ScopeId, kind: &EntityKind, n: u64) -> Result<Option<String>, Error> {
        let key = (scope.clone(), kind.clone(), n);
        let now = now();
        if let Some((v, touched)) = self.caches()?.by_number.get(&key) {
            if now - touched < TOUCH_INTERVAL {
                return Ok(Some(v.clone()));
            }
        }
        let conn = self.conn()?;
        let blob: Option<Vec<u8>> = conn
            .query_row(
                "SELECT value_ct FROM entries WHERE scope = ?1 AND kind = ?2 AND n = ?3",
                params![scope.as_str(), kind.as_str(), n as i64],
                |r| r.get(0),
            )
            .optional()?;
        let Some(blob) = blob else {
            return Ok(None);
        };
        let value = self.decrypt(scope, kind, n, &blob)?;
        self.touch(&conn, scope, kind, n, now)?;
        self.caches()?.by_number.put(key, (value.clone(), now));
        Ok(Some(value))
    }

    fn clear_caches(&self) -> Result<(), Error> {
        let mut c = self.caches()?;
        c.by_value.clear();
        c.by_number.clear();
        Ok(())
    }

    fn purge_before(&self, cutoff: i64) -> Result<u64, Error> {
        let conn = self.conn()?;
        let n = conn.execute("DELETE FROM entries WHERE last_used_at < ?1", params![cutoff])?;
        conn.execute("DELETE FROM responses WHERE created_at < ?1", params![cutoff])?;
        drop(conn);
        self.clear_caches()?;
        Ok(n as u64)
    }
}

impl Vault for SqliteVault {
    fn get_or_create(&self, scope: &ScopeId, kind: &EntityKind, value: &str) -> Result<u64, veil_engine::VaultError> {
        Ok(self.get_or_create_inner(scope, kind, value)?)
    }

    fn lookup(&self, scope: &ScopeId, kind: &EntityKind, n: u64) -> Result<Option<String>, veil_engine::VaultError> {
        Ok(self.lookup_inner(scope, kind, n)?)
    }

    fn reserve(&self, scope: &ScopeId, kind: &EntityKind, n: u64) -> Result<(), veil_engine::VaultError> {
        self.conn()?
            .execute(
                "INSERT INTO counters (scope, kind, last) VALUES (?1, ?2, ?3)
                 ON CONFLICT (scope, kind) DO UPDATE SET last = max(last, excluded.last)",
                params![scope.as_str(), kind.as_str(), n as i64],
            )
            .map_err(Error::from)?;
        Ok(())
    }
}

impl ManagedVault for SqliteVault {
    fn conversation_scope(&self, hint: &str) -> ScopeId {
        ScopeId::keyed(&self.keys.scope, hint)
    }

    // Bindings are in the `responses` table, keyed by an HMAC of the ID
    // under the label `response`: the names of earlier builds, kept so
    // existing vaults keep working.
    fn bind_scope(&self, id: &str, scope: &ScopeId) -> Result<(), Error> {
        let id_mac = self.keys.mac(&[b"response", id.as_bytes()]);
        self.conn()?.execute(
            "INSERT OR REPLACE INTO responses (id_mac, scope, created_at) VALUES (?1, ?2, ?3)",
            params![id_mac, scope.as_str(), now()],
        )?;
        Ok(())
    }

    fn bound_scope(&self, id: &str) -> Result<Option<ScopeId>, Error> {
        let id_mac = self.keys.mac(&[b"response", id.as_bytes()]);
        let scope: Option<String> = self
            .conn()?
            .query_row("SELECT scope FROM responses WHERE id_mac = ?1", params![id_mac], |r| r.get(0))
            .optional()?;
        Ok(scope.map(ScopeId::new))
    }

    fn info(&self) -> Result<VaultInfo, Error> {
        let (entries, oldest): (i64, Option<i64>) =
            self.conn()?
                .query_row("SELECT count(*), min(created_at) FROM entries", [], |r| Ok((r.get(0)?, r.get(1)?)))?;
        Ok(VaultInfo { entries: entries as u64, oldest_created_at: oldest, persistent: true })
    }

    fn clear(&self) -> Result<(), Error> {
        // Counters are kept, so cleared numbers are never handed out again.
        self.conn()?.execute_batch("DELETE FROM entries; DELETE FROM responses; VACUUM;")?;
        self.clear_caches()
    }

    fn purge_expired(&self) -> Result<u64, Error> {
        let cutoff = now() - self.ttl.as_secs() as i64;
        self.purge_before(cutoff)
    }
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64)
}

pub(crate) fn random_key() -> MasterKey {
    let mut key = [0u8; 32];
    getrandom::fill(&mut key).expect("system random source");
    key
}

fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn parse_hex(s: &str) -> Option<MasterKey> {
    if s.len() != 64 {
        return None;
    }
    let mut key = [0u8; 32];
    for (i, k) in key.iter_mut().enumerate() {
        *k = u8::from_str_radix(s.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(key)
}

/// Creates a new file readable and writable only by the current user.
fn private_file(path: &Path) -> std::io::Result<std::fs::File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    opts.open(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: Duration = Duration::from_secs(86_400);

    fn kind(s: &str) -> EntityKind {
        EntityKind::new(s).unwrap()
    }

    fn scope() -> ScopeId {
        ScopeId::profile("default")
    }

    fn open(dir: &tempfile::TempDir, key: &MasterKey) -> SqliteVault {
        SqliteVault::open(&dir.path().join("vault.db"), key, 7 * DAY).unwrap()
    }

    #[test]
    fn numbers_are_stable_and_survive_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let key = random_key();
        let v = open(&dir, &key);
        assert_eq!(v.get_or_create(&scope(), &kind("EMAIL"), "ana@example.com").unwrap(), 1);
        assert_eq!(v.get_or_create(&scope(), &kind("EMAIL"), "bob@example.com").unwrap(), 2);
        assert_eq!(v.get_or_create(&scope(), &kind("PHONE"), "+40 721 555 019").unwrap(), 1);
        assert_eq!(v.get_or_create(&scope(), &kind("EMAIL"), "ana@example.com").unwrap(), 1);
        drop(v);
        let v = open(&dir, &key);
        assert_eq!(v.get_or_create(&scope(), &kind("EMAIL"), "ana@example.com").unwrap(), 1);
        assert_eq!(v.lookup(&scope(), &kind("EMAIL"), 2).unwrap().as_deref(), Some("bob@example.com"));
        assert_eq!(v.get_or_create(&scope(), &kind("EMAIL"), "new@example.com").unwrap(), 3);
        assert_eq!(v.lookup(&ScopeId::profile("other"), &kind("EMAIL"), 1).unwrap(), None);
    }

    #[test]
    fn wrong_key_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        drop(open(&dir, &random_key()));
        let err = SqliteVault::open(&dir.path().join("vault.db"), &random_key(), DAY).err().unwrap();
        assert!(matches!(err, Error::WrongKey));
    }

    #[test]
    fn values_are_not_stored_in_plain_text() {
        let dir = tempfile::tempdir().unwrap();
        let v = open(&dir, &random_key());
        v.get_or_create(&scope(), &kind("EMAIL"), "canary-7f3a9c@example.com").unwrap();
        drop(v);
        for entry in std::fs::read_dir(dir.path()).unwrap() {
            let bytes = std::fs::read(entry.unwrap().path()).unwrap();
            assert!(!bytes.windows(13).any(|w| w == b"canary-7f3a9c"), "plain value found on disk");
        }
    }

    #[test]
    fn ciphertexts_are_bound_to_their_slot() {
        let dir = tempfile::tempdir().unwrap();
        let v = open(&dir, &random_key());
        v.get_or_create(&scope(), &kind("EMAIL"), "a@example.com").unwrap();
        v.get_or_create(&scope(), &kind("EMAIL"), "b@example.com").unwrap();
        // Swap the two ciphertexts on disk; decryption must fail rather than mix them up.
        {
            let c = v.conn.lock().unwrap();
            c.execute_batch(
                "UPDATE entries SET n = -1 WHERE n = 1; UPDATE entries SET n = 1 WHERE n = 2; UPDATE entries SET n = 2 WHERE n = -1;",
            )
            .unwrap();
        }
        v.clear_caches().unwrap();
        assert!(v.lookup(&scope(), &kind("EMAIL"), 1).is_err());
    }

    #[test]
    fn reserve_skips_numbers() {
        let dir = tempfile::tempdir().unwrap();
        let v = open(&dir, &random_key());
        v.reserve(&scope(), &kind("EMAIL"), 5).unwrap();
        v.reserve(&scope(), &kind("EMAIL"), 2).unwrap();
        assert_eq!(v.get_or_create(&scope(), &kind("EMAIL"), "a@example.com").unwrap(), 6);
    }

    #[test]
    fn purge_and_clear_keep_counters() {
        let dir = tempfile::tempdir().unwrap();
        let v = open(&dir, &random_key());
        v.get_or_create(&scope(), &kind("EMAIL"), "a@example.com").unwrap();
        v.bind_scope("resp_1", &scope()).unwrap();
        assert_eq!(v.purge_expired().unwrap(), 0);
        assert_eq!(v.purge_before(now() + 1).unwrap(), 1);
        assert_eq!(v.info().unwrap().entries, 0);
        assert_eq!(v.lookup(&scope(), &kind("EMAIL"), 1).unwrap(), None);
        assert_eq!(v.get_or_create(&scope(), &kind("EMAIL"), "a@example.com").unwrap(), 2);
        v.clear().unwrap();
        assert_eq!(v.info().unwrap().entries, 0);
        assert_eq!(v.get_or_create(&scope(), &kind("EMAIL"), "a@example.com").unwrap(), 3);
    }

    #[test]
    fn responses_and_conversation_scopes() {
        let dir = tempfile::tempdir().unwrap();
        let key = random_key();
        let v = open(&dir, &key);
        let conv = v.conversation_scope("system prompt + first message");
        assert!(conv.as_str().starts_with("conv:"));
        assert!(!conv.as_str().contains("system"));
        assert_eq!(conv, open(&tempfile::tempdir().unwrap(), &key).conversation_scope("system prompt + first message"));
        v.bind_scope("resp_abc", &conv).unwrap();
        assert_eq!(v.bound_scope("resp_abc").unwrap(), Some(conv));
        assert_eq!(v.bound_scope("resp_other").unwrap(), None);
    }

    #[test]
    fn key_file_is_created_once_and_private() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keys/vault.key");
        let a = KeySource::File(path.clone()).load_or_create().unwrap();
        let b = KeySource::File(path.clone()).load_or_create().unwrap();
        assert_eq!(a, b);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        std::fs::write(&path, "not a key").unwrap();
        assert!(matches!(KeySource::File(path).load_or_create(), Err(Error::KeyFormat(_))));
    }

    #[test]
    fn works_with_the_engine() {
        use std::sync::Arc;
        use veil_engine::Engine;
        let dir = tempfile::tempdir().unwrap();
        let key = random_key();
        let text = "Mail ana@example.com about card 4111 1111 1111 1111";
        let redacted = {
            let e = Engine::builder().vault(Arc::new(open(&dir, &key))).build().unwrap();
            e.redact_text(&scope(), text).unwrap().text
        };
        assert_eq!(redacted, "Mail [EMAIL_1] about card [CARD_1]");
        let e = Engine::builder().vault(Arc::new(open(&dir, &key))).build().unwrap();
        assert_eq!(e.restore_text(&scope(), &redacted).text, text);
    }
}
