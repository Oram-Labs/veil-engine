# veil-vault

Encrypted storage for [veil-engine](https://docs.rs/veil-engine)'s placeholders: which real value each `[EMAIL_1]` stands for. It keeps them in a SQLite file, encrypted with a key from the OS keychain, so placeholders still restore after a restart and nothing readable is left on disk.

```rust
use std::sync::Arc;
use std::time::Duration;
use veil_engine::{Engine, ScopeId};
use veil_vault::{KeySource, ManagedVault, SqliteVault};

# let dir = tempfile::tempdir()?;
// The key is created on first use. KeySource::default_keychain() keeps it in
// the OS keychain; a key file suits servers and containers.
let key = KeySource::File(dir.path().join("vault.key")).load_or_create()?;
let ttl = Duration::from_secs(30 * 86_400); // forget values unused for 30 days
let vault = Arc::new(SqliteVault::open(&dir.path().join("vault.db"), &key, ttl)?);

let engine = Engine::builder().vault(vault.clone()).build()?;
let scope = vault.conversation_scope("conversation 42");
let r = engine.redact_text(&scope, "Email ana@example.com")?;
assert_eq!(r.text, "Email [EMAIL_1]");

// Days later, after a restart:
let vault = Arc::new(SqliteVault::open(&dir.path().join("vault.db"), &key, ttl)?);
let engine = Engine::builder().vault(vault.clone()).build()?;
let scope = vault.conversation_scope("conversation 42");
assert_eq!(engine.restore_text(&scope, "[EMAIL_1]").text, "ana@example.com");
# Ok::<(), Box<dyn std::error::Error>>(())
```

## How values are protected

- **Encryption.** Each value is encrypted with AES-256-GCM under a fresh random 96-bit nonce. Its scope, kind and number are bound in as associated data, so a ciphertext moved to another entry fails to decrypt instead of restoring the wrong value.
- **Lookups without decrypting.** Finding a value's existing placeholder uses an HMAC-SHA256 of the value, so nothing is decrypted to search.
- **Keys.** One 256-bit master key, in the OS keychain (Keychain on macOS, Credential Manager on Windows, Secret Service on Linux) or in a key file created with owner-only permissions. Three subkeys are derived from it with HKDF-SHA256: one to encrypt, one for lookups, and one for conversation scopes.
- **Wrong key.** Opening a vault with a different key fails, so a lost or changed key can never silently start a fresh mapping over the old one.
- **Deleting.** SQLite's `secure_delete` is on, so deleted entries are overwritten. [`ManagedVault::purge_expired`] deletes entries unused for longer than the time-to-live, and [`ManagedVault::clear`] deletes them all. Placeholder numbers are never reused after either, so an old placeholder can't restore to a different value.
- **Conversation scopes.** [`ManagedVault::conversation_scope`] derives a scope from a hint (a conversation's ID or first message) with a secret key, so the stored scope reveals nothing about the conversation.

What is not encrypted: each entry's scope, kind, number and timestamps. Someone with the file can see, for example, that a scope holds three email addresses, but not which ones. Recently used values are also kept decrypted in memory, in a small cache. See [the threat model](https://github.com/Oram-Labs/veil-engine/blob/main/THREAT_MODEL.md).

## Kinds of vault

| Type | Keeps values | Use |
|---|---|---|
| [`SqliteVault`] | On disk, encrypted | Placeholders that survive restarts |
| [`RamVault`] | In memory | Nothing written to disk; everything is forgotten on restart |

Both implement [`ManagedVault`], the engine's [`Vault`](veil_engine::Vault) plus conversation scopes, scopes bound to IDs (such as a stored response), counts, clearing and expiry.

## License

Apache-2.0.
