# Threat model: veil-engine and veil-vault

Oct 2026. Covers the two open-source crates. The Veil app around them (the local proxy, the desktop app, the browser extension) has its own risks, noted only where it decides how the engine is used.

## What they protect against

**Sending detected values to an AI provider by accident.** A person or a program sends text to a model. The engine replaces each value it detects with a placeholder before the text leaves, and puts the real values back into the reply on the user's machine. The provider sees `[EMAIL_1]`, never `ana@example.com`.

The engine is a safety net for mistakes, not a guarantee that nothing sensitive is sent.

## Who and what is trusted

| Party | Trusted? | Why |
|---|---|---|
| The user and their machine | Yes | The engine runs there. An attacker on the machine can read the text before it is redacted. |
| The application calling the engine | Yes | It sees all text in plain form, chooses the rules, and decides what to do when redaction fails. |
| A [`Vault`](crates/engine/src/vault.rs) or [`EntityRecognizer`](crates/engine/src/ner.rs) implementation | Yes | Each receives the values themselves. |
| A [`Recorder`](crates/engine/src/lib.rs) | Yes | It is told every value that matched, so an app can show recent matches. |
| The AI provider and the network to it | No | This is who the values are kept from. |
| The model's output | No | It can be steered by the prompt, by documents, or by a prompt injection. |

## Risks, and what limits them

### Values the rules don't detect

The engine only replaces what its detectors and rules find. It misses:

- values in formats no detector knows, such as an internal customer number, until a regex or dictionary rule covers it;
- values written in an unusual way, such as `ana at example dot com` or a card number split over two lines;
- names, unless name detection is on with a model, and even then some names (it is statistical);
- anything in images, audio or binary attachments. The engine works on text and JSON only.

**Limits:** dictionary and regex rules for an organisation's own terms; the detection test corpus in `fixtures/corpus`; `veil eval` for measuring detection. Apps should say clearly that redaction is best effort.

### What placeholders reveal

The provider can't see values but can see the shape of the text:

- the kinds of values (`[EMAIL_n]`, `[CARD_n]`);
- how many distinct values of each kind there are in a scope;
- which mentions are the same value, because a value keeps its placeholder within a scope;
- the words around each placeholder.

This is a deliberate trade: consistent placeholders let the model reason about the text, and keep the provider's prompt cache working. **Limits:** scopes. A per-conversation scope stops linking across conversations. Every placeholder names its kind; for dictionary and regex rules the kind name is the rule author's choice, so it can be a neutral one such as `TERM`.

### Restoring values the model chose

Restoration puts real values back wherever the model writes a known placeholder. The model never saw the values, but it can still use them:

- **Tool calls.** If a reply's tool call is restored, its arguments hold real values. A prompt injection (for example, hidden in a web page the model read) could make the model write `[SECRET_1]` into a command that sends it to an attacker, and restoring would turn that into the real secret. Restoring tool-call arguments is the calling application's choice; Veil exposes it as the `restore_tool_arguments` setting.
- **Unknown placeholders.** A placeholder the scope doesn't know (often one the model made up) is left as it is and counted in `Report::unknown_placeholders`. It never restores to a value from another scope.
- **Placeholders the user typed.** If the user's own text contains `[EMAIL_3]`, number 3 is reserved and never given to a real value, so the model can't turn the user's literal text into someone's address.

### Failing open

If redaction fails (the vault fails, or name detection is on without a model), the engine returns an error and does not return text. What happens next is up to the application: sending the original text instead would leak everything. Name detection turned on without a model is an error, not a silent skip, and so is a detector a build leaves out (`RulesError::NotBuiltIn`). Veil's proxy refuses the request unless the user turns off `fail_closed`.

### The vault at rest (veil-vault)

- Values are encrypted with AES-256-GCM, bound to their scope, kind and number. Lookups use an HMAC, so nothing is decrypted to search.
- Not encrypted: each entry's scope, kind, number and timestamps. Someone with the file learns, for example, that a scope holds three email addresses and when they were used, not which ones. Profile scopes are stored by name (`profile:default`); conversation scopes are keyed hashes and reveal nothing about the conversation.
- The master key is in the OS keychain, or in a key file with owner-only permissions. Anyone who can read both the key and the database file can read every value. On most systems that is any program running as the same user.
- Deleted entries are overwritten (SQLite `secure_delete`). Copies in backups, the SQLite write-ahead log before a checkpoint, or the file system's own history are outside the vault's control.

### Values in memory

Values exist in plain form in the process's memory while text is redacted or restored, and the vault keeps recently used values decrypted in a small cache. Memory is not cleared after use. An attacker who can read the process's memory, or a crash dump, can see them.

### Values in logs and errors

The engine has no logging, and its reports, matches, statistics and errors never contain the values found (`crates/engine/tests/guarantees.rs`). The calling application must take the same care with the text itself: Veil's proxy logs request bodies only after redaction, and only at debug level.

### Denial of service

Custom regex rules use the `regex` crate, which runs in linear time (no catastrophic backtracking), with each compiled pattern limited to 1 MB. Very large inputs take time proportional to their size; applications should limit request size (Veil's proxy has `max_body_mb`).

## Out of scope

- An attacker with access to the user's account or machine.
- A malicious vault, recognizer or recorder implementation, or a malicious application calling the engine.
- What the provider does with the redacted text.
- Side channels such as timing.

## Reporting a vulnerability

Please report it privately; see `SECURITY.md` in the repository. Don't open a public issue.
