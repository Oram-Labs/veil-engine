# veil-engine

Finds sensitive values in text, replaces them with placeholders such as `[EMAIL_1]`, and puts the real values back into the reply. It is the redaction engine of [Veil](https://getveil.tech), which keeps personal data and secrets out of what you send to AI models.

```text
you write          Email ana@example.com about card 4111 1111 1111 1111
the model sees     Email [EMAIL_1] about card [CARD_1]
the model replies  I emailed [EMAIL_1].
you see            I emailed ana@example.com.
```

The engine does no file or network access and no logging. It only transforms the text and JSON you give it, so you can read all of it and check what it does. See [the threat model](https://github.com/Oram-Labs/veil-engine/blob/main/THREAT_MODEL.md) for what it protects against and what it doesn't.

## Redact and restore

```rust
use veil_engine::{Engine, ScopeId};

let engine = Engine::builder().build()?;
// Placeholders are numbered per scope: one conversation, profile or user.
let scope = ScopeId::new("chat-42");

let r = engine.redact_text(&scope, "Email ana@example.com about card 4111 1111 1111 1111")?;
assert_eq!(r.text, "Email [EMAIL_1] about card [CARD_1]");
assert_eq!(r.report.redacted, 2);

let back = engine.restore_text(&scope, "I emailed [EMAIL_1].");
assert_eq!(back.text, "I emailed ana@example.com.");
# Ok::<(), Box<dyn std::error::Error>>(())
```

The same value always gets the same placeholder in a scope, so a conversation stays consistent and a provider's prompt cache keeps working.

## Streamed replies

A placeholder can be split across chunks of a streamed reply. [`StreamRestorer`] holds back only the text that could still become a placeholder:

```rust
use veil_engine::{Engine, ScopeId, StreamRestorer};

let engine = Engine::builder().build()?;
let scope = ScopeId::new("chat-42");
engine.redact_text(&scope, "ana@example.com")?;

let mut restorer = StreamRestorer::default();
let mut out = String::new();
for chunk in ["Sent to [EMA", "IL_1], done."] {
    out += &restorer.push(&engine, &scope, chunk);
}
out += &restorer.finish(&engine, &scope);
assert_eq!(out, "Sent to ana@example.com, done.");
# Ok::<(), Box<dyn std::error::Error>>(())
```

## JSON request bodies

API requests mix content with structure such as model names and roles. A [`KeyPolicy`] says which keys hold content:

```rust
use serde_json::{json, Map, Value};
use veil_engine::{Engine, KeyAction, KeyPolicy, ScopeId};

struct Messages;

impl KeyPolicy for Messages {
    fn action(&self, _parent: &Map<String, Value>, key: &str) -> KeyAction {
        match key {
            "model" | "role" => KeyAction::Skip,
            _ => KeyAction::Walk,
        }
    }
}

let engine = Engine::builder().build()?;
let mut body = json!({
    "model": "some-model",
    "messages": [{"role": "user", "content": "Mail ana@example.com"}]
});
engine.redact_json(&ScopeId::new("chat-42"), &mut body, &Messages)?;
assert_eq!(body["messages"][0]["content"], "Mail [EMAIL_1]");
assert_eq!(body["model"], "some-model");
# Ok::<(), Box<dyn std::error::Error>>(())
```

`KeyAction::JsonString` handles strings that hold JSON themselves, such as tool-call arguments.

## Rules

What to detect is a [`RulesFile`], usually written as YAML:

```rust
use veil_engine::{Engine, RulesFile, ScopeId};

let rules: RulesFile = serde_yaml_ng::from_str(r#"
version: 1
detectors:
  phone: { enabled: true, regions: [GB, DE] }
  url: on
dictionary:
  - { term: "Project Halcyon", type: CODENAME, match_case: true }
regex:
  - { name: tickets, type: TICKET, pattern: '\bTCK-\d{6}\b' }
allowlist: [support@acme.com]
"#)?;

let engine = Engine::builder().rules(rules).build()?;
let r = engine.redact_text(&ScopeId::new("s"), "Project Halcyon, see TCK-004211, ask support@acme.com")?;
assert_eq!(r.text, "[CODENAME_1], see [TICKET_1], ask support@acme.com");
# Ok::<(), Box<dyn std::error::Error>>(())
```

Built-in detectors: email, phone, payment cards (Luhn-checked, known issuers), IBAN (checksum-checked), API keys and tokens, IP addresses, URLs (off by default), and national ID numbers for US, GB, DE, FR, ES, IT, NL, PL and RO. Names of people, organisations and places need a name-detection model, which you plug in through [`EntityRecognizer`]. The engine doesn't include one, since a model has to be loaded from disk.

## Where placeholders are kept

The engine asks a [`Vault`] which value each placeholder stands for. It needs three methods:

```rust
use veil_engine::{EntityKind, ScopeId, Vault, VaultError};

struct MyVault;

impl Vault for MyVault {
    fn get_or_create(&self, scope: &ScopeId, kind: &EntityKind, value: &str) -> Result<u64, VaultError> {
        todo!("the number for this value, creating one if it's new")
    }
    fn lookup(&self, scope: &ScopeId, kind: &EntityKind, n: u64) -> Result<Option<String>, VaultError> {
        todo!("the value behind number n, if known")
    }
    fn reserve(&self, scope: &ScopeId, kind: &EntityKind, n: u64) -> Result<(), VaultError> {
        todo!("never hand out number n for a new value")
    }
}
```

[`MemoryVault`] keeps everything in memory and is the default. The [`veil-vault`](https://docs.rs/veil-vault) crate stores values encrypted on disk, with the key in the OS keychain.

## Guarantees

Each of these has a test.

- Redacting and then restoring gives back the original text.
- The same input in the same scope gives the same output.
- Redacting already redacted text changes nothing.
- Restoring a stream gives the same text as restoring it whole, wherever the chunks split.
- A placeholder the user typed is never given to a real value.
- Scopes never share placeholders.
- If name detection is on but no model was given, redaction fails rather than send names.
- Reports, matches and errors never hold the values found.
- The engine does no file or network access and no logging.

## Showing which version runs

[`VERSION`] is the version of the engine compiled into a program, so an application can show which release it runs, for example on an About screen. `veil_vault::VERSION` does the same for the vault.

```rust
assert_eq!(veil_engine::VERSION, env!("CARGO_PKG_VERSION"));
```

## Cargo features

| Feature | Default | What it adds |
|---|---|---|
| `phone` | on | The phone number detector. Its number metadata is the largest part of the engine. Without it, rules that turn phone detection on fail to compile. |
| `schema` | off | `schemars::JsonSchema` for `RulesFile` and its parts, for editor autocompletion of rules files. |

## License

Apache-2.0.
