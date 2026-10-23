//! Guarantees the README states that the other tests don't already cover.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::{json, Map, Value};
use veil_engine::{
    DictionaryEntry, Engine, Entity, EntityKind, EntityRecognizer, Error, KeyAction, KeyPolicy, RecognizerError,
    RulesFile, ScopeId, Setting, StreamRestorer, Vault, VaultError,
};

/// Values of every built-in kind, and a dictionary term.
const VALUES: &[&str] = &[
    "ana@example.com",
    "4111 1111 1111 1111",
    "GB82 WEST 1234 5698 7654 32",
    "+44 20 7946 0958",
    "sk-ant-api03-abcdefghijklmnopqrstuvwxyz",
    "203.0.113.7",
    "https://intranet.example/payroll",
    "Project Halcyon",
];

fn rules() -> RulesFile {
    let mut r = RulesFile::default();
    r.detectors.url = Setting::on();
    r.dictionary.push(DictionaryEntry { term: "Project Halcyon".into(), kind: "CODENAME".into(), match_case: true });
    r
}

/// Fails if `shown` contains any of the values, or a recognisable part of one.
fn assert_no_values(what: &str, shown: &str) {
    for v in VALUES {
        assert!(!shown.contains(v), "{what} shows {v:?}: {shown}");
        for part in v.split([' ', '@', '/', '.']).filter(|p| p.len() >= 5) {
            assert!(!shown.contains(part), "{what} shows part of {v:?} ({part:?}): {shown}");
        }
    }
}

struct Walk;

impl KeyPolicy for Walk {
    fn action(&self, _: &Map<String, Value>, _: &str) -> KeyAction {
        KeyAction::Walk
    }
}

#[test]
fn reports_matches_and_stats_never_hold_values() {
    let engine = Engine::builder().rules(rules()).build().unwrap();
    let scope = ScopeId::new("s");
    let text = VALUES.join(", ");

    let r = engine.redact_text(&scope, &text).unwrap();
    assert_eq!(r.report.redacted, VALUES.len(), "every value was found: {}", r.text);
    assert_no_values("redacted text", &r.text);
    assert_no_values("report", &format!("{:?}", r.report));
    for m in &r.matches {
        assert_no_values("match", &format!("{m:?}"));
    }
    assert_no_values("scan", &format!("{:?}", engine.scan(&text).unwrap()));

    let mut body = json!({"messages": [{"content": text}]});
    assert_no_values("JSON report", &format!("{:?}", engine.redact_json(&scope, &mut body, &Walk).unwrap()));
    let audit = json!({"messages": [{"content": text}]});
    assert_no_values("audit report", &format!("{:?}", engine.scan_json(&audit, &Walk).unwrap()));

    let restored = engine.restore_text(&scope, &r.text);
    assert_eq!(restored.text, text);
    assert_no_values("restore report", &format!("{:?}", restored.report));
    let mut stream = StreamRestorer::default();
    stream.push(&engine, &scope, &r.text);
    stream.finish(&engine, &scope);
    assert_no_values("stream report", &format!("{:?}", stream.report()));

    assert_no_values("cache stats", &format!("{:?}", engine.cache_stats()));
}

/// A vault and a recognizer that fail with a message of their own.
struct Failing;

impl Vault for Failing {
    fn get_or_create(&self, _: &ScopeId, _: &EntityKind, _: &str) -> Result<u64, VaultError> {
        Err(VaultError::new("disk full"))
    }
    fn lookup(&self, _: &ScopeId, _: &EntityKind, _: u64) -> Result<Option<String>, VaultError> {
        Err(VaultError::new("disk full"))
    }
    fn reserve(&self, _: &ScopeId, _: &EntityKind, _: u64) -> Result<(), VaultError> {
        Err(VaultError::new("disk full"))
    }
}

impl EntityRecognizer for Failing {
    fn recognize(&self, _: &str) -> Result<Vec<Entity>, RecognizerError> {
        Err(RecognizerError::new("model crashed"))
    }
}

#[test]
fn errors_never_hold_values() {
    let text = VALUES.join(", ");
    let scope = ScopeId::new("s");
    let shown = |e: Error| format!("{e} / {e:?}");

    let e = Engine::builder().rules(rules()).vault(Arc::new(Failing)).build().unwrap();
    let err = e.redact_text(&scope, &text).unwrap_err();
    assert!(matches!(err, Error::Vault(_)));
    assert_no_values("vault error", &shown(err));

    let mut ner = rules();
    ner.detectors.ner = Setting::on();
    let e = Engine::builder().rules(ner.clone()).recognizer(Arc::new(Failing)).build().unwrap();
    let err = e.redact_text(&scope, &text).unwrap_err();
    assert!(matches!(err, Error::Recognizer(_)));
    assert_no_values("recognizer error", &shown(err));

    let e = Engine::builder().rules(ner).build().unwrap();
    let err = e.redact_text(&scope, &text).unwrap_err();
    assert!(matches!(err, Error::RecognizerMissing));
    assert_no_values("missing model error", &shown(err));
}

/// The engine's own code: every `.rs` file under `src`, without its test module.
fn sources() -> Vec<(PathBuf, String)> {
    fn walk(dir: &Path, out: &mut Vec<(PathBuf, String)>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                let text = std::fs::read_to_string(&path).unwrap();
                let code = text.split("#[cfg(test)]").next().unwrap().to_owned();
                out.push((path, code));
            }
        }
    }
    let mut out = Vec::new();
    walk(&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"), &mut out);
    assert!(out.len() > 10, "found the sources");
    out
}

#[test]
fn the_engine_does_no_io_and_no_logging() {
    // Ways to reach files, the network, other processes, the environment or
    // the terminal, and logging. `std::net` is allowed only for parsing IP
    // addresses.
    let forbidden = [
        "std::fs",
        "std::process",
        "std::env",
        "std::os",
        "std::io",
        "TcpStream",
        "TcpListener",
        "UdpSocket",
        "ToSocketAddrs",
        "File::open",
        "File::create",
        "OpenOptions",
        "print!",
        "println!",
        "eprint!",
        "eprintln!",
        "dbg!",
        "tracing",
        "log::",
        "unsafe",
        "extern ",
    ];
    for (path, code) in sources() {
        for word in forbidden {
            assert!(!code.contains(word), "{} uses `{word}`", path.display());
        }
        for (i, line) in code.lines().enumerate().filter(|(_, l)| l.contains("std::net")) {
            let only_addresses = line
                .split("std::net::")
                .skip(1)
                .all(|rest| ["IpAddr", "Ipv4Addr", "Ipv6Addr", "{"].iter().any(|ok| rest.starts_with(ok)));
            assert!(only_addresses, "{}:{} uses std::net beyond IP addresses: {line}", path.display(), i + 1);
        }
    }

    // A new dependency could do I/O on the engine's behalf: review it, then
    // add it here. CI also checks the whole dependency tree.
    let manifest = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")).unwrap();
    let deps = manifest.split("[dependencies]").nth(1).unwrap().split("\n[").next().unwrap();
    let reviewed = [
        "aho-corasick",
        "arc-swap",
        "hmac",
        "lru",
        "phonenumber",
        "regex",
        "schemars",
        "serde",
        "serde_json",
        "sha2",
        "thiserror",
    ];
    for line in deps.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let name = line.split(['.', ' ', '=']).next().unwrap();
        assert!(reviewed.contains(&name), "new dependency `{name}`: check it does no I/O, then add it to the list");
    }
}
