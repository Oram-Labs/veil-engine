//! The engine's fast paths must never change what is redacted: the scan
//! cache (reusing the scan of text seen on an earlier turn) and looking each
//! value up once per request. Most tests run the same traffic through an
//! engine with the cache and one without, and require identical results.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use veil_engine::{
    CompiledRules, DictionaryEntry, Engine, EntityKind, MemoryVault, Options, Recorder, Report, RulesFile, ScopeId,
    Vault, VaultError, WalkAll,
};

fn rules() -> RulesFile {
    let mut r = RulesFile::default();
    r.dictionary.push(DictionaryEntry { term: "Project Halcyon".into(), kind: "CODENAME".into(), match_case: false });
    r
}

fn compiled(r: &RulesFile) -> CompiledRules {
    CompiledRules::compile(r, &Options::default(), None).unwrap()
}

fn cached() -> Engine {
    Engine::builder().rules(rules()).build().unwrap()
}

fn uncached() -> Engine {
    Engine::builder().rules(rules()).scan_cache_bytes(0).build().unwrap()
}

/// Long enough to be cached (the cache skips short strings).
fn long(s: &str) -> String {
    format!("{s} {}", "Nothing sensitive in this filler sentence about the build. ".repeat(6))
}

/// Turn `i` of a conversation, with a mix of values, repeats, Unicode and
/// placeholder-shaped text the user typed.
fn turn(i: usize) -> String {
    let extra = match i % 5 {
        0 => "Ping ana@example.com again, and ana@example.com once more.".to_owned(),
        1 => format!("Server 203.0.113.{} and 2001:db8::{:x} are down.", i % 250 + 1, i + 1),
        2 => "Call +44 20 7946 0958 about Project Halcyon (prøject façade ✓).".to_owned(),
        3 => "I typed [EMAIL_7] myself; also see bo@example.org.".to_owned(),
        _ => "Plain text only.".to_owned(),
    };
    long(&format!("Turn {i}: write to dev{}@example.com. {extra}", i % 7))
}

fn conversation(turns: usize) -> Value {
    let messages: Vec<Value> = (0..turns)
        .map(|i| {
            let role = if i % 2 == 0 { "user" } else { "assistant" };
            json!({"role": role, "content": [{"type": "text", "text": turn(i)}], "meta": {"short": "x@y.co"}})
        })
        .collect();
    json!({"system": long("System prompt, owner ops@example.com."), "messages": messages})
}

fn redact(e: &Engine, scope: &ScopeId, body: &Value) -> (Value, Report) {
    let mut b = body.clone();
    let report = e.redact_json(scope, &mut b, &WalkAll).unwrap();
    (b, report)
}

#[test]
fn a_growing_conversation_is_redacted_exactly_as_without_the_cache() {
    let (a, b) = (cached(), uncached());
    let scope = ScopeId::profile("t");
    for n in 1..=40 {
        let body = conversation(n);
        assert_eq!(redact(&a, &scope, &body), redact(&b, &scope, &body), "turn {n}");
    }
    let s = a.cache_stats();
    assert!(s.hits > 500, "earlier turns are reused: {s:?}");
    assert_eq!(b.cache_stats().entries, 0, "a budget of 0 turns the cache off");
}

#[test]
fn each_turn_only_scans_what_is_new() {
    let e = cached();
    let scope = ScopeId::profile("t");
    redact(&e, &scope, &conversation(10));
    let before = e.cache_stats();
    redact(&e, &scope, &conversation(11));
    let after = e.cache_stats();
    // One new message; the system prompt and ten old messages are hits.
    assert_eq!(after.misses - before.misses, 1);
    assert_eq!(after.hits - before.hits, 11);
}

#[test]
fn a_cached_scan_is_reused_across_conversations_with_their_own_numbers() {
    let e = cached();
    let (a, b) = (ScopeId::profile("a"), ScopeId::profile("b"));
    // Give scope b a different numbering first.
    e.redact_text(&b, "first carol@example.com").unwrap();
    let text = long("Write to ana@example.com.");
    let in_a = e.redact_text(&a, &text).unwrap().text;
    let in_b = e.redact_text(&b, &text).unwrap().text;
    assert!(in_a.contains("[EMAIL_1]") && !in_a.contains("ana@"), "{in_a}");
    assert!(in_b.contains("[EMAIL_2]") && !in_b.contains("ana@"), "{in_b}");
    assert!(e.cache_stats().hits >= 1);
    // Each scope restores its own placeholder.
    assert_eq!(e.restore_text(&a, "[EMAIL_1]").text, "ana@example.com");
    assert_eq!(e.restore_text(&b, "[EMAIL_2]").text, "ana@example.com");
    assert_eq!(e.restore_text(&b, "[EMAIL_1]").text, "carol@example.com");
}

/// The same steps with the cache and without; returns both engines' output.
fn with_and_without(steps: impl Fn(&Engine, &MemoryVault) -> Vec<String>) -> (Vec<String>, Vec<String>) {
    let (va, vb) = (Arc::new(MemoryVault::default()), Arc::new(MemoryVault::default()));
    let a = Engine::builder().vault(va.clone()).rules(rules()).build().unwrap();
    let b = Engine::builder().vault(vb.clone()).rules(rules()).scan_cache_bytes(0).build().unwrap();
    (steps(&a, &va), steps(&b, &vb))
}

#[test]
fn after_the_vault_is_cleared_a_cached_scan_gets_numbers_from_the_vault_again() {
    let scope = ScopeId::profile("t");
    let text = long("Mail zed@example.com and ana@example.com.");
    let (cached, plain) = with_and_without(|e, vault| {
        let mut out = vec![e.redact_text(&scope, &long("Mail bo@example.com first.")).unwrap().text];
        out.push(e.redact_text(&scope, &text).unwrap().text);
        vault.clear();
        let after = e.redact_text(&scope, &text).unwrap().text;
        // The cleared numbers are not reused, and the new ones restore.
        assert!(!after.contains("[EMAIL_1]") && !after.contains("[EMAIL_2]"), "{after}");
        assert_eq!(e.restore_text(&scope, &after).text, text);
        out.push(after);
        out
    });
    assert_eq!(cached, plain);
}

#[test]
fn changing_the_rules_drops_cached_scans() {
    let e = cached();
    let scope = ScopeId::profile("t");
    let text = long("Mail ana@example.com about Project Halcyon.");
    assert!(e.redact_text(&scope, &text).unwrap().text.contains("[EMAIL_"));
    assert_eq!(e.cache_stats().entries, 1);

    let mut no_email = rules();
    no_email.detectors.email.enabled = false;
    e.set_rules(compiled(&no_email));
    assert_eq!(e.cache_stats().entries, 0);
    let out = e.redact_text(&scope, &text).unwrap().text;
    assert!(out.contains("ana@example.com") && out.contains("[CODENAME_1]"), "{out}");

    let mut allowed = rules();
    allowed.allowlist.push("example.com".into());
    e.set_rules(compiled(&allowed));
    let out = e.redact_text(&scope, &text).unwrap().text;
    assert!(out.contains("ana@example.com"), "the new allowlist applies at once: {out}");
}

#[test]
fn placeholders_the_user_typed_stay_reserved_on_cached_scans() {
    let scope = ScopeId::profile("t");
    let text = long("I wrote [EMAIL_9] myself. Real one: ana@example.com.");
    let (cached, plain) = with_and_without(|e, vault| {
        let first = e.redact_text(&scope, &text).unwrap().text;
        vault.clear();
        // Typed after the clear; the real value must not take [EMAIL_9] or below.
        let second = e.redact_text(&scope, &text).unwrap().text;
        vec![first, second]
    });
    assert_eq!(cached, plain);
    for out in &cached {
        assert!(out.contains("[EMAIL_9] myself") && !out.contains("ana@"), "{out}");
        assert!(!out.contains("Real one: [EMAIL_9]") && !out.contains("Real one: [EMAIL_1]"), "{out}");
    }
}

#[test]
fn short_strings_are_scanned_every_time_and_not_kept() {
    let e = cached();
    let scope = ScopeId::profile("t");
    for _ in 0..3 {
        assert!(e.redact_text(&scope, "mail ana@example.com").unwrap().text.contains("[EMAIL_1]"));
    }
    let s = e.cache_stats();
    assert_eq!((s.entries, s.hits, s.misses), (0, 0, 0));
}

#[test]
fn a_tiny_budget_evicts_but_never_changes_the_result() {
    let tiny = Engine::builder().rules(rules()).scan_cache_bytes(300).build().unwrap();
    let plain = uncached();
    let scope = ScopeId::profile("t");
    for n in 1..=15 {
        let body = conversation(n);
        assert_eq!(redact(&tiny, &scope, &body), redact(&plain, &scope, &body), "turn {n}");
        assert!(tiny.cache_stats().bytes <= 300);
    }
}

#[test]
fn redact_text_returns_the_same_offsets_from_a_cached_scan() {
    let e = cached();
    let scope = ScopeId::profile("t");
    let text = long("Mail ana@example.com, call +44 20 7946 0958.");
    let first = e.redact_text(&scope, &text).unwrap();
    let second = e.redact_text(&scope, &text).unwrap();
    assert_eq!(first, second);
    assert!(e.cache_stats().hits == 1);
    for m in &second.matches {
        assert!(["ana@example.com", "+44 20 7946 0958"].contains(&&text[m.start..m.end]));
    }
}

#[test]
fn audit_scans_count_the_same_with_and_without_the_cache() {
    let (a, b) = (cached(), uncached());
    for n in [5, 6, 7] {
        let body = conversation(n);
        assert_eq!(a.scan_json(&body, &WalkAll).unwrap(), b.scan_json(&body, &WalkAll).unwrap());
    }
    assert!(a.cache_stats().hits > 0);
}

/// Counts what reaches the vault.
#[derive(Default)]
struct CountingVault {
    inner: MemoryVault,
    creates: Mutex<BTreeMap<String, usize>>,
}

impl Vault for CountingVault {
    fn get_or_create(&self, scope: &ScopeId, kind: &EntityKind, value: &str) -> Result<u64, VaultError> {
        *self.creates.lock().unwrap().entry(value.to_owned()).or_default() += 1;
        self.inner.get_or_create(scope, kind, value)
    }
    fn lookup(&self, scope: &ScopeId, kind: &EntityKind, n: u64) -> Result<Option<String>, VaultError> {
        self.inner.lookup(scope, kind, n)
    }
    fn reserve(&self, scope: &ScopeId, kind: &EntityKind, n: u64) -> Result<(), VaultError> {
        self.inner.reserve(scope, kind, n)
    }
}

#[test]
fn each_value_reaches_the_vault_once_per_request() {
    let vault = Arc::new(CountingVault::default());
    let e = Engine::builder().vault(vault.clone()).rules(rules()).build().unwrap();
    let scope = ScopeId::profile("t");
    let body =
        json!({"a": "ana@example.com ".repeat(50), "b": ["ana@example.com", "bo@example.org", "bo@example.org"]});
    let (out, report) = redact(&e, &scope, &body);
    assert_eq!(report.redacted, 53);
    assert_eq!(out["b"], json!(["[EMAIL_1]", "[EMAIL_2]", "[EMAIL_2]"]));
    let counts = vault.creates.lock().unwrap().clone();
    assert_eq!(counts, BTreeMap::from([("ana@example.com".into(), 1), ("bo@example.org".into(), 1)]));
    // A second request looks each value up again, once: the vault keeps
    // them fresh and hands out any new numbers.
    redact(&e, &scope, &body);
    assert_eq!(vault.creates.lock().unwrap()["ana@example.com"], 2);
}

#[test]
fn the_same_value_of_two_kinds_gets_two_placeholders() {
    let mut r = rules();
    r.dictionary.push(DictionaryEntry { term: "orion".into(), kind: "CLIENT".into(), match_case: false });
    r.dictionary.push(DictionaryEntry { term: "Orion".into(), kind: "CODENAME".into(), match_case: true });
    let e = Engine::builder().rules(r.clone()).build().unwrap();
    let plain = Engine::builder().rules(r.clone()).scan_cache_bytes(0).build().unwrap();
    let body = json!({"t": long("Orion and orion and ORION")});
    let scope = ScopeId::profile("t");
    assert_eq!(redact(&e, &scope, &body), redact(&plain, &scope, &body));
}

/// Kind, value, placeholder and times, as the recorder heard them.
type Heard = (String, String, Option<String>, u64);

/// Remembers what the recorder was told.
#[derive(Default)]
struct Log(Mutex<Vec<Heard>>);

impl Recorder for Log {
    fn matched(&self, kind: &EntityKind, value: &str, placeholder: Option<&str>, times: u64) {
        self.0.lock().unwrap().push((kind.to_string(), value.into(), placeholder.map(Into::into), times));
    }
}

fn recorded(log: &Log) -> Vec<Heard> {
    std::mem::take(&mut *log.0.lock().unwrap())
}

#[test]
fn the_recorder_hears_each_value_once_with_its_count_in_order() {
    let log = Arc::new(Log::default());
    let e = Engine::builder().rules(rules()).recorder(log.clone()).build().unwrap();
    let scope = ScopeId::profile("t");
    let body = json!({"a": long("bo@example.org, ana@example.com, bo@example.org"), "b": "ana@example.com"});
    redact(&e, &scope, &body);
    let first = recorded(&log);
    assert_eq!(
        first,
        vec![
            ("EMAIL".into(), "bo@example.org".into(), Some("[EMAIL_1]".into()), 2),
            ("EMAIL".into(), "ana@example.com".into(), Some("[EMAIL_2]".into()), 2),
        ]
    );
    // From the cache, the recorder hears exactly the same.
    redact(&e, &scope, &body);
    assert_eq!(recorded(&log), first);

    // Audit mode: found, not replaced.
    e.scan_json(&body, &WalkAll).unwrap();
    assert_eq!(
        recorded(&log),
        vec![("EMAIL".into(), "bo@example.org".into(), None, 2), ("EMAIL".into(), "ana@example.com".into(), None, 2),]
    );
}

#[test]
fn concurrent_conversations_match_a_sequential_run_without_the_cache() {
    let shared = Arc::new(cached());
    let threads: Vec<_> = (0..8)
        .map(|t| {
            let e = shared.clone();
            std::thread::spawn(move || {
                let scope = ScopeId::profile(&format!("c{t}"));
                (1..=12).map(|n| redact(&e, &scope, &conversation(n + t))).collect::<Vec<_>>()
            })
        })
        .collect();
    for (t, h) in threads.into_iter().enumerate() {
        let got = h.join().unwrap();
        let plain = uncached();
        let scope = ScopeId::profile(&format!("c{t}"));
        let want: Vec<_> = (1..=12).map(|n| redact(&plain, &scope, &conversation(n + t))).collect();
        assert_eq!(got, want, "conversation {t}");
    }
}

#[test]
fn a_cached_scan_reserves_typed_placeholders_in_each_new_conversation() {
    let e = cached();
    let text = long("I wrote [EMAIL_9] myself. Real one: ana@example.com.");
    let first = e.redact_text(&ScopeId::profile("a"), &text).unwrap().text;
    let other = ScopeId::profile("b");
    let second = e.redact_text(&other, &text).unwrap().text;
    assert_eq!(e.cache_stats().hits, 1, "the second conversation reuses the scan");
    assert_eq!(first, second, "both reserve [EMAIL_9], so the real value is [EMAIL_10] in each");
    assert!(second.contains("Real one: [EMAIL_10]"), "{second}");
    // In the second conversation a new value also stays clear of it.
    assert!(e.redact_text(&other, "and bo@example.org").unwrap().text.contains("[EMAIL_11]"));
}
