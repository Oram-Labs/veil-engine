#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

mod allowlist;
mod builder;
mod detect;
mod error;
mod kind;
mod ner;
mod placeholder;
mod rules;
mod scan_cache;
mod stream;
mod vault;
mod walk;

pub use builder::EngineBuilder;
pub use detect::Source;
pub use error::{Error, RecognizerError, VaultError};
pub use kind::{kinds, EntityKind, InvalidKind};
pub use ner::{Entity, EntityRecognizer};
pub use placeholder::{PlaceholderFormat, Token, DEFAULT_FORMAT};
pub use rules::{
    CompiledRules, Detectors, DictionaryEntry, IpOptions, NatIdOptions, NerOptions, NoOptions, Options, PhoneOptions,
    RegexRule, RulesError, RulesFile, Setting,
};
pub use scan_cache::{ScanCacheStats, DEFAULT_BUDGET as DEFAULT_SCAN_CACHE_BUDGET};
pub use stream::StreamRestorer;
pub use vault::{MemoryVault, Vault};
pub use walk::{KeyAction, KeyPolicy, WalkAll};

/// This crate's version as compiled in, such as `"0.2.0"`, so an application
/// can show which release of it is running.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::sync::Arc;

use arc_swap::ArcSwap;
use scan_cache::{ScanCache, Scanned};
use serde_json::Value;
use walk::StrKind;

/// Identifies which placeholder mapping a request uses.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ScopeId(String);

impl ScopeId {
    /// A scope with exactly this ID.
    pub fn new(id: impl Into<String>) -> Self {
        ScopeId(id.into())
    }

    /// The scope for a named profile, `profile:{name}`. Every conversation using
    /// the profile shares its placeholders.
    pub fn profile(name: &str) -> Self {
        ScopeId(format!("profile:{name}"))
    }

    /// A scope derived from `hint` (for example a conversation's ID or first
    /// message) with the secret `key`: HMAC-SHA256, so the scope reveals
    /// nothing about the hint. The same key and hint give the same scope.
    pub fn keyed(key: &[u8], hint: &str) -> Self {
        use hmac::{Hmac, Mac};
        let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
        mac.update(hint.as_bytes());
        let digest = mac.finalize().into_bytes();
        let hex: String = digest[..16].iter().map(|b| format!("{b:02x}")).collect();
        ScopeId(format!("conv:{hex}"))
    }

    /// The scope's ID.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ScopeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A detected value. Offsets are bytes into the scanned text.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Match {
    /// Byte offset where the value starts.
    pub start: usize,
    /// Byte offset just past the value.
    pub end: usize,
    /// What kind of value it is.
    pub kind: EntityKind,
    /// Which detector found it.
    pub source: Source,
}

/// Counts from one pass. Never holds values.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Report {
    /// Values replaced (redact mode) or found (audit mode).
    pub redacted: usize,
    /// [`redacted`](Self::redacted), by kind name.
    pub by_kind: BTreeMap<String, usize>,
    /// Placeholders put back to their real values.
    pub restored: usize,
    /// Placeholder-shaped text whose number this scope doesn't know, left as it
    /// is. Often a placeholder the model made up.
    pub unknown_placeholders: usize,
}

impl Report {
    /// Adds `other`'s counts to these.
    pub fn merge(&mut self, other: &Report) {
        self.redacted += other.redacted;
        for (k, v) in &other.by_kind {
            *self.by_kind.entry(k.clone()).or_default() += v;
        }
        self.restored += other.restored;
        self.unknown_placeholders += other.unknown_placeholders;
    }

    fn count(&mut self, kind: &EntityKind) {
        self.redacted += 1;
        *self.by_kind.entry(kind.as_str().to_owned()).or_default() += 1;
    }
}

/// The result of redacting one string.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Redacted {
    /// The text with every match replaced by its placeholder.
    pub text: String,
    /// Offsets refer to the original text.
    pub matches: Vec<Match>,
    /// Counts for this text.
    pub report: Report,
}

/// The result of restoring one string.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Restored {
    /// The text with every known placeholder replaced by its real value.
    pub text: String,
    /// Counts for this text.
    pub report: Report,
}

/// Told about the values live traffic matched, e.g. to show recent matches.
/// Not called for restores, or for [`Engine::scan`].
pub trait Recorder: Send + Sync {
    /// `value` matched `times` times in one request, in order of first
    /// appearance. `placeholder` is what replaced it, or `None` when it was
    /// only found and sent unchanged ([`Engine::scan_json`], audit mode).
    fn matched(&self, kind: &EntityKind, value: &str, placeholder: Option<&str>, times: u64);
}

/// Finds sensitive values, replaces them with placeholders and puts the real
/// values back. Build one with [`Engine::builder`].
pub struct Engine {
    rules: ArcSwap<CompiledRules>,
    vault: Arc<dyn Vault>,
    recorder: Option<Arc<dyn Recorder>>,
    scans: ScanCache,
}

/// The values one call has seen. Each distinct value is looked up in the
/// vault once, however often it appears, and reported to the recorder once.
#[derive(Default)]
struct Pass {
    index: HashMap<EntityKind, HashMap<String, usize>>,
    seen: Vec<Seen>,
    reserved: HashSet<(EntityKind, u64)>,
}

struct Seen {
    kind: EntityKind,
    value: String,
    placeholder: Option<String>,
    times: u64,
}

impl Pass {
    fn find(&self, kind: &EntityKind, value: &str) -> Option<usize> {
        self.index.get(kind).and_then(|m| m.get(value)).copied()
    }

    fn add(&mut self, kind: &EntityKind, value: &str, placeholder: Option<String>) -> usize {
        let i = self.seen.len();
        self.seen.push(Seen { kind: kind.clone(), value: value.to_owned(), placeholder, times: 0 });
        self.index.entry(kind.clone()).or_default().insert(value.to_owned(), i);
        i
    }
}

impl Default for Engine {
    /// The default rules and placeholder format, with an in-memory vault.
    fn default() -> Self {
        Engine::builder().build().expect("default rules compile")
    }
}

impl Engine {
    /// Starts building an engine. With nothing set, it uses the default
    /// rules, the `[{TYPE}_{N}]` placeholder format and an in-memory vault.
    pub fn builder() -> EngineBuilder {
        EngineBuilder::default()
    }

    /// How the cache of recent scans is doing.
    pub fn cache_stats(&self) -> ScanCacheStats {
        self.scans.stats()
    }

    /// Swaps in new rules. Calls already running finish with the old ones.
    /// Scans made with the old rules are dropped: they can't be reused.
    pub fn set_rules(&self, rules: CompiledRules) {
        self.rules.store(Arc::new(rules));
        self.scans.clear();
    }

    /// The rules in use now.
    pub fn rules(&self) -> Arc<CompiledRules> {
        self.rules.load_full()
    }

    /// The vault placeholders are kept in.
    pub fn vault(&self) -> &Arc<dyn Vault> {
        &self.vault
    }

    /// Finds sensitive values without changing anything or touching the vault.
    pub fn scan(&self, text: &str) -> Result<Vec<Match>, Error> {
        scan_with(&self.rules(), text)
    }

    /// Replaces every detected value in `text` with its placeholder.
    pub fn redact_text(&self, scope: &ScopeId, text: &str) -> Result<Redacted, Error> {
        let rules = self.rules();
        let mut pass = Pass::default();
        let (out, report, scanned) = self.redact_with(&rules, scope, text, &mut pass)?;
        self.report(pass);
        Ok(Redacted { text: out.into_owned(), matches: scanned.matches.clone(), report })
    }

    /// Redacts every string in `body` that `policy` does not skip.
    pub fn redact_json(&self, scope: &ScopeId, body: &mut Value, policy: &dyn KeyPolicy) -> Result<Report, Error> {
        let rules = self.rules();
        let mut report = Report::default();
        let mut pass = Pass::default();
        walk::walk(body, policy, &mut |s, kind| self.redact_string(&rules, scope, s, kind, &mut report, &mut pass))?;
        self.report(pass);
        Ok(report)
    }

    /// Counts what would be redacted in `body` without changing it (audit mode).
    /// Each match is reported to the recorder as sent unchanged.
    pub fn scan_json(&self, body: &Value, policy: &dyn KeyPolicy) -> Result<Report, Error> {
        let rules = self.rules();
        let mut report = Report::default();
        let mut pass = Pass::default();
        let mut copy = body.clone();
        walk::walk(&mut copy, policy, &mut |s, kind| {
            let text: Cow<'_, str> = match kind {
                StrKind::Json => {
                    serde_json::from_str::<Value>(s).map_or(Cow::Borrowed(s.as_str()), |v| json_strings(&v).into())
                }
                StrKind::Plain => Cow::Borrowed(s.as_str()),
            };
            let scanned = self.scanned(&rules, &text)?;
            for m in &scanned.matches {
                report.count(&m.kind);
                if self.recorder.is_some() {
                    let value = &text[m.start..m.end];
                    let i = pass.find(&m.kind, value).unwrap_or_else(|| pass.add(&m.kind, value, None));
                    pass.seen[i].times += 1;
                }
            }
            Ok(())
        })?;
        self.report(pass);
        Ok(report)
    }

    /// Replaces every known placeholder in `text` with its real value.
    /// Unknown placeholders are left as they are and counted.
    pub fn restore_text(&self, scope: &ScopeId, text: &str) -> Restored {
        self.restore_with(scope, text, |v| v.to_owned())
    }

    /// Like [`Engine::restore_text`], but passes each real value through
    /// `escape` first, e.g. to restore inside raw JSON text.
    pub fn restore_with(&self, scope: &ScopeId, text: &str, escape: impl Fn(&str) -> String) -> Restored {
        self.restore_after(scope, None, text, escape)
    }

    /// Restores `text` that follows the character `before`, which decides
    /// whether a bracketless placeholder at the very start stands alone.
    pub(crate) fn restore_after(
        &self,
        scope: &ScopeId,
        before: Option<char>,
        text: &str,
        escape: impl Fn(&str) -> String,
    ) -> Restored {
        let rules = self.rules();
        let tokens: Vec<(usize, usize, String, u64, bool)> = if rules.fuzzy_restore {
            rules
                .placeholder
                .fuzzy_tokens_after(before, text)
                .into_iter()
                .map(|t| (t.start, t.end, t.kind, t.n, t.exact))
                .collect()
        } else {
            rules.placeholder.tokens(text).map(|t| (t.start, t.end, t.kind.to_owned(), t.n, true)).collect()
        };
        let mut report = Report::default();
        let mut out = String::with_capacity(text.len());
        let mut last = 0;
        for (start, end, kind, n, exact) in tokens {
            let value = EntityKind::new(&kind).ok().and_then(|kind| self.vault.lookup(scope, &kind, n).ok().flatten());
            out.push_str(&text[last..start]);
            match value {
                Some(v) => {
                    out.push_str(&escape(&v));
                    report.restored += 1;
                }
                None => {
                    out.push_str(&text[start..end]);
                    // Near misses that aren't in the vault are just text.
                    if exact {
                        report.unknown_placeholders += 1;
                    }
                }
            }
            last = end;
        }
        out.push_str(&text[last..]);
        Restored { text: out, report }
    }

    /// Restores every string in `value` that `policy` does not skip.
    pub fn restore_json(&self, scope: &ScopeId, value: &mut Value, policy: &dyn KeyPolicy) -> Report {
        let mut report = Report::default();
        let result = walk::walk(value, policy, &mut |s, kind| {
            let r = match kind {
                StrKind::Plain => self.restore_text(scope, s),
                StrKind::Json => self.restore_with(scope, s, json_escape),
            };
            *s = r.text;
            report.merge(&r.report);
            Ok(())
        });
        debug_assert!(result.is_ok(), "restoration never fails");
        report
    }

    fn redact_string(
        &self,
        rules: &CompiledRules,
        scope: &ScopeId,
        s: &mut String,
        kind: StrKind,
        report: &mut Report,
        pass: &mut Pass,
    ) -> Result<(), Error> {
        if kind == StrKind::Json {
            if let Ok(mut inner) = serde_json::from_str::<Value>(s) {
                walk::walk(&mut inner, &WalkAll, &mut |s, k| self.redact_string(rules, scope, s, k, report, pass))?;
                *s = inner.to_string();
                return Ok(());
            }
        }
        let (out, r, _) = self.redact_with(rules, scope, s, pass)?;
        report.merge(&r);
        if let Cow::Owned(out) = out {
            *s = out;
        }
        Ok(())
    }

    /// Redacts one string. Returns it unchanged (borrowed) when nothing matched.
    fn redact_with<'t>(
        &self,
        rules: &CompiledRules,
        scope: &ScopeId,
        text: &'t str,
        pass: &mut Pass,
    ) -> Result<(Cow<'t, str>, Report, Arc<Scanned>), Error> {
        let scanned = self.scanned(rules, text)?;
        // Placeholder-shaped text the vault doesn't know was written by the
        // user. Reserve its number so a real value never gets it later.
        for (kind, n) in &scanned.tokens {
            if pass.reserved.insert((kind.clone(), *n)) && self.vault.lookup(scope, kind, *n)?.is_none() {
                self.vault.reserve(scope, kind, *n)?;
            }
        }
        let mut report = Report::default();
        if scanned.matches.is_empty() {
            return Ok((Cow::Borrowed(text), report, scanned));
        }
        let mut out = String::with_capacity(text.len());
        let mut last = 0;
        for m in &scanned.matches {
            out.push_str(&text[last..m.start]);
            let value = &text[m.start..m.end];
            let i = match pass.find(&m.kind, value) {
                Some(i) => i,
                None => {
                    let n = self.vault.get_or_create(scope, &m.kind, value)?;
                    pass.add(&m.kind, value, Some(rules.placeholder.format(&m.kind, n)))
                }
            };
            let seen = &mut pass.seen[i];
            seen.times += 1;
            out.push_str(seen.placeholder.as_deref().expect("redacted values have a placeholder"));
            report.count(&m.kind);
            last = m.end;
        }
        out.push_str(&text[last..]);
        Ok((Cow::Owned(out), report, scanned))
    }

    /// Scans `text`, or reuses the scan of the same text with the same rules.
    fn scanned(&self, rules: &CompiledRules, text: &str) -> Result<Arc<Scanned>, Error> {
        if !self.scans.enabled() || text.len() < scan_cache::MIN_LEN {
            return Ok(Arc::new(scan_full(rules, text)?));
        }
        let key = ScanCache::key(rules.id, text);
        if let Some(hit) = self.scans.get(&key) {
            return Ok(hit);
        }
        let scanned = Arc::new(scan_full(rules, text)?);
        self.scans.put(key, scanned.clone());
        Ok(scanned)
    }

    /// Tells the recorder what this call matched.
    fn report(&self, pass: Pass) {
        if let Some(r) = &self.recorder {
            for s in pass.seen {
                r.matched(&s.kind, &s.value, s.placeholder.as_deref(), s.times);
            }
        }
    }
}

fn scan_full(rules: &CompiledRules, text: &str) -> Result<Scanned, Error> {
    let tokens: Vec<Token<'_>> = rules.placeholder.tokens(text).collect();
    let matches = scan_tokens(rules, text, &tokens)?;
    let tokens = tokens.iter().filter_map(|t| EntityKind::new(t.kind).ok().map(|k| (k, t.n))).collect();
    Ok(Scanned { matches, tokens })
}

fn scan_with(rules: &CompiledRules, text: &str) -> Result<Vec<Match>, Error> {
    let tokens: Vec<Token<'_>> = rules.placeholder.tokens(text).collect();
    scan_tokens(rules, text, &tokens)
}

fn scan_tokens(rules: &CompiledRules, text: &str, tokens: &[Token<'_>]) -> Result<Vec<Match>, Error> {
    let protected: Vec<(usize, usize)> = tokens.iter().map(|t| (t.start, t.end)).collect();
    let mut candidates = Vec::new();
    for d in &rules.detectors {
        d.find(text, &mut candidates);
    }
    if let Some(ner) = &rules.ner {
        if text.chars().any(char::is_alphabetic) {
            let recognizer = ner.recognizer.as_ref().ok_or(Error::RecognizerMissing)?;
            for e in recognizer.recognize(text)? {
                let valid = e.start < e.end
                    && e.end <= text.len()
                    && text.is_char_boundary(e.start)
                    && text.is_char_boundary(e.end);
                if valid && e.score >= ner.threshold && ner.kinds.contains(&e.kind) {
                    candidates.push(detect::Candidate {
                        start: e.start,
                        end: e.end,
                        kind: e.kind,
                        source: Source::Ner,
                        priority: detect::P_NER,
                    });
                }
            }
        }
    }
    candidates.retain(|c| protected.iter().all(|&(s, e)| c.end <= s || c.start >= e));
    Ok(detect::resolve(candidates)
        .into_iter()
        .filter(|c| !rules.allowlist.allows(&text[c.start..c.end]))
        .map(|c| Match { start: c.start, end: c.end, kind: c.kind, source: c.source })
        .collect())
}

/// All string values in a JSON value joined by newlines, for scanning.
fn json_strings(v: &Value) -> String {
    let mut out = String::new();
    let mut copy = v.clone();
    let _ = walk::walk(&mut copy, &WalkAll, &mut |s, _| {
        out.push_str(s);
        out.push('\n');
        Ok(())
    });
    out
}

fn json_escape(v: &str) -> String {
    let quoted = Value::String(v.to_owned()).to_string();
    quoted[1..quoted.len() - 1].to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn engine_with(rules: RulesFile) -> Engine {
        Engine::builder().rules(rules).build().unwrap()
    }

    fn engine() -> Engine {
        engine_with(RulesFile::default())
    }

    fn scope() -> ScopeId {
        ScopeId::profile("default")
    }

    #[test]
    fn redacts_and_restores() {
        let e = engine();
        let r = e.redact_text(&scope(), "Mail ana@example.com or bob@test.org, ana@example.com.").unwrap();
        assert_eq!(r.text, "Mail [EMAIL_1] or [EMAIL_2], [EMAIL_1].");
        assert_eq!(r.report.redacted, 3);
        assert_eq!(r.report.by_kind["EMAIL"], 3);
        let Restored { text: restored, report } = e.restore_text(&scope(), &r.text);
        assert_eq!(restored, "Mail ana@example.com or bob@test.org, ana@example.com.");
        assert_eq!(report.restored, 3);
    }

    #[test]
    fn several_kinds_in_one_text() {
        let e = engine();
        let text = "Card 4111 1111 1111 1111, IBAN GB82 WEST 1234 5698 7654 32, call +44 20 7946 0958, key sk-ant-api03-abcdefghijklmnopqrstuvwxyz";
        let r = e.redact_text(&scope(), text).unwrap();
        assert_eq!(r.text, "Card [CARD_1], IBAN [IBAN_1], call [PHONE_1], key [SECRET_1]");
        assert_eq!(e.restore_text(&scope(), &r.text).text, text);
    }

    #[test]
    fn scopes_do_not_share_placeholders() {
        let e = engine();
        let redacted = e.redact_text(&ScopeId::profile("a"), "ana@example.com").unwrap().text;
        let Restored { text: restored, report } = e.restore_text(&ScopeId::profile("b"), &redacted);
        assert_eq!(restored, "[EMAIL_1]");
        assert_eq!(report.unknown_placeholders, 1);
    }

    #[test]
    fn keyed_scopes_never_change() {
        // Stored mappings are filed under these IDs: a change would orphan
        // every existing user's placeholders.
        assert_eq!(ScopeId::keyed(b"fixed key", "conversation 1").as_str(), "conv:994b52d98b13f5df97e24363ad999bbc");
        assert_ne!(ScopeId::keyed(b"other key", "conversation 1"), ScopeId::keyed(b"fixed key", "conversation 1"));
    }

    #[test]
    fn user_written_placeholders_are_never_reassigned() {
        let e = engine();
        let text = "Template uses [EMAIL_1] and [EMAIL_2]; real one is ana@example.com";
        let r = e.redact_text(&scope(), text).unwrap();
        assert_eq!(r.text, "Template uses [EMAIL_1] and [EMAIL_2]; real one is [EMAIL_3]");
        // The literal tokens stay literal on the way back.
        assert_eq!(e.restore_text(&scope(), &r.text).text, text);
    }

    #[test]
    fn redaction_is_idempotent() {
        let e = engine();
        let once = e.redact_text(&scope(), "ana@example.com and 4111111111111111").unwrap().text;
        let twice = e.redact_text(&scope(), &once).unwrap().text;
        assert_eq!(once, twice);
    }

    #[test]
    fn allowlist_applies_after_overlap_resolution() {
        let mut rules = RulesFile::default();
        rules.allowlist.push("support@acme.com".into());
        rules.dictionary.push(DictionaryEntry { term: "acme".into(), kind: "CLIENT".into(), match_case: false });
        let e = engine_with(rules);
        assert_eq!(
            e.redact_text(&scope(), "write support@acme.com about ACME").unwrap().text,
            "write support@acme.com about [CLIENT_1]"
        );
        assert_eq!(e.redact_text(&scope(), "sales@acme.com").unwrap().text, "[EMAIL_1]");
    }

    #[test]
    fn the_default_rules_allow_nothing() {
        assert!(RulesFile::default().allowlist.is_empty());
        assert_eq!(engine().redact_text(&scope(), "noreply@anthropic.com").unwrap().text, "[EMAIL_1]");
    }

    #[test]
    fn dictionary_and_custom_regex() {
        let mut rules = RulesFile::default();
        rules.dictionary.push(DictionaryEntry {
            term: "Project Halcyon".into(),
            kind: "CODENAME".into(),
            match_case: true,
        });
        rules.dictionary.push(DictionaryEntry {
            term: "Acme Holdings".into(),
            kind: "CLIENT".into(),
            match_case: false,
        });
        rules.regex.push(RegexRule { name: "tickets".into(), kind: "TICKET".into(), pattern: r"\bTCK-\d{6}\b".into() });
        let e = engine_with(rules);
        let r = e
            .redact_text(&scope(), "Project Halcyon for ACME HOLDINGS, see TCK-004211 not TCK-12; project halcyon")
            .unwrap();
        assert_eq!(r.text, "[CODENAME_1] for [CLIENT_1], see [TICKET_1] not TCK-12; project halcyon");
        assert_eq!(r.matches[0].source, Source::Dictionary);
        assert_eq!(r.matches[2].source, Source::Regex("tickets".into()));
    }

    #[test]
    fn redact_json_respects_policy_and_json_strings() {
        struct Policy;
        impl KeyPolicy for Policy {
            fn action(&self, _: &serde_json::Map<String, Value>, key: &str) -> KeyAction {
                match key {
                    "model" => KeyAction::Skip,
                    "arguments" => KeyAction::JsonString,
                    _ => KeyAction::Walk,
                }
            }
        }
        let e = engine();
        let mut body = json!({
            "model": "a@b.co",
            "messages": [{"content": "hi a@b.co"}],
            "tool": {"arguments": "{\"to\":\"a@b.co\",\"n\":1}"},
            "broken": {"arguments": "{\"to\": \"a@b.co\""}
        });
        let report = e.redact_json(&scope(), &mut body, &Policy).unwrap();
        assert_eq!(body["model"], "a@b.co");
        assert_eq!(body["messages"][0]["content"], "hi [EMAIL_1]");
        assert_eq!(body["tool"]["arguments"], "{\"to\":\"[EMAIL_1]\",\"n\":1}");
        assert_eq!(body["broken"]["arguments"], "{\"to\": \"[EMAIL_1]\"");
        assert_eq!(report.redacted, 3);

        let audit = e
            .scan_json(
                &json!({"model": "a@b.co", "x": "c@d.co", "tool": {"arguments": "{\"to\":\"e@f.co\"}"}}),
                &Policy,
            )
            .unwrap();
        assert_eq!(audit.redacted, 2);
    }

    #[test]
    fn restore_json_escapes_inside_json_strings() {
        let e = engine();
        // A value with a quote: only valid inside JSON text if escaped.
        e.redact_text(&scope(), "\"ana\"@example.com").unwrap();
        let mut rules = RulesFile::default();
        rules.dictionary.push(DictionaryEntry { term: "say \"hi\"".into(), kind: "PHRASE".into(), match_case: false });
        let e = engine_with(rules);
        let r = e.redact_text(&scope(), "say \"hi\" now").unwrap();
        assert_eq!(r.text, "[PHRASE_1] now");
        struct Args;
        impl KeyPolicy for Args {
            fn action(&self, _: &serde_json::Map<String, Value>, _: &str) -> KeyAction {
                KeyAction::JsonString
            }
        }
        let mut v = json!({"arguments": "{\"text\":\"[PHRASE_1]\"}"});
        e.restore_json(&scope(), &mut v, &Args);
        let inner: Value = serde_json::from_str(v["arguments"].as_str().unwrap()).unwrap();
        assert_eq!(inner["text"], "say \"hi\"");
    }

    #[test]
    fn rules_can_be_swapped_live() {
        let e = engine();
        assert_eq!(e.redact_text(&scope(), "see https://x.example/a").unwrap().text, "see https://x.example/a");
        let mut rules = RulesFile::default();
        rules.detectors.url = Setting::on();
        e.set_rules(CompiledRules::compile(&rules, &Options::default(), None).unwrap());
        assert_eq!(e.redact_text(&scope(), "see https://x.example/a").unwrap().text, "see [URL_1]");
    }

    /// Finds fixed words, with fixed scores.
    struct FakeNer(Vec<(&'static str, &'static str, f32)>);

    impl EntityRecognizer for FakeNer {
        fn recognize(&self, text: &str) -> Result<Vec<Entity>, RecognizerError> {
            if text.contains("FAIL") {
                return Err(RecognizerError::new("model crashed"));
            }
            Ok(self
                .0
                .iter()
                .flat_map(|&(word, kind, score)| {
                    text.match_indices(word).map(move |(i, _)| Entity {
                        start: i,
                        end: i + word.len(),
                        kind: EntityKind::new(kind).unwrap(),
                        score,
                    })
                })
                .collect())
        }
    }

    fn ner_engine(rules: &RulesFile) -> Engine {
        let ner = FakeNer(vec![
            ("Ana Pop", "PERSON", 0.97),
            ("Acme", "ORG", 0.9),
            ("Jordan", "PERSON", 0.4),
            ("Paris", "LOCATION", 0.95),
        ]);
        Engine::builder().rules(rules.clone()).recognizer(Arc::new(ner)).build().unwrap()
    }

    #[test]
    fn ner_redacts_names_above_the_threshold() {
        let mut rules = RulesFile::default();
        rules.detectors.ner = Setting::on();
        let e = ner_engine(&rules);
        let text = "Ana Pop (ana@example.com) of Acme met Jordan in Paris";
        let r = e.redact_text(&scope(), text).unwrap();
        assert_eq!(r.text, "[PERSON_1] ([EMAIL_1]) of [ORG_1] met Jordan in [LOCATION_1]");
        assert!(r.matches.iter().any(|m| m.source == Source::Ner));
        assert_eq!(e.restore_text(&scope(), &r.text).text, text);

        rules.detectors.ner.options.kinds = vec!["PERSON".into()];
        rules.detectors.ner.options.threshold = 0.3;
        rules.allowlist.push("Ana Pop".into());
        let e = ner_engine(&rules);
        assert_eq!(e.redact_text(&scope(), text).unwrap().text, "Ana Pop ([EMAIL_1]) of Acme met [PERSON_1] in Paris");
    }

    #[test]
    fn dictionary_beats_ner_on_the_same_span() {
        let mut rules = RulesFile::default();
        rules.detectors.ner = Setting::on();
        rules.dictionary.push(DictionaryEntry { term: "Acme".into(), kind: "CLIENT".into(), match_case: true });
        assert_eq!(ner_engine(&rules).redact_text(&scope(), "Acme").unwrap().text, "[CLIENT_1]");
    }

    #[test]
    fn ner_fails_closed() {
        let mut rules = RulesFile::default();
        rules.detectors.ner = Setting::on();
        // Turned on without a model: refuse rather than send names.
        let compiled = CompiledRules::compile(&rules, &Options::default(), None).unwrap();
        assert!(compiled.ner_missing());
        let e = Engine::builder().compiled_rules(compiled).build().unwrap();
        assert!(matches!(e.redact_text(&scope(), "Ana Pop"), Err(Error::RecognizerMissing)));
        // Text with no letters can't hold a name, so it doesn't need the model.
        assert_eq!(e.redact_text(&scope(), "12 + 3").unwrap().text, "12 + 3");
        assert!(matches!(ner_engine(&rules).redact_text(&scope(), "FAIL"), Err(Error::Recognizer(_))));
    }

    #[test]
    fn fuzzy_restore_is_opt_in() {
        let compile = |fuzzy| {
            let options = Options { fuzzy_restore: fuzzy, ..Options::default() };
            CompiledRules::compile(&RulesFile::default(), &options, None).unwrap()
        };
        let e = Engine::builder().compiled_rules(compile(false)).build().unwrap();
        e.redact_text(&scope(), "ana@example.com and +44 20 7946 0958").unwrap();
        let model = r"Wrote to [email_1], [ PHONE 1 ], EMAIL_1 and [EMAIL\_1]; [email_9] is unknown.";
        let Restored { text: exact, report } = e.restore_text(&scope(), model);
        assert_eq!(exact, model);
        assert_eq!(report.restored, 0);
        e.set_rules(compile(true));
        let Restored { text: fuzzy, report } = e.restore_text(&scope(), model);
        assert_eq!(
            fuzzy,
            "Wrote to ana@example.com, +44 20 7946 0958, ana@example.com and ana@example.com; [email_9] is unknown."
        );
        assert_eq!((report.restored, report.unknown_placeholders), (4, 0));
    }

    #[test]
    fn ner_options_are_checked() {
        let mut rules = RulesFile::default();
        rules.detectors.ner = Setting::on();
        rules.detectors.ner.options.kinds = vec!["DATE".into()];
        assert!(matches!(CompiledRules::compile(&rules, &Options::default(), None), Err(RulesError::Ner(_))));
        rules.detectors.ner.options = NerOptions { threshold: 1.5, ..NerOptions::default() };
        assert!(matches!(CompiledRules::compile(&rules, &Options::default(), None), Err(RulesError::Ner(_))));
    }

    mod props {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn redact_then_restore_is_identity(text in "[a-z0-9 .,@\\[\\]_A-Z\\n+-]{0,80}") {
                let e = engine();
                let r = e.redact_text(&scope(), &text).unwrap();
                prop_assert_eq!(e.restore_text(&scope(), &r.text).text, text);
            }

            #[test]
            fn redaction_is_deterministic(text in "[a-z0-9 .,@\\[\\]_A-Z\\n+-]{0,80}") {
                let e = engine();
                let a = e.redact_text(&scope(), &text).unwrap().text;
                let b = e.redact_text(&scope(), &text).unwrap().text;
                prop_assert_eq!(a, b);
            }
        }
    }
}
