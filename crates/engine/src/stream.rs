//! Restoration for streamed text, where a placeholder can be split across chunks.

use crate::{Engine, Report, ScopeId};

/// Restores one block of streamed model text.
///
/// Text is released as soon as it cannot be part of a placeholder. A tail that
/// could still become one (for the default format, an open `[` followed only
/// by placeholder characters) is held until it completes, stops matching,
/// grows past the longest possible placeholder, or [`StreamRestorer::finish`]
/// is called.
///
/// It holds no reference to the engine, so it can live inside a long-running
/// response stream; the engine and scope are passed to each call.
#[derive(Default)]
pub struct StreamRestorer {
    pending: String,
    /// The last character released, as the model wrote it.
    last: Option<char>,
    report: Report,
}

impl StreamRestorer {
    /// Adds a chunk and returns the restored text that is safe to send now.
    pub fn push(&mut self, engine: &Engine, scope: &ScopeId, chunk: &str) -> String {
        self.pending.push_str(chunk);
        let rules = engine.rules();
        let hold_from = match rules.fuzzy_restore {
            true => rules.placeholder.hold_from_fuzzy(&self.pending),
            false => rules.placeholder.hold_from(&self.pending),
        };
        let ready: String = self.pending.drain(..hold_from).collect();
        self.restore(engine, scope, &ready)
    }

    /// Flushes any held text at the end of the block.
    pub fn finish(&mut self, engine: &Engine, scope: &ScopeId) -> String {
        let rest = std::mem::take(&mut self.pending);
        self.restore(engine, scope, &rest)
    }

    /// True while text is being held back.
    pub fn is_holding(&self) -> bool {
        !self.pending.is_empty()
    }

    /// Counts so far for this block.
    pub fn report(&self) -> &Report {
        &self.report
    }

    fn restore(&mut self, engine: &Engine, scope: &ScopeId, text: &str) -> String {
        if text.is_empty() {
            return String::new();
        }
        let r = engine.restore_after(scope, self.last, text, str::to_owned);
        self.last = text.chars().next_back();
        self.report.merge(&r.report);
        r.text
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::StreamRestorer;
    use crate::{Engine, Options, ScopeId};

    fn setup() -> (Engine, ScopeId) {
        let engine = Engine::default();
        let scope = ScopeId::profile("default");
        engine.redact_text(&scope, "ana@example.com bob@example.org").unwrap();
        (engine, scope)
    }

    fn stream(engine: &Engine, scope: &ScopeId, chunks: &[&str]) -> String {
        let mut r = StreamRestorer::default();
        let mut out: String = chunks.iter().map(|c| r.push(engine, scope, c)).collect();
        out.push_str(&r.finish(engine, scope));
        out
    }

    #[test]
    fn placeholder_split_across_chunks() {
        let (e, s) = setup();
        assert_eq!(stream(&e, &s, &["Hi [EM", "AIL_", "1], bye"]), "Hi ana@example.com, bye");
    }

    #[test]
    fn releases_text_before_the_open_bracket_immediately() {
        let (e, s) = setup();
        let mut r = StreamRestorer::default();
        assert_eq!(r.push(&e, &s, "Hello there [EMA"), "Hello there ");
        assert!(r.is_holding());
        assert_eq!(r.push(&e, &s, "IL_2]!"), "bob@example.org!");
        assert!(!r.is_holding());
    }

    #[test]
    fn non_placeholder_brackets_are_not_held() {
        let (e, s) = setup();
        let mut r = StreamRestorer::default();
        assert_eq!(r.push(&e, &s, "a [link](x) and [b"), "a [link](x) and [b");
        assert_eq!(r.push(&e, &s, "[EMAIL_"), "");
        assert_eq!(r.finish(&e, &s), "[EMAIL_");
    }

    #[test]
    fn long_brackets_are_released() {
        let (e, s) = setup();
        let mut r = StreamRestorer::default();
        let long = format!("[{}", "A".repeat(60));
        assert_eq!(r.push(&e, &s, &long), long);
    }

    #[test]
    fn custom_format_streams() {
        let options = Options { placeholder_format: "<<{TYPE}:{N}>>".into(), ..Options::default() };
        let e = Engine::builder().options(options).build().unwrap();
        let s = ScopeId::profile("default");
        assert_eq!(e.redact_text(&s, "ana@example.com").unwrap().text, "<<EMAIL:1>>");
        assert_eq!(stream(&e, &s, &["x <", "<EMAIL:", "1>", "> y"]), "x ana@example.com y");
    }

    fn fuzzy_setup() -> (Engine, ScopeId) {
        let options = Options { fuzzy_restore: true, ..Options::default() };
        let engine = Engine::builder().options(options).build().unwrap();
        let scope = ScopeId::profile("default");
        engine.redact_text(&scope, "ana@example.com bob@example.org").unwrap();
        (engine, scope)
    }

    #[test]
    fn fuzzy_variants_split_across_chunks() {
        let (e, s) = fuzzy_setup();
        assert_eq!(
            stream(&e, &s, &["Hi [ em", "ail 1 ] and EMA", "IL_2", ". Bye"]),
            "Hi ana@example.com and bob@example.org. Bye"
        );
        assert_eq!(stream(&e, &s, &[r"\[EMAIL\", r"_2\]"]), "bob@example.org");
        // Plain words are not held for long: only a trailing uppercase word.
        let mut r = StreamRestorer::default();
        assert_eq!(r.push(&e, &s, "Hello there. Nice"), "Hello there. Nice");
        assert_eq!(r.push(&e, &s, " day, OK"), " day, ");
    }

    fn model_text() -> impl Strategy<Value = String> {
        let piece = prop_oneof![
            Just("[EMAIL_1]".to_owned()),
            Just("[EMAIL_2]".to_owned()),
            Just("[EMAIL_7]".to_owned()),
            Just("[".to_owned()),
            Just("]".to_owned()),
            Just("[EMAIL".to_owned()),
            Just("[ email 1 ]".to_owned()),
            Just("EMAIL_2".to_owned()),
            Just("\\[EMAIL\\_1\\]".to_owned()),
            "[a-zA-Z0-9 _\\[\\]\\n,.é\\\\-]{0,12}",
        ];
        prop::collection::vec(piece, 0..20).prop_map(|v| v.concat())
    }

    proptest! {
        #[test]
        fn streaming_matches_whole_text_restore(text in model_text(), cuts in prop::collection::vec(any::<prop::sample::Index>(), 0..12)) {
            let (e, s) = setup();
            let mut bounds: Vec<usize> = cuts.iter().map(|i| i.index(text.len() + 1)).filter(|&b| text.is_char_boundary(b)).collect();
            bounds.sort_unstable();
            bounds.dedup();
            let mut chunks = Vec::new();
            let mut last = 0;
            for b in bounds { chunks.push(&text[last..b]); last = b; }
            chunks.push(&text[last..]);
            let streamed = stream(&e, &s, &chunks);
            let whole = e.restore_text(&s, &text).text;
            prop_assert_eq!(streamed, whole);
            let (e, s) = fuzzy_setup();
            let streamed = stream(&e, &s, &chunks);
            let whole = e.restore_text(&s, &text).text;
            prop_assert_eq!(streamed, whole);
        }
    }
}
