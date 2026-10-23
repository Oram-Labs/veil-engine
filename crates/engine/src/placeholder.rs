//! Placeholder format, such as the default `[{TYPE}_{N}]`.

use regex::Regex;

use crate::EntityKind;

/// The default placeholder template, giving `[EMAIL_1]`, `[PHONE_2]` and so on.
pub const DEFAULT_FORMAT: &str = "[{TYPE}_{N}]";

#[derive(Clone, Debug)]
enum Seg {
    Lit(String),
    Type,
    Num,
}

/// A parsed placeholder template.
///
/// Rules: it contains `{TYPE}` and `{N}` once each, separated by literal
/// text, and it starts and ends with literal text. The opening text must start
/// with a character that is not a letter, digit or `_`, so placeholders can't
/// run into surrounding words.
#[derive(Clone, Debug)]
pub struct PlaceholderFormat {
    template: String,
    segs: Vec<Seg>,
    regex: Regex,
    /// Also matches the variants models sometimes write; see [`PlaceholderFormat::fuzzy_tokens`].
    fuzzy: Regex,
    opener: String,
    closer: String,
    inner: Vec<char>,
    max_len: usize,
}

/// A placeholder found by fuzzy matching. `exact` is true if it is written
/// exactly as the format produces it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FuzzyToken {
    pub start: usize,
    pub end: usize,
    pub kind: String,
    pub n: u64,
    pub exact: bool,
    /// Ends with the closing text, so more text can't change it.
    closed: bool,
}

/// A placeholder-shaped token found in text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token<'a> {
    /// Byte offset where the token starts.
    pub start: usize,
    /// Byte offset just past the token.
    pub end: usize,
    /// The `{TYPE}` part, as written.
    pub kind: &'a str,
    /// The `{N}` part.
    pub n: u64,
}

impl PlaceholderFormat {
    /// Parses a template. The error says which rule it breaks.
    pub fn parse(template: &str) -> Result<Self, String> {
        let mut segs = Vec::new();
        let mut rest = template;
        while !rest.is_empty() {
            if let Some(r) = rest.strip_prefix("{TYPE}") {
                segs.push(Seg::Type);
                rest = r;
            } else if let Some(r) = rest.strip_prefix("{N}") {
                segs.push(Seg::Num);
                rest = r;
            } else {
                let next = [rest.find("{TYPE}"), rest.find("{N}")].into_iter().flatten().min().unwrap_or(rest.len());
                let next = if next == 0 { 1 } else { next };
                match segs.last_mut() {
                    Some(Seg::Lit(s)) => s.push_str(&rest[..next]),
                    _ => segs.push(Seg::Lit(rest[..next].to_owned())),
                }
                rest = &rest[next..];
            }
        }
        let count = |f: fn(&Seg) -> bool| segs.iter().filter(|s| f(s)).count();
        if count(|s| matches!(s, Seg::Type)) != 1 || count(|s| matches!(s, Seg::Num)) != 1 {
            return Err("the format must contain {TYPE} and {N} exactly once".into());
        }
        let (Some(Seg::Lit(opener)), Some(Seg::Lit(closer))) = (segs.first(), segs.last()) else {
            return Err("the format must start and end with literal text, such as [ and ]".into());
        };
        if opener.starts_with(|c: char| c.is_alphanumeric() || c == '_') {
            return Err("the format must start with a symbol, not a letter, digit or _".into());
        }
        if segs.windows(2).any(|w| !matches!(w[0], Seg::Lit(_)) && !matches!(w[1], Seg::Lit(_))) {
            return Err("{TYPE} and {N} must be separated by literal text, such as _".into());
        }
        let (opener, closer) = (opener.clone(), closer.clone());
        let mut pattern = String::new();
        let mut inner = Vec::new();
        let mut literal_len = 0;
        for (i, seg) in segs.iter().enumerate() {
            match seg {
                Seg::Lit(s) => {
                    pattern.push_str(&regex::escape(s));
                    literal_len += s.len();
                    if i != 0 && i != segs.len() - 1 {
                        inner.extend(s.chars());
                    }
                }
                Seg::Type => pattern.push_str("(?P<t>[A-Z][A-Z0-9_]{0,31}?)"),
                Seg::Num => pattern.push_str("(?P<n>[0-9]{1,9})"),
            }
        }
        let regex = Regex::new(&pattern).map_err(|e| e.to_string())?;
        let fuzzy = Regex::new(&fuzzy_pattern(&segs)).map_err(|e| e.to_string())?;
        Ok(PlaceholderFormat {
            template: template.to_owned(),
            segs,
            regex,
            fuzzy,
            opener,
            closer,
            inner,
            max_len: literal_len + 32 + 9,
        })
    }

    /// The template, as given.
    pub fn template(&self) -> &str {
        &self.template
    }

    /// The placeholder for number `n` of `kind`, such as `[EMAIL_1]`.
    pub fn format(&self, kind: &EntityKind, n: u64) -> String {
        let mut out = String::new();
        for seg in &self.segs {
            match seg {
                Seg::Lit(s) => out.push_str(s),
                Seg::Type => out.push_str(kind.as_str()),
                Seg::Num => out.push_str(&n.to_string()),
            }
        }
        out
    }

    /// Finds every placeholder-shaped token in `text`.
    pub fn tokens<'a>(&'a self, text: &'a str) -> impl Iterator<Item = Token<'a>> + 'a {
        self.regex.captures_iter(text).filter_map(|c| {
            let whole = c.get(0)?;
            Some(Token {
                start: whole.start(),
                end: whole.end(),
                kind: c.name("t")?.as_str(),
                n: c.name("n")?.as_str().parse().ok()?,
            })
        })
    }

    /// Finds placeholders including the variants models sometimes write:
    ///
    /// - different case or spaces inside the brackets: `[email_1]`, `[ EMAIL 1 ]`
    /// - Markdown escapes: `[EMAIL\_1]`, `\[EMAIL_1\]`
    /// - missing brackets, only when the rest is exact and stands alone: `EMAIL_1`
    ///
    /// Exact placeholders are found too.
    pub(crate) fn fuzzy_tokens(&self, text: &str) -> Vec<FuzzyToken> {
        self.fuzzy_tokens_after(None, text)
    }

    /// Like [`PlaceholderFormat::fuzzy_tokens`] for text that follows
    /// `before`, e.g. the last character already sent in a stream.
    pub(crate) fn fuzzy_tokens_after(&self, before: Option<char>, text: &str) -> Vec<FuzzyToken> {
        let is_word = |c: char| c.is_alphanumeric() || c == '_';
        let mut out = Vec::new();
        for c in self.fuzzy.captures_iter(text) {
            let (Some(whole), Some(t), Some(n_match)) = (c.get(0), c.name("t"), c.name("n")) else { continue };
            if text[n_match.end()..].starts_with(|c: char| c.is_ascii_digit()) {
                continue; // more than nine digits
            }
            let Ok(n) = n_match.as_str().parse() else { continue };
            let Ok(kind) = EntityKind::new(&t.as_str().replace('\\', "").to_ascii_uppercase()) else { continue };
            let (opened, closed) = (c.name("o").is_some(), c.name("c").is_some());
            let exact_text = self.format(&kind, n);
            if !(opened && closed) {
                // Without both brackets, only the exact core counts, and it
                // must not be part of a longer word.
                let core = &text[t.start()..n_match.end()];
                let exact_core = &exact_text[self.opener.len()..exact_text.len() - self.closer.len()];
                let before = if whole.start() == 0 { before } else { text[..whole.start()].chars().next_back() };
                let after = text[whole.end()..].chars().next();
                if core != exact_core
                    || (!opened && before.is_some_and(is_word))
                    || (!closed && after.is_some_and(is_word))
                {
                    continue;
                }
            }
            out.push(FuzzyToken {
                start: whole.start(),
                end: whole.end(),
                exact: whole.as_str() == exact_text,
                kind: kind.as_str().to_owned(),
                n,
                closed,
            });
        }
        out
    }

    /// Like [`PlaceholderFormat::hold_from`], for fuzzy restoration: also holds
    /// a tail that could still become one of the variants.
    pub(crate) fn hold_from_fuzzy(&self, text: &str) -> usize {
        let max = self.max_len * 2;
        let min = text.len().saturating_sub(max);
        let in_brackets = |c: char| {
            c.is_ascii_alphanumeric()
                || matches!(c, '_' | '\\' | ' ' | '\t' | '-')
                || self.opener.contains(c)
                || self.closer.contains(c)
                || self.inner.contains(&c)
        };
        let bare = |c: char| {
            c.is_ascii_uppercase() || c.is_ascii_digit() || self.inner.contains(&c) || self.closer.contains(c)
        };
        let prev_is_word = |i: usize| text[..i].chars().next_back().is_some_and(|c| c.is_alphanumeric() || c == '_');
        text.char_indices()
            .map(|(i, _)| i)
            .skip_while(|&i| i < min)
            .find(|&i| {
                let tail = &text[i..];
                let first = tail.chars().next().expect("non-empty tail");
                // A placeholder can start at an opener (maybe escaped), or at
                // an uppercase word for the bracketless form.
                // A backslash only starts one if the opener (or its start) follows.
                let unescaped = tail.strip_prefix('\\').unwrap_or(tail);
                let opens =
                    unescaped.is_empty() || unescaped.chars().next().is_some_and(|c| self.opener.starts_with(c));
                let could_be = if opens {
                    tail.chars().all(in_brackets)
                } else {
                    first.is_ascii_uppercase() && !prev_is_word(i) && tail.chars().all(bare)
                };
                let complete = || self.fuzzy_tokens(tail).first().is_some_and(|t| t.start == 0 && t.closed);
                tail.len() < max && could_be && !complete()
            })
            .unwrap_or(text.len())
    }

    /// The offset from which `text` must be held back because its tail could
    /// still grow into a placeholder. Returns `text.len()` if nothing needs holding.
    pub(crate) fn hold_from(&self, text: &str) -> usize {
        let min = text.len().saturating_sub(self.max_len);
        text.char_indices()
            .map(|(i, _)| i)
            .skip_while(|&i| i < min)
            .find(|&i| self.could_complete(&text[i..]))
            .unwrap_or(text.len())
    }

    fn could_complete(&self, tail: &str) -> bool {
        if tail.is_empty() || tail.len() >= self.max_len {
            return false;
        }
        if self.opener.starts_with(tail) {
            return true;
        }
        let Some(rest) = tail.strip_prefix(self.opener.as_str()) else {
            return false;
        };
        let body_end = rest
            .char_indices()
            .find(|&(_, c)| !(c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_' || self.inner.contains(&c)))
            .map_or(rest.len(), |(i, _)| i);
        let after = &rest[body_end..];
        after.is_empty() || (self.closer.starts_with(after) && after != self.closer)
    }
}

/// The fuzzy pattern: literal parts may be Markdown-escaped and padded with
/// spaces, the separator may be a space or `-`, the type any case, and the
/// opening and closing text may be missing (checked by the caller).
fn fuzzy_pattern(segs: &[Seg]) -> String {
    let lit = |s: &str| s.chars().map(|c| format!(r"\\?{}", regex::escape(&c.to_string()))).collect::<String>();
    let mut pattern = String::new();
    let last = segs.len() - 1;
    for (i, seg) in segs.iter().enumerate() {
        match seg {
            Seg::Lit(s) if i == 0 => pattern.push_str(&format!(r"(?P<o>{}[ \t]*)?", lit(s))),
            Seg::Lit(s) if i == last => pattern.push_str(&format!(r"(?P<c>[ \t]*{})?", lit(s))),
            Seg::Lit(s) => pattern.push_str(&format!(r"(?:[ \t]*{}[ \t]*|[ \t]+|[ \t]*-[ \t]*)", lit(s))),
            Seg::Type => pattern.push_str(r"(?P<t>[A-Za-z](?:[A-Za-z0-9]|\\?_){0,40}?)"),
            Seg::Num => pattern.push_str(r"(?P<n>[0-9]{1,9})"),
        }
    }
    pattern
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kind(s: &str) -> EntityKind {
        EntityKind::new(s).unwrap()
    }

    #[test]
    fn default_format_round_trips() {
        let f = PlaceholderFormat::parse(DEFAULT_FORMAT).unwrap();
        assert_eq!(f.format(&kind("NATIONAL_ID"), 12), "[NATIONAL_ID_12]");
        let toks: Vec<_> = f.tokens("a [NATIONAL_ID_12] b [EMAIL_1] [email_1] [EMAIL]").collect();
        assert_eq!(toks.len(), 2);
        assert_eq!((toks[0].kind, toks[0].n), ("NATIONAL_ID", 12));
        assert_eq!((toks[1].kind, toks[1].n), ("EMAIL", 1));
    }

    #[test]
    fn custom_formats() {
        let f = PlaceholderFormat::parse("<<{TYPE}:{N}>>").unwrap();
        assert_eq!(f.format(&kind("EMAIL"), 3), "<<EMAIL:3>>");
        assert_eq!(f.tokens("x <<EMAIL:3>> y").count(), 1);
        assert_eq!(f.hold_from("text <"), 5);
        assert_eq!(f.hold_from("text <<EMA"), 5);
        assert_eq!(f.hold_from("text <<EMAIL:3>"), 5);
        assert_eq!(f.hold_from("text <<EMAIL:3>>"), 16);
        assert_eq!(f.hold_from("a <b"), 4);
    }

    #[test]
    fn rejects_bad_formats() {
        for bad in ["{TYPE}_{N}", "[{TYPE}{N}]", "[{TYPE}]", "[{N}_{N}]", "x{TYPE}_{N}]", "[{TYPE}_{N}"] {
            assert!(PlaceholderFormat::parse(bad).is_err(), "{bad}");
        }
    }

    fn fuzzy(f: &PlaceholderFormat, text: &str) -> Vec<(String, String, u64, bool)> {
        f.fuzzy_tokens(text).into_iter().map(|t| (text[t.start..t.end].to_owned(), t.kind, t.n, t.exact)).collect()
    }

    #[test]
    fn fuzzy_variants() {
        let f = PlaceholderFormat::parse(DEFAULT_FORMAT).unwrap();
        let t = |s: &str, k: &str, n, exact| (s.to_owned(), k.to_owned(), n, exact);
        assert_eq!(fuzzy(&f, "[EMAIL_1]"), [t("[EMAIL_1]", "EMAIL", 1, true)]);
        assert_eq!(fuzzy(&f, "a [email_2] b"), [t("[email_2]", "EMAIL", 2, false)]);
        assert_eq!(fuzzy(&f, "[ Email 3 ]"), [t("[ Email 3 ]", "EMAIL", 3, false)]);
        assert_eq!(fuzzy(&f, "[EMAIL - 4]"), [t("[EMAIL - 4]", "EMAIL", 4, false)]);
        assert_eq!(fuzzy(&f, r"[NATIONAL\_ID\_5]"), [t(r"[NATIONAL\_ID\_5]", "NATIONAL_ID", 5, false)]);
        assert_eq!(fuzzy(&f, r"\[EMAIL_6\]"), [t(r"\[EMAIL_6\]", "EMAIL", 6, false)]);
        assert_eq!(fuzzy(&f, "to EMAIL_7, and"), [t("EMAIL_7", "EMAIL", 7, false)]);
        assert_eq!(fuzzy(&f, "x [PHONE_8 y"), [t("[PHONE_8", "PHONE", 8, false)]);
        // Bracketless forms must be exact and stand alone.
        for no in ["send email 1 now", "aEMAIL_1", "EMAIL_12a", "Email_1", "EMAIL 1", "[EMAIL_1234567890]"] {
            assert_eq!(fuzzy(&f, no), [], "{no}");
        }
        let f = PlaceholderFormat::parse("<<{TYPE}:{N}>>").unwrap();
        assert_eq!(fuzzy(&f, "<< email : 3 >>"), [t("<< email : 3 >>", "EMAIL", 3, false)]);
    }

    #[test]
    fn fuzzy_hold_back() {
        let f = PlaceholderFormat::parse(DEFAULT_FORMAT).unwrap();
        assert_eq!(f.hold_from_fuzzy("Hi [ em"), 3);
        assert_eq!(f.hold_from_fuzzy(r"Hi \[EMAIL\_"), 3);
        assert_eq!(f.hold_from_fuzzy("Hi EMAIL_"), 3);
        assert_eq!(f.hold_from_fuzzy("Hi [email_1]"), 12);
        assert_eq!(f.hold_from_fuzzy("Hi there."), 9);
        assert_eq!(f.hold_from_fuzzy("lowercase words"), 15);
    }

    #[test]
    fn hold_from_default() {
        let f = PlaceholderFormat::parse(DEFAULT_FORMAT).unwrap();
        assert_eq!(f.hold_from("Hi ["), 3);
        assert_eq!(f.hold_from("Hi [EMAIL_1"), 3);
        assert_eq!(f.hold_from("Hi [EMAIL_1]"), 12);
        assert_eq!(f.hold_from("Hi [a"), 5);
        assert_eq!(f.hold_from("[[EMAIL_1"), 1);
        let long = format!("[{}", "A".repeat(60));
        assert_eq!(f.hold_from(&long), long.len());
    }
}
