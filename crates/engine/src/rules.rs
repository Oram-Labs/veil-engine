//! The rules file (`rules.yaml`) and its compiled form.

use std::fmt;
use std::marker::PhantomData;
use std::sync::Arc;

#[cfg(feature = "schema")]
use schemars::JsonSchema;
use serde::de::{self, Deserializer, MapAccess, Visitor};
use serde::{Deserialize, Serialize};

use crate::allowlist::Allowlist;
use crate::detect::{self, Detector};
use crate::kind::{kinds, EntityKind, InvalidKind};
use crate::ner::EntityRecognizer;
use crate::placeholder::{PlaceholderFormat, DEFAULT_FORMAT};

/// What gets redacted. Serialised as `rules.yaml`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(default, deny_unknown_fields)]
#[non_exhaustive]
pub struct RulesFile {
    /// The format version. Only `1` exists.
    pub version: u32,
    /// Which built-in detectors run, and their options.
    pub detectors: Detectors,
    /// Fixed terms to redact, such as client or project names.
    pub dictionary: Vec<DictionaryEntry>,
    /// Patterns to redact, each with its own kind.
    pub regex: Vec<RegexRule>,
    /// Values that are never redacted. An entry with `@` and no local part
    /// (`@acme.com`) or a bare domain (`acme.com`) allows every email address
    /// and URL at that domain and its subdomains.
    pub allowlist: Vec<String>,
}

impl Default for RulesFile {
    fn default() -> Self {
        RulesFile {
            version: 1,
            detectors: Detectors::default(),
            dictionary: Vec::new(),
            regex: Vec::new(),
            allowlist: Vec::new(),
        }
    }
}

/// Built-in detectors. Each accepts `true`/`false`, `on`/`off`, or a map with
/// `enabled` and its options.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(default, deny_unknown_fields)]
#[non_exhaustive]
pub struct Detectors {
    /// Email addresses.
    pub email: Setting<NoOptions>,
    /// Phone numbers. Needs the `phone` feature.
    pub phone: Setting<PhoneOptions>,
    /// Payment card numbers from known issuers that pass the Luhn check.
    pub card: Setting<NoOptions>,
    /// IBANs with a valid checksum.
    pub iban: Setting<NoOptions>,
    /// API keys and tokens with a recognisable prefix or shape.
    pub secret: Setting<NoOptions>,
    /// IPv4 and IPv6 addresses.
    pub ip: Setting<IpOptions>,
    /// URLs.
    pub url: Setting<NoOptions>,
    /// National ID numbers of the configured countries.
    pub natid: Setting<NatIdOptions>,
    /// Names of people, organisations and places, found by a local model
    /// that is downloaded on first use.
    pub ner: Setting<NerOptions>,
}

impl Default for Detectors {
    fn default() -> Self {
        Detectors {
            email: Setting::on(),
            // On when it's built in, so the default rules always compile.
            phone: Setting { enabled: cfg!(feature = "phone"), options: PhoneOptions::default() },
            card: Setting::on(),
            iban: Setting::on(),
            secret: Setting::on(),
            ip: Setting::on(),
            // Off by default: the model often needs links to help.
            url: Setting::off(),
            natid: Setting::on(),
            // Off by default: it needs a download and makes more mistakes
            // than the pattern detectors.
            ner: Setting::off(),
        }
    }
}

/// One detector: on or off, and its options. In YAML it can be just `true`,
/// `false`, `on` or `off`.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[cfg_attr(feature = "schema", schemars(rename = "Setting_{T}"))]
pub struct Setting<T> {
    /// Whether the detector runs.
    pub enabled: bool,
    /// The detector's options.
    #[serde(flatten)]
    pub options: T,
}

impl<T: Default> Setting<T> {
    /// On, with default options.
    pub fn on() -> Self {
        Setting { enabled: true, options: T::default() }
    }
    /// Off, with default options.
    pub fn off() -> Self {
        Setting { enabled: false, options: T::default() }
    }
}

impl<T: Default> Default for Setting<T> {
    fn default() -> Self {
        Self::on()
    }
}

impl<'de, T: Deserialize<'de> + Default> Deserialize<'de> for Setting<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V<T>(PhantomData<T>);
        impl<'de, T: Deserialize<'de> + Default> Visitor<'de> for V<T> {
            type Value = Setting<T>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("true, false, \"on\", \"off\" or a map with `enabled` and options")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Self::Value, E> {
                Ok(Setting { enabled: v, options: T::default() })
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                match v {
                    "on" | "true" | "yes" => self.visit_bool(true),
                    "off" | "false" | "no" => self.visit_bool(false),
                    _ => Err(E::invalid_value(de::Unexpected::Str(v), &self)),
                }
            }
            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
                #[derive(Deserialize)]
                struct Full<T> {
                    #[serde(default = "yes")]
                    enabled: bool,
                    #[serde(flatten)]
                    options: T,
                }
                fn yes() -> bool {
                    true
                }
                let full = Full::<T>::deserialize(de::value::MapAccessDeserializer::new(map))?;
                Ok(Setting { enabled: full.enabled, options: full.options })
            }
        }
        d.deserialize_any(V(PhantomData))
    }
}

/// For detectors without options.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[non_exhaustive]
pub struct NoOptions {}

/// Options for phone number detection.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(default)]
#[non_exhaustive]
pub struct PhoneOptions {
    /// Countries whose national formats are recognised (ISO 3166 codes).
    /// Numbers written with a leading `+` or `00` are recognised for every country.
    pub regions: Vec<String>,
}

impl Default for PhoneOptions {
    fn default() -> Self {
        PhoneOptions { regions: vec!["US".into()] }
    }
}

/// Options for IP address detection.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(default)]
#[non_exhaustive]
pub struct IpOptions {
    /// Also redact private-range addresses such as 192.168.x.x. Loopback and
    /// unspecified addresses are never redacted.
    pub include_private: bool,
}

impl Default for IpOptions {
    fn default() -> Self {
        IpOptions { include_private: true }
    }
}

/// Options for national ID detection.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(default)]
#[non_exhaustive]
pub struct NatIdOptions {
    /// Supported: US (Social Security number, with dashes), GB (National
    /// Insurance number), DE (tax ID), FR (NIR), ES (DNI and NIE), IT (codice
    /// fiscale), NL (BSN), PL (PESEL) and RO (CNP).
    pub locales: Vec<String>,
}

impl Default for NatIdOptions {
    fn default() -> Self {
        NatIdOptions { locales: ["US", "GB", "DE"].map(String::from).to_vec() }
    }
}

/// Options for name detection.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(default)]
#[non_exhaustive]
pub struct NerOptions {
    /// Minimum confidence, from 0 to 1. Higher means fewer false alarms and
    /// more missed names.
    pub threshold: f32,
    /// Which of PERSON, ORG and LOCATION to redact.
    pub kinds: Vec<String>,
}

impl Default for NerOptions {
    fn default() -> Self {
        NerOptions { threshold: 0.8, kinds: [kinds::PERSON, kinds::ORG, kinds::LOCATION].map(String::from).to_vec() }
    }
}

/// A fixed term to redact.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct DictionaryEntry {
    /// The text to find. It matches only as a whole word.
    pub term: String,
    /// The placeholder kind, such as `CLIENT`. Written `type` in YAML.
    #[serde(rename = "type")]
    pub kind: String,
    /// Match the term's case exactly. Off by default.
    #[serde(default)]
    pub match_case: bool,
}

/// A pattern to redact.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(JsonSchema))]
#[serde(deny_unknown_fields)]
pub struct RegexRule {
    /// A name for the rule, reported as [`Source::Regex`](crate::Source::Regex).
    pub name: String,
    /// The placeholder kind. Written `type` in YAML.
    #[serde(rename = "type")]
    pub kind: String,
    /// The pattern, in the [`regex`](https://docs.rs/regex) crate's syntax.
    pub pattern: String,
}

/// How rules run, besides the rules themselves: the placeholder template
/// and restoration options. Not part of `rules.yaml`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Options {
    /// The placeholder template; see [`PlaceholderFormat`]. Default `[{TYPE}_{N}]`.
    pub placeholder_format: String,
    /// Also restore placeholders the model wrote slightly differently, such
    /// as `[email_1]` or `EMAIL_1`. Off by default.
    pub fuzzy_restore: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options { placeholder_format: DEFAULT_FORMAT.to_owned(), fuzzy_restore: false }
    }
}

/// Why rules could not be compiled.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RulesError {
    /// A kind name is invalid.
    #[error(transparent)]
    Kind(#[from] InvalidKind),
    /// A regex rule's pattern doesn't compile.
    #[error("regex rule {name:?}: {error}")]
    Regex {
        /// The rule's name.
        name: String,
        /// What is wrong with the pattern.
        error: String,
    },
    /// A dictionary entry's term is empty. Holds the entry's index.
    #[error("dictionary entry {0}: the term is empty")]
    EmptyTerm(usize),
    /// A phone region code isn't known.
    #[error("unknown phone region {0:?}")]
    Region(String),
    /// A national ID locale isn't supported.
    #[error("unsupported national ID locale {0:?} (supported: US, GB, DE, FR, ES, IT, NL, PL, RO)")]
    Locale(String),
    /// The placeholder template is invalid.
    #[error("placeholder format: {0}")]
    Placeholder(String),
    /// The rules' version isn't supported.
    #[error("unsupported rules file version {0}")]
    Version(u32),
    /// The name detection options are invalid.
    #[error("name detection: {0}")]
    Ner(String),
    /// The rules turn on a detector this build leaves out, such as `phone`
    /// without the `phone` feature.
    #[error("the {0} detector is not in this build (cargo feature `{0}`)")]
    NotBuiltIn(&'static str),
}

/// Rules ready to run. Built once per change of the rules file or format.
pub struct CompiledRules {
    /// Unique per compile, so cached scans never outlive the rules they used.
    pub(crate) id: u64,
    pub(crate) detectors: Vec<Box<dyn Detector>>,
    pub(crate) ner: Option<NerStage>,
    pub(crate) allowlist: Allowlist,
    pub(crate) placeholder: PlaceholderFormat,
    pub(crate) fuzzy_restore: bool,
}

/// Name detection as configured. `recognizer` is `None` when it is turned on
/// but no model is loaded: scanning then fails, so nothing is sent unredacted.
pub(crate) struct NerStage {
    pub recognizer: Option<Arc<dyn EntityRecognizer>>,
    pub threshold: f32,
    pub kinds: Vec<EntityKind>,
}

impl CompiledRules {
    /// Compiles `rules` with `options`. `recognizer` is the name-detection
    /// model; if the rules turn name detection on and it is `None`, scanning
    /// fails until rules are compiled with one, so names are never sent.
    pub fn compile(
        rules: &RulesFile,
        options: &Options,
        recognizer: Option<Arc<dyn EntityRecognizer>>,
    ) -> Result<Self, RulesError> {
        if rules.version != 1 {
            return Err(RulesError::Version(rules.version));
        }
        let placeholder = PlaceholderFormat::parse(&options.placeholder_format).map_err(RulesError::Placeholder)?;
        let ner = &rules.detectors.ner;
        let ner = if ner.enabled {
            let o = &ner.options;
            if !(0.0..=1.0).contains(&o.threshold) {
                return Err(RulesError::Ner(format!("the threshold must be between 0 and 1, not {}", o.threshold)));
            }
            let allowed = [kinds::PERSON, kinds::ORG, kinds::LOCATION];
            let kinds = o
                .kinds
                .iter()
                .map(|k| match allowed.contains(&k.as_str()) {
                    true => Ok(kind(k)?),
                    false => Err(RulesError::Ner(format!("unknown kind {k:?} (use PERSON, ORG or LOCATION)"))),
                })
                .collect::<Result<_, _>>()?;
            Some(NerStage { recognizer, threshold: o.threshold, kinds })
        } else {
            None
        };
        static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        Ok(CompiledRules {
            id: NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            detectors: detect::build(rules)?,
            ner,
            allowlist: Allowlist::new(&rules.allowlist),
            placeholder,
            fuzzy_restore: options.fuzzy_restore,
        })
    }

    /// True if the rules turn name detection on but no model was supplied.
    pub fn ner_missing(&self) -> bool {
        self.ner.as_ref().is_some_and(|n| n.recognizer.is_none())
    }

    /// True if the rules turn name detection on.
    pub fn ner_enabled(&self) -> bool {
        self.ner.is_some()
    }

    /// The placeholder format these rules use.
    pub fn placeholder(&self) -> &PlaceholderFormat {
        &self.placeholder
    }
}

impl Default for CompiledRules {
    fn default() -> Self {
        CompiledRules::compile(&RulesFile::default(), &Options::default(), None).expect("default rules compile")
    }
}

pub(crate) fn kind(name: &str) -> Result<EntityKind, InvalidKind> {
    EntityKind::new(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn format(template: &str) -> Options {
        Options { placeholder_format: template.into(), ..Options::default() }
    }

    #[test]
    fn parses_shorthand_and_full_settings() {
        let yaml = r#"
version: 1
detectors:
  email: on
  url: off
  card: false
  phone: { enabled: true, regions: [GB] }
  ip: { include_private: false }
dictionary:
  - { term: "Project Halcyon", type: CODENAME, match_case: true }
regex:
  - { name: tickets, type: TICKET, pattern: '\bTCK-\d{6}\b' }
allowlist: [support@acme.com]
"#;
        let r: RulesFile = serde_yaml_ng::from_str(yaml).unwrap();
        assert!(r.detectors.email.enabled);
        assert!(!r.detectors.url.enabled && !r.detectors.card.enabled);
        assert_eq!(r.detectors.phone.options.regions, ["GB"]);
        assert!(r.detectors.ip.enabled && !r.detectors.ip.options.include_private);
        assert!(r.detectors.natid.enabled);
        assert_eq!(r.dictionary[0].kind, "CODENAME");
        CompiledRules::compile(&r, &Options::default(), None).unwrap();
    }

    #[test]
    fn reports_bad_rules() {
        let mut r = RulesFile::default();
        r.regex.push(RegexRule { name: "x".into(), kind: "X".into(), pattern: "(".into() });
        assert!(matches!(CompiledRules::compile(&r, &Options::default(), None), Err(RulesError::Regex { .. })));
        let mut r = RulesFile::default();
        r.dictionary.push(DictionaryEntry { term: "a".into(), kind: "lower".into(), match_case: false });
        assert!(matches!(CompiledRules::compile(&r, &Options::default(), None), Err(RulesError::Kind(_))));
        let mut r = RulesFile::default();
        r.detectors.phone.options.regions = vec!["XX".into()];
        assert!(matches!(CompiledRules::compile(&r, &Options::default(), None), Err(RulesError::Region(_))));
        let mut r = RulesFile::default();
        r.detectors.natid.options.locales = vec!["XX".into()];
        assert!(matches!(CompiledRules::compile(&r, &Options::default(), None), Err(RulesError::Locale(_))));
        assert!(matches!(
            CompiledRules::compile(&RulesFile::default(), &format("{TYPE}"), None),
            Err(RulesError::Placeholder(_))
        ));
    }

    #[test]
    fn phone_detection_is_on_by_default_only_when_built_in() {
        assert_eq!(RulesFile::default().detectors.phone.enabled, cfg!(feature = "phone"));
        CompiledRules::default();
        let mut r = RulesFile::default();
        r.detectors.phone.enabled = true;
        let compiled = CompiledRules::compile(&r, &Options::default(), None);
        if cfg!(feature = "phone") {
            assert!(compiled.is_ok());
        } else {
            assert!(matches!(compiled, Err(RulesError::NotBuiltIn("phone"))));
        }
    }

    #[test]
    fn rejects_unknown_fields() {
        assert!(serde_yaml_ng::from_str::<RulesFile>("detectors: { emial: on }").is_err());
    }
}
