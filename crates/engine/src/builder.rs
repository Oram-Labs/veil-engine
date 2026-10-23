//! Building an [`Engine`].

use std::sync::Arc;

use arc_swap::ArcSwap;

use crate::scan_cache::{self, ScanCache};
use crate::{CompiledRules, Engine, EntityRecognizer, MemoryVault, Options, Recorder, RulesError, RulesFile, Vault};

/// Builds an [`Engine`]. Start with [`Engine::builder`].
///
/// ```
/// use veil_engine::{Engine, RulesFile, ScopeId};
///
/// let engine = Engine::builder().rules(RulesFile::default()).build()?;
/// let r = engine.redact_text(&ScopeId::new("chat-42"), "Email ana@example.com")?;
/// assert_eq!(r.text, "Email [EMAIL_1]");
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[must_use]
pub struct EngineBuilder {
    rules: Rules,
    options: Options,
    recognizer: Option<Arc<dyn EntityRecognizer>>,
    vault: Option<Arc<dyn Vault>>,
    recorder: Option<Arc<dyn Recorder>>,
    scan_cache_bytes: usize,
}

enum Rules {
    File(RulesFile),
    Compiled(CompiledRules),
}

impl Default for EngineBuilder {
    fn default() -> Self {
        EngineBuilder {
            rules: Rules::File(RulesFile::default()),
            options: Options::default(),
            recognizer: None,
            vault: None,
            recorder: None,
            scan_cache_bytes: scan_cache::DEFAULT_BUDGET,
        }
    }
}

impl EngineBuilder {
    /// What to detect. Default: [`RulesFile::default`].
    pub fn rules(mut self, rules: RulesFile) -> Self {
        self.rules = Rules::File(rules);
        self
    }

    /// The placeholder format and restoration options. Default: [`Options::default`].
    pub fn options(mut self, options: Options) -> Self {
        self.options = options;
        self
    }

    /// The name-detection model, used when the rules turn name detection on.
    /// Without one, such rules make every redaction fail rather than send names.
    pub fn recognizer(mut self, recognizer: Arc<dyn EntityRecognizer>) -> Self {
        self.recognizer = Some(recognizer);
        self
    }

    /// Rules compiled in advance with [`CompiledRules::compile`], used as they
    /// are. Replaces anything given to [`rules`](Self::rules),
    /// [`options`](Self::options) and [`recognizer`](Self::recognizer).
    pub fn compiled_rules(mut self, rules: CompiledRules) -> Self {
        self.rules = Rules::Compiled(rules);
        self
    }

    /// Where placeholder mappings are kept. Default: a new [`MemoryVault`].
    pub fn vault(mut self, vault: Arc<dyn Vault>) -> Self {
        self.vault = Some(vault);
        self
    }

    /// Told about every value that live traffic matched. Default: none.
    pub fn recorder(mut self, recorder: Arc<dyn Recorder>) -> Self {
        self.recorder = Some(recorder);
        self
    }

    /// Memory for remembering scans between calls, in bytes; 0 scans every
    /// call in full. Default: [`DEFAULT_SCAN_CACHE_BUDGET`](crate::DEFAULT_SCAN_CACHE_BUDGET).
    pub fn scan_cache_bytes(mut self, bytes: usize) -> Self {
        self.scan_cache_bytes = bytes;
        self
    }

    /// Compiles the rules, unless they were given compiled, and builds the engine.
    pub fn build(self) -> Result<Engine, RulesError> {
        let rules = match self.rules {
            Rules::File(file) => CompiledRules::compile(&file, &self.options, self.recognizer)?,
            Rules::Compiled(compiled) => compiled,
        };
        Ok(Engine {
            rules: ArcSwap::from_pointee(rules),
            vault: self.vault.unwrap_or_else(|| Arc::new(MemoryVault::default())),
            recorder: self.recorder,
            scans: ScanCache::new(self.scan_cache_bytes),
        })
    }
}
