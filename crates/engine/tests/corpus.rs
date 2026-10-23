//! Runs every file in `fixtures/corpus`: each positive must be found with the
//! exact expected text and kind, and no negative may produce that kind.

use std::path::PathBuf;

use serde::Deserialize;
use veil_engine::{Engine, RulesFile, Setting};

#[derive(Deserialize)]
struct Corpus {
    kind: String,
    /// National ID locales to turn on for this file; the default set otherwise.
    #[serde(default)]
    natid_locales: Option<Vec<String>>,
    /// Phone regions to turn on for this file; the default set otherwise.
    #[serde(default)]
    phone_regions: Option<Vec<String>>,
    positive: Vec<Positive>,
    negative: Vec<String>,
}

#[derive(Deserialize)]
struct Positive {
    text: String,
    #[serde(rename = "match")]
    expected: String,
}

fn engine(natid_locales: Option<&Vec<String>>, phone_regions: Option<&Vec<String>>) -> Engine {
    let mut rules = RulesFile::default();
    if let Some(r) = phone_regions {
        rules.detectors.phone.options.regions = r.clone();
    }
    if let Some(l) = natid_locales {
        rules.detectors.natid.options.locales = l.clone();
    }
    rules.detectors.url = Setting::on();
    rules.allowlist.clear();
    Engine::builder().rules(rules).build().unwrap()
}

#[test]
fn corpus() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/corpus");
    let mut failures = Vec::new();
    let mut files = 0;
    for entry in std::fs::read_dir(&dir).expect("corpus directory exists") {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "yaml") {
            continue;
        }
        files += 1;
        let corpus: Corpus = serde_yaml_ng::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert!(corpus.positive.len() >= 20 && corpus.negative.len() >= 20, "{}: needs 20 of each", corpus.kind);
        let engine = engine(corpus.natid_locales.as_ref(), corpus.phone_regions.as_ref());
        for p in &corpus.positive {
            let found = engine.scan(&p.text).unwrap();
            if !found.iter().any(|m| m.kind.as_str() == corpus.kind && p.text[m.start..m.end] == p.expected) {
                let got: Vec<_> = found.iter().map(|m| format!("{}={:?}", m.kind, &p.text[m.start..m.end])).collect();
                failures.push(format!("{} missed {:?} in {:?}; found {got:?}", corpus.kind, p.expected, p.text));
            }
        }
        for n in &corpus.negative {
            for m in engine.scan(n).unwrap().iter().filter(|m| m.kind.as_str() == corpus.kind) {
                failures.push(format!("{} false positive {:?} in {n:?}", corpus.kind, &n[m.start..m.end]));
            }
        }
    }
    assert!(files >= 8, "expected the corpus files in {}", dir.display());
    assert!(failures.is_empty(), "{} corpus failures:\n{}", failures.len(), failures.join("\n"));
}
