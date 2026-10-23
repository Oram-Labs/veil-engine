//! Redaction and restoration speed. Run with `cargo bench -p veil-engine`.
//!
//! Budgets from the implementation plan: under 5 ms for 100 KB with a
//! 10,000-term dictionary, and a median added latency under 5 ms for a
//! typical request.

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use serde_json::{json, Map, Value};
use veil_engine::{DictionaryEntry, Engine, KeyAction, KeyPolicy, RulesFile, ScopeId, StreamRestorer};

/// Ordinary prose and code with a sensitive value every few hundred bytes.
fn text(bytes: usize) -> String {
    let parts = [
        "The deploy finished at 14:02 and the dashboard looks healthy again. ",
        "Please email ana.popescu@example.com about invoice 2041 before Friday. ",
        "fn total(items: &[Item]) -> u64 { items.iter().map(|i| i.price * i.qty).sum() }\n",
        "Call me on +44 20 7946 0958 if the build breaks again tonight. ",
        "We moved the staging database to 10.20.30.40 last week; nothing else changed. ",
        "Refund card 4111 1111 1111 1111 and close ticket TCK-004211, then tell the team. ",
        "Version 2.1.294 of the CLI fixed the timeout; the next release is planned for March. ",
    ];
    let mut out = String::with_capacity(bytes + 100);
    let mut i = 0;
    while out.len() < bytes {
        out.push_str(parts[i % parts.len()]);
        i += 1;
    }
    out
}

fn dictionary(n: usize) -> Vec<DictionaryEntry> {
    (0..n)
        .map(|i| DictionaryEntry {
            term: match i % 3 {
                0 => format!("Client {i} Holdings"),
                1 => format!("Ștefan Proiect{i}"),
                _ => format!("CODE{i:05}"),
            },
            kind: "CLIENT".into(),
            match_case: i % 3 == 2,
        })
        .collect()
}

fn engine(rules: &RulesFile) -> Engine {
    Engine::builder().rules(rules.clone()).build().unwrap()
}

struct Messages;
impl KeyPolicy for Messages {
    fn action(&self, _: &Map<String, Value>, key: &str) -> KeyAction {
        match key {
            "model" | "role" | "type" | "id" | "name" => KeyAction::Skip,
            _ => KeyAction::Walk,
        }
    }
}

/// A typical coding-assistant request: a long system prompt and a few turns.
fn request() -> Value {
    json!({
        "model": "claude-sonnet",
        "max_tokens": 4096,
        "system": text(6_000),
        "messages": [
            {"role": "user", "content": text(800)},
            {"role": "assistant", "content": [{"type": "text", "text": text(600)}]},
            {"role": "user", "content": [{"type": "text", "text": "Now fix the failing test and email bob@example.org."}]}
        ]
    })
}

fn benches(c: &mut Criterion) {
    let scope = ScopeId::profile("bench");
    let big = text(100_000);

    let mut g = c.benchmark_group("redact 100 KB");
    g.throughput(Throughput::Bytes(big.len() as u64));
    let default = engine(&RulesFile::default());
    g.bench_function("default rules", |b| b.iter(|| default.redact_text(&scope, black_box(&big)).unwrap()));
    let mut dict_rules = RulesFile::default();
    dict_rules.dictionary = dictionary(10_000);
    let with_dict = engine(&dict_rules);
    g.bench_function("default rules + 10,000-term dictionary", |b| {
        b.iter(|| with_dict.redact_text(&scope, black_box(&big)).unwrap())
    });
    // Worst case for the phone detector: every number is new, so none is
    // answered from its cache. Uses its own engine so the cache starts empty.
    let mut n = 0u32;
    g.bench_function("default rules, 200 unseen phone numbers", |b| {
        b.iter_batched(
            || {
                n += 1;
                let mut t = big.clone();
                for i in 0..200 {
                    t.push_str(&format!(" call +44 20 7946 {:04} ", (n * 200 + i) % 10_000));
                }
                (engine(&RulesFile::default()), t)
            },
            |(e, t)| e.redact_text(&scope, black_box(&t)).unwrap(),
            criterion::BatchSize::LargeInput,
        )
    });
    g.finish();

    let body = request();
    let mut g = c.benchmark_group("typical request");
    g.throughput(Throughput::Bytes(body.to_string().len() as u64));
    g.bench_function("redact_json (8 KB body)", |b| {
        b.iter(|| {
            let mut v = body.clone();
            default.redact_json(&scope, &mut v, &Messages).unwrap()
        })
    });
    g.finish();

    let reply = default.redact_text(&scope, &text(20_000)).unwrap().text;
    let mut g = c.benchmark_group("restore");
    g.throughput(Throughput::Bytes(reply.len() as u64));
    g.bench_function("stream 20 KB in 8-byte chunks", |b| {
        b.iter(|| {
            let mut r = StreamRestorer::default();
            let mut out = String::new();
            let mut i = 0;
            while i < reply.len() {
                let mut j = (i + 8).min(reply.len());
                while !reply.is_char_boundary(j) {
                    j += 1;
                }
                out.push_str(&r.push(&default, &scope, &reply[i..j]));
                i = j;
            }
            out.push_str(&r.finish(&default, &scope));
            out
        })
    });
    g.finish();
}

criterion_group!(group, benches);
criterion_main!(group);
