//! Walks every string in a JSON value, letting the caller skip structural keys.

use serde_json::{Map, Value};

use crate::Error;

/// What to do with one key's value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyAction {
    /// Leave this key's value untouched.
    Skip,
    /// Walk this key's value with the same policy.
    Walk,
    /// Walk every string under this key, ignoring the policy. Used for
    /// free-form user data such as tool-call arguments.
    WalkAll,
    /// The value is a string that itself holds JSON, such as OpenAI's
    /// `function.arguments`. Every string inside it is walked.
    JsonString,
}

/// Decides, per object key, whether its value is redacted or restored.
pub trait KeyPolicy: Sync {
    /// What to do with `key`, given the object it is in.
    fn action(&self, parent: &Map<String, Value>, key: &str) -> KeyAction;
}

/// A policy that walks everything.
pub struct WalkAll;

impl KeyPolicy for WalkAll {
    fn action(&self, _: &Map<String, Value>, _: &str) -> KeyAction {
        KeyAction::Walk
    }
}

/// What kind of string the visitor is given.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StrKind {
    Plain,
    Json,
}

pub(crate) type Visitor<'a> = dyn FnMut(&mut String, StrKind) -> Result<(), Error> + 'a;

pub(crate) fn walk(value: &mut Value, policy: &dyn KeyPolicy, f: &mut Visitor<'_>) -> Result<(), Error> {
    match value {
        Value::String(s) => f(s, StrKind::Plain),
        Value::Array(items) => items.iter_mut().try_for_each(|v| walk(v, policy, f)),
        Value::Object(map) => {
            let actions: Vec<(String, KeyAction)> = map.keys().map(|k| (k.clone(), policy.action(map, k))).collect();
            for (key, action) in actions {
                let child = map.get_mut(&key).expect("key exists");
                match action {
                    KeyAction::Skip => {}
                    KeyAction::Walk => walk(child, policy, f)?,
                    KeyAction::WalkAll => walk(child, &WalkAll, f)?,
                    KeyAction::JsonString => match child {
                        Value::String(s) => f(s, StrKind::Json)?,
                        other => walk(other, &WalkAll, f)?,
                    },
                }
            }
            Ok(())
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => Ok(()),
    }
}
