//! Names found by a statistical model (named-entity recognition).
//!
//! The engine does no I/O, so the model itself lives elsewhere and is
//! plugged in through [`EntityRecognizer`].

use crate::kind::EntityKind;
use crate::RecognizerError;

/// A name the model found. Offsets are bytes into the text it was given.
#[derive(Clone, Debug, PartialEq)]
pub struct Entity {
    /// Byte offset where the name starts.
    pub start: usize,
    /// Byte offset just past the name.
    pub end: usize,
    /// One of `PERSON`, `ORG` or `LOCATION`.
    pub kind: EntityKind,
    /// The model's confidence, 0 to 1.
    pub score: f32,
}

/// Finds names in text. Implementations should return every entity they
/// find with its score; the engine applies the threshold from the rules.
pub trait EntityRecognizer: Send + Sync {
    /// Returns every name found in `text`, with byte offsets into it.
    fn recognize(&self, text: &str) -> Result<Vec<Entity>, RecognizerError>;
}
