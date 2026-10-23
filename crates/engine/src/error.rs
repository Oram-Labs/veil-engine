//! Errors from redacting and scanning.

use std::error::Error as StdError;
use std::fmt;

/// Why a redaction or scan failed. Callers should not send the text on: a
/// failed redaction means sensitive values may still be in it.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The rules turn name detection on, but no [`EntityRecognizer`](crate::EntityRecognizer)
    /// was given. The engine fails rather than send names unredacted.
    #[error("name detection is on, but no name-detection model was given")]
    RecognizerMissing,
    /// The name-detection model failed.
    #[error("name detection failed: {0}")]
    Recognizer(#[from] RecognizerError),
    /// The [`Vault`](crate::Vault) failed.
    #[error("vault: {0}")]
    Vault(#[from] VaultError),
}

/// Defines an error type that wraps an implementation's own error, so the
/// engine's API doesn't depend on any one implementation.
macro_rules! wrapped_error {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Debug)]
        pub struct $name(Box<dyn StdError + Send + Sync>);

        impl $name {
            /// Wraps an error, or a message such as `"disk full"`.
            pub fn new(error: impl Into<Box<dyn StdError + Send + Sync>>) -> Self {
                $name(error.into())
            }

            /// The wrapped error, for example to downcast it.
            pub fn get_ref(&self) -> &(dyn StdError + Send + Sync + 'static) {
                &*self.0
            }

            /// Returns the wrapped error.
            pub fn into_inner(self) -> Box<dyn StdError + Send + Sync> {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }

        impl StdError for $name {
            fn source(&self) -> Option<&(dyn StdError + 'static)> {
                self.0.source()
            }
        }
    };
}

wrapped_error! {
    /// An error from a [`Vault`](crate::Vault) implementation.
    VaultError
}

wrapped_error! {
    /// An error from an [`EntityRecognizer`](crate::EntityRecognizer) implementation.
    RecognizerError
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapped_errors_show_the_inner_message() {
        let io = std::io::Error::other("disk full");
        let e = Error::from(VaultError::new(io));
        assert_eq!(e.to_string(), "vault: disk full");
        let Error::Vault(v) = e else { unreachable!() };
        assert!(v.get_ref().downcast_ref::<std::io::Error>().is_some());
        assert_eq!(
            Error::from(RecognizerError::new("model crashed")).to_string(),
            "name detection failed: model crashed"
        );
    }
}
