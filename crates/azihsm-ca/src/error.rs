//! Closed product error and exit-code mapping.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorClass {
    Usage = 2,
    State = 3,
    Provider = 4,
    PendingInitialization = 5,
    Validation = 6,
    Http = 7,
    Issuance = 8,
    AlreadyInitialized = 10,
    StateBusy = 11,
    Precondition = 12,
}

#[derive(Debug)]
pub struct Error {
    class: ErrorClass,
    message: String,
}

impl Error {
    pub fn new(class: ErrorClass, message: impl Into<String>) -> Self {
        Self {
            class,
            message: message.into(),
        }
    }

    pub fn exit_code(&self) -> u8 {
        self.class as u8
    }

    pub fn class(&self) -> ErrorClass {
        self.class
    }
}

#[allow(non_upper_case_globals)]
impl ErrorClass {
    pub(crate) const Signing: Self = Self::Issuance;
    pub(crate) const Cleanup: Self = Self::State;
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.class, self.message)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;
