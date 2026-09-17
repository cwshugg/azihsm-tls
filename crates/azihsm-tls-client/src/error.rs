// Copyright (C) Microsoft Corporation. All rights reserved.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCode {
    Usage = 2,
    Io = 3,
    Tls = 4,
    Trust = 5,
}

#[derive(Debug)]
pub struct Error {
    code: ExitCode,
    message: String,
}

impl Error {
    pub fn new(code: ExitCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn exit_code(&self) -> u8 {
        self.code as u8
    }

    pub fn code(&self) -> ExitCode {
        self.code
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;
