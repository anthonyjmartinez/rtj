// rtj provides a generic job execution framework in Rust
// Copyright 2021-2024 Anthony Martinez
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

/// Custom errors for RTJ crate
#[derive(Debug)]
pub enum RtjError {
    Generic(Box<dyn std::error::Error>),
    Encryption(crypto_box::aead::Error),
    Rng(rand::Error),
    InvalidOperation(String),
}

impl std::fmt::Display for RtjError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            RtjError::Generic(..) => {
                write!(f, "general error")
            }
            RtjError::Encryption(..) => {
                write!(f, "encryption/decryption failure")
            }
            RtjError::Rng(..) => {
                write!(f, "rng failure")
            }
            RtjError::InvalidOperation(..) => {
                write!(f, "invalid operation")
            }
        }
    }
}

impl std::error::Error for RtjError {}

impl From<Box<dyn std::error::Error>> for RtjError {
    fn from(err: Box<dyn std::error::Error>) -> RtjError {
        RtjError::Generic(err)
    }
}

impl From<rand::Error> for RtjError {
    fn from(err: rand::Error) -> RtjError {
        RtjError::Rng(err)
    }
}

impl From<crypto_box::aead::Error> for RtjError {
    fn from(err: crypto_box::aead::Error) -> RtjError {
        RtjError::Encryption(err)
    }
}
