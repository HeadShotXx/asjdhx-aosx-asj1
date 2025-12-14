use base64::{engine::general_purpose, Engine as _};
use std::string::FromUtf8Error;
use base64::DecodeError;
use std::fmt;
use std::error::Error;

#[derive(Debug)]
pub enum DeobfuscateError {
    Base64(DecodeError),
    Utf8(FromUtf8Error),
}

impl fmt::Display for DeobfuscateError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DeobfuscateError::Base64(e) => write!(f, "Base64 decoding error: {}", e),
            DeobfuscateError::Utf8(e) => write!(f, "UTF-8 conversion error: {}", e),
        }
    }
}

impl Error for DeobfuscateError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            DeobfuscateError::Base64(e) => Some(e),
            DeobfuscateError::Utf8(e) => Some(e),
        }
    }
}

impl From<DecodeError> for DeobfuscateError {
    fn from(err: DecodeError) -> DeobfuscateError {
        DeobfuscateError::Base64(err)
    }
}

impl From<FromUtf8Error> for DeobfuscateError {
    fn from(err: FromUtf8Error) -> DeobfuscateError {
        DeobfuscateError::Utf8(err)
    }
}

pub fn deobfuscate(encoded: &str) -> Result<String, DeobfuscateError> {
    general_purpose::STANDARD.decode(encoded)
        .map_err(DeobfuscateError::Base64)
        .and_then(|bytes| String::from_utf8(bytes).map_err(DeobfuscateError::Utf8))
}
