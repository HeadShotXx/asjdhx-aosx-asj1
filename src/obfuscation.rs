use base64::{engine::general_purpose, Engine as _};
use std::string::FromUtf8Error;
use base64::DecodeError;
use std::fmt;
use std::error::Error;

const XOR_KEY: u8 = 0x55;

#[derive(Debug)]
pub enum DeobfuscateError {
    Base64(DecodeError),
    Base45(qr_base45::Base45Error),
    Utf8(FromUtf8Error),
}

impl fmt::Display for DeobfuscateError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DeobfuscateError::Base64(e) => write!(f, "Base64 decoding error: {}", e),
            DeobfuscateError::Base45(e) => write!(f, "Base45 decoding error: {}", e),
            DeobfuscateError::Utf8(e) => write!(f, "UTF-8 conversion error: {}", e),
        }
    }
}

impl Error for DeobfuscateError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            DeobfuscateError::Base64(e) => Some(e),
            DeobfuscateError::Base45(e) => Some(e),
            DeobfuscateError::Utf8(e) => Some(e),
        }
    }
}

impl From<DecodeError> for DeobfuscateError {
    fn from(err: DecodeError) -> DeobfuscateError {
        DeobfuscateError::Base64(err)
    }
}

impl From<qr_base45::Base45Error> for DeobfuscateError {
    fn from(err: qr_base45::Base45Error) -> DeobfuscateError {
        DeobfuscateError::Base45(err)
    }
}

impl From<FromUtf8Error> for DeobfuscateError {
    fn from(err: FromUtf8Error) -> DeobfuscateError {
        DeobfuscateError::Utf8(err)
    }
}

fn xor_decrypt(data: &[u8]) -> Vec<u8> {
    data.iter().map(|&b| b ^ XOR_KEY).collect()
}

pub fn deobfuscate(encoded: &str) -> Result<String, DeobfuscateError> {
    let base64_decoded_bytes = general_purpose::STANDARD.decode(encoded)?;
    let base45_encoded_str = String::from_utf8(base64_decoded_bytes)?;
    let base45_decoded_bytes = qr_base45::decode(&base45_encoded_str)?;
    let xor_decrypted_bytes = xor_decrypt(&base45_decoded_bytes);
    String::from_utf8(xor_decrypted_bytes).map_err(DeobfuscateError::Utf8)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xor_encrypt(data: &[u8]) -> Vec<u8> {
        data.iter().map(|&b| b ^ XOR_KEY).collect()
    }

    #[test]
    fn test_deobfuscation_symmetry() {
        let original_string = "Hello, World!";

        // Encode
        let xor_encrypted = xor_encrypt(original_string.as_bytes());
        let base45_encoded = qr_base45::encode(&xor_encrypted);
        let base64_encoded = general_purpose::STANDARD.encode(&base45_encoded);

        // Decode
        let deobfuscated_string = deobfuscate(&base64_encoded).unwrap();

        assert_eq!(original_string, deobfuscated_string);
    }
}
