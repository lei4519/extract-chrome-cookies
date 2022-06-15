use colored::*;
use core::result::Result;
use crypto::{
    aes::cbc_decryptor,
    blockmodes::PkcsPadding,
    buffer::{BufferResult, ReadBuffer, RefReadBuffer, RefWriteBuffer, WriteBuffer},
    hmac::Hmac,
    pbkdf2::pbkdf2,
    sha1::Sha1,
};
use keytar;
use rusqlite::{Connection, Row};
use std::{
    env,
    io::{self, Write},
    path::Path,
    process::exit,
};
use url::Url;

use clap::{Arg, ArgMatches, Command};

static SALT: &[u8; 9] = b"saltysalt";
const KEYLENGTH: usize = 16;
const IV: [u8; 16] = [32; KEYLENGTH];
const MAC_ITERATIONS: u32 = 1003;
const LINUX_ITERATIONS: u32 = 1;
const FORMATS: [&str; 4] = ["curl", "header", "json", "object"];
const FORMAT_HELP: &str =
    "Control how cookies are formatted, One of 'curl', 'header', 'json', 'object'";
#[derive(Debug)]
struct Cookie {
    host_key: String,
    path: String,
    is_secure: u8,
    expires_utc: usize,
    name: String,
    value: String,
    encrypted_value: Vec<u8>,
    creation_utc: usize,
    is_httponly: u8,
    has_expires: u8,
    is_persistent: u8,
}

fn main() {
    let matchs = build_cli().get_matches();

    match run(matchs) {
        Ok(_) => {}
        Err(e) => {
            println!("{}", e.red());
            exit(1);
        }
    };
}

fn run(matchs: ArgMatches) -> Result<(), String> {
    let url = matchs.value_of("url").unwrap();
    let format = matchs.value_of("format").unwrap();
    let profile = matchs.value_of("profile_name").unwrap();
    let profile_path = matchs.value_of("profile_path");

    let url = Url::parse(url).map_err(|e| format!("URL Parse Error: {}", e))?;

    let domain = url
        .domain()
        .ok_or("Could not parse domain from URI, format should be http://www.example.com/path/")?;

    // println!("{:#?}", url);
    // println!("{:#?}", format);
    // println!("{:#?}", profile);
    // println!("{:#?}", profile_path);

    let path;
    let mut home_path = String::new();
    if profile_path.is_some() {
        path = profile_path.unwrap().to_string();
    } else {
        home_path = get_home_path().ok_or(cant_resolve_profile_path(None)?)?;

        path = get_profile_path(&home_path, profile)? + "/Cookies";
    }

    if !Path::new(&path).exists() {
        let home = if home_path.is_empty() {
            None
        } else {
            Some(home_path)
        };
        return Err(cant_resolve_profile_path(home)?);
    }

    let connection = Connection::open(path).map_err(|e| format!("Open database Failed: {e}"))?;

    let cookies = get_cookies(&connection, domain)?;

    let result = format_cookies(format, &cookies);

    print!("{result}");

    io::stdout().flush().unwrap();

    connection.close();

    Ok(())
}

fn build_cli() -> Command<'static> {
    Command::new("extract-chrome-cookies")
        .version("0.0.1")
        .about("Getting cookies by reading Chrome's cookie database on your computer.")
        .arg(
            Arg::new("url")
                .required(true)
                .help("Extract the cookie of this URL"),
        )
        .arg(
            Arg::new("format")
                .short('f')
                .takes_value(true)
                .default_value("curl")
                .validator(|v| {
                    if FORMATS.contains(&v) {
                        return Ok(());
                    }
                    Err(format!("{}{:?}", "Must One of ", &FORMATS))
                })
                .help(FORMAT_HELP),
        )
        .arg(
            Arg::new("profile_name")
                .short('n')
                .takes_value(true)
                // TODO
                // .default_value("Default")
                .default_value("Profile 1")
                .help("Chrome Profile Name"),
        )
        .arg(
            Arg::new("profile_path")
                .short('p')
                .takes_value(true)
                .help("Direct pass chrome profile path"),
        )
}

fn cant_resolve_profile_path(home_path: Option<String>) -> Result<String, String> {
    if home_path.is_none() {
        print!("{}\n\n", "The program can't resolve your Google profile path automatically, Please use '-p' option to pass it in manually.".red());
    } else {
        print!("{}\n\n", "The program can't resolve your Google profile path automatically, you need to pass it in manually.".red());
    }
    print!("{}\n", "Follow these steps find your profile path:".green());
    print!("  {}\n", "1. Open Chrome");
    print!("  {}\n", "2. Enter 'chrome://version'");
    print!("  {}\n\n", "3. Find 'profile path'");

    if home_path.is_some() {
        let path = get_profile_path(&home_path.unwrap(), "<PROFILE NAME>")?;
        print!("{}\n", "If the path looks like this:".green());
        print!("  {}\n\n", path);
        print!("{}\n", "You just pass in the profile name:".green());
        print!(
            "  {}\n\n",
            "extract-chrome-cookies <URL> -n <PROFILE NAME>".cyan()
        );

        print!(
            "{}\n",
            "Otherwise, you need to pass in the entire profile path:".green()
        );
    } else {
        print!("{}\n", "Run command:".green());
    }

    print!(
        "  {}",
        "extract-chrome-cookies <URL> -p <PROFILE PATH>".cyan()
    );

    io::stdout().flush().unwrap();

    Ok(String::new())
}

fn get_home_path() -> Option<String> {
    Some(String::from(home::home_dir()?.to_str()?))
}

fn get_profile_path(home_path: &str, profile: &str) -> Result<String, String> {
    match env::consts::OS {
        "macos" => Ok(format!(
            "{home_path}/Library/Application Support/Google/Chrome/{profile}",
        )),
        "linux" => Ok(format!("{home_path}/.config/google-chrome/{profile}")),
        // "windows" => {
        //     let mut p = format!(
        //         "{home_path}\\AppData\\Local\\Google\\Chrome\\User Data\\{profile}\\Network"
        //     );
        //     if !Path::new(&p).exists() {
        //         p = format!("{home_path}\\AppData\\Local\\Google\\Chrome\\User Data\\{profile}");
        //     }
        //     p
        // }
        _ => Err("Only Mac and Linux are supported.".to_string()),
    }
}

fn get_cookies(conn: &Connection, domain: &str) -> Result<Vec<Cookie>, String> {
    // only macos linux can go here, so value must a Some
    let key = get_derived_key().ok_or("Get derived key failed.")?;

    let statement = format!("SELECT host_key, path, is_secure, expires_utc, name, value, encrypted_value, creation_utc, is_httponly, has_expires, is_persistent FROM cookies where host_key like '%{domain}' ORDER BY LENGTH(path) DESC, creation_utc ASC");

    let mut stmt = conn
        .prepare(&statement)
        .map_err(|e| format!("Prepare a SQL statement for execution failed: {e}"))?;

    let rows = stmt
        .query_map([], |row: &Row| {
            // for i in 1..11 {
            //     println!("{i}: {:#?}", row.get_ref(i));
            // }
            Ok(Cookie {
                host_key: row.get(0)?,
                path: row.get(1)?,
                is_secure: row.get(2)?,
                expires_utc: row.get(3)?,
                name: row.get(4)?,
                value: row.get(5)?,
                encrypted_value: row.get(6)?,
                creation_utc: row.get(7)?,
                is_httponly: row.get(8)?,
                has_expires: row.get(9)?,
                is_persistent: row.get(10)?,
            })
        })
        .map_err(|e| format!("Query Cookie Map Failed: {}", e))?;

    let mut cookies = vec![];

    for cookie in rows {
        let mut cookie = cookie.map_err(|e| format!("Get Cookie Map Failed: {}", e))?;

        if cookie.value.is_empty() && !cookie.encrypted_value.is_empty() {
            cookie.value = decrypt(&key, &cookie.encrypted_value)?;
            // if (process.platform === 'win32') {
            //   if (encryptedValue[0] == 0x01 && encryptedValue[1] == 0x00 && encryptedValue[2] == 0x00 && encryptedValue[3] == 0x00) {
            //     cookie.value = dpapi.unprotectData(encryptedValue, null, 'CurrentUser').toString('utf-8');

            //   } else if (encryptedValue[0] == 0x76 && encryptedValue[1] == 0x31 && encryptedValue[2] == 0x30) {
            //     localState = JSON.parse(fs.readFileSync(os.homedir() + '/AppData/Local/Google/Chrome/User Data/Local State'));
            //     b64encodedKey = localState.os_crypt.encrypted_key;
            //     encryptedKey = new Buffer.from(b64encodedKey, 'base64');
            //     key = dpapi.unprotectData(encryptedKey.slice(5, encryptedKey.length), null, 'CurrentUser');
            //     nonce = encryptedValue.slice(3, 15);
            //     tag = encryptedValue.slice(encryptedValue.length - 16, encryptedValue.length);
            //     encryptedValue = encryptedValue.slice(15, encryptedValue.length - 16);
            //     cookie.value = decryptAES256GCM(key, encryptedValue, nonce, tag).toString('utf-8');
            //   }
            // }
        }

        cookies.push(cookie);
    }
    Ok(cookies)
}

fn get_derived_key() -> Option<[u8; 16]> {
    match env::consts::OS {
        "macos" => {
            // format!("{home_path}/Library/Application Support/Google/Chrome/{profile}",)
            if let Ok(res) = keytar::get_password("Chrome Safe Storage", "Chrome") {
                if res.success {
                    let mut buffer: [u8; 16] = [0; 16];
                    let mut m = Hmac::new(Sha1::new(), res.password.as_bytes());
                    pbkdf2(&mut m, SALT, MAC_ITERATIONS, &mut buffer);

                    return Some(buffer);
                }
            }
            return None;
        }
        "linux" => {
            let mut buffer: [u8; 16] = [0; 16];
            let mut m = Hmac::new(Sha1::new(), b"peanuts");
            pbkdf2(&mut m, SALT, MAC_ITERATIONS, &mut buffer);

            return Some(buffer);
        }
        _ => None,
    }
}

fn decrypt(key: &[u8], encrypted_data: &[u8]) -> Result<String, String> {
    let mut decipher = cbc_decryptor(crypto::aes::KeySize::KeySize128, &key, &IV, PkcsPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = RefReadBuffer::new(&encrypted_data[3..]);
    let mut buffer = [0; 4096];
    let mut write_buffer = RefWriteBuffer::new(&mut buffer);

    loop {
        let result = decipher.decrypt(&mut read_buffer, &mut write_buffer, true);
        final_result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .map(|&i| i),
        );

        match result {
            Ok(r) => match r {
                BufferResult::BufferUnderflow => break,
                BufferResult::BufferOverflow => {}
            },
            Err(e) => return Err(format!("Decrypt Failed: {:?}", e)),
        }
    }

    String::from_utf8(final_result).map_err(|e| format!("Decrypt buffer to string failed: {}", e))
}

fn format_cookies(format: &str, cookies: &Vec<Cookie>) -> String {
    let mut out = String::new();
    cookies.iter().for_each(|cookie| {
        out.push_str(&cookie.name);
        out.push('=');
        out.push_str(&cookie.value);
        out.push_str("; ");
    });
    out.pop();
    out.pop();
    return out;
}
