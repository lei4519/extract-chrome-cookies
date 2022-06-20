use cli::build_cli;
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
use rusqlite::{Connection, Row};
use std::{
    collections::HashMap,
    env,
    io::{self, Write},
    path::Path,
    process::exit,
};
use tldextract::{TldExtractor, TldOption};
use url::Url;

use clap::ArgMatches;

mod cli;

static SALT: &[u8; 9] = b"saltysalt";
const KEYLENGTH: usize = 16;
const IV: [u8; 16] = [32; KEYLENGTH];
// const FORMATS: [&str; 6] = ["curl", "jar", "set-cookie", "puppeteer", "header", "object"];
// const FORMAT_HELP: &str =
//     "Control how cookies are formatted, One of 'curl', 'jar', 'set-cookie', 'puppeteer', 'header', 'object'";

#[derive(Debug)]
struct Cookie {
    host_key: String,
    path: String,
    is_secure: bool,
    // expires_utc: usize,
    name: String,
    value: String,
    encrypted_value: Vec<u8>,
    // creation_utc: usize,
    // is_httponly: bool,
    // has_expires: bool,
    // is_persistent: bool,
}

fn main() {
    let matchs = build_cli().get_matches();

    match run(matchs) {
        Ok(_) => {}
        Err(e) => {
            eprint!("{}", e.red());
            io::stderr().flush().unwrap();
            exit(1);
        }
    };
}

fn run(matchs: ArgMatches) -> Result<(), String> {
    match env::consts::OS {
        "macos" | "linux" => Ok(()),
        _ => Err("Only Mac and Linux are supported.".to_string()),
    }?;

    let url = matchs.value_of("url").unwrap();
    // let format = matchs.value_of("format").unwrap();
    let profile = matchs.value_of("profile_name").unwrap();
    let profile_path = matchs.value_of("profile_path");

    let path;
    if profile_path.is_some() {
        path = profile_path.unwrap().to_string();
    } else {
        let home_path = get_home_path();

        if home_path.is_none() {
            cant_resolve_profile_path(None);
        }

        let home_path = home_path.unwrap();

        path = get_profile_path(&home_path, profile) + "/Cookies";

        if !Path::new(&path).exists() {
            cant_resolve_profile_path(Some(home_path));
        }
    }

    let connection = Connection::open(path).map_err(|e| format!("Open database Failed: {e}"))?;

    let cookies = get_cookies(&connection, url)?;

    let result = format_cookies(&cookies);

    print!("{result}");

    io::stdout().flush().unwrap();

    Ok(())
}

fn cant_resolve_profile_path(home_path: Option<String>) -> ! {
    if home_path.is_none() {
        eprint!("{}\n\n", "The program can't resolve your Google profile path automatically, Please use '-p' option to pass it in manually.".red());
    } else {
        eprint!("{}\n\n", "The program can't resolve your Google profile path automatically, you need to pass it in manually.".red());
    }
    eprint!("{}\n", "Follow these steps find your profile path:".green());
    eprint!("  {}\n", "1. Open Chrome");
    eprint!("  {}\n", "2. Enter 'chrome://version'");
    eprint!("  {}\n\n", "3. Find 'profile path'");

    if home_path.is_some() {
        let path = get_profile_path(&home_path.unwrap(), "<PROFILE NAME>");
        eprint!("{}\n", "If the path looks like this:".green());
        eprint!("  {}\n\n", path);
        eprint!("{}\n", "You just pass in the profile name:".green());
        eprint!(
            "  {}\n\n",
            "extract-chrome-cookies <URL> -n <PROFILE NAME>".cyan()
        );

        eprint!(
            "{}\n",
            "Otherwise, you need to pass in the entire profile path:".green()
        );
    } else {
        eprint!("{}\n", "Run command:".green());
    }

    eprint!(
        "  {}",
        "extract-chrome-cookies <URL> -p <PROFILE PATH>".cyan()
    );

    io::stderr().flush().unwrap();

    exit(1)
}

fn get_home_path() -> Option<String> {
    Some(String::from(home::home_dir()?.to_str()?))
}

fn get_profile_path(home_path: &str, profile: &str) -> String {
    match env::consts::OS {
        "macos" => format!("{home_path}/Library/Application Support/Google/Chrome/{profile}",),
        "linux" => format!("{home_path}/.config/google-chrome/{profile}"),
        _ => "".to_string(),
    }
}

fn get_cookies(conn: &Connection, url: &str) -> Result<Vec<Cookie>, String> {
    let option = TldOption {
        cache_path: Some(".tld_cache".to_string()),
        private_domains: false,
        update_local: false,
        naive_mode: false,
    };

    let ext = TldExtractor::new(option);
    let cant_resolve_domain =
        "Could not parse domain from URI, format should be http://www.example.com/path/"
            .to_string();
    let extor = ext.extract(url).map_err(|_| &cant_resolve_domain)?;
    let domain = extor.domain.ok_or(&cant_resolve_domain)?;
    let suffix = extor.suffix.ok_or(&cant_resolve_domain)?;
    let domain = format!("{domain}.{suffix}");

    let url = Url::parse(url).map_err(|e| format!("URL Parse Error: {}", e))?;
    let host = url.host_str().unwrap();
    let path = url.path();
    let is_https = url.scheme() == "https";

    let statement = format!("SELECT host_key, path, is_secure, expires_utc, name, value, encrypted_value, creation_utc, is_httponly, has_expires, is_persistent FROM cookies where host_key like '%{domain}' ORDER BY LENGTH(path) DESC, creation_utc ASC");

    let mut stmt = conn
        .prepare(&statement)
        .map_err(|e| format!("Prepare a SQL statement for execution failed: {e}"))?;

    let rows = stmt
        .query_map([], |row: &Row| {
            Ok(Cookie {
                host_key: row.get(0)?,
                path: row.get(1)?,
                is_secure: row.get(2)?,
                // expires_utc: row.get(3)?,
                name: row.get(4)?,
                value: row.get(5)?,
                encrypted_value: row.get(6)?,
                // creation_utc: row.get(7)?,
                // is_httponly: row.get(8)?,
                // has_expires: row.get(9)?,
                // is_persistent: row.get(10)?,
            })
        })
        .map_err(|e| format!("Query Cookie Map Failed: {}", e))?;

    let mut cookies = vec![];
    let mut de_duplicate = HashMap::new();

    let mut key = None;
    for cookie in rows {
        let mut cookie = cookie.map_err(|e| format!("Get Cookie Map Failed: {}", e))?;

        if cookie.is_secure && !is_https {
            continue;
        }

        if !domain_match(host, &cookie.host_key) {
            continue;
        }

        if !path_match(path, &cookie.path) {
            continue;
        }

        if cookie.value.is_empty() && !cookie.encrypted_value.is_empty() {
            if key.is_none() {
                // only macos linux can go here, so value must a Some
                key = Some(get_derived_key().ok_or("Get derived key failed.")?);
            }
            cookie.value = decrypt(&key.unwrap(), &cookie.encrypted_value)?;
        }

        if de_duplicate.get(&cookie.name).is_some() {
            continue;
        }

        de_duplicate.insert(cookie.name.clone(), 0);

        cookies.push(cookie);
    }
    Ok(cookies)
}

fn canonical(s: &str) -> &str {
    if &s[0..1] == "." {
        return &s[1..];
    }
    s
}

fn domain_match(mut a: &str, mut b: &str) -> bool {
    a = canonical(a);
    b = canonical(b);

    if a == b {
        return true;
    }

    let i = a.find(b);

    if i.is_none() {
        return false;
    }
    let i = i.unwrap();

    if a.len() != b.len() + i {
        return false;
    }

    if &a[i - 1..i] != "." {
        return false;
    }

    return true;
}

fn path_match(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }

    let i = a.find(b);
    if matches!(i, Some(i) if i == 0) {
        let blen = b.len();
        if &b[blen - 1..] == "/" {
            return true;
        }
        if &a[blen..blen + 1] == "/" {
            return true;
        }
    }

    false
}

// #[cfg(target_os = "windows")]
#[cfg(target_os = "linux")]
fn get_derived_key() -> Option<[u8; 16]> {
    const ITERATIONS: u32 = 1;
    let mut buffer: [u8; 16] = [0; 16];
    let mut m = Hmac::new(Sha1::new(), b"peanuts");
    pbkdf2(&mut m, SALT, ITERATIONS, &mut buffer);

    return Some(buffer);
}

#[cfg(target_os = "macos")]
fn get_derived_key() -> Option<[u8; 16]> {
    const ITERATIONS: u32 = 1003;
    if let Ok(res) = keytar::get_password("Chrome Safe Storage", "Chrome") {
        if res.success {
            let mut buffer: [u8; 16] = [0; 16];
            let mut m = Hmac::new(Sha1::new(), res.password.as_bytes());

            pbkdf2(&mut m, SALT, ITERATIONS, &mut buffer);
            return Some(buffer);
        }
    }
    return None;
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

fn format_cookies(cookies: &Vec<Cookie>) -> String {
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
