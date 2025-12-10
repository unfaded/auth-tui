use clap::{Parser, Subcommand};
use data_encoding::BASE32_NOPAD;
use std::fs;
use std::io::{self, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use totp_rs::{Algorithm, TOTP};
use url::Url;

#[derive(Parser)]
#[command(name = "auth-tui")]
#[command(about = "Simple TOTP authenticator")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Path to the secrets file (default: ~/.auth-tui)
    #[arg(short, long)]
    file: Option<String>,
}

#[derive(Subcommand)]
enum Command {
    /// Import OTP URIs from a text file (one per line)
    Import {
        /// Path to the file containing otpauth:// URIs
        path: String,
    },
    /// Export OTP URIs to a text file
    Export {
        /// Path to write the URIs
        path: String,
    },
}

fn default_secrets_path() -> String {
    dirs::home_dir()
        .map(|p| p.join(".auth-tui").to_string_lossy().to_string())
        .unwrap_or_else(|| ".auth-tui".to_string())
}

fn load_secrets(path: &str) -> Vec<String> {
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|l| l.starts_with("otpauth://"))
        .map(String::from)
        .collect()
}

fn save_secrets(path: &str, secrets: &[String]) -> io::Result<()> {
    fs::write(path, secrets.join("\n"))
}

fn parse_totp(uri: &str) -> Option<(String, String, TOTP)> {
    let url = Url::parse(uri).ok()?;
    
    // Extract account name from path (after /totp/)
    let path = url.path();
    let label = urlencoding::decode(path.trim_start_matches("/totp/").trim_start_matches('/')).ok()?;
    
    // Label can be "issuer:account" or just "account"
    let (issuer_from_label, account) = if let Some(pos) = label.find(':') {
        (Some(label[..pos].to_string()), label[pos + 1..].to_string())
    } else {
        (None, label.to_string())
    };
    
    // Parse query parameters
    let mut secret = None;
    let mut issuer = issuer_from_label;
    let mut algorithm = Algorithm::SHA1;
    let mut digits = 6u32;
    let mut period = 30u64;
    
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "secret" => secret = Some(value.to_string()),
            "issuer" => issuer = Some(value.to_string()),
            "algorithm" => {
                algorithm = match value.to_uppercase().as_str() {
                    "SHA256" => Algorithm::SHA256,
                    "SHA512" => Algorithm::SHA512,
                    _ => Algorithm::SHA1,
                };
            }
            "digits" => digits = value.parse().unwrap_or(6),
            "period" => period = value.parse().unwrap_or(30),
            _ => {}
        }
    }
    
    let secret = secret?;
    let secret_bytes = BASE32_NOPAD
        .decode(secret.to_uppercase().as_bytes())
        .ok()?;
    
    let totp = TOTP::new_unchecked(
        algorithm,
        digits as usize,
        1,
        period,
        secret_bytes,
        Some(issuer.clone().unwrap_or_default()),
        account.clone(),
    );
    
    Some((account, issuer.unwrap_or_default(), totp))
}

fn generate_code(totp: &TOTP) -> String {
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    totp.generate(time)
}

fn seconds_remaining() -> u64 {
    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    30 - (time % 30)
}

fn display(secrets: &[String], line_count: usize) {
    // Move cursor up to redraw
    if line_count > 0 {
        print!("\x1B[{}A", line_count);
    }
    
    let remaining = seconds_remaining();
    println!("{:<30} {:<20} {:>8} {:>4}", "USERNAME", "ISSUER", "CODE", "TTL");
    println!("{}", "-".repeat(68));
    
    for uri in secrets {
        if let Some((account, issuer, totp)) = parse_totp(uri) {
            let code = generate_code(&totp);
            println!("{:<30} {:<20} {:>8} {:>3}s", account, issuer, code, remaining);
        }
    }
    io::stdout().flush().unwrap();
}

fn run_tui(secrets_path: &str) {
    let secrets = load_secrets(secrets_path);
    
    if secrets.is_empty() {
        eprintln!("No secrets found. Import some with: auth-tui import <file>");
        return;
    }
    
    // header (2) + entries
    let line_count = 2 + secrets.len();
    let mut first = true;
    
    loop {
        display(&secrets, if first { 0 } else { line_count });
        first = false;
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn main() {
    let cli = Cli::parse();
    let secrets_path = cli.file.unwrap_or_else(default_secrets_path);

    match cli.command {
        Some(Command::Import { path }) => {
            let mut existing = load_secrets(&secrets_path);
            let new_secrets = load_secrets(&path);
            let count = new_secrets.len();
            
            for s in new_secrets {
                if !existing.contains(&s) {
                    existing.push(s);
                }
            }
            
            if let Err(e) = save_secrets(&secrets_path, &existing) {
                eprintln!("Failed to save: {}", e);
                std::process::exit(1);
            }
            println!("Imported {} entries", count);
        }
        Some(Command::Export { path }) => {
            let secrets = load_secrets(&secrets_path);
            if let Err(e) = fs::write(&path, secrets.join("\n")) {
                eprintln!("Failed to export: {}", e);
                std::process::exit(1);
            }
            println!("Exported {} entries to {}", secrets.len(), path);
        }
        None => {
            run_tui(&secrets_path);
        }
    }
}
