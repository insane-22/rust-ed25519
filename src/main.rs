use anyhow::Result;
use clap::{Parser, Subcommand};
use hex::{decode, encode};
use std::fs;
use std::path::PathBuf;
use rust_ed25519::{generate_keypair, sign_message, verify_signature};

#[derive(Parser)]
#[command(name = "ed25519-rust", about = "Ed25519 sign/verify demo")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    GenKeypair {
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    Sign {
        key: String,
        #[arg(short, long)]
        message: Option<String>,
    },
    Verify {
        public: String,
        signature: String,
        #[arg(short, long)]
        message: Option<String>,
    },
}

fn read_hex_or_file(s: &str) -> Result<Vec<u8>> {
    let p = PathBuf::from(s);
    let content = if p.exists() { fs::read_to_string(p)? } else { s.to_string() };
    Ok(decode(content.trim())?)
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::GenKeypair { out } => {
            let (sk, pk) = generate_keypair()?;
            println!("Private key (hex): {}", encode(&sk));
            println!("Public key  (hex): {}", encode(&pk));
            if let Some(path) = out {
                fs::write(&path, encode(&sk))?;
                println!("Saved private key to {:?}", path);
            }
        }
        Commands::Sign { key, message } => {
            let sk = read_hex_or_file(&key)?;
            let msg = message.unwrap_or_else(|| {
                let mut s = String::new();
                std::io::stdin().read_line(&mut s).unwrap();
                s.trim().to_string()
            });
            let sig = sign_message(&sk, msg.as_bytes())?;
            println!("Signature (hex): {}", encode(sig));
        }
        Commands::Verify { public, signature, message } => {
            let pk = read_hex_or_file(&public)?;
            let sig = read_hex_or_file(&signature)?;
            let msg = message.unwrap_or_else(|| {
                let mut s = String::new();
                std::io::stdin().read_line(&mut s).unwrap();
                s.trim().to_string()
            });
            let valid = verify_signature(&pk, msg.as_bytes(), &sig)?;
            println!("Verified: {}", valid);
        }
    }

    Ok(())
}
