use clap::{Parser, Subcommand};
use anyhow::Result;
use ethers::prelude::*;
use ethers::signers::{coins_bip39::{English, Mnemonic}, MnemonicBuilder};
use hex::encode as hex_encode;

/// Simple Ethereum wallet CLI using ethers v2 only.
#[derive(Parser)]
#[command(name = "rust-eth-wallet")]
#[command(about = "Ethereum wallet in Rust")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new mnemonic and first address
    Generate,

    /// Import an existing mnemonic
    Import {
        mnemonic: String,
    },

    /// Derive address by index (BIP44 m/44'/60'/0'/0/index)
    Derive {
        mnemonic: String,
        #[arg(short, long, default_value_t = 0)]
        index: u32,
    },

    /// Sign a message
    Sign {
        mnemonic: String,
        #[arg(short, long, default_value_t = 0)]
        index: u32,
        message: String,
    },

    /// Export private key
    Export {
        mnemonic: String,
        #[arg(short, long, default_value_t = 0)]
        index: u32,
    },
}

/// Derive a wallet from mnemonic using BIP44 Ethereum path.
fn derive_wallet(mnemonic: &str, index: u32) -> Result<LocalWallet> {
    let builder = MnemonicBuilder::<English>::default()
        .phrase(mnemonic)
        .derivation_path(&format!("m/44'/60'/0'/0/{}", index))?;

    let wallet = builder.build()?;

    Ok(wallet)
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Generate => {
            let mnemonic = Mnemonic::<English>::new(&mut rand::thread_rng());
            println!("Mnemonic: {}", mnemonic.to_phrase());

            let wallet = derive_wallet(&mnemonic.to_phrase(), 0)?;
            println!("Address (index 0): {:?}", wallet.address());
        }

        Commands::Import { mnemonic } => {
            let wallet = derive_wallet(&mnemonic, 0)?;
            println!("Address: {:?}", wallet.address());
        }

        Commands::Derive { mnemonic, index } => {
            let wallet = derive_wallet(&mnemonic, index)?;
            println!("Address (index {}): {:?}", index, wallet.address());
        }

        Commands::Sign {
            mnemonic,
            index,
            message,
        } => {
            let wallet = derive_wallet(&mnemonic, index)?;
            let signature = futures::executor::block_on(wallet.sign_message(message))?;
            println!("Signature: {:?}", signature);
        }

        Commands::Export { mnemonic, index } => {
            let wallet = derive_wallet(&mnemonic, index)?;
            let pk = wallet.signer().to_bytes();
            println!("Private Key: 0x{}", hex_encode(pk));
            println!("Address: {:?}", wallet.address());
        }
    }

    Ok(())
}