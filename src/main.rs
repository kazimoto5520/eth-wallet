use clap::{Parser, Subcommand};
use anyhow::Result;
use hex::encode as hex_encode;
use bip39::{Mnemonic, Language};
use bip32::{DerivationPath, XPrv};
use ethers::prelude::*;
use ethers::signers::Signer;

#[derive(Parser)]
#[command(name = "rust-eth-wallet")]
#[command(about = "Ethereum wallet CLI in Rust")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Generate,
    Import {
        mnemonic: String,
    },
    Derive {
        mnemonic: String,
        #[arg(short, long, default_value_t = 0)]
        index: u32,
    },
    Sign {
        mnemonic: String,
        #[arg(short, long, default_value_t = 0)]
        index: u32,
        message: String,
    },
    Export {
        mnemonic: String,
        #[arg(short, long, default_value_t = 0)]
        index: u32,
    },
    Balance {
        address: String,
        #[arg(short, long, default_value = "https://ethereum.llamarpc.com")]
        rpc: String,
    },
}

fn derive_wallet(mnemonic: &str, index: u32) -> Result<LocalWallet> {
    let mnemonic = Mnemonic::parse_in(Language::English, mnemonic)?;
    
    // Convert mnemonic to seed
    let seed = mnemonic.to_seed("");
    
    // Create extended private key from seed
    let xprv = XPrv::new(&seed)?;
    
    // Create derivation path
    let path_str = format!("m/44'/60'/0'/0/{}", index);
    let path: DerivationPath = path_str.parse()?;
    
    // Derive child key using iterator
    let mut child_xprv = xprv;
    for child_num in path.as_ref() {
        child_xprv = child_xprv.derive_child(*child_num)?;
    }
    
    // Get private key bytes as a slice
    let private_key_bytes = child_xprv.private_key().to_bytes();
    
    // Convert to SigningKey first, then to LocalWallet
    let signing_key = k256::ecdsa::SigningKey::from_bytes(&private_key_bytes)?;
    let wallet: LocalWallet = LocalWallet::from(signing_key);
    
    Ok(wallet)
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Generate => {
            // Generate random entropy (128 bits = 12 words)
            let mut entropy = [0u8; 16];
            rand::Rng::fill(&mut rand::thread_rng(), &mut entropy);
            let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)?;
            
            println!("Mnemonic: {}", mnemonic);
            
            let wallet = derive_wallet(&mnemonic.to_string(), 0)?;
            println!("Address (0): {:?}", wallet.address());
        }

        Commands::Import { mnemonic } => {
            let wallet = derive_wallet(&mnemonic, 0)?;
            println!("Address (0): {:?}", wallet.address());
        }

        Commands::Derive { mnemonic, index } => {
            let wallet = derive_wallet(&mnemonic, index)?;
            println!("Address ({}): {:?}", index, wallet.address());
        }

        Commands::Sign {
            mnemonic,
            index,
            message,
        } => {
            let wallet = derive_wallet(&mnemonic, index)?;
            let signature = wallet.sign_message(message).await?;
            println!("Signature: {}", signature);
        }

        Commands::Export { mnemonic, index } => {
            let wallet = derive_wallet(&mnemonic, index)?;
            let pk = wallet.signer().to_bytes();
            println!("Private Key: 0x{}", hex_encode(pk));
            println!("Address: {:?}", wallet.address());
        }

        Commands::Balance { address, rpc } => {
            let provider = Provider::<Http>::try_from(rpc)?;
            let addr = address.parse::<Address>()?;
            let balance_wei = provider.get_balance(addr, None).await?;
            let balance_eth = ethers::utils::format_units(balance_wei, "ether")?;
            
            println!("Address: {}", addr);
            println!("Balance (wei): {}", balance_wei);
            println!("Balance (ETH): {}", balance_eth);
        }
    }

    Ok(())
}