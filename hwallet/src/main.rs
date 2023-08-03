// TO DO
// make a transaction
// miniscript
// taproot script spend

use bip39::Language;
use bip39::Mnemonic;
use bitcoin::absolute::LockTime;
use bitcoin::address::NetworkUnchecked;
use bitcoin::bip32::{ChildNumber, DerivationPath, ExtendedPrivKey, ExtendedPubKey};
use bitcoin::consensus::encode::{self, serialize_hex};
use bitcoin::key::TapTweak;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::{
    bip32, taproot, Address, Amount, Network, Sequence, Transaction, TxIn, TxOut, Witness,
};
use clap::{Parser, Subcommand};
use std::fs::File;
use std::io::prelude::*;
use std::str::FromStr;
use utxos::{coin_selection, list_tr_utxos};

mod utxos;

#[derive(serde::Deserialize)]
struct MempoolAddress {
    chain_stats: ChainStats,
    mempool_stats: MempoolStats,
}

#[derive(serde::Deserialize)]
struct ChainStats {
    funded_txo_sum: u64,
    spent_txo_sum: u64,
}

#[derive(serde::Deserialize)]
struct MempoolStats {
    funded_txo_sum: u64,
    spent_txo_sum: u64,
}

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Commands,

    /// the directory for a file to be saved in
    #[arg(short, long)]
    directory: Option<String>,

    /// the gap limit for seaching addresses
    #[arg(short, long)]
    gap_limit: Option<u32>,

    /// the network the wallet operates on
    #[arg(short, long)]
    network: Option<String>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// generates a random 12 word seed
    Generate {},
    /// prints a new BIP86 receive address
    Address {},
    /// checks the total balance of the wallet
    Balance {},
    /// lists available utxos
    Utxos {},
    /// Sends an amount to the specified address
    Send {
        address: Address<NetworkUnchecked>,
        satoshis: u64,
    },
}

pub fn generate(file_path: String) -> Result<(), anyhow::Error> {
    let mut rng = bip39::rand::thread_rng();
    let seed_words = Mnemonic::generate_in_with(&mut rng, Language::English, 12).unwrap();

    let mut file = File::create(file_path)?;
    file.write_all(seed_words.to_string().as_bytes())?;
    Ok(())
}

pub fn address(
    file_path: String,
    derivation_path: DerivationPath,
    network: Network,
) -> Result<(), anyhow::Error> {
    let mnemonic = mnemonic_from_file(file_path)?;
    let root_xpriv = derive_root_xpriv(&mnemonic, network)?;
    let (_xpriv, xpub) = derive_xpriv_xpub(root_xpriv, derivation_path.clone())?;
    let derivation_path = DerivationPath::from_str("m/0")?;

    let new_address = new_address(xpub, derivation_path)?;
    println!("{}", new_address);
    Ok(())
}

pub fn balance(
    file_path: String,
    gap_limit: u32,
    derivation_path: DerivationPath,
    network: bitcoin::Network,
) -> Result<(), anyhow::Error> {
    let mnemonic = mnemonic_from_file(file_path)?;
    let root_xpriv = derive_root_xpriv(&mnemonic, network)?;
    let (_xpriv, xpub) = derive_xpriv_xpub(root_xpriv, derivation_path)?;

    let derivation_path = DerivationPath::from_str("m")?;
    let mut wallet_balance = 0;
    let mut change_index = 0;
    while change_index <= 1 {
        let outer_path = derivation_path.child(ChildNumber::Normal {
            index: change_index,
        });
        let mut address_index = 0;
        let mut gap_counter = 0;
        while gap_counter < gap_limit {
            let inner_path = outer_path.child(ChildNumber::Normal {
                index: address_index,
            });
            let address = get_address(xpub, inner_path)?;
            let address_balance = address_balance(address)?;
            if address_balance == 0 {
                gap_counter += 1;
            } else {
                wallet_balance += address_balance;
                gap_counter = 0;
            }
            address_index += 1;
        }
        change_index += 1;
    }
    println!("Wallet balance is: {}", wallet_balance);
    Ok(())
}

pub fn utxos(
    file_path: String,
    gap_limit: u32,
    derivation_path: DerivationPath,
    network: Network,
) -> Result<(), anyhow::Error> {
    let mnemonic = mnemonic_from_file(file_path)?;
    let root_xpriv = derive_root_xpriv(&mnemonic, network)?;
    let (_xpriv, xpub) = derive_xpriv_xpub(root_xpriv, derivation_path.clone())?;

    let utxo_list = list_tr_utxos(xpub, gap_limit)?;
    if utxo_list.is_empty() {
        println!("No UTXOs")
    } else {
        for (element, _derivation_path) in utxo_list {
            println!(
                "Amount: {} at {}",
                element.txout.value, element.txout.script_pubkey
            );
        }
    }
    Ok(())
}

pub fn send(
    address: Address<NetworkUnchecked>,
    satoshis: u64,
    file_path: String,
    gap_limit: u32,
    derivation_path: DerivationPath,
    network: bitcoin::Network,
) -> Result<(), anyhow::Error> {
    let mnemonic = mnemonic_from_file(file_path.clone())?;

    let root_xpriv = derive_root_xpriv(&mnemonic, network)?;
    // xpriv and xpub at m/86'/1'/0'
    // println!("{}", derivation_path);
    let (xpriv, xpub) = derive_xpriv_xpub(root_xpriv, derivation_path.clone())?;

    let list_of_tr_utxos = list_tr_utxos(xpub, gap_limit)?;
    let transaction_fee = 1000;
    let (selected_utxos, change_amount) =
        coin_selection(list_of_tr_utxos, satoshis, transaction_fee)?;
    let change_amount = Amount::from_sat(change_amount);

    let send_address = address.require_network(network)?;
    let send_amount = Amount::from_sat(satoshis);

    let derivation_path = DerivationPath::from_str("m/1")?;
    let change_address = new_address(xpub, derivation_path)?;

    let mut transaction = Transaction {
        version: 2,
        lock_time: LockTime::ZERO,
        input: {
            let mut input = Vec::new();
            for (utxo, _derivation_path) in selected_utxos.iter() {
                let tx_in = TxIn {
                    previous_output: utxo.outpoint,
                    script_sig: Default::default(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::default(),
                };
                input.push(tx_in);
            }
            input
        },
        output: {
            let mut output = Vec::new();

            let send_tx_out = TxOut {
                value: send_amount.to_sat(),
                script_pubkey: send_address.script_pubkey(),
            };
            output.push(send_tx_out);

            let change_tx_out = TxOut {
                value: change_amount.to_sat(),
                script_pubkey: change_address.script_pubkey(),
            };
            output.push(change_tx_out);

            output
        },
    };

    let input_count = transaction.input.len();
    let mut sighash_cache = SighashCache::new(&mut transaction);

    let list_tx_outs = selected_utxos
        .iter()
        .map(|(utxo, _derivation_path)| &utxo.txout)
        .collect::<Vec<_>>();
    let list_derivation_paths = selected_utxos
        .iter()
        .map(|(_utxo, derivation_path)| derivation_path)
        .collect::<Vec<_>>();
    let prevouts = Prevouts::All(&list_tx_outs);
    let annex = None;
    let leaf_hash_code_separator = None;
    let sighash_type = bitcoin::sighash::TapSighashType::Default;
    let secp = Secp256k1::new();

    for input_index in 0..input_count {
        let sighash = sighash_cache.taproot_signature_hash(
            input_index,
            &prevouts,
            annex.clone(),
            leaf_hash_code_separator,
            sighash_type,
        )?;

        let message = bitcoin::secp256k1::Message::from(sighash);
        let (xpriv, xpub) = derive_xpriv_xpub(xpriv, list_derivation_paths[input_index].clone())?;

        // check script_pubkey from TxOut against script_pubkey from keypair being used to sign
        println!("{}", list_tx_outs[input_index].script_pubkey);
        let internal_key = xpub.to_x_only_pub();
        let merkle_root = None;
        let network = xpub.network;
        let address = Address::p2tr(&secp, internal_key, merkle_root, network);
        println!("{}", address.script_pubkey());

        let keypair = xpriv.to_keypair(&secp);
        let tweaked_keypair = keypair.tap_tweak(&secp, merkle_root).to_inner();
        let signature = secp.sign_schnorr_no_aux_rand(&message, &tweaked_keypair);
        let taproot_signature = taproot::Signature {
            sig: signature,
            hash_ty: sighash_type,
        };
        let signature_bytes = taproot_signature.to_vec();
        sighash_cache
            .witness_mut(input_index)
            .unwrap()
            .push(signature_bytes);
    }

    let _serialized_tx = encode::serialize(&transaction);
    let hex_tx = serialize_hex(&transaction);

    // println!("The transaction is {:?}", serialized_tx);
    println!("The transaction is {}", hex_tx);

    Ok(())
}

fn main() -> Result<(), anyhow::Error> {
    let args = Args::parse();

    // sets file path, default is current directorys
    let file_path = match args.directory {
        Some(directory) => format!("{}/seed.txt", directory),
        None => String::from("seed.txt"),
    };

    // sets gap limit, defalt is 3
    let gap_limit = match args.gap_limit {
        Some(gap_limit) => gap_limit,
        None => 3,
    };

    // sets network, default is Signet
    let network = match args.network {
        Some(network) => match network.as_str() {
            "bitcoin" => bitcoin::Network::Bitcoin,
            "regtest" => bitcoin::Network::Regtest,
            "signet" => bitcoin::Network::Signet,
            "testnet" => bitcoin::Network::Testnet,
            _ => bitcoin::Network::Signet,
        },
        None => bitcoin::Network::Signet,
    };

    println!("network: {}", network);

    // select correct derivation path for bitcoin network or signet
    let path = match network {
        Network::Bitcoin => "m/86h/0h/0h",
        _ => "m/86h/1h/0h",
    };
    let derivation_path = DerivationPath::from_str(&path)?;

    match args.command {
        Commands::Generate {} => generate(file_path)?,

        Commands::Address {} => {
            address(file_path, derivation_path, network)?;
        }

        Commands::Balance {} => balance(file_path, gap_limit, derivation_path, network)?,

        Commands::Utxos {} => utxos(file_path, gap_limit, derivation_path, network)?,

        Commands::Send { address, satoshis } => send(
            address,
            satoshis,
            file_path,
            gap_limit,
            derivation_path,
            network,
        )?,
    }
    Ok(())
}

pub fn mnemonic_from_file(file_path: String) -> Result<Mnemonic, anyhow::Error> {
    let mut file = File::open(file_path)?;
    let mut seed_text = String::new();
    file.read_to_string(&mut seed_text)?;
    let mnemonic = Mnemonic::parse_normalized(&seed_text)?;
    Ok(mnemonic)
}

pub fn derive_root_xpriv(
    mnemonic: &Mnemonic,
    network: bitcoin::Network,
) -> Result<ExtendedPrivKey, anyhow::Error> {
    let seed = Mnemonic::to_seed_normalized(&mnemonic, "");
    let root_xpriv = ExtendedPrivKey::new_master(network, &seed)?;
    Ok(root_xpriv)
}

pub fn derive_xpriv_xpub(
    root_xpriv: ExtendedPrivKey,
    derivation_path: DerivationPath,
) -> Result<(ExtendedPrivKey, ExtendedPubKey), anyhow::Error> {
    let secp = Secp256k1::new();
    let xpriv = root_xpriv.derive_priv(&secp, &derivation_path)?;
    let xpub = bip32::ExtendedPubKey::from_priv(&secp, &xpriv);
    Ok((xpriv, xpub))
}

pub fn get_address(
    xpub: ExtendedPubKey,
    derivation_path: DerivationPath,
) -> Result<Address, anyhow::Error> {
    let secp = Secp256k1::new();
    let pk = xpub.derive_pub(&secp, &derivation_path)?;

    let internal_key = pk.to_x_only_pub();
    let merkle_root = None;
    let network = pk.network;

    let address = Address::p2tr(&secp, internal_key, merkle_root, network);
    Ok(address)
}

pub fn new_address(
    xpub: ExtendedPubKey,
    derivation_path: DerivationPath,
) -> Result<Address, anyhow::Error> {
    let mempool_network = match xpub.network {
        Network::Bitcoin => "",
        Network::Testnet => "testnet/",
        Network::Signet => "signet/",
        Network::Regtest => "regtest/",
        _ => "signet/",
    };

    let mut is_address_used = true;
    let mut address_index = 0;
    let mut address = get_address(
        xpub,
        derivation_path.child(ChildNumber::Normal {
            index: address_index,
        }),
    )?;

    while is_address_used {
        let current_path = derivation_path.child(ChildNumber::Normal {
            index: address_index,
        });
        address = get_address(xpub, current_path)?;

        let mempool_address = reqwest::blocking::get(format!(
            "https://mempool.space/{}api/address/{}",
            mempool_network,
            address,
        ))?
        .json::<MempoolAddress>()?;
        let chain_stats = mempool_address.chain_stats;
        let mempool_stats = mempool_address.mempool_stats;
        let funded = chain_stats.funded_txo_sum + mempool_stats.funded_txo_sum;
        if funded == 0 {
            is_address_used = false;
        } else {
            address_index += 1;
        }
    }
    Ok(address)
}

pub fn address_balance(address: Address) -> Result<u64, anyhow::Error> {
    let mempool_network = match address.network {
        Network::Bitcoin => "",
        Network::Testnet => "testnet/",
        Network::Signet => "signet/",
        Network::Regtest => "regtest/",
        _ => "signet/",
    };

    let mempool_address = reqwest::blocking::get(format!(
        "https://mempool.space/{}api/address/{}",
        mempool_network,
        address,
    ))?
    .json::<MempoolAddress>()?;
    let chain_stats = mempool_address.chain_stats;
    let mempool_stats = mempool_address.mempool_stats;
    let balance = chain_stats.funded_txo_sum - chain_stats.spent_txo_sum
        + mempool_stats.funded_txo_sum
        - mempool_stats.spent_txo_sum;
    Ok(balance)
}

#[cfg(test)]
mod tests {
    use bitcoin::bip32::{DerivationPath, ExtendedPubKey};
    use std::str::FromStr;

    use crate::{derive_root_xpriv, derive_xpriv_xpub, get_address, mnemonic_from_file};

    fn test_setup() -> ExtendedPubKey {
        let network = bitcoin::Network::Bitcoin;
        let file_path = String::from("test.txt");
        let mnemonic = mnemonic_from_file(file_path).unwrap();
        let derivation_path = DerivationPath::from_str("m/86h/0h/0h").unwrap();
        let root_xpriv = derive_root_xpriv(&mnemonic, network).unwrap();
        let (_xpriv, xpub) = derive_xpriv_xpub(root_xpriv, derivation_path.clone()).unwrap();
        xpub
    }

    #[test]
    fn test_bip86_first_receive_address() {
        let xpub = test_setup();
        let derivation_path = DerivationPath::from_str("m/0/0").unwrap();

        let address = get_address(xpub, derivation_path).unwrap();
        assert_eq!(
            address.to_string(),
            String::from("bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr")
        );
    }

    #[test]
    fn test_bip86_second_receive_address() {
        let xpub = test_setup();
        let derivation_path = DerivationPath::from_str("m/0/1").unwrap();

        let address = get_address(xpub, derivation_path).unwrap();
        assert_eq!(
            address.to_string(),
            String::from("bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh")
        );
    }

    #[test]
    fn test_bip86_first_change_address() {
        let xpub = test_setup();
        let derivation_path = DerivationPath::from_str("m/1/0").unwrap();

        let address = get_address(xpub, derivation_path).unwrap();
        assert_eq!(
            address.to_string(),
            String::from("bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7")
        );
    }
}
