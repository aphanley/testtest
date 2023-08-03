use bitcoin::bip32::{ChildNumber, DerivationPath, ExtendedPubKey};
use bitcoin::{secp256k1::*, Network};
use bitcoin::{OutPoint, TxOut, Txid};
use std::str::FromStr;

use crate::get_address;

#[derive(Debug, Clone)]
pub struct Utxo {
    pub outpoint: OutPoint,
    // outpoint is the location; transation hash and index to vout
    pub txout: TxOut,
    // txout is the data; value and scriptpubkey
}

#[derive(serde::Deserialize)]
struct AddressUtxo {
    txid: Txid,
    vout: u32,
    value: u64,
}

// consider tuple of utxo and address/derivation path
// xpub and gap limit inputs only
pub fn list_tr_utxos(
    xpub: ExtendedPubKey,
    gap_limit: u32,
) -> Result<Vec<(Utxo, DerivationPath)>, anyhow::Error> {
    let mempool_network = match xpub.network {
        Network::Bitcoin => "",
        Network::Testnet => "testnet/",
        Network::Signet => "signet/",
        Network::Regtest => "regtest/",
        _ => "signet/",
    };

    let mut utxo_list: Vec<(Utxo, DerivationPath)> = Vec::new();
    let derivation_path = DerivationPath::from_str("m")?;

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
            let address = get_address(xpub, inner_path.clone())?;

            // query mempool.space for any associated utxos
            let mempool_address_utxo = reqwest::blocking::get(format!(
                "https://mempool.space/{}api/address/{}/utxo",
                mempool_network,
                address,
            ))?
            .json::<Vec<AddressUtxo>>()?;

            if mempool_address_utxo.is_empty() {
                gap_counter += 1;
            } else {
                for element in mempool_address_utxo.iter() {
                    let txid = element.txid;
                    let vout = element.vout;
                    let value = element.value;
                    let script_pubkey = address.script_pubkey();

                    let outpoint = OutPoint {
                        txid: txid,
                        vout: vout,
                    };
                    let txout = TxOut {
                        value: value,
                        script_pubkey: script_pubkey,
                    };

                    let utxo = Utxo {
                        outpoint: outpoint,
                        txout: txout,
                    };

                    utxo_list.push((utxo, inner_path.clone()));
                }
                gap_counter = 0;
            }
            address_index += 1;
        }
        change_index += 1;
    }
    Ok(utxo_list)
}

pub fn coin_selection(
    wallet_utxos: Vec<(Utxo, DerivationPath)>,
    satoshis: u64,
    transaction_fee: u64,
) -> Result<(Vec<(Utxo, DerivationPath)>, u64), SelectionError> {
    let mut selected_utxos = Vec::new();
    let mut excess: i64 = -(satoshis as i64 + transaction_fee as i64);
    for (utxo, derivation_path) in wallet_utxos.iter() {
        selected_utxos.push((utxo.clone(), derivation_path.clone()));
        excess += utxo.txout.value as i64;
        if excess >= 0 {
            break;
        }
    }
    let change_amount: u64 = excess
        .try_into()
        .map_err(|_| SelectionError::InsufficientFunds {
            amount: excess.abs() as u64,
        })?;
    Ok((selected_utxos, change_amount))
}

#[derive(Clone, Debug)]
pub enum SelectionError {
    InsufficientFunds { amount: u64 },
    // add fields to indicate amount
}

impl core::fmt::Display for SelectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SelectionError::InsufficientFunds { amount } => {
                write!(f, "You had insufficient funds, missing {}", amount)
            }
        }
    }
}

impl std::error::Error for SelectionError {}
