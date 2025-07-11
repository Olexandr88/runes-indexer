pub mod address;
pub mod errors;
pub mod management;
pub mod wallet;

use crate::btc::address::BitcoinAddress;
use bitcoin::{Amount, Txid};
use candid::CandidType;
use ic_btc_interface::Network;
use ic_crypto_sha2::Sha256;
use ic_ic00_types::DerivationPath;
use serde_bytes::ByteBuf;
use serde_derive::Deserialize;
use std::str::FromStr;

pub async fn init_etching_account_info() -> EtchingAccountInfo {
  let btc_network = Network::Mainnet;
  let key_name = "key_1".to_string(); //read_state(|s| s.ecdsa_key_name.clone());
  let derive_path_str = "etching_address";
  let dp = DerivationPath::new(vec![ByteBuf::from(derive_path_str.as_bytes())]);
  let pub_key = management::ecdsa_public_key(key_name.clone(), dp.clone())
    .await
    .unwrap_or_else(|e| ic_cdk::trap(&format!("failed to retrieve ECDSA public key: {e}")));

  use ripemd::{Digest, Ripemd160};
  let address =
    BitcoinAddress::P2wpkhV0(Ripemd160::digest(Sha256::hash(&pub_key.public_key)).into());
  let deposit_addr = address.display(btc_network);
  let account_info = EtchingAccountInfo {
    pubkey: hex::encode(pub_key.public_key),
    address: deposit_addr,
    derive_path: derive_path_str.to_string(),
    key_name,
  };
  account_info
}

#[derive(Clone, Debug, PartialEq, Default, Eq, serde::Deserialize, CandidType)]
pub struct EtchingAccountInfo {
  pub pubkey: String,
  pub address: String,
  pub derive_path: String,
  pub key_name: String,
}

/// Unspent transaction output to be used as input of a transaction
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Utxo {
  pub id: Txid,
  pub index: u32,
  pub amount: Amount,
}

/// Unspent transaction output to be used as input of a transaction
#[derive(CandidType, Debug, Clone, Deserialize)]
pub struct UtxoArgs {
  pub id: String,
  pub index: u32,
  pub amount: u64,
}

impl From<UtxoArgs> for Utxo {
  fn from(a: UtxoArgs) -> Self {
    Utxo {
      id: bitcoin::hash_types::Txid::from_str(a.id.as_str()).unwrap(),
      index: a.index,
      amount: Amount::from_sat(a.amount),
    }
  }
}
