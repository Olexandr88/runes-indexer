//! This module contains async functions for interacting with the management canister.

use bitcoin::Transaction;
use candid::{CandidType, Principal};
use ic_ic00_types::{
  DerivationPath, ECDSAPublicKeyArgs, ECDSAPublicKeyResponse, EcdsaCurve, EcdsaKeyId,
  SignWithECDSAArgs, SignWithECDSAReply,
};
use serde::de::DeserializeOwned;

async fn call<I, O>(method: &str, payment: u64, input: &I) -> Result<O, String>
where
  I: CandidType,
  O: CandidType + DeserializeOwned,
{
  let balance = ic_cdk::api::canister_balance128();
  if balance < payment as u128 {
    return Err("Reason::OutOfCycles".to_string());
  }

  let res: Result<(O,), _> = ic_cdk::api::call::call_with_payment(
    Principal::management_canister(),
    method,
    (input,),
    payment,
  )
  .await;

  match res {
    Ok((output,)) => Ok(output),
    Err((_, msg)) => Err(msg),
  }
}

/// Sends the transaction to the network the management canister interacts with.
pub async fn send_etching(transaction: &Transaction) {
  use ic_cdk::api::management_canister::bitcoin::BitcoinNetwork;
  let cdk_network = BitcoinNetwork::Mainnet;
  let tx_bytes = bitcoin::consensus::serialize(&transaction);
  ic_cdk::api::management_canister::bitcoin::bitcoin_send_transaction(
    ic_cdk::api::management_canister::bitcoin::SendTransactionRequest {
      transaction: tx_bytes,
      network: cdk_network,
    },
  )
  .await
  .unwrap();
}

/// Fetches the ECDSA public key of the canister.
pub async fn ecdsa_public_key(
  key_name: String,
  derivation_path: DerivationPath,
) -> Result<ECDSAPublicKey, String> {
  // Retrieve the public key of this canister at the given derivation path
  // from the ECDSA API.
  call(
    "ecdsa_public_key",
    /*payment=*/ 0,
    &ECDSAPublicKeyArgs {
      canister_id: None,
      derivation_path,
      key_id: EcdsaKeyId {
        curve: EcdsaCurve::Secp256k1,
        name: key_name,
      },
    },
  )
  .await
  .map(|response: ECDSAPublicKeyResponse| ECDSAPublicKey {
    public_key: response.public_key,
    chain_code: response.chain_code,
  })
}

/// Signs a message hash using the tECDSA API.
pub async fn sign_with_ecdsa(
  key_name: String,
  derivation_path: DerivationPath,
  message_hash: [u8; 32],
) -> Result<Vec<u8>, String> {
  const CYCLES_PER_SIGNATURE: u64 = 30_000_000_000;

  let reply: SignWithECDSAReply = call(
    "sign_with_ecdsa",
    CYCLES_PER_SIGNATURE,
    &SignWithECDSAArgs {
      message_hash,
      derivation_path,
      key_id: EcdsaKeyId {
        curve: EcdsaCurve::Secp256k1,
        name: key_name.clone(),
      },
    },
  )
  .await?;
  Ok(reply.signature)
}

#[derive(CandidType, Clone, Debug, PartialEq, Eq)]
pub struct ECDSAPublicKey {
  pub public_key: Vec<u8>,
  pub chain_code: Vec<u8>,
}
