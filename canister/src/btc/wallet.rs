use crate::btc::errors::{OrdError, OrdResult};
use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::{self, Message};
use bitcoin::sighash::SighashCache;
use bitcoin::taproot::ControlBlock;
use bitcoin::{Address, PublicKey, ScriptBuf, Transaction, Witness};
use ic_ic00_types::DerivationPath;
use serde_bytes::ByteBuf;

use super::{init_etching_account_info, Utxo};

/// An Ordinal-aware Bitcoin wallet.
#[derive(Clone)]
pub struct Wallet {
  pub signer: MixSigner,
}

impl Wallet {
  pub fn new_with_signer(signer: MixSigner) -> Self {
    Self { signer }
  }

  pub async fn sign_commit_transaction(
    &mut self,
    own_pubkey: &PublicKey,
    inputs: &[Utxo],
    transaction: Transaction,
    txin_script: &ScriptBuf,
  ) -> OrdResult<Transaction> {
    self
      .sign_ecdsa(own_pubkey, inputs, transaction, txin_script)
      .await
  }

  async fn sign_ecdsa(
    &mut self,
    own_pubkey: &PublicKey,
    utxos: &[Utxo],
    transaction: Transaction,
    script: &ScriptBuf,
  ) -> OrdResult<Transaction> {
    let mut hash = SighashCache::new(transaction.clone());
    for (index, input) in utxos.iter().enumerate() {
      let sighash = hash
        .p2wpkh_signature_hash(index, script, input.amount, bitcoin::EcdsaSighashType::All)
        .unwrap();
      let message = Message::from(sighash);
      let signature = self.signer.sign_with_ecdsa(message).await?;

      // append witness
      let signature = bitcoin::ecdsa::Signature::sighash_all(signature).into();
      self.append_witness_to_input(&mut hash, signature, index, &own_pubkey.inner, None, None)?;
    }

    Ok(hash.into_transaction())
  }

  fn append_witness_to_input(
    &self,
    sighasher: &mut SighashCache<Transaction>,
    signature: OrdSignature,
    index: usize,
    pubkey: &secp256k1::PublicKey,
    redeem_script: Option<&ScriptBuf>,
    control_block: Option<&ControlBlock>,
  ) -> OrdResult<()> {
    // push redeem script if necessary
    let witness = if let Some(redeem_script) = redeem_script {
      let mut witness = Witness::new();
      match signature {
        OrdSignature::Ecdsa(signature) => witness.push_ecdsa_signature(&signature),
        OrdSignature::Schnorr(signature) => witness.push(signature.to_vec()),
      }
      witness.push(redeem_script.as_bytes());
      if let Some(control_block) = control_block {
        witness.push(control_block.serialize());
      }
      witness
    } else {
      // otherwise, push pubkey
      match signature {
        OrdSignature::Ecdsa(signature) => Witness::p2wpkh(&signature, pubkey),
        OrdSignature::Schnorr(_) => return Err(OrdError::UnexpectedSignature),
      }
    };
    // append witness
    *sighasher
      .witness_mut(index)
      .ok_or(OrdError::InputNotFound(index))? = witness;

    Ok(())
  }
}

enum OrdSignature {
  Schnorr(bitcoin::taproot::Signature),
  Ecdsa(bitcoin::ecdsa::Signature),
}

impl From<bitcoin::taproot::Signature> for OrdSignature {
  fn from(sig: bitcoin::taproot::Signature) -> Self {
    Self::Schnorr(sig)
  }
}

impl From<bitcoin::ecdsa::Signature> for OrdSignature {
  fn from(sig: bitcoin::ecdsa::Signature) -> Self {
    Self::Ecdsa(sig)
  }
}

#[derive(Clone)]
pub struct MixSigner {
  pub pubkey: PublicKey,
  pub signer_addr: Address,
  pub key_name: String,
}

impl MixSigner {
  pub fn new(public_key: PublicKey, addr: Address, key_name: String) -> Self {
    Self {
      pubkey: public_key,
      signer_addr: addr,
      key_name,
    }
  }

  pub async fn sign_with_ecdsa(&self, message: Message) -> OrdResult<Signature> {
    let etching_account = init_etching_account_info().await;
    let sighash = *message.as_ref();
    let sec1_signature = crate::btc::management::sign_with_ecdsa(
      self.key_name.clone(),
      DerivationPath::new(vec![ByteBuf::from(etching_account.derive_path.as_bytes())]),
      sighash,
    )
    .await
    .unwrap();
    Signature::from_compact(sec1_signature.as_slice()).map_err(OrdError::Signature)
  }
}

/// Ordinal-aware transaction builder for arbitrary (`Nft`)
/// and `Brc20` inscriptions.
///
#[derive(Clone)]
pub struct OrdTransactionBuilder {
  public_key: PublicKey,
  signer: Wallet,
}

impl OrdTransactionBuilder {
  pub fn new(public_key: PublicKey, signer: Wallet) -> Self {
    Self { public_key, signer }
  }

  pub fn signer(&self) -> MixSigner {
    self.signer.signer.clone()
  }

  /// Sign the commit transaction
  pub async fn sign_commit_transaction(
    &mut self,
    unsigned_tx: Transaction,
    args: SignCommitTransactionArgs,
  ) -> OrdResult<Transaction> {
    // sign transaction and update witness
    self
      .signer
      .sign_commit_transaction(
        &self.public_key,
        &args.inputs,
        unsigned_tx,
        &args.txin_script_pubkey,
      )
      .await
  }

  /// Initialize a new `OrdTransactionBuilder` with the given private key and use P2TR as script type (preferred).
  pub fn p2tr(public_key: PublicKey, address: Address, key_name: String) -> Self {
    let wallet = Wallet::new_with_signer(MixSigner::new(public_key, address, key_name));
    Self::new(public_key, wallet)
  }
}

#[derive(Debug, Clone)]
pub struct SignCommitTransactionArgs {
  /// UTXOs to be used as inputs of the transaction
  pub inputs: Vec<Utxo>,
  /// Script pubkey of the inputs
  pub txin_script_pubkey: ScriptBuf,
}
