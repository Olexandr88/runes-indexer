use crate::btc::management::send_etching;
use crate::btc::wallet::{OrdTransactionBuilder, SignCommitTransactionArgs};
use crate::btc::{init_etching_account_info, Utxo};
use bitcoin::absolute::LockTime;
use bitcoin::transaction::Version;
use bitcoin::{
  Address, Amount, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use std::str::FromStr;

const TRANSFER_FEE: u64 = 160;

pub async fn etching_fee_transfer(utxos: Vec<Utxo>, to_addr: String) {
  let mut total_amount = 0u64;
  for utxo in utxos.clone() {
    total_amount += utxo.amount.to_sat();
  }
  let to_address = Address::from_str(&to_addr).unwrap().assume_checked();
  let output_amount = total_amount - TRANSFER_FEE;
  let tx_in = utxos
    .iter()
    .map(|input| TxIn {
      previous_output: OutPoint {
        txid: input.id,
        vout: input.index,
      },
      script_sig: ScriptBuf::new(),
      sequence: Sequence::from_consensus(0xfffffff0),
      witness: Witness::new(),
    })
    .collect();
  let tx_out = vec![TxOut {
    value: Amount::from_sat(output_amount),
    script_pubkey: to_address.script_pubkey(),
  }];
  // make transaction and sign it
  let unsigned_tx = Transaction {
    version: Version::TWO,
    lock_time: LockTime::ZERO,
    input: tx_in,
    output: tx_out,
  };
  let etching_account = init_etching_account_info().await;
  let sender = Address::from_str(etching_account.address.as_str())
    .unwrap()
    .assume_checked();
  let mut builder = OrdTransactionBuilder::p2tr(
    PublicKey::from_str(etching_account.pubkey.as_str()).unwrap(),
    sender.clone(),
    etching_account.key_name.clone(),
  );

  let signed_tx = builder
    .sign_commit_transaction(
      unsigned_tx,
      SignCommitTransactionArgs {
        inputs: utxos,
        txin_script_pubkey: sender.script_pubkey(),
      },
    )
    .await
    .unwrap();
  send_etching(&signed_tx).await;
}
