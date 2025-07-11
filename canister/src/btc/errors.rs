use thiserror::Error;

/// Ordinal transaction handling error types
#[derive(Error, Debug)]
pub enum OrdError {
  #[error("when using P2TR, the taproot keypair option must be provided")]
  TaprootKeypairNotProvided,
  #[error("Hex codec error: {0}")]
  HexCodec(#[from] hex::FromHexError),
  #[error("Ord codec error: {0}")]
  Codec(#[from] serde_json::Error),
  #[error("Bitcoin script error: {0}")]
  PushBytes(#[from] bitcoin::script::PushBytesError),
  #[error("Bad transaction input: {0}")]
  InputNotFound(usize),
  #[error("Insufficient balance")]
  InsufficientBalance { required: u64, available: u64 },
  #[error("Invalid signature: {0}")]
  Signature(#[from] bitcoin::secp256k1::Error),
  #[error("Invalid signature")]
  UnexpectedSignature,
  #[error("Taproot builder error: {0}")]
  TaprootBuilder(#[from] bitcoin::taproot::TaprootBuilderError),
  #[error("Taproot compute error")]
  TaprootCompute,
  #[error("Scripterror: {0}")]
  Script(#[from] bitcoin::blockdata::script::Error),
  #[error("No transaction inputs")]
  NoInputs,
  #[error("Invalid UTF-8 in: {0}")]
  Utf8Encoding(#[from] std::str::Utf8Error),
  #[error("Inscription parser error")]
  InvalidInputs,
  #[error("Invalid script type")]
  InvalidScriptType,
  #[error("custom error: {0}")]
  Custom(String),
}

pub type OrdResult<T> = std::result::Result<T, OrdError>;
