//! Utilities to derive, display, and parse bitcoin addresses.

use ic_btc_interface::Network;
use serde::{Deserialize, Serialize};

#[derive(candid::CandidType, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BitcoinAddress {
  /// Pay to witness public key hash address.
  /// See BIP-173.
  #[serde(rename = "p2wpkh_v0")]
  P2wpkhV0([u8; 20]),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum WitnessVersion {
  V0 = 0,
}

impl BitcoinAddress {
  /// Converts the address to the textual representation.
  pub fn display(&self, network: Network) -> String {
    match self {
      Self::P2wpkhV0(pkhash) => encode_bech32(network, pkhash, WitnessVersion::V0),
    }
  }
}

fn encode_bech32(network: Network, hash: &[u8], version: WitnessVersion) -> String {
  use bech32::u5;

  let hrp = hrp(network);
  let witness_version: u5 =
    u5::try_from_u8(version as u8).expect("bug: witness version must be smaller than 32");
  let data: Vec<u5> = std::iter::once(witness_version)
    .chain(
      bech32::convert_bits(hash, 8, 5, true)
        .expect("bug: bech32 bit conversion failed on valid inputs")
        .into_iter()
        .map(|b| u5::try_from_u8(b).expect("bug: bech32 bit conversion produced invalid outputs")),
    )
    .collect();
  match version {
    WitnessVersion::V0 => bech32::encode(hrp, data, bech32::Variant::Bech32)
      .expect("bug: bech32 encoding failed on valid inputs"),
  }
}

/// Returns the human-readable part of a bech32 address
pub fn hrp(network: Network) -> &'static str {
  match network {
    ic_btc_interface::Network::Mainnet => "bc",
    ic_btc_interface::Network::Testnet => "tb",
    ic_btc_interface::Network::Regtest => "bcrt",
  }
}
