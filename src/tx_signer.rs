use log::{debug, info};
// pub use tx_request::TxSigningRequest;

use cosmrs::{
    rpc::{Client, HttpClient},
    tendermint,
};
use stdtx::amino;
use subtle_encoding::hex;

use crate::{error::LedgerCosmosError, sign_msg::SignMsg};

// / Broadcast signed transaction to the Tendermint P2P network via RPC
// async fn broadcast_tx(
//     client: HttpClient,
//     sign_msg: SignMsg,
//     sequence: u64,
// ) -> Result<(), LedgerCosmosError> {
//     let tx = sign_tx(&sign_msg)?;

//     let amino_tx = tendermint_rpc::abci::Transaction::from(
//         tx.to_amino_bytes(self.tx_builder.schema().namespace()),
//     );

//     let amino_tx_hex =
//         String::from_utf8(hex::encode(amino_tx.as_ref())).expect("hex should always be UTF-8");

//     info!(
//         "[{}] broadcasting TX: {}",
//         self.chain_id,
//         amino_tx_hex.to_ascii_uppercase()
//     );

//     let response = match self.rpc_client.broadcast_tx_commit(amino_tx).await {
//         Ok(resp) => {
//             self.last_tx = LastTx::Response(Box::new(resp.clone()));
//             resp
//         }
//         Err(e) => {
//             self.last_tx = LastTx::Error(e.clone());
//             return Err(e.into());
//         }
//     };

//     if response.check_tx.code.is_err() {
//         fail!(
//             ErrorKind::TendermintError,
//             "TX broadcast failed: {} (CheckTx code={})",
//             response.check_tx.log,
//             response.check_tx.code.value(),
//         );
//     }

//     // If CheckTx succeeds the sequence number always needs to be
//     // incremented, even if DeliverTx subsequently fails
//     self.seq_file.persist(sequence.checked_add(1).unwrap())?;

//     if response.deliver_tx.code.is_err() {
//         fail!(
//             ErrorKind::TendermintError,
//             "TX broadcast failed: {} (DeliverTx code={}, hash={})",
//             response.deliver_tx.log,
//             response.deliver_tx.code.value(),
//             response.hash
//         );
//     }

//     info!(
//         "[{}] successfully broadcast TX {} (shash={})",
//         self.chain_id,
//         self.seq_file.sequence(),
//         response.hash
//     );

//     Ok(())
// }

// fn sign_tx(sign_msg: &SignMsg) -> Result<amino::StdTx, LedgerCosmosError> {
//     let mut signature = amino::StdSignature::from(sign(sign_msg.sign_bytes())?);

//     signature.pub_key = chain
//         .keyring
//         .get_account_pubkey(account_id)
//         .expect("missing account key")
//         .to_bytes();

//     let msg_type_info = sign_msg
//         .msg_types()
//         .iter()
//         .map(|ty| ty.to_string())
//         .collect::<Vec<_>>()
//         .join(", ");

//     let address = self
//         .address
//         .to_bech32(self.tx_builder.schema().acc_prefix());

//     info!(
//         "[{}] signed TX {} for {} ({} msgs total; types: {})",
//         self.chain_id,
//         self.seq_file.sequence(),
//         address,
//         sign_msg.msgs().len(),
//         msg_type_info,
//     );

//     Ok(sign_msg.to_stdtx(signature))
// }
