//! String representation of a message to be signed

use crate::error::LedgerCosmosError;

use super::tx_request::TxSigningRequest;
use std::collections::BTreeSet as Set;
use stdtx::amino;

/// String representation of a message that describes a particular transaction
/// to be signed by transaction signer
#[derive(Debug)]
pub struct SignMsg {
    /// Fee
    pub fee: amino::StdFee,

    /// Memo
    pub memo: String,

    /// Messages
    msgs: Vec<amino::Msg>,

    /// Message types
    msg_types: Set<amino::TypeName>,

    /// String representation
    repr: String,
}

impl SignMsg {
    /// Create a new [`SignMsg`] from a [`TxSigningRequest`]
    pub fn new(
        req: &TxSigningRequest,
        tx_builder: &amino::Builder,
        sequence: u64,
    ) -> Result<Self, LedgerCosmosError> {
        let mut msgs = vec![];
        let mut msg_types = Set::new();

        for msg_value in &req.msgs {
            let msg = amino::Msg::from_json_value(tx_builder.schema(), msg_value.clone()).unwrap();
            msg_types.insert(msg.type_name().clone());
            msgs.push(msg);
        }

        let repr = tx_builder.create_sign_msg(sequence, &req.fee, &req.memo, msgs.as_slice());

        Ok(Self {
            fee: req.fee.clone(),
            memo: req.memo.clone(),
            msgs,
            msg_types,
            repr,
        })
    }

    /// Serialize a [`StdTx`] after obtaining a signature
    pub fn to_stdtx(&self, sig: amino::StdSignature) -> amino::StdTx {
        amino::StdTx::new(&self.msgs, self.fee.clone(), vec![sig], self.memo.clone())
    }

    /// Borrow the signed messages
    pub fn msgs(&self) -> &[amino::Msg] {
        self.msgs.as_slice()
    }

    /// Borrow the set of signed message types
    pub fn msg_types(&self) -> &Set<amino::TypeName> {
        &self.msg_types
    }

    /// Get the signed byte representation
    pub fn sign_bytes(&self) -> &[u8] {
        self.repr.as_bytes()
    }
}
