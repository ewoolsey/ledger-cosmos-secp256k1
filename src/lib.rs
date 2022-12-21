#![allow(clippy::too_many_arguments)]
use byteorder::{LittleEndian, WriteBytesExt};
use cosmrs::{
    tendermint::PublicKey,
    tx::{Fee, Msg},
};
use error::LedgerCosmosError;

use k256::ecdsa::Signature;
use ledger_transport::{APDUCommand, APDUErrorCode, Exchange};
use ledger_zondax_generic::{App, AppExt};
use log::info;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sign_msg::SignMsg;
use stdtx::amino;

pub mod error;
// pub mod jsonrpc;
pub mod sign_msg;
pub mod tx_request;
pub mod tx_signer;

/// CLA for the cosmos app.
const COSMOS_CLA: u8 = 0x55;

/// Instruction for getting the cosmos app version.
const GET_VERSION_INS: u8 = 0x00;

/// Instruction for getting the secp256k1 public key.
const GET_ADDR_SECP256K1_INS: u8 = 0x04;

/// Instruction for signing a secp256k1 transaction.
const SIGN_SECP256K1_INS: u8 = 0x02;

pub trait IntoValue: Msg + Serialize {
    fn into_value(self) -> Value;
}

impl<T> IntoValue for T
where
    T: Msg + Serialize,
{
    fn into_value(self) -> Value {
        let type_url = self.to_any().unwrap().type_url;
        let value = serde_json::to_value(self).unwrap();
        json!({
            "type": type_url,
            "value": sort_object_keys(value),
        })
    }
}
#[derive(Debug, Serialize, Deserialize)]
pub struct CosmosAppVersion {
    pub test_mode: u8,
    pub major: u8,
    pub minor: u8,
    pub patch: u8,
    pub locked: u8,
}

pub struct Secp256k1Response {
    pub public_key: PublicKey,
    pub addr: String,
}

// #[derive(Debug, Serialize, Deserialize)]
// pub struct LedgerSignDoc {
//     pub account_number: u64,
//     pub chain_id: String,
//     pub fee: Fee,
//     pub memo: String,
//     pub msgs: Vec<Value>,
//     pub sequence: u64,
// }

// impl LedgerSignDoc {
//     pub fn into_value(self) -> Value {
//         json!({
//             "account_number": self.account_number.to_string(),
//             "chain_id": self.chain_id,
//             "fee": {
//                 "amount": self.fee.amount.into_iter().map(|c| json!({
//                     "amount": c.amount.to_string(),
//                     "denom": c.denom,
//                 })).collect::<Vec<Value>>(),
//                 "gas": self.fee.gas_limit.to_string(),
//             },
//             "memo": self.memo,
//             "msgs": self.msgs.into_iter().map(sort_object_keys).collect::<Vec<Value>>(),
//             "sequence": self.sequence.to_string(),
//         })
//     }
//     fn into_bytes(self) -> Result<Vec<u8>, LedgerCosmosError> {
//         let sorted = self.into_value();
//         Ok(serde_json::to_vec(&sorted)?)
//     }
// }

pub struct CosmosApp<T>
where
    T: Exchange + Send + Sync,
    T::Error: std::error::Error,
{
    transport: T,
}

impl<T> App for CosmosApp<T>
where
    T: Exchange + Send + Sync,
    T::Error: std::error::Error,
{
    const CLA: u8 = COSMOS_CLA;
}

impl<T> CosmosApp<T>
where
    T: Exchange + Send + Sync,
    T::Error: std::error::Error,
{
    pub fn new(transport: T) -> Self {
        CosmosApp { transport }
    }

    pub async fn get_cosmos_app_version(&self) -> Result<CosmosAppVersion, LedgerCosmosError> {
        let command = APDUCommand {
            cla: COSMOS_CLA,
            ins: GET_VERSION_INS,
            p1: 0x00,
            p2: 0x00,
            data: vec![],
        };
        info!("Sending command: {:#?}", command);
        let answer = self
            .transport
            .exchange(&command)
            .await
            .map_err(|e| LedgerCosmosError::Exchange(e.to_string()))?;
        let error_code = answer.error_code();
        info!("code received: {:#?}", error_code);
        match error_code {
            Ok(code) => match code {
                APDUErrorCode::NoError => {
                    let data = answer.apdu_data();
                    Ok(CosmosAppVersion {
                        test_mode: data[0],
                        major: data[1],
                        minor: data[2],
                        patch: data[3],
                        locked: data[4],
                    })
                }
                _ => Err(LedgerCosmosError::Apdu(code.description())),
            },
            Err(code) => Err(LedgerCosmosError::UnknownApduCode(code)),
        }
    }

    pub async fn get_addr_secp256k1(
        &self,
        path: [u32; 5],
        hrp: &str,
        display_on_ledger: bool,
    ) -> Result<Secp256k1Response, LedgerCosmosError> {
        info!(
            "Getting secp256k1 address
            path: {:?}
            hrp: {}
            display_on_ledger: {:#?}",
            path, hrp, display_on_ledger
        );
        let mut get_addr_payload: Vec<u8> = Vec::new();
        get_addr_payload.write_u8(hrp.len() as u8).unwrap(); // hrp len
        get_addr_payload.extend(hrp.as_bytes()); // hrp
        get_addr_payload
            .write_u32::<LittleEndian>(path[0] + 0x80000000)
            .unwrap();
        get_addr_payload
            .write_u32::<LittleEndian>(path[1] + 0x80000000)
            .unwrap();
        get_addr_payload
            .write_u32::<LittleEndian>(path[2] + 0x80000000)
            .unwrap();
        get_addr_payload.write_u32::<LittleEndian>(path[3]).unwrap();
        get_addr_payload.write_u32::<LittleEndian>(path[4]).unwrap();
        let command = APDUCommand {
            cla: COSMOS_CLA,
            ins: GET_ADDR_SECP256K1_INS,
            p1: display_on_ledger as u8,
            p2: 0x00,
            data: get_addr_payload,
        };
        info!("Sending apdu command: {:#?}", command);
        let answer = self
            .transport
            .exchange(&command)
            .await
            .map_err(|e| LedgerCosmosError::Exchange(e.to_string()))?;
        let error_code = answer.error_code();
        info!("code received: {:#?}", error_code);
        match error_code {
            Ok(code) => match code {
                APDUErrorCode::NoError => {
                    let data = answer.apdu_data();
                    Ok(Secp256k1Response {
                        public_key: decompress_pk(&data[0..33]).unwrap(),
                        addr: String::from_utf8(data[33..].to_vec())
                            .map_err(|_| LedgerCosmosError::InvalidAddress)?,
                    })
                }
                _ => Err(LedgerCosmosError::Apdu(code.description())),
            },
            Err(code) => Err(LedgerCosmosError::UnknownApduCode(code)),
        }
    }

    pub async fn sign_secp256k1(
        &self,
        path: [u32; 5],
        message: &[u8],
    ) -> Result<Signature, LedgerCosmosError> {
        let mut init_payload: Vec<u8> = Vec::new();
        init_payload
            .write_u32::<LittleEndian>(path[0] + 0x80000000)
            .unwrap();
        init_payload
            .write_u32::<LittleEndian>(path[1] + 0x80000000)
            .unwrap();
        init_payload
            .write_u32::<LittleEndian>(path[2] + 0x80000000)
            .unwrap();
        init_payload.write_u32::<LittleEndian>(path[3]).unwrap();
        init_payload.write_u32::<LittleEndian>(path[4]).unwrap();
        let init_command = APDUCommand {
            cla: COSMOS_CLA,
            ins: SIGN_SECP256K1_INS,
            p1: 0x00,
            p2: 0x00,
            data: init_payload,
        };
        info!("init command: {:#?}", init_command);
        let res = Self::send_chunks::<Vec<u8>>(&self.transport, init_command, &message).await;
        let sign_answer = res.unwrap();
        let sign_error_code = sign_answer.error_code();
        match sign_error_code {
            Ok(code) => match code {
                APDUErrorCode::NoError => {
                    info!("code: {:?}", code);
                    let data = sign_answer.apdu_data().to_vec();
                    info!("data: {:?}", data);
                    let signature = Signature::from_der(data.as_slice()).unwrap();
                    dbg!(signature);

                    Ok(signature)
                }
                _ => Err(LedgerCosmosError::Apdu(code.description())),
            },
            Err(code) => Err(LedgerCosmosError::UnknownApduCode(code)),
        }
    }

    pub async fn sign(
        &self,
        derivation_path: [u32; 5],
        sign_msg: SignMsg,
    ) -> Result<amino::StdTx, LedgerCosmosError> {
        info!(
            "Signing secp256k1
            derivation_path: {:?}
            ledger_sign_doc: {:#?}",
            derivation_path, sign_msg
        );
        let res = self
            .sign_secp256k1(derivation_path, sign_msg.sign_bytes())
            .await?;
        info!("res: {:?}", res);
        let mut signature = amino::StdSignature::from(res);

        signature.pub_key = self
            .get_addr_secp256k1(derivation_path, "cosmos", false)
            .await?
            .public_key
            .to_bytes();

        let msg_type_info = sign_msg
            .msg_types()
            .iter()
            .map(|ty| ty.to_string())
            .collect::<Vec<_>>()
            .join(", ");

        // let address = self
        //     .address
        //     .to_bech32(self.tx_builder.schema().acc_prefix());

        // info!(
        //     "[{}] signed TX {} for {} ({} msgs total; types: {})",
        //     self.chain_id,
        //     self.seq_file.sequence(),
        //     address,
        //     sign_msg.msgs().len(),
        //     msg_type_info,
        // );

        Ok(sign_msg.to_stdtx(signature))
    }
}

fn decompress_pk(compressed_pk: &[u8]) -> Result<PublicKey, LedgerCosmosError> {
    Ok(PublicKey::from_raw_secp256k1(compressed_pk).expect("invalid secp256k1 key"))
}

fn sort_object_keys(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut vec: Vec<(String, Value)> = map
                .into_iter()
                .map(|(k, v)| (k, sort_object_keys(v)))
                .collect();
            vec.sort_by(|a, b| a.0.cmp(&b.0));
            Value::Object(vec.into_iter().collect())
        }
        Value::Array(mut vec) => {
            vec.iter_mut()
                .for_each(|x| *x = sort_object_keys(x.to_owned()));
            Value::Array(vec)
        }
        _ => value,
    }
}

#[cfg(test)]
mod tests {

    use std::str::FromStr;
    use stdtx::amino::{self, types::Coin};
    use test_log::test;

    use cosmrs::Denom;

    use ledger_transport_hid::{hidapi::HidApi, TransportNativeHID};

    use log::info;
    use serde_json::json;
    use serial_test::serial;

    use crate::{sign_msg::SignMsg, tx_request::TxSigningRequest, CosmosApp};

    // #[test(tokio::test)]
    // #[serial]
    // async fn test_get_addr_secp256k1() {
    //     let manager = platform::Manager::new().await.unwrap();
    //     let ledger = TransportNativeBle::new(&manager)
    //         .await
    //         .unwrap()
    //         .pop()
    //         .unwrap();
    //     let app = CosmosApp::new(ledger);
    //     let path = [44, 118, 0, 0, 0];
    //     let hrp = "cosmos";
    //     let display_on_ledger = true;
    //     let res = app
    //         .get_addr_secp256k1(path, hrp, display_on_ledger)
    //         .await
    //         .unwrap();
    //     info!("public key: {:?}", res.public_key);
    //     info!("addr: {:?}", res.addr);
    // }

    #[test(tokio::test)]
    #[serial]
    async fn test_sign() {
        let api = HidApi::new().unwrap();
        let device = TransportNativeHID::list_ledgers(&api).next().unwrap();
        let ledger = TransportNativeHID::open_device(&api, device).unwrap();

        let app = CosmosApp::new(ledger);
        let derivation_path = [44, 118, 0, 0, 0];

        let fee = amino::StdFee {
            amount: vec![Coin {
                denom: "uatom".into(),
                amount: "45".into(),
            }],
            gas: 4000,
        };

        let account_number = 123;
        let chain_id = "oasis-1".to_string();
        let memo = "hello".to_string();
        let sequence = 500;

        let value = json!({
            "hello": "world"
        });

        // let msg = MsgExecuteContract {
        //     sender: AccountId::from_str("noria19n42dwl6mgwcep5ytqt7qpthy067ssq72gjsrk").unwrap(),
        //     contract: AccountId::from_str("noria19n42dwl6mgwcep5ytqt7qpthy067ssq72gjsrk").unwrap(),
        //     msg: b"hello".to_vec(),
        //     funds: vec![],
        // };

        // let value = msg.into_value();
        info!("value: {}", serde_json::to_string(&value).unwrap());

        pub const TERRA_SCHEMA: &str = r#"
            namespace = "core/StdTx"
            acc_prefix = "terra"
            val_prefix = "terravaloper"

            [[definition]]
            type_name = "oracle/MsgExchangeRatePrevote"
            fields = [
                { name = "hash",  type = "string" },
                { name = "denom", type = "string" },
                { name = "feeder", type = "sdk.AccAddress" },
                { name = "validator", type = "sdk.ValAddress" },
            ]

            [[definition]]
            type_name = "oracle/MsgExchangeRateVote"
            fields = [
                { name = "exchange_rate", type = "sdk.Dec"},
                { name = "salt", type = "string" },
                { name = "denom", type = "string" },
                { name = "feeder", type = "sdk.AccAddress" },
                { name = "validator", type = "sdk.ValAddress" },
            ]

            [[definition]]
            type_name = "oracle/MsgType"
            fields = [
                { name = "denom", type = "string" },
                { name = "salt", type = "string" },
            ]
        "#;

        let msg = json!({
            "type": "oracle/MsgType",
            "value": {
                "denom": "denom",
                "salt": "hash",
            }
        });

        let schema = amino::Schema::from_str(TERRA_SCHEMA).unwrap();

        dbg!(schema.clone());

        let tx_builder = amino::Builder::new(schema, chain_id.clone(), account_number);

        let signing_request = TxSigningRequest {
            /// Requested chain ID
            chain_id,

            /// Fee
            fee,

            /// Memo
            memo,

            /// Transaction messages to be signed
            msgs: vec![msg],
        };

        let sign_msg = SignMsg::new(&signing_request, &tx_builder, sequence).unwrap();

        // let sign_doc = LedgerSignDoc {
        //     account_number,
        //     chain_id,
        //     fee,
        //     memo,
        //     msgs: vec![value],
        //     sequence,
        // };

        dbg!(sign_msg.clone());
        let res = app.sign(derivation_path, sign_msg).await.unwrap();
        info!("res: {:?}", res);
    }
}
