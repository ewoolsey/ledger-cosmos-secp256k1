#![allow(clippy::too_many_arguments)]
use byteorder::{LittleEndian, WriteBytesExt};
use cosmrs::{tendermint::PublicKey, tx::Msg};
use errors::LedgerCosmosError;

use k256::ecdsa::Signature;
use ledger_transport::{APDUCommand, APDUErrorCode, Exchange};
use ledger_zondax_generic::{App, AppExt};
use log::info;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub mod errors;

/// CLA for the cosmos app.
const COSMOS_CLA: u8 = 0x55;

/// Instruction for getting the cosmos app version.
const GET_VERSION_INS: u8 = 0x00;

/// Instruction for getting the secp256k1 public key.
const GET_ADDR_SECP256K1_INS: u8 = 0x04;

/// Instruction for signing a secp256k1 transaction.
const SIGN_SECP256K1_INS: u8 = 0x02;

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

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AnyJson {
    #[serde(rename = "type")]
    pub type_url: String,
    pub value: Value,
}

pub trait IntoAnyJson: Msg + Serialize {
    fn into_any_json(self) -> AnyJson;
}

impl<T> IntoAnyJson for T
where
    T: Msg + Serialize,
{
    fn into_any_json(self) -> AnyJson {
        let type_url = self.to_any().unwrap().type_url;
        let value = serde_json::to_value(self).unwrap();
        AnyJson { type_url, value }
    }
}

#[derive(Debug)]
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

#[derive(Serialize, Deserialize, Debug)]
pub struct Fee {
    pub amount: Vec<Coin>,
    pub gas: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Coin {
    pub amount: String,
    pub denom: String,
}

#[derive(Serialize, Debug)]
pub struct LedgerPayload {
    pub account_number: String,
    pub chain_id: String,
    pub fee: Fee,
    pub memo: String,
    pub msgs: Vec<Value>,
    pub sequence: String,
}

impl<T> CosmosApp<T>
where
    T: Exchange + Send + Sync,
    T::Error: std::error::Error,
{
    pub fn new(transport: T) -> Self {
        CosmosApp { transport }
    }

    pub async fn get_cosmos_app_version(
        &self,
    ) -> Result<CosmosAppVersion, LedgerCosmosError<T::Error>> {
        let command = APDUCommand {
            cla: COSMOS_CLA,
            ins: GET_VERSION_INS,
            p1: 0x00,
            p2: 0x00,
            data: vec![],
        };
        let answer = self.transport.exchange(&command).await?;
        let error_code = answer.error_code();
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
    ) -> Result<Secp256k1Response, LedgerCosmosError<T::Error>> {
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
        let answer = self.transport.exchange(&command).await?;
        let error_code = answer.error_code();
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
        message: Vec<u8>,
    ) -> Result<Signature, LedgerCosmosError<T::Error>> {
        // if messages.is_empty() {
        //     return Err(LedgerCosmosError::NoMessages);
        // }
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
        fee: Fee,
        chain_id: String,
        memo: String,
        account_number: u64,
        sequence: u64,
        msgs: Vec<Value>,
    ) -> Result<Signature, LedgerCosmosError<T::Error>> {
        let payload = LedgerPayload {
            account_number: account_number.to_string(),
            chain_id,
            fee,
            memo,
            msgs,
            sequence: sequence.to_string(),
        };

        let payload_val = serde_json::to_value(&payload).unwrap();
        let payload_val_sorted = crate::sort_object_keys(payload_val.clone());
        let bytes = serde_json::to_vec(&payload_val_sorted).unwrap();
        info!(
            "payload: {}",
            serde_json::to_string_pretty(&payload_val_sorted).unwrap()
        );
        let res = self.sign_secp256k1(derivation_path, bytes).await?;
        info!("res: {:?}", res);
        Ok(res)
    }
}

fn decompress_pk(compressed_pk: &[u8]) -> Result<PublicKey, LedgerCosmosError<()>> {
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

    use btleplug::platform;

    use cosmrs::{cosmwasm::MsgExecuteContract, AccountId};
    use ledger_bluetooth::TransportNativeBle;
    use ledger_transport_hid::{hidapi::HidApi, TransportNativeHID};

    use log::info;
    use serial_test::serial;

    use crate::{Coin, CosmosApp, Fee, IntoAnyJson};

    #[tokio::test]
    #[serial]
    async fn test_get_addr_secp256k1() {
        let manager = platform::Manager::new().await.unwrap();
        let ledger = TransportNativeBle::new(&manager)
            .await
            .unwrap()
            .pop()
            .unwrap();
        let app = CosmosApp::new(ledger);
        let path = [44, 118, 0, 0, 0];
        let hrp = "cosmos";
        let display_on_ledger = true;
        let res = app
            .get_addr_secp256k1(path, hrp, display_on_ledger)
            .await
            .unwrap();
        info!("public key: {:?}", res.public_key);
        info!("addr: {:?}", res.addr);
    }

    #[tokio::test]
    // #[serial]
    async fn test_sign() {
        let api = HidApi::new().unwrap();
        let device = TransportNativeHID::list_ledgers(&api).next().unwrap();
        let ledger = TransportNativeHID::open_device(&api, device).unwrap();
        let app = CosmosApp::new(ledger);
        let derivation_path = [44, 118, 0, 0, 0];

        let fee = Fee {
            amount: vec![Coin {
                denom: "uatom".into(),
                amount: "45".into(),
            }],
            gas: "4000".to_string(),
        };

        let account_number = 123;
        let chain_id = "oasis-1".to_string();
        let memo = "hello".to_string();
        let sequence = 500;

        let msg = MsgExecuteContract {
            sender: AccountId::from_str("noria19n42dwl6mgwcep5ytqt7qpthy067ssq72gjsrk").unwrap(),
            contract: AccountId::from_str("noria19n42dwl6mgwcep5ytqt7qpthy067ssq72gjsrk").unwrap(),
            msg: b"hello".to_vec(),
            funds: vec![],
        };

        let any_json = msg.into_any_json();
        let value = serde_json::to_value(any_json).unwrap();
        info!("value: {}", serde_json::to_string(&value).unwrap());

        let res = app
            .sign(
                derivation_path,
                fee,
                chain_id,
                memo,
                account_number,
                sequence,
                vec![value],
            )
            .await
            .unwrap();
        info!("res: {:?}", res);
    }
}
