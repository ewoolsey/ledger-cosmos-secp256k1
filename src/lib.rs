use byteorder::{LittleEndian, WriteBytesExt};
use cosmrs::{tendermint::PublicKey, tx::Raw};
use errors::LedgerCosmosError;

use ledger_transport::{async_trait, APDUCommand, APDUErrorCode, Exchange};

pub mod errors;

/// CLA for the cosmos app.
const CLA: u8 = 0x55;

/// Instruction for getting the cosmos app version.
const GET_VERSION_INS: u8 = 0x00;

/// Instruction for getting the secp256k1 public key.
const GET_ADDR_SECP256K1_INS: u8 = 0x04;

/// Instruction for signing a secp256k1 transaction.
const SIGN_SECP256K1_INS: u8 = 0x02;

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

#[async_trait]
pub trait CosmosApp {
    type Error;
    async fn get_cosmos_app_version(
        &self,
    ) -> Result<CosmosAppVersion, LedgerCosmosError<Self::Error>>;
    async fn get_addr_secp256k1(
        &self,
        path: [u32; 5],
        hrp: &str,
        display_on_ledger: bool,
    ) -> Result<Secp256k1Response, LedgerCosmosError<Self::Error>>;
    async fn sign_secp256k1(
        &self,
        path: [u32; 5],
        messages: Vec<Vec<u8>>,
    ) -> Result<Vec<Raw>, LedgerCosmosError<Self::Error>>;
}

#[async_trait]
impl<T> CosmosApp for T
where
    T: Exchange + Sync,
{
    type Error = T::Error;
    async fn get_cosmos_app_version(
        &self,
    ) -> Result<CosmosAppVersion, LedgerCosmosError<T::Error>> {
        let command = APDUCommand {
            cla: CLA,
            ins: GET_VERSION_INS,
            p1: 0x00,
            p2: 0x00,
            data: vec![],
        };
        let answer = self.exchange(&command).await?;
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

    async fn get_addr_secp256k1(
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
            cla: CLA,
            ins: GET_ADDR_SECP256K1_INS,
            p1: display_on_ledger as u8,
            p2: 0x00,
            data: get_addr_payload,
        };
        let answer = self.exchange(&command).await?;
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

    async fn sign_secp256k1(
        &self,
        path: [u32; 5],
        messages: Vec<Vec<u8>>,
    ) -> Result<Vec<Raw>, LedgerCosmosError<T::Error>> {
        if messages.is_empty() {
            return Err(LedgerCosmosError::NoMessages);
        }
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
            cla: CLA,
            ins: SIGN_SECP256K1_INS,
            p1: 0x00,
            p2: 0x00,
            data: init_payload,
        };
        let init_answer = self.exchange(&init_command).await?;
        let init_error_code = init_answer.error_code();
        match init_error_code {
            Ok(code) => match code {
                APDUErrorCode::NoError => {}
                _ => return Err(LedgerCosmosError::Apdu(code.description())),
            },
            Err(code) => return Err(LedgerCosmosError::UnknownApduCode(code)),
        }
        let messages_len = messages.len();
        let mut signed_messages = Vec::new();
        for (i, message) in messages.into_iter().enumerate() {
            let p1 = if i + 1 == messages_len {
                0x02 // last message
            } else {
                0x01 // add message
            };
            let sign_command = APDUCommand {
                cla: CLA,
                ins: SIGN_SECP256K1_INS,
                p1,
                p2: 0x00,
                data: message,
            };
            let sign_answer = self.exchange(&sign_command).await?;
            let sign_error_code = sign_answer.error_code();
            match sign_error_code {
                Ok(code) => match code {
                    APDUErrorCode::NoError => {
                        let data = sign_answer.apdu_data().to_vec();
                        let raw = Raw::from_bytes(&data).unwrap();
                        signed_messages.push(raw);
                    }
                    _ => return Err(LedgerCosmosError::Apdu(code.description())),
                },
                Err(code) => return Err(LedgerCosmosError::UnknownApduCode(code)),
            }
        }
        Ok(signed_messages)
    }
}

fn decompress_pk(compressed_pk: &[u8]) -> Result<PublicKey, LedgerCosmosError<()>> {
    Ok(PublicKey::from_raw_secp256k1(compressed_pk).expect("invalid secp256k1 key"))
}

#[cfg(test)]
mod tests {
    use btleplug::platform;
    use ledger_bluetooth::TransportNativeBle;
    use serial_test::serial;

    use crate::CosmosApp;

    #[tokio::test]
    #[serial]
    async fn test_get_addr_secp256k1() {
        let manager = platform::Manager::new().await.unwrap();
        let ledger = TransportNativeBle::new(&manager)
            .await
            .unwrap()
            .pop()
            .unwrap();
        let path = [44, 118, 0, 0, 0];
        let hrp = "cosmos";
        let display_on_ledger = true;
        let res = ledger
            .get_addr_secp256k1(path, hrp, display_on_ledger)
            .await
            .unwrap();
        println!("public key: {:?}", res.public_key);
        println!("addr: {:?}", res.addr);
    }

    #[tokio::test]
    #[serial]
    async fn test_sign_secp256k1() {
        let manager = platform::Manager::new().await.unwrap();
        let ledger = TransportNativeBle::new(&manager)
            .await
            .unwrap()
            .pop()
            .unwrap();
        let path = [44, 118, 0, 0, 0];
        let res = ledger.sign_secp256k1(path, vec![vec![1]]).await.unwrap();
        println!("res: {:?}", res);
    }
}
