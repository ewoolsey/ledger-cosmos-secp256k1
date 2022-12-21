use thiserror::Error;

const LEDGER_COSMOS_ERROR: &str = "Ledger Cosmos Error:";

#[derive(Error, Debug)]
pub enum LedgerCosmosError {
    #[error("{} communication error `{0}`", LEDGER_COSMOS_ERROR)]
    Comm(&'static str),
    #[error("{} apdu error `{0}`", LEDGER_COSMOS_ERROR)]
    Apdu(String),
    #[error("{} unknown apdu error. code `{0}`", LEDGER_COSMOS_ERROR)]
    UnknownApduCode(u16),
    #[error("{} could not deserialize address", LEDGER_COSMOS_ERROR)]
    InvalidAddress,
    #[error("{} Ledger Exchange error `{0}`", LEDGER_COSMOS_ERROR)]
    Exchange(String),
    #[error("{} serde_json error `{0}`", LEDGER_COSMOS_ERROR)]
    Serde(#[from] serde_json::Error),
}
