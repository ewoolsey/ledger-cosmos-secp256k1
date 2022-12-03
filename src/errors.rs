/*******************************************************************************
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
*
*  Unless required by applicable law or agreed to in writing, software
*  distributed under the License is distributed on an "AS IS" BASIS,
*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*  See the License for the specific language governing permissions and
*  limitations under the License.
********************************************************************************/
use thiserror::Error;

#[derive(Error, Debug)]
pub enum LedgerCosmosError<E> {
    /// Communication error
    #[error("Ledger device: communication error `{0}`")]
    Comm(&'static str),
    /// Communication error
    #[error("Ledger device: apdu error `{0}`")]
    Apdu(String),
    /// Communication error
    #[error("Ledger device: unknown apdu error. code `{0}`")]
    UnknownApduCode(u16),
    /// Communication error
    #[error("Ledger device: could not deserialize public key")]
    InvalidPublicKey,
    /// Communication error
    #[error("Ledger device: could not deserialize address")]
    InvalidAddress,
    /// Communication error
    #[error("Ledger device: Error, no messages provided")]
    NoMessages,
    /// Error during apdu exchange
    #[error("Ledger device: Exchange error `{0}`")]
    Exchange(#[from] E),
}