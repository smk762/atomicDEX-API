use web3::types::BlockNumber;
use web3::{api::Namespace,
           helpers::{self, CallFuture},
           types::{Address, U256},
           Transport};

/// `ParityNonce` namespace.
#[derive(Debug, Clone)]
pub struct ParityNonce<T> {
    transport: T,
}

impl<T: Transport> Namespace<T> for ParityNonce<T> {
    fn new(transport: T) -> Self
    where
        Self: Sized,
    {
        ParityNonce { transport }
    }

    fn transport(&self) -> &T { &self.transport }
}

impl<T: Transport> ParityNonce<T> {
    /// Parity next nonce.
    pub fn parity_next_nonce(&self, addr: Address) -> CallFuture<U256, T::Out> {
        let addr = helpers::serialize(&addr);
        CallFuture::new(self.transport.execute("parity_nextNonce", vec![addr]))
    }
}

/// `EthNonce` namespace.
#[derive(Debug, Clone)]
pub struct EthNonce<T> {
    transport: T,
}

impl<T: Transport> Namespace<T> for EthNonce<T> {
    fn new(transport: T) -> Self
    where
        Self: Sized,
    {
        EthNonce { transport }
    }

    fn transport(&self) -> &T { &self.transport }
}

impl<T: Transport> EthNonce<T> {
    /// Get nonce.
    /// Fixes MetaMask response deserialization.
    pub async fn transaction_count(&self, address: Address, block: Option<BlockNumber>) -> Result<U256, web3::Error> {
        let address = helpers::serialize(&address);
        let block = helpers::serialize(&block.unwrap_or(BlockNumber::Latest));

        let count: U256De =
            CallFuture::new(self.transport.execute("eth_getTransactionCount", vec![address, block])).await?;
        Ok(U256::from(count))
    }
}

/// U256 deserialization helper.
/// Allows to deserialize structures like `{ "value": 4 }`.
#[derive(Deserialize)]
#[serde(untagged)]
enum U256De {
    Base(U256),
    Raw(u64),
}

impl From<U256De> for U256 {
    fn from(u: U256De) -> Self {
        match u {
            U256De::Base(base) => base,
            U256De::Raw(raw) => U256::from(raw),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_u256_de() {
        #[derive(serde::Deserialize)]
        struct ForTest {
            value: U256De,
        }

        let inputs = serde_json::json!([
            { "value": 4 },
            { "value": "4" },
            { "value": "0x4" },
        ]);

        for input in inputs.as_array().unwrap() {
            let ForTest { value } = serde_json::from_value(input.clone()).expect(&format!("{input}"));
            let value = U256::from(value);
            assert_eq!(value, 4.into());
        }
    }
}
