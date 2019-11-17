use base58::{FromBase58, FromBase58Error, ToBase58};
use bigdecimal::BigDecimal;
use bitcrypto::{sha256, dhash256};
use blake2::{VarBlake2b, Blake2b};
use blake2::digest::{Input, VariableOutput};
use chrono::prelude::*;
use common::executor::Timer;
use common::mm_ctx::MmArc;
use common::mm_number::MmNumber;
use crate::{TradeInfo, FoundSwapTxSpend, WithdrawRequest};
use derive_more::{Add, Deref, Display};
use ed25519_dalek::{Keypair as EdKeypair, SecretKey as EdSecretKey, Signature as EdSignature, SignatureError,
                    PublicKey as EdPublicKey};
use futures::TryFutureExt;
use futures01::Future;
use num_bigint::{BigInt, BigUint, ToBigInt};
use num_traits::pow::Pow;
use num_traits::cast::ToPrimitive;
use primitives::hash::{H32, H160, H256, H512};
use rpc::v1::types::{Bytes as BytesJson};
use serde::{Serialize, Serializer, Deserialize};
use serde::de::{Deserializer, Visitor};
use serde_json::{self as json, Value as Json};
use serialization::{Deserializable, deserialize, Reader, Serializable, serialize, Stream};
use sha2::{Sha512};
use std::borrow::Cow;
use std::cmp::PartialEq;
use std::collections::HashMap;
use std::convert::{TryInto, TryFrom};
use std::fmt;
use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use super::{HistorySyncState, MarketCoinOps, MmCoin, SwapOps, TradeFee, Transaction, TransactionDetails,
            TransactionEnum, TransactionFut};
use common::{slurp_url, block_on, now_ms};

mod tezos_rpc;
use self::tezos_rpc::{BigMapReq, ForgeOperationsRequest, Operation, PreapplyOperation,
                      PreapplyOperationsRequest, TezosInputType, TezosRpcClient};
use crate::MmCoinEnum::Tezos;
use crate::tezos::tezos_rpc::TezosRpcClientImpl;
use futures::compat::Future01CompatExt;
use num_traits::AsPrimitive;

macro_rules! impl_display_for_base_58_check_sum {
    ($impl_for: ident) => {
        impl fmt::Display for $impl_for {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                let mut bytes = self.prefixed_bytes();
                let checksum = dhash256(&bytes);
                bytes.extend_from_slice(&checksum[..4]);
                bytes.to_base58().fmt(f)
            }
        }
    };
}

fn blake2b_256(input: &[u8]) -> H256 {
    let mut blake = unwrap!(VarBlake2b::new(32));
    blake.input(&input);
    H256::from(blake.vec_result().as_slice())
}

fn blake2b_160(input: &[u8]) -> H160 {
    let mut blake = unwrap!(VarBlake2b::new(20));
    blake.input(&input);
    H160::from(blake.vec_result().as_slice())
}

const ED_SK_PREFIX: [u8; 4] = [13, 15, 58, 7];
const ED_SIG_PREFIX: [u8; 5] = [9, 245, 205, 134, 18];

#[derive(Debug, Eq, PartialEq)]
struct TezosSignature {
    prefix: [u8; 5],
    sig: EdSignature,
}

pub type TezosAddrPrefix = [u8; 3];
pub type OpHashPrefix = [u8; 2];
pub type BlockHashPrefix = [u8; 2];

const OP_HASH_PREFIX: OpHashPrefix = [5, 116];

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct TezosAddress {
    prefix: TezosAddrPrefix,
    hash: H160,
}

#[derive(Debug, PartialEq)]
pub struct OpHash {
    prefix: OpHashPrefix,
    hash: H256,
}

#[derive(Debug, PartialEq)]
pub enum ParseAddressError {
    InvalidBase58(FromBase58Error),
    InvalidLength,
    InvalidCheckSum,
}

impl FromStr for TezosAddress {
    type Err = ParseAddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = s.from_base58().map_err(|e| ParseAddressError::InvalidBase58(e))?;
        if bytes.len() != 27 {
            return Err(ParseAddressError::InvalidLength);
        }
        let checksum = dhash256(&bytes[..23]);
        if bytes[23..] != checksum[..4] {
            return Err(ParseAddressError::InvalidCheckSum);
        }
        Ok(TezosAddress {
            prefix: unwrap!(bytes[..3].try_into(), "slice with incorrect length"),
            hash: H160::from(&bytes[3..23]),
        })
    }
}

impl FromStr for OpHash {
    type Err = ParseAddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = s.from_base58().map_err(|e| ParseAddressError::InvalidBase58(e))?;
        if bytes.len() != 38 {
            return Err(ParseAddressError::InvalidLength);
        }
        let checksum = dhash256(&bytes[..34]);
        if bytes[34..] != checksum[..4] {
            return Err(ParseAddressError::InvalidCheckSum);
        }
        Ok(OpHash {
            prefix: unwrap!(bytes[..2].try_into(), "slice with incorrect length"),
            hash: H256::from(&bytes[2..34]),
        })
    }
}

#[derive(Debug)]
pub enum ParseSigError {
    InvalidBase58(FromBase58Error),
    InvalidLength,
    InvalidCheckSum,
    InvalidSig(SignatureError),
}

impl FromStr for TezosSignature {
    type Err = ParseSigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = s.from_base58().map_err(|e| ParseSigError::InvalidBase58(e))?;
        if bytes.len() != 73 {
            return Err(ParseSigError::InvalidLength);
        }
        let checksum = dhash256(&bytes[..69]);
        if bytes[69..] != checksum[..4] {
            return Err(ParseSigError::InvalidCheckSum);
        }
        let sig = EdSignature::from_bytes(&bytes[5..69]).map_err(|e| ParseSigError::InvalidSig(e))?;
        Ok(TezosSignature {
            prefix: unwrap!(bytes[..5].try_into(), "slice with incorrect length"),
            sig,
        })
    }
}

impl TezosAddress {
    fn prefixed_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.extend_from_slice(&self.prefix);
        bytes.extend_from_slice(&*self.hash);
        bytes
    }

    fn from_rpc_bytes(bytes: BytesJson, prefix: TezosAddrPrefix) -> Result<Self, String> {
        let bytes = bytes.0;
        if bytes.len() != 22 {
            return ERR!("Invalid input len {}, expected 22", bytes.len());
        }

        match bytes[0] {
            0 => if bytes[1] == 0 {
                Ok(TezosAddress {
                    prefix,
                    hash: H160::from(&bytes[2..]),
                })
            } else {
                ERR!("Input has unexpected prefix, expected 0000, got {}", hex::encode(&bytes[..2]))
            },
            1 => {
                Ok(TezosAddress {
                    prefix,
                    hash: H160::from(&bytes[1..21]),
                })
            },
            _ => ERR!("Input {} has unexpected prefix", hex::encode(bytes))
        }
    }
}

impl_display_for_base_58_check_sum!(TezosAddress);

impl TezosSignature {
    fn prefixed_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.extend_from_slice(&self.prefix);
        bytes.extend_from_slice(&self.sig.to_bytes());
        bytes
    }
}

impl_display_for_base_58_check_sum!(TezosSignature);

impl OpHash {
    fn from_op_bytes(bytes: &[u8]) -> Self {
        OpHash {
            prefix: OP_HASH_PREFIX,
            hash: blake2b_256(bytes),
        }
    }

    fn prefixed_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.extend_from_slice(&self.prefix);
        bytes.extend_from_slice(&*self.hash);
        bytes
    }
}

impl_display_for_base_58_check_sum!(OpHash);

#[derive(Debug, PartialEq)]
struct TezosBlockHash {
    prefix: BlockHashPrefix,
    hash: H256,
}

impl TezosBlockHash {
    fn prefixed_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.extend_from_slice(&self.prefix);
        bytes.extend_from_slice(&*self.hash);
        bytes
    }
}

impl FromStr for TezosBlockHash {
    type Err = ParseSigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = s.from_base58().map_err(|e| ParseSigError::InvalidBase58(e))?;
        if bytes.len() != 38 {
            return Err(ParseSigError::InvalidLength);
        }
        let checksum = dhash256(&bytes[..34]);
        if bytes[34..] != checksum[..4] {
            return Err(ParseSigError::InvalidCheckSum);
        }
        Ok(TezosBlockHash {
            prefix: unwrap!(bytes[..2].try_into(), "slice with incorrect length"),
            hash: H256::from(&bytes[2..34]),
        })
    }
}

impl_display_for_base_58_check_sum!(TezosBlockHash);

/// Represents possible elliptic curves keypairs supported by Tezos
#[derive(Debug)]
enum TezosKeyPair {
    /// ED25519 keypair, used by Tezos by default, corresponds to tz1 addresses
    ED25519(EdKeypair),
    /// will be implemented later, corresponds to tz2 addresses
    SECP256K1,
    /// will be implemented later, corresponds to tz3 addresses
    P256,
}

impl PartialEq for TezosKeyPair {
    fn eq(&self, other: &Self) -> bool {
        match self {
            TezosKeyPair::ED25519(lhs) => {
                match other {
                    TezosKeyPair::ED25519(rhs) => lhs.secret.as_bytes() == rhs.secret.as_bytes() && lhs.public == rhs.public,
                    _ => false,
                }
            },
            _ => unimplemented!(),
        }
    }
}

impl TezosKeyPair {
    fn prefixed_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        match self {
            TezosKeyPair::ED25519(key_pair) => {
                bytes.extend_from_slice(&ED_SK_PREFIX);
                bytes.extend_from_slice(key_pair.secret.as_bytes());
            }
            _ => unimplemented!(),
        }
        bytes
    }
}

impl_display_for_base_58_check_sum!(TezosKeyPair);

#[derive(Debug, PartialEq)]
pub enum ParseKeyPairError {
    InvalidBase58(FromBase58Error),
    InvalidLength,
    InvalidPrefix,
    InvalidSecret(SignatureError),
    InvalidCheckSum,
}

impl fmt::Display for ParseKeyPairError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        format!("{:?}", self).fmt(f)
    }
}

impl fmt::Display for ParseAddressError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        format!("{:?}", self).fmt(f)
    }
}

impl FromStr for TezosKeyPair {
    type Err = ParseKeyPairError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = s.from_base58().map_err(|e| ParseKeyPairError::InvalidBase58(e))?;
        if bytes.len() != 40 {
            return Err(ParseKeyPairError::InvalidLength);
        }
        let checksum = dhash256(&bytes[..36]);
        if bytes[36..] != checksum[..4] {
            return Err(ParseKeyPairError::InvalidCheckSum);
        }
        match unwrap!(bytes[..4].try_into(), "slice with incorrect length") {
            ED_SK_PREFIX => {
                Self::from_bytes(&bytes[4..36])
            }
            _ => Err(ParseKeyPairError::InvalidPrefix),
        }
    }
}

impl TezosKeyPair {
    fn get_address(&self, prefix: TezosAddrPrefix) -> TezosAddress {
        let hash = match self {
            TezosKeyPair::ED25519(pair) => {
                blake2b_160(pair.public.as_bytes())
            },
            _ => unimplemented!()
        };
        TezosAddress {
            prefix,
            hash,
        }
    }

    fn from_bytes(bytes: &[u8]) -> Result<TezosKeyPair, ParseKeyPairError> {
        let secret = EdSecretKey::from_bytes(bytes).map_err(|e| ParseKeyPairError::InvalidSecret(e))?;
        let public = EdPublicKey::from_secret::<Sha512>(&secret);
        Ok(TezosKeyPair::ED25519(EdKeypair {
            secret,
            public,
        }))
    }
}

#[derive(Debug)]
pub enum TezosCoinType {
    /// Tezos or it's forks (Dune, etc.)
    Tezos,
    /// ERC like token with smart contract address
    ERC(TezosAddress),
}

#[derive(Debug)]
pub struct TezosCoinImpl {
    coin_type: TezosCoinType,
    decimals: u8,
    key_pair: TezosKeyPair,
    my_address: TezosAddress,
    required_confirmations: AtomicU64,
    rpc_client: TezosRpcClient,
    swap_contract_address: TezosAddress,
    ticker: String,
}

#[derive(Clone, Debug)]
pub struct TezosCoin(Arc<TezosCoinImpl>);

impl Deref for TezosCoin {type Target = TezosCoinImpl; fn deref (&self) -> &TezosCoinImpl {&*self.0}}

impl MarketCoinOps for TezosCoin {
    fn ticker (&self) -> &str {
        &self.ticker
    }

    fn my_address(&self) -> Cow<str> {
        format!("{}", self.my_address).into()
    }

    fn my_balance(&self) -> Box<dyn Future<Item=BigDecimal, Error=String> + Send> {
        let selfi = self.clone();
        let addr = format!("{}", self.my_address);
        let fut = Box::pin(async move {
            match &selfi.coin_type {
                TezosCoinType::Tezos => selfi.rpc_client.get_balance(&addr).await,
                TezosCoinType::ERC(token_addr) => {
                    let req = BigMapReq {
                        r#type: TezosInputType {
                            prim: "address".into(),
                        },
                        key: TezosValue::String {
                            string: selfi.my_address.to_string(),
                        }
                    };
                    let account: TezosErcAccount = try_s!(selfi.rpc_client.get_big_map(
                        &token_addr.to_string(),
                        req,
                    ).await);
                    Ok(BigDecimal::from(BigInt::from(account.balance)))
                }
            }
        });
        let divisor = BigDecimal::from(10u64.pow(self.decimals as u32));
        Box::new(fut.compat().map(move |balance| balance / divisor))
    }

    /// Receives raw transaction bytes in hexadecimal format as input and returns tx hash in hexadecimal format
    fn send_raw_tx(&self, tx: &str) -> Box<dyn Future<Item=String, Error=String> + Send> {
        let client = self.rpc_client.clone();
        let tx = tx.to_owned();
        let fut = Box::pin(async move {
            client.inject_operation(&tx).await
        });
        Box::new(fut.compat())
    }

    fn wait_for_confirmations(
        &self,
        tx: &[u8],
        confirmations: u64,
        wait_until: u64,
        check_every: u64,
        since_block: u64
    ) -> Box<dyn Future<Item=(), Error=String> + Send> {
        let coin = self.clone();
        let op_hash = OpHash::from_op_bytes(tx).to_string();
        let fut = Box::pin(async move {
            let since_block_header = try_s!(coin.rpc_client.block_header(&since_block.to_string()).await);
            let since_block_timestamp = Some(since_block_header.timestamp.timestamp());
            let mut found_tx_in_block = None;
            loop {
                if now_ms() / 1000 > wait_until {
                    return ERR!("Waited too long until {} for transaction {} to be confirmed {} times", wait_until, op_hash, confirmations);
                }

                let current_block_header = try_s!(coin.rpc_client.block_header("head").await);
                if current_block_header.level > since_block_header.level {
                    if found_tx_in_block.is_none() {
                        if current_block_header.level == since_block_header.level + 1 {
                            let operations = try_s!(coin.rpc_client.operation_hashes(&current_block_header.hash).await);
                            for operation in operations {
                                if operation == op_hash {
                                    found_tx_in_block = Some(current_block_header.level);
                                }
                            }
                        } else {
                            let length = current_block_header.level - since_block_header.level;
                            let blocks = try_s!(coin.rpc_client.blocks(since_block_timestamp, Some(length), None).await);
                            for block in blocks {
                                let operations = try_s!(coin.rpc_client.operation_hashes(&block).await);
                                for operation in operations {
                                    if operation == op_hash {
                                        let header = try_s!(coin.rpc_client.block_header(&block).await);
                                        found_tx_in_block = Some(header.level);
                                    }
                                }
                            }
                        }
                    }
                }
                if let Some(block_number) = found_tx_in_block {
                    let current_confirmations = current_block_header.level - block_number + 1;
                    if current_confirmations >= confirmations {
                        return Ok(());
                    }
                }
                Timer::sleep(check_every as f64).await
            }
        });
        Box::new(fut.compat())
    }

    fn wait_for_tx_spend(&self, transaction: &[u8], wait_until: u64, from_block: u64) -> TransactionFut {
        unimplemented!()
    }

    fn tx_enum_from_bytes(&self, bytes: &[u8]) -> Result<TransactionEnum, String> {
        unimplemented!()
    }

    fn current_block(&self) -> Box<dyn Future<Item=u64, Error=String> + Send> {
        let client = self.rpc_client.clone();
        let fut = Box::pin(async move {
            client.block_header("head").await
        });
        Box::new(fut.compat().map(|header| header.level))
    }

    fn address_from_pubkey_str(&self, pubkey: &str) -> Result<String, String> {
        unimplemented!()
    }
}

impl SwapOps for TezosCoin {
    fn send_taker_fee(&self, fee_addr: &[u8], amount: BigDecimal) -> TransactionFut {
        unimplemented!()
    }

    fn send_maker_payment(
        &self,
        time_lock: u32,
        taker_pub: &[u8],
        secret_hash: &[u8],
        amount: BigDecimal,
    ) -> TransactionFut {
        unimplemented!()
    }

    fn send_taker_payment(
        &self,
        uuid: &[u8],
        time_lock: u32,
        maker_pub: &[u8],
        secret_hash: &[u8],
        amount: BigDecimal,
    ) -> TransactionFut {
        let maker_addr = TezosAddress {
            prefix: [4, 177, 1],
            hash: blake2b_160(maker_pub),
        };

        let (amount, args) = match &self.coin_type {
            TezosCoinType::Tezos => {
                let args = init_tezos_swap_call(
                    uuid.to_vec().into(),
                    DateTime::from_utc(NaiveDateTime::from_timestamp(time_lock as i64, 0), Utc),
                    secret_hash.to_vec().into(),
                    maker_addr,
                );
                let amount = (amount * BigDecimal::from(10u64.pow(self.decimals as u32))).to_bigint().unwrap().to_biguint().unwrap();
                (amount, args)
            },
            TezosCoinType::ERC(addr) => {
                let amount: BigUint = (amount * BigDecimal::from(10u64.pow(self.decimals as u32))).to_bigint().unwrap().to_biguint().unwrap();
                let args = init_tezos_erc_swap_call(
                    uuid.to_vec().into(),
                    DateTime::from_utc(NaiveDateTime::from_timestamp(time_lock as i64, 0), Utc),
                    secret_hash.to_vec().into(),
                    maker_addr,
                    amount,
                    &addr,
                );
                (BigUint::from(0u8), args)
            }
        };

        let coin = self.clone();
        let fut = Box::pin(async move {
            let dest = coin.swap_contract_address.clone();
            sign_and_send_operation(coin, amount, &dest, Some(args)).await
        }).compat().map(|tx| tx.into());
        Box::new(fut)
    }

    fn send_maker_spends_taker_payment(
        &self,
        uuid: &[u8],
        taker_payment_tx: &[u8],
        time_lock: u32,
        taker_pub: &[u8],
        secret: &[u8],
    ) -> TransactionFut {
        let taker_addr = TezosAddress {
            prefix: [4, 177, 1],
            hash: blake2b_160(taker_pub),
        };

        let args = receiver_spends_call(
            uuid.to_vec().into(),
            secret.to_vec().into(),
            self.my_address.clone(),
        );

        let coin = self.clone();
        let fut = Box::pin(async move {
            let dest = coin.swap_contract_address.clone();
            sign_and_send_operation(coin, BigUint::from(0u8), &dest, Some(args)).await
        }).compat().map(|tx| tx.into());
        Box::new(fut)
    }

    fn send_taker_spends_maker_payment(
        &self,
        maker_payment_tx: &[u8],
        time_lock: u32,
        maker_pub: &[u8],
        secret: &[u8],
    ) -> TransactionFut {
        unimplemented!()
    }

    fn send_taker_refunds_payment(
        &self,
        taker_payment_tx: &[u8],
        time_lock: u32,
        maker_pub: &[u8],
        secret_hash: &[u8],
    ) -> TransactionFut {
        unimplemented!()
    }

    fn send_maker_refunds_payment(
        &self,
        maker_payment_tx: &[u8],
        time_lock: u32,
        taker_pub: &[u8],
        secret_hash: &[u8],
    ) -> TransactionFut {
        unimplemented!()
    }

    fn validate_fee(
        &self,
        fee_tx: &TransactionEnum,
        fee_addr: &[u8],
        amount: &BigDecimal,
    ) -> Box<dyn Future<Item=(), Error=String> + Send> {
        unimplemented!()
    }

    fn validate_maker_payment(
        &self,
        payment_tx: &[u8],
        time_lock: u32,
        maker_pub: &[u8],
        priv_bn_hash: &[u8],
        amount: BigDecimal,
    ) -> Box<dyn Future<Item=(), Error=String> + Send> {
        unimplemented!()
    }

    fn validate_taker_payment(
        &self,
        payment_tx: &[u8],
        time_lock: u32,
        taker_pub: &[u8],
        priv_bn_hash: &[u8],
        amount: BigDecimal,
    ) -> Box<dyn Future<Item=(), Error=String> + Send> {
        unimplemented!()
    }

    fn check_if_my_payment_sent(
        &self,
        time_lock: u32,
        other_pub: &[u8],
        secret_hash: &[u8],
        search_from_block: u64,
    ) -> Box<dyn Future<Item=Option<TransactionEnum>, Error=String> + Send> {
        unimplemented!()
    }

    fn search_for_swap_tx_spend_my(
        &self,
        time_lock: u32,
        other_pub: &[u8],
        secret_hash: &[u8],
        tx: &[u8],
        search_from_block: u64,
    ) -> Result<Option<FoundSwapTxSpend>, String> {
        unimplemented!()
    }

    fn search_for_swap_tx_spend_other(
        &self,
        time_lock: u32,
        other_pub: &[u8],
        secret_hash: &[u8],
        tx: &[u8],
        search_from_block: u64,
    ) -> Result<Option<FoundSwapTxSpend>, String> {
        unimplemented!()
    }
}

impl Transaction for TezosOperation {
    fn tx_hex(&self) -> Vec<u8> {
        serialize(self).take()
    }

    fn extract_secret(&self) -> Result<Vec<u8>, String> {
        unimplemented!()
    }

    fn tx_hash(&self) -> BytesJson {
        unimplemented!()
    }
}

async fn sign_and_send_operation(
    coin: TezosCoin,
    amount: BigUint,
    destination: &TezosAddress,
    parameters: Option<TezosValue>
) -> Result<TezosOperation, String> {
    let counter = try_s!(coin.rpc_client.counter(&coin.my_address()).await) + BigUint::from(1u8);
    let head = try_s!(coin.rpc_client.block_header("head").await);
    let op = Operation {
        amount,
        counter,
        destination: destination.to_string(),
        fee: BigUint::from(0100000u32),
        gas_limit: BigUint::from(800000u32),
        kind: "transaction".into(),
        parameters,
        source: coin.my_address().into(),
        storage_limit: BigUint::from(60000u32),
    };
    let forge_req = ForgeOperationsRequest {
        branch: head.hash.clone(),
        contents: vec![op.clone()]
    };
    let mut tx_bytes = try_s!(coin.rpc_client.forge_operations(&head.chain_id, &head.hash, forge_req).await);
    let mut prefixed = vec![3u8];
    prefixed.append(&mut tx_bytes.0);
    let sig_hash = blake2b_256(&prefixed);
    let sig = match &coin.key_pair {
        TezosKeyPair::ED25519(key_pair) => key_pair.sign::<Sha512>(&*sig_hash),
        _ => unimplemented!(),
    };
    let signature = TezosSignature {
        prefix: ED_SIG_PREFIX,
        sig,
    };
    let preapply_req = PreapplyOperationsRequest(vec![PreapplyOperation {
        branch: head.hash,
        contents: vec![op],
        protocol: head.protocol,
        signature: format!("{}", signature),
    }]);
    try_s!(coin.rpc_client.preapply_operations(preapply_req).await);
    prefixed.extend_from_slice(&signature.sig.to_bytes());
    prefixed.remove(0);
    try_s!(coin.rpc_client.inject_operation(&hex::encode(&prefixed)).await);
    log!((hex::encode(prefixed.as_slice())));
    Ok(deserialize(prefixed.as_slice()).unwrap())
}

async fn withdraw_impl(coin: TezosCoin, req: WithdrawRequest) -> Result<TransactionDetails, String> {
    let to_addr: TezosAddress = try_s!(req.to.parse());
    let counter = try_s!(coin.rpc_client.counter(&coin.my_address()).await) + BigUint::from(1u8);
    let head = try_s!(coin.rpc_client.block_header("head").await);
    let op = match &coin.coin_type {
        TezosCoinType::Tezos => Operation {
            amount: (&req.amount * BigDecimal::from(10u64.pow(coin.decimals as u32))).to_bigint().unwrap().to_biguint().unwrap(),
            counter,
            destination: req.to.clone(),
            fee: BigUint::from(1420u32),
            gas_limit: BigUint::from(10600u32),
            kind: "transaction".into(),
            parameters: None,
            source: coin.my_address().into(),
            storage_limit: BigUint::from(300u32),
        },
        TezosCoinType::ERC(addr) => {
            let amount: BigUint = (&req.amount * BigDecimal::from(10u64.pow(coin.decimals as u32))).to_bigint().unwrap().to_biguint().unwrap();
            let parameters = Some(erc_transfer_call(&to_addr, &amount));
            Operation {
                amount: BigUint::from(0u8),
                counter,
                destination: addr.to_string(),
                fee: BigUint::from(100000u32),
                gas_limit: BigUint::from(800000u32),
                kind: "transaction".into(),
                parameters,
                source: coin.my_address().into(),
                storage_limit: BigUint::from(60000u32),
            }
        },
    };
    let forge_req = ForgeOperationsRequest {
        branch: head.hash.clone(),
        contents: vec![op.clone()]
    };
    let mut tx_bytes = try_s!(coin.rpc_client.forge_operations(&head.chain_id, &head.hash, forge_req).await);
    let mut prefixed = vec![3u8];
    prefixed.append(&mut tx_bytes.0);
    let sig_hash = blake2b_256(&prefixed);
    let sig = match &coin.key_pair {
        TezosKeyPair::ED25519(key_pair) => key_pair.sign::<Sha512>(&*sig_hash),
        _ => unimplemented!(),
    };
    let signature = TezosSignature {
        prefix: ED_SIG_PREFIX,
        sig,
    };
    let preapply_req = PreapplyOperationsRequest(vec![PreapplyOperation {
        branch: head.hash,
        contents: vec![op],
        protocol: head.protocol,
        signature: format!("{}", signature),
    }]);
    try_s!(coin.rpc_client.preapply_operations(preapply_req).await);
    prefixed.extend_from_slice(&signature.sig.to_bytes());
    prefixed.remove(0);
    let op_hash = OpHash::from_op_bytes(&prefixed);
    let details = TransactionDetails {
        coin: coin.ticker.clone(),
        to: vec![req.to],
        from: vec![coin.my_address().into()],
        fee_details: None,
        tx_hex: prefixed.into(),
        block_height: 0,
        my_balance_change: 0.into(),
        total_amount: 0.into(),
        internal_id: vec![].into(),
        timestamp: 0,
        received_by_me: 0.into(),
        spent_by_me: 0.into(),
        tx_hash: op_hash.to_string()
    };
    Ok(details)
}

impl MmCoin for TezosCoin {
    fn is_asset_chain(&self) -> bool {
        unimplemented!()
    }

    fn check_i_have_enough_to_trade(&self, amount: &MmNumber, balance: &MmNumber, trade_info: TradeInfo) -> Box<dyn Future<Item=(), Error=String> + Send> {
        unimplemented!()
    }

    fn can_i_spend_other_payment(&self) -> Box<dyn Future<Item=(), Error=String> + Send> {
        unimplemented!()
    }

    fn withdraw(&self, req: WithdrawRequest) -> Box<dyn Future<Item=TransactionDetails, Error=String> + Send> {
        Box::new(Box::pin(withdraw_impl(self.clone(), req)).compat())
    }

    fn decimals(&self) -> u8 {
        unimplemented!()
    }

    fn process_history_loop(&self, ctx: MmArc) {
        unimplemented!()
    }

    fn tx_details_by_hash(&self, hash: &[u8]) -> Box<dyn Future<Item=TransactionDetails, Error=String> + Send> {
        unimplemented!()
    }

    fn history_sync_status(&self) -> HistorySyncState {
        unimplemented!()
    }

    /// Get fee to be paid per 1 swap transaction
    fn get_trade_fee(&self) -> Box<dyn Future<Item=TradeFee, Error=String> + Send> {
        unimplemented!()
    }

    fn required_confirmations(&self) -> u64 {
        self.required_confirmations.load(AtomicOrdering::Relaxed)
    }

    fn set_required_confirmations(&self, confirmations: u64) {
        self.required_confirmations.store(confirmations, AtomicOrdering::Relaxed);
    }
}

pub async fn tezos_coin_from_conf_and_request(
    ticker: &str,
    conf: &Json,
    req: &Json,
    priv_key: &[u8],
) -> Result<TezosCoin, String> {
    let mut urls: Vec<String> = try_s!(json::from_value(req["urls"].clone()));
    if urls.is_empty() {
        return ERR!("Enable request for Tezos coin protocol must have at least 1 node URL");
    }
    let rpc_client = try_s!(TezosRpcClient::new(urls));
    let key_pair = try_s!(TezosKeyPair::from_bytes(priv_key));
    let ed25519_addr_prefix: TezosAddrPrefix = try_s!(json::from_value(conf["ed25519_addr_prefix"].clone()));
    let my_address = key_pair.get_address(ed25519_addr_prefix);
    let (decimals, coin_type) = match conf["protocol"]["token_type"].as_str().unwrap() {
        "TEZOS" => {
            let decimals = conf["decimals"].as_u64().unwrap_or (6) as u8;
            (decimals, TezosCoinType::Tezos)
        },
        "ERC20" => {
            let addr = try_s!(TezosAddress::from_str(conf["protocol"]["contract_address"].as_str().unwrap()));
            let decimals = match conf["decimals"].as_u64() {
                Some(d) => d as u8,
                None => {
                    let storage: TezosErcStorage = try_s!(rpc_client.get_storage(&addr.to_string()).await);
                    storage.decimals
                }
            };

            (decimals, TezosCoinType::ERC(addr))
        },
        _ => unimplemented!()
    };

    Ok(TezosCoin(Arc::new(TezosCoinImpl {
        coin_type,
        decimals,
        key_pair,
        my_address,
        required_confirmations: conf["required_confirmations"].as_u64().unwrap_or(1).into(),
        rpc_client,
        swap_contract_address: "KT1B1D1iVrVyrABRRp6PxPU894dzWghvt4mf".parse().unwrap(),
        ticker: ticker.into(),
    })))
}

#[test]
fn tezos_address_from_to_string() {
    let address = TezosAddress {
        prefix: [6, 161, 159],
        hash: H160::from([218, 201, 245, 37, 67, 218, 26, 237, 11, 193, 214, 180, 107, 247, 193, 13, 183, 1, 76, 214]),
    };

    assert_eq!("tz1faswCTDciRzE4oJ9jn2Vm2dvjeyA9fUzU", address.to_string());
    assert_eq!(address, unwrap!(TezosAddress::from_str("tz1faswCTDciRzE4oJ9jn2Vm2dvjeyA9fUzU")));
}

#[test]
fn tezos_block_hash_from_to_string() {
    let block_hash = TezosBlockHash {
        prefix: [1, 52],
        hash: H256::from([179, 210, 18, 192, 241, 185, 183, 107, 195, 238, 140, 247, 125, 33, 193, 145, 186, 39, 80, 186, 231, 132, 73, 236, 217, 134, 218, 226, 45, 91, 94, 180]),
    };

    assert_eq!("BM5UcRC5rLiajhwDNEmF3mF152f2Uiaqsj9CFTr4WyQvCsaY4pm", block_hash.to_string());
    assert_eq!(block_hash, unwrap!(TezosBlockHash::from_str("BM5UcRC5rLiajhwDNEmF3mF152f2Uiaqsj9CFTr4WyQvCsaY4pm")));
}

#[test]
fn dune_address_from_to_string() {
    let address = TezosAddress {
        prefix: [4, 177, 1],
        hash: H160::from([218, 201, 245, 37, 67, 218, 26, 237, 11, 193, 214, 180, 107, 247, 193, 13, 183, 1, 76, 214]),
    };

    assert_eq!("dn1c5mt3XTbLo5mKBpaTqidP6bSzUVD9T5By", address.to_string());
    assert_eq!(address, unwrap!(TezosAddress::from_str("dn1c5mt3XTbLo5mKBpaTqidP6bSzUVD9T5By")));

    let address = TezosAddress {
        prefix: [4, 177, 4],
        hash: H160::from([218, 201, 245, 37, 67, 218, 26, 237, 11, 193, 214, 180, 107, 247, 193, 13, 183, 1, 76, 214]),
    };

    assert_eq!("dn2p6aqNRKitBiDcc5eiqg5kuxLWFKLiDwmb", address.to_string());
    assert_eq!(address, unwrap!(TezosAddress::from_str("dn2p6aqNRKitBiDcc5eiqg5kuxLWFKLiDwmb")));
}

#[test]
fn tezos_key_pair_from_to_string() {
    let key_pair = TezosKeyPair::ED25519(EdKeypair {
        secret: unwrap!(EdSecretKey::from_bytes(&[197, 109, 203, 119, 241, 255, 240, 13, 26, 31, 83, 48, 167, 122, 159, 31, 49, 207, 112, 250, 122, 214, 145, 162, 43, 94, 194, 140, 219, 35, 35, 80])),
        public: unwrap!(EdPublicKey::from_bytes(&[107, 106, 160, 0, 4, 28, 170, 101, 209, 223, 114, 53, 77, 50, 155, 234, 226, 167, 130, 197, 144, 33, 242, 92, 111, 64, 191, 74, 136, 120, 28, 27])),
    });

    assert_eq!("edsk4ArLQgBTLWG5FJmnGnT689VKoqhXwmDPBuGx3z4cvwU9MmrPZZ", key_pair.to_string());
    assert_eq!(key_pair, unwrap!(TezosKeyPair::from_str("edsk4ArLQgBTLWG5FJmnGnT689VKoqhXwmDPBuGx3z4cvwU9MmrPZZ")));

    let key_pair: TezosKeyPair = "edsk2j9jaipLSH77rtwZFroZqEoSkr5fFUzcPqhphBH3BKudQU9rtw".parse().unwrap();
    log!([key_pair]);
    log!((hex::encode([7, 96, 182, 24, 158, 16, 97, 13, 56, 0, 215, 93, 20, 255, 226, 240, 171, 179, 95, 139, 246, 18, 169, 81, 11, 85, 152, 217, 120, 248, 63, 122])));
}

#[test]
fn key_pair_get_address() {
    let key_pair: TezosKeyPair = unwrap!("edsk4ArLQgBTLWG5FJmnGnT689VKoqhXwmDPBuGx3z4cvwU9MmrPZZ".parse());
    let expected = TezosAddress {
        prefix: [6, 161, 159],
        hash: H160::from([218, 201, 245, 37, 67, 218, 26, 237, 11, 193, 214, 180, 107, 247, 193, 13, 183, 1, 76, 214]),
    };

    assert_eq!(expected, key_pair.get_address([6, 161, 159]));
}

#[test]
fn sign_transaction() {
    let destination: TezosAddress = "dn1c5mt3XTbLo5mKBpaTqidP6bSzUVD9T5By".parse().unwrap();
    let source: TezosAddress = "dn1Kutfh4ewtNxu9FcwDHfz7X4SWuWZdRGyp".parse().unwrap();

    log!((hex::encode(&*destination.hash)));
    log!((hex::encode(&*source.hash)));
    let unsigned = hex::decode("03711c24b8e5535f6d47a4ddea053ec82e136ae0e474f34a7e0fbe8aa1cccb340a0800002969737230bd5ea60f632b52777981e43a25d069a08d06fa0380ea30e0d4030001c56d2c471c59aa98400fa4256bd94cc7217ec4aa00ff00000030000505070701000000244b5431474532415a68617a52784773416a52566b516363486342327076414e58515764370000").unwrap();
    let signedtx = hex::decode("65b4ddad474b95481602e3769d1ae3ca18aeb7d6f0d9be4bb2b09d68a97347aa0800002969737230bd5ea60f632b52777981e43a25d0698c0bf903e852ac02c0843d0000dac9f52543da1aed0bc1d6b46bf7c10db7014cd6006ffb48688b8a5d68652aa52a48902d536c7a315b64b77db8f12ac79cc713b50265e25bcee6d00aad44e024352f8018eccf61e82616fc1db87ccb5bf75f966801").unwrap();

    let key_pair: TezosKeyPair = "edsk2j9jaipLSH77rtwZFroZqEoSkr5fFUzcPqhphBH3BKudQU9rtw".parse().unwrap();
    match key_pair {
        TezosKeyPair::ED25519(pair) => {
            let sig = pair.sign::<Sha512>(&unsigned);
            log!([sig]);
            let sig = pair.sign::<Blake2b>(&unsigned);
            log!([sig]);
            log!([signedtx]);
        },
        _ => unimplemented!(),
    }
}

#[test]
fn tezos_signature_from_to_string() {
    let sig_str = "edsigtrFyTY19vJ4XFdrK8uUM3qHzE6427u4JYRNsMtzdBqQvPPnKZYE3xps25CEPm2yTXu53Po16Z523PHG7jzgowb3X75w66Y";
    let sig: TezosSignature = sig_str.parse().unwrap();
    assert_eq!(sig_str, sig.to_string());
}

#[test]
fn operation_hash_from_to_string() {
    let op_hash_str = "op9z9QouqrxjnE4RRQ86PCvhLLQcyKoWBoHBLX6BRE8JqBmcKWe";
    let op_hash: OpHash = op_hash_str.parse().unwrap();
    log!([op_hash]);
    assert_eq!(op_hash_str, op_hash.to_string());
}

#[derive(Debug)]
struct TezosErcStorage {
    accounts: HashMap<BytesJson, TezosErcAccount>,
    version: u64,
    total_supply: BigUint,
    decimals: u8,
    name: String,
    symbol: String,
    owner: String,
}

impl TryFrom<TezosValue> for BigUint {
    type Error = String;

    fn try_from(value: TezosValue) -> Result<Self, Self::Error> {
        match value {
            TezosValue::Int { int } => Ok(try_s!(int.to_biguint().ok_or(fomat!("Could not convert " (int) " to BigUint")))),
            _ => ERR!("BigUint can be constructed only from TezosValue::Int, got {:?}", value),
        }
    }
}

impl TryFrom<TezosValue> for u8 {
    type Error = String;

    fn try_from(value: TezosValue) -> Result<Self, Self::Error> {
        match value {
            TezosValue::Int { int } => Ok(try_s!(int.to_u8().ok_or(fomat!("Could not convert " (int) " to u8")))),
            _ => ERR!("u8 can be constructed only from TezosValue::Int, got {:?}", value),
        }
    }
}

impl TryFrom<TezosValue> for u64 {
    type Error = String;

    fn try_from(value: TezosValue) -> Result<Self, Self::Error> {
        match value {
            TezosValue::Int { int } => Ok(try_s!(int.to_u64().ok_or(fomat!("Could not convert " (int) " to u64")))),
            _ => ERR!("u64 can be constructed only from TezosValue::Int, got {:?}", value),
        }
    }
}

impl TryFrom<TezosValue> for String {
    type Error = String;

    fn try_from(value: TezosValue) -> Result<Self, Self::Error> {
        match value {
            TezosValue::String { string } => Ok(string),
            _ => ERR!("String can be constructed only from TezosValue::String, got {:?}", value),
        }
    }
}

macro_rules! impl_try_from_tezos_rpc_value_for_hash_map {
    ($key_type: ident, $value_type: ident) => {
        impl TryFrom<TezosValue> for HashMap<$key_type, $value_type> {
            type Error = String;

            fn try_from(value: TezosValue) -> Result<Self, Self::Error> {
                match value {
                    TezosValue::List (elems) => {
                        let mut res = HashMap::new();
                        for elem in elems {
                            match elem {
                                TezosValue::TezosPrim(TezosPrim::Elt((key, value))) => {
                                    res.insert(try_s!((*key).try_into()), try_s!((*value).try_into()));
                                },
                                _ => return ERR!("Unexpected item {:?} in list, must be TezosPrim::Elt", elem),
                            }
                        }
                        Ok(res)
                    },
                    _ => ERR!("HashMap can be constructed only from TezosValue::List, got {:?}", value),
                }
            }
        }
    };
}

impl_try_from_tezos_rpc_value_for_hash_map!(BytesJson, TezosErcAccount);
impl_try_from_tezos_rpc_value_for_hash_map!(BytesJson, BigUint);

impl TryFrom<TezosValue> for TezosErcAccount {
    type Error = String;

    fn try_from(value: TezosValue) -> Result<Self, Self::Error> {
        let mut reader = TezosValueReader {
            inner: Some(value),
        };

        Ok(TezosErcAccount {
            balance: try_s!(reader.read().unwrap().try_into()),
            allowances: try_s!(reader.read().unwrap().try_into()),
        })
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "prim", content = "args")]
pub enum TezosPrim {
    Pair ((Box<TezosValue>, Box<TezosValue>)),
    Elt ((Box<TezosValue>, Box<TezosValue>)),
    Right ([Box<TezosValue>; 1]),
    Left ([Box<TezosValue>; 1]),
    Some ([Box<TezosValue>; 1]),
    Unit,
    None,
}

impl Serialize for TezosInt {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error> where S: Serializer {
        s.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for TezosInt {
    fn deserialize<D>(d: D) -> Result<TezosInt, D::Error> where D: Deserializer<'de> {
        struct BigIntStringVisitor;

        impl<'de> Visitor<'de> for BigIntStringVisitor {
            type Value = TezosInt;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string containing json data")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
            {

                BigInt::from_str(v).map_err(E::custom).map(|num| num.into())
            }
        }

        d.deserialize_any(BigIntStringVisitor)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(untagged)]
pub enum TezosValue {
    Bytes { bytes: BytesJson },
    Int { int: TezosInt },
    List (Vec<TezosValue>),
    TezosPrim (TezosPrim),
    String { string: String },
}

impl TezosValue {
    fn split_and_read_value(self) -> (TezosValue, Option<TezosValue>) {
        match self {
            TezosValue::TezosPrim(TezosPrim::Pair((left, right))) => (*left, Some(*right)),
            _ => (self, None),
        }
    }
}

struct TezosValueReader {
    inner: Option<TezosValue>,
}

impl Serializable for TezosValue {
    fn serialize(&self, s: &mut Stream) {
        match self {
            TezosValue::String { string } => {
                let bytes = string.as_bytes();
                s.append(&1u8);
                s.append_slice(&(bytes.len() as u32).to_be_bytes());
                s.append_slice(&bytes);
            },
            TezosValue::Int { int } => {
                s.append(&0u8);
                s.append(int);
            },
            TezosValue::Bytes { bytes } => {
                s.append(&10u8);
                s.append_slice(&(bytes.len() as u32).to_be_bytes());
                s.append_slice(&bytes);
            },
            TezosValue::TezosPrim(TezosPrim::Pair((left, right))) => {
                s.append(&7u8);
                s.append(&7u8);
                s.append(left.as_ref());
                s.append(right.as_ref());
            },
            TezosValue::TezosPrim(TezosPrim::Left(value)) => {
                s.append(&5u8);
                s.append(&5u8);
                s.append(value[0].as_ref());
            },
            TezosValue::TezosPrim(TezosPrim::Right(value)) => {
                s.append(&5u8);
                s.append(&8u8);
                s.append(value[0].as_ref());
            },
            _ => unimplemented!(),
        }
    }
}

impl TezosValueReader {
    fn read(&mut self) -> Result<TezosValue, String> {
        let val = self.inner.take();
        let (res, next) = val.unwrap().split_and_read_value();
        self.inner = next;
        log!([res]);
        Ok(res)
    }
}

impl TryFrom<TezosValue> for TezosErcStorage {
    type Error = String;

    fn try_from(value: TezosValue) -> Result<Self, Self::Error> {
        let mut reader = TezosValueReader {
            inner: Some(value),
        };

        Ok(TezosErcStorage {
            accounts: try_s!(reader.read().unwrap().try_into()),
            version: try_s!(reader.read().unwrap().try_into()),
            total_supply: try_s!(reader.read().unwrap().try_into()),
            decimals: try_s!(reader.read().unwrap().try_into()),
            name: try_s!(reader.read().unwrap().try_into()),
            symbol: try_s!(reader.read().unwrap().try_into()),
            owner: try_s!(reader.read().unwrap().try_into()),
        })
    }
}

impl TryFrom<TezosValue> for BytesJson {
    type Error = String;

    fn try_from(value: TezosValue) -> Result<Self, Self::Error> {
        match value {
            TezosValue::Bytes { bytes } => Ok(bytes),
            _ => ERR!("Bytes can be constructed only from TezosValue::Bytes, got {:?}", value),
        }
    }
}

#[derive(Debug)]
struct TezosErcAccount {
    balance: BigUint,
    allowances: HashMap<BytesJson, BigUint>,
}

#[test]
fn deserialize_erc_storage() {
    let json = r#"{"prim":"Pair","args":[[],{"prim":"Pair","args":[{"int":"1"},{"prim":"Pair","args":[{"int":"100000"},{"prim":"Pair","args":[{"int":"0"},{"prim":"Pair","args":[{"string":"TEST"},{"prim":"Pair","args":[{"string":"TEST"},{"string":"dn1Kutfh4ewtNxu9FcwDHfz7X4SWuWZdRGyp"}]}]}]}]}]}]}"#;
    let pair: TezosValue = json::from_str(&json).unwrap();
    log!([pair]);
    let storage = unwrap!(TezosErcStorage::try_from(pair));
    log!([storage]);
}

#[test]
fn deserialize_erc_account() {
    let json = r#"{"prim":"Pair","args":[{"int":"99984"},[{"prim":"Elt","args":[{"bytes":"01088e02012f75cdee43326dfdec205f7bfd30dd6c00"},{"int":"990"}]},{"prim":"Elt","args":[{"bytes":"0122bef431640e29dd4a01cf7cc5befac05f0b99b700"},{"int":"999"}]},{"prim":"Elt","args":[{"bytes":"0152f0ecfb244e2b393b60263d8ae60ac13d08472900"},{"int":"999"}]},{"prim":"Elt","args":[{"bytes":"0153663d8ad9f9c6b28f94508599a255b6c2c5b0c900"},{"int":"999"}]},{"prim":"Elt","args":[{"bytes":"0153d475620cccc1cdb1fb2e1d20c2c713a729fc5100"},{"int":"1"}]},{"prim":"Elt","args":[{"bytes":"015eef25239095cfef6325bbbe7671821d0761936e00"},{"int":"999"}]},{"prim":"Elt","args":[{"bytes":"0164ba0f8a211f0584171b47e1c7d00686d80642d600"},{"int":"999"}]},{"prim":"Elt","args":[{"bytes":"0169ad9656ad447d6394c0dae64588f307f47ac37500"},{"int":"1000"}]},{"prim":"Elt","args":[{"bytes":"017d8c19f42235a54c7e932cf0120a9b869a141fad00"},{"int":"999"}]},{"prim":"Elt","args":[{"bytes":"01c90438d5b073d5d8bde6f2cd24957f911bd78beb00"},{"int":"998"}]},{"prim":"Elt","args":[{"bytes":"01d2fd4e3c7cb8a766462c02d388b530ce40192f5c00"},{"int":"999"}]},{"prim":"Elt","args":[{"bytes":"01fcf0818b6d79358258675f07451f8de76ff8626e00"},{"int":"999"}]}]]}"#;
    let rpc_value: TezosValue = json::from_str(&json).unwrap();
    log!([rpc_value]);
    let erc_account = unwrap!(TezosErcAccount::try_from(rpc_value));
    log!([erc_account]);
}

#[test]
fn tezos_address_from_rpc_bytes() {
    let bytes: BytesJson = unwrap!(hex::decode("00002969737230bd5ea60f632b52777981e43a25d069")).into();
    let addr = unwrap!(TezosAddress::from_rpc_bytes(bytes, [4, 177, 1]));
    assert_eq!("dn1Kutfh4ewtNxu9FcwDHfz7X4SWuWZdRGyp", addr.to_string());

    let bytes: BytesJson = unwrap!(hex::decode("00002969737230bd5ea60f632b52777981e43a25d069")).into();
    let addr = unwrap!(TezosAddress::from_rpc_bytes(bytes, [4, 177, 1]));
    assert_eq!("dn1Kutfh4ewtNxu9FcwDHfz7X4SWuWZdRGyp", addr.to_string());

    let bytes: BytesJson = unwrap!(hex::decode("01c56d2c471c59aa98400fa4256bd94cc7217ec4aa00")).into();
    let addr = unwrap!(TezosAddress::from_rpc_bytes(bytes, [2, 90, 121]));
    assert_eq!("KT1SafU2UYYQEDchguKra2ya9AKpaEgY2KLx", addr.to_string());
}

#[test]
fn blake2b_of_zeros() {
    let input = [0; 32];
    let blake = blake2b_256(&input);
    let sha = sha256(&input);
    log!((hex::encode(&*blake)));
    log!((hex::encode(&*sha)));
    log!((hex::encode(&input)));
}

enum Or {
    L,
    R,
}

impl Into<TezosValue> for &str {
    fn into(self) -> TezosValue {
        TezosValue::String {
            string: self.into()
        }
    }
}

impl Into<TezosValue> for &TezosAddress {
    fn into(self) -> TezosValue {
        TezosValue::String {
            string: self.to_string()
        }
    }
}

impl Into<TezosValue> for &BigUint {
    fn into(self) -> TezosValue {
        TezosValue::Int {
            int: unwrap!(self.to_bigint()).into()
        }
    }
}

impl Into<TezosValue> for BigUint {
    fn into(self) -> TezosValue {
        TezosValue::Int {
            int: unwrap!(self.to_bigint()).into()
        }
    }
}

impl Into<TezosValue> for BytesJson {
    fn into(self) -> TezosValue {
        TezosValue::Bytes {
            bytes: self
        }
    }
}

impl Into<TezosValue> for TezosAddress {
    fn into(self) -> TezosValue {
        TezosValue::String {
            string: self.to_string()
        }
    }
}

impl Into<TezosValue> for DateTime<Utc> {
    fn into(self) -> TezosValue {
        TezosValue::String {
            string: self.to_rfc3339_opts(SecondsFormat::Secs, true)
        }
    }
}

macro_rules! tezos_func {
    ($func:expr $(, $arg_name:ident)*) => {{
        let mut params: Vec<TezosValue> = vec![];
        $(
            params.push($arg_name.into());
        )*
        let args = match params.pop() {
            Some(a) => a,
            None => TezosValue::TezosPrim(TezosPrim::Unit),
        };
        let args = params.into_iter().rev().fold(args, |arg, cur| TezosValue::TezosPrim(TezosPrim::Pair((
            Box::new(cur),
            Box::new(arg)
        ))));
        construct_function_call($func, args)
    }}
}

fn erc_transfer_call(to: &TezosAddress, amount: &BigUint) -> TezosValue {
    tezos_func!(&[Or::L], to, amount)
}

fn init_tezos_swap_call(
    id: BytesJson,
    time_lock: DateTime<Utc>,
    secret_hash: BytesJson,
    receiver: TezosAddress,
) -> TezosValue {
    tezos_func!(&[Or::L], id, time_lock, secret_hash, receiver)
}

fn init_tezos_erc_swap_call(
    id: BytesJson,
    time_lock: DateTime<Utc>,
    secret_hash: BytesJson,
    receiver: TezosAddress,
    amount: BigUint,
    erc_addr: &TezosAddress,
) -> TezosValue {
    tezos_func!(&[Or::R, Or::L], id, time_lock, secret_hash, receiver, amount, erc_addr)
}

fn receiver_spends_call(
    id: BytesJson,
    secret: BytesJson,
    send_to: TezosAddress,
) -> TezosValue {
    tezos_func!(&[Or::R, Or::R, Or::L], id, secret, send_to)
}

fn sender_refunds_call(
    id: BytesJson,
    send_to: TezosAddress,
) -> TezosValue {
    tezos_func!(&[Or::R, Or::R, Or::R], id, send_to)
}

fn construct_function_call(func: &[Or], args: TezosValue) -> TezosValue {
    func.iter().rev().fold(args, |arg, or| match or {
        Or::L => TezosValue::TezosPrim(TezosPrim::Left([Box::new(arg)])),
        Or::R => TezosValue::TezosPrim(TezosPrim::Right([Box::new(arg)])),
    })
}

#[test]
fn test_construct_function_call() {
    let id = BytesJson(vec![1]);
    let timestamp: DateTime<Utc> = "1970-01-01T00:00:00Z".parse().unwrap();
    let secret_hash: BytesJson = hex::decode("66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925").unwrap().into();
    let address: TezosAddress = "dn1Kutfh4ewtNxu9FcwDHfz7X4SWuWZdRGyp".parse().unwrap();
    let call = tezos_func!(&[Or::L], id, timestamp, secret_hash, address);
    let expected = r#"{"prim":"Left","args":[{"prim":"Pair","args":[{"bytes":"01"},{"prim":"Pair","args":[{"string":"1970-01-01T00:00:00Z"},{"prim":"Pair","args":[{"bytes":"66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"},{"string":"dn1Kutfh4ewtNxu9FcwDHfz7X4SWuWZdRGyp"}]}]}]}]}"#;
    assert_eq!(expected, json::to_string(&call).unwrap());

    let id = BytesJson(vec![0x10]);
    let timestamp = DateTime::from_utc(NaiveDateTime::from_timestamp(0, 0), Utc);
    let secret_hash: BytesJson = hex::decode("66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925").unwrap().into();
    let address: TezosAddress = "dn1Kutfh4ewtNxu9FcwDHfz7X4SWuWZdRGyp".parse().unwrap();
    let call = tezos_func!(&[Or::R, Or::L], id, timestamp, secret_hash, address);
    let expected = r#"{"prim":"Right","args":[{"prim":"Left","args":[{"prim":"Pair","args":[{"bytes":"10"},{"prim":"Pair","args":[{"string":"1970-01-01T00:00:00Z"},{"prim":"Pair","args":[{"bytes":"66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"},{"string":"dn1Kutfh4ewtNxu9FcwDHfz7X4SWuWZdRGyp"}]}]}]}]}]}"#;
    assert_eq!(expected, json::to_string(&call).unwrap());

    let call = tezos_func!(&[Or::L]);
    let expected = r#"{"prim":"Left","args":[{"prim":"Unit"}]}"#;
    assert_eq!(expected, json::to_string(&call).unwrap());
}

fn tezos_coin_for_test() -> TezosCoin {
    let conf = json!({
        "coin": "DUNETEST",
        "name": "dunetestnet",
        "ed25519_addr_prefix": [4, 177, 1],
        "protocol": {
          "platform": "TEZOS",
          "token_type": "TEZOS"
        },
        "mm2": 1
    });
    let req = json!({
        "method": "enable",
        "coin": "DUNETEST",
        "urls": [
            "https://testnet-node.dunscan.io"
        ],
        "mm2":1
    });
    let priv_key = hex::decode("0760b6189e10610d3800d75d14ffe2f0abb35f8bf612a9510b5598d978f83f7a").unwrap();
    let coin = block_on(tezos_coin_from_conf_and_request("DUNETEST", &conf, &req, &priv_key)).unwrap();
    coin
}

fn tezos_erc_coin_for_test() -> TezosCoin {
    let conf = json!({
        "coin": "DUNETESTERC",
        "name": "dunetesterc",
        "ed25519_addr_prefix": [4, 177, 1],
        "protocol": {
            "platform": "TEZOS",
            "token_type": "ERC20",
            "contract_address": "KT1Bzq2mPvZk6jdmSzvVySXrQhYrybPnnxyZ"
        },
        "mm2": 1
    });
    let req = json!({
        "method": "enable",
        "coin": "DUNETESTERC",
        "urls": [
            "https://testnet-node.dunscan.io"
        ],
        "mm2":1
    });
    let priv_key = hex::decode("0760b6189e10610d3800d75d14ffe2f0abb35f8bf612a9510b5598d978f83f7a").unwrap();
    let coin = block_on(tezos_coin_from_conf_and_request("DUNETEST", &conf, &req, &priv_key)).unwrap();
    coin
}

#[test]
fn send_swap_payment_tezos() {
    let coin = tezos_coin_for_test();
    log!((coin.my_address));
    let maker_pub = match &coin.key_pair {
        TezosKeyPair::ED25519(p) => p.public.as_bytes(),
        _ => unimplemented!(),
    };
    let current_block = coin.current_block().wait().unwrap();
    let tx = coin.send_taker_payment(
        &[0x30],
        0,
        maker_pub,
        &hex::decode("66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925").unwrap(),
        1.into(),
    ).wait().unwrap();

    let op_hash = OpHash::from_op_bytes(&tx.tx_hex());
    log!((op_hash));
    coin.wait_for_confirmations(
        &tx.tx_hex(),
        1,
        now_ms() + 2000,
        1,
        current_block
    ).wait().unwrap();
}

#[test]
fn send_swap_payment_tezos_erc() {
    let coin = tezos_erc_coin_for_test();
    let maker_pub = match &coin.key_pair {
        TezosKeyPair::ED25519(p) => p.public.as_bytes(),
        _ => unimplemented!(),
    };
    let tx = coin.send_taker_payment(
        &[0x13],
        0,
        maker_pub,
        &hex::decode("66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925").unwrap(),
        1.into(),
    ).wait().unwrap();

    let op_hash = OpHash::from_op_bytes(&tx.tx_hex());
    log!((op_hash));
}

#[test]
fn spend_swap_payment() {
    let coin = tezos_coin_for_test();
    let taker_pub = match &coin.key_pair {
        TezosKeyPair::ED25519(p) => p.public.as_bytes(),
        _ => unimplemented!(),
    };
    let tx = coin.send_maker_spends_taker_payment(
        &[0x30],
        &[],
        0,
        taker_pub,
        &[0; 32],
    ).wait().unwrap();

    let op_hash = OpHash::from_op_bytes(&tx.tx_hex());
    log!((op_hash));
}

fn forge_op_req_to_bytes(req: ForgeOperationsRequest) -> Vec<u8> {
    let mut bytes = vec![];
    let branch = TezosBlockHash::from_str(&req.branch).unwrap();
    bytes.extend_from_slice(&*branch.hash);
    bytes.push(8);
    let source = TezosAddress::from_str(&req.contents[0].source).unwrap();
    bytes.push(0);
    bytes.push(0);
    bytes.extend_from_slice(&*source.hash);
    bytes.extend_from_slice(&big_uint_to_zarith_bytes(req.contents[0].fee.clone()));
    bytes.extend_from_slice(&big_uint_to_zarith_bytes(req.contents[0].counter.clone()));
    bytes.extend_from_slice(&big_uint_to_zarith_bytes(req.contents[0].gas_limit.clone()));
    bytes.extend_from_slice(&big_uint_to_zarith_bytes(req.contents[0].storage_limit.clone()));
    bytes.extend_from_slice(&big_uint_to_zarith_bytes(req.contents[0].amount.clone()));
    bytes.push(1);
    let destination = TezosAddress::from_str(&req.contents[0].destination).unwrap();
    bytes.extend_from_slice(&*destination.hash);
    bytes.push(0);
    match &req.contents[0].parameters {
        Some(value) => {
            bytes.push(255);
            let serialized = serialize(value).take();
            bytes.extend_from_slice(&(serialized.len() as u32 + 1).to_be_bytes());
            bytes.push(0);
            bytes.extend_from_slice(&serialized);
        },
        None => bytes.push(0),
    }
    bytes
}

#[test]
fn forge_req_to_bytes_tezos_transfer() {
    let req_str = r#"{"branch":"BLc29pAgdyGbfGL1J1b3jDUmiBw2xSLhNzw5mYhnDLY9SApQ1Eh","contents":[{"amount":"1000000","counter":"604","destination":"dn1c5mt3XTbLo5mKBpaTqidP6bSzUVD9T5By","fee":"1420","gas_limit":"10600","kind":"transaction","source":"dn1Kutfh4ewtNxu9FcwDHfz7X4SWuWZdRGyp","storage_limit":"300"}]}"#;
    let req: ForgeOperationsRequest = unwrap!(json::from_str(req_str));
    assert_eq!(req_str, unwrap!(json::to_string(&req)));
    let source = TezosAddress::from_str(&req.contents[0].source).unwrap();
    log!("source " (hex::encode(&*source.hash)));
    let destination = TezosAddress::from_str(&req.contents[0].destination).unwrap();
    log!("destination " (hex::encode(&*destination.hash)));

    let bytes = [117, 122, 92, 120, 117, 24, 110, 37, 70, 231, 68, 150, 245, 171, 132, 141, 207, 8, 207, 13, 239, 225, 226, 30, 28, 135, 75, 61, 27, 109, 57, 108, 8, 0, 0, 41, 105, 115, 114, 48, 189, 94, 166, 15, 99, 43, 82, 119, 121, 129, 228, 58, 37, 208, 105, 140, 11, 220, 4, 232, 82, 172, 2, 192, 132, 61, 0, 0, 218, 201, 245, 37, 67, 218, 26, 237, 11, 193, 214, 180, 107, 247, 193, 13, 183, 1, 76, 214, 0].to_vec();
    log!((hex::encode(&bytes)));

    let actual = forge_op_req_to_bytes(req);
    assert_eq!(bytes, actual);

    let byte1 = 0x0fu8;
    let byte2 = 1u8 << 7;
    log!((byte2));
    println!("{:b}", 0xc0);
    println!("{:b}", 0x84);
    println!("{:b}", 0x3d);
    println!("0xf801 {:b}", 0xf801);
    println!("0x8084af5f {:b}", 0x8084af5fu32);
    println!("100000000 {:b}", 100000000u32);
    println!("120 {:b}", 120u8);
    println!("{}", 0xc0u8);
    println!("{}", 0xc0u8 ^ byte2);
    println!("{}", 0x84u8 ^ byte2);

    assert_eq!(BigUint::from(1000000u64), big_uint_from_zarith_hex("c0843d"));
    assert_eq!(BigUint::from(2000000u64), big_uint_from_zarith_hex("80897a"));
    assert_eq!(BigUint::from(1420u64), big_uint_from_zarith_hex("8c0b"));
    // assert_eq!(BigUint::from(100000000u64), big_uint_from_zarith_hex("8084af5f"));
    assert_eq!("c0843d", big_uint_to_zarith_hex(BigUint::from(1000000u64)));
    assert_eq!("80897a", big_uint_to_zarith_hex(BigUint::from(2000000u64)));
    assert_eq!("8c0b", big_uint_to_zarith_hex(BigUint::from(1420u64)));
    assert_eq!("7f", big_uint_to_zarith_hex(BigUint::from(127u64)));
    assert_eq!("8001", big_uint_to_zarith_hex(BigUint::from(128u64)));
    assert_eq!("8101", big_uint_to_zarith_hex(BigUint::from(129u64)));

    assert_eq!(BigInt::from(8192), big_int_from_zarith_hex("808001"));
    assert_eq!(BigInt::from(-8192), big_int_from_zarith_hex("c08001"));
    assert_eq!(BigInt::from(-1000000000i64), big_int_from_zarith_hex("c0a8d6b907"));
    assert_eq!(BigInt::from(1000000000i64), big_int_from_zarith_hex("80a8d6b907"));

    assert_eq!("808001", big_int_to_zarith_hex(BigInt::from(8192)));
    assert_eq!("c08001", big_int_to_zarith_hex(BigInt::from(-8192)));
    assert_eq!("c0a8d6b907", big_int_to_zarith_hex(BigInt::from(-1000000000i64)));
    assert_eq!("80a8d6b907", big_int_to_zarith_hex(BigInt::from(1000000000i64)));
}

#[test]
fn forge_req_to_bytes_erc_transfer() {
    let req_str = r#"{"branch":"BM7RE1ewrJhdBNLDh3Jtb6BSp1VbQapE9narho8VXTwuzE6erep","contents":[{"amount":"0","counter":"604","destination":"KT1SafU2UYYQEDchguKra2ya9AKpaEgY2KLx","fee":"100000","gas_limit":"800000","kind":"transaction","parameters":{"prim":"Left","args":[{"prim":"Pair","args":[{"string":"dn1c5mt3XTbLo5mKBpaTqidP6bSzUVD9T5By"},{"int":"1"}]}]},"source":"dn1Kutfh4ewtNxu9FcwDHfz7X4SWuWZdRGyp","storage_limit":"60000"}]}"#;
    let req: ForgeOperationsRequest = unwrap!(json::from_str(req_str));
    assert_eq!(req_str, unwrap!(json::to_string(&req)));
    let source = TezosAddress::from_str(&req.contents[0].source).unwrap();
    log!("source " (hex::encode(&*source.hash)));
    let destination = TezosAddress::from_str(&req.contents[0].destination).unwrap();
    log!("destination " (hex::encode(&*destination.hash)));

    let bytes = [184, 58, 177, 178, 101, 40, 98, 181, 99, 108, 195, 108, 52, 208, 103, 161, 242, 34, 85, 116, 209, 239, 243, 54, 135, 13, 4, 55, 156, 93, 95, 219, 8, 0, 0, 41, 105, 115, 114, 48, 189, 94, 166, 15, 99, 43, 82, 119, 121, 129, 228, 58, 37, 208, 105, 160, 141, 6, 220, 4, 128, 234, 48, 224, 212, 3, 0, 1, 197, 109, 44, 71, 28, 89, 170, 152, 64, 15, 164, 37, 107, 217, 76, 199, 33, 126, 196, 170, 0, 255, 0, 0, 0, 48, 0, 5, 5, 7, 7, 1, 0, 0, 0, 36, 100, 110, 49, 99, 53, 109, 116, 51, 88, 84, 98, 76, 111, 53, 109, 75, 66, 112, 97, 84, 113, 105, 100, 80, 54, 98, 83, 122, 85, 86, 68, 57, 84, 53, 66, 121, 0, 1].to_vec();
    log!((hex::encode(&bytes)));

    let actual = forge_op_req_to_bytes(req);
    assert_eq!(bytes, actual);

    let req_str = r#"{"branch":"BKuQLz7JwinB1rZoEwdqQD4mu9nwtLmbjxyd5MB8ARmCA6TR6pA","contents":[{"kind":"transaction","source":"dn1Kutfh4ewtNxu9FcwDHfz7X4SWuWZdRGyp","fee":"0100000","counter":"604","gas_limit":"800000","storage_limit":"60000","amount":"0000000","destination":"KT1SafU2UYYQEDchguKra2ya9AKpaEgY2KLx","parameters":{"prim":"Right","args":[{"prim":"Right","args":[{"prim":"Right","args":[{"prim":"Left","args":[{"prim":"Pair","args":[{"string":"dn1Kutfh4ewtNxu9FcwDHfz7X4SWuWZdRGyp"},{"int":"0"}]}]}]}]}]}}]}"#;
    let req: ForgeOperationsRequest = unwrap!(json::from_str(req_str));

    let expected_bytes = unwrap!(hex::decode("194053273d19ec275875e7df74c8ca15b8dc8afec855ece1830b0c2b9a8e0a6b0800002969737230bd5ea60f632b52777981e43a25d069a08d06dc0480ea30e0d4030001c56d2c471c59aa98400fa4256bd94cc7217ec4aa00ff0000003600050805080508050507070100000024646e314b75746668346577744e7875394663774448667a375834535775575a64524779700000"));
    let actual_bytes = forge_op_req_to_bytes(req);
    assert_eq!(expected_bytes, actual_bytes);
}

fn big_uint_from_zarith_hex(hex: &str) -> BigUint {
    let bytes = hex::decode(hex).unwrap();
    let mut res = BigUint::from(0u8);
    for (i, mut byte) in bytes.into_iter().enumerate() {
        if byte & 1u8 << 7 != 0 {
            byte ^= 1u8 << 7;
        }
        res += byte * BigUint::from(128u8).pow(i as u32);
    }
    res
}

fn big_int_from_zarith_hex(hex: &str) -> BigInt {
    let bytes = hex::decode(hex).unwrap();
    let mut res = BigInt::from(0u8);
    let mut sign = BigInt::from(1);
    for (i, mut byte) in bytes.into_iter().enumerate() {
        if byte & 1u8 << 7 != 0 {
            byte ^= 1u8 << 7;
        }
        if i == 0 && byte & 1u8 << 6 != 0 {
            sign = -sign;
            byte ^= 1u8 << 6;
        }

        res += byte * BigInt::from(128u8).pow(i as u32);
    }
    sign * (res >> 1)
}

fn big_uint_to_zarith_bytes(mut num: BigUint) -> Vec<u8> {
    let mut bytes = vec![];
    loop {
        let remainder = &num % 128u8;
        num = num / 128u8;
        if num == BigUint::from(0u32) {
            bytes.push(unwrap!(remainder.to_u8()));
            break;
        } else {
            bytes.push(unwrap!(remainder.to_u8()) ^ 1u8 << 7);
        }
    }
    bytes
}

fn big_uint_to_zarith_hex(num: BigUint) -> String {
    hex::encode(&big_uint_to_zarith_bytes(num))
}

fn big_int_to_zarith_bytes(mut num: BigInt) -> Vec<u8> {
    let mut bytes = vec![];
    let mut divisor = 64u8;
    let zero = BigInt::from(0);
    let sign = if num < zero {
        num = -num;
        1u8
    } else {
        0u8
    };

    loop {
        let mut remainder = unwrap!((&num % divisor).to_u8());
        num = num / divisor;
        if divisor == 64 {
            remainder ^= (sign << 6);
        }
        if num == zero {
            bytes.push(remainder);
            break;
        } else {
            bytes.push(remainder ^ (1u8 << 7));
        }
        divisor = 128;
    }
    bytes
}

#[derive(Clone, Debug, PartialEq)]
enum CurveType {
    ED25519,
    SECP256K1,
    P256,
}

/// http://tezos.gitlab.io/api/p2p.html#public-key-hash-21-bytes-8-bit-tag
#[derive(Clone, Debug, PartialEq)]
struct PubkeyHash {
    curve_type: CurveType,
    hash: H160,
}

/// http://tezos.gitlab.io/api/p2p.html#contract-id-22-bytes-8-bit-tag
#[derive(Clone, Debug, PartialEq)]
enum ContractId {
    PubkeyHash(PubkeyHash),
    Originated(H160),
}

impl Serializable for ContractId {
    fn serialize(&self, s: &mut Stream) {
        match self {
            ContractId::PubkeyHash(hash) => {
                s.append(&0u8);
                match hash.curve_type {
                    CurveType::ED25519 => s.append(&0u8),
                    CurveType::SECP256K1 => s.append(&1u8),
                    CurveType::P256 => s.append(&2u8),
                };
                s.append(&hash.hash);
            },
            ContractId::Originated(hash) => {
                s.append(&1u8);
                s.append(hash);
                s.append(&0u8);
            },
        }
    }
}

impl Deserializable for ContractId {
    fn deserialize<T>(reader: &mut Reader<T>) -> Result<Self, serialization::Error>
        where Self: Sized, T: std::io::Read
    {
        let tag: u8 = reader.read()?;
        match tag {
            0 => {
                let curve_tag: u8 = reader.read()?;
                let curve_type = match curve_tag {
                    0 => CurveType::ED25519,
                    1 => CurveType::SECP256K1,
                    2 => CurveType::P256,
                    _ => return Err(serialization::Error::MalformedData),
                };
                Ok(ContractId::PubkeyHash(PubkeyHash {
                    curve_type,
                    hash: reader.read()?,
                }))
            },
            1 => {
                let hash = reader.read()?;
                let padding: u8 = reader.read()?;
                Ok(ContractId::Originated(hash))
            },
            _ => Err(serialization::Error::MalformedData)
        }
    }
}

impl Deserializable for TezosValue {
    fn deserialize<T>(reader: &mut Reader<T>) -> Result<Self, serialization::Error>
        where Self: Sized, T: std::io::Read
    {
        let tag: u8 = reader.read()?;
        match tag {
            0 => {
                Ok(TezosValue::Int {
                    int: reader.read()?
                })
            },
            1 => {
                let length: H32 = reader.read()?;
                let length = u32::from_be_bytes(length.take());
                let mut bytes = vec![0; length as usize];
                reader.read_slice(&mut bytes)?;
                Ok(TezosValue::String {
                    string: String::from_utf8(bytes).map_err(|_| serialization::Error::MalformedData)?
                })
            },
            5 => {
                let sub_tag: u8 = reader.read()?;
                match sub_tag {
                    5 => Ok(TezosValue::TezosPrim(TezosPrim::Left([
                        Box::new(reader.read()?),
                    ]))),
                    8 => Ok(TezosValue::TezosPrim(TezosPrim::Right([
                        Box::new(reader.read()?),
                    ]))),
                    _ => unimplemented!(),
                }
            },
            7 => {
                let sub_tag: u8 = reader.read()?;
                match sub_tag {
                    7 => Ok(TezosValue::TezosPrim(TezosPrim::Pair((
                        Box::new(reader.read()?),
                        Box::new(reader.read()?),
                    )))),
                    _ => unimplemented!(),
                }
            },
            10 => {
                let length: H32 = reader.read()?;
                let length = u32::from_be_bytes(length.take());
                let mut bytes = vec![0; length as usize];
                reader.read_slice(&mut bytes)?;
                Ok(TezosValue::Bytes {
                    bytes: bytes.into()
                })
            },
            _ => unimplemented!(),
        }
    }
}

#[derive(Add, Clone, Debug, Deref, Display, PartialEq)]
pub struct TezosInt(pub BigInt);

impl Deserializable for TezosInt {
    fn deserialize<T>(reader: &mut Reader<T>) -> Result<Self, serialization::Error>
        where Self: Sized, T: std::io::Read
    {
        let mut res = BigInt::from(0u8);
        let mut sign = BigInt::from(1);
        let mut i = 0u32;
        let mut stop = false;
        loop {
            let mut byte: u8 = reader.read()?;
            if i == 0 && byte & 1u8 << 6 != 0 {
                sign = -sign;
                byte ^= 1u8 << 6;
            }

            if byte & 1u8 << 7 != 0 {
                byte ^= 1u8 << 7;
            } else {
                stop = true
            }
            res += byte * BigInt::from(128u8).pow(i);
            if stop { break; }
            i += 1;
        }

        if i > 0 {
            res = res >> 1;
        }
        Ok(TezosInt::from(sign * res))
    }
}

impl Serializable for TezosInt {
    fn serialize(&self, s: &mut Stream) {
        let bytes = big_int_to_zarith_bytes(self.0.clone());
        s.append_slice(&bytes);
    }
}

/// http://tezos.gitlab.io/api/p2p.html#transaction-tag-108
#[derive(Clone, Debug, PartialEq)]
pub struct TezosTransaction {
    source: ContractId,
    fee: TezosUint,
    counter: TezosUint,
    gas_limit: TezosUint,
    storage_limit: TezosUint,
    amount: TezosUint,
    destination: ContractId,
    parameters: Option<TezosValue>,
}

fn read_parameters<T>(reader: &mut Reader<T>) -> Result<Option<TezosValue>, serialization::Error>
    where T: std::io::Read {
    let has_parameters: u8 = reader.read()?;
    match has_parameters {
        0 => Ok(None),
        255 => {
            let len: H32 = reader.read()?;
            let len = u32::from_be_bytes(len.take()) as usize;
            let mut bytes = vec![0; len];
            reader.read_slice(&mut bytes)?;
            deserialize(&bytes[1..]).map(|res| Some(res))
        },
        _ => Err(serialization::Error::MalformedData),
    }
}

impl Deserializable for TezosTransaction {
    fn deserialize<T>(reader: &mut Reader<T>) -> Result<Self, serialization::Error>
        where Self: Sized, T: std::io::Read
    {
        Ok(TezosTransaction {
            source: reader.read()?,
            fee: reader.read()?,
            counter: reader.read()?,
            gas_limit: reader.read()?,
            storage_limit: reader.read()?,
            amount: reader.read()?,
            destination: reader.read()?,
            parameters: read_parameters(reader)?,
        })
    }
}

impl Serializable for TezosTransaction {
    fn serialize(&self, s: &mut Stream) {
        s.append(&self.source);
        s.append(&self.fee);
        s.append(&self.counter);
        s.append(&self.gas_limit);
        s.append(&self.storage_limit);
        s.append(&self.amount);
        s.append(&self.destination);
        match &self.parameters {
            Some(params) => {
                s.append(&255u8);
                let bytes = serialize(params).take();
                let len = bytes.len() as u32 + 1;
                s.append_slice(&len.to_be_bytes());
                s.append(&0u8);
                s.append_slice(&bytes);
            },
            None => {
                s.append(&0u8);
            },
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum TezosOperationEnum {
    Transaction(TezosTransaction)
}

#[derive(Clone, Debug, PartialEq)]
pub struct TezosOperation {
    branch: H256,
    op: TezosOperationEnum,
    signature: Option<H512>,
}

impl Deserializable for TezosOperation {
    fn deserialize<T>(reader: &mut Reader<T>) -> Result<Self, serialization::Error>
        where Self: Sized, T: std::io::Read
    {
        let branch = reader.read()?;
        let tag: u8 = reader.read()?;
        let op = match tag {
            8 => {
                TezosOperationEnum::Transaction(reader.read()?)
            },
            _ => unimplemented!(),
        };
        let signature = if reader.is_finished() {
            None
        } else {
            Some(reader.read()?)
        };
        Ok(TezosOperation {
            branch,
            op,
            signature
        })
    }
}

impl Serializable for TezosOperation {
    fn serialize(&self, s: &mut Stream) {
        s.append(&self.branch);
        match &self.op {
            TezosOperationEnum::Transaction(tx) => {
                s.append(&8u8);
                s.append(tx);
            }
        }
        if let Some(sig) = &self.signature {
            s.append(sig);
        }
    }
}

#[derive(Add, Clone, Debug, Deref, Display, PartialEq)]
pub struct TezosUint(pub BigUint);

impl Deserializable for TezosUint {
    fn deserialize<T>(reader: &mut Reader<T>) -> Result<Self, serialization::Error>
        where Self: Sized, T: std::io::Read
    {
        let mut res = BigUint::from(0u8);
        let mut stop = false;
        let mut i = 0u32;
        loop {
            let mut byte: u8 = reader.read()?;
            if byte & 1u8 << 7 != 0 {
                byte ^= 1u8 << 7;
            } else {
                stop = true
            }
            res += byte * BigUint::from(128u8).pow(i);
            if stop { break; }
            i += 1;
        }
        Ok(TezosUint::from(res))
    }
}

impl Serializable for TezosUint {
    fn serialize(&self, s: &mut Stream) {
        let bytes = big_uint_to_zarith_bytes(self.0.clone());
        s.append_slice(&bytes);
    }
}

impl From<BigInt> for TezosInt {
    fn from(n: BigInt) -> TezosInt {
        TezosInt(n)
    }
}

impl From<BigUint> for TezosUint {
    fn from(n: BigUint) -> TezosUint {
        TezosUint(n)
    }
}

fn big_int_to_zarith_hex(num: BigInt) -> String {
    hex::encode(&big_int_to_zarith_bytes(num))
}

#[test]
fn test_tezos_rpc_value_binary_serialization() {
    let expected_bytes = unwrap!(hex::decode("0100000024646e314b75746668346577744e7875394663774448667a375834535775575a6452477970"));
    let value = TezosValue::String {
        string: "dn1Kutfh4ewtNxu9FcwDHfz7X4SWuWZdRGyp".into()
    };
    let serialized = serialize(&value).take();
    assert_eq!(expected_bytes, serialized);
    let deserialized = unwrap!(deserialize(serialized.as_slice()));
    assert_eq!(value, deserialized);

    let expected_bytes = unwrap!(hex::decode("0080a8d6b907"));
    let value = TezosValue::Int {
        int: BigInt::from(1000000000i64).into()
    };
    let serialized = serialize(&value).take();
    assert_eq!(expected_bytes, serialized);
    let deserialized = unwrap!(deserialize(serialized.as_slice()));
    assert_eq!(value, deserialized);

    let expected_bytes = unwrap!(hex::decode("07070100000024646e314b75746668346577744e7875394663774448667a375834535775575a64524779700080a8d6b907"));
    let value = TezosValue::TezosPrim(TezosPrim::Pair ((
        Box::new(TezosValue::String {
            string: "dn1Kutfh4ewtNxu9FcwDHfz7X4SWuWZdRGyp".into()
        }),
        Box::new(TezosValue::Int {
            int: BigInt::from(1000000000i64).into()
        }),
    )));
    let serialized = serialize(&value).take();
    assert_eq!(expected_bytes, serialized);
    let deserialized = unwrap!(deserialize(serialized.as_slice()));
    assert_eq!(value, deserialized);

    let expected_bytes = unwrap!(hex::decode("050507070100000024646e314b75746668346577744e7875394663774448667a375834535775575a64524779700080a8d6b907"));
    let value = TezosValue::TezosPrim(TezosPrim::Left([
        Box::new(value)
    ]));
    let serialized = serialize(&value).take();
    assert_eq!(expected_bytes, serialized);
    let deserialized = unwrap!(deserialize(serialized.as_slice()));
    assert_eq!(value, deserialized);

    let expected_bytes = unwrap!(hex::decode("0508050507070100000024646e314b75746668346577744e7875394663774448667a375834535775575a64524779700080a8d6b907"));
    let value = TezosValue::TezosPrim(TezosPrim::Right([
        Box::new(value)
    ]));
    let serialized = serialize(&value).take();
    assert_eq!(expected_bytes, serialized);
    let deserialized = unwrap!(deserialize(serialized.as_slice()));
    assert_eq!(value, deserialized);
}

#[test]
fn test_operation_serde() {
    let tx_hex = "ef48deeeae27573e2c77f3c5c011af40437ffebde394f343a1545e82d39f854d0800002969737230bd5ea60f632b52777981e43a25d069a08d06e00480ea30e0d403c0843d01192109476f194a603982c1cfc028b5fad65b789100ff0000007600050507070a000000012507070100000014313937302d30312d30315430303a30303a30305a07070a0000002066687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f29250100000024646e314b75746668346577744e7875394663774448667a375834535775575a6452477970d110ea0d70706147276244fc231f71d4452e4dde51647595d984aa49ce95aee2928aa521bd4a316ee29b2cc62d56e8c8a750208062abf0d19077c637310ec201";
    let tx_bytes = hex::decode(tx_hex).unwrap();
    let op: TezosOperation = unwrap!(deserialize(tx_bytes.as_slice()));
    let serialized = serialize(&op).take();
    assert_eq!(tx_bytes, serialized);

    let tx_hex = "4ea793fe179be186e7cad783eb797d5ef00e4e91b840d856172dc3ee51ddafe90800002969737230bd5ea60f632b52777981e43a25d069a08d06ee0480ea30e0d40300011a8f7a22dd852d1c8542d795eae3b094a7c629aa00ff000000a7000508050507070a000000011307070100000014313937302d30312d30315430303a30303a30305a07070a0000002066687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f292507070100000024646e314b75746668346577744e7875394663774448667a375834535775575a64524779700707000101000000244b5431427a71326d50765a6b366a646d537a765679535872516859727962506e6e78795a079655d5c2b8c864945c698dc49de289ebc041f14eff57436cbd6beed52b455c80983e94352f080fa209177bd4f347fd026b891b122fdc9bd7f47c974780e303";
    let tx_bytes = hex::decode(tx_hex).unwrap();
    let op: TezosOperation = unwrap!(deserialize(tx_bytes.as_slice()));
    log!([op]);
    let serialized = serialize(&op).take();
    log!((hex::encode(&serialized)));
    let tx_hex = "4ea793fe179be186e7cad783eb797d5ef00e4e91b840d856172dc3ee51ddafe90800002969737230bd5ea60f632b52777981e43a25d069a08d06ee0480ea30e0d40300011a8f7a22dd852d1c8542d795eae3b094a7c629aa00ff000000a7000508050507070a000000011307070100000014313937302d30312d30315430303a30303a30305a07070a0000002066687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f292507070100000024646e314b75746668346577744e7875394663774448667a375834535775575a64524779700707000001000000244b5431427a71326d50765a6b366a646d537a765679535872516859727962506e6e78795a079655d5c2b8c864945c698dc49de289ebc041f14eff57436cbd6beed52b455c80983e94352f080fa209177bd4f347fd026b891b122fdc9bd7f47c974780e303";
    assert_eq!(tx_bytes, serialized);
}

enum TezosAtomicSwapState {
    Initialized,
    ReceiverSpent,
    SenderRefunded,
}

impl TryFrom<TezosValue> for TezosAtomicSwapState {
    type Error = String;

    fn try_from(value: TezosValue) -> Result<Self, Self::Error> {
        match value {
            TezosValue::TezosPrim(TezosPrim::Left(_)) => Ok(TezosAtomicSwapState::Initialized),
            TezosValue::TezosPrim(TezosPrim::Right(value)) => match *value[0] {
                TezosValue::TezosPrim(TezosPrim::Left(_)) => Ok(TezosAtomicSwapState::ReceiverSpent),
                TezosValue::TezosPrim(TezosPrim::Right(_)) => Ok(TezosAtomicSwapState::SenderRefunded),
                _ => ERR!("TezosAtomicSwapState can be constructed only from TezosPrim::Left or TezosPrim::Right, got {:?}", value),
            },
            _ => ERR!("TezosAtomicSwapState can be constructed only from TezosPrim::Left or TezosPrim::Right, got {:?}", value),
        }
    }
}

struct TezosAtomicSwap {
    amount: BigUint,
    amount_nat: BigUint,
    contract_address: TezosOption<ContractId>,
    lock_time: BigUint,
    receiver: ContractId,
    secret_hash: BytesJson,
    sender: ContractId,
    state: TezosAtomicSwapState,
    uuid: BytesJson,
    spent_at: TezosOption<BigUint>,
}

impl TryFrom<TezosValue> for TezosAtomicSwap {
    type Error = String;

    fn try_from(value: TezosValue) -> Result<Self, Self::Error> {
        let mut reader = TezosValueReader {
            inner: Some(value),
        };

        Ok(TezosAtomicSwap {
            amount: try_s!(reader.read().unwrap().try_into()),
            amount_nat: try_s!(reader.read().unwrap().try_into()),
            contract_address: try_s!(reader.read().unwrap().try_into()),
            lock_time: try_s!(reader.read().unwrap().try_into()),
            receiver: try_s!(reader.read().unwrap().try_into()),
            secret_hash: try_s!(reader.read().unwrap().try_into()),
            sender: try_s!(reader.read().unwrap().try_into()),
            state: try_s!(reader.read().unwrap().try_into()),
            uuid: try_s!(reader.read().unwrap().try_into()),
            spent_at: try_s!(reader.read().unwrap().try_into()),
        })
    }
}

impl TryFrom<TezosValue> for ContractId {
    type Error = String;

    fn try_from(value: TezosValue) -> Result<Self, Self::Error> {
        match value {
            TezosValue::Bytes { bytes } => Ok(try_s!(deserialize(bytes.0.as_slice()).map_err(|e| ERRL!("{:?}", e)))),
            _ => ERR!("ContractId can be constructed only from TezosValue::Bytes, got {:?}", value),
        }
    }
}

struct TezosOption<T>(Option<T>);

impl<T: TryFrom<TezosValue>> TryFrom<TezosValue> for TezosOption<T>
where T::Error: fmt::Display {
    type Error = String;

    fn try_from(value: TezosValue) -> Result<Self, Self::Error> {
        match value {
            TezosValue::TezosPrim(TezosPrim::None) => Ok(TezosOption(None)),
            TezosValue::TezosPrim(TezosPrim::Some(value)) => Ok(TezosOption(Some(try_s!(T::try_from((*value[0]).clone()))))),
            _ => ERR!("TezosOption can be constructed only from TezosPrim::None or TezosPrim::Some, got {:?}", value),
        }
    }
}

#[test]
fn test_tezos_atomic_swap_from_value() {
    let json_str = r#"{"prim":"Pair","args":[{"int":"1000000"},{"prim":"Pair","args":[{"int":"0"},{"prim":"Pair","args":[{"prim":"None"},{"prim":"Pair","args":[{"int":"0"},{"prim":"Pair","args":[{"bytes":"00002969737230bd5ea60f632b52777981e43a25d069"},{"prim":"Pair","args":[{"bytes":"66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"},{"prim":"Pair","args":[{"bytes":"00002969737230bd5ea60f632b52777981e43a25d069"},{"prim":"Pair","args":[{"prim":"Left","args":[{"prim":"Unit"}]},{"prim":"Pair","args":[{"bytes":"30"},{"prim":"None"}]}]}]}]}]}]}]}]}]}"#;
    let value: TezosValue = unwrap!(json::from_str(json_str));
    let swap = unwrap!(TezosAtomicSwap::try_from(value));

    let json_str = r#"{"prim":"Pair","args":[{"int":"1000000"},{"prim":"Pair","args":[{"int":"0"},{"prim":"Pair","args":[{"prim":"None"},{"prim":"Pair","args":[{"int":"0"},{"prim":"Pair","args":[{"bytes":"00002969737230bd5ea60f632b52777981e43a25d069"},{"prim":"Pair","args":[{"bytes":"66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925"},{"prim":"Pair","args":[{"bytes":"00002969737230bd5ea60f632b52777981e43a25d069"},{"prim":"Pair","args":[{"prim":"Right","args":[{"prim":"Left","args":[{"prim":"Unit"}]}]},{"prim":"Pair","args":[{"bytes":"30"},{"prim":"Some","args":[{"int":"1574016141"}]}]}]}]}]}]}]}]}]}]}"#;
    let value: TezosValue = unwrap!(json::from_str(json_str));
    let swap = unwrap!(TezosAtomicSwap::try_from(value));
}

#[test]
fn tezos_int_binary_serde() {
    let bytes = vec![1];
    let num: TezosInt = unwrap!(deserialize(bytes.as_slice()));
    assert_eq!(num.0, BigInt::from(1));
}
