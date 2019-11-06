use base58::{FromBase58, FromBase58Error, ToBase58};
use bigdecimal::BigDecimal;
use bitcrypto::{sha256, dhash256};
use blake2::{VarBlake2b, Blake2b};
use blake2::digest::{Input, VariableOutput};
use chrono::prelude::*;
use common::mm_ctx::MmArc;
use common::mm_number::MmNumber;
use crate::{TradeInfo, FoundSwapTxSpend, WithdrawRequest};
use ed25519_dalek::{Keypair as EdKeypair, SecretKey as EdSecretKey, Signature as EdSignature, SignatureError,
                    PublicKey as EdPublicKey};
use futures::TryFutureExt;
use futures01::Future;
use num_bigint::{BigInt, BigUint, ToBigInt};
use primitives::hash::{H160, H256};
use rpc::v1::types::{Bytes as BytesJson};
use serde_json::{self as json, Value as Json};
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
use common::{slurp_url, block_on};

mod tezos_rpc;
use self::tezos_rpc::{BigMapReq, ForgeOperationsRequest, Operation, PreapplyOperation,
                      PreapplyOperationsRequest, TezosInputType, TezosRpcClient};
use crate::MmCoinEnum::Tezos;
use crate::tezos::tezos_rpc::TezosRpcClientImpl;

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
    fn for_op_bytes(bytes: &[u8]) -> Self {
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
                        key: TezosRpcValue::String {
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
    ) -> Box<dyn Future<Item=(), Error=String> + Send> {
        unimplemented!()
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
                let amount = amount * BigDecimal::from(10u64.pow(self.decimals as u32));
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
                (0.into(), args)
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
            sign_and_send_operation(coin, 0.into(), &dest, Some(args)).await
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

#[derive(Clone, Debug, PartialEq)]
pub struct TezosTransaction(Vec<u8>);

impl Transaction for TezosTransaction {
    fn tx_hex(&self) -> Vec<u8> {
        self.0.clone()
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
    amount: BigDecimal,
    destination: &TezosAddress,
    parameters: Option<TezosRpcValue>
) -> Result<TezosTransaction, String> {
    let counter = try_s!(coin.rpc_client.counter(&coin.my_address()).await) + BigDecimal::from(1);
    let head = try_s!(coin.rpc_client.block_header("head").await);
    let op = Operation {
        amount,
        counter,
        destination: destination.to_string(),
        fee: 0100000.into(),
        gas_limit: 800000.into(),
        kind: "transaction".into(),
        parameters,
        source: coin.my_address().into(),
        storage_limit: 60000.into(),
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
    Ok(TezosTransaction(prefixed))
}

async fn withdraw_impl(coin: TezosCoin, req: WithdrawRequest) -> Result<TransactionDetails, String> {
    let to_addr: TezosAddress = try_s!(req.to.parse());
    let counter = try_s!(coin.rpc_client.counter(&coin.my_address()).await) + BigDecimal::from(1);
    let head = try_s!(coin.rpc_client.block_header("head").await);
    let op = match &coin.coin_type {
        TezosCoinType::Tezos => Operation {
            amount: &req.amount * BigDecimal::from(10u64.pow(coin.decimals as u32)),
            counter,
            destination: req.to.clone(),
            fee: 1420.into(),
            gas_limit: 10600.into(),
            kind: "transaction".into(),
            parameters: None,
            source: coin.my_address().into(),
            storage_limit: 300.into(),
        },
        TezosCoinType::ERC(addr) => {
            let amount: BigUint = (&req.amount * BigDecimal::from(10u64.pow(coin.decimals as u32))).to_bigint().unwrap().to_biguint().unwrap();
            let parameters = Some(erc_transfer_call(&to_addr, &amount));
            Operation {
                amount: 0.into(),
                counter,
                destination: addr.to_string(),
                fee: 0100000.into(),
                gas_limit: 800000.into(),
                kind: "transaction".into(),
                parameters,
                source: coin.my_address().into(),
                storage_limit: 60000.into(),
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
    let op_hash = OpHash::for_op_bytes(&prefixed);
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
        swap_contract_address: "KT1SrjTJMRwZEzy7kReBV9ZDktRopu5Ebdgu".parse().unwrap(),
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

impl TryFrom<TezosRpcValue> for BigUint {
    type Error = String;

    fn try_from(value: TezosRpcValue) -> Result<Self, Self::Error> {
        match value {
            TezosRpcValue::Int { int } => Ok(try_s!(int.parse())),
            _ => ERR!("BigUint can be constructed only from TezosRpcValue::Int, got {:?}", value),
        }
    }
}

impl TryFrom<TezosRpcValue> for u8 {
    type Error = String;

    fn try_from(value: TezosRpcValue) -> Result<Self, Self::Error> {
        match value {
            TezosRpcValue::Int { int } => Ok(try_s!(int.parse())),
            _ => ERR!("u8 can be constructed only from TezosRpcValue::Int, got {:?}", value),
        }
    }
}

impl TryFrom<TezosRpcValue> for u64 {
    type Error = String;

    fn try_from(value: TezosRpcValue) -> Result<Self, Self::Error> {
        match value {
            TezosRpcValue::Int { int } => Ok(try_s!(int.parse())),
            _ => ERR!("u64 can be constructed only from TezosRpcValue::Int, got {:?}", value),
        }
    }
}

impl TryFrom<TezosRpcValue> for String {
    type Error = String;

    fn try_from(value: TezosRpcValue) -> Result<Self, Self::Error> {
        match value {
            TezosRpcValue::String { string } => Ok(string),
            _ => ERR!("String can be constructed only from TezosRpcValue::String, got {:?}", value),
        }
    }
}

macro_rules! impl_try_from_tezos_rpc_value_for_hash_map {
    ($key_type: ident, $value_type: ident) => {
        impl TryFrom<TezosRpcValue> for HashMap<$key_type, $value_type> {
            type Error = String;

            fn try_from(value: TezosRpcValue) -> Result<Self, Self::Error> {
                match value {
                    TezosRpcValue::List (elems) => {
                        let mut res = HashMap::new();
                        for elem in elems {
                            match elem {
                                TezosRpcValue::TezosPrim(TezosPrim::Elt((key, value))) => {
                                    res.insert(try_s!((*key).try_into()), try_s!((*value).try_into()));
                                },
                                _ => return ERR!("Unexpected item {:?} in list, must be TezosPrim::Elt", elem),
                            }
                        }
                        Ok(res)
                    },
                    _ => ERR!("HashMap can be constructed only from TezosRpcValue::List, got {:?}", value),
                }
            }
        }
    };
}

impl_try_from_tezos_rpc_value_for_hash_map!(BytesJson, TezosErcAccount);
impl_try_from_tezos_rpc_value_for_hash_map!(BytesJson, BigUint);

impl TryFrom<TezosRpcValue> for TezosErcAccount {
    type Error = String;

    fn try_from(value: TezosRpcValue) -> Result<Self, Self::Error> {
        let mut reader = TezosRpcValueReader {
            inner: Some(value),
        };

        Ok(TezosErcAccount {
            balance: try_s!(reader.read().unwrap().try_into()),
            allowances: try_s!(reader.read().unwrap().try_into()),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "prim", content = "args")]
pub enum TezosPrim {
    Pair ((Box<TezosRpcValue>, Box<TezosRpcValue>)),
    Elt ((Box<TezosRpcValue>, Box<TezosRpcValue>)),
    Right ([Box<TezosRpcValue>; 1]),
    Left ([Box<TezosRpcValue>; 1]),
    Unit,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum TezosRpcValue {
    Bytes { bytes: BytesJson },
    Int { int: String },
    List (Vec<TezosRpcValue>),
    TezosPrim (TezosPrim),
    String { string: String },
}

impl TezosRpcValue {
    fn split_and_read_value(self) -> (TezosRpcValue, Option<TezosRpcValue>) {
        match self {
            TezosRpcValue::TezosPrim(TezosPrim::Pair((left, right))) => (*left, Some(*right)),
            _ => (self, None),
        }
    }
}

struct TezosRpcValueReader {
    inner: Option<TezosRpcValue>,
}

impl TezosRpcValueReader {
    fn read(&mut self) -> Result<TezosRpcValue, String> {
        let val = self.inner.take();
        let (res, next) = val.unwrap().split_and_read_value();
        self.inner = next;
        Ok(res)
    }
}

impl TryFrom<TezosRpcValue> for TezosErcStorage {
    type Error = String;

    fn try_from(value: TezosRpcValue) -> Result<Self, Self::Error> {
        let mut reader = TezosRpcValueReader {
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

impl TryFrom<TezosRpcValue> for BytesJson {
    type Error = String;

    fn try_from(value: TezosRpcValue) -> Result<Self, Self::Error> {
        match value {
            TezosRpcValue::Bytes { bytes } => Ok(bytes),
            _ => ERR!("Bytes can be constructed only from TezosRpcValue::Bytes, got {:?}", value),
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
    let pair: TezosRpcValue = json::from_str(&json).unwrap();
    log!([pair]);
    let storage = unwrap!(TezosErcStorage::try_from(pair));
    log!([storage]);
}

#[test]
fn deserialize_erc_account() {
    let json = r#"{"prim":"Pair","args":[{"int":"99984"},[{"prim":"Elt","args":[{"bytes":"01088e02012f75cdee43326dfdec205f7bfd30dd6c00"},{"int":"990"}]},{"prim":"Elt","args":[{"bytes":"0122bef431640e29dd4a01cf7cc5befac05f0b99b700"},{"int":"999"}]},{"prim":"Elt","args":[{"bytes":"0152f0ecfb244e2b393b60263d8ae60ac13d08472900"},{"int":"999"}]},{"prim":"Elt","args":[{"bytes":"0153663d8ad9f9c6b28f94508599a255b6c2c5b0c900"},{"int":"999"}]},{"prim":"Elt","args":[{"bytes":"0153d475620cccc1cdb1fb2e1d20c2c713a729fc5100"},{"int":"1"}]},{"prim":"Elt","args":[{"bytes":"015eef25239095cfef6325bbbe7671821d0761936e00"},{"int":"999"}]},{"prim":"Elt","args":[{"bytes":"0164ba0f8a211f0584171b47e1c7d00686d80642d600"},{"int":"999"}]},{"prim":"Elt","args":[{"bytes":"0169ad9656ad447d6394c0dae64588f307f47ac37500"},{"int":"1000"}]},{"prim":"Elt","args":[{"bytes":"017d8c19f42235a54c7e932cf0120a9b869a141fad00"},{"int":"999"}]},{"prim":"Elt","args":[{"bytes":"01c90438d5b073d5d8bde6f2cd24957f911bd78beb00"},{"int":"998"}]},{"prim":"Elt","args":[{"bytes":"01d2fd4e3c7cb8a766462c02d388b530ce40192f5c00"},{"int":"999"}]},{"prim":"Elt","args":[{"bytes":"01fcf0818b6d79358258675f07451f8de76ff8626e00"},{"int":"999"}]}]]}"#;
    let rpc_value: TezosRpcValue = json::from_str(&json).unwrap();
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

impl Into<TezosRpcValue> for &str {
    fn into(self) -> TezosRpcValue {
        TezosRpcValue::String {
            string: self.into()
        }
    }
}

impl Into<TezosRpcValue> for &TezosAddress {
    fn into(self) -> TezosRpcValue {
        TezosRpcValue::String {
            string: self.to_string()
        }
    }
}

impl Into<TezosRpcValue> for &BigUint {
    fn into(self) -> TezosRpcValue {
        TezosRpcValue::Int {
            int: self.to_string()
        }
    }
}

impl Into<TezosRpcValue> for BigUint {
    fn into(self) -> TezosRpcValue {
        TezosRpcValue::Int {
            int: self.to_string()
        }
    }
}

impl Into<TezosRpcValue> for BytesJson {
    fn into(self) -> TezosRpcValue {
        TezosRpcValue::Bytes {
            bytes: self
        }
    }
}

impl Into<TezosRpcValue> for TezosAddress {
    fn into(self) -> TezosRpcValue {
        TezosRpcValue::String {
            string: self.to_string()
        }
    }
}

impl Into<TezosRpcValue> for DateTime<Utc> {
    fn into(self) -> TezosRpcValue {
        TezosRpcValue::String {
            string: self.to_rfc3339_opts(SecondsFormat::Secs, true)
        }
    }
}

macro_rules! tezos_func {
    ($func:expr $(, $arg_name:ident)*) => {{
        let mut params: Vec<TezosRpcValue> = vec![];
        $(
            params.push($arg_name.into());
        )*
        let args = match params.pop() {
            Some(a) => a,
            None => TezosRpcValue::TezosPrim(TezosPrim::Unit),
        };
        let args = params.into_iter().rev().fold(args, |arg, cur| TezosRpcValue::TezosPrim(TezosPrim::Pair((
            Box::new(cur),
            Box::new(arg)
        ))));
        construct_function_call($func, args)
    }}
}

fn erc_transfer_call(to: &TezosAddress, amount: &BigUint) -> TezosRpcValue {
    tezos_func!(&[Or::L], to, amount)
}

fn init_tezos_swap_call(
    id: BytesJson,
    time_lock: DateTime<Utc>,
    secret_hash: BytesJson,
    receiver: TezosAddress,
) -> TezosRpcValue {
    tezos_func!(&[Or::R, Or::L], id, time_lock, secret_hash, receiver)
}

fn init_tezos_erc_swap_call(
    id: BytesJson,
    time_lock: DateTime<Utc>,
    secret_hash: BytesJson,
    receiver: TezosAddress,
    amount: BigUint,
    erc_addr: &TezosAddress,
) -> TezosRpcValue {
    tezos_func!(&[Or::R, Or::R, Or::L], id, time_lock, secret_hash, receiver, amount, erc_addr)
}

fn receiver_spends_call(
    id: BytesJson,
    secret: BytesJson,
    send_to: TezosAddress,
) -> TezosRpcValue {
    tezos_func!(&[Or::R, Or::R, Or::R], id, secret, send_to)
}

fn construct_function_call(func: &[Or], args: TezosRpcValue) -> TezosRpcValue {
    func.iter().rev().fold(args, |arg, or| match or {
        Or::L => TezosRpcValue::TezosPrim(TezosPrim::Left([Box::new(arg)])),
        Or::R => TezosRpcValue::TezosPrim(TezosPrim::Right([Box::new(arg)])),
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
            "contract_address": "KT1SafU2UYYQEDchguKra2ya9AKpaEgY2KLx"
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
    let maker_pub = match &coin.key_pair {
        TezosKeyPair::ED25519(p) => p.public.as_bytes(),
        _ => unimplemented!(),
    };
    let tx = coin.send_taker_payment(
        &[0x12],
        0,
        maker_pub,
        &hex::decode("66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925").unwrap(),
        1.into(),
    ).wait().unwrap();

    let op_hash = OpHash::for_op_bytes(&tx.tx_hex());
    log!((op_hash));
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

    let op_hash = OpHash::for_op_bytes(&tx.tx_hex());
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
        &[0x13],
        &[],
        0,
        taker_pub,
        &[0; 32],
    ).wait().unwrap();

    let op_hash = OpHash::for_op_bytes(&tx.tx_hex());
    log!((op_hash));
}
