use base58::{FromBase58, FromBase58Error, ToBase58};
use bigdecimal::BigDecimal;
use bitcrypto::{dhash256};
use blake2::{VarBlake2b};
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
use num_traits::Num;
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
use super::{CurveType, EcPubkey, HistorySyncState, MarketCoinOps, MmCoin, SwapOps, TradeActor, TradeFee,
            Transaction, TransactionDetails, TransactionDetailsFut, TransactionEnum, TransactionFut};
use common::{block_on, now_ms};

mod tezos_rpc;

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

#[cfg(test)]
mod tezos_tests;

use self::tezos_rpc::{BigMapReq, ForgeOperationsRequest, Operation, PreapplyOperation,
                      PreapplyOperationsRequest, TezosInputType, TezosRpcClient, Transaction as Tx};
use crate::tezos::tezos_rpc::{Reveal, OperationStatus};

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
    prefix: Vec<u8>,
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
        let len = bytes.len();
        let prefix_len = match len {
            71 => 3,
            73 => 5,
            _ => return Err(ParseSigError::InvalidLength),
        };
        let checksum = dhash256(&bytes[..len - 4]);
        if bytes[len - 4..] != checksum[..4] {
            return Err(ParseSigError::InvalidCheckSum);
        }
        let sig = EdSignature::from_bytes(&bytes[prefix_len..len - 4]).map_err(|e| ParseSigError::InvalidSig(e))?;
        Ok(TezosSignature {
            prefix: bytes[..prefix_len].to_vec(),
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

fn tagged_swap_uuid(uuid: &[u8], i_am: TradeActor) -> Vec<u8> {
    let mut vec = uuid.to_vec();
    match i_am {
        TradeActor::Maker => vec.push(0),
        TradeActor::Taker => vec.push(1),
    };
    vec
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
    fn from_bytes(bytes: &[u8]) -> Result<TezosKeyPair, ParseKeyPairError> {
        let secret = EdSecretKey::from_bytes(bytes).map_err(|e| ParseKeyPairError::InvalidSecret(e))?;
        let public = EdPublicKey::from_secret::<Sha512>(&secret);
        Ok(TezosKeyPair::ED25519(EdKeypair {
            secret,
            public,
        }))
    }

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

    fn get_pubkey(&self) -> TezosPubkey {
        match self {
            TezosKeyPair::ED25519(key_pair) => {
                TezosPubkey {
                    prefix: [13, 15, 37, 217],
                    bytes: key_pair.public.as_bytes().to_vec(),
                }
            },
            _ => unimplemented!(),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct TezosPubkey {
    prefix: [u8; 4],
    bytes: Vec<u8>,
}

impl TezosPubkey {
    fn prefixed_bytes(&self) -> Vec<u8> {
        let mut bytes = vec![];
        bytes.extend_from_slice(&self.prefix);
        bytes.extend_from_slice(&self.bytes);
        bytes
    }
}

impl_display_for_base_58_check_sum!(TezosPubkey);

impl FromStr for TezosPubkey {
    type Err = ParseAddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = s.from_base58().map_err(|e| ParseAddressError::InvalidBase58(e))?;
        let len = bytes.len();
        if !(len == 40 || len == 41) {
            return Err(ParseAddressError::InvalidLength);
        }
        let checksum = dhash256(&bytes[..len - 4]);
        if bytes[len-4..] != checksum[..4] {
            return Err(ParseAddressError::InvalidCheckSum);
        }
        Ok(TezosPubkey {
            prefix: unwrap!(bytes[..4].try_into(), "slice with incorrect length"),
            bytes: bytes[4..len - 4].to_vec(),
        })
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
struct AddressPrefixes {
    ed25519: TezosAddrPrefix,
    secp256k1: TezosAddrPrefix,
    p256: TezosAddrPrefix,
    originated: TezosAddrPrefix,
}

#[derive(Debug)]
pub struct TezosCoinImpl {
    addr_prefixes: AddressPrefixes,
    coin_type: TezosCoinType,
    decimals: u8,
    key_pair: TezosKeyPair,
    my_address: TezosAddress,
    required_confirmations: AtomicU64,
    rpc_client: TezosRpcClient,
    swap_contract_address: TezosAddress,
    ticker: String,
}

impl TezosCoinImpl {
    fn address_to_contract_id(&self, addr: &TezosAddress) -> Result<ContractId, String> {
        if addr.prefix == self.addr_prefixes.ed25519 {
            Ok(ContractId::PubkeyHash(PubkeyHash {
                curve_type: CurveType::ED25519,
                hash: addr.hash.clone(),
            }))
        } else if addr.prefix == self.addr_prefixes.secp256k1 {
            Ok(ContractId::PubkeyHash(PubkeyHash {
                curve_type: CurveType::SECP256K1,
                hash: addr.hash.clone(),
            }))
        } else if addr.prefix == self.addr_prefixes.p256 {
            Ok(ContractId::PubkeyHash(PubkeyHash {
                curve_type: CurveType::P256,
                hash: addr.hash.clone(),
            }))
        } else if addr.prefix == self.addr_prefixes.originated {
            Ok(ContractId::Originated(addr.hash.clone()))
        } else {
            ERR!("Address prefix {:?} doesn't match coin prefixes", addr.prefix)
        }
    }

    fn contract_id_to_addr(&self, contract_id: &ContractId) -> TezosAddress {
        match contract_id {
            ContractId::PubkeyHash(key_hash) => match key_hash.curve_type {
                CurveType::ED25519 => TezosAddress {
                    prefix: self.addr_prefixes.ed25519,
                    hash: key_hash.hash.clone(),
                },
                CurveType::SECP256K1 => TezosAddress {
                    prefix: self.addr_prefixes.secp256k1,
                    hash: key_hash.hash.clone(),
                },
                CurveType::P256 => TezosAddress {
                    prefix: self.addr_prefixes.p256,
                    hash: key_hash.hash.clone(),
                },
            },
            ContractId::Originated(hash) => TezosAddress {
                prefix: self.addr_prefixes.originated,
                hash: hash.clone(),
            }
        }
    }

    async fn my_erc_account(&self, token_addr: &TezosAddress) -> Result<TezosErcAccount, String> {
        let req = BigMapReq {
            r#type: TezosInputType {
                prim: "address".into(),
            },
            key: TezosValue::String {
                string: self.my_address.to_string(),
            }
        };

        let account = try_s!(self.rpc_client.get_big_map(
            &token_addr.to_string(),
            req,
        ).await).unwrap_or(TezosErcAccount::default());
        Ok(account)
    }

    async fn sign_and_send_operation(
        &self,
        amount: BigUint,
        destination: &TezosAddress,
        parameters: Option<TezosValue>
    ) -> Result<TezosOperation, String> {
        let mut operations = vec![];
        let mut counter = TezosUint(try_s!(self.rpc_client.counter(&self.my_address.to_string()).await) + BigUint::from(1u8));
        let head = try_s!(self.rpc_client.block_header("head").await);
        let manager_key = try_s!(self.rpc_client.manager_key(&self.my_address.to_string()).await);
        match manager_key.key {
            Some(_) => (),
            None => {
                let reveal = Operation::reveal(Reveal {
                    counter: counter.clone(),
                    fee: BigUint::from(1269u32).into(),
                    gas_limit: BigUint::from(10000u32).into(),
                    public_key: self.key_pair.get_pubkey().to_string(),
                    source: self.my_address.to_string(),
                    storage_limit: BigUint::from(0u8).into(),
                });
                operations.push(reveal);
                counter = counter + TezosUint(BigUint::from(0u8));
            },
        };
        let op = Operation::transaction(Tx {
            amount: amount.into(),
            counter,
            destination: destination.to_string(),
            fee: BigUint::from(0100000u32).into(),
            gas_limit: BigUint::from(800000u32).into(),
            parameters,
            source: self.my_address.to_string(),
            storage_limit: BigUint::from(60000u32).into(),
        });
        operations.push(op);
        let forge_req = ForgeOperationsRequest {
            branch: head.hash.clone(),
            contents: operations.clone()
        };
        let mut tx_bytes = try_s!(self.rpc_client.forge_operations(&head.chain_id, &head.hash, forge_req).await);
        let mut prefixed = vec![3u8];
        prefixed.append(&mut tx_bytes.0);
        let sig_hash = blake2b_256(&prefixed);
        let sig = match &self.key_pair {
            TezosKeyPair::ED25519(key_pair) => key_pair.sign::<Sha512>(&*sig_hash),
            _ => unimplemented!(),
        };
        let signature = TezosSignature {
            prefix: ED_SIG_PREFIX.to_vec(),
            sig,
        };
        let preapply_req = PreapplyOperationsRequest(vec![PreapplyOperation {
            branch: head.hash,
            contents: operations,
            protocol: head.protocol,
            signature: format!("{}", signature),
        }]);
        try_s!(self.rpc_client.preapply_operations(preapply_req).await);
        prefixed.extend_from_slice(&signature.sig.to_bytes());
        prefixed.remove(0);
        try_s!(self.rpc_client.inject_operation(&hex::encode(&prefixed)).await);
        Ok(deserialize(prefixed.as_slice()).unwrap())
    }

    fn address_from_ec_pubkey(&self, pubkey: &EcPubkey) -> Result<TezosAddress, String> {
        let prefix = match pubkey.curve_type {
            CurveType::SECP256K1 => self.addr_prefixes.secp256k1,
            CurveType::ED25519 => self.addr_prefixes.ed25519,
            CurveType::P256 => self.addr_prefixes.p256,
        };
        Ok(TezosAddress {
            prefix,
            hash: blake2b_160(&pubkey.bytes),
        })
    }

    async fn validate_htlc_payment(
        &self,
        operation: TezosOperation,
        uuid: Vec<u8>,
        time_lock: u32,
        other_addr: TezosAddress,
        secret_hash: Vec<u8>,
        amount: BigDecimal,
    ) -> Result<(), String> {
        match operation.op {
            TezosOperationEnum::Transaction(tx) => {
                if tx.source != try_s!(self.address_to_contract_id(&other_addr)) {
                    return ERR!("Invalid transaction source");
                };

                if tx.destination != try_s!(self.address_to_contract_id(&self.swap_contract_address)) {
                    return ERR!("Invalid transaction destination");
                }
                let amount = (amount * BigDecimal::from(10u64.pow(self.decimals as u32))).to_bigint().unwrap().to_biguint().unwrap();
                let expected_params = match self.coin_type {
                    TezosCoinType::Tezos => {
                        if tx.amount.0 != amount {
                            return ERR!("Invalid transaction amount");
                        }
                        init_tezos_swap_call(uuid.into(), time_lock, secret_hash.into(), self.my_address.clone())
                    },
                    TezosCoinType::ERC(ref token_addr) =>
                        init_tezos_erc_swap_call(uuid.into(), time_lock, secret_hash.into(), self.my_address.clone(), amount, token_addr),
                };
                if tx.parameters != Some(expected_params) {
                    return ERR!("Invalid transaction parameters");
                };
                Ok(())
            },
            _ => ERR!("The payment must have Transaction type"),
        }
    }

    async fn check_if_payment_sent(&self, uuid: BytesJson, search_from_block: u64) -> Result<Option<TezosOperation>, String> {
        let req = BigMapReq {
            r#type: TezosInputType {
                prim: "bytes".into(),
            },
            key: TezosValue::Bytes {
                bytes: uuid.clone(),
            }
        };
        let swap: Option<TezosAtomicSwap> = try_s!(self.rpc_client.get_big_map(&self.swap_contract_address.to_string(), req).await);
        match swap {
            Some(swap) => {
                let mut current_block = search_from_block;
                let uuid: TezosValue = uuid.into();

                loop {
                    let operations = try_s!(self.rpc_client.operations(&current_block.to_string()).await);
                    for operation in operations {
                        for transaction in operation.contents {
                            match transaction.op {
                                Operation::transaction(tx) => {
                                    if tx.destination == self.swap_contract_address.to_string() {
                                        match tx.parameters {
                                            Some(ref params) => {
                                                let (path, args) = read_function_call(vec![], params.clone());
                                                let (tx_uuid, _) = args.split_and_read_value();
                                                if (path == [Or::L] || path == [Or::R, Or::L]) && tx_uuid == uuid {
                                                    let branch = unwrap!(TezosBlockHash::from_str(&operation.branch));
                                                    let signature = unwrap!(TezosSignature::from_str(&operation.signature));
                                                    let destination = unwrap!(TezosAddress::from_str(&tx.destination));
                                                    let source = unwrap!(TezosAddress::from_str(&tx.source));
                                                    let operation = TezosOperation {
                                                        branch: branch.hash,
                                                        signature: Some(H512::from(signature.sig.to_bytes())),
                                                        op: TezosOperationEnum::Transaction(TezosTransaction {
                                                            amount: tx.amount.into(),
                                                            counter: tx.counter.into(),
                                                            destination: unwrap!(self.address_to_contract_id(&destination)),
                                                            source: unwrap!(self.address_to_contract_id(&source)),
                                                            fee: tx.fee.into(),
                                                            gas_limit: tx.gas_limit.into(),
                                                            storage_limit: tx.storage_limit.into(),
                                                            parameters: tx.parameters,
                                                        })
                                                    };
                                                    return Ok(Some(operation.into()))
                                                }
                                            },
                                            None => continue,
                                        }
                                    }
                                },
                                _ => continue,
                            }
                        }
                    }
                    current_block += 1;
                }
                ERR!("Swap is created but corresponding operation is not found")
            },
            None => Ok(None),
        }
    }
}

#[derive(Clone, Debug)]
pub struct TezosCoin(Arc<TezosCoinImpl>);

impl Deref for TezosCoin {type Target = TezosCoinImpl; fn deref (&self) -> &TezosCoinImpl {&*self.0}}

impl TezosCoin {
    async fn check_and_update_allowance(&self, token_addr: &TezosAddress, spender: &TezosAddress, amount: &BigUint) -> Result<(), String> {
        let my_account = try_s!(self.my_erc_account(token_addr).await);
        let contract_id = try_s!(self.address_to_contract_id(spender));
        let contract_id = serialize(&contract_id).take().into();
        let zero = BigUint::from(0u8);
        let current_allowance = my_account.allowances.get(&contract_id).unwrap_or(&zero);
        if current_allowance < amount {
            let args = erc_approve_call(spender, &my_account.balance);
            let op = try_s!(self.sign_and_send_operation(zero, token_addr, Some(args)).await);
            self.wait_for_operation_confirmation(
                &op,
                1,
                now_ms() / 1000 + 120,
                10,
                0,
            ).await
        } else {
            Ok(())
        }
    }

    async fn wait_for_operation_confirmation(
        &self,
        op: &TezosOperation,
        confirmations: u64,
        wait_until: u64,
        check_every: u64,
        _since_block: u64
    ) -> Result<(), String> {
        let block_hash = TezosBlockHash {
            prefix: [1, 52],
            hash: op.branch.clone(),
        };
        let op_hash = op.op_hash();
        let since_block_header = try_s!(self.rpc_client.block_header(&block_hash.to_string()).await);
        let since_block_timestamp = Some(since_block_header.timestamp.timestamp());
        let mut found_tx_in_block = None;
        loop {
            if now_ms() / 1000 > wait_until {
                return ERR!("Waited too long until {} for transaction {} to be confirmed {} times", wait_until, op_hash, confirmations);
            }

            let current_block_header = try_s!(self.rpc_client.block_header("head").await);
            if current_block_header.level > since_block_header.level {
                if found_tx_in_block.is_none() {
                    if current_block_header.level == since_block_header.level + 1 {
                        let operations = try_s!(self.rpc_client.operation_hashes(&current_block_header.hash).await);
                        for (validation, operation) in operations.into_iter().enumerate() {
                            for (offset, op) in operation.into_iter().enumerate() {
                                if op == op_hash.to_string() {
                                    found_tx_in_block = Some((current_block_header.level, validation, offset));
                                }
                            }
                        }
                    } else {
                        let length = current_block_header.level - since_block_header.level;
                        let blocks = try_s!(self.rpc_client.blocks(since_block_timestamp, Some(length), None).await);
                        for block in blocks {
                            let operations = try_s!(self.rpc_client.operation_hashes(&block).await);
                            for (validation, operation) in operations.into_iter().enumerate() {
                                for (offset, op) in operation.into_iter().enumerate() {
                                    if op == op_hash.to_string() {
                                        let header = try_s!(self.rpc_client.block_header(&block).await);
                                        found_tx_in_block = Some((header.level, validation, offset));
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if let Some((block_number, validation, offset)) = found_tx_in_block {
                let op_from_rpc = try_s!(self.rpc_client.single_operation(&
                    block_number.to_string(),
                    validation,
                    offset,
                ).await);
                if op_from_rpc.contents[0].metadata.operation_result != Some(OperationStatus::applied) {
                    return ERR!("Operation status must be `applied`");
                }
                let current_confirmations = current_block_header.level - block_number + 1;
                if current_confirmations >= confirmations {
                    return Ok(());
                }
            }
            Timer::sleep(check_every as f64).await
        }
    }
}

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
                    let my_account = try_s!(selfi.my_erc_account(token_addr).await);
                    Ok(BigDecimal::from(BigInt::from(my_account.balance)))
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
        let op: TezosOperation = try_fus!(deserialize(tx).map_err(|e| fomat!([e])));
        let fut = async move {
            coin.wait_for_operation_confirmation(&op, confirmations, wait_until, check_every, since_block).await
        };
        Box::new(Box::pin(fut).compat())
    }

    fn wait_for_tx_spend(&self, transaction: &[u8], wait_until: u64, from_block: u64) -> TransactionFut {
        let coin = self.clone();
        let tx: TezosOperation = try_fus!(deserialize(transaction).map_err(|e| fomat!([e])));
        let fut = async move {
            match &tx.op {
                TezosOperationEnum::Transaction(op) => {
                    match &op.parameters {
                        Some(params) => {
                            let (path, args) = read_function_call(vec![], params.clone());
                            if path != vec![Or::R, Or::L] {
                                return ERR!("Invalid entry path {:?}", path);
                            }
                            let (uuid, _) = args.split_and_read_value();
                            let bytes: BytesJson = try_s!(uuid.clone().try_into());
                            loop {
                                let req = BigMapReq {
                                    r#type: TezosInputType {
                                        prim: "bytes".into(),
                                    },
                                    key: TezosValue::Bytes {
                                        bytes: bytes.clone()
                                    }
                                };
                                let swap: TezosAtomicSwap = match try_s!(coin.rpc_client.get_big_map(&coin.swap_contract_address.to_string(), req).await) {
                                    Some(s) => s,
                                    None => {
                                        if now_ms() / 1000 > wait_until {
                                            return ERR!("Waited too long for transaction {:?} to be spent", tx);
                                        }

                                        Timer::sleep(10.).await;
                                        continue;
                                    }
                                };

                                match swap.state {
                                    TezosAtomicSwapState::ReceiverSpent => {
                                        let mut current_block = from_block;
                                        loop {
                                            let operations = try_s!(coin.rpc_client.operations(&current_block.to_string()).await);
                                            for operation in operations {
                                                for transaction in operation.contents {
                                                    match transaction.op {
                                                        Operation::transaction(tx) => {
                                                            if tx.destination == coin.swap_contract_address.to_string() {
                                                                match tx.parameters {
                                                                    Some(ref params) => {
                                                                        let (path, args) = read_function_call(vec![], params.clone());
                                                                        let (tx_uuid, _) = args.split_and_read_value();
                                                                        if path == [Or::R, Or::R, Or::L] && tx_uuid == uuid {
                                                                            let branch = unwrap!(TezosBlockHash::from_str(&operation.branch));
                                                                            let signature = unwrap!(TezosSignature::from_str(&operation.signature));
                                                                            let destination = unwrap!(TezosAddress::from_str(&tx.destination));
                                                                            let source = unwrap!(TezosAddress::from_str(&tx.source));
                                                                            let operation = TezosOperation {
                                                                                branch: branch.hash,
                                                                                signature: Some(H512::from(signature.sig.to_bytes())),
                                                                                op: TezosOperationEnum::Transaction(TezosTransaction {
                                                                                    amount: tx.amount.into(),
                                                                                    counter: tx.counter.into(),
                                                                                    destination: unwrap!(coin.address_to_contract_id(&destination)),
                                                                                    source: unwrap!(coin.address_to_contract_id(&source)),
                                                                                    fee: tx.fee.into(),
                                                                                    gas_limit: tx.gas_limit.into(),
                                                                                    storage_limit: tx.storage_limit.into(),
                                                                                    parameters: tx.parameters,
                                                                                })
                                                                            };
                                                                            return Ok(operation.into())
                                                                        }
                                                                    },
                                                                    None => continue,
                                                                }
                                                            }
                                                        },
                                                        _ => continue,
                                                    }
                                                }
                                            }
                                            current_block += 1;
                                        }
                                    },
                                    TezosAtomicSwapState::SenderRefunded => return ERR!("Swap payment was refunded"),
                                    TezosAtomicSwapState::Initialized => {
                                        if now_ms() / 1000 > wait_until {
                                            return ERR!("Waited too long for transaction {:?} to be spent", tx);
                                        }

                                        Timer::sleep(10.).await;
                                        continue;
                                    }
                                }
                            }
                        },
                        None => ERR!("Operation params can't be None"),
                    }
                },
                _ => unimplemented!(),
            }
        };
        let fut = Box::pin(fut);
        Box::new(fut.compat())
    }

    fn tx_enum_from_bytes(&self, bytes: &[u8]) -> Result<TransactionEnum, String> {
        let tx: TezosOperation = try_s!(deserialize(bytes).map_err(|e| fomat!([e])));
        Ok(tx.into())
    }

    fn current_block(&self) -> Box<dyn Future<Item=u64, Error=String> + Send> {
        let client = self.rpc_client.clone();
        let fut = Box::pin(async move {
            client.block_header("head").await
        });
        Box::new(fut.compat().map(|header| header.level))
    }

    fn address_from_pubkey_str(&self, pubkey: &str) -> Result<String, String> {
        let pubkey_bytes = try_s!(hex::decode(pubkey));
        let pubkey: EcPubkey = try_s!(deserialize(pubkey_bytes.as_slice()).map_err(|e| ERRL!("{:?}", e)));
        let address = try_s!(self.address_from_ec_pubkey(&pubkey));
        Ok(address.to_string())
    }

    fn tx_hash_to_string(&self, hash: &[u8]) -> String {
        let hash = H256::from(hash);
        OpHash {
            prefix: OP_HASH_PREFIX,
            hash,
        }.to_string()
    }

    fn get_pubkey(&self) -> EcPubkey {
        match &self.key_pair {
            TezosKeyPair::ED25519(pair) =>  EcPubkey {
                curve_type: CurveType::ED25519,
                bytes: pair.public.as_bytes().to_vec(),
            },
            _ => unimplemented!(),
        }
    }
}

async fn send_htlc_payment(
    coin: TezosCoin,
    uuid: Vec<u8>,
    time_lock: u32,
    other_pub: EcPubkey,
    secret_hash: Vec<u8>,
    amount: BigDecimal,
) -> Result<TransactionDetails, String> {
    let other_addr = try_s!(coin.address_from_ec_pubkey(&other_pub));

    let (amount, args) = match &coin.coin_type {
        TezosCoinType::Tezos => {
            let args = init_tezos_swap_call(
                uuid.into(),
                time_lock,
                secret_hash.into(),
                other_addr,
            );
            let amount = (amount * BigDecimal::from(10u64.pow(coin.decimals as u32))).to_bigint().unwrap().to_biguint().unwrap();
            (amount, args)
        },
        TezosCoinType::ERC(token_addr) => {
            let amount: BigUint = (amount * BigDecimal::from(10u64.pow(coin.decimals as u32))).to_bigint().unwrap().to_biguint().unwrap();
            try_s!(coin.check_and_update_allowance(token_addr, &coin.swap_contract_address, &amount).await);
            let args = init_tezos_erc_swap_call(
                uuid.into(),
                time_lock,
                secret_hash.into(),
                other_addr,
                amount,
                token_addr,
            );
            (BigUint::from(0u8), args)
        }
    };
    let tx = try_s!(coin.sign_and_send_operation(amount, &coin.swap_contract_address, Some(args)).await);
    Ok(TransactionDetails {
        block_height: 0,
        coin: coin.ticker.clone(),
        fee_details: None,
        from: vec![],
        internal_id: vec![].into(),
        my_balance_change: 0.into(),
        received_by_me: 0.into(),
        spent_by_me: 0.into(),
        timestamp: now_ms() / 1000,
        to: vec![],
        tx_hash: coin.tx_hash_to_string(&tx.tx_hash()),
        total_amount: 0.into(),
        tx_hex: tx.tx_hex().into(),
    })
}

impl SwapOps for TezosCoin {
    fn send_taker_fee(&self, fee_pubkey: &EcPubkey, amount: BigDecimal) -> TransactionDetailsFut {
        let prefix = match fee_pubkey.curve_type {
            CurveType::SECP256K1 => self.addr_prefixes.secp256k1,
            CurveType::ED25519 => self.addr_prefixes.ed25519,
            CurveType::P256 => self.addr_prefixes.p256,
        };
        let fee_addr = TezosAddress {
            prefix,
            hash: blake2b_160(&fee_pubkey.bytes),
        };
        let ticker = self.ticker.clone();
        let coin = self.clone();
        let fut = Box::pin(async move {
            let (amount, dest, args) = match coin.coin_type {
                TezosCoinType::Tezos => {
                    let amount = (amount * BigDecimal::from(10u64.pow(coin.decimals as u32))).to_bigint().unwrap().to_biguint().unwrap();
                    (amount, fee_addr, None)
                },
                TezosCoinType::ERC(ref token_addr) => {
                    let amount: BigUint = (amount * BigDecimal::from(10u64.pow(coin.decimals as u32))).to_bigint().unwrap().to_biguint().unwrap();
                    let args = erc_transfer_call(
                        &fee_addr,
                        &amount,
                    );
                    (BigUint::from(0u8), token_addr.clone(), Some(args))
                }
            };
            let tx = try_s!(coin.sign_and_send_operation(amount, &dest, args).await);
            Ok(TransactionDetails {
                block_height: 0,
                coin: ticker,
                fee_details: None,
                from: vec![],
                internal_id: vec![].into(),
                my_balance_change: 0.into(),
                received_by_me: 0.into(),
                spent_by_me: 0.into(),
                timestamp: now_ms() / 1000,
                to: vec![],
                tx_hash: coin.tx_hash_to_string(&tx.tx_hash()),
                total_amount: 0.into(),
                tx_hex: tx.tx_hex().into(),
            })
        }).compat();
        Box::new(fut)
    }

    fn send_maker_payment(
        &self,
        uuid: &[u8],
        time_lock: u32,
        taker_pub: &EcPubkey,
        secret_hash: &[u8],
        amount: BigDecimal,
    ) -> TransactionDetailsFut {
        let uuid = tagged_swap_uuid(uuid, TradeActor::Maker);
        let fut = Box::pin(send_htlc_payment(self.clone(), uuid, time_lock, taker_pub.clone(), secret_hash.to_vec(), amount)).compat();
        Box::new(fut)
    }

    fn send_taker_payment(
        &self,
        uuid: &[u8],
        time_lock: u32,
        maker_pub: &EcPubkey,
        secret_hash: &[u8],
        amount: BigDecimal,
    ) -> TransactionDetailsFut {
        let uuid = tagged_swap_uuid(uuid, TradeActor::Taker);
        let fut = Box::pin(send_htlc_payment(self.clone(), uuid, time_lock, maker_pub.clone(), secret_hash.to_vec(), amount)).compat();
        Box::new(fut)
    }

    fn send_maker_spends_taker_payment(
        &self,
        uuid: &[u8],
        _taker_payment_tx: &[u8],
        _time_lock: u32,
        _taker_pub: &EcPubkey,
        secret: &[u8],
    ) -> TransactionFut {
        let uuid = tagged_swap_uuid(uuid, TradeActor::Taker);
        let args = receiver_spends_call(
            uuid.into(),
            secret.to_vec().into(),
            self.my_address.clone(),
        );

        let coin = self.clone();
        let fut = Box::pin(async move {
            let dest = coin.swap_contract_address.clone();
            coin.sign_and_send_operation(BigUint::from(0u8), &dest, Some(args)).await
        }).compat().map(|tx| tx.into());
        Box::new(fut)
    }

    fn send_taker_spends_maker_payment(
        &self,
        uuid: &[u8],
        maker_payment_tx: &[u8],
        time_lock: u32,
        maker_pub: &EcPubkey,
        secret: &[u8],
    ) -> TransactionFut {
        let uuid = tagged_swap_uuid(uuid, TradeActor::Maker);
        let args = receiver_spends_call(
            uuid.into(),
            secret.to_vec().into(),
            self.my_address.clone(),
        );

        let coin = self.clone();
        let fut = Box::pin(async move {
            let dest = coin.swap_contract_address.clone();
            coin.sign_and_send_operation(BigUint::from(0u8), &dest, Some(args)).await
        }).compat().map(|tx| tx.into());
        Box::new(fut)
    }

    fn send_taker_refunds_payment(
        &self,
        uuid: &[u8],
        taker_payment_tx: &[u8],
        time_lock: u32,
        maker_pub: &EcPubkey,
        secret_hash: &[u8],
    ) -> TransactionFut {
        let uuid = tagged_swap_uuid(uuid, TradeActor::Taker);
        let args = sender_refunds_call(uuid.into(), &self.my_address);
        let coin = self.clone();
        let fut = Box::pin(async move {
            let dest = coin.swap_contract_address.clone();
            coin.sign_and_send_operation(BigUint::from(0u8), &dest, Some(args)).await
        }).compat().map(|tx| tx.into());
        Box::new(fut)
    }

    fn send_maker_refunds_payment(
        &self,
        uuid: &[u8],
        maker_payment_tx: &[u8],
        time_lock: u32,
        taker_pub: &EcPubkey,
        secret_hash: &[u8],
    ) -> TransactionFut {
        let uuid = tagged_swap_uuid(uuid, TradeActor::Maker);
        let args = sender_refunds_call(uuid.into(), &self.my_address);
        let coin = self.clone();
        let fut = Box::pin(async move {
            let dest = coin.swap_contract_address.clone();
            coin.sign_and_send_operation(BigUint::from(0u8), &dest, Some(args)).await
        }).compat().map(|tx| tx.into());
        Box::new(fut)
    }

    fn validate_fee(
        &self,
        fee_tx: &TransactionEnum,
        fee_addr: &EcPubkey,
        amount: &BigDecimal,
    ) -> Box<dyn Future<Item=(), Error=String> + Send> {
        let op = match fee_tx {
            TransactionEnum::TezosOperation(op) => op.clone(),
            _ => unimplemented!(),
        };
        let fee_addr = try_fus!(self.address_from_ec_pubkey(fee_addr));
        let amount = (amount * BigDecimal::from(10u64.pow(self.decimals as u32))).to_bigint().unwrap().to_biguint().unwrap();
        let coin = self.clone();
        let fut = async move {
            match op.op {
                TezosOperationEnum::Transaction(ref tx) => {
                    match coin.coin_type {
                        TezosCoinType::Tezos => {
                            if tx.amount.0 != amount {
                                return ERR!("Invalid dex fee tx amount");
                            }
                            let fee_contract_id = try_s!(coin.address_to_contract_id(&fee_addr));
                            if tx.destination != fee_contract_id {
                                return ERR!("Invalid dex fee tx destination");
                            }
                        },
                        TezosCoinType::ERC(ref token_addr) => {
                            let token_contract_id = try_s!(coin.address_to_contract_id(token_addr));
                            if tx.destination != token_contract_id {
                                return ERR!("Invalid dex fee tx destination");
                            }
                            let expected_params = erc_transfer_call(&fee_addr, &amount);
                            if tx.parameters != Some(expected_params) {
                                return ERR!("Invalid dex fee tx parameters");
                            }
                        },
                    }
                },
                _ => return ERR!("Taker fee must be TezosOperationEnum::Transaction"),
            }
            coin.wait_for_operation_confirmation(
                &op,
                coin.required_confirmations(),
                now_ms() / 1000 + 120,
                10,
                0,
            ).await
        };
        Box::new(Box::pin(fut).compat())
    }

    fn validate_maker_payment(
        &self,
        uuid: &[u8],
        payment_tx: &[u8],
        time_lock: u32,
        maker_pub: &EcPubkey,
        secret_hash: &[u8],
        amount: BigDecimal,
    ) -> Box<dyn Future<Item=(), Error=String> + Send> {
        let operation: TezosOperation = try_fus!(deserialize(payment_tx).map_err(|e|  fomat!([e])));
        let maker_addr = try_fus!(self.address_from_ec_pubkey(maker_pub));
        let uuid = tagged_swap_uuid(uuid, TradeActor::Maker);
        let secret_hash = secret_hash.to_vec();
        let coin = self.clone();
        let fut = async move {
            coin.validate_htlc_payment(operation, uuid, time_lock, maker_addr, secret_hash, amount).await
        };
        Box::new(Box::pin(fut).compat())
    }

    fn validate_taker_payment(
        &self,
        uuid: &[u8],
        payment_tx: &[u8],
        time_lock: u32,
        taker_pub: &EcPubkey,
        secret_hash: &[u8],
        amount: BigDecimal,
    ) -> Box<dyn Future<Item=(), Error=String> + Send> {
        let operation: TezosOperation = try_fus!(deserialize(payment_tx).map_err(|e|  fomat!([e])));
        let taker_addr = try_fus!(self.address_from_ec_pubkey(taker_pub));
        let uuid = tagged_swap_uuid(uuid, TradeActor::Taker);
        let secret_hash = secret_hash.to_vec();
        let coin = self.clone();
        let fut = async move {
            coin.validate_htlc_payment(operation, uuid, time_lock, taker_addr, secret_hash, amount).await
        };
        Box::new(Box::pin(fut).compat())
    }

    fn check_if_my_maker_payment_sent(
        &self,
        uuid: &[u8],
        time_lock: u32,
        other_pub: &EcPubkey,
        secret_hash: &[u8],
        search_from_block: u64,
    ) -> Box<dyn Future<Item=Option<TransactionEnum>, Error=String> + Send> {
        let uuid = BytesJson(tagged_swap_uuid(uuid, TradeActor::Maker));
        let coin = self.clone();
        let fut = async move {
            let tx = try_s!(coin.check_if_payment_sent(uuid, search_from_block).await);
            Ok(tx.map(|tx| tx.into()))
        };
        Box::new(Box::pin(fut).compat())
    }

    fn check_if_my_taker_payment_sent(
        &self,
        uuid: &[u8],
        time_lock: u32,
        other_pub: &EcPubkey,
        secret_hash: &[u8],
        search_from_block: u64,
    ) -> Box<dyn Future<Item=Option<TransactionEnum>, Error=String> + Send> {
        let uuid = BytesJson(tagged_swap_uuid(uuid, TradeActor::Taker));
        let coin = self.clone();
        let fut = async move {
            let tx = try_s!(coin.check_if_payment_sent(uuid, search_from_block).await);
            Ok(tx.map(|tx| tx.into()))
        };
        Box::new(Box::pin(fut).compat())
    }

    fn search_for_swap_tx_spend_my(
        &self,
        time_lock: u32,
        other_pub: &EcPubkey,
        secret_hash: &[u8],
        tx: &[u8],
        search_from_block: u64,
    ) -> Result<Option<FoundSwapTxSpend>, String> {

    }

    fn search_for_swap_tx_spend_other(
        &self,
        time_lock: u32,
        other_pub: &EcPubkey,
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
        match &self.op {
            TezosOperationEnum::Transaction(tx) => {
                match &tx.parameters {
                    Some(params) => {
                        let (path, args) = read_function_call(vec![], params.clone());
                        if path == vec![Or::R, Or::R, Or::L] {
                            let values = args.values_vec(vec![]);
                            match values.get(1) {
                                Some(val) => match val {
                                    TezosValue::Bytes { bytes} => Ok(bytes.0.clone()),
                                    _ => ERR!("The argument at index 1 must be TezosValue::Bytes, got {:?}", val),
                                },
                                None => ERR!("There's no argument at index 1"),
                            }
                        } else {
                            ERR!("Invalid function call")
                        }
                    },
                    None => ERR!("parameters are None"),
                }
            },
            _ => ERR!("Can't extract secret from non-Transaction operation"),
        }
    }

    fn tx_hash(&self) -> BytesJson {
        blake2b_256(&serialize(self).take()).to_vec().into()
    }
}

async fn withdraw_impl(coin: TezosCoin, req: WithdrawRequest) -> Result<TransactionDetails, String> {
    let to_addr: TezosAddress = try_s!(req.to.parse());
    let counter = TezosUint(try_s!(coin.rpc_client.counter(&coin.my_address()).await) + BigUint::from(1u8));
    let head = try_s!(coin.rpc_client.block_header("head").await);
    let op = match &coin.coin_type {
        TezosCoinType::Tezos => Operation::transaction(Tx{
            amount: (&req.amount * BigDecimal::from(10u64.pow(coin.decimals as u32))).to_bigint().unwrap().to_biguint().unwrap().into(),
            counter,
            destination: req.to.clone(),
            fee: BigUint::from(1420u32).into(),
            gas_limit: BigUint::from(10600u32).into(),
            parameters: None,
            source: coin.my_address().into(),
            storage_limit: BigUint::from(300u32).into(),
        }),
        TezosCoinType::ERC(addr) => {
            let amount: BigUint = (&req.amount * BigDecimal::from(10u64.pow(coin.decimals as u32))).to_bigint().unwrap().to_biguint().unwrap();
            let parameters = Some(erc_transfer_call(&to_addr, &amount));
            Operation::transaction(Tx {
                amount: BigUint::from(0u8).into(),
                counter,
                destination: addr.to_string(),
                fee: BigUint::from(100000u32).into(),
                gas_limit: BigUint::from(800000u32).into(),
                parameters,
                source: coin.my_address().into(),
                storage_limit: BigUint::from(60000u32).into(),
            })
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
        prefix: ED_SIG_PREFIX.to_vec(),
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
        false
    }

    fn check_i_have_enough_to_trade(&self, amount: &MmNumber, balance: &MmNumber, trade_info: TradeInfo) -> Box<dyn Future<Item=(), Error=String> + Send> {
        Box::new(futures01::future::ok(()))
    }

    fn can_i_spend_other_payment(&self) -> Box<dyn Future<Item=(), Error=String> + Send> {
        Box::new(futures01::future::ok(()))
    }

    fn withdraw(&self, req: WithdrawRequest) -> Box<dyn Future<Item=TransactionDetails, Error=String> + Send> {
        Box::new(Box::pin(withdraw_impl(self.clone(), req)).compat())
    }

    fn decimals(&self) -> u8 {
        self.decimals
    }

    fn process_history_loop(&self, ctx: MmArc) {
        unimplemented!()
    }

    fn tx_details_by_hash(&self, hash: &[u8]) -> Box<dyn Future<Item=TransactionDetails, Error=String> + Send> {
        Box::new(futures01::future::ok(TransactionDetails::default()))
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
        _ => return ERR!("Unsupported token type"),
    };

    Ok(TezosCoin(Arc::new(TezosCoinImpl {
        addr_prefixes: AddressPrefixes {
            ed25519: [4, 177, 1],
            secp256k1: [4, 177, 3],
            p256: [4, 177, 6],
            originated: [2, 90, 121],
        },
        coin_type,
        decimals,
        key_pair,
        my_address,
        required_confirmations: conf["required_confirmations"].as_u64().unwrap_or(1).into(),
        rpc_client,
        swap_contract_address: "KT1PKk5L9vt2RB1FcWNN1mBJQD3diafPNAD7".parse().unwrap(),
        ticker: ticker.into(),
    })))
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

impl Serialize for TezosUint {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error> where S: Serializer {
        s.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for TezosUint {
    fn deserialize<D>(d: D) -> Result<TezosUint, D::Error> where D: Deserializer<'de> {
        struct TezosUintStringVisitor;

        impl<'de> Visitor<'de> for TezosUintStringVisitor {
            type Value = TezosUint;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string containing json data")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
            {

                BigUint::from_str(v).map_err(E::custom).map(|num| num.into())
            }
        }

        d.deserialize_any(TezosUintStringVisitor)
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

    fn values_vec(self, mut values: Vec<TezosValue>) -> Vec<TezosValue> {
        let (cur, next) = self.split_and_read_value();
        values.push(cur);
        match next {
            Some(val) => val.values_vec(values),
            None => values,
        }
    }
}

fn read_function_call(mut path: Vec<Or>, value: TezosValue) -> (Vec<Or>, TezosValue) {
    match value {
        TezosValue::TezosPrim(TezosPrim::Left(val)) => {
            path.push(Or::L);
            read_function_call(path, *val[0].clone())
        },
        TezosValue::TezosPrim(TezosPrim::Right(val)) => {
            path.push(Or::R);
            read_function_call(path, *val[0].clone())
        },
        _ => (path, value)
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

#[derive(Debug, Default)]
struct TezosErcAccount {
    balance: BigUint,
    allowances: HashMap<BytesJson, BigUint>,
}

#[derive(Debug, PartialEq)]
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

fn erc_transfer_call(to: &TezosAddress, amount: &BigUint) -> TezosValue {
    tezos_func!(&[Or::L], to, amount)
}

fn erc_approve_call(spender: &TezosAddress, amount: &BigUint) -> TezosValue {
    tezos_func!(&[Or::R, Or::L], spender, amount)
}

fn init_tezos_swap_call(
    id: BytesJson,
    time_lock: u32,
    secret_hash: BytesJson,
    receiver: TezosAddress,
) -> TezosValue {
    let time_lock = DateTime::from_utc(NaiveDateTime::from_timestamp(time_lock as i64, 0), Utc);
    tezos_func!(&[Or::L], id, time_lock, secret_hash, receiver)
}

fn init_tezos_erc_swap_call(
    id: BytesJson,
    time_lock: u32,
    secret_hash: BytesJson,
    receiver: TezosAddress,
    amount: BigUint,
    erc_addr: &TezosAddress,
) -> TezosValue {
    let time_lock = DateTime::from_utc(NaiveDateTime::from_timestamp(time_lock as i64, 0), Utc);
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
    send_to: &TezosAddress,
) -> TezosValue {
    tezos_func!(&[Or::R, Or::R, Or::R], id, send_to)
}

fn construct_function_call(func: &[Or], args: TezosValue) -> TezosValue {
    func.iter().rev().fold(args, |arg, or| match or {
        Or::L => TezosValue::TezosPrim(TezosPrim::Left([Box::new(arg)])),
        Or::R => TezosValue::TezosPrim(TezosPrim::Right([Box::new(arg)])),
    })
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
            remainder ^= sign << 6;
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
        let mut bits_str = String::new();
        let mut sign = BigInt::from(1);
        let mut i = 0u32;
        let mut stop = false;
        loop {
            let mut byte: u8 = reader.read()?;
            if i == 0 && byte & (1u8 << 6) != 0 {
                sign = -sign;
                byte ^= 1u8 << 6;
            }

            if byte & (1u8 << 7) != 0 {
                byte ^= 1u8 << 7;
            } else {
                stop = true
            }
            if i == 0 {
                bits_str.insert_str(0, &format!("{:06b}", byte));
            } else {
                bits_str.insert_str(0, &format!("{:07b}", byte));
            }
            if stop { break; }
            i += 1;
        }
        let num = BigUint::from_str_radix(&bits_str, 2).map_err(|_| serialization::Error::MalformedData)?;
        Ok(TezosInt::from(sign * BigInt::from(num)))
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
    Transaction(TezosTransaction),
    Reveal,
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
            },
            _ => unimplemented!(),
        }
        if let Some(sig) = &self.signature {
            s.append(sig);
        }
    }
}

impl TezosOperation {
    fn op_hash(&self) -> OpHash {
        OpHash::from_op_bytes(&serialize(self).take())
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

#[derive(Debug)]
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

#[derive(Debug)]
struct TezosAtomicSwap {
    amount: BigUint,
    amount_nat: BigUint,
    contract_address: TezosOption<ContractId>,
    created_at: BigUint,
    lock_time: BigUint,
    receiver: ContractId,
    secret_hash: BytesJson,
    sender: ContractId,
    state: TezosAtomicSwapState,
    spent_at: TezosOption<BigUint>,
    uuid: BytesJson,
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
            created_at: try_s!(reader.read().unwrap().try_into()),
            lock_time: try_s!(reader.read().unwrap().try_into()),
            receiver: try_s!(reader.read().unwrap().try_into()),
            secret_hash: try_s!(reader.read().unwrap().try_into()),
            sender: try_s!(reader.read().unwrap().try_into()),
            spent_at: try_s!(reader.read().unwrap().try_into()),
            state: try_s!(reader.read().unwrap().try_into()),
            uuid: try_s!(reader.read().unwrap().try_into()),
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

#[derive(Debug)]
struct TezosOption<T>(Option<T>);

impl<T: TryFrom<TezosValue>> TryFrom<TezosValue> for TezosOption<T>
    where T::Error: fmt::Display
{
    type Error = String;

    fn try_from(value: TezosValue) -> Result<Self, Self::Error> {
        match value {
            TezosValue::TezosPrim(TezosPrim::None) => Ok(TezosOption(None)),
            TezosValue::TezosPrim(TezosPrim::Some(value)) => Ok(TezosOption(Some(try_s!(T::try_from((*value[0]).clone()))))),
            _ => ERR!("TezosOption can be constructed only from TezosPrim::None or TezosPrim::Some, got {:?}", value),
        }
    }
}
