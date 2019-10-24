use base58::{FromBase58, FromBase58Error, ToBase58};
use bigdecimal::BigDecimal;
use bitcrypto::{sha256, dhash256};
use blake2::{VarBlake2b, Blake2b};
use blake2::digest::{Input, VariableOutput};
use common::mm_ctx::MmArc;
use common::mm_number::MmNumber;
use crate::{TradeInfo, FoundSwapTxSpend, WithdrawRequest};
use ed25519_dalek::{Keypair as EdKeypair, SecretKey as EdSecretKey, Signature as EdSignature, SignatureError,
                    PublicKey as EdPublicKey};
use futures::TryFutureExt;
use futures01::Future;
use primitives::hash::H160;
use serde_json::{self as json, Value as Json};
use sha2::{Sha512};
use std::borrow::Cow;
use std::cmp::PartialEq;
use std::convert::TryInto;
use std::fmt;
use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use super::{HistorySyncState, MarketCoinOps, MmCoin, SwapOps, TradeFee, TransactionDetails, TransactionEnum, TransactionFut};
use common::slurp_url;

mod tezos_rpc;
use self::tezos_rpc::{ForgeOperationsRequest, Operation, PreapplyOperation, PreapplyOperationsRequest,
                      TezosRpcClient};

const ED_SK_PREFIX: [u8; 4] = [13, 15, 58, 7];
const ED_SIG_PREFIX: [u8; 5] = [9, 245, 205, 134, 18];

#[derive(Debug, Eq, PartialEq)]
struct TezosSignature {
    prefix: [u8; 5],
    sig: EdSignature,
}

pub type TezosAddrPrefix = [u8; 3];

#[derive(Debug, PartialEq)]
pub struct TezosAddress {
    prefix: TezosAddrPrefix,
    hash: H160,
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

impl fmt::Display for TezosAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut buf = Vec::with_capacity(27);

        buf.extend_from_slice(&self.prefix);
        buf.extend_from_slice(&*self.hash);
        let checksum = dhash256(&buf[..23]);
        buf.extend_from_slice(&checksum[..4]);

        buf.to_base58().fmt(f)
    }
}

impl fmt::Display for TezosSignature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut buf = Vec::with_capacity(73);

        buf.extend_from_slice(&self.prefix);
        buf.extend_from_slice(&self.sig.to_bytes());
        let checksum = dhash256(&buf[..69]);
        buf.extend_from_slice(&checksum[..4]);

        buf.to_base58().fmt(f)
    }
}

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

impl fmt::Display for TezosKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut buf = Vec::with_capacity(40);
        match self {
            TezosKeyPair::ED25519(k) => {
                buf.extend_from_slice(&ED_SK_PREFIX);
                buf.extend_from_slice(k.secret.as_bytes());
            }
            _ => unimplemented!()
        }
        let checksum = dhash256(&buf[..36]);
        buf.extend_from_slice(&checksum[..4]);
        buf.to_base58().fmt(f)
    }
}

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
                let mut h = H160::default();
                let mut blake = unwrap!(VarBlake2b::new(20));
                blake.input(pair.public.as_bytes());
                blake.variable_result(|res| h = H160::from(res));
                h
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
        let client = self.rpc_client.clone();
        let addr = format!("{}", self.my_address);
        let fut = Box::pin(async move {
            client.get_balance(&addr).await
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
        time_lock: u32,
        maker_pub: &[u8],
        secret_hash: &[u8],
        amount: BigDecimal,
    ) -> TransactionFut {
        unimplemented!()
    }

    fn send_maker_spends_taker_payment(
        &self,
        taker_payment_tx: &[u8],
        time_lock: u32,
        taker_pub: &[u8],
        secret: &[u8],
    ) -> TransactionFut {
        unimplemented!()
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

async fn withdraw_impl(coin: TezosCoin, req: WithdrawRequest) -> Result<TransactionDetails, String> {
    let to_addr: TezosAddress = try_s!(req.to.parse());
    let counter = try_s!(coin.rpc_client.counter(&coin.my_address()).await) + BigDecimal::from(1);
    let head = try_s!(coin.rpc_client.block_header("head").await);
    let op = Operation {
        amount: &req.amount * BigDecimal::from(10u64.pow(coin.decimals as u32)),
        counter,
        destination: req.to.clone(),
        fee: 1420.into(),
        gas_limit: 10600.into(),
        kind: "transaction".into(),
        source: coin.my_address().into(),
        storage_limit: 300.into(),
    };
    let forge_req = ForgeOperationsRequest {
        branch: head.hash.clone(),
        contents: vec![op.clone()]
    };
    let mut tx_bytes = try_s!(coin.rpc_client.forge_operations(&head.chain_id, &head.hash, forge_req).await);
    let mut prefixed = vec![3u8];
    prefixed.append(&mut tx_bytes.0);
    let mut sig_hash = unwrap!(VarBlake2b::new(32));
    sig_hash.input(&prefixed);
    let sig_hash = sig_hash.vec_result();
    let sig = match &coin.key_pair {
        TezosKeyPair::ED25519(key_pair) => key_pair.sign::<Sha512>(&sig_hash),
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
        tx_hash: vec![].into()
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
    let decimals = conf["decimals"].as_u64().unwrap_or (6) as u8;

    Ok(TezosCoin(Arc::new(TezosCoinImpl {
        coin_type: TezosCoinType::Tezos,
        decimals,
        key_pair,
        my_address,
        required_confirmations: conf["required_confirmations"].as_u64().unwrap_or(1).into(),
        rpc_client,
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
    log!([sig]);

    let key_pair: TezosKeyPair = "edsk2j9jaipLSH77rtwZFroZqEoSkr5fFUzcPqhphBH3BKudQU9rtw".parse().unwrap();
    log!((key_pair.get_address([4, 177, 1])));

    let unsigned = hex::decode("036fd71cb17630f3b805e841b98000c80349c4757c97faaf79710d32fc8c34a9220800002969737230bd5ea60f632b52777981e43a25d069a08d06fc0380ea30e0d4030001c56d2c471c59aa98400fa4256bd94cc7217ec4aa00ff000000330005080505070701000000244b5431474532415a68617a52784773416a52566b516363486342327076414e585157643700a80f").unwrap();
    if let TezosKeyPair::ED25519(key_pair) = key_pair {
        let mut hashed = unwrap!(VarBlake2b::new(32));
        hashed.input(&unsigned);
        let hash = hashed.vec_result();
        log!([hash]);
        log!([hash.len()]);

        let sig = key_pair.sign::<Sha512>(&hash);
        let sig = TezosSignature {
            prefix: ED_SIG_PREFIX,
            sig,
        };
        log!((sig));
    }
}
