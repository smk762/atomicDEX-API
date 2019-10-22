use base58::{FromBase58, FromBase58Error, ToBase58};
use bigdecimal::BigDecimal;
use common::mm_ctx::MmArc;
use common::mm_number::MmNumber;
use crate::{TradeInfo, FoundSwapTxSpend, WithdrawRequest};
use ed25519_dalek::{Keypair as EdKeypair, SecretKey as EdSecretKey, Signature as EdSignature, SignatureError,
                    PublicKey as EdPublicKey};
use futures01::Future;
use mocktopus::macros::*;
use std::borrow::Cow;
use std::cmp::PartialEq;
use std::convert::TryInto;
use std::fmt;
use std::io::{Cursor, Write};
use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;
use super::{HistorySyncState, MarketCoinOps, MmCoin, SwapOps, TradeFee, TransactionDetails, TransactionEnum, TransactionFut};
use sha2::{Digest, Sha256, Sha512};
use blake2::{VarBlake2b};
use bitcrypto::{sha256, dhash256};
use blake2::digest::{Input, VariableOutput};
use primitives::hash::H160;

const ED_SK_PREFIX: [u8; 4] = [13, 15, 58, 7];

#[derive(Debug, PartialEq)]
struct TezosAddress {
    prefix: [u8; 3],
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
                let secret = EdSecretKey::from_bytes(&bytes[4..36]).map_err(|e| ParseKeyPairError::InvalidSecret(e))?;
                let public = EdPublicKey::from_secret::<Sha512>(&secret);
                Ok(TezosKeyPair::ED25519(EdKeypair {
                    secret,
                    public,
                }))
            }
            _ => Err(ParseKeyPairError::InvalidPrefix),
        }
    }
}

#[derive(Debug)]
pub struct TezosCoinImpl {
    key_pair: TezosKeyPair,
    ticker: String,
}

#[derive(Clone, Debug)]
pub struct TezosCoin(Arc<TezosCoinImpl>);

impl Deref for TezosCoin {type Target = TezosCoinImpl; fn deref (&self) -> &TezosCoinImpl {&*self.0}}

#[mockable]
impl MarketCoinOps for TezosCoin {
    fn ticker (&self) -> &str {
        unimplemented!()
    }

    fn my_address(&self) -> Cow<str> {
        unimplemented!()
    }

    fn my_balance(&self) -> Box<dyn Future<Item=BigDecimal, Error=String> + Send> {
        unimplemented!()
    }

    /// Receives raw transaction bytes in hexadecimal format as input and returns tx hash in hexadecimal format
    fn send_raw_tx(&self, tx: &str) -> Box<dyn Future<Item=String, Error=String> + Send> {
        unimplemented!()
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
        unimplemented!()
    }

    fn address_from_pubkey_str(&self, pubkey: &str) -> Result<String, String> {
        unimplemented!()
    }
}

#[mockable]
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

#[mockable]
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
        unimplemented!()
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
        unimplemented!()
    }

    fn set_required_confirmations(&self, confirmations: u64) {
        unimplemented!()
    }
}

#[test]
fn decode_address() {
    let bytes: Vec<u8> = "edsk4ArLQgBTLWG5FJmnGnT689VKoqhXwmDPBuGx3z4cvwU9MmrPZZ".from_base58().unwrap();
    log!([bytes]);
    log!([bytes.len()]);
    let checksum = &bytes[bytes.len() - 4..];
    log!([checksum]);
    log!((hex::encode(&bytes)));
    log!([sha256(&bytes[..bytes.len() - 4])]);
    log!([dhash256(&bytes[..bytes.len() - 4])]);

    let priv_key: [u8; 32] = [197, 109, 203, 119, 241, 255, 240, 13, 26, 31, 83, 48, 167, 122, 159, 31, 49, 207, 112, 250, 122, 214, 145, 162, 43, 94, 194, 140, 219, 35, 35, 80];
    let secret = EdSecretKey::from_bytes(&priv_key).unwrap();
    let public = EdPublicKey::from_secret::<Sha512>(&secret);
    log!([secret]);
    log!([public]);

    let bytes: Vec<u8> = "edpkuTXkJDGcFd5nh6VvMz8phXxU3Bi7h6hqgywNFi1vZTfQNnS1RV".from_base58().unwrap();
    log!([bytes]);
    log!([bytes.len()]);
    log!([sha256(&bytes[..bytes.len() - 4])]);
    log!([dhash256(&bytes[..bytes.len() - 4])]);
    log!((hex::encode(&bytes)));

    let mut blake = VarBlake2b::new(20).unwrap();
    blake.input(&bytes[4..bytes.len() - 4]);
    log!([blake.vec_result()]);

    let bytes: Vec<u8> = "tz1faswCTDciRzE4oJ9jn2Vm2dvjeyA9fUzU".from_base58().unwrap();
    log!([bytes]);
    log!([bytes.len()]);
    log!([sha256(&bytes[..bytes.len() - 4])]);
    log!([dhash256(&bytes[..bytes.len() - 4])]);
    log!((hex::encode(&bytes)));
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
fn tezos_key_pair_from_to_string() {
    let key_pair = TezosKeyPair::ED25519(EdKeypair {
        secret: unwrap!(EdSecretKey::from_bytes(&[197, 109, 203, 119, 241, 255, 240, 13, 26, 31, 83, 48, 167, 122, 159, 31, 49, 207, 112, 250, 122, 214, 145, 162, 43, 94, 194, 140, 219, 35, 35, 80])),
        public: unwrap!(EdPublicKey::from_bytes(&[107, 106, 160, 0, 4, 28, 170, 101, 209, 223, 114, 53, 77, 50, 155, 234, 226, 167, 130, 197, 144, 33, 242, 92, 111, 64, 191, 74, 136, 120, 28, 27])),
    });

    assert_eq!("edsk4ArLQgBTLWG5FJmnGnT689VKoqhXwmDPBuGx3z4cvwU9MmrPZZ", key_pair.to_string());
    assert_eq!(key_pair, unwrap!(TezosKeyPair::from_str("edsk4ArLQgBTLWG5FJmnGnT689VKoqhXwmDPBuGx3z4cvwU9MmrPZZ")));
}
