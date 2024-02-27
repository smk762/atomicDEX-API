use super::*;
use crate::coin_balance::{AddressBalanceStatus, HDAddressBalance, HDWalletBalanceOps};
use crate::coin_errors::{MyAddressError, ValidatePaymentError, ValidatePaymentResult};
use crate::eth::EthCoinType;
use crate::hd_confirm_address::HDConfirmAddress;
use crate::hd_pubkey::{ExtractExtendedPubkey, HDExtractPubkeyError, HDXPubExtractor};
use crate::hd_wallet::{AccountUpdatingError, AddressDerivingResult, HDAccountMut, HDAccountsMap,
                       NewAccountCreatingError, NewAddressDeriveConfirmError, NewAddressDerivingError};
use crate::hd_wallet_storage::{HDWalletCoinWithStorageOps, HDWalletStorageResult};
use crate::lp_price::get_base_price_in_rel;
use crate::rpc_command::init_withdraw::WithdrawTaskHandleShared;
use crate::utxo::rpc_clients::{electrum_script_hash, BlockHashOrHeight, UnspentInfo, UnspentMap, UtxoRpcClientEnum,
                               UtxoRpcClientOps, UtxoRpcResult};
use crate::utxo::spv::SimplePaymentVerification;
use crate::utxo::tx_cache::TxCacheResult;
use crate::utxo::utxo_withdraw::{InitUtxoWithdraw, StandardUtxoWithdraw, UtxoWithdraw};
use crate::watcher_common::validate_watcher_reward;
use crate::{CanRefundHtlc, CoinBalance, CoinWithDerivationMethod, ConfirmPaymentInput, DexFee, GenPreimageResult,
            GenTakerFundingSpendArgs, GenTakerPaymentSpendArgs, GetWithdrawSenderAddress, HDAccountAddressId,
            RawTransactionError, RawTransactionRequest, RawTransactionRes, RawTransactionResult,
            RefundFundingSecretArgs, RefundMakerPaymentArgs, RefundPaymentArgs, RewardTarget,
            SearchForSwapTxSpendInput, SendMakerPaymentArgs, SendMakerPaymentSpendPreimageInput, SendPaymentArgs,
            SendTakerFundingArgs, SignRawTransactionEnum, SignRawTransactionRequest, SignUtxoTransactionParams,
            SignatureError, SignatureResult, SpendMakerPaymentArgs, SpendPaymentArgs, SwapOps,
            SwapTxTypeWithSecretHash, TradePreimageValue, TransactionFut, TransactionResult, TxFeeDetails, TxGenError,
            TxMarshalingErr, TxPreimageWithSig, ValidateAddressResult, ValidateOtherPubKeyErr, ValidatePaymentFut,
            ValidatePaymentInput, ValidateSwapV2TxError, ValidateSwapV2TxResult, ValidateTakerFundingArgs,
            ValidateTakerFundingSpendPreimageError, ValidateTakerFundingSpendPreimageResult,
            ValidateTakerPaymentSpendPreimageError, ValidateTakerPaymentSpendPreimageResult,
            ValidateWatcherSpendInput, VerificationError, VerificationResult, WatcherSearchForSwapTxSpendInput,
            WatcherValidatePaymentInput, WatcherValidateTakerFeeInput, WithdrawFrom, WithdrawResult,
            WithdrawSenderAddress, EARLY_CONFIRMATION_ERR_LOG, INVALID_RECEIVER_ERR_LOG, INVALID_REFUND_TX_ERR_LOG,
            INVALID_SCRIPT_ERR_LOG, INVALID_SENDER_ERR_LOG, OLD_TRANSACTION_ERR_LOG};
use crate::{MmCoinEnum, WatcherReward, WatcherRewardError};
pub use bitcrypto::{dhash160, sha256, ChecksumType};
use bitcrypto::{dhash256, ripemd160};
use chain::constants::SEQUENCE_FINAL;
use chain::{OutPoint, TransactionInput, TransactionOutput};
use common::executor::Timer;
use common::jsonrpc_client::JsonRpcErrorType;
use common::log::{debug, error, warn};
use crypto::{Bip32DerPathOps, Bip44Chain, RpcDerivationPath, StandardHDPath, StandardHDPathError};
use futures::compat::Future01CompatExt;
use futures::future::{FutureExt, TryFutureExt};
use futures01::future::Either;
use itertools::Itertools;
use keys::bytes::Bytes;
#[cfg(test)] use keys::prefixes::{KMD_PREFIXES, T_QTUM_PREFIXES};
use keys::{Address, AddressBuilder, AddressBuilderOption, AddressFormat as UtxoAddressFormat, AddressFormat,
           AddressHashEnum, AddressScriptType, CompactSignature, Public, SegwitAddress};
use mm2_core::mm_ctx::MmArc;
use mm2_err_handle::prelude::*;
use mm2_number::bigdecimal_custom::CheckedDivision;
use mm2_number::{BigDecimal, MmNumber};
use primitives::hash::H512;
use rpc::v1::types::{Bytes as BytesJson, ToTxHash, TransactionInputEnum, H256 as H256Json};
use script::{Builder, Opcode, Script, ScriptAddress, TransactionInputSigner, UnsignedTransactionInput};
use secp256k1::{PublicKey, Signature as SecpSignature};
use serde_json::{self as json};
use serialization::{deserialize, serialize, serialize_with_flags, CoinVariant, CompactInteger, Serializable, Stream,
                    SERIALIZE_TRANSACTION_WITNESS};
use std::cmp::Ordering;
use std::collections::hash_map::{Entry, HashMap};
use std::str::FromStr;
use std::sync::atomic::Ordering as AtomicOrdering;
use utxo_signer::with_key_pair::{calc_and_sign_sighash, p2sh_spend, signature_hash_to_sign, SIGHASH_ALL,
                                 SIGHASH_SINGLE};
use utxo_signer::UtxoSignerOps;

pub use chain::Transaction as UtxoTx;

pub mod utxo_tx_history_v2_common;

pub const DEFAULT_FEE_VOUT: usize = 0;
pub const DEFAULT_SWAP_TX_SPEND_SIZE: u64 = 305;
pub const DEFAULT_SWAP_VOUT: usize = 0;
pub const DEFAULT_SWAP_VIN: usize = 0;
const MIN_BTC_TRADING_VOL: &str = "0.00777";

macro_rules! true_or {
    ($cond: expr, $etype: expr) => {
        if !$cond {
            return Err(MmError::new($etype));
        }
    };
}

lazy_static! {
    pub static ref HISTORY_TOO_LARGE_ERROR: Json = json!({
        "code": 1,
        "message": "history too large"
    });
}

pub const HISTORY_TOO_LARGE_ERR_CODE: i64 = -1;

pub async fn get_tx_fee(coin: &UtxoCoinFields) -> UtxoRpcResult<ActualTxFee> {
    let conf = &coin.conf;
    match &coin.tx_fee {
        TxFee::Dynamic(method) => {
            let fee = coin
                .rpc_client
                .estimate_fee_sat(coin.decimals, method, &conf.estimate_fee_mode, conf.estimate_fee_blocks)
                .compat()
                .await?;
            Ok(ActualTxFee::Dynamic(fee))
        },
        TxFee::FixedPerKb(satoshis) => Ok(ActualTxFee::FixedPerKb(*satoshis)),
    }
}

fn derive_address_with_cache<T>(
    coin: &T,
    hd_account: &UtxoHDAccount,
    hd_addresses_cache: &mut HashMap<HDAddressId, UtxoHDAddress>,
    hd_address_id: HDAddressId,
) -> AddressDerivingResult<UtxoHDAddress>
where
    T: UtxoCommonOps,
{
    // Check if the given HD address has been derived already.
    if let Some(hd_address) = hd_addresses_cache.get(&hd_address_id) {
        return Ok(hd_address.clone());
    }

    let change_child = hd_address_id.chain.to_child_number();
    let address_id_child = ChildNumber::from(hd_address_id.address_id);

    let derived_pubkey = hd_account
        .extended_pubkey
        .derive_child(change_child)?
        .derive_child(address_id_child)?;
    let address = coin.address_from_extended_pubkey(&derived_pubkey);
    let pubkey = Public::Compressed(H264::from(derived_pubkey.public_key().serialize()));

    let mut derivation_path = hd_account.account_derivation_path.to_derivation_path();
    derivation_path.push(change_child);
    derivation_path.push(address_id_child);

    let hd_address = HDAddress {
        address,
        pubkey,
        derivation_path,
    };

    // Cache the derived `hd_address`.
    hd_addresses_cache.insert(hd_address_id, hd_address.clone());
    Ok(hd_address)
}

/// [`HDWalletCoinOps::derive_addresses`] native implementation.
///
/// # Important
///
/// The [`HDAddressesCache::cache`] mutex is locked once for the entire duration of this function.
#[cfg(not(target_arch = "wasm32"))]
pub async fn derive_addresses<T, Ids>(
    coin: &T,
    hd_account: &UtxoHDAccount,
    address_ids: Ids,
) -> AddressDerivingResult<Vec<UtxoHDAddress>>
where
    T: UtxoCommonOps,
    Ids: Iterator<Item = HDAddressId>,
{
    let mut hd_addresses_cache = hd_account.derived_addresses.lock().await;
    address_ids
        .map(|hd_address_id| derive_address_with_cache(coin, hd_account, &mut hd_addresses_cache, hd_address_id))
        .collect()
}

/// [`HDWalletCoinOps::derive_addresses`] WASM implementation.
///
/// # Important
///
/// This function locks [`HDAddressesCache::cache`] mutex at each iteration.
///
/// # Performance
///
/// Locking the [`HDAddressesCache::cache`] mutex at each iteration may significantly degrade performance.
/// But this is required at least for now due the facts that:
/// 1) mm2 runs in the same thread as `KomodoPlatform/air_dex` runs;
/// 2) [`ExtendedPublicKey::derive_child`] is a synchronous operation, and it takes a long time.
/// So we need to periodically invoke Javascript runtime to handle UI events and other asynchronous tasks.
#[cfg(target_arch = "wasm32")]
pub async fn derive_addresses<T, Ids>(
    coin: &T,
    hd_account: &UtxoHDAccount,
    address_ids: Ids,
) -> AddressDerivingResult<Vec<UtxoHDAddress>>
where
    T: UtxoCommonOps,
    Ids: Iterator<Item = HDAddressId>,
{
    let mut result = Vec::new();
    for hd_address_id in address_ids {
        let mut hd_addresses_cache = hd_account.derived_addresses.lock().await;

        let hd_address = derive_address_with_cache(coin, hd_account, &mut hd_addresses_cache, hd_address_id)?;
        result.push(hd_address);
    }

    Ok(result)
}

pub async fn generate_and_confirm_new_address<Coin, ConfirmAddress>(
    coin: &Coin,
    hd_wallet: &Coin::HDWallet,
    hd_account: &mut Coin::HDAccount,
    chain: Bip44Chain,
    confirm_address: &ConfirmAddress,
) -> MmResult<HDAddress<Coin::Address, Coin::Pubkey>, NewAddressDeriveConfirmError>
where
    Coin: HDWalletCoinWithStorageOps<Address = Address, HDWallet = UtxoHDWallet, HDAccount = UtxoHDAccount>
        + AsRef<UtxoCoinFields>
        + Sync,
    ConfirmAddress: HDConfirmAddress,
{
    use crate::hd_wallet::inner_impl;

    let inner_impl::NewAddress {
        address,
        new_known_addresses_number,
    } = inner_impl::generate_new_address_immutable(coin, hd_wallet, hd_account, chain).await?;

    let trezor_coin = coin.as_ref().conf.trezor_coin.clone().or_mm_err(|| {
        let ticker = &coin.as_ref().conf.ticker;
        let error = format!("'{ticker}' coin must contain the 'trezor_coin' field in the coins config");
        NewAddressDeriveConfirmError::DeriveError(NewAddressDerivingError::Internal(error))
    })?;
    let expected_address = address.address.to_string();
    // Ask the user to confirm if the given `expected_address` is the same as on the HW display.
    confirm_address
        .confirm_utxo_address(trezor_coin, address.derivation_path.clone(), expected_address)
        .await?;

    let actual_known_addresses_number = hd_account.known_addresses_number(chain)?;
    // Check if the actual `known_addresses_number` hasn't been changed while we waited for the user confirmation.
    // If the actual value is greater than the new one, we don't need to update.
    if actual_known_addresses_number < new_known_addresses_number {
        coin.set_known_addresses_number(hd_wallet, hd_account, chain, new_known_addresses_number)
            .await?;
    }

    Ok(address)
}

pub async fn create_new_account<'a, Coin, XPubExtractor>(
    coin: &Coin,
    hd_wallet: &'a UtxoHDWallet,
    xpub_extractor: &XPubExtractor,
) -> MmResult<HDAccountMut<'a, UtxoHDAccount>, NewAccountCreatingError>
where
    Coin: ExtractExtendedPubkey<ExtendedPublicKey = Secp256k1ExtendedPublicKey>
        + HDWalletCoinWithStorageOps<HDWallet = UtxoHDWallet, HDAccount = UtxoHDAccount>
        + Sync,
    XPubExtractor: HDXPubExtractor,
{
    const INIT_ACCOUNT_ID: u32 = 0;
    let new_account_id = hd_wallet
        .accounts
        .lock()
        .await
        .iter()
        // The last element of the BTreeMap has the max account index.
        .last()
        .map(|(account_id, _account)| *account_id + 1)
        .unwrap_or(INIT_ACCOUNT_ID);
    let max_accounts_number = hd_wallet.account_limit();
    if new_account_id >= max_accounts_number {
        return MmError::err(NewAccountCreatingError::AccountLimitReached { max_accounts_number });
    }

    let account_child_hardened = true;
    let account_child = ChildNumber::new(new_account_id, account_child_hardened)
        .map_to_mm(|e| NewAccountCreatingError::Internal(e.to_string()))?;

    let account_derivation_path: StandardHDPathToAccount = hd_wallet.derivation_path.derive(account_child)?;
    let account_pubkey = coin
        .extract_extended_pubkey(xpub_extractor, account_derivation_path.to_derivation_path())
        .await?;

    let new_account = UtxoHDAccount {
        account_id: new_account_id,
        extended_pubkey: account_pubkey,
        account_derivation_path,
        // We don't know how many addresses are used by the user at this moment.
        external_addresses_number: 0,
        internal_addresses_number: 0,
        derived_addresses: HDAddressesCache::default(),
    };

    let accounts = hd_wallet.accounts.lock().await;
    if accounts.contains_key(&new_account_id) {
        let error = format!(
            "Account '{}' has been activated while we proceed the 'create_new_account' function",
            new_account_id
        );
        return MmError::err(NewAccountCreatingError::Internal(error));
    }

    coin.upload_new_account(hd_wallet, new_account.to_storage_item())
        .await?;

    Ok(AsyncMutexGuard::map(accounts, |accounts| {
        accounts
            .entry(new_account_id)
            // the `entry` method should return [`Entry::Vacant`] due to the checks above
            .or_insert(new_account)
    }))
}

pub async fn set_known_addresses_number<T>(
    coin: &T,
    hd_wallet: &UtxoHDWallet,
    hd_account: &mut UtxoHDAccount,
    chain: Bip44Chain,
    new_known_addresses_number: u32,
) -> MmResult<(), AccountUpdatingError>
where
    T: HDWalletCoinWithStorageOps<HDWallet = UtxoHDWallet, HDAccount = UtxoHDAccount> + Sync,
{
    let max_addresses_number = hd_wallet.address_limit();
    if new_known_addresses_number >= max_addresses_number {
        return MmError::err(AccountUpdatingError::AddressLimitReached { max_addresses_number });
    }
    match chain {
        Bip44Chain::External => {
            coin.update_external_addresses_number(hd_wallet, hd_account.account_id, new_known_addresses_number)
                .await?;
            hd_account.external_addresses_number = new_known_addresses_number;
        },
        Bip44Chain::Internal => {
            coin.update_internal_addresses_number(hd_wallet, hd_account.account_id, new_known_addresses_number)
                .await?;
            hd_account.internal_addresses_number = new_known_addresses_number;
        },
    }
    Ok(())
}

pub async fn produce_hd_address_scanner<T>(coin: &T) -> BalanceResult<UtxoAddressScanner>
where
    T: AsRef<UtxoCoinFields>,
{
    Ok(UtxoAddressScanner::init(coin.as_ref().rpc_client.clone()).await?)
}

pub async fn scan_for_new_addresses<T>(
    coin: &T,
    hd_wallet: &T::HDWallet,
    hd_account: &mut T::HDAccount,
    address_scanner: &T::HDAddressScanner,
    gap_limit: u32,
) -> BalanceResult<Vec<HDAddressBalance>>
where
    T: HDWalletBalanceOps + Sync,
    T::Address: std::fmt::Display,
{
    let mut addresses = scan_for_new_addresses_impl(
        coin,
        hd_wallet,
        hd_account,
        address_scanner,
        Bip44Chain::External,
        gap_limit,
    )
    .await?;
    addresses.extend(
        scan_for_new_addresses_impl(
            coin,
            hd_wallet,
            hd_account,
            address_scanner,
            Bip44Chain::Internal,
            gap_limit,
        )
        .await?,
    );

    Ok(addresses)
}

/// Checks addresses that either had empty transaction history last time we checked or has not been checked before.
/// The checking stops at the moment when we find `gap_limit` consecutive empty addresses.
pub async fn scan_for_new_addresses_impl<T>(
    coin: &T,
    hd_wallet: &T::HDWallet,
    hd_account: &mut T::HDAccount,
    address_scanner: &T::HDAddressScanner,
    chain: Bip44Chain,
    gap_limit: u32,
) -> BalanceResult<Vec<HDAddressBalance>>
where
    T: HDWalletBalanceOps + Sync,
    T::Address: std::fmt::Display,
{
    let mut balances = Vec::with_capacity(gap_limit as usize);

    // Get the first unknown address id.
    let mut checking_address_id = hd_account
        .known_addresses_number(chain)
        // A UTXO coin should support both [`Bip44Chain::External`] and [`Bip44Chain::Internal`].
        .mm_err(|e| BalanceError::Internal(e.to_string()))?;

    let mut unused_addresses_counter = 0;
    let max_addresses_number = hd_wallet.address_limit();
    while checking_address_id < max_addresses_number && unused_addresses_counter <= gap_limit {
        let HDAddress {
            address: checking_address,
            derivation_path: checking_address_der_path,
            ..
        } = coin.derive_address(hd_account, chain, checking_address_id).await?;

        match coin.is_address_used(&checking_address, address_scanner).await? {
            // We found a non-empty address, so we have to fill up the balance list
            // with zeros starting from `last_non_empty_address_id = checking_address_id - unused_addresses_counter`.
            AddressBalanceStatus::Used(non_empty_balance) => {
                let last_non_empty_address_id = checking_address_id - unused_addresses_counter;

                // First, derive all empty addresses and put it into `balances` with default balance.
                let address_ids = (last_non_empty_address_id..checking_address_id)
                    .into_iter()
                    .map(|address_id| HDAddressId { chain, address_id });
                let empty_addresses =
                    coin.derive_addresses(hd_account, address_ids)
                        .await?
                        .into_iter()
                        .map(|empty_address| HDAddressBalance {
                            address: empty_address.address.to_string(),
                            derivation_path: RpcDerivationPath(empty_address.derivation_path),
                            chain,
                            balance: CoinBalance::default(),
                        });
                balances.extend(empty_addresses);

                // Then push this non-empty address.
                balances.push(HDAddressBalance {
                    address: checking_address.to_string(),
                    derivation_path: RpcDerivationPath(checking_address_der_path),
                    chain,
                    balance: non_empty_balance,
                });
                // Reset the counter of unused addresses to zero since we found a non-empty address.
                unused_addresses_counter = 0;
            },
            AddressBalanceStatus::NotUsed => unused_addresses_counter += 1,
        }

        checking_address_id += 1;
    }

    coin.set_known_addresses_number(
        hd_wallet,
        hd_account,
        chain,
        checking_address_id - unused_addresses_counter,
    )
    .await?;

    Ok(balances)
}

pub async fn all_known_addresses_balances<T>(
    coin: &T,
    hd_account: &T::HDAccount,
) -> BalanceResult<Vec<HDAddressBalance>>
where
    T: HDWalletBalanceOps + Sync,
    T::Address: std::fmt::Display + Clone,
{
    let external_addresses = hd_account
        .known_addresses_number(Bip44Chain::External)
        // A UTXO coin should support both [`Bip44Chain::External`] and [`Bip44Chain::Internal`].
        .mm_err(|e| BalanceError::Internal(e.to_string()))?;
    let internal_addresses = hd_account
        .known_addresses_number(Bip44Chain::Internal)
        // A UTXO coin should support both [`Bip44Chain::External`] and [`Bip44Chain::Internal`].
        .mm_err(|e| BalanceError::Internal(e.to_string()))?;

    let mut balances = coin
        .known_addresses_balances_with_ids(hd_account, Bip44Chain::External, 0..external_addresses)
        .await?;
    balances.extend(
        coin.known_addresses_balances_with_ids(hd_account, Bip44Chain::Internal, 0..internal_addresses)
            .await?,
    );

    Ok(balances)
}

pub async fn load_hd_accounts_from_storage(
    hd_wallet_storage: &HDWalletCoinStorage,
    derivation_path: &StandardHDPathToCoin,
) -> HDWalletStorageResult<HDAccountsMap<UtxoHDAccount>> {
    let accounts = hd_wallet_storage.load_all_accounts().await?;
    let res: HDWalletStorageResult<HDAccountsMap<UtxoHDAccount>> = accounts
        .iter()
        .map(|account_info| {
            let account = UtxoHDAccount::try_from_storage_item(derivation_path, account_info)?;
            Ok((account.account_id, account))
        })
        .collect();
    match res {
        Ok(accounts) => Ok(accounts),
        Err(e) if e.get_inner().is_deserializing_err() => {
            warn!("Error loading HD accounts from the storage: '{}'. Clear accounts", e);
            hd_wallet_storage.clear_accounts().await?;
            Ok(HDAccountsMap::new())
        },
        Err(e) => Err(e),
    }
}

/// Requests balance of the given `address`.
pub async fn address_balance<T>(coin: &T, address: &Address) -> BalanceResult<CoinBalance>
where
    T: UtxoCommonOps + GetUtxoListOps + MarketCoinOps,
{
    if coin.as_ref().check_utxo_maturity {
        let (unspents, _) = coin.get_mature_unspent_ordered_list(address).await?;
        return Ok(unspents.to_coin_balance(coin.as_ref().decimals));
    }

    let balance = coin
        .as_ref()
        .rpc_client
        .display_balance(address.clone(), coin.as_ref().decimals)
        .compat()
        .await?;

    Ok(CoinBalance {
        spendable: balance,
        unspendable: BigDecimal::from(0),
    })
}

/// Requests balances of the given `addresses`.
/// The pairs `(Address, CoinBalance)` are guaranteed to be in the same order in which they were requested.
pub async fn addresses_balances<T>(coin: &T, addresses: Vec<Address>) -> BalanceResult<Vec<(Address, CoinBalance)>>
where
    T: UtxoCommonOps + GetUtxoMapOps + MarketCoinOps,
{
    if coin.as_ref().check_utxo_maturity {
        let (unspents_map, _) = coin.get_mature_unspent_ordered_map(addresses.clone()).await?;
        addresses
            .into_iter()
            .map(|address| {
                let unspents = unspents_map.get(&address).or_mm_err(|| {
                    let error = format!("'get_mature_unspent_ordered_map' should have returned '{}'", address);
                    BalanceError::Internal(error)
                })?;
                let balance = unspents.to_coin_balance(coin.as_ref().decimals);
                Ok((address, balance))
            })
            .collect()
    } else {
        Ok(coin
            .as_ref()
            .rpc_client
            .display_balances(addresses.clone(), coin.as_ref().decimals)
            .compat()
            .await?
            .into_iter()
            .map(|(address, spendable)| {
                let unspendable = BigDecimal::from(0);
                let balance = CoinBalance { spendable, unspendable };
                (address, balance)
            })
            .collect())
    }
}

pub fn derivation_method(coin: &UtxoCoinFields) -> &DerivationMethod<Address, UtxoHDWallet> { &coin.derivation_method }

pub async fn extract_extended_pubkey<XPubExtractor>(
    conf: &UtxoCoinConf,
    xpub_extractor: &XPubExtractor,
    derivation_path: DerivationPath,
) -> MmResult<Secp256k1ExtendedPublicKey, HDExtractPubkeyError>
where
    XPubExtractor: HDXPubExtractor,
{
    let trezor_coin = conf
        .trezor_coin
        .clone()
        .or_mm_err(|| HDExtractPubkeyError::CoinDoesntSupportTrezor)?;
    let xpub = xpub_extractor.extract_utxo_xpub(trezor_coin, derivation_path).await?;
    Secp256k1ExtendedPublicKey::from_str(&xpub).map_to_mm(|e| HDExtractPubkeyError::InvalidXpub(e.to_string()))
}

/// returns the fee required to be paid for HTLC spend transaction
pub async fn get_htlc_spend_fee<T: UtxoCommonOps>(
    coin: &T,
    tx_size: u64,
    stage: &FeeApproxStage,
) -> UtxoRpcResult<u64> {
    let coin_fee = coin.get_tx_fee().await?;
    let mut fee = match coin_fee {
        // atomic swap payment spend transaction is slightly more than 300 bytes in average as of now
        ActualTxFee::Dynamic(fee_per_kb) => {
            let fee_per_kb = increase_dynamic_fee_by_stage(&coin, fee_per_kb, stage);
            (fee_per_kb * tx_size) / KILO_BYTE
        },
        // return satoshis here as swap spend transaction size is always less than 1 kb
        ActualTxFee::FixedPerKb(satoshis) => {
            let tx_size_kb = if tx_size % KILO_BYTE == 0 {
                tx_size / KILO_BYTE
            } else {
                tx_size / KILO_BYTE + 1
            };
            satoshis * tx_size_kb
        },
    };
    if coin.as_ref().conf.force_min_relay_fee {
        let relay_fee = coin.as_ref().rpc_client.get_relay_fee().compat().await?;
        let relay_fee_sat = sat_from_big_decimal(&relay_fee, coin.as_ref().decimals)?;
        if fee < relay_fee_sat {
            fee = relay_fee_sat;
        }
    }
    Ok(fee)
}

pub fn addresses_from_script<T: UtxoCommonOps>(coin: &T, script: &Script) -> Result<Vec<Address>, String> {
    let destinations: Vec<ScriptAddress> = try_s!(script.extract_destinations());

    let conf = &coin.as_ref().conf;

    let addresses = destinations
        .into_iter()
        .map(|dst| {
            let (addr_format, build_option) = match dst.kind {
                AddressScriptType::P2PKH => (
                    coin.addr_format_for_standard_scripts(),
                    AddressBuilderOption::BuildAsPubkeyHash,
                ),
                AddressScriptType::P2SH => (
                    coin.addr_format_for_standard_scripts(),
                    AddressBuilderOption::BuildAsScriptHash,
                ),
                AddressScriptType::P2WPKH => (UtxoAddressFormat::Segwit, AddressBuilderOption::BuildAsPubkeyHash),
                AddressScriptType::P2WSH => (UtxoAddressFormat::Segwit, AddressBuilderOption::BuildAsScriptHash),
            };

            AddressBuilder::new(
                addr_format,
                dst.hash,
                conf.checksum_type,
                conf.address_prefixes.clone(),
                conf.bech32_hrp.clone(),
            )
            .with_build_option(build_option)
            .build()
            .expect("valid address props")
        })
        .collect();

    Ok(addresses)
}

pub fn denominate_satoshis(coin: &UtxoCoinFields, satoshi: i64) -> f64 {
    satoshi as f64 / 10f64.powf(coin.decimals as f64)
}

pub fn base_coin_balance<T>(coin: &T) -> BalanceFut<BigDecimal>
where
    T: MarketCoinOps,
{
    coin.my_spendable_balance()
}

pub fn address_from_str_unchecked(coin: &UtxoCoinFields, address: &str) -> MmResult<Address, AddrFromStrError> {
    let mut errors = Vec::with_capacity(3);

    match Address::from_legacyaddress(address, &coin.conf.address_prefixes) {
        Ok(legacy) => return Ok(legacy),
        Err(e) => errors.push(e),
    };

    match Address::from_segwitaddress(address, coin.conf.checksum_type) {
        Ok(segwit) => return Ok(segwit),
        Err(e) => errors.push(e),
    }

    match Address::from_cashaddress(address, coin.conf.checksum_type, &coin.conf.address_prefixes) {
        Ok(cashaddress) => return Ok(cashaddress),
        Err(e) => errors.push(e),
    }

    MmError::err(AddrFromStrError::CannotDetermineFormat(errors))
}

pub fn my_public_key(coin: &UtxoCoinFields) -> Result<&Public, MmError<UnexpectedDerivationMethod>> {
    match coin.priv_key_policy {
        PrivKeyPolicy::Iguana(ref key_pair) => Ok(key_pair.public()),
        PrivKeyPolicy::HDWallet {
            activated_key: ref activated_key_pair,
            ..
        } => Ok(activated_key_pair.public()),
        // Hardware Wallets requires BIP32/BIP44 derivation path to extract a public key.
        PrivKeyPolicy::Trezor => MmError::err(UnexpectedDerivationMethod::Trezor),
        #[cfg(target_arch = "wasm32")]
        PrivKeyPolicy::Metamask(_) => MmError::err(UnexpectedDerivationMethod::UnsupportedError(
            "`PrivKeyPolicy::Metamask` is not supported in this context".to_string(),
        )),
    }
}

pub fn checked_address_from_str<T: UtxoCommonOps>(coin: &T, address: &str) -> MmResult<Address, AddrFromStrError> {
    let addr = address_from_str_unchecked(coin.as_ref(), address)?;
    check_withdraw_address_supported(coin, &addr)?;
    Ok(addr)
}

pub async fn get_current_mtp(coin: &UtxoCoinFields, coin_variant: CoinVariant) -> UtxoRpcResult<u32> {
    let current_block = coin.rpc_client.get_block_count().compat().await?;
    coin.rpc_client
        .get_median_time_past(current_block, coin.conf.mtp_block_count, coin_variant)
        .compat()
        .await
}

pub fn send_outputs_from_my_address<T>(coin: T, outputs: Vec<TransactionOutput>) -> TransactionFut
where
    T: UtxoCommonOps + GetUtxoListOps,
{
    let fut = send_outputs_from_my_address_impl(coin, outputs);
    Box::new(fut.boxed().compat().map(|tx| tx.into()))
}

pub fn tx_size_in_v_bytes(from_addr_format: &UtxoAddressFormat, tx: &UtxoTx) -> usize {
    let transaction_bytes = serialize(tx);
    // 2 bytes are used to indicate the length of signature and pubkey
    // total is 107
    let additional_len = 2 + MAX_DER_SIGNATURE_LEN + COMPRESSED_PUBKEY_LEN;
    // Virtual size of the transaction
    // https://bitcoin.stackexchange.com/questions/87275/how-to-calculate-segwit-transaction-fee-in-bytes/87276#87276
    match from_addr_format {
        UtxoAddressFormat::Segwit => {
            let base_size = transaction_bytes.len();
            // 4 additional bytes (2 for the marker and 2 for the flag) and 1 additional byte for every input in the witness for the SIGHASH flag
            let total_size = transaction_bytes.len() + 4 + tx.inputs().len() * (additional_len + 1);
            ((0.75 * base_size as f64) + (0.25 * total_size as f64)) as usize
        },
        _ => transaction_bytes.len() + tx.inputs().len() * additional_len,
    }
}

/// Implements building utxo script pubkey for an address with checking coin conf prefixes
pub fn output_script_checked(coin: &UtxoCoinFields, addr: &Address) -> MmResult<Script, UnsupportedAddr> {
    match addr.addr_format() {
        UtxoAddressFormat::Standard => {
            if addr.prefix() != &coin.conf.address_prefixes.p2pkh && addr.prefix() != &coin.conf.address_prefixes.p2sh {
                return MmError::err(UnsupportedAddr::PrefixError(coin.conf.ticker.clone()));
            }
        },
        UtxoAddressFormat::Segwit => match (coin.conf.bech32_hrp.as_ref(), addr.hrp().as_ref()) {
            (Some(conf_hrp), Some(addr_hrp)) => {
                if conf_hrp != addr_hrp {
                    return MmError::err(UnsupportedAddr::HrpError {
                        ticker: coin.conf.ticker.clone(),
                        hrp: addr_hrp.to_string(),
                    });
                }
            },
            (_, _) => {
                return MmError::err(UnsupportedAddr::HrpError {
                    ticker: coin.conf.ticker.clone(),
                    hrp: addr.hrp().clone().unwrap_or_else(|| "".to_owned()),
                });
            },
        },
        UtxoAddressFormat::CashAddress {
            network: _,
            pub_addr_prefix,
            p2sh_addr_prefix,
        } => {
            if AddressPrefix::from([*pub_addr_prefix]) != coin.conf.address_prefixes.p2pkh
                && AddressPrefix::from([*p2sh_addr_prefix]) != coin.conf.address_prefixes.p2sh
            {
                return MmError::err(UnsupportedAddr::PrefixError(coin.conf.ticker.clone()));
            }
        },
    }
    output_script(addr).map_to_mm(UnsupportedAddr::from)
}

pub struct UtxoTxBuilder<'a, T: AsRef<UtxoCoinFields> + UtxoTxGenerationOps> {
    coin: &'a T,
    from: Option<Address>,
    /// The available inputs that *can* be included in the resulting tx
    available_inputs: Vec<UnspentInfo>,
    fee_policy: FeePolicy,
    fee: Option<ActualTxFee>,
    gas_fee: Option<u64>,
    tx: TransactionInputSigner,
    change: u64,
    sum_inputs: u64,
    sum_outputs_value: u64,
    tx_fee: u64,
    min_relay_fee: Option<u64>,
    dust: Option<u64>,
}

impl<'a, T: AsRef<UtxoCoinFields> + UtxoTxGenerationOps> UtxoTxBuilder<'a, T> {
    pub fn new(coin: &'a T) -> Self {
        UtxoTxBuilder {
            tx: coin.as_ref().transaction_preimage(),
            coin,
            from: coin.as_ref().derivation_method.single_addr().cloned(),
            available_inputs: vec![],
            fee_policy: FeePolicy::SendExact,
            fee: None,
            gas_fee: None,
            change: 0,
            sum_inputs: 0,
            sum_outputs_value: 0,
            tx_fee: 0,
            min_relay_fee: None,
            dust: None,
        }
    }

    pub fn with_from_address(mut self, from: Address) -> Self {
        self.from = Some(from);
        self
    }

    pub fn with_dust(mut self, dust_amount: u64) -> Self {
        self.dust = Some(dust_amount);
        self
    }

    pub fn add_required_inputs(mut self, inputs: impl IntoIterator<Item = UnspentInfo>) -> Self {
        self.tx
            .inputs
            .extend(inputs.into_iter().map(|input| UnsignedTransactionInput {
                previous_output: input.outpoint,
                sequence: SEQUENCE_FINAL,
                amount: input.value,
                witness: Vec::new(),
            }));
        self
    }

    /// This function expects that utxos are sorted by amounts in ascending order
    /// Consider sorting before calling this function
    pub fn add_available_inputs(mut self, inputs: impl IntoIterator<Item = UnspentInfo>) -> Self {
        self.available_inputs.extend(inputs);
        self
    }

    pub fn add_outputs(mut self, outputs: impl IntoIterator<Item = TransactionOutput>) -> Self {
        self.tx.outputs.extend(outputs);
        self
    }

    pub fn with_fee_policy(mut self, new_policy: FeePolicy) -> Self {
        self.fee_policy = new_policy;
        self
    }

    pub fn with_fee(mut self, fee: ActualTxFee) -> Self {
        self.fee = Some(fee);
        self
    }

    /// Note `gas_fee` should be enough to execute all of the contract calls within UTXO outputs.
    /// QRC20 specific: `gas_fee` should be calculated by: gas_limit * gas_price * (count of contract calls),
    /// or should be sum of gas fee of all contract calls.
    pub fn with_gas_fee(mut self, gas_fee: u64) -> Self {
        self.gas_fee = Some(gas_fee);
        self
    }

    /// Recalculates fee and checks whether transaction is complete (inputs collected cover the outputs)
    fn update_fee_and_check_completeness(
        &mut self,
        from_addr_format: &UtxoAddressFormat,
        actual_tx_fee: &ActualTxFee,
    ) -> bool {
        self.tx_fee = match &actual_tx_fee {
            ActualTxFee::Dynamic(f) => {
                let transaction = UtxoTx::from(self.tx.clone());
                let v_size = tx_size_in_v_bytes(from_addr_format, &transaction);
                (f * v_size as u64) / KILO_BYTE
            },
            ActualTxFee::FixedPerKb(f) => {
                let transaction = UtxoTx::from(self.tx.clone());
                let v_size = tx_size_in_v_bytes(from_addr_format, &transaction) as u64;
                let v_size_kb = if v_size % KILO_BYTE == 0 {
                    v_size / KILO_BYTE
                } else {
                    v_size / KILO_BYTE + 1
                };
                f * v_size_kb
            },
        };

        match self.fee_policy {
            FeePolicy::SendExact => {
                let mut outputs_plus_fee = self.sum_outputs_value + self.tx_fee;
                if self.sum_inputs >= outputs_plus_fee {
                    self.change = self.sum_inputs - outputs_plus_fee;
                    if self.change > self.dust() {
                        // there will be change output
                        if let ActualTxFee::Dynamic(ref f) = actual_tx_fee {
                            self.tx_fee += (f * P2PKH_OUTPUT_LEN) / KILO_BYTE;
                            outputs_plus_fee += (f * P2PKH_OUTPUT_LEN) / KILO_BYTE;
                        }
                    }
                    if let Some(min_relay) = self.min_relay_fee {
                        if self.tx_fee < min_relay {
                            outputs_plus_fee -= self.tx_fee;
                            outputs_plus_fee += min_relay;
                            self.tx_fee = min_relay;
                        }
                    }
                    self.sum_inputs >= outputs_plus_fee
                } else {
                    false
                }
            },
            FeePolicy::DeductFromOutput(_) => {
                if self.sum_inputs >= self.sum_outputs_value {
                    self.change = self.sum_inputs - self.sum_outputs_value;
                    if self.change > self.dust() {
                        if let ActualTxFee::Dynamic(ref f) = actual_tx_fee {
                            self.tx_fee += (f * P2PKH_OUTPUT_LEN) / KILO_BYTE;
                        }
                    }
                    if let Some(min_relay) = self.min_relay_fee {
                        if self.tx_fee < min_relay {
                            self.tx_fee = min_relay;
                        }
                    }
                    true
                } else {
                    false
                }
            },
        }
    }

    fn dust(&self) -> u64 {
        match self.dust {
            Some(dust) => dust,
            None => self.coin.as_ref().dust_amount,
        }
    }

    /// Generates unsigned transaction (TransactionInputSigner) from specified utxos and outputs.
    /// sends the change (inputs amount - outputs amount) to the [`UtxoTxBuilder::from`] address.
    /// Also returns additional transaction data
    pub async fn build(mut self) -> GenerateTxResult {
        let coin = self.coin;
        let dust: u64 = self.dust();
        let from = self
            .from
            .clone()
            .or_mm_err(|| GenerateTxError::Internal("'from' address is not specified".to_owned()))?;
        let change_script_pubkey = output_script(&from).map(|script| script.to_bytes())?;

        let actual_tx_fee = match self.fee {
            Some(fee) => fee,
            None => coin.get_tx_fee().await?,
        };

        true_or!(!self.tx.outputs.is_empty(), GenerateTxError::EmptyOutputs);

        let mut received_by_me = 0;
        for output in self.tx.outputs.iter() {
            let script: Script = output.script_pubkey.clone().into();
            if script.opcodes().next() != Some(Ok(Opcode::OP_RETURN)) {
                true_or!(output.value >= dust, GenerateTxError::OutputValueLessThanDust {
                    value: output.value,
                    dust
                });
            }
            self.sum_outputs_value += output.value;
            if output.script_pubkey == change_script_pubkey {
                received_by_me += output.value;
            }
        }

        if let Some(gas_fee) = self.gas_fee {
            self.sum_outputs_value += gas_fee;
        }

        true_or!(
            !self.available_inputs.is_empty() || !self.tx.inputs.is_empty(),
            GenerateTxError::EmptyUtxoSet {
                required: self.sum_outputs_value
            }
        );

        self.min_relay_fee = if coin.as_ref().conf.force_min_relay_fee {
            let fee_dec = coin.as_ref().rpc_client.get_relay_fee().compat().await?;
            let min_relay_fee = sat_from_big_decimal(&fee_dec, coin.as_ref().decimals)?;
            Some(min_relay_fee)
        } else {
            None
        };

        for utxo in self.available_inputs.clone() {
            self.tx.inputs.push(UnsignedTransactionInput {
                previous_output: utxo.outpoint,
                sequence: SEQUENCE_FINAL,
                amount: utxo.value,
                witness: vec![],
            });
            self.sum_inputs += utxo.value;

            if self.update_fee_and_check_completeness(from.addr_format(), &actual_tx_fee) {
                break;
            }
        }

        match self.fee_policy {
            FeePolicy::SendExact => self.sum_outputs_value += self.tx_fee,
            FeePolicy::DeductFromOutput(i) => {
                let min_output = self.tx_fee + dust;
                let val = self.tx.outputs[i].value;
                true_or!(val >= min_output, GenerateTxError::DeductFeeFromOutputFailed {
                    output_idx: i,
                    output_value: val,
                    required: min_output,
                });
                self.tx.outputs[i].value -= self.tx_fee;
                if self.tx.outputs[i].script_pubkey == change_script_pubkey {
                    received_by_me -= self.tx_fee;
                }
            },
        };
        true_or!(
            self.sum_inputs >= self.sum_outputs_value,
            GenerateTxError::NotEnoughUtxos {
                sum_utxos: self.sum_inputs,
                required: self.sum_outputs_value
            }
        );

        let change = self.sum_inputs - self.sum_outputs_value;
        let unused_change = if change > dust {
            self.tx.outputs.push({
                TransactionOutput {
                    value: change,
                    script_pubkey: change_script_pubkey.clone(),
                }
            });
            received_by_me += change;
            0
        } else {
            change
        };

        let data = AdditionalTxData {
            fee_amount: self.tx_fee,
            received_by_me,
            spent_by_me: self.sum_inputs,
            unused_change,
            // will be changed if the ticker is KMD
            kmd_rewards: None,
        };

        Ok(coin
            .calc_interest_if_required(self.tx, data, change_script_pubkey, dust)
            .await?)
    }

    /// Generates unsigned transaction (TransactionInputSigner) from specified utxos and outputs.
    /// Adds or updates inputs with UnspentInfo
    /// Does not do any checks or add any outputs
    pub async fn build_unchecked(mut self) -> Result<TransactionInputSigner, MmError<GenerateTxError>> {
        for output in self.tx.outputs.iter() {
            self.sum_outputs_value += output.value;
        }

        true_or!(
            !self.available_inputs.is_empty() || !self.tx.inputs.is_empty(),
            GenerateTxError::EmptyUtxoSet {
                required: self.sum_outputs_value
            }
        );

        for utxo in self.available_inputs.clone() {
            if let Some(input) = self
                .tx
                .inputs
                .iter_mut()
                .find(|input| input.previous_output == utxo.outpoint)
            {
                input.amount = utxo.value;
            } else {
                self.tx.inputs.push(UnsignedTransactionInput {
                    previous_output: utxo.outpoint,
                    sequence: SEQUENCE_FINAL,
                    amount: utxo.value,
                    witness: vec![],
                });
            }
        }

        Ok(self.tx)
    }

    pub fn with_transaction_input_signer(mut self, tx_input_signer: TransactionInputSigner) -> Self {
        self.tx = tx_input_signer;
        self
    }
}

/// Calculates interest if the coin is KMD
/// Adds the value to existing output to my_script_pub or creates additional interest output
/// returns transaction and data as is if the coin is not KMD
pub async fn calc_interest_if_required<T: UtxoCommonOps>(
    coin: &T,
    mut unsigned: TransactionInputSigner,
    mut data: AdditionalTxData,
    my_script_pub: Bytes,
    dust: u64,
) -> UtxoRpcResult<(TransactionInputSigner, AdditionalTxData)> {
    if coin.as_ref().conf.ticker != "KMD" {
        return Ok((unsigned, data));
    }
    unsigned.lock_time = coin.get_current_mtp().await?;
    let mut interest = 0;
    for input in unsigned.inputs.iter() {
        let prev_hash = input.previous_output.hash.reversed().into();
        let tx = coin
            .as_ref()
            .rpc_client
            .get_verbose_transaction(&prev_hash)
            .compat()
            .await?;
        if let Ok(output_interest) =
            kmd_interest(tx.height, input.amount, tx.locktime as u64, unsigned.lock_time as u64)
        {
            interest += output_interest;
        };
    }
    if interest > 0 {
        data.received_by_me += interest;
        let mut output_to_me = unsigned
            .outputs
            .iter_mut()
            .find(|out| out.script_pubkey == my_script_pub);
        // add calculated interest to existing output to my address
        // or create the new one if it's not found
        match output_to_me {
            Some(ref mut output) => output.value += interest,
            None => {
                let maybe_change_output_value = interest + data.unused_change;
                if maybe_change_output_value > dust {
                    let change_output = TransactionOutput {
                        script_pubkey: my_script_pub,
                        value: maybe_change_output_value,
                    };
                    unsigned.outputs.push(change_output);
                    data.unused_change = 0;
                } else {
                    data.unused_change += interest;
                }
            },
        };
    } else {
        // if interest is zero attempt to set the lowest possible lock_time to claim it later
        unsigned.lock_time = now_sec_u32() - 3600 + 777 * 2;
    }
    let rewards_amount = big_decimal_from_sat_unsigned(interest, coin.as_ref().decimals);
    data.kmd_rewards = Some(KmdRewardsDetails::claimed_by_me(rewards_amount));
    Ok((unsigned, data))
}

pub struct P2SHSpendingTxInput<'a> {
    prev_transaction: UtxoTx,
    redeem_script: Bytes,
    outputs: Vec<TransactionOutput>,
    script_data: Script,
    sequence: u32,
    lock_time: u32,
    keypair: &'a KeyPair,
}

enum LocktimeSetting {
    CalcByHtlcLocktime(u32),
    UseExact(u32),
}

enum NTimeSetting {
    UseNow,
    UseValue(Option<u32>),
}

enum FundingSpendFeeSetting {
    GetFromCoin,
    UseExact(u64),
}

async fn p2sh_spending_tx_preimage<T: UtxoCommonOps>(
    coin: &T,
    prev_tx: &UtxoTx,
    lock_time: LocktimeSetting,
    set_n_time: NTimeSetting,
    sequence: u32,
    outputs: Vec<TransactionOutput>,
) -> Result<TransactionInputSigner, String> {
    let amount = try_s!(prev_tx.first_output()).value;
    let lock_time = match lock_time {
        LocktimeSetting::CalcByHtlcLocktime(lock) => try_s!(coin.p2sh_tx_locktime(lock).await),
        LocktimeSetting::UseExact(lock) => lock,
    };
    let n_time = if coin.as_ref().conf.is_pos {
        match set_n_time {
            NTimeSetting::UseNow => Some(now_sec_u32()),
            NTimeSetting::UseValue(value) => value,
        }
    } else {
        None
    };
    let str_d_zeel = if coin.as_ref().conf.ticker == "NAV" {
        Some("".into())
    } else {
        None
    };
    let hash_algo = coin.as_ref().tx_hash_algo.into();
    Ok(TransactionInputSigner {
        lock_time,
        version: coin.as_ref().conf.tx_version,
        n_time,
        overwintered: coin.as_ref().conf.overwintered,
        inputs: vec![UnsignedTransactionInput {
            sequence,
            previous_output: OutPoint {
                hash: prev_tx.hash(),
                index: DEFAULT_SWAP_VOUT as u32,
            },
            amount,
            witness: Vec::new(),
        }],
        outputs,
        expiry_height: 0,
        join_splits: vec![],
        shielded_spends: vec![],
        shielded_outputs: vec![],
        value_balance: 0,
        version_group_id: coin.as_ref().conf.version_group_id,
        consensus_branch_id: coin.as_ref().conf.consensus_branch_id,
        zcash: coin.as_ref().conf.zcash,
        posv: coin.as_ref().conf.is_posv,
        str_d_zeel,
        hash_algo,
    })
}

pub async fn p2sh_spending_tx<T: UtxoCommonOps>(coin: &T, input: P2SHSpendingTxInput<'_>) -> Result<UtxoTx, String> {
    let unsigned = try_s!(
        p2sh_spending_tx_preimage(
            coin,
            &input.prev_transaction,
            LocktimeSetting::CalcByHtlcLocktime(input.lock_time),
            NTimeSetting::UseNow,
            input.sequence,
            input.outputs
        )
        .await
    );
    let signed_input = try_s!(p2sh_spend(
        &unsigned,
        DEFAULT_SWAP_VOUT,
        input.keypair,
        input.script_data,
        input.redeem_script.into(),
        coin.as_ref().conf.signature_version,
        coin.as_ref().conf.fork_id
    ));
    Ok(UtxoTx {
        version: unsigned.version,
        n_time: unsigned.n_time,
        overwintered: unsigned.overwintered,
        lock_time: unsigned.lock_time,
        inputs: vec![signed_input],
        outputs: unsigned.outputs,
        expiry_height: unsigned.expiry_height,
        join_splits: vec![],
        shielded_spends: vec![],
        shielded_outputs: vec![],
        value_balance: 0,
        version_group_id: coin.as_ref().conf.version_group_id,
        binding_sig: H512::default(),
        join_split_sig: H512::default(),
        join_split_pubkey: H256::default(),
        zcash: coin.as_ref().conf.zcash,
        posv: coin.as_ref().conf.is_posv,
        str_d_zeel: unsigned.str_d_zeel,
        tx_hash_algo: unsigned.hash_algo.into(),
    })
}

type GenPreimageResInner = MmResult<TransactionInputSigner, TxGenError>;

async fn gen_taker_funding_spend_preimage<T: UtxoCommonOps>(
    coin: &T,
    args: &GenTakerFundingSpendArgs<'_, T>,
    n_time: NTimeSetting,
    fee: FundingSpendFeeSetting,
) -> GenPreimageResInner {
    let payment_time_lock = args
        .taker_payment_time_lock
        .try_into()
        .map_to_mm(|e: TryFromIntError| TxGenError::LocktimeOverflow(e.to_string()))?;

    let payment_redeem_script = swap_proto_v2_scripts::taker_payment_script(
        payment_time_lock,
        args.maker_secret_hash,
        args.taker_pub,
        args.maker_pub,
    );

    let funding_amount = args
        .funding_tx
        .first_output()
        .map_to_mm(|_| TxGenError::PrevTxIsNotValid("Funding tx has no outputs".into()))?
        .value;

    let fee = match fee {
        FundingSpendFeeSetting::GetFromCoin => {
            coin.get_htlc_spend_fee(DEFAULT_SWAP_TX_SPEND_SIZE, &FeeApproxStage::WithoutApprox)
                .await?
        },
        FundingSpendFeeSetting::UseExact(f) => f,
    };

    let fee_plus_dust = fee + coin.as_ref().dust_amount;
    if funding_amount < fee_plus_dust {
        return MmError::err(TxGenError::TxFeeTooHigh(format!(
            "Fee + dust {} is larger than funding amount {}",
            fee_plus_dust, funding_amount
        )));
    }

    let payment_output = TransactionOutput {
        value: funding_amount - fee,
        script_pubkey: Builder::build_p2sh(&AddressHashEnum::AddressHash(dhash160(&payment_redeem_script))).to_bytes(),
    };

    p2sh_spending_tx_preimage(
        coin,
        args.funding_tx,
        LocktimeSetting::UseExact(0),
        n_time,
        SEQUENCE_FINAL,
        vec![payment_output],
    )
    .await
    .map_to_mm(TxGenError::Legacy)
}

pub async fn gen_and_sign_taker_funding_spend_preimage<T: UtxoCommonOps>(
    coin: &T,
    args: &GenTakerFundingSpendArgs<'_, T>,
    htlc_keypair: &KeyPair,
) -> GenPreimageResult<T> {
    let funding_time_lock = args
        .funding_time_lock
        .try_into()
        .map_to_mm(|e: TryFromIntError| TxGenError::LocktimeOverflow(e.to_string()))?;

    let preimage =
        gen_taker_funding_spend_preimage(coin, args, NTimeSetting::UseNow, FundingSpendFeeSetting::GetFromCoin).await?;

    let redeem_script = swap_proto_v2_scripts::taker_funding_script(
        funding_time_lock,
        args.taker_secret_hash,
        args.taker_pub,
        args.maker_pub,
    );
    let signature = calc_and_sign_sighash(
        &preimage,
        DEFAULT_SWAP_VOUT,
        &redeem_script,
        htlc_keypair,
        coin.as_ref().conf.signature_version,
        SIGHASH_ALL,
        coin.as_ref().conf.fork_id,
    )?;
    Ok(TxPreimageWithSig {
        preimage: preimage.into(),
        signature: signature.take().into(),
    })
}

/// Common implementation of taker funding spend preimage validation for UTXO coins.
/// Checks maker's signature and compares received preimage with the expected tx.
pub async fn validate_taker_funding_spend_preimage<T: UtxoCommonOps + SwapOps>(
    coin: &T,
    gen_args: &GenTakerFundingSpendArgs<'_, T>,
    preimage: &TxPreimageWithSig<T>,
) -> ValidateTakerFundingSpendPreimageResult {
    let funding_amount = gen_args
        .funding_tx
        .first_output()
        .map_to_mm(|_| ValidateTakerFundingSpendPreimageError::FundingTxNoOutputs)?
        .value;

    let payment_amount = preimage
        .preimage
        .first_output()
        .map_to_mm(|_| ValidateTakerFundingSpendPreimageError::InvalidPreimage("Preimage has no outputs".into()))?
        .value;

    if payment_amount > funding_amount {
        return MmError::err(ValidateTakerFundingSpendPreimageError::InvalidPreimage(format!(
            "Preimage output {} larger than funding input {}",
            payment_amount, funding_amount
        )));
    }

    let expected_fee = coin
        .get_htlc_spend_fee(DEFAULT_SWAP_TX_SPEND_SIZE, &FeeApproxStage::WithoutApprox)
        .await?;

    let actual_fee = funding_amount - payment_amount;

    let fee_div = expected_fee as f64 / actual_fee as f64;

    if !(0.9..=1.1).contains(&fee_div) {
        return MmError::err(ValidateTakerFundingSpendPreimageError::UnexpectedPreimageFee(format!(
            "Too large difference between expected {} and actual {} fees",
            expected_fee, actual_fee
        )));
    }

    let expected_preimage = gen_taker_funding_spend_preimage(
        coin,
        gen_args,
        NTimeSetting::UseValue(preimage.preimage.n_time),
        FundingSpendFeeSetting::UseExact(actual_fee),
    )
    .await?;

    let funding_time_lock = gen_args
        .funding_time_lock
        .try_into()
        .map_to_mm(|e: TryFromIntError| ValidateTakerFundingSpendPreimageError::LocktimeOverflow(e.to_string()))?;
    let redeem_script = swap_proto_v2_scripts::taker_funding_script(
        funding_time_lock,
        gen_args.taker_secret_hash,
        gen_args.taker_pub,
        gen_args.maker_pub,
    );
    let sig_hash = signature_hash_to_sign(
        &expected_preimage,
        DEFAULT_SWAP_VOUT,
        &redeem_script,
        coin.as_ref().conf.signature_version,
        SIGHASH_ALL,
        coin.as_ref().conf.fork_id,
    )?;

    if !gen_args
        .maker_pub
        .verify(&sig_hash, &preimage.signature)
        .map_to_mm(|e| ValidateTakerFundingSpendPreimageError::SignatureVerificationFailure(e.to_string()))?
    {
        return MmError::err(ValidateTakerFundingSpendPreimageError::InvalidMakerSignature);
    };
    let expected_preimage_tx: UtxoTx = expected_preimage.into();
    if expected_preimage_tx != preimage.preimage {
        return MmError::err(ValidateTakerFundingSpendPreimageError::InvalidPreimage(
            "Preimage is not equal to expected".into(),
        ));
    }
    Ok(())
}

/// Common implementation of taker funding spend finalization and broadcast for UTXO coins.
pub async fn sign_and_send_taker_funding_spend<T: UtxoCommonOps>(
    coin: &T,
    preimage: &TxPreimageWithSig<T>,
    gen_args: &GenTakerFundingSpendArgs<'_, T>,
    htlc_keypair: &KeyPair,
) -> Result<UtxoTx, TransactionErr> {
    let redeem_script = swap_proto_v2_scripts::taker_funding_script(
        try_tx_s!(gen_args.funding_time_lock.try_into()),
        gen_args.taker_secret_hash,
        gen_args.taker_pub,
        gen_args.maker_pub,
    );

    let mut signer: TransactionInputSigner = preimage.preimage.clone().into();
    let payment_input = try_tx_s!(signer.inputs.first_mut().ok_or("Preimage doesn't have inputs"));
    let funding_output = try_tx_s!(gen_args.funding_tx.first_output());
    payment_input.amount = funding_output.value;
    signer.consensus_branch_id = coin.as_ref().conf.consensus_branch_id;

    let taker_signature = try_tx_s!(calc_and_sign_sighash(
        &signer,
        DEFAULT_SWAP_VOUT,
        &redeem_script,
        htlc_keypair,
        coin.as_ref().conf.signature_version,
        SIGHASH_ALL,
        coin.as_ref().conf.fork_id
    ));
    let sig_hash_all_fork_id = (SIGHASH_ALL | coin.as_ref().conf.fork_id) as u8;

    let mut maker_signature_with_sighash = preimage.signature.to_vec();
    maker_signature_with_sighash.push(sig_hash_all_fork_id);
    drop_mutability!(maker_signature_with_sighash);

    let mut taker_signature_with_sighash: Vec<u8> = taker_signature.take();
    taker_signature_with_sighash.push(sig_hash_all_fork_id);
    drop_mutability!(taker_signature_with_sighash);

    let script_sig = Builder::default()
        .push_data(&maker_signature_with_sighash)
        .push_data(&taker_signature_with_sighash)
        .push_opcode(Opcode::OP_1)
        .push_opcode(Opcode::OP_0)
        .push_data(&redeem_script)
        .into_bytes();
    let mut final_tx: UtxoTx = signer.into();
    let final_tx_input = try_tx_s!(final_tx.inputs.first_mut().ok_or("Final tx doesn't have inputs"));
    final_tx_input.script_sig = script_sig;
    drop_mutability!(final_tx);

    if let UtxoRpcClientEnum::Native(client) = &coin.as_ref().rpc_client {
        let payment_redeem_script = swap_proto_v2_scripts::taker_payment_script(
            try_tx_s!(gen_args.taker_payment_time_lock.try_into()),
            gen_args.maker_secret_hash,
            gen_args.taker_pub,
            gen_args.maker_pub,
        );
        let payment_address = AddressBuilder::new(
            UtxoAddressFormat::Standard,
            AddressHashEnum::AddressHash(dhash160(&payment_redeem_script)),
            coin.as_ref().conf.checksum_type,
            coin.as_ref().conf.address_prefixes.clone(),
            coin.as_ref().conf.bech32_hrp.clone(),
        )
        .as_sh()
        .build()
        .map_err(TransactionErr::Plain)?;
        let payment_address_str = payment_address.to_string();
        try_tx_s!(
            client
                .import_address(&payment_address_str, &payment_address_str, false)
                .compat()
                .await
        );
    }

    try_tx_s!(coin.broadcast_tx(&final_tx).await, final_tx);
    Ok(final_tx)
}

async fn gen_taker_payment_spend_preimage<T: UtxoCommonOps>(
    coin: &T,
    args: &GenTakerPaymentSpendArgs<'_, T>,
    n_time: NTimeSetting,
) -> GenPreimageResInner {
    let dex_fee_address = address_from_raw_pubkey(
        args.dex_fee_pub,
        coin.as_ref().conf.address_prefixes.clone(),
        coin.as_ref().conf.checksum_type,
        coin.as_ref().conf.bech32_hrp.clone(),
        coin.addr_format().clone(),
    )
    .map_to_mm(|e| TxGenError::AddressDerivation(format!("Failed to derive dex_fee_address: {}", e)))?;

    let mut outputs = generate_taker_fee_tx_outputs(coin.as_ref().decimals, dex_fee_address.hash(), args.dex_fee)?;
    if let DexFee::WithBurn { .. } = args.dex_fee {
        let script = output_script(args.maker_address).map_to_mm(|e| {
            TxGenError::Other(format!(
                "Couldn't generate output script for maker address {}, error {}",
                args.maker_address, e
            ))
        })?;
        let tx_fee = coin
            .get_htlc_spend_fee(DEFAULT_SWAP_TX_SPEND_SIZE, &FeeApproxStage::WithoutApprox)
            .await?;
        let maker_value = args
            .taker_tx
            .first_output()
            .map_to_mm(|e| TxGenError::PrevTxIsNotValid(e.to_string()))?
            .value
            - outputs[0].value
            - outputs[1].value
            - tx_fee;
        outputs.push(TransactionOutput {
            value: maker_value,
            script_pubkey: script.to_bytes(),
        })
    }

    p2sh_spending_tx_preimage(
        coin,
        args.taker_tx,
        LocktimeSetting::UseExact(0),
        n_time,
        SEQUENCE_FINAL,
        outputs,
    )
    .await
    .map_to_mm(TxGenError::Legacy)
}

pub async fn gen_and_sign_taker_payment_spend_preimage<T: UtxoCommonOps>(
    coin: &T,
    args: &GenTakerPaymentSpendArgs<'_, T>,
    htlc_keypair: &KeyPair,
) -> GenPreimageResult<T> {
    let time_lock = args
        .time_lock
        .try_into()
        .map_to_mm(|e: TryFromIntError| TxGenError::LocktimeOverflow(e.to_string()))?;

    let preimage = gen_taker_payment_spend_preimage(coin, args, NTimeSetting::UseNow).await?;

    let redeem_script =
        swap_proto_v2_scripts::taker_payment_script(time_lock, args.maker_secret_hash, args.taker_pub, args.maker_pub);

    let sig_hash_type = match args.dex_fee {
        DexFee::Standard(_) => SIGHASH_SINGLE,
        DexFee::WithBurn { .. } => SIGHASH_ALL,
    };

    let signature = calc_and_sign_sighash(
        &preimage,
        DEFAULT_SWAP_VOUT,
        &redeem_script,
        htlc_keypair,
        coin.as_ref().conf.signature_version,
        sig_hash_type,
        coin.as_ref().conf.fork_id,
    )?;
    Ok(TxPreimageWithSig {
        preimage: preimage.into(),
        signature: signature.take().into(),
    })
}

/// Common implementation of taker payment spend preimage validation for UTXO coins.
/// Checks taker's signature and compares received preimage with the expected tx.
pub async fn validate_taker_payment_spend_preimage<T: UtxoCommonOps + SwapOps>(
    coin: &T,
    gen_args: &GenTakerPaymentSpendArgs<'_, T>,
    preimage: &TxPreimageWithSig<T>,
) -> ValidateTakerPaymentSpendPreimageResult {
    // Here, we have to use the exact lock time from the preimage because maker
    // can get different values (e.g. if MTP advances during preimage exchange/fee rate changes)
    let expected_preimage =
        gen_taker_payment_spend_preimage(coin, gen_args, NTimeSetting::UseValue(preimage.preimage.n_time)).await?;

    let time_lock = gen_args
        .time_lock
        .try_into()
        .map_to_mm(|e: TryFromIntError| ValidateTakerPaymentSpendPreimageError::LocktimeOverflow(e.to_string()))?;
    let redeem_script = swap_proto_v2_scripts::taker_payment_script(
        time_lock,
        gen_args.maker_secret_hash,
        gen_args.taker_pub,
        gen_args.maker_pub,
    );

    let sig_hash_type = match gen_args.dex_fee {
        DexFee::Standard(_) => SIGHASH_SINGLE,
        DexFee::WithBurn { .. } => SIGHASH_ALL,
    };

    let sig_hash = signature_hash_to_sign(
        &expected_preimage,
        DEFAULT_SWAP_VOUT,
        &redeem_script,
        coin.as_ref().conf.signature_version,
        sig_hash_type,
        coin.as_ref().conf.fork_id,
    )?;

    if !gen_args
        .taker_pub
        .verify(&sig_hash, &preimage.signature)
        .map_to_mm(|e| ValidateTakerPaymentSpendPreimageError::SignatureVerificationFailure(e.to_string()))?
    {
        return MmError::err(ValidateTakerPaymentSpendPreimageError::InvalidTakerSignature);
    };
    let expected_preimage_tx: UtxoTx = expected_preimage.into();
    if expected_preimage_tx != preimage.preimage {
        return MmError::err(ValidateTakerPaymentSpendPreimageError::InvalidPreimage(
            "Preimage is not equal to expected".into(),
        ));
    }
    Ok(())
}

/// Common implementation of taker payment spend finalization and broadcast for UTXO coins.
/// Appends maker output to the preimage, signs it with SIGHASH_ALL and submits the resulting tx to coin's RPC.
pub async fn sign_and_broadcast_taker_payment_spend<T: UtxoCommonOps>(
    coin: &T,
    preimage: &TxPreimageWithSig<T>,
    gen_args: &GenTakerPaymentSpendArgs<'_, T>,
    secret: &[u8],
    htlc_keypair: &KeyPair,
) -> Result<UtxoTx, TransactionErr> {
    let secret_hash = dhash160(secret);
    let redeem_script = swap_proto_v2_scripts::taker_payment_script(
        try_tx_s!(gen_args.time_lock.try_into()),
        secret_hash.as_slice(),
        gen_args.taker_pub,
        htlc_keypair.public(),
    );

    let mut signer: TransactionInputSigner = preimage.preimage.clone().into();
    let payment_input = try_tx_s!(signer.inputs.first_mut().ok_or("Preimage doesn't have inputs"));
    let payment_output = try_tx_s!(gen_args.taker_tx.first_output());
    payment_input.amount = payment_output.value;
    signer.consensus_branch_id = coin.as_ref().conf.consensus_branch_id;

    if let DexFee::Standard(dex_fee) = gen_args.dex_fee {
        let dex_fee_sat = try_tx_s!(sat_from_big_decimal(&dex_fee.to_decimal(), coin.as_ref().decimals));

        let miner_fee = try_tx_s!(
            coin.get_htlc_spend_fee(DEFAULT_SWAP_TX_SPEND_SIZE, &FeeApproxStage::WithoutApprox)
                .await
        );

        if miner_fee + coin.as_ref().dust_amount + dex_fee_sat > payment_output.value {
            return TX_PLAIN_ERR!("Payment amount is too small to cover miner fee + dust + dex_fee_sat");
        }

        let maker_address = try_tx_s!(coin.as_ref().derivation_method.single_addr_or_err());
        let maker_output = TransactionOutput {
            value: payment_output.value - miner_fee - dex_fee_sat,
            script_pubkey: try_tx_s!(output_script(maker_address)).to_bytes(),
        };
        signer.outputs.push(maker_output);
    }
    drop_mutability!(signer);

    let maker_signature = try_tx_s!(calc_and_sign_sighash(
        &signer,
        DEFAULT_SWAP_VOUT,
        &redeem_script,
        htlc_keypair,
        coin.as_ref().conf.signature_version,
        SIGHASH_ALL,
        coin.as_ref().conf.fork_id
    ));
    let mut taker_signature_with_sighash = preimage.signature.to_vec();
    let taker_sig_hash = match gen_args.dex_fee {
        DexFee::Standard(_) => (SIGHASH_SINGLE | coin.as_ref().conf.fork_id) as u8,
        DexFee::WithBurn { .. } => (SIGHASH_ALL | coin.as_ref().conf.fork_id) as u8,
    };

    taker_signature_with_sighash.push(taker_sig_hash);
    drop_mutability!(taker_signature_with_sighash);

    let sig_hash_all_fork_id = (SIGHASH_ALL | coin.as_ref().conf.fork_id) as u8;
    let mut maker_signature_with_sighash: Vec<u8> = maker_signature.take();
    maker_signature_with_sighash.push(sig_hash_all_fork_id);
    drop_mutability!(maker_signature_with_sighash);

    let script_sig = Builder::default()
        .push_data(&maker_signature_with_sighash)
        .push_data(&taker_signature_with_sighash)
        .push_data(secret)
        .push_opcode(Opcode::OP_0)
        .push_data(&redeem_script)
        .into_bytes();
    let mut final_tx: UtxoTx = signer.into();
    let final_tx_input = try_tx_s!(final_tx.inputs.first_mut().ok_or("Final tx doesn't have inputs"));
    final_tx_input.script_sig = script_sig;
    drop_mutability!(final_tx);

    try_tx_s!(coin.broadcast_tx(&final_tx).await, final_tx);
    Ok(final_tx)
}

pub fn send_taker_fee<T>(coin: T, fee_pub_key: &[u8], dex_fee: DexFee) -> TransactionFut
where
    T: UtxoCommonOps + GetUtxoListOps,
{
    let address = try_tx_fus!(address_from_raw_pubkey(
        fee_pub_key,
        coin.as_ref().conf.address_prefixes.clone(),
        coin.as_ref().conf.checksum_type,
        coin.as_ref().conf.bech32_hrp.clone(),
        coin.addr_format().clone(),
    ));

    let outputs = try_tx_fus!(generate_taker_fee_tx_outputs(
        coin.as_ref().decimals,
        address.hash(),
        &dex_fee,
    ));

    send_outputs_from_my_address(coin, outputs)
}

fn generate_taker_fee_tx_outputs(
    decimals: u8,
    address_hash: &AddressHashEnum,
    dex_fee: &DexFee,
) -> Result<Vec<TransactionOutput>, MmError<NumConversError>> {
    let fee_amount = dex_fee.fee_uamount(decimals)?;

    let mut outputs = vec![TransactionOutput {
        value: fee_amount,
        script_pubkey: Builder::build_p2pkh(address_hash).to_bytes(),
    }];

    if let Some(burn_amount) = dex_fee.burn_uamount(decimals)? {
        outputs.push(TransactionOutput {
            value: burn_amount,
            script_pubkey: Builder::default().push_opcode(Opcode::OP_RETURN).into_bytes(),
        });
    }

    Ok(outputs)
}

pub fn send_maker_payment<T>(coin: T, args: SendPaymentArgs) -> TransactionFut
where
    T: UtxoCommonOps + GetUtxoListOps + SwapOps,
{
    let maker_htlc_key_pair = coin.derive_htlc_key_pair(args.swap_unique_data);
    let SwapPaymentOutputsResult {
        payment_address,
        outputs,
    } = try_tx_fus!(generate_swap_payment_outputs(
        &coin,
        try_tx_fus!(args.time_lock.try_into()),
        maker_htlc_key_pair.public_slice(),
        args.other_pubkey,
        args.amount,
        SwapTxTypeWithSecretHash::TakerOrMakerPayment {
            maker_secret_hash: args.secret_hash
        },
    ));
    let send_fut = match &coin.as_ref().rpc_client {
        UtxoRpcClientEnum::Electrum(_) => Either::A(send_outputs_from_my_address(coin, outputs)),
        UtxoRpcClientEnum::Native(client) => {
            let addr_string = try_tx_fus!(payment_address.display_address());
            Either::B(
                client
                    .import_address(&addr_string, &addr_string, false)
                    .map_err(|e| TransactionErr::Plain(ERRL!("{}", e)))
                    .and_then(move |_| send_outputs_from_my_address(coin, outputs)),
            )
        },
    };
    Box::new(send_fut)
}

pub fn send_taker_payment<T>(coin: T, args: SendPaymentArgs) -> TransactionFut
where
    T: UtxoCommonOps + GetUtxoListOps + SwapOps,
{
    let total_amount = match args.watcher_reward {
        Some(reward) => args.amount + reward.amount,
        None => args.amount,
    };

    let taker_htlc_key_pair = coin.derive_htlc_key_pair(args.swap_unique_data);
    let SwapPaymentOutputsResult {
        payment_address,
        outputs,
    } = try_tx_fus!(generate_swap_payment_outputs(
        &coin,
        try_tx_fus!(args.time_lock.try_into()),
        taker_htlc_key_pair.public_slice(),
        args.other_pubkey,
        total_amount,
        SwapTxTypeWithSecretHash::TakerOrMakerPayment {
            maker_secret_hash: args.secret_hash
        },
    ));

    let send_fut = match &coin.as_ref().rpc_client {
        UtxoRpcClientEnum::Electrum(_) => Either::A(send_outputs_from_my_address(coin, outputs)),
        UtxoRpcClientEnum::Native(client) => {
            let addr_string = try_tx_fus!(payment_address.display_address());
            Either::B(
                client
                    .import_address(&addr_string, &addr_string, false)
                    .map_err(|e| TransactionErr::Plain(ERRL!("{}", e)))
                    .and_then(move |_| send_outputs_from_my_address(coin, outputs)),
            )
        },
    };
    Box::new(send_fut)
}

pub fn send_maker_spends_taker_payment<T: UtxoCommonOps + SwapOps>(coin: T, args: SpendPaymentArgs) -> TransactionFut {
    let my_address = try_tx_fus!(coin.as_ref().derivation_method.single_addr_or_err()).clone();
    let mut prev_transaction: UtxoTx = try_tx_fus!(deserialize(args.other_payment_tx).map_err(|e| ERRL!("{:?}", e)));
    prev_transaction.tx_hash_algo = coin.as_ref().tx_hash_algo;
    drop_mutability!(prev_transaction);

    let payment_value = try_tx_fus!(prev_transaction.first_output()).value;

    let key_pair = coin.derive_htlc_key_pair(args.swap_unique_data);
    let script_data = Builder::default()
        .push_data(args.secret)
        .push_opcode(Opcode::OP_0)
        .into_script();

    let time_lock = try_tx_fus!(args.time_lock.try_into());
    let redeem_script = payment_script(
        time_lock,
        args.secret_hash,
        &try_tx_fus!(Public::from_slice(args.other_pubkey)),
        key_pair.public(),
    )
    .into();
    let fut = async move {
        let fee = try_tx_s!(
            coin.get_htlc_spend_fee(DEFAULT_SWAP_TX_SPEND_SIZE, &FeeApproxStage::WithoutApprox)
                .await
        );
        if fee >= payment_value {
            return TX_PLAIN_ERR!(
                "HTLC spend fee {} is greater than transaction output {}",
                fee,
                payment_value
            );
        }
        let script_pubkey = output_script(&my_address).map(|script| script.to_bytes())?;
        let output = TransactionOutput {
            value: payment_value - fee,
            script_pubkey,
        };

        let input = P2SHSpendingTxInput {
            prev_transaction,
            redeem_script,
            outputs: vec![output],
            script_data,
            sequence: SEQUENCE_FINAL,
            lock_time: time_lock,
            keypair: &key_pair,
        };
        let transaction = try_tx_s!(coin.p2sh_spending_tx(input).await);

        let tx_fut = coin.as_ref().rpc_client.send_transaction(&transaction).compat();
        try_tx_s!(tx_fut.await, transaction);

        Ok(transaction.into())
    };
    Box::new(fut.boxed().compat())
}

pub fn send_maker_payment_spend_preimage<T: UtxoCommonOps + SwapOps>(
    coin: &T,
    input: SendMakerPaymentSpendPreimageInput,
) -> TransactionFut {
    let mut transaction: UtxoTx = try_tx_fus!(deserialize(input.preimage).map_err(|e| ERRL!("{:?}", e)));
    if transaction.inputs.is_empty() {
        return try_tx_fus!(TX_PLAIN_ERR!("Transaction doesn't have any input"));
    }
    let script = Script::from(transaction.inputs[DEFAULT_SWAP_VIN].script_sig.clone());
    let mut instructions = script.iter();

    let instruction_1 = try_tx_fus!(try_tx_fus!(instructions.next().ok_or("Instruction not found")));
    let instruction_2 = try_tx_fus!(try_tx_fus!(instructions.next().ok_or("Instruction not found")));

    let script_sig = try_tx_fus!(instruction_1
        .data
        .ok_or("No script signature in the taker spends maker payment preimage"));
    let redeem_script = try_tx_fus!(instruction_2
        .data
        .ok_or("No redeem script in the taker spends maker payment preimage"));
    let script_data = Builder::default()
        .push_data(input.secret)
        .push_opcode(Opcode::OP_0)
        .into_script();

    let mut resulting_script = Builder::default().push_data(script_sig).into_bytes();
    resulting_script.extend_from_slice(&script_data);
    let redeem_part = Builder::default().push_data(redeem_script).into_bytes();
    resulting_script.extend_from_slice(&redeem_part);

    transaction.inputs[DEFAULT_SWAP_VIN].script_sig = resulting_script;

    let coin = coin.clone();
    let fut = async move {
        let tx_fut = coin.as_ref().rpc_client.send_transaction(&transaction).compat();
        try_tx_s!(tx_fut.await, transaction);

        Ok(transaction.into())
    };

    Box::new(fut.boxed().compat())
}

pub fn create_maker_payment_spend_preimage<T: UtxoCommonOps + SwapOps>(
    coin: &T,
    maker_payment_tx: &[u8],
    time_lock: u32,
    maker_pub: &[u8],
    secret_hash: &[u8],
    swap_unique_data: &[u8],
) -> TransactionFut {
    let my_address = try_tx_fus!(coin.as_ref().derivation_method.single_addr_or_err()).clone();
    let mut prev_transaction: UtxoTx = try_tx_fus!(deserialize(maker_payment_tx).map_err(|e| ERRL!("{:?}", e)));
    prev_transaction.tx_hash_algo = coin.as_ref().tx_hash_algo;
    drop_mutability!(prev_transaction);
    let payment_value = try_tx_fus!(prev_transaction.first_output()).value;

    let key_pair = coin.derive_htlc_key_pair(swap_unique_data);

    let script_data = Builder::default().into_script();
    let redeem_script = payment_script(
        time_lock,
        secret_hash,
        &try_tx_fus!(Public::from_slice(maker_pub)),
        key_pair.public(),
    )
    .into();
    let coin = coin.clone();
    let fut = async move {
        let fee = try_tx_s!(
            coin.get_htlc_spend_fee(DEFAULT_SWAP_TX_SPEND_SIZE, &FeeApproxStage::WatcherPreimage)
                .await
        );

        if fee >= payment_value {
            return TX_PLAIN_ERR!(
                "HTLC spend fee {} is greater than transaction output {}",
                fee,
                payment_value
            );
        }
        let script_pubkey = output_script(&my_address).map(|script| script.to_bytes())?;
        let output = TransactionOutput {
            value: payment_value - fee,
            script_pubkey,
        };

        let input = P2SHSpendingTxInput {
            prev_transaction,
            redeem_script,
            outputs: vec![output],
            script_data,
            sequence: SEQUENCE_FINAL,
            lock_time: time_lock,
            keypair: &key_pair,
        };
        let transaction = try_tx_s!(coin.p2sh_spending_tx(input).await);

        Ok(transaction.into())
    };
    Box::new(fut.boxed().compat())
}

pub fn create_taker_payment_refund_preimage<T: UtxoCommonOps + SwapOps>(
    coin: &T,
    taker_payment_tx: &[u8],
    time_lock: u32,
    maker_pub: &[u8],
    secret_hash: &[u8],
    swap_unique_data: &[u8],
) -> TransactionFut {
    let coin = coin.clone();
    let my_address = try_tx_fus!(coin.as_ref().derivation_method.single_addr_or_err()).clone();
    let mut prev_transaction: UtxoTx =
        try_tx_fus!(deserialize(taker_payment_tx).map_err(|e| TransactionErr::Plain(format!("{:?}", e))));
    prev_transaction.tx_hash_algo = coin.as_ref().tx_hash_algo;
    drop_mutability!(prev_transaction);
    let payment_value = try_tx_fus!(prev_transaction.first_output()).value;

    let key_pair = coin.derive_htlc_key_pair(swap_unique_data);
    let script_data = Builder::default().push_opcode(Opcode::OP_1).into_script();
    let redeem_script = payment_script(
        time_lock,
        secret_hash,
        key_pair.public(),
        &try_tx_fus!(Public::from_slice(maker_pub)),
    )
    .into();
    let fut = async move {
        let fee = try_tx_s!(
            coin.get_htlc_spend_fee(DEFAULT_SWAP_TX_SPEND_SIZE, &FeeApproxStage::WatcherPreimage)
                .await
        );
        if fee >= payment_value {
            return TX_PLAIN_ERR!(
                "HTLC spend fee {} is greater than transaction output {}",
                fee,
                payment_value
            );
        }
        let script_pubkey = output_script(&my_address).map(|script| script.to_bytes())?;
        let output = TransactionOutput {
            value: payment_value - fee,
            script_pubkey,
        };

        let input = P2SHSpendingTxInput {
            prev_transaction,
            redeem_script,
            outputs: vec![output],
            script_data,
            sequence: SEQUENCE_FINAL - 1,
            lock_time: time_lock,
            keypair: &key_pair,
        };
        let transaction = try_tx_s!(coin.p2sh_spending_tx(input).await);

        Ok(transaction.into())
    };
    Box::new(fut.boxed().compat())
}

pub fn send_taker_spends_maker_payment<T: UtxoCommonOps + SwapOps>(coin: T, args: SpendPaymentArgs) -> TransactionFut {
    let my_address = try_tx_fus!(coin.as_ref().derivation_method.single_addr_or_err()).clone();
    let mut prev_transaction: UtxoTx = try_tx_fus!(deserialize(args.other_payment_tx).map_err(|e| ERRL!("{:?}", e)));
    prev_transaction.tx_hash_algo = coin.as_ref().tx_hash_algo;
    drop_mutability!(prev_transaction);
    let payment_value = try_tx_fus!(prev_transaction.first_output()).value;

    let key_pair = coin.derive_htlc_key_pair(args.swap_unique_data);

    let script_data = Builder::default()
        .push_data(args.secret)
        .push_opcode(Opcode::OP_0)
        .into_script();

    let time_lock = try_tx_fus!(args.time_lock.try_into());
    let redeem_script = payment_script(
        time_lock,
        args.secret_hash,
        &try_tx_fus!(Public::from_slice(args.other_pubkey)),
        key_pair.public(),
    )
    .into();

    let fut = async move {
        let fee = try_tx_s!(
            coin.get_htlc_spend_fee(DEFAULT_SWAP_TX_SPEND_SIZE, &FeeApproxStage::WithoutApprox)
                .await
        );
        if fee >= payment_value {
            return TX_PLAIN_ERR!(
                "HTLC spend fee {} is greater than transaction output {}",
                fee,
                payment_value
            );
        }
        let script_pubkey = output_script(&my_address).map(|script| script.to_bytes())?;
        let output = TransactionOutput {
            value: payment_value - fee,
            script_pubkey,
        };

        let input = P2SHSpendingTxInput {
            prev_transaction,
            redeem_script,
            outputs: vec![output],
            script_data,
            sequence: SEQUENCE_FINAL,
            lock_time: time_lock,
            keypair: &key_pair,
        };
        let transaction = try_tx_s!(coin.p2sh_spending_tx(input).await);

        let tx_fut = coin.as_ref().rpc_client.send_transaction(&transaction).compat();
        try_tx_s!(tx_fut.await, transaction);

        Ok(transaction.into())
    };
    Box::new(fut.boxed().compat())
}

pub async fn refund_htlc_payment<T: UtxoCommonOps + SwapOps>(
    coin: T,
    args: RefundPaymentArgs<'_>,
) -> Result<UtxoTx, TransactionErr> {
    let my_address = try_tx_s!(coin.as_ref().derivation_method.single_addr_or_err()).clone();
    let mut prev_transaction: UtxoTx =
        try_tx_s!(deserialize(args.payment_tx).map_err(|e| TransactionErr::Plain(format!("{:?}", e))));
    prev_transaction.tx_hash_algo = coin.as_ref().tx_hash_algo;
    drop_mutability!(prev_transaction);
    let payment_value = try_tx_s!(prev_transaction.first_output()).value;
    let other_public = try_tx_s!(Public::from_slice(args.other_pubkey));

    let key_pair = coin.derive_htlc_key_pair(args.swap_unique_data);
    let script_data = Builder::default().push_opcode(Opcode::OP_1).into_script();
    let time_lock = try_tx_s!(args.time_lock.try_into());

    let redeem_script = args
        .tx_type_with_secret_hash
        .redeem_script(time_lock, key_pair.public(), &other_public)
        .into();
    let fee = try_tx_s!(
        coin.get_htlc_spend_fee(DEFAULT_SWAP_TX_SPEND_SIZE, &FeeApproxStage::WithoutApprox)
            .await
    );
    if fee >= payment_value {
        return TX_PLAIN_ERR!(
            "HTLC spend fee {} is greater than transaction output {}",
            fee,
            payment_value
        );
    }
    let script_pubkey = output_script(&my_address).map(|script| script.to_bytes())?;
    let output = TransactionOutput {
        value: payment_value - fee,
        script_pubkey,
    };

    let input = P2SHSpendingTxInput {
        prev_transaction,
        redeem_script,
        outputs: vec![output],
        script_data,
        sequence: SEQUENCE_FINAL - 1,
        lock_time: time_lock,
        keypair: &key_pair,
    };
    let transaction = try_tx_s!(coin.p2sh_spending_tx(input).await);

    let tx_fut = coin.as_ref().rpc_client.send_transaction(&transaction).compat();
    try_tx_s!(tx_fut.await, transaction);

    Ok(transaction)
}

#[inline]
pub async fn send_taker_refunds_payment<T: UtxoCommonOps + SwapOps>(
    coin: T,
    args: RefundPaymentArgs<'_>,
) -> TransactionResult {
    refund_htlc_payment(coin, args).await.map(|tx| tx.into())
}

pub fn send_taker_payment_refund_preimage<T: UtxoCommonOps + SwapOps>(
    coin: &T,
    watcher_refunds_payment_args: RefundPaymentArgs,
) -> TransactionFut {
    let coin = coin.clone();
    let transaction: UtxoTx = try_tx_fus!(
        deserialize(watcher_refunds_payment_args.payment_tx).map_err(|e| TransactionErr::Plain(format!("{:?}", e)))
    );

    let fut = async move {
        let tx_fut = coin.as_ref().rpc_client.send_transaction(&transaction).compat();
        try_tx_s!(tx_fut.await, transaction);

        Ok(transaction.into())
    };

    Box::new(fut.boxed().compat())
}

#[inline]
pub async fn send_maker_refunds_payment<T: UtxoCommonOps + SwapOps>(
    coin: T,
    args: RefundPaymentArgs<'_>,
) -> TransactionResult {
    refund_htlc_payment(coin, args).await.map(|tx| tx.into())
}

/// Extracts pubkey from script sig
fn pubkey_from_script_sig(script: &Script) -> Result<H264, String> {
    match script.get_instruction(0) {
        Some(Ok(instruction)) => match instruction.opcode {
            Opcode::OP_PUSHBYTES_70 | Opcode::OP_PUSHBYTES_71 | Opcode::OP_PUSHBYTES_72 => match instruction.data {
                Some(bytes) => try_s!(SecpSignature::from_der(&bytes[..bytes.len() - 1])),
                None => return ERR!("No data at instruction 0 of script {:?}", script),
            },
            _ => return ERR!("Unexpected opcode {:?}", instruction.opcode),
        },
        Some(Err(e)) => return ERR!("Error {} on getting instruction 0 of script {:?}", e, script),
        None => return ERR!("None instruction 0 of script {:?}", script),
    };

    let pubkey = match script.get_instruction(1) {
        Some(Ok(instruction)) => match instruction.opcode {
            Opcode::OP_PUSHBYTES_33 => match instruction.data {
                Some(bytes) => try_s!(PublicKey::from_slice(bytes)),
                None => return ERR!("No data at instruction 1 of script {:?}", script),
            },
            _ => return ERR!("Unexpected opcode {:?}", instruction.opcode),
        },
        Some(Err(e)) => return ERR!("Error {} on getting instruction 1 of script {:?}", e, script),
        None => return ERR!("None instruction 1 of script {:?}", script),
    };

    if script.get_instruction(2).is_some() {
        return ERR!("Unexpected instruction at position 2 of script {:?}", script);
    }
    Ok(pubkey.serialize().into())
}

/// Extracts pubkey from witness script
fn pubkey_from_witness_script(witness_script: &[Bytes]) -> Result<H264, String> {
    if witness_script.len() != 2 {
        return ERR!("Invalid witness length {}", witness_script.len());
    }

    let signature = witness_script[0].clone().take();
    if signature.is_empty() {
        return ERR!("Empty signature data in witness script");
    }
    try_s!(SecpSignature::from_der(&signature[..signature.len() - 1]));

    let pubkey = try_s!(PublicKey::from_slice(&witness_script[1]));

    Ok(pubkey.serialize().into())
}

pub async fn is_tx_confirmed_before_block<T>(coin: &T, tx: &RpcTransaction, block_number: u64) -> Result<bool, String>
where
    T: UtxoCommonOps,
{
    match tx.height {
        Some(confirmed_at) => Ok(confirmed_at <= block_number),
        // fallback to a number of confirmations
        None => {
            if tx.confirmations > 0 {
                let current_block = try_s!(coin.as_ref().rpc_client.get_block_count().compat().await);
                let confirmed_at = current_block + 1 - tx.confirmations as u64;
                Ok(confirmed_at <= block_number)
            } else {
                Ok(false)
            }
        },
    }
}

pub fn check_all_inputs_signed_by_pub(tx: &[u8], expected_pub: &[u8]) -> Result<bool, MmError<ValidatePaymentError>> {
    let tx: UtxoTx = deserialize(tx)?;
    check_all_utxo_inputs_signed_by_pub(&tx, expected_pub)
}

pub fn check_all_utxo_inputs_signed_by_pub(
    tx: &UtxoTx,
    expected_pub: &[u8],
) -> Result<bool, MmError<ValidatePaymentError>> {
    for input in &tx.inputs {
        let pubkey = if input.has_witness() {
            pubkey_from_witness_script(&input.script_witness).map_to_mm(ValidatePaymentError::TxDeserializationError)?
        } else {
            let script: Script = input.script_sig.clone().into();
            pubkey_from_script_sig(&script).map_to_mm(ValidatePaymentError::TxDeserializationError)?
        };
        if *pubkey != expected_pub {
            return Ok(false);
        }
    }

    Ok(true)
}

pub fn watcher_validate_taker_fee<T: UtxoCommonOps>(
    coin: &T,
    input: WatcherValidateTakerFeeInput,
    output_index: usize,
) -> ValidatePaymentFut<()> {
    let coin = coin.clone();
    let sender_pubkey = input.sender_pubkey;
    let taker_fee_hash = input.taker_fee_hash;
    let min_block_number = input.min_block_number;
    let lock_duration = input.lock_duration;
    let fee_addr = input.fee_addr.to_vec();

    let fut = async move {
        let mut attempts = 0;
        loop {
            let tx_from_rpc = match coin
                .as_ref()
                .rpc_client
                .get_verbose_transaction(&H256Json::from(taker_fee_hash.as_slice()))
                .compat()
                .await
            {
                Ok(t) => t,
                Err(e) => {
                    if attempts > 2 {
                        return MmError::err(ValidatePaymentError::from(e.into_inner()));
                    };
                    attempts += 1;
                    error!("Error getting tx {:?} from rpc: {:?}", taker_fee_hash, e);
                    Timer::sleep(10.).await;
                    continue;
                },
            };

            let taker_fee_tx: UtxoTx = deserialize(tx_from_rpc.hex.0.as_slice())?;
            let inputs_signed_by_pub = check_all_utxo_inputs_signed_by_pub(&taker_fee_tx, &sender_pubkey)?;
            if !inputs_signed_by_pub {
                return MmError::err(ValidatePaymentError::WrongPaymentTx(format!(
                    "{}: Taker fee does not belong to the verified public key",
                    INVALID_SENDER_ERR_LOG
                )));
            }

            let tx_confirmed_before_block = is_tx_confirmed_before_block(&coin, &tx_from_rpc, min_block_number)
                .await
                .map_to_mm(ValidatePaymentError::InternalError)?;
            if tx_confirmed_before_block {
                return MmError::err(ValidatePaymentError::WrongPaymentTx(format!(
                    "{}: Fee tx {:?} confirmed before min_block {}",
                    EARLY_CONFIRMATION_ERR_LOG, taker_fee_tx, min_block_number
                )));
            }

            if now_sec_u32() - taker_fee_tx.lock_time > lock_duration as u32 {
                return MmError::err(ValidatePaymentError::WrongPaymentTx(format!(
                    "{}: Taker fee {:?} is too old",
                    OLD_TRANSACTION_ERR_LOG, taker_fee_tx
                )));
            }

            let address = address_from_raw_pubkey(
                &fee_addr,
                coin.as_ref().conf.address_prefixes.clone(),
                coin.as_ref().conf.checksum_type,
                coin.as_ref().conf.bech32_hrp.clone(),
                coin.addr_format().clone(),
            )
            .map_to_mm(ValidatePaymentError::TxDeserializationError)?;

            match taker_fee_tx.outputs.get(output_index) {
                Some(out) => {
                    let expected_script_pubkey = Builder::build_p2pkh(address.hash()).to_bytes();
                    if out.script_pubkey != expected_script_pubkey {
                        return MmError::err(ValidatePaymentError::WrongPaymentTx(format!(
                            "{}: Provided dex fee tx output script_pubkey doesn't match expected {:?} {:?}",
                            INVALID_RECEIVER_ERR_LOG, out.script_pubkey, expected_script_pubkey
                        )));
                    }
                },
                None => {
                    return MmError::err(ValidatePaymentError::WrongPaymentTx(format!(
                        "Provided dex fee tx {:?} does not have output {}",
                        taker_fee_tx, output_index
                    )))
                },
            }

            return Ok(());
        }
    };
    Box::new(fut.boxed().compat())
}

pub fn validate_fee<T: UtxoCommonOps>(
    coin: T,
    tx: UtxoTx,
    output_index: usize,
    sender_pubkey: &[u8],
    dex_amount: &DexFee,
    min_block_number: u64,
    fee_addr: &[u8],
) -> ValidatePaymentFut<()> {
    let address = try_f!(address_from_raw_pubkey(
        fee_addr,
        coin.as_ref().conf.address_prefixes.clone(),
        coin.as_ref().conf.checksum_type,
        coin.as_ref().conf.bech32_hrp.clone(),
        coin.addr_format().clone(),
    )
    .map_to_mm(ValidatePaymentError::TxDeserializationError));

    let inputs_signed_by_pub = try_f!(check_all_utxo_inputs_signed_by_pub(&tx, sender_pubkey));
    if !inputs_signed_by_pub {
        return Box::new(futures01::future::err(
            ValidatePaymentError::WrongPaymentTx(format!(
                "{INVALID_SENDER_ERR_LOG}: Taker payment does not belong to the verified public key"
            ))
            .into(),
        ));
    }

    let fee_amount = try_f!(dex_amount.fee_uamount(coin.as_ref().decimals));
    let burn_amount = try_f!(dex_amount.burn_uamount(coin.as_ref().decimals));

    let fut = async move {
        let tx_from_rpc = coin
            .as_ref()
            .rpc_client
            .get_verbose_transaction(&tx.hash().reversed().into())
            .compat()
            .await?;

        let tx_confirmed_before_block = is_tx_confirmed_before_block(&coin, &tx_from_rpc, min_block_number)
            .await
            .map_to_mm(ValidatePaymentError::InternalError)?;

        if tx_confirmed_before_block {
            return MmError::err(ValidatePaymentError::WrongPaymentTx(format!(
                "{}: Fee tx {:?} confirmed before min_block {}",
                EARLY_CONFIRMATION_ERR_LOG, tx_from_rpc, min_block_number
            )));
        }
        if tx_from_rpc.hex.0 != serialize(&tx).take()
            && tx_from_rpc.hex.0 != serialize_with_flags(&tx, SERIALIZE_TRANSACTION_WITNESS).take()
        {
            return MmError::err(ValidatePaymentError::WrongPaymentTx(format!(
                "Provided dex fee tx {:?} doesn't match tx data from rpc {:?}",
                tx, tx_from_rpc
            )));
        }

        match tx.outputs.get(output_index) {
            Some(out) => {
                let expected_script_pubkey = Builder::build_p2pkh(address.hash()).to_bytes();
                if out.script_pubkey != expected_script_pubkey {
                    return MmError::err(ValidatePaymentError::WrongPaymentTx(format!(
                        "{}: Provided dex fee tx output script_pubkey doesn't match expected {:?} {:?}",
                        INVALID_RECEIVER_ERR_LOG, out.script_pubkey, expected_script_pubkey
                    )));
                }
                if out.value < fee_amount {
                    return MmError::err(ValidatePaymentError::WrongPaymentTx(format!(
                        "Provided dex fee tx output value is less than expected {:?} {:?}",
                        out.value, fee_amount
                    )));
                }
            },
            None => {
                return MmError::err(ValidatePaymentError::WrongPaymentTx(format!(
                    "Provided dex fee tx {:?} does not have output {}",
                    tx, output_index
                )))
            },
        }

        if let Some(burn_amount) = burn_amount {
            match tx.outputs.get(output_index + 1) {
                Some(out) => {
                    let expected_script_pubkey = Builder::default().push_opcode(Opcode::OP_RETURN).into_bytes();

                    if out.script_pubkey != expected_script_pubkey {
                        return MmError::err(ValidatePaymentError::WrongPaymentTx(format!(
                            "{}: Provided burn tx output script_pubkey doesn't match expected {:?} {:?}",
                            INVALID_RECEIVER_ERR_LOG, out.script_pubkey, expected_script_pubkey
                        )));
                    }

                    if out.value < burn_amount {
                        return MmError::err(ValidatePaymentError::WrongPaymentTx(format!(
                            "Provided burn tx output value is less than expected {:?} {:?}",
                            out.value, burn_amount
                        )));
                    }
                },
                None => {
                    return MmError::err(ValidatePaymentError::WrongPaymentTx(format!(
                        "Provided burn tx output {:?} does not have output {}",
                        tx, output_index
                    )))
                },
            }
        }

        Ok(())
    };
    Box::new(fut.boxed().compat())
}

pub async fn validate_maker_payment<T: UtxoCommonOps + SwapOps>(
    coin: &T,
    input: ValidatePaymentInput,
) -> ValidatePaymentResult<()> {
    let mut tx: UtxoTx = deserialize(input.payment_tx.as_slice())?;
    tx.tx_hash_algo = coin.as_ref().tx_hash_algo;

    let htlc_keypair = coin.derive_htlc_key_pair(&input.unique_swap_data);
    let other_pub = Public::from_slice(&input.other_pub)
        .map_to_mm(|err| ValidatePaymentError::InvalidParameter(err.to_string()))?;
    let time_lock = input
        .time_lock
        .try_into()
        .map_to_mm(ValidatePaymentError::TimelockOverflow)?;
    validate_payment(
        coin.clone(),
        &tx,
        DEFAULT_SWAP_VOUT,
        &other_pub,
        htlc_keypair.public(),
        SwapTxTypeWithSecretHash::TakerOrMakerPayment {
            maker_secret_hash: &input.secret_hash,
        },
        input.amount,
        input.watcher_reward,
        time_lock,
        input.try_spv_proof_until,
        input.confirmations,
    )
    .await
}

pub fn watcher_validate_taker_payment<T: UtxoCommonOps + SwapOps>(
    coin: &T,
    input: WatcherValidatePaymentInput,
) -> ValidatePaymentFut<()> {
    let taker_payment_tx: UtxoTx = try_f!(deserialize(input.payment_tx.as_slice()));
    let taker_payment_refund_preimage: UtxoTx = try_f!(deserialize(input.taker_payment_refund_preimage.as_slice()));
    let taker_pub = &try_f!(
        Public::from_slice(&input.taker_pub).map_err(|err| ValidatePaymentError::InvalidParameter(err.to_string()))
    );
    let maker_pub = &try_f!(
        Public::from_slice(&input.maker_pub).map_err(|err| ValidatePaymentError::InvalidParameter(err.to_string()))
    );
    let time_lock = try_f!(input
        .time_lock
        .try_into()
        .map_to_mm(ValidatePaymentError::TimelockOverflow));
    let expected_redeem = payment_script(time_lock, &input.secret_hash, taker_pub, maker_pub);
    let coin = coin.clone();

    let fut = async move {
        let inputs_signed_by_pub = check_all_utxo_inputs_signed_by_pub(&taker_payment_tx, &input.taker_pub)?;
        if !inputs_signed_by_pub {
            return MmError::err(ValidatePaymentError::WrongPaymentTx(format!(
                "{INVALID_SENDER_ERR_LOG}: Taker payment does not belong to the verified public key"
            )));
        }

        let taker_payment_locking_script = match taker_payment_tx.outputs.get(DEFAULT_SWAP_VOUT) {
            Some(output) => output.script_pubkey.clone(),
            None => {
                return MmError::err(ValidatePaymentError::WrongPaymentTx(
                    "Payment tx has no outputs".to_string(),
                ))
            },
        };

        if taker_payment_locking_script != Builder::build_p2sh(&dhash160(&expected_redeem).into()).to_bytes() {
            return MmError::err(ValidatePaymentError::WrongPaymentTx(format!(
                "{INVALID_SCRIPT_ERR_LOG}: Payment tx locking script {taker_payment_locking_script:?} doesn't match expected"
            )));
        }

        let script_sig = match taker_payment_refund_preimage.inputs.get(DEFAULT_SWAP_VIN) {
            Some(input) => Script::from(input.script_sig.clone()),
            None => {
                return MmError::err(ValidatePaymentError::WrongPaymentTx(
                    "Taker payment refund tx has no inputs".to_string(),
                ))
            },
        };

        let instruction = script_sig
            .iter()
            .last()
            .or_mm_err(|| ValidatePaymentError::WrongPaymentTx(String::from("Instruction not found")))?
            .map_to_mm(|err| ValidatePaymentError::WrongPaymentTx(err.to_string()))?;

        let redeem_script = instruction.data.or_mm_err(|| {
            ValidatePaymentError::WrongPaymentTx(String::from("No redeem script in the taker payment refund preimage"))
        })?;

        if expected_redeem.as_slice() != redeem_script {
            return MmError::err(ValidatePaymentError::WrongPaymentTx(
                format!("{INVALID_REFUND_TX_ERR_LOG}: Taker payment tx locking script doesn't match with taker payment refund redeem script")
            ));
        }

        if let UtxoRpcClientEnum::Electrum(client) = &coin.as_ref().rpc_client {
            if coin.as_ref().conf.spv_conf.is_some() && input.confirmations != 0 {
                client.validate_spv_proof(&taker_payment_tx, input.wait_until).await?;
            }
        }
        Ok(())
    };
    Box::new(fut.boxed().compat())
}

pub async fn validate_taker_payment<T: UtxoCommonOps + SwapOps>(
    coin: &T,
    input: ValidatePaymentInput,
) -> ValidatePaymentResult<()> {
    let mut tx: UtxoTx = deserialize(input.payment_tx.as_slice())?;
    tx.tx_hash_algo = coin.as_ref().tx_hash_algo;

    let htlc_keypair = coin.derive_htlc_key_pair(&input.unique_swap_data);
    let other_pub = Public::from_slice(&input.other_pub)
        .map_to_mm(|err| ValidatePaymentError::InvalidParameter(err.to_string()))?;
    let time_lock = input
        .time_lock
        .try_into()
        .map_to_mm(ValidatePaymentError::TimelockOverflow)?;
    validate_payment(
        coin.clone(),
        &tx,
        DEFAULT_SWAP_VOUT,
        &other_pub,
        htlc_keypair.public(),
        SwapTxTypeWithSecretHash::TakerOrMakerPayment {
            maker_secret_hash: &input.secret_hash,
        },
        input.amount,
        input.watcher_reward,
        time_lock,
        input.try_spv_proof_until,
        input.confirmations,
    )
    .await
}

pub fn validate_payment_spend_or_refund<T: UtxoCommonOps + SwapOps>(
    coin: &T,
    input: ValidateWatcherSpendInput,
) -> ValidatePaymentFut<()> {
    let mut payment_spend_tx: UtxoTx = try_f!(deserialize(input.payment_tx.as_slice()));
    payment_spend_tx.tx_hash_algo = coin.as_ref().tx_hash_algo;

    let my_address = try_f!(coin.as_ref().derivation_method.single_addr_or_err());
    let expected_script_pubkey = try_f!(output_script(my_address).map(|script| script.to_bytes()));
    let output = try_f!(payment_spend_tx
        .outputs
        .get(DEFAULT_SWAP_VOUT)
        .ok_or_else(|| ValidatePaymentError::WrongPaymentTx("Payment tx has no outputs".to_string(),)));

    if expected_script_pubkey != output.script_pubkey {
        return Box::new(futures01::future::err(
            ValidatePaymentError::WrongPaymentTx(format!(
                "Provided payment tx script pubkey doesn't match expected {:?} {:?}",
                output.script_pubkey, expected_script_pubkey
            ))
            .into(),
        ));
    }

    Box::new(futures01::future::ok(()))
}

pub fn check_if_my_payment_sent<T: UtxoCommonOps + SwapOps>(
    coin: T,
    time_lock: u32,
    other_pub: &[u8],
    secret_hash: &[u8],
    swap_unique_data: &[u8],
) -> Box<dyn Future<Item = Option<TransactionEnum>, Error = String> + Send> {
    let my_htlc_keypair = coin.derive_htlc_key_pair(swap_unique_data);
    let script = payment_script(
        time_lock,
        secret_hash,
        my_htlc_keypair.public(),
        &try_fus!(Public::from_slice(other_pub)),
    );
    let hash = dhash160(&script);
    let p2sh = Builder::build_p2sh(&hash.into());
    let script_hash = electrum_script_hash(&p2sh);
    let fut = async move {
        match &coin.as_ref().rpc_client {
            UtxoRpcClientEnum::Electrum(client) => {
                let history = try_s!(client.scripthash_get_history(&hex::encode(script_hash)).compat().await);
                match history.first() {
                    Some(item) => {
                        let tx_bytes = try_s!(client.get_transaction_bytes(&item.tx_hash).compat().await);
                        let mut tx: UtxoTx = try_s!(deserialize(tx_bytes.0.as_slice()).map_err(|e| ERRL!("{:?}", e)));
                        tx.tx_hash_algo = coin.as_ref().tx_hash_algo;
                        Ok(Some(tx.into()))
                    },
                    None => Ok(None),
                }
            },
            UtxoRpcClientEnum::Native(client) => {
                let target_addr = AddressBuilder::new(
                    coin.addr_format_for_standard_scripts(),
                    hash.into(),
                    coin.as_ref().conf.checksum_type,
                    coin.as_ref().conf.address_prefixes.clone(),
                    coin.as_ref().conf.bech32_hrp.clone(),
                )
                .as_sh()
                .build()?;
                let target_addr = target_addr.to_string();
                let is_imported = try_s!(client.is_address_imported(&target_addr).await);
                if !is_imported {
                    return Ok(None);
                }
                let received_by_addr = try_s!(client.list_received_by_address(0, true, true).compat().await);
                for item in received_by_addr {
                    if item.address == target_addr && !item.txids.is_empty() {
                        let tx_bytes = try_s!(client.get_transaction_bytes(&item.txids[0]).compat().await);
                        let mut tx: UtxoTx = try_s!(deserialize(tx_bytes.0.as_slice()).map_err(|e| ERRL!("{:?}", e)));
                        tx.tx_hash_algo = coin.as_ref().tx_hash_algo;
                        return Ok(Some(tx.into()));
                    }
                }
                Ok(None)
            },
        }
    };
    Box::new(fut.boxed().compat())
}

pub async fn watcher_search_for_swap_tx_spend<T: AsRef<UtxoCoinFields> + SwapOps>(
    coin: &T,
    input: WatcherSearchForSwapTxSpendInput<'_>,
    output_index: usize,
) -> Result<Option<FoundSwapTxSpend>, String> {
    search_for_swap_output_spend(
        coin.as_ref(),
        input.time_lock,
        &try_s!(Public::from_slice(input.taker_pub)),
        &try_s!(Public::from_slice(input.maker_pub)),
        input.secret_hash,
        input.tx,
        output_index,
        input.search_from_block,
    )
    .await
}

pub async fn search_for_swap_tx_spend_my<T: AsRef<UtxoCoinFields> + SwapOps>(
    coin: &T,
    input: SearchForSwapTxSpendInput<'_>,
    output_index: usize,
) -> Result<Option<FoundSwapTxSpend>, String> {
    search_for_swap_output_spend(
        coin.as_ref(),
        try_s!(input.time_lock.try_into()),
        coin.derive_htlc_key_pair(input.swap_unique_data).public(),
        &try_s!(Public::from_slice(input.other_pub)),
        input.secret_hash,
        input.tx,
        output_index,
        input.search_from_block,
    )
    .await
}

pub async fn search_for_swap_tx_spend_other<T: AsRef<UtxoCoinFields> + SwapOps>(
    coin: &T,
    input: SearchForSwapTxSpendInput<'_>,
    output_index: usize,
) -> Result<Option<FoundSwapTxSpend>, String> {
    search_for_swap_output_spend(
        coin.as_ref(),
        try_s!(input.time_lock.try_into()),
        &try_s!(Public::from_slice(input.other_pub)),
        coin.derive_htlc_key_pair(input.swap_unique_data).public(),
        input.secret_hash,
        input.tx,
        output_index,
        input.search_from_block,
    )
    .await
}

pub async fn get_taker_watcher_reward<T: UtxoCommonOps + SwapOps + MarketCoinOps>(
    coin: &T,
    other_coin: &MmCoinEnum,
    coin_amount: Option<BigDecimal>,
    other_coin_amount: Option<BigDecimal>,
    reward_amount: Option<BigDecimal>,
    wait_until: u64,
) -> Result<WatcherReward, MmError<WatcherRewardError>> {
    let reward_target = RewardTarget::PaymentReceiver;
    let is_exact_amount = reward_amount.is_some();

    let other_coin = match other_coin {
        MmCoinEnum::EthCoin(coin) => coin,
        _ => {
            return Err(WatcherRewardError::InvalidCoinType(
                "At least one coin must be Ethereum to use watcher rewards".to_string(),
            )
            .into())
        },
    };

    let amount = match reward_amount {
        Some(amount) => amount,
        None => {
            let gas_cost_eth = other_coin.get_watcher_reward_amount(wait_until).await?;
            let price_in_eth = if let (EthCoinType::Eth, Some(coin_amount), Some(other_coin_amount)) =
                (&other_coin.coin_type, coin_amount, other_coin_amount)
            {
                other_coin_amount.checked_div(coin_amount)
            } else {
                get_base_price_in_rel(Some(coin.ticker().to_string()), Some("ETH".to_string())).await
            };

            price_in_eth
                .and_then(|price_in_eth| gas_cost_eth.checked_div(price_in_eth))
                .ok_or_else(|| {
                    WatcherRewardError::RPCError(format!("Price of coin {} in ETH could not be found", coin.ticker()))
                })?
        },
    };

    let send_contract_reward_on_spend = false;

    Ok(WatcherReward {
        amount,
        is_exact_amount,
        reward_target,
        send_contract_reward_on_spend,
    })
}

/// Extract a secret from the `spend_tx`.
/// Note spender could generate the spend with several inputs where the only one input is the p2sh script.
pub fn extract_secret(secret_hash: &[u8], spend_tx: &[u8]) -> Result<Vec<u8>, String> {
    let spend_tx: UtxoTx = try_s!(deserialize(spend_tx).map_err(|e| ERRL!("{:?}", e)));
    let expected_secret_hash = if secret_hash.len() == 32 {
        ripemd160(secret_hash)
    } else {
        H160::from(secret_hash)
    };
    for input in spend_tx.inputs.into_iter() {
        let script: Script = input.script_sig.clone().into();
        for instruction in script.iter().flatten() {
            if instruction.opcode == Opcode::OP_PUSHBYTES_32 {
                if let Some(secret) = instruction.data {
                    let actual_secret_hash = dhash160(secret);
                    if actual_secret_hash == expected_secret_hash {
                        return Ok(secret.to_vec());
                    }
                }
            }
        }
    }
    ERR!("Couldn't extract secret")
}

pub fn my_address<T: UtxoCommonOps>(coin: &T) -> MmResult<String, MyAddressError> {
    match coin.as_ref().derivation_method {
        DerivationMethod::SingleAddress(ref my_address) => {
            my_address.display_address().map_to_mm(MyAddressError::InternalError)
        },
        DerivationMethod::HDWallet(_) => MmError::err(MyAddressError::UnexpectedDerivationMethod(
            "'my_address' is deprecated for HD wallets".to_string(),
        )),
    }
}

/// Hash message for signature using Bitcoin's message signing format.
/// sha256(sha256(PREFIX_LENGTH + PREFIX + MESSAGE_LENGTH + MESSAGE))
pub fn sign_message_hash(coin: &UtxoCoinFields, message: &str) -> Option<[u8; 32]> {
    let message_prefix = coin.conf.sign_message_prefix.clone()?;
    let mut stream = Stream::new();
    let prefix_len = CompactInteger::from(message_prefix.len());
    prefix_len.serialize(&mut stream);
    stream.append_slice(message_prefix.as_bytes());
    let msg_len = CompactInteger::from(message.len());
    msg_len.serialize(&mut stream);
    stream.append_slice(message.as_bytes());
    Some(dhash256(&stream.out()).take())
}

pub fn sign_message(coin: &UtxoCoinFields, message: &str) -> SignatureResult<String> {
    let message_hash = sign_message_hash(coin, message).ok_or(SignatureError::PrefixNotFound)?;
    let private_key = coin.priv_key_policy.activated_key_or_err()?.private();
    let signature = private_key.sign_compact(&H256::from(message_hash))?;
    Ok(base64::encode(&*signature))
}

pub fn verify_message<T: UtxoCommonOps>(
    coin: &T,
    signature_base64: &str,
    message: &str,
    address: &str,
) -> VerificationResult<bool> {
    let message_hash = sign_message_hash(coin.as_ref(), message).ok_or(VerificationError::PrefixNotFound)?;
    let signature = CompactSignature::from(base64::decode(signature_base64)?);
    let recovered_pubkey = Public::recover_compact(&H256::from(message_hash), &signature)?;
    let received_address = checked_address_from_str(coin, address)?;
    Ok(AddressHashEnum::from(recovered_pubkey.address_hash()) == *received_address.hash())
}

pub fn my_balance<T>(coin: T) -> BalanceFut<CoinBalance>
where
    T: UtxoCommonOps + GetUtxoListOps + MarketCoinOps,
{
    let my_address = try_f!(coin
        .as_ref()
        .derivation_method
        .single_addr_or_err()
        .mm_err(BalanceError::from))
    .clone();
    let fut = async move { address_balance(&coin, &my_address).await };
    Box::new(fut.boxed().compat())
}

/// Takes raw transaction as input and returns tx hash in hexadecimal format
pub fn send_raw_tx(coin: &UtxoCoinFields, tx: &str) -> Box<dyn Future<Item = String, Error = String> + Send> {
    let bytes = try_fus!(hex::decode(tx));
    Box::new(
        coin.rpc_client
            .send_raw_transaction(bytes.into())
            .map_err(|e| ERRL!("{}", e))
            .map(|hash| format!("{:?}", hash)),
    )
}

/// Takes raw transaction bytes as input and returns tx hash in hexadecimal format
pub fn send_raw_tx_bytes(
    coin: &UtxoCoinFields,
    tx_bytes: &[u8],
) -> Box<dyn Future<Item = String, Error = String> + Send> {
    Box::new(
        coin.rpc_client
            .send_raw_transaction(tx_bytes.into())
            .map_err(|e| ERRL!("{}", e))
            .map(|hash| format!("{:?}", hash)),
    )
}

/// Helper to load unspent outputs from cache or rpc
/// also returns first previous scriptpubkey
async fn get_unspents_for_inputs(
    coin: &UtxoCoinFields,
    inputs: &Vec<TransactionInput>,
) -> Result<(Option<Script>, Vec<UnspentInfo>), RawTransactionError> {
    let txids_reversed = inputs
        .iter()
        .map(|input| input.previous_output.hash.reversed().into()) // reverse hashes to send to electrum
        .collect::<HashSet<H256Json>>();

    if txids_reversed.is_empty() {
        return Ok((None, vec![]));
    }

    let prev_txns_loaded = utxo_common::get_verbose_transactions_from_cache_or_rpc(coin, txids_reversed)
        .await
        .map_err(|err| RawTransactionError::InvalidParam(err.to_string()))?;

    let mut prev_script = None;
    let mut unspents_loaded = vec![];

    for input in inputs {
        let prev_tx = prev_txns_loaded
            .iter()
            .find(|prev_tx| (*prev_tx.0).reversed() == input.previous_output.hash.into())
            .ok_or_else(|| {
                RawTransactionError::NonExistentPrevOutputError(format!(
                    "{}/{}",
                    input.previous_output.hash, input.previous_output.index
                ))
            });
        let prev_tx = prev_tx?.1.to_inner();
        if (input.previous_output.index as usize) >= prev_tx.vout.len() {
            return Err(RawTransactionError::NonExistentPrevOutputError(format!(
                "{}/{}",
                input.previous_output.hash, input.previous_output.index
            )));
        }
        if prev_script.is_none() {
            // get first previous script pubkey
            let script_bytes: Vec<u8> = prev_tx.vout[input.previous_output.index as usize]
                .clone()
                .script
                .hex
                .into();
            prev_script = Some(Script::from(script_bytes));
        }
        let prev_amount = prev_tx.vout[input.previous_output.index as usize]
            .value
            .ok_or_else(|| {
                RawTransactionError::NonExistentPrevOutputError(String::from("No amount in transaction vout"))
            })?;
        let prev_amount = prev_amount.try_into().expect("Amount conversion must succeed");

        unspents_loaded.push(UnspentInfo {
            outpoint: OutPoint {
                hash: input.previous_output.hash,
                index: input.previous_output.index,
            },
            value: sat_from_big_decimal(&prev_amount, coin.decimals)
                .expect("Conversion to satoshi from bigdecimal must be valid"),
            height: None,
        });
    }
    Ok((prev_script, unspents_loaded))
}

/// Takes args with a raw transaction in hexadecimal format and previous transactions data as input
/// Returns signed tx in hexadecimal format
pub async fn sign_raw_tx<T: AsRef<UtxoCoinFields> + UtxoTxGenerationOps>(
    coin: &T,
    args: &SignRawTransactionRequest,
) -> RawTransactionResult {
    if let SignRawTransactionEnum::UTXO(utxo_args) = &args.tx {
        sign_raw_utxo_tx(coin, utxo_args).await
    } else {
        MmError::err(RawTransactionError::InvalidParam("utxo type expected".to_string()))
    }
}

/// Takes args with a raw transaction in hexadecimal format and previous transactions data as input
/// Returns signed tx in hexadecimal format
async fn sign_raw_utxo_tx<T: AsRef<UtxoCoinFields> + UtxoTxGenerationOps>(
    coin: &T,
    args: &SignUtxoTransactionParams,
) -> RawTransactionResult {
    let tx_bytes =
        hex::decode(args.tx_hex.as_bytes()).map_to_mm(|e| RawTransactionError::DecodeError(e.to_string()))?;
    let tx: UtxoTx = deserialize(tx_bytes.as_slice()).map_to_mm(|e| RawTransactionError::DecodeError(e.to_string()))?;

    let mut prev_script = HashSet::new();
    let mut unspents = vec![];

    if let Some(prev_txns) = &args.prev_txns {
        for prev_utxo in prev_txns.iter() {
            // get first previous utxo script assuming all are the same
            let script_bytes = hex::decode(prev_utxo.clone().script_pub_key)
                .map_to_mm(|e| RawTransactionError::DecodeError(e.to_string()))?;
            prev_script.insert(Script::from(script_bytes));

            let prev_hash = hex::decode(prev_utxo.tx_hash.as_bytes())
                .map_to_mm(|e| RawTransactionError::DecodeError(e.to_string()))?;

            unspents.push(UnspentInfo {
                outpoint: OutPoint {
                    hash: prev_hash.as_slice().into(),
                    index: prev_utxo.index,
                },
                value: sat_from_big_decimal(&prev_utxo.amount, coin.as_ref().decimals)
                    .expect("conversion satoshi from bigdecimal must be valid"),
                height: None,
            });
        }
    }

    let inputs_to_load = tx
        .inputs()
        .iter()
        .cloned()
        .filter(|input| {
            !unspents.iter().any(|u| {
                u.outpoint.hash == input.previous_output.hash && u.outpoint.index == input.previous_output.index
            })
        })
        .collect::<Vec<TransactionInput>>();

    // If some previous utxos are not provided in the params load them from the chain
    if !inputs_to_load.is_empty() {
        let (loaded_script, loaded_unspents) = get_unspents_for_inputs(coin.as_ref(), &inputs_to_load).await?;
        unspents.extend(loaded_unspents.into_iter());
        if let Some(loaded_script) = loaded_script {
            prev_script.insert(loaded_script);
        }
    }

    // TODO: use zeroise for privkey
    let key_pair = coin.as_ref().priv_key_policy.activated_key_or_err().unwrap();

    let mut input_signer_incomplete = TransactionInputSigner::from(tx);
    input_signer_incomplete.consensus_branch_id = coin.as_ref().conf.consensus_branch_id;

    let builder = UtxoTxBuilder::new(coin)
        .with_transaction_input_signer(input_signer_incomplete)
        .add_available_inputs(unspents);
    let unsigned = builder
        .build_unchecked()
        .await
        .map_err(|e| RawTransactionError::InvalidParam(e.to_string()))?;
    debug!("Unsigned tx = {:?} for signing", unsigned);

    let prev_script = match prev_script.len() {
        0 => {
            return MmError::err(RawTransactionError::NonExistentPrevOutputError(String::from(
                "no previous script",
            )))
        },
        1 => prev_script.into_iter().next().unwrap(),
        _ => {
            return MmError::err(RawTransactionError::InvalidParam(String::from(
                "spends are from same address only",
            )))
        },
    };
    let signature_version = match prev_script.is_pay_to_witness_key_hash() {
        true => SignatureVersion::WitnessV0,
        _ => coin.as_ref().conf.signature_version,
    };
    let tx_signed = sign_tx(
        unsigned,
        key_pair,
        prev_script,
        signature_version,
        coin.as_ref().conf.fork_id,
    )
    .map_err(|err| RawTransactionError::SigningError(err.to_string()))?;

    let tx_signed_bytes = serialize_with_flags(&tx_signed, SERIALIZE_TRANSACTION_WITNESS);
    Ok(RawTransactionRes {
        tx_hex: tx_signed_bytes.into(),
    })
}

pub fn wait_for_confirmations(
    coin: &UtxoCoinFields,
    input: ConfirmPaymentInput,
) -> Box<dyn Future<Item = (), Error = String> + Send> {
    let mut tx: UtxoTx = try_fus!(deserialize(input.payment_tx.as_slice()).map_err(|e| ERRL!("{:?}", e)));
    tx.tx_hash_algo = coin.tx_hash_algo;
    coin.rpc_client.wait_for_confirmations(
        tx.hash().reversed().into(),
        tx.expiry_height,
        input.confirmations as u32,
        input.requires_nota,
        input.wait_until,
        input.check_every,
    )
}

#[derive(Debug)]
pub enum WaitForOutputSpendErr {
    NoOutputWithIndex(usize),
    Timeout { wait_until: u64, now: u64 },
}

pub async fn wait_for_output_spend_impl(
    coin: &UtxoCoinFields,
    tx: &UtxoTx,
    output_index: usize,
    from_block: u64,
    wait_until: u64,
    check_every: f64,
) -> MmResult<UtxoTx, WaitForOutputSpendErr> {
    loop {
        let script_pubkey = &tx
            .outputs
            .get(output_index)
            .or_mm_err(|| WaitForOutputSpendErr::NoOutputWithIndex(output_index))?
            .script_pubkey;

        match coin
            .rpc_client
            .find_output_spend(
                tx.hash(),
                script_pubkey,
                output_index,
                BlockHashOrHeight::Height(from_block as i64),
                coin.tx_hash_algo,
            )
            .compat()
            .await
        {
            Ok(Some(spent_output_info)) => {
                return Ok(spent_output_info.spending_tx);
            },
            Ok(None) => (),
            Err(e) => error!("Error on find_output_spend_of_tx: {}", e),
        };

        let now = now_sec();
        if now > wait_until {
            return MmError::err(WaitForOutputSpendErr::Timeout { wait_until, now });
        }
        Timer::sleep(check_every).await;
    }
}

pub fn wait_for_output_spend<T: AsRef<UtxoCoinFields> + Send + Sync + 'static>(
    coin: T,
    tx_bytes: &[u8],
    output_index: usize,
    from_block: u64,
    wait_until: u64,
    check_every: f64,
) -> TransactionFut {
    let mut tx: UtxoTx = try_tx_fus!(deserialize(tx_bytes).map_err(|e| ERRL!("{:?}", e)));
    tx.tx_hash_algo = coin.as_ref().tx_hash_algo;

    let fut = async move {
        wait_for_output_spend_impl(coin.as_ref(), &tx, output_index, from_block, wait_until, check_every)
            .await
            .map(|tx| tx.into())
            .map_err(|e| TransactionErr::Plain(format!("{:?}", e)))
    };
    Box::new(fut.boxed().compat())
}

pub fn tx_enum_from_bytes(coin: &UtxoCoinFields, bytes: &[u8]) -> Result<TransactionEnum, MmError<TxMarshalingErr>> {
    let mut transaction: UtxoTx = deserialize(bytes).map_to_mm(|e| TxMarshalingErr::InvalidInput(e.to_string()))?;

    let serialized_length = transaction.tx_hex().len();
    if bytes.len() != serialized_length {
        return MmError::err(TxMarshalingErr::CrossCheckFailed(format!(
            "Expected '{}' lenght of the serialized transaction, found '{}'",
            bytes.len(),
            serialized_length
        )));
    }

    transaction.tx_hash_algo = coin.tx_hash_algo;
    Ok(transaction.into())
}

pub fn current_block(coin: &UtxoCoinFields) -> Box<dyn Future<Item = u64, Error = String> + Send> {
    Box::new(coin.rpc_client.get_block_count().map_err(|e| ERRL!("{}", e)))
}

pub fn display_priv_key(coin: &UtxoCoinFields) -> Result<String, String> {
    match coin.priv_key_policy {
        PrivKeyPolicy::Iguana(ref key_pair) => Ok(key_pair.private().to_string()),
        PrivKeyPolicy::HDWallet {
            activated_key: ref activated_key_pair,
            ..
        } => Ok(activated_key_pair.private().to_string()),
        PrivKeyPolicy::Trezor => ERR!("'display_priv_key' doesn't support Hardware Wallets"),
        #[cfg(target_arch = "wasm32")]
        PrivKeyPolicy::Metamask(_) => ERR!("'display_priv_key' doesn't support Metamask"),
    }
}

pub fn min_tx_amount(coin: &UtxoCoinFields) -> BigDecimal {
    big_decimal_from_sat(coin.dust_amount as i64, coin.decimals)
}

pub fn min_trading_vol(coin: &UtxoCoinFields) -> MmNumber {
    if coin.conf.ticker == "BTC" {
        return MmNumber::from(MIN_BTC_TRADING_VOL);
    }
    let dust_multiplier = MmNumber::from(10);
    dust_multiplier * min_tx_amount(coin).into()
}

pub fn is_asset_chain(coin: &UtxoCoinFields) -> bool { coin.conf.asset_chain }

pub async fn get_raw_transaction(coin: &UtxoCoinFields, req: RawTransactionRequest) -> RawTransactionResult {
    let hash = H256Json::from_str(&req.tx_hash).map_to_mm(|e| RawTransactionError::InvalidHashError(e.to_string()))?;
    let hex = coin
        .rpc_client
        .get_transaction_bytes(&hash)
        .compat()
        .await
        .map_err(|e| RawTransactionError::Transport(e.to_string()))?;
    Ok(RawTransactionRes { tx_hex: hex })
}

pub async fn get_tx_hex_by_hash(coin: &UtxoCoinFields, tx_hash: Vec<u8>) -> RawTransactionResult {
    let hex = coin
        .rpc_client
        .get_transaction_bytes(&H256Json::from(tx_hash.as_slice()))
        .compat()
        .await
        .map_err(|e| RawTransactionError::Transport(e.to_string()))?;
    Ok(RawTransactionRes { tx_hex: hex })
}

pub async fn withdraw<T>(coin: T, req: WithdrawRequest) -> WithdrawResult
where
    T: UtxoCommonOps + GetUtxoListOps + MarketCoinOps,
{
    StandardUtxoWithdraw::new(coin, req)?.build().await
}

pub async fn init_withdraw<T>(
    ctx: MmArc,
    coin: T,
    req: WithdrawRequest,
    task_handle: WithdrawTaskHandleShared,
) -> WithdrawResult
where
    T: UtxoCommonOps
        + GetUtxoListOps
        + UtxoSignerOps
        + CoinWithDerivationMethod
        + GetWithdrawSenderAddress<Address = Address, Pubkey = Public>,
{
    InitUtxoWithdraw::new(ctx, coin, req, task_handle).await?.build().await
}

pub async fn get_withdraw_from_address<T>(
    coin: &T,
    req: &WithdrawRequest,
) -> MmResult<WithdrawSenderAddress<Address, Public>, WithdrawError>
where
    T: CoinWithDerivationMethod<Address = Address, HDWallet = <T as HDWalletCoinOps>::HDWallet>
        + HDWalletCoinOps<Address = Address, Pubkey = Public>
        + UtxoCommonOps,
{
    match coin.derivation_method() {
        DerivationMethod::SingleAddress(my_address) => get_withdraw_iguana_sender(coin, req, my_address),
        DerivationMethod::HDWallet(hd_wallet) => get_withdraw_hd_sender(coin, req, hd_wallet).await,
    }
}

#[allow(clippy::result_large_err)]
pub fn get_withdraw_iguana_sender<T: UtxoCommonOps>(
    coin: &T,
    req: &WithdrawRequest,
    my_address: &Address,
) -> MmResult<WithdrawSenderAddress<Address, Public>, WithdrawError> {
    if req.from.is_some() {
        let error = "'from' is not supported if the coin is initialized with an Iguana private key";
        return MmError::err(WithdrawError::UnexpectedFromAddress(error.to_owned()));
    }
    let pubkey = coin
        .my_public_key()
        .mm_err(|e| WithdrawError::InternalError(e.to_string()))?;
    Ok(WithdrawSenderAddress {
        address: my_address.clone(),
        pubkey: *pubkey,
        derivation_path: None,
    })
}

pub async fn get_withdraw_hd_sender<T>(
    coin: &T,
    req: &WithdrawRequest,
    hd_wallet: &T::HDWallet,
) -> MmResult<WithdrawSenderAddress<Address, Public>, WithdrawError>
where
    T: HDWalletCoinOps<Address = Address, Pubkey = Public> + Sync,
{
    let HDAccountAddressId {
        account_id,
        chain,
        address_id,
    } = match req.from.clone().or_mm_err(|| WithdrawError::FromAddressNotFound)? {
        WithdrawFrom::AddressId(id) => id,
        WithdrawFrom::DerivationPath { derivation_path } => {
            let derivation_path = StandardHDPath::from_str(&derivation_path)
                .map_to_mm(StandardHDPathError::from)
                .mm_err(|e| WithdrawError::UnexpectedFromAddress(e.to_string()))?;
            let coin_type = derivation_path.coin_type();
            let expected_coin_type = hd_wallet.coin_type();
            if coin_type != expected_coin_type {
                let error = format!(
                    "Derivation path '{}' must has '{}' coin type",
                    derivation_path, expected_coin_type
                );
                return MmError::err(WithdrawError::UnexpectedFromAddress(error));
            }
            HDAccountAddressId::from(derivation_path)
        },
        WithdrawFrom::HDWalletAddress(_) => {
            return MmError::err(WithdrawError::UnsupportedError(
                "`WithdrawFrom::HDWalletAddress` is not supported for `get_withdraw_hd_sender`".to_string(),
            ))
        },
    };

    let hd_account = hd_wallet
        .get_account(account_id)
        .await
        .or_mm_err(|| WithdrawError::UnknownAccount { account_id })?;
    let hd_address = coin.derive_address(&hd_account, chain, address_id).await?;

    let is_address_activated = hd_account
        .is_address_activated(chain, address_id)
        // If [`HDWalletCoinOps::derive_address`] succeeds, [`HDAccountOps::is_address_activated`] shouldn't fails with an `InvalidBip44ChainError`.
        .mm_err(|e| WithdrawError::InternalError(e.to_string()))?;
    if !is_address_activated {
        let error = format!("'{}' address is not activated", hd_address.address);
        return MmError::err(WithdrawError::UnexpectedFromAddress(error));
    }

    Ok(WithdrawSenderAddress::from(hd_address))
}

pub fn decimals(coin: &UtxoCoinFields) -> u8 { coin.decimals }

pub fn convert_to_address<T: UtxoCommonOps>(coin: &T, from: &str, to_address_format: Json) -> Result<String, String> {
    let to_address_format: UtxoAddressFormat =
        json::from_value(to_address_format).map_err(|e| ERRL!("Error on parse UTXO address format {:?}", e))?;
    let from_address = try_s!(coin.address_from_str(from));
    match to_address_format {
        UtxoAddressFormat::Standard => {
            // assuming convertion to p2pkh
            Ok(LegacyAddress::new(
                from_address.hash(),
                coin.as_ref().conf.address_prefixes.p2pkh.clone(),
                coin.as_ref().conf.checksum_type,
            )
            .to_string())
        },
        UtxoAddressFormat::Segwit => {
            let bech32_hrp = &coin.as_ref().conf.bech32_hrp;
            match bech32_hrp {
                Some(hrp) => Ok(SegwitAddress::new(from_address.hash(), hrp.clone()).to_string()),
                None => ERR!("Cannot convert to a segwit address for a coin with no bech32_hrp in config"),
            }
        },
        UtxoAddressFormat::CashAddress { network, .. } => Ok(try_s!(from_address
            .to_cashaddress(&network, &coin.as_ref().conf.address_prefixes)
            .and_then(|cashaddress| cashaddress.encode()))),
    }
}

pub fn validate_address<T: UtxoCommonOps>(coin: &T, address: &str) -> ValidateAddressResult {
    let result = coin.address_from_str(address);
    let address = match result {
        Ok(addr) => addr,
        Err(e) => {
            return ValidateAddressResult {
                is_valid: false,
                reason: Some(e.to_string()),
            }
        },
    };

    let is_p2pkh = address.prefix() == &coin.as_ref().conf.address_prefixes.p2pkh;
    let is_p2sh = address.prefix() == &coin.as_ref().conf.address_prefixes.p2sh;
    let is_segwit =
        address.hrp().is_some() && address.hrp() == &coin.as_ref().conf.bech32_hrp && coin.as_ref().conf.segwit;

    if is_p2pkh || is_p2sh || is_segwit {
        ValidateAddressResult {
            is_valid: true,
            reason: None,
        }
    } else {
        ValidateAddressResult {
            is_valid: false,
            reason: Some(ERRL!("Address {} has invalid prefix", address)),
        }
    }
}

// Quick fix for null valued coin fields in fee details of old tx history entries
#[cfg(not(target_arch = "wasm32"))]
async fn tx_history_migration_1<T>(coin: &T, ctx: &MmArc)
where
    T: UtxoStandardOps + UtxoCommonOps + MmCoin + MarketCoinOps,
{
    const MIGRATION_NUMBER: u64 = 1;
    let history = match coin.load_history_from_file(ctx).compat().await {
        Ok(history) => history,
        Err(e) => {
            log_tag!(
                ctx,
                "",
                "tx_history",
                "coin" => coin.as_ref().conf.ticker;
                fmt = "Error {} on 'load_history_from_file', stop the history loop", e
            );
            return;
        },
    };

    let mut updated = false;
    let to_write: Vec<TransactionDetails> = history
        .into_iter()
        .filter_map(|mut tx| match tx.fee_details {
            Some(TxFeeDetails::Utxo(ref mut fee_details)) => {
                if fee_details.coin.is_none() {
                    fee_details.coin = Some(String::from(&tx.coin));
                    updated = true;
                }
                Some(tx)
            },
            Some(_) => None,
            None => Some(tx),
        })
        .collect();

    if updated {
        if let Err(e) = coin.save_history_to_file(ctx, to_write).compat().await {
            log_tag!(
                ctx,
                "",
                "tx_history",
                "coin" => coin.as_ref().conf.ticker;
                fmt = "Error {} on 'save_history_to_file'", e
            );
            return;
        };
    }
    if let Err(e) = coin.update_migration_file(ctx, MIGRATION_NUMBER).compat().await {
        log_tag!(
            ctx,
            "",
            "tx_history",
            "coin" => coin.as_ref().conf.ticker;
            fmt = "Error {} on 'update_migration_file'", e
        );
    };
}

#[cfg(not(target_arch = "wasm32"))]
async fn migrate_tx_history<T>(coin: &T, ctx: &MmArc)
where
    T: UtxoStandardOps + UtxoCommonOps + MmCoin + MarketCoinOps,
{
    let current_migration = coin.get_tx_history_migration(ctx).compat().await.unwrap_or(0);
    if current_migration < 1 {
        tx_history_migration_1(coin, ctx).await;
    }
}

#[allow(clippy::cognitive_complexity)]
pub async fn process_history_loop<T>(coin: T, ctx: MmArc)
where
    T: UtxoStandardOps + UtxoCommonOps + MmCoin + MarketCoinOps,
{
    #[cfg(not(target_arch = "wasm32"))]
    migrate_tx_history(&coin, &ctx).await;

    let mut my_balance: Option<CoinBalance> = None;
    let history = match coin.load_history_from_file(&ctx).compat().await {
        Ok(history) => history,
        Err(e) => {
            log_tag!(
                ctx,
                "",
                "tx_history",
                "coin" => coin.as_ref().conf.ticker;
                fmt = "Error {} on 'load_history_from_file', stop the history loop", e
            );
            return;
        },
    };

    let mut history_map: HashMap<H256Json, TransactionDetails> = history
        .into_iter()
        .filter_map(|tx| {
            let tx_hash = H256Json::from_str(&tx.tx_hash).ok()?;
            Some((tx_hash, tx))
        })
        .collect();

    let mut success_iteration = 0i32;
    loop {
        if ctx.is_stopping() {
            break;
        };
        {
            let coins_ctx = CoinsContext::from_ctx(&ctx).unwrap();
            let coins = coins_ctx.coins.lock().await;
            if !coins.contains_key(&coin.as_ref().conf.ticker) {
                log_tag!(ctx, "", "tx_history", "coin" => coin.as_ref().conf.ticker; fmt = "Loop stopped");
                break;
            };
        }

        let actual_balance = match coin.my_balance().compat().await {
            Ok(actual_balance) => Some(actual_balance),
            Err(err) => {
                log_tag!(
                    ctx,
                    "",
                    "tx_history",
                    "coin" => coin.as_ref().conf.ticker;
                    fmt = "Error {:?} on getting balance", err
                );
                None
            },
        };

        let need_update = history_map.iter().any(|(_, tx)| tx.should_update());
        match (&my_balance, &actual_balance) {
            (Some(prev_balance), Some(actual_balance)) if prev_balance == actual_balance && !need_update => {
                // my balance hasn't been changed, there is no need to reload tx_history
                Timer::sleep(30.).await;
                continue;
            },
            _ => (),
        }

        let metrics = ctx.metrics.clone();
        let tx_ids = match coin.request_tx_history(metrics).await {
            RequestTxHistoryResult::Ok(tx_ids) => tx_ids,
            RequestTxHistoryResult::Retry { error } => {
                log_tag!(
                    ctx,
                    "",
                    "tx_history",
                    "coin" => coin.as_ref().conf.ticker;
                    fmt = "{}, retrying", error
                );
                Timer::sleep(10.).await;
                continue;
            },
            RequestTxHistoryResult::HistoryTooLarge => {
                log_tag!(
                    ctx,
                    "",
                    "tx_history",
                    "coin" => coin.as_ref().conf.ticker;
                    fmt = "Got `history too large`, stopping further attempts to retrieve it"
                );
                *coin.as_ref().history_sync_state.lock().unwrap() = HistorySyncState::Error(json!({
                    "code": HISTORY_TOO_LARGE_ERR_CODE,
                    "message": "Got `history too large` error from Electrum server. History is not available",
                }));
                break;
            },
            RequestTxHistoryResult::CriticalError(e) => {
                log_tag!(
                    ctx,
                    "",
                    "tx_history",
                    "coin" => coin.as_ref().conf.ticker;
                    fmt = "{}, stopping futher attempts to retreive it", e
                );
                break;
            },
        };

        // Remove transactions in the history_map that are not in the requested transaction list anymore
        let history_length = history_map.len();
        let requested_ids: HashSet<H256Json> = tx_ids.iter().map(|x| x.0).collect();
        history_map.retain(|hash, _| requested_ids.contains(hash));

        if history_map.len() < history_length {
            let to_write: Vec<TransactionDetails> = history_map.values().cloned().collect();
            if let Err(e) = coin.save_history_to_file(&ctx, to_write).compat().await {
                log_tag!(
                    ctx,
                    "",
                    "tx_history",
                    "coin" => coin.as_ref().conf.ticker;
                    fmt = "Error {} on 'save_history_to_file', stop the history loop", e
                );
                return;
            };
        }

        let mut transactions_left = if tx_ids.len() > history_map.len() {
            *coin.as_ref().history_sync_state.lock().unwrap() = HistorySyncState::InProgress(json!({
                "transactions_left": tx_ids.len() - history_map.len()
            }));
            tx_ids.len() - history_map.len()
        } else {
            *coin.as_ref().history_sync_state.lock().unwrap() = HistorySyncState::InProgress(json!({
                "transactions_left": 0
            }));
            0
        };

        // This is the cache of the already requested transactions.
        let mut input_transactions = HistoryUtxoTxMap::default();
        for (txid, height) in tx_ids {
            let mut updated = false;
            match history_map.entry(txid) {
                Entry::Vacant(e) => {
                    mm_counter!(ctx.metrics, "tx.history.request.count", 1, "coin" => coin.as_ref().conf.ticker.clone(), "method" => "tx_detail_by_hash");

                    match coin.tx_details_by_hash(&txid.0, &mut input_transactions).await {
                        Ok(mut tx_details) => {
                            mm_counter!(ctx.metrics, "tx.history.response.count", 1, "coin" => coin.as_ref().conf.ticker.clone(), "method" => "tx_detail_by_hash");

                            if tx_details.block_height == 0 && height > 0 {
                                tx_details.block_height = height;
                            }

                            e.insert(tx_details);
                            if transactions_left > 0 {
                                transactions_left -= 1;
                                *coin.as_ref().history_sync_state.lock().unwrap() =
                                    HistorySyncState::InProgress(json!({ "transactions_left": transactions_left }));
                            }
                            updated = true;
                        },
                        Err(e) => log_tag!(
                            ctx,
                            "",
                            "tx_history",
                            "coin" => coin.as_ref().conf.ticker;
                            fmt = "Error {:?} on getting the details of {:?}, skipping the tx", e, txid
                        ),
                    }
                },
                Entry::Occupied(mut e) => {
                    // update block height for previously unconfirmed transaction
                    if e.get().should_update_block_height() && height > 0 {
                        e.get_mut().block_height = height;
                        updated = true;
                    }
                    if e.get().should_update_timestamp() || e.get().firo_negative_fee() {
                        mm_counter!(ctx.metrics, "tx.history.request.count", 1, "coin" => coin.as_ref().conf.ticker.clone(), "method" => "tx_detail_by_hash");

                        match coin.tx_details_by_hash(&txid.0, &mut input_transactions).await {
                            Ok(tx_details) => {
                                mm_counter!(ctx.metrics, "tx.history.response.count", 1, "coin" => coin.as_ref().conf.ticker.clone(), "method" => "tx_detail_by_hash");
                                // replace with new tx details in case we need to update any data
                                e.insert(tx_details);
                                updated = true;
                            },
                            Err(e) => log_tag!(
                                ctx,
                                "",
                                "tx_history",
                                "coin" => coin.as_ref().conf.ticker;
                                fmt = "Error {:?} on getting the details of {:?}, skipping the tx", e, txid
                            ),
                        }
                    }
                },
            }
            if updated {
                let to_write: Vec<TransactionDetails> = history_map.values().cloned().collect();
                if let Err(e) = coin.save_history_to_file(&ctx, to_write).compat().await {
                    log_tag!(
                        ctx,
                        "",
                        "tx_history",
                        "coin" => coin.as_ref().conf.ticker;
                        fmt = "Error {} on 'save_history_to_file', stop the history loop", e
                    );
                    return;
                };
            }
        }
        *coin.as_ref().history_sync_state.lock().unwrap() = HistorySyncState::Finished;

        if success_iteration == 0 {
            log_tag!(
                ctx,
                "😅",
                "tx_history",
                "coin" => coin.as_ref().conf.ticker;
                fmt = "history has been loaded successfully"
            );
        }

        my_balance = actual_balance;
        success_iteration += 1;
        Timer::sleep(30.).await;
    }
}

pub async fn request_tx_history<T>(coin: &T, metrics: MetricsArc) -> RequestTxHistoryResult
where
    T: UtxoCommonOps + MmCoin + MarketCoinOps,
{
    let my_address = match coin.my_address() {
        Ok(addr) => addr,
        Err(e) => {
            return RequestTxHistoryResult::CriticalError(ERRL!(
                "Error on getting self address: {}. Stop tx history",
                e
            ))
        },
    };

    let tx_ids = match &coin.as_ref().rpc_client {
        UtxoRpcClientEnum::Native(client) => {
            let mut from = 0;
            let mut all_transactions = vec![];
            loop {
                mm_counter!(metrics, "tx.history.request.count", 1,
                    "coin" => coin.as_ref().conf.ticker.clone(), "client" => "native", "method" => "listtransactions");

                let transactions = match client.list_transactions(100, from).compat().await {
                    Ok(value) => value,
                    Err(e) => {
                        return RequestTxHistoryResult::Retry {
                            error: ERRL!("Error {} on list transactions", e),
                        };
                    },
                };

                mm_counter!(metrics, "tx.history.response.count", 1,
                    "coin" => coin.as_ref().conf.ticker.clone(), "client" => "native", "method" => "listtransactions");

                if transactions.is_empty() {
                    break;
                }
                from += 100;
                all_transactions.extend(transactions);
            }

            mm_counter!(metrics, "tx.history.response.total_length", all_transactions.len() as u64,
                "coin" => coin.as_ref().conf.ticker.clone(), "client" => "native", "method" => "listtransactions");

            all_transactions
                .into_iter()
                .filter_map(|item| {
                    if item.address == my_address {
                        Some((item.txid, item.blockindex))
                    } else {
                        None
                    }
                })
                .collect()
        },
        UtxoRpcClientEnum::Electrum(client) => {
            let my_address = match coin.as_ref().derivation_method.single_addr_or_err() {
                Ok(my_address) => my_address,
                Err(e) => return RequestTxHistoryResult::CriticalError(e.to_string()),
            };
            let script = match output_script(my_address) {
                Ok(script) => script,
                Err(err) => return RequestTxHistoryResult::CriticalError(err.to_string()),
            };
            let script_hash = electrum_script_hash(&script);

            mm_counter!(metrics, "tx.history.request.count", 1,
                "coin" => coin.as_ref().conf.ticker.clone(), "client" => "electrum", "method" => "blockchain.scripthash.get_history");

            let electrum_history = match client.scripthash_get_history(&hex::encode(script_hash)).compat().await {
                Ok(value) => value,
                Err(e) => match &e.error {
                    JsonRpcErrorType::InvalidRequest(e)
                    | JsonRpcErrorType::Parse(_, e)
                    | JsonRpcErrorType::Transport(e)
                    | JsonRpcErrorType::Internal(e) => {
                        return RequestTxHistoryResult::Retry {
                            error: ERRL!("Error {} on scripthash_get_history", e),
                        };
                    },
                    JsonRpcErrorType::Response(_addr, err) => {
                        if HISTORY_TOO_LARGE_ERROR.eq(err) {
                            return RequestTxHistoryResult::HistoryTooLarge;
                        } else {
                            return RequestTxHistoryResult::Retry {
                                error: ERRL!("Error {:?} on scripthash_get_history", e),
                            };
                        }
                    },
                },
            };
            mm_counter!(metrics, "tx.history.response.count", 1,
                "coin" => coin.as_ref().conf.ticker.clone(), "client" => "electrum", "method" => "blockchain.scripthash.get_history");

            mm_counter!(metrics, "tx.history.response.total_length", electrum_history.len() as u64,
                "coin" => coin.as_ref().conf.ticker.clone(), "client" => "electrum", "method" => "blockchain.scripthash.get_history");

            // electrum returns the most recent transactions in the end but we need to
            // process them first so rev is required
            electrum_history
                .into_iter()
                .rev()
                .map(|item| {
                    let height = if item.height < 0 { 0 } else { item.height as u64 };
                    (item.tx_hash, height)
                })
                .collect()
        },
    };
    RequestTxHistoryResult::Ok(tx_ids)
}

pub async fn tx_details_by_hash<T: UtxoCommonOps>(
    coin: &T,
    hash: &[u8],
    input_transactions: &mut HistoryUtxoTxMap,
) -> Result<TransactionDetails, String> {
    let ticker = &coin.as_ref().conf.ticker;
    let hash = H256Json::from(hash);
    let verbose_tx = try_s!(coin.as_ref().rpc_client.get_verbose_transaction(&hash).compat().await);
    let mut tx: UtxoTx = try_s!(deserialize(verbose_tx.hex.as_slice()).map_err(|e| ERRL!("{:?}", e)));
    tx.tx_hash_algo = coin.as_ref().tx_hash_algo;
    let my_address = try_s!(coin.as_ref().derivation_method.single_addr_or_err());

    input_transactions.insert(hash, HistoryUtxoTx {
        tx: tx.clone(),
        height: verbose_tx.height,
    });

    let mut input_amount = 0;
    let mut output_amount = 0;
    let mut from_addresses = Vec::new();
    let mut to_addresses = Vec::new();
    let mut spent_by_me = 0;
    let mut received_by_me = 0;

    for input in tx.inputs.iter() {
        // input transaction is zero if the tx is the coinbase transaction
        if input.previous_output.hash.is_zero() {
            continue;
        }

        let prev_tx_hash: H256Json = input.previous_output.hash.reversed().into();
        let prev_tx = try_s!(
            coin.get_mut_verbose_transaction_from_map_or_rpc(prev_tx_hash, input_transactions)
                .await
        );
        let prev_tx = &mut prev_tx.tx;
        prev_tx.tx_hash_algo = coin.as_ref().tx_hash_algo;

        let prev_output_index: usize = try_s!(input.previous_output.index.try_into());
        let prev_tx_output = prev_tx.outputs.get(prev_output_index).ok_or(ERRL!(
            "Previous output index is out of bound: coin={}, prev_output_index={}, prev_tx_hash={}, tx_hash={}, tx_hex={:02x}",
            ticker,
            prev_output_index,
            prev_tx_hash,
            hash,
            verbose_tx.hex,
        ))?;
        input_amount += prev_tx_output.value;
        let from: Vec<Address> = try_s!(coin.addresses_from_script(&prev_tx_output.script_pubkey.clone().into()));
        if from.contains(my_address) {
            spent_by_me += prev_tx_output.value;
        }
        from_addresses.extend(from.into_iter());
    }

    for output in tx.outputs.iter() {
        output_amount += output.value;
        let to = try_s!(coin.addresses_from_script(&output.script_pubkey.clone().into()));
        if to.contains(my_address) {
            received_by_me += output.value;
        }
        to_addresses.extend(to.into_iter());
    }

    // TODO uncomment this when `calc_interest_of_tx` works fine
    // let (fee, kmd_rewards) = if ticker == "KMD" {
    //     let kmd_rewards = try_s!(coin.calc_interest_of_tx(&tx, input_transactions).await);
    //     // `input_amount = output_amount + fee`, where `output_amount = actual_output_amount + kmd_rewards`,
    //     // so to calculate an actual transaction fee, we have to subtract the `kmd_rewards` from the total `output_amount`:
    //     // `fee = input_amount - actual_output_amount` or simplified `fee = input_amount - output_amount + kmd_rewards`
    //     let fee = input_amount as i64 - output_amount as i64 + kmd_rewards as i64;
    //
    //     let my_address = &coin.as_ref().my_address;
    //     let claimed_by_me = from_addresses.iter().all(|from| from == my_address) && to_addresses.contains(my_address);
    //     let kmd_rewards_details = KmdRewardsDetails {
    //         amount: big_decimal_from_sat_unsigned(kmd_rewards, coin.as_ref().decimals),
    //         claimed_by_me,
    //     };
    //     (
    //         big_decimal_from_sat(fee, coin.as_ref().decimals),
    //         Some(kmd_rewards_details),
    //     )
    // } else if input_amount == 0 {
    //     let fee = verbose_tx.vin.iter().fold(0., |cur, input| {
    //         let fee = match input {
    //             TransactionInputEnum::Lelantus(lelantus) => lelantus.n_fees,
    //             _ => 0.,
    //         };
    //         cur + fee
    //     });
    //     (fee.into(), None)
    // } else {
    //     let fee = input_amount as i64 - output_amount as i64;
    //     (big_decimal_from_sat(fee, coin.as_ref().decimals), None)
    // };

    let (fee, kmd_rewards) = if input_amount == 0 {
        let fee = verbose_tx.vin.iter().fold(0., |cur, input| {
            let fee = match input {
                TransactionInputEnum::Lelantus(lelantus) => lelantus.n_fees,
                _ => 0.,
            };
            cur + fee
        });
        (try_s!(fee.try_into()), None)
    } else {
        let fee = input_amount as i64 - output_amount as i64;
        (big_decimal_from_sat(fee, coin.as_ref().decimals), None)
    };

    // remove address duplicates in case several inputs were spent from same address
    // or several outputs are sent to same address
    let mut from_addresses: Vec<String> =
        try_s!(from_addresses.into_iter().map(|addr| addr.display_address()).collect());
    from_addresses.sort();
    from_addresses.dedup();
    let mut to_addresses: Vec<String> = try_s!(to_addresses.into_iter().map(|addr| addr.display_address()).collect());
    to_addresses.sort();
    to_addresses.dedup();

    let fee_details = UtxoFeeDetails {
        coin: Some(coin.as_ref().conf.ticker.clone()),
        amount: fee,
    };

    Ok(TransactionDetails {
        from: from_addresses,
        to: to_addresses,
        received_by_me: big_decimal_from_sat_unsigned(received_by_me, coin.as_ref().decimals),
        spent_by_me: big_decimal_from_sat_unsigned(spent_by_me, coin.as_ref().decimals),
        my_balance_change: big_decimal_from_sat(received_by_me as i64 - spent_by_me as i64, coin.as_ref().decimals),
        total_amount: big_decimal_from_sat_unsigned(input_amount, coin.as_ref().decimals),
        tx_hash: tx.hash().reversed().to_vec().to_tx_hash(),
        tx_hex: verbose_tx.hex,
        fee_details: Some(fee_details.into()),
        block_height: verbose_tx.height.unwrap_or(0),
        coin: ticker.clone(),
        internal_id: tx.hash().reversed().to_vec().into(),
        timestamp: verbose_tx.time.into(),
        kmd_rewards,
        transaction_type: Default::default(),
        memo: None,
    })
}

pub async fn get_mut_verbose_transaction_from_map_or_rpc<'a, 'b, T>(
    coin: &'a T,
    tx_hash: H256Json,
    utxo_tx_map: &'b mut HistoryUtxoTxMap,
) -> UtxoRpcResult<&'b mut HistoryUtxoTx>
where
    T: AsRef<UtxoCoinFields>,
{
    let tx = match utxo_tx_map.entry(tx_hash) {
        Entry::Vacant(e) => {
            let verbose = coin
                .as_ref()
                .rpc_client
                .get_verbose_transaction(&tx_hash)
                .compat()
                .await?;
            let tx = HistoryUtxoTx {
                tx: deserialize(verbose.hex.as_slice())
                    .map_to_mm(|e| UtxoRpcError::InvalidResponse(format!("{:?}, tx: {:?}", e, tx_hash)))?,
                height: verbose.height,
            };
            e.insert(tx)
        },
        Entry::Occupied(e) => e.into_mut(),
    };
    Ok(tx)
}

/// This function is used when the transaction details were calculated without considering the KMD rewards.
/// We know that [`TransactionDetails::fee`] was calculated by `fee = input_amount - output_amount`,
/// where `output_amount = actual_output_amount + kmd_rewards` or `actual_output_amount = output_amount - kmd_rewards`.
/// To calculate an actual fee amount, we have to replace `output_amount` with `actual_output_amount`:
/// `actual_fee = input_amount - actual_output_amount` or `actual_fee = input_amount - output_amount + kmd_rewards`.
/// Substitute [`TransactionDetails::fee`] to the last equation:
/// `actual_fee = TransactionDetails::fee + kmd_rewards`
pub async fn update_kmd_rewards<T>(
    coin: &T,
    tx_details: &mut TransactionDetails,
    input_transactions: &mut HistoryUtxoTxMap,
) -> UtxoRpcResult<()>
where
    T: UtxoCommonOps + UtxoStandardOps + MarketCoinOps,
{
    if !tx_details.should_update_kmd_rewards() {
        let error = "There is no need to update KMD rewards".to_owned();
        return MmError::err(UtxoRpcError::Internal(error));
    }
    let tx: UtxoTx = deserialize(tx_details.tx_hex.as_slice()).map_to_mm(|e| {
        UtxoRpcError::Internal(format!(
            "Error deserializing the {:?} transaction hex: {:?}",
            tx_details.tx_hash, e
        ))
    })?;
    let kmd_rewards = coin.calc_interest_of_tx(&tx, input_transactions).await?;
    let kmd_rewards = big_decimal_from_sat_unsigned(kmd_rewards, coin.as_ref().decimals);

    if let Some(TxFeeDetails::Utxo(UtxoFeeDetails { ref amount, .. })) = tx_details.fee_details {
        let actual_fee_amount = amount + &kmd_rewards;
        tx_details.fee_details = Some(TxFeeDetails::Utxo(UtxoFeeDetails {
            coin: Some(coin.as_ref().conf.ticker.clone()),
            amount: actual_fee_amount,
        }));
    }

    let my_address = &coin.my_address()?;
    let claimed_by_me = tx_details.from.iter().all(|from| from == my_address) && tx_details.to.contains(my_address);

    tx_details.kmd_rewards = Some(KmdRewardsDetails {
        amount: kmd_rewards,
        claimed_by_me,
    });
    Ok(())
}

pub async fn calc_interest_of_tx<T: UtxoCommonOps>(
    coin: &T,
    tx: &UtxoTx,
    input_transactions: &mut HistoryUtxoTxMap,
) -> UtxoRpcResult<u64> {
    if coin.as_ref().conf.ticker != "KMD" {
        let error = format!("Expected KMD ticker, found {}", coin.as_ref().conf.ticker);
        return MmError::err(UtxoRpcError::Internal(error));
    }

    let mut kmd_rewards = 0;
    for input in tx.inputs.iter() {
        // input transaction is zero if the tx is the coinbase transaction
        if input.previous_output.hash.is_zero() {
            continue;
        }

        let prev_tx_hash: H256Json = input.previous_output.hash.reversed().into();
        let prev_tx = coin
            .get_mut_verbose_transaction_from_map_or_rpc(prev_tx_hash, input_transactions)
            .await?;

        let prev_tx_value = prev_tx.tx.outputs[input.previous_output.index as usize].value;
        let prev_tx_locktime = prev_tx.tx.lock_time as u64;
        let this_tx_locktime = tx.lock_time as u64;
        if let Ok(interest) = kmd_interest(prev_tx.height, prev_tx_value, prev_tx_locktime, this_tx_locktime) {
            kmd_rewards += interest;
        }
    }
    Ok(kmd_rewards)
}

pub fn history_sync_status(coin: &UtxoCoinFields) -> HistorySyncState {
    coin.history_sync_state.lock().unwrap().clone()
}

pub fn get_trade_fee<T: UtxoCommonOps>(coin: T) -> Box<dyn Future<Item = TradeFee, Error = String> + Send> {
    let ticker = coin.as_ref().conf.ticker.clone();
    let decimals = coin.as_ref().decimals;
    let fut = async move {
        let fee = try_s!(coin.get_tx_fee().await);
        let amount = match fee {
            ActualTxFee::Dynamic(f) => f,
            ActualTxFee::FixedPerKb(f) => f,
        };
        Ok(TradeFee {
            coin: ticker,
            amount: big_decimal_from_sat(amount as i64, decimals).into(),
            paid_from_trading_vol: false,
        })
    };
    Box::new(fut.boxed().compat())
}

/// To ensure the `get_sender_trade_fee(x) <= get_sender_trade_fee(y)` condition is satisfied for any `x < y`,
/// we should include a `change` output into the result fee. Imagine this case:
/// Let `sum_inputs = 11000` and `total_tx_fee: { 200, if there is no the change output; 230, if there is the change output }`.
///
/// If `value = TradePreimageValue::Exact(10000)`, therefore `sum_outputs = 10000`.
/// then `change = sum_inputs - sum_outputs - total_tx_fee = 800`, so `change < dust` and `total_tx_fee = 200` (including the change output).
///
/// But if `value = TradePreimageValue::Exact(9000)`, therefore `sum_outputs = 9000`. Let `sum_inputs = 11000`, `total_tx_fee = 230`
/// where `change = sum_inputs - sum_outputs - total_tx_fee = 1770`, so `change > dust` and `total_tx_fee = 230` (including the change output).
///
/// To sum up, `get_sender_trade_fee(TradePreimageValue::Exact(9000)) > get_sender_trade_fee(TradePreimageValue::Exact(10000))`.
/// So we should always return a fee as if a transaction includes the change output.
pub async fn preimage_trade_fee_required_to_send_outputs<T>(
    coin: &T,
    ticker: &str,
    outputs: Vec<TransactionOutput>,
    fee_policy: FeePolicy,
    gas_fee: Option<u64>,
    stage: &FeeApproxStage,
) -> TradePreimageResult<BigDecimal>
where
    T: UtxoCommonOps + GetUtxoListOps,
{
    let decimals = coin.as_ref().decimals;
    let tx_fee = coin.get_tx_fee().await?;
    // [`FeePolicy::DeductFromOutput`] is used if the value is [`TradePreimageValue::UpperBound`] only
    let is_amount_upper_bound = matches!(fee_policy, FeePolicy::DeductFromOutput(_));
    let my_address = coin.as_ref().derivation_method.single_addr_or_err()?;

    match tx_fee {
        // if it's a dynamic fee, we should generate a swap transaction to get an actual trade fee
        ActualTxFee::Dynamic(fee) => {
            // take into account that the dynamic tx fee may increase during the swap
            let dynamic_fee = coin.increase_dynamic_fee_by_stage(fee, stage);

            let outputs_count = outputs.len();
            let (unspents, _recently_sent_txs) = coin.get_unspent_ordered_list(my_address).await?;

            let actual_tx_fee = ActualTxFee::Dynamic(dynamic_fee);

            let mut tx_builder = UtxoTxBuilder::new(coin)
                .add_available_inputs(unspents)
                .add_outputs(outputs)
                .with_fee_policy(fee_policy)
                .with_fee(actual_tx_fee);
            if let Some(gas) = gas_fee {
                tx_builder = tx_builder.with_gas_fee(gas);
            }
            let (tx, data) = tx_builder.build().await.mm_err(|e| {
                TradePreimageError::from_generate_tx_error(e, ticker.to_owned(), decimals, is_amount_upper_bound)
            })?;

            let total_fee = if tx.outputs.len() == outputs_count {
                // take into account the change output
                data.fee_amount + (dynamic_fee * P2PKH_OUTPUT_LEN) / KILO_BYTE
            } else {
                // the change output is included already
                data.fee_amount
            };

            Ok(big_decimal_from_sat(total_fee as i64, decimals))
        },
        ActualTxFee::FixedPerKb(fee) => {
            let outputs_count = outputs.len();
            let (unspents, _recently_sent_txs) = coin.get_unspent_ordered_list(my_address).await?;

            let mut tx_builder = UtxoTxBuilder::new(coin)
                .add_available_inputs(unspents)
                .add_outputs(outputs)
                .with_fee_policy(fee_policy)
                .with_fee(tx_fee);
            if let Some(gas) = gas_fee {
                tx_builder = tx_builder.with_gas_fee(gas);
            }
            let (tx, data) = tx_builder.build().await.mm_err(|e| {
                TradePreimageError::from_generate_tx_error(e, ticker.to_string(), decimals, is_amount_upper_bound)
            })?;

            let total_fee = if tx.outputs.len() == outputs_count {
                // take into account the change output if tx_size_kb(tx with change) > tx_size_kb(tx without change)
                let tx = UtxoTx::from(tx);
                let tx_bytes = serialize(&tx);
                if tx_bytes.len() as u64 % KILO_BYTE + P2PKH_OUTPUT_LEN > KILO_BYTE {
                    data.fee_amount + fee
                } else {
                    data.fee_amount
                }
            } else {
                // the change output is included already
                data.fee_amount
            };

            Ok(big_decimal_from_sat(total_fee as i64, decimals))
        },
    }
}

/// Maker or Taker should pay fee only for sending his payment.
/// Even if refund will be required the fee will be deducted from P2SH input.
/// Please note the `get_sender_trade_fee` satisfies the following condition:
/// `get_sender_trade_fee(x) <= get_sender_trade_fee(y)` for any `x < y`.
pub async fn get_sender_trade_fee<T>(
    coin: &T,
    value: TradePreimageValue,
    stage: FeeApproxStage,
) -> TradePreimageResult<TradeFee>
where
    T: MarketCoinOps + UtxoCommonOps,
{
    let (amount, fee_policy) = match value {
        TradePreimageValue::UpperBound(upper_bound) => (upper_bound, FeePolicy::DeductFromOutput(0)),
        TradePreimageValue::Exact(amount) => (amount, FeePolicy::SendExact),
    };

    // pass the dummy params
    let time_lock = now_sec_u32();
    let my_pub = &[0; 33]; // H264 is 33 bytes
    let other_pub = &[0; 33]; // H264 is 33 bytes
    let secret_hash = &[0; 20]; // H160 is 20 bytes

    // `generate_swap_payment_outputs` may fail due to either invalid `other_pub` or a number conversation error
    let SwapPaymentOutputsResult { outputs, .. } = generate_swap_payment_outputs(
        coin,
        time_lock,
        my_pub,
        other_pub,
        amount,
        SwapTxTypeWithSecretHash::TakerOrMakerPayment {
            maker_secret_hash: secret_hash,
        },
    )
    .map_to_mm(TradePreimageError::InternalError)?;
    let gas_fee = None;
    let fee_amount = coin
        .preimage_trade_fee_required_to_send_outputs(outputs, fee_policy, gas_fee, &stage)
        .await?;
    Ok(TradeFee {
        coin: coin.as_ref().conf.ticker.clone(),
        amount: fee_amount.into(),
        paid_from_trading_vol: false,
    })
}

/// The fee to spend (receive) other payment is deducted from the trading amount so we should display it
pub fn get_receiver_trade_fee<T: UtxoCommonOps>(coin: T) -> TradePreimageFut<TradeFee> {
    let fut = async move {
        let amount_sat = get_htlc_spend_fee(&coin, DEFAULT_SWAP_TX_SPEND_SIZE, &FeeApproxStage::WithoutApprox).await?;
        let amount = big_decimal_from_sat_unsigned(amount_sat, coin.as_ref().decimals).into();
        Ok(TradeFee {
            coin: coin.as_ref().conf.ticker.clone(),
            amount,
            paid_from_trading_vol: true,
        })
    };
    Box::new(fut.boxed().compat())
}

pub async fn get_fee_to_send_taker_fee<T>(
    coin: &T,
    dex_fee: DexFee,
    stage: FeeApproxStage,
) -> TradePreimageResult<TradeFee>
where
    T: MarketCoinOps + UtxoCommonOps,
{
    let decimals = coin.as_ref().decimals;

    let outputs = generate_taker_fee_tx_outputs(decimals, &AddressHashEnum::default_address_hash(), &dex_fee)?;

    let gas_fee = None;
    let fee_amount = coin
        .preimage_trade_fee_required_to_send_outputs(outputs, FeePolicy::SendExact, gas_fee, &stage)
        .await?;
    Ok(TradeFee {
        coin: coin.ticker().to_owned(),
        amount: fee_amount.into(),
        paid_from_trading_vol: false,
    })
}

pub fn required_confirmations(coin: &UtxoCoinFields) -> u64 {
    coin.conf.required_confirmations.load(AtomicOrdering::Relaxed)
}

pub fn requires_notarization(coin: &UtxoCoinFields) -> bool {
    coin.conf.requires_notarization.load(AtomicOrdering::Relaxed)
}

pub fn set_required_confirmations(coin: &UtxoCoinFields, confirmations: u64) {
    coin.conf
        .required_confirmations
        .store(confirmations, AtomicOrdering::Relaxed);
}

pub fn set_requires_notarization(coin: &UtxoCoinFields, requires_nota: bool) {
    coin.conf
        .requires_notarization
        .store(requires_nota, AtomicOrdering::Relaxed);
}

pub fn coin_protocol_info<T: UtxoCommonOps>(coin: &T) -> Vec<u8> {
    rmp_serde::to_vec(coin.addr_format()).expect("Serialization should not fail")
}

pub fn is_coin_protocol_supported<T: UtxoCommonOps>(coin: &T, info: &Option<Vec<u8>>) -> bool {
    match info {
        Some(format) => rmp_serde::from_slice::<UtxoAddressFormat>(format).is_ok(),
        None => !coin.addr_format().is_segwit(),
    }
}

/// [`GetUtxoListOps::get_mature_unspent_ordered_list`] implementation.
/// Returns available mature and immature unspents in ascending order
/// + `RecentlySpentOutPoints` MutexGuard for further interaction (e.g. to add new transaction to it).
pub async fn get_mature_unspent_ordered_list<'a, T>(
    coin: &'a T,
    address: &Address,
) -> UtxoRpcResult<(MatureUnspentList, RecentlySpentOutPointsGuard<'a>)>
where
    T: UtxoCommonOps + GetUtxoListOps,
{
    let (unspents, recently_spent) = coin.get_all_unspent_ordered_list(address).await?;
    let mature_unspents = identify_mature_unspents(coin, unspents).await?;
    Ok((mature_unspents, recently_spent))
}

/// [`GetUtxoMapOps::get_mature_unspent_ordered_map`] implementation.
/// Returns available mature and immature unspents in ascending order for every given `addresses`
/// + `RecentlySpentOutPoints` MutexGuard for further interaction (e.g. to add new transaction to it).
pub async fn get_mature_unspent_ordered_map<T>(
    coin: &T,
    addresses: Vec<Address>,
) -> UtxoRpcResult<(MatureUnspentMap, RecentlySpentOutPointsGuard<'_>)>
where
    T: UtxoCommonOps + GetUtxoMapOps,
{
    let (unspents_map, recently_spent) = coin.get_all_unspent_ordered_map(addresses).await?;
    // Get an iterator of futures: `Future<Output=UtxoRpcResult<(Address, MatureUnspentList)>>`
    let fut_it = unspents_map.into_iter().map(|(address, unspents)| {
        identify_mature_unspents(coin, unspents).map(|res| -> UtxoRpcResult<(Address, MatureUnspentList)> {
            let mature_unspents = res?;
            Ok((address, mature_unspents))
        })
    });
    // Poll the `fut_it` futures concurrently.
    let result_map = futures::future::try_join_all(fut_it).await?.into_iter().collect();
    Ok((result_map, recently_spent))
}

/// Splits the given `unspents` outputs into mature and immature.
pub async fn identify_mature_unspents<T>(coin: &T, unspents: Vec<UnspentInfo>) -> UtxoRpcResult<MatureUnspentList>
where
    T: UtxoCommonOps,
{
    /// Returns `true` if the given transaction has a known non-zero height.
    fn can_tx_be_cached(tx: &RpcTransaction) -> bool { tx.height > Some(0) }

    /// Calculates actual confirmations number of the given `tx` transaction loaded from cache.
    fn calc_actual_cached_tx_confirmations(tx: &RpcTransaction, block_count: u64) -> UtxoRpcResult<u32> {
        let tx_height = tx.height.or_mm_err(|| {
            UtxoRpcError::Internal(format!(r#"Warning, height of cached "{:?}" tx is unknown"#, tx.txid))
        })?;
        // There shouldn't be cached transactions with height == 0
        if tx_height == 0 {
            let error = format!(
                r#"Warning, height of cached "{:?}" tx is expected to be non-zero"#,
                tx.txid
            );
            return MmError::err(UtxoRpcError::Internal(error));
        }
        if block_count < tx_height {
            let error = format!(
                r#"Warning, actual block_count {} less than cached tx_height {} of {:?}"#,
                block_count, tx_height, tx.txid
            );
            return MmError::err(UtxoRpcError::Internal(error));
        }

        let confirmations = block_count - tx_height + 1;
        Ok(confirmations as u32)
    }

    let block_count = coin.as_ref().rpc_client.get_block_count().compat().await?;

    let to_verbose: HashSet<H256Json> = unspents
        .iter()
        .map(|unspent| unspent.outpoint.hash.reversed().into())
        .collect();
    let verbose_txs = coin
        .get_verbose_transactions_from_cache_or_rpc(to_verbose)
        .compat()
        .await?;
    // Transactions that should be cached.
    let mut txs_to_cache = HashMap::with_capacity(verbose_txs.len());

    let mut result = MatureUnspentList::with_capacity(unspents.len());
    for unspent in unspents {
        let tx_hash: H256Json = unspent.outpoint.hash.reversed().into();
        let tx_info = verbose_txs
            .get(&tx_hash)
            .or_mm_err(|| {
                UtxoRpcError::Internal(format!(
                    "'get_verbose_transactions_from_cache_or_rpc' should have returned '{:?}'",
                    tx_hash
                ))
            })?
            .clone();
        let tx_info = match tx_info {
            VerboseTransactionFrom::Cache(mut tx) => {
                if unspent.height.is_some() {
                    tx.height = unspent.height;
                }
                match calc_actual_cached_tx_confirmations(&tx, block_count) {
                    Ok(conf) => tx.confirmations = conf,
                    // do not skip the transaction with unknown confirmations,
                    // because the transaction can be matured
                    Err(e) => error!("{}", e),
                }
                tx
            },
            VerboseTransactionFrom::Rpc(mut tx) => {
                if tx.height.is_none() {
                    tx.height = unspent.height;
                }
                if can_tx_be_cached(&tx) {
                    txs_to_cache.insert(tx_hash, tx.clone());
                }
                tx
            },
        };

        if coin.is_unspent_mature(&tx_info) {
            result.mature.push(unspent);
        } else {
            result.immature.push(unspent);
        }
    }

    coin.as_ref()
        .tx_cache
        .cache_transactions_concurrently(&txs_to_cache)
        .await;
    Ok(result)
}

pub fn is_unspent_mature(mature_confirmations: u32, output: &RpcTransaction) -> bool {
    // don't skip outputs with confirmations == 0, because we can spend them
    !output.is_coinbase() || output.confirmations >= mature_confirmations
}

/// [`UtxoCommonOps::get_verbose_transactions_from_cache_or_rpc`] implementation.
/// Loads verbose transactions from cache or requests it using RPC client.
pub async fn get_verbose_transactions_from_cache_or_rpc(
    coin: &UtxoCoinFields,
    tx_ids: HashSet<H256Json>,
) -> UtxoRpcResult<HashMap<H256Json, VerboseTransactionFrom>> {
    /// Determines whether the transaction is needed to be requested through RPC or not.
    /// Puts the inner `RpcTransaction` transaction into `result_map` if it has been loaded successfully,
    /// otherwise puts `txid` into `to_request`.
    fn on_cached_transaction_result(
        result_map: &mut HashMap<H256Json, VerboseTransactionFrom>,
        to_request: &mut Vec<H256Json>,
        txid: H256Json,
        res: TxCacheResult<Option<RpcTransaction>>,
    ) {
        match res {
            Ok(Some(tx)) => {
                result_map.insert(txid, VerboseTransactionFrom::Cache(tx));
            },
            // txid not found
            Ok(None) => {
                to_request.push(txid);
            },
            Err(err) => {
                error!(
                    "Error loading the {:?} transaction: {:?}. Trying to request tx using RPC client",
                    err, txid
                );
                to_request.push(txid);
            },
        }
    }

    let mut result_map = HashMap::with_capacity(tx_ids.len());
    let mut to_request = Vec::with_capacity(tx_ids.len());

    coin.tx_cache
        .load_transactions_from_cache_concurrently(tx_ids)
        .await
        .into_iter()
        .for_each(|(txid, res)| on_cached_transaction_result(&mut result_map, &mut to_request, txid, res));

    result_map.extend(
        coin.rpc_client
            .get_verbose_transactions(&to_request)
            .compat()
            .await?
            .into_iter()
            .map(|tx| (tx.txid, VerboseTransactionFrom::Rpc(tx))),
    );
    Ok(result_map)
}

/// Swap contract address is not used by standard UTXO coins.
#[inline]
pub fn swap_contract_address() -> Option<BytesJson> { None }

/// Fallback swap contract address is not used by standard UTXO coins.
#[inline]
pub fn fallback_swap_contract() -> Option<BytesJson> { None }

/// Convert satoshis to BigDecimal amount of coin units
#[inline]
pub fn big_decimal_from_sat(satoshis: i64, decimals: u8) -> BigDecimal {
    BigDecimal::from(satoshis) / BigDecimal::from(10u64.pow(decimals as u32))
}

#[inline]
pub fn big_decimal_from_sat_unsigned(satoshis: u64, decimals: u8) -> BigDecimal {
    BigDecimal::from(satoshis) / BigDecimal::from(10u64.pow(decimals as u32))
}

pub fn address_from_raw_pubkey(
    pub_key: &[u8],
    prefixes: NetworkAddressPrefixes,
    checksum_type: ChecksumType,
    hrp: Option<String>,
    addr_format: UtxoAddressFormat,
) -> Result<Address, String> {
    AddressBuilder::new(
        addr_format,
        try_s!(Public::from_slice(pub_key)).address_hash().into(),
        checksum_type,
        prefixes,
        hrp,
    )
    .as_pkh()
    .build()
}

pub fn address_from_pubkey(
    pub_key: &Public,
    prefixes: NetworkAddressPrefixes,
    checksum_type: ChecksumType,
    hrp: Option<String>,
    addr_format: UtxoAddressFormat,
) -> Address {
    AddressBuilder::new(addr_format, pub_key.address_hash().into(), checksum_type, prefixes, hrp)
        .as_pkh()
        .build()
        .expect("valid address props")
}

#[allow(clippy::too_many_arguments)]
#[cfg_attr(test, mockable)]
pub async fn validate_payment<'a, T: UtxoCommonOps>(
    coin: T,
    tx: &'a UtxoTx,
    output_index: usize,
    first_pub0: &'a Public,
    second_pub0: &'a Public,
    tx_type_with_secret_hash: SwapTxTypeWithSecretHash<'a>,
    amount: BigDecimal,
    watcher_reward: Option<WatcherReward>,
    time_lock: u32,
    try_spv_proof_until: u64,
    confirmations: u64,
) -> ValidatePaymentResult<()> {
    let amount = sat_from_big_decimal(&amount, coin.as_ref().decimals)?;

    let expected_redeem = tx_type_with_secret_hash.redeem_script(time_lock, first_pub0, second_pub0);
    let tx_hash = tx.tx_hash();

    let tx_from_rpc = retry_on_err!(async {
        coin.as_ref()
            .rpc_client
            .get_transaction_bytes(&tx.hash().reversed().into())
            .compat()
            .await
    })
    .repeat_every_secs(10.)
    .attempts(4)
    .inspect_err(move |e| error!("Error getting tx {tx_hash:?} from rpc: {e:?}"))
    .await
    .map_err(|repeat_err| repeat_err.into_error().map(ValidatePaymentError::from))?;

    if serialize(tx).take() != tx_from_rpc.0
        && serialize_with_flags(tx, SERIALIZE_TRANSACTION_WITNESS).take() != tx_from_rpc.0
    {
        return MmError::err(ValidatePaymentError::WrongPaymentTx(format!(
            "Provided payment tx {:?} doesn't match tx data from rpc {:?}",
            tx, tx_from_rpc
        )));
    }

    let expected_script_pubkey: Bytes = Builder::build_p2sh(&dhash160(&expected_redeem).into()).into();

    let actual_output = match tx.outputs.get(output_index) {
        Some(output) => output,
        None => {
            return MmError::err(ValidatePaymentError::WrongPaymentTx(
                "Payment tx has no outputs".to_string(),
            ))
        },
    };

    if expected_script_pubkey != actual_output.script_pubkey {
        return MmError::err(ValidatePaymentError::WrongPaymentTx(format!(
            "Provided payment tx script pubkey doesn't match expected {:?} {:?}",
            actual_output.script_pubkey, expected_script_pubkey
        )));
    }

    if let Some(watcher_reward) = watcher_reward {
        let expected_reward = sat_from_big_decimal(&watcher_reward.amount, coin.as_ref().decimals)?;
        let actual_reward = actual_output.value - amount;
        validate_watcher_reward(expected_reward, actual_reward, false)?;
    } else if actual_output.value != amount {
        return MmError::err(ValidatePaymentError::WrongPaymentTx(format!(
            "Provided payment tx output value doesn't match expected {:?} {:?}",
            actual_output.value, amount
        )));
    }

    if let UtxoRpcClientEnum::Electrum(client) = &coin.as_ref().rpc_client {
        if coin.as_ref().conf.spv_conf.is_some() && confirmations != 0 {
            client.validate_spv_proof(tx, try_spv_proof_until).await?;
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn search_for_swap_output_spend(
    coin: &UtxoCoinFields,
    time_lock: u32,
    first_pub: &Public,
    second_pub: &Public,
    secret_hash: &[u8],
    tx: &[u8],
    output_index: usize,
    search_from_block: u64,
) -> Result<Option<FoundSwapTxSpend>, String> {
    let mut tx: UtxoTx = try_s!(deserialize(tx).map_err(|e| ERRL!("{:?}", e)));
    tx.tx_hash_algo = coin.tx_hash_algo;
    drop_mutability!(tx);
    if tx.outputs.is_empty() {
        return ERR!("Transaction doesn't have any output");
    }
    let script = payment_script(time_lock, secret_hash, first_pub, second_pub);
    let expected_script_pubkey = Builder::build_p2sh(&dhash160(&script).into()).to_bytes();
    let script_pubkey = &tx
        .outputs
        .get(output_index)
        .ok_or(ERRL!("No output with index {}", output_index))?
        .script_pubkey;

    if *script_pubkey != expected_script_pubkey {
        return ERR!(
            "Transaction {:?} output {} script_pubkey doesn't match expected {:?}",
            tx,
            output_index,
            expected_script_pubkey
        );
    }

    let spend = try_s!(
        coin.rpc_client
            .find_output_spend(
                tx.hash(),
                script_pubkey,
                output_index,
                BlockHashOrHeight::Height(search_from_block as i64),
                coin.tx_hash_algo,
            )
            .compat()
            .await
    );
    match spend {
        Some(spent_output_info) => {
            let tx = spent_output_info.spending_tx;
            let script: Script = spent_output_info.input.script_sig.into();
            if let Some(Ok(ref i)) = script.iter().nth(2) {
                if i.opcode == Opcode::OP_0 {
                    return Ok(Some(FoundSwapTxSpend::Spent(tx.into())));
                }
            }

            if let Some(Ok(ref i)) = script.iter().nth(1) {
                if i.opcode == Opcode::OP_1 {
                    return Ok(Some(FoundSwapTxSpend::Refunded(tx.into())));
                }
            }

            ERR!(
                "Couldn't find required instruction in script_sig of input 0 of tx {:?}",
                tx
            )
        },
        None => Ok(None),
    }
}

struct SwapPaymentOutputsResult {
    payment_address: Address,
    outputs: Vec<TransactionOutput>,
}

fn generate_swap_payment_outputs<T>(
    coin: T,
    time_lock: u32,
    my_pub: &[u8],
    other_pub: &[u8],
    amount: BigDecimal,
    tx_type: SwapTxTypeWithSecretHash<'_>,
) -> Result<SwapPaymentOutputsResult, String>
where
    T: AsRef<UtxoCoinFields>,
{
    let my_public = try_s!(Public::from_slice(my_pub));
    let other_public = try_s!(Public::from_slice(other_pub));
    let redeem_script = tx_type.redeem_script(time_lock, &my_public, &other_public);
    let redeem_script_hash = dhash160(&redeem_script);
    let amount = try_s!(sat_from_big_decimal(&amount, coin.as_ref().decimals));
    let htlc_out = TransactionOutput {
        value: amount,
        script_pubkey: Builder::build_p2sh(&redeem_script_hash.into()).into(),
    };
    // record secret hash to blockchain too making it impossible to lose
    // lock time may be easily brute forced so it is not mandatory to record it
    let mut op_return_builder = Builder::default().push_opcode(Opcode::OP_RETURN);

    // add the full redeem script to the OP_RETURN for ARRR to simplify the validation for the daemon
    op_return_builder = if coin.as_ref().conf.ticker == "ARRR" {
        op_return_builder.push_data(&redeem_script)
    } else {
        op_return_builder.push_data(&tx_type.op_return_data())
    };

    let op_return_script = op_return_builder.into_bytes();

    let op_return_out = TransactionOutput {
        value: 0,
        script_pubkey: op_return_script,
    };

    let payment_address = AddressBuilder::new(
        UtxoAddressFormat::Standard,
        redeem_script_hash.into(),
        coin.as_ref().conf.checksum_type,
        coin.as_ref().conf.address_prefixes.clone(),
        coin.as_ref().conf.bech32_hrp.clone(),
    )
    .as_sh()
    .build()?;
    let result = SwapPaymentOutputsResult {
        payment_address,
        outputs: vec![htlc_out, op_return_out],
    };
    Ok(result)
}

pub fn payment_script(time_lock: u32, secret_hash: &[u8], pub_0: &Public, pub_1: &Public) -> Script {
    let mut builder = Builder::default()
        .push_opcode(Opcode::OP_IF)
        .push_data(&time_lock.to_le_bytes())
        .push_opcode(Opcode::OP_CHECKLOCKTIMEVERIFY)
        .push_opcode(Opcode::OP_DROP)
        .push_data(pub_0)
        .push_opcode(Opcode::OP_CHECKSIG)
        .push_opcode(Opcode::OP_ELSE)
        .push_opcode(Opcode::OP_SIZE)
        .push_data(&[32])
        .push_opcode(Opcode::OP_EQUALVERIFY)
        .push_opcode(Opcode::OP_HASH160);

    if secret_hash.len() == 32 {
        builder = builder.push_data(ripemd160(secret_hash).as_slice());
    } else {
        builder = builder.push_data(secret_hash);
    }

    builder
        .push_opcode(Opcode::OP_EQUALVERIFY)
        .push_data(pub_1)
        .push_opcode(Opcode::OP_CHECKSIG)
        .push_opcode(Opcode::OP_ENDIF)
        .into_script()
}

pub fn dex_fee_script(uuid: [u8; 16], time_lock: u32, watcher_pub: &Public, sender_pub: &Public) -> Script {
    let builder = Builder::default();
    builder
        .push_data(&uuid)
        .push_opcode(Opcode::OP_DROP)
        .push_opcode(Opcode::OP_IF)
        .push_data(&time_lock.to_le_bytes())
        .push_opcode(Opcode::OP_CHECKLOCKTIMEVERIFY)
        .push_opcode(Opcode::OP_DROP)
        .push_data(sender_pub)
        .push_opcode(Opcode::OP_CHECKSIG)
        .push_opcode(Opcode::OP_ELSE)
        .push_data(watcher_pub)
        .push_opcode(Opcode::OP_CHECKSIG)
        .push_opcode(Opcode::OP_ENDIF)
        .into_script()
}

/// [`GetUtxoListOps::get_unspent_ordered_list`] implementation.
/// Returns available unspents in ascending order
/// + `RecentlySpentOutPoints` MutexGuard for further interaction (e.g. to add new transaction to it).
pub async fn get_unspent_ordered_list<'a, T>(
    coin: &'a T,
    address: &Address,
) -> UtxoRpcResult<(Vec<UnspentInfo>, RecentlySpentOutPointsGuard<'a>)>
where
    T: UtxoCommonOps + GetUtxoListOps,
{
    if coin.as_ref().check_utxo_maturity {
        coin.get_mature_unspent_ordered_list(address)
            .await
            // Convert `MatureUnspentList` into `Vec<UnspentInfo>` by discarding immature unspents.
            .map(|(mature_unspents, recently_spent)| (mature_unspents.only_mature(), recently_spent))
    } else {
        coin.get_all_unspent_ordered_list(address).await
    }
}

/// [`GetUtxoMapOps::get_unspent_ordered_map`] implementation.
/// Returns available unspents in ascending order + `RecentlySpentOutPoints` MutexGuard for further interaction
/// (e.g. to add new transaction to it).
pub async fn get_unspent_ordered_map<T>(
    coin: &T,
    addresses: Vec<Address>,
) -> UtxoRpcResult<(UnspentMap, RecentlySpentOutPointsGuard<'_>)>
where
    T: UtxoCommonOps + GetUtxoMapOps,
{
    if coin.as_ref().check_utxo_maturity {
        coin.get_mature_unspent_ordered_map(addresses)
            .await
            // Convert `MatureUnspentMap` into `UnspentMap` by discarding immature unspents.
            .map(|(mature_unspents_map, recently_spent)| {
                let unspents_map = mature_unspents_map
                    .into_iter()
                    .map(|(address, unspents)| (address, unspents.only_mature()))
                    .collect();
                (unspents_map, recently_spent)
            })
    } else {
        coin.get_all_unspent_ordered_map(addresses).await
    }
}

/// [`GetUtxoListOps::get_all_unspent_ordered_list`] implementation.
/// Returns available mature and immature unspents in ascending
/// + `RecentlySpentOutPoints` MutexGuard for further interaction (e.g. to add new transaction to it).
pub async fn get_all_unspent_ordered_list<'a, T: UtxoCommonOps>(
    coin: &'a T,
    address: &Address,
) -> UtxoRpcResult<(Vec<UnspentInfo>, RecentlySpentOutPointsGuard<'a>)> {
    let decimals = coin.as_ref().decimals;
    let unspents = coin
        .as_ref()
        .rpc_client
        .list_unspent(address, decimals)
        .compat()
        .await?;
    let recently_spent = coin.as_ref().recently_spent_outpoints.lock().await;
    let unordered_unspents = recently_spent.replace_spent_outputs_with_cache(unspents.into_iter().collect());
    let ordered_unspents = sort_dedup_unspents(unordered_unspents);
    Ok((ordered_unspents, recently_spent))
}

/// [`GetUtxoMapOps::get_all_unspent_ordered_map`] implementation.
/// Returns available mature and immature unspents in ascending order for every given `addresses`
/// + `RecentlySpentOutPoints` MutexGuard for further interaction (e.g. to add new transaction to it).
pub async fn get_all_unspent_ordered_map<T: UtxoCommonOps>(
    coin: &T,
    addresses: Vec<Address>,
) -> UtxoRpcResult<(UnspentMap, RecentlySpentOutPointsGuard<'_>)> {
    let decimals = coin.as_ref().decimals;
    let mut unspents_map = coin
        .as_ref()
        .rpc_client
        .list_unspent_group(addresses, decimals)
        .compat()
        .await?;
    let recently_spent = coin.as_ref().recently_spent_outpoints.lock().await;
    for (_address, unspents) in unspents_map.iter_mut() {
        let unordered_unspents = recently_spent.replace_spent_outputs_with_cache(unspents.iter().cloned().collect());
        *unspents = sort_dedup_unspents(unordered_unspents);
    }
    Ok((unspents_map, recently_spent))
}

/// Increase the given `dynamic_fee` according to the fee approximation `stage` using the [`UtxoCoinFields::tx_fee_volatility_percent`].
pub fn increase_dynamic_fee_by_stage<T>(coin: &T, dynamic_fee: u64, stage: &FeeApproxStage) -> u64
where
    T: AsRef<UtxoCoinFields>,
{
    let base_percent = coin.as_ref().conf.tx_fee_volatility_percent;
    let percent = match stage {
        FeeApproxStage::WithoutApprox => return dynamic_fee,
        // Take into account that the dynamic fee may increase during the swap by [`UtxoCoinFields::tx_fee_volatility_percent`].
        FeeApproxStage::StartSwap => base_percent,
        // Take into account that the dynamic fee may increase until the watcher can spend it [`UtxoCoinFields::tx_fee_volatility_percent`].
        FeeApproxStage::WatcherPreimage => base_percent, //This needs discussion
        // Take into account that the dynamic fee may increase at each of the following stages up to [`UtxoCoinFields::tx_fee_volatility_percent`]:
        // - until a swap is started;
        // - during the swap.
        FeeApproxStage::OrderIssue => base_percent * 2.,
        // Take into account that the dynamic fee may increase at each of the following stages up to [`UtxoCoinFields::tx_fee_volatility_percent`]:
        // - until an order is issued;
        // - until a swap is started;
        // - during the swap.
        FeeApproxStage::TradePreimage => base_percent * 2.5,
    };
    increase_by_percent(dynamic_fee, percent)
}

fn increase_by_percent(num: u64, percent: f64) -> u64 {
    let percent = num as f64 / 100. * percent;
    num + (percent.round() as u64)
}

pub async fn can_refund_htlc<T>(coin: &T, locktime: u64) -> Result<CanRefundHtlc, MmError<UtxoRpcError>>
where
    T: UtxoCommonOps,
{
    let now = now_sec();
    if now < locktime {
        let to_wait = locktime - now + 1;
        return Ok(CanRefundHtlc::HaveToWait(to_wait.min(3600)));
    }

    let mtp = coin.get_current_mtp().await?;
    let locktime = coin.p2sh_tx_locktime(locktime as u32).await?;

    if locktime < mtp {
        Ok(CanRefundHtlc::CanRefundNow)
    } else {
        let to_wait = (locktime - mtp + 1) as u64;
        Ok(CanRefundHtlc::HaveToWait(to_wait.min(3600)))
    }
}

pub async fn p2sh_tx_locktime<T>(coin: &T, ticker: &str, htlc_locktime: u32) -> Result<u32, MmError<UtxoRpcError>>
where
    T: UtxoCommonOps,
{
    let lock_time = if ticker == "KMD" {
        now_sec_u32() - 3600 + 2 * 777
    } else {
        coin.get_current_mtp().await? - 1
    };
    Ok(lock_time.max(htlc_locktime))
}

pub fn addr_format(coin: &dyn AsRef<UtxoCoinFields>) -> &UtxoAddressFormat {
    match coin.as_ref().derivation_method {
        DerivationMethod::SingleAddress(ref my_address) => my_address.addr_format(),
        DerivationMethod::HDWallet(UtxoHDWallet { ref address_format, .. }) => address_format,
    }
}

pub fn addr_format_for_standard_scripts(coin: &dyn AsRef<UtxoCoinFields>) -> UtxoAddressFormat {
    match &coin.as_ref().conf.default_address_format {
        UtxoAddressFormat::Segwit => UtxoAddressFormat::Standard,
        format @ (UtxoAddressFormat::Standard | UtxoAddressFormat::CashAddress { .. }) => format.clone(),
    }
}

fn check_withdraw_address_supported<T>(coin: &T, addr: &Address) -> MmResult<(), UnsupportedAddr>
where
    T: UtxoCommonOps,
{
    let conf = &coin.as_ref().conf;

    match addr.addr_format() {
        // Considering that legacy is supported with any configured formats
        // This can be changed depending on the coins implementation
        UtxoAddressFormat::Standard => {
            let is_p2pkh = addr.prefix() == &conf.address_prefixes.p2pkh;
            let is_p2sh = addr.prefix() == &conf.address_prefixes.p2sh;
            if !is_p2pkh && !is_p2sh {
                MmError::err(UnsupportedAddr::PrefixError(conf.ticker.clone()))
            } else {
                Ok(())
            }
        },
        UtxoAddressFormat::Segwit => {
            if !conf.segwit {
                return MmError::err(UnsupportedAddr::SegwitNotActivated(conf.ticker.clone()));
            }

            if addr.hrp() != &conf.bech32_hrp {
                MmError::err(UnsupportedAddr::HrpError {
                    ticker: conf.ticker.clone(),
                    hrp: addr.hrp().clone().unwrap_or_default(),
                })
            } else {
                Ok(())
            }
        },
        UtxoAddressFormat::CashAddress { .. } => {
            if addr.addr_format() == &conf.default_address_format || addr.addr_format() == coin.addr_format() {
                Ok(())
            } else {
                MmError::err(UnsupportedAddr::FormatMismatch {
                    ticker: conf.ticker.clone(),
                    activated_format: coin.addr_format().to_string(),
                    used_format: addr.addr_format().to_string(),
                })
            }
        },
    }
}

pub async fn broadcast_tx<T>(coin: &T, tx: &UtxoTx) -> Result<H256Json, MmError<BroadcastTxErr>>
where
    T: AsRef<UtxoCoinFields>,
{
    coin.as_ref()
        .rpc_client
        .send_transaction(tx)
        .compat()
        .await
        .mm_err(From::from)
}

#[inline]
pub fn derive_htlc_key_pair(coin: &UtxoCoinFields, _swap_unique_data: &[u8]) -> KeyPair {
    match coin.priv_key_policy {
        PrivKeyPolicy::Iguana(k) => k,
        PrivKeyPolicy::HDWallet {
            activated_key: activated_key_pair,
            ..
        } => activated_key_pair,
        PrivKeyPolicy::Trezor => todo!(),
        #[cfg(target_arch = "wasm32")]
        PrivKeyPolicy::Metamask(_) => panic!("`PrivKeyPolicy::Metamask` is not supported for UTXO coins"),
    }
}

#[inline]
pub fn derive_htlc_pubkey(coin: &dyn SwapOps, swap_unique_data: &[u8]) -> Vec<u8> {
    coin.derive_htlc_key_pair(swap_unique_data).public_slice().to_vec()
}

pub fn validate_other_pubkey(raw_pubkey: &[u8]) -> MmResult<(), ValidateOtherPubKeyErr> {
    if let Err(err) = Public::from_slice(raw_pubkey) {
        return MmError::err(ValidateOtherPubKeyErr::InvalidPubKey(err.to_string()));
    };
    Ok(())
}

/// Sorts and deduplicates the given `unspents` in ascending order.
fn sort_dedup_unspents<I>(unspents: I) -> Vec<UnspentInfo>
where
    I: IntoIterator<Item = UnspentInfo>,
{
    unspents
        .into_iter()
        // dedup just in case we add duplicates of same unspent out
        .unique_by(|unspent| unspent.outpoint)
        .sorted_unstable_by(|a, b| {
            if a.value < b.value {
                Ordering::Less
            } else {
                Ordering::Greater
            }
        })
        .collect()
}

/// Common implementation of taker funding generation and broadcast for UTXO coins.
pub async fn send_taker_funding<T>(coin: T, args: SendTakerFundingArgs<'_>) -> Result<UtxoTx, TransactionErr>
where
    T: UtxoCommonOps + GetUtxoListOps + SwapOps,
{
    let taker_htlc_key_pair = coin.derive_htlc_key_pair(args.swap_unique_data);
    let total_amount = &args.dex_fee.total_spend_amount().to_decimal() + &args.premium_amount + &args.trading_amount;

    let SwapPaymentOutputsResult {
        payment_address,
        outputs,
    } = try_tx_s!(generate_swap_payment_outputs(
        &coin,
        try_tx_s!(args.time_lock.try_into()),
        taker_htlc_key_pair.public_slice(),
        args.maker_pub,
        total_amount,
        SwapTxTypeWithSecretHash::TakerFunding {
            taker_secret_hash: args.taker_secret_hash
        },
    ));
    if let UtxoRpcClientEnum::Native(client) = &coin.as_ref().rpc_client {
        let addr_string = try_tx_s!(payment_address.display_address());
        client
            .import_address(&addr_string, &addr_string, false)
            .map_err(|e| TransactionErr::Plain(ERRL!("{}", e)))
            .compat()
            .await?;
    }
    send_outputs_from_my_address_impl(coin, outputs).await
}

/// Common implementation of taker funding reclaim for UTXO coins using immediate refund path with secret reveal.
pub async fn refund_taker_funding_secret<T>(
    coin: T,
    args: RefundFundingSecretArgs<'_, T>,
) -> Result<UtxoTx, TransactionErr>
where
    T: UtxoCommonOps + GetUtxoListOps + SwapOps,
{
    let my_address = try_tx_s!(coin.as_ref().derivation_method.single_addr_or_err()).clone();
    let payment_value = try_tx_s!(args.funding_tx.first_output()).value;

    let key_pair = coin.derive_htlc_key_pair(args.swap_unique_data);
    let script_data = Builder::default()
        .push_data(args.taker_secret)
        .push_opcode(Opcode::OP_0)
        .push_opcode(Opcode::OP_0)
        .into_script();
    let time_lock = try_tx_s!(args.time_lock.try_into());

    let redeem_script = swap_proto_v2_scripts::taker_funding_script(
        time_lock,
        args.taker_secret_hash,
        key_pair.public(),
        args.maker_pubkey,
    )
    .into();
    let fee = try_tx_s!(
        coin.get_htlc_spend_fee(DEFAULT_SWAP_TX_SPEND_SIZE, &FeeApproxStage::WithoutApprox)
            .await
    );
    if fee >= payment_value {
        return TX_PLAIN_ERR!(
            "HTLC spend fee {} is greater than transaction output {}",
            fee,
            payment_value
        );
    }
    let script_pubkey = output_script(&my_address).map(|script| script.to_bytes())?;
    let output = TransactionOutput {
        value: payment_value - fee,
        script_pubkey,
    };

    let input = P2SHSpendingTxInput {
        prev_transaction: args.funding_tx.clone(),
        redeem_script,
        outputs: vec![output],
        script_data,
        sequence: SEQUENCE_FINAL,
        lock_time: time_lock,
        keypair: &key_pair,
    };
    let transaction = try_tx_s!(coin.p2sh_spending_tx(input).await);

    let tx_fut = coin.as_ref().rpc_client.send_transaction(&transaction).compat();
    try_tx_s!(tx_fut.await, transaction);

    Ok(transaction)
}

/// Common implementation of taker funding validation for UTXO coins.
pub async fn validate_taker_funding<T>(coin: &T, args: ValidateTakerFundingArgs<'_, T>) -> ValidateSwapV2TxResult
where
    T: UtxoCommonOps + SwapOps,
{
    let maker_htlc_key_pair = coin.derive_htlc_key_pair(args.swap_unique_data);
    let total_expected_amount =
        &args.dex_fee.total_spend_amount().to_decimal() + &args.premium_amount + &args.trading_amount;

    let expected_amount_sat = sat_from_big_decimal(&total_expected_amount, coin.as_ref().decimals)?;

    let time_lock = args
        .time_lock
        .try_into()
        .map_to_mm(|e: TryFromIntError| ValidateSwapV2TxError::LocktimeOverflow(e.to_string()))?;

    let redeem_script = swap_proto_v2_scripts::taker_funding_script(
        time_lock,
        args.taker_secret_hash,
        args.other_pub,
        maker_htlc_key_pair.public(),
    );
    let expected_output = TransactionOutput {
        value: expected_amount_sat,
        script_pubkey: Builder::build_p2sh(&AddressHashEnum::AddressHash(dhash160(&redeem_script))).into(),
    };

    if args.funding_tx.outputs.get(0) != Some(&expected_output) {
        return MmError::err(ValidateSwapV2TxError::InvalidDestinationOrAmount(format!(
            "Expected {:?}, got {:?}",
            expected_output,
            args.funding_tx.outputs.get(0)
        )));
    }

    let tx_bytes_from_rpc = coin
        .as_ref()
        .rpc_client
        .get_transaction_bytes(&args.funding_tx.hash().reversed().into())
        .compat()
        .await?;
    let actual_tx_bytes = serialize(args.funding_tx).take();
    if tx_bytes_from_rpc.0 != actual_tx_bytes {
        return MmError::err(ValidateSwapV2TxError::TxBytesMismatch {
            from_rpc: tx_bytes_from_rpc,
            actual: actual_tx_bytes.into(),
        });
    }

    // import funding address in native mode to track funding tx spend
    let funding_address = AddressBuilder::new(
        AddressFormat::Standard,
        dhash160(&redeem_script).into(),
        coin.as_ref().conf.checksum_type,
        coin.as_ref().conf.address_prefixes.clone(),
        coin.as_ref().conf.bech32_hrp.clone(),
    )
    .as_sh()
    .build()
    .map_to_mm(ValidateSwapV2TxError::Internal)?;

    if let UtxoRpcClientEnum::Native(client) = &coin.as_ref().rpc_client {
        let addr_string = funding_address
            .display_address()
            .map_to_mm(ValidateSwapV2TxError::Internal)?;
        client
            .import_address(&addr_string, &addr_string, false)
            .compat()
            .await
            .map_to_mm(|e| ValidateSwapV2TxError::Rpc(e.to_string()))?;
    }
    Ok(())
}

/// Common implementation of maker payment v2 generation and broadcast for UTXO coins.
pub async fn send_maker_payment_v2<T>(coin: T, args: SendMakerPaymentArgs<'_, T>) -> Result<UtxoTx, TransactionErr>
where
    T: UtxoCommonOps + GetUtxoListOps + SwapOps,
{
    let maker_htlc_key_pair = coin.derive_htlc_key_pair(args.swap_unique_data);

    let SwapPaymentOutputsResult {
        payment_address,
        outputs,
    } = try_tx_s!(generate_swap_payment_outputs(
        &coin,
        try_tx_s!(args.time_lock.try_into()),
        maker_htlc_key_pair.public_slice(),
        args.taker_pub,
        args.amount,
        SwapTxTypeWithSecretHash::MakerPaymentV2 {
            maker_secret_hash: args.maker_secret_hash,
            taker_secret_hash: args.taker_secret_hash,
        },
    ));
    if let UtxoRpcClientEnum::Native(client) = &coin.as_ref().rpc_client {
        let addr_string = try_tx_s!(payment_address.display_address());
        client
            .import_address(&addr_string, &addr_string, false)
            .map_err(|e| TransactionErr::Plain(ERRL!("{}", e)))
            .compat()
            .await?;
    }
    send_outputs_from_my_address_impl(coin, outputs).await
}

pub fn address_to_scripthash(address: &Address) -> Result<String, keys::Error> {
    let script = output_script(address)?;
    let script_hash = electrum_script_hash(&script);
    Ok(hex::encode(script_hash))
}

pub async fn utxo_prepare_addresses_for_balance_stream_if_enabled<T>(
    coin: &T,
    addresses: HashSet<Address>,
) -> MmResult<(), String>
where
    T: UtxoCommonOps,
{
    if let UtxoRpcClientEnum::Electrum(electrum_client) = &coin.as_ref().rpc_client {
        if let Some(sender) = &electrum_client.scripthash_notification_sender {
            sender
                .unbounded_send(ScripthashNotification::SubscribeToAddresses(addresses))
                .map_err(|e| ERRL!("Failed sending scripthash message. {}", e))?;
        }
    };

    Ok(())
}

pub async fn spend_maker_payment_v2<T: UtxoCommonOps + SwapOps>(
    coin: &T,
    args: SpendMakerPaymentArgs<'_, T>,
) -> Result<UtxoTx, TransactionErr> {
    let my_address = try_tx_s!(coin.as_ref().derivation_method.single_addr_or_err()).clone();
    let payment_value = try_tx_s!(args.maker_payment_tx.first_output()).value;

    let key_pair = coin.derive_htlc_key_pair(args.swap_unique_data);
    let script_data = Builder::default()
        .push_data(args.maker_secret)
        .push_opcode(Opcode::OP_1)
        .push_opcode(Opcode::OP_0)
        .into_script();
    let time_lock = try_tx_s!(args.time_lock.try_into());

    let redeem_script = swap_proto_v2_scripts::maker_payment_script(
        time_lock,
        args.maker_secret_hash,
        args.taker_secret_hash,
        args.maker_pub,
        key_pair.public(),
    )
    .into();

    let fee = try_tx_s!(
        coin.get_htlc_spend_fee(DEFAULT_SWAP_TX_SPEND_SIZE, &FeeApproxStage::WithoutApprox)
            .await
    );
    if fee >= payment_value {
        return TX_PLAIN_ERR!(
            "HTLC spend fee {} is greater than transaction output {}",
            fee,
            payment_value
        );
    }
    let script_pubkey = try_tx_s!(output_script(&my_address)).to_bytes();
    let output = TransactionOutput {
        value: payment_value - fee,
        script_pubkey,
    };

    let input = P2SHSpendingTxInput {
        prev_transaction: args.maker_payment_tx.clone(),
        redeem_script,
        outputs: vec![output],
        script_data,
        sequence: SEQUENCE_FINAL,
        lock_time: time_lock,
        keypair: &key_pair,
    };
    let transaction = try_tx_s!(coin.p2sh_spending_tx(input).await);

    let tx_fut = coin.as_ref().rpc_client.send_transaction(&transaction).compat();
    try_tx_s!(tx_fut.await, transaction);

    Ok(transaction)
}

/// Common implementation of maker payment v2 reclaim for UTXO coins using immediate refund path with secret reveal.
pub async fn refund_maker_payment_v2_secret<T>(
    coin: T,
    args: RefundMakerPaymentArgs<'_, T>,
) -> Result<UtxoTx, TransactionErr>
where
    T: UtxoCommonOps + SwapOps,
{
    let my_address = try_tx_s!(coin.as_ref().derivation_method.single_addr_or_err()).clone();
    let payment_value = try_tx_s!(args.maker_payment_tx.first_output()).value;

    let key_pair = coin.derive_htlc_key_pair(args.swap_unique_data);
    let script_data = Builder::default()
        .push_data(args.taker_secret)
        .push_opcode(Opcode::OP_0)
        .push_opcode(Opcode::OP_0)
        .into_script();
    let time_lock = try_tx_s!(args.time_lock.try_into());

    let redeem_script = swap_proto_v2_scripts::maker_payment_script(
        time_lock,
        args.maker_secret_hash,
        args.taker_secret_hash,
        key_pair.public(),
        args.taker_pub,
    )
    .into();
    let fee = try_tx_s!(
        coin.get_htlc_spend_fee(DEFAULT_SWAP_TX_SPEND_SIZE, &FeeApproxStage::WithoutApprox)
            .await
    );
    if fee >= payment_value {
        return TX_PLAIN_ERR!(
            "HTLC spend fee {} is greater than transaction output {}",
            fee,
            payment_value
        );
    }
    let script_pubkey = try_tx_s!(output_script(&my_address)).to_bytes();
    let output = TransactionOutput {
        value: payment_value - fee,
        script_pubkey,
    };

    let input = P2SHSpendingTxInput {
        prev_transaction: args.maker_payment_tx.clone(),
        redeem_script,
        outputs: vec![output],
        script_data,
        sequence: SEQUENCE_FINAL,
        lock_time: time_lock,
        keypair: &key_pair,
    };
    let transaction = try_tx_s!(coin.p2sh_spending_tx(input).await);

    let tx_fut = coin.as_ref().rpc_client.send_transaction(&transaction).compat();
    try_tx_s!(tx_fut.await, transaction);

    Ok(transaction)
}

#[test]
fn test_increase_by_percent() {
    assert_eq!(increase_by_percent(4300, 1.), 4343);
    assert_eq!(increase_by_percent(30, 6.9), 32);
    assert_eq!(increase_by_percent(30, 6.), 32);
    assert_eq!(increase_by_percent(10, 6.), 11);
    assert_eq!(increase_by_percent(1000, 0.1), 1001);
    assert_eq!(increase_by_percent(0, 20.), 0);
    assert_eq!(increase_by_percent(20, 0.), 20);
    assert_eq!(increase_by_percent(23, 100.), 46);
    assert_eq!(increase_by_percent(100, 2.4), 102);
    assert_eq!(increase_by_percent(100, 2.5), 103);
}

#[test]
fn test_pubkey_from_script_sig() {
    let script_sig = Script::from("473044022071edae37cf518e98db3f7637b9073a7a980b957b0c7b871415dbb4898ec3ebdc022031b402a6b98e64ffdf752266449ca979a9f70144dba77ed7a6a25bfab11648f6012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36fa");
    let expected_pub = H264::from("03ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36fa");
    let actual_pub = pubkey_from_script_sig(&script_sig).unwrap();
    assert_eq!(expected_pub, actual_pub);

    let script_sig_err = Script::from("473044022071edae37cf518e98db3f7637b9073a7a980b957b0c7b871415dbb4898ec3ebdc022031b402a6b98e64ffdf752266449ca979a9f70144dba77ed7a6a25bfab11648f6012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36fa21");
    pubkey_from_script_sig(&script_sig_err).unwrap_err();

    let script_sig_err = Script::from("493044022071edae37cf518e98db3f7637b9073a7a980b957b0c7b871415dbb4898ec3ebdc022031b402a6b98e64ffdf752266449ca979a9f70144dba77ed7a6a25bfab11648f6012103ad6f89abc2e5beaa8a3ac28e22170659b3209fe2ddf439681b4b8f31508c36fa");
    pubkey_from_script_sig(&script_sig_err).unwrap_err();
}

#[test]
fn test_tx_v_size() {
    // Multiple legacy inputs with P2SH and P2PKH output
    // https://live.blockcypher.com/btc-testnet/tx/ac6218b33d02e069c4055af709bbb6ca92ce11e55450cde96bc17411e281e5e7/
    let mut tx: UtxoTx = "0100000002440f1a2929eb08c350cc8d2385c77c40411560c3b43b65efb5b06f997fc67672020000006b483045022100f82e88af256d2487afe0c30a166c9ecf6b7013e764e1407317c712d47f7731bd0220358a4d7987bfde2271599b5c4376d26f9ce9f1df2e04f5de8f89593352607110012103c6a78589e18b482aea046975e6d0acbdea7bf7dbf04d9d5bd67fda917815e3edfffffffffb9c2fd7a19b55a4ffbda2ce5065d988a4f4efcf1ae567b4ddb6d97529c8fb0c000000006b483045022100dd75291db32dc859657a5eead13b85c340b4d508e57d2450ebfad76484f254130220727fcd65dda046ea62b449ab217da264dbf7c7ca7e63b39c8835973a152752c1012103c6a78589e18b482aea046975e6d0acbdea7bf7dbf04d9d5bd67fda917815e3edffffffff03102700000000000017a9148d0ad41545dea44e914c419d33d422148c35a274870000000000000000166a149c0a919d4e9a23f0234df916a7dd21f9e2fdaa8f931d0000000000001976a9146d9d2b554d768232320587df75c4338ecc8bf37d88acbd8ff160".into();
    // Removing inputs script_sig as it's not included in UnsignedTransactionInput when fees are calculated
    tx.inputs[0].script_sig = Bytes::new();
    tx.inputs[1].script_sig = Bytes::new();
    let v_size = tx_size_in_v_bytes(&UtxoAddressFormat::Standard, &tx);
    assert_eq!(v_size, 403);
    // Segwit input with 2 P2WPKH outputs
    // https://live.blockcypher.com/btc-testnet/tx/8a32e794b2a8a0356bb3b2717279d118b4010bf8bb3229abb5a2b4fb86541bb2/
    // the transaction is deserialized without the witnesses which makes the calculation of v_size similar to how
    // it's calculated in generate_transaction
    let tx: UtxoTx = "0200000000010192a4497268107d7999e9551be733f5e0eab479be7d995a061a7bbdc43ef0e5ed0000000000feffffff02cd857a00000000001600145cb39bfcd68d520e29cadc990bceb5cd1562c507a0860100000000001600149a85cc05e9a722575feb770a217c73fd6145cf01024730440220030e0fb58889ab939c701f12d950f00b64836a1a33ec0d6697fd3053d469d244022053e33d72ef53b37b86eea8dfebbafffb0f919ef952dcb6ea6058b81576d8dc86012102225de6aed071dc29d0ca10b9f64a4b502e33e55b3c0759eedd8e333834c6a7d07a1f2000".into();
    let v_size = tx_size_in_v_bytes(&UtxoAddressFormat::Segwit, &tx);
    assert_eq!(v_size, 141);
    // Segwit input with 1 P2WSH output
    // https://live.blockcypher.com/btc-testnet/tx/f8c1fed6f307eb131040965bd11018787567413e6437c907b1fd15de6517ad16/
    let tx: UtxoTx = "010000000001017996e77b2b1f4e66da606cfc2f16e3f52e1eac4a294168985bd4dbd54442e61f0100000000ffffffff01ab36010000000000220020693090c0e291752d448826a9dc72c9045b34ed4f7bd77e6e8e62645c23d69ac502483045022100d0800719239d646e69171ede7f02af916ac778ffe384fa0a5928645b23826c9f022044072622de2b47cfc81ac5172b646160b0c48d69d881a0ce77be06dbd6f6e5ac0121031ac6d25833a5961e2a8822b2e8b0ac1fd55d90cbbbb18a780552cbd66fc02bb3735a9e61".into();
    let v_size = tx_size_in_v_bytes(&UtxoAddressFormat::Segwit, &tx);
    assert_eq!(v_size, 122);
    // Multiple segwit inputs with P2PKH output
    // https://live.blockcypher.com/btc-testnet/tx/649d514d76702a0925a917d830e407f4f1b52d78832520e486c140ce8d0b879f/
    let tx: UtxoTx = "0100000000010250c434acbad252481564d56b41990577c55d247aedf4bb853dca3567c4404c8f0000000000ffffffff55baf016f0628ecf0f0ec228e24d8029879b0491ab18bac61865afaa9d16e8bb0000000000ffffffff01e8030000000000001976a9146d9d2b554d768232320587df75c4338ecc8bf37d88ac0247304402202611c05dd0e748f7c9955ed94a172af7ed56a0cdf773e8c919bef6e70b13ec1c02202fd7407891c857d95cdad1038dcc333186815f50da2fc9a334f814dd8d0a2d63012103c6a78589e18b482aea046975e6d0acbdea7bf7dbf04d9d5bd67fda917815e3ed02483045022100bb9d483f6b2b46f8e70d62d65b33b6de056e1878c9c2a1beed69005daef2f89502201690cd44cf6b114fa0d494258f427e1ed11a21d897e407d8a1ff3b7e09b9a426012103c6a78589e18b482aea046975e6d0acbdea7bf7dbf04d9d5bd67fda917815e3ed9cf7bd60".into();
    let v_size = tx_size_in_v_bytes(&UtxoAddressFormat::Segwit, &tx);
    assert_eq!(v_size, 181);
    // Multiple segwit inputs
    // https://live.blockcypher.com/btc-testnet/tx/a7bb128703b57058955d555ed48b65c2c9bdefab6d3acbb4243c56e430533def/
    let tx: UtxoTx = "010000000001023b7308e5ca5d02000b743441f7653c1110e07275b7ab0e983f489e92bfdd2b360100000000ffffffffd6c4f22e9b1090b2584a82cf4cb6f85595dd13c16ad065711a7585cc373ae2e50000000000ffffffff02947b2a00000000001600148474e72f396d44504cd30b1e7b992b65344240c609050700000000001600141b891309c8fe1338786fa3476d5d1a9718d43a0202483045022100bfae465fcd8d2636b2513f68618eb4996334c94d47e285cb538e3416eaf4521b02201b953f46ff21c8715a0997888445ca814dfdb834ef373a29e304bee8b32454d901210226bde3bca3fe7c91e4afb22c4bc58951c60b9bd73514081b6bd35f5c09b8c9a602483045022100ba48839f7becbf8f91266140f9727edd08974fcc18017661477af1d19603ed31022042fd35af1b393eeb818b420e3a5922079776cc73f006d26dd67be932e1b4f9000121034b6a54040ad2175e4c198370ac36b70d0b0ab515b59becf100c4cd310afbfd0c00000000".into();
    let v_size = tx_size_in_v_bytes(&UtxoAddressFormat::Segwit, &tx);
    assert_eq!(v_size, 209)
}

#[test]
fn test_generate_taker_fee_tx_outputs() {
    let amount = BigDecimal::from(6150);
    let fee_amount = sat_from_big_decimal(&amount, 8).unwrap();

    let outputs = generate_taker_fee_tx_outputs(
        8,
        &AddressHashEnum::default_address_hash(),
        &DexFee::Standard(amount.into()),
    )
    .unwrap();

    assert_eq!(outputs.len(), 1);

    assert_eq!(outputs[0].value, fee_amount);
}

#[test]
fn test_generate_taker_fee_tx_outputs_with_burn() {
    let fee_amount = BigDecimal::from(6150);
    let burn_amount = &(&fee_amount / &BigDecimal::from_str("0.75").unwrap()) - &fee_amount;

    let fee_uamount = sat_from_big_decimal(&fee_amount, 8).unwrap();
    let burn_uamount = sat_from_big_decimal(&burn_amount, 8).unwrap();

    let outputs = generate_taker_fee_tx_outputs(
        8,
        &AddressHashEnum::default_address_hash(),
        &DexFee::with_burn(fee_amount.into(), burn_amount.into()),
    )
    .unwrap();

    assert_eq!(outputs.len(), 2);

    assert_eq!(outputs[0].value, fee_uamount);

    assert_eq!(outputs[1].value, burn_uamount);
}

#[test]
fn test_address_to_scripthash() {
    let address = Address::from_legacyaddress("RMGJ9tRST45RnwEKHPGgBLuY3moSYP7Mhk", &KMD_PREFIXES).unwrap();
    let actual = address_to_scripthash(&address).expect("valid script hash to be built");
    let expected = "e850499408c6ebcf6b3340282747e540fb23748429fca5f2b36cdeef54ddf5b1".to_owned();
    assert_eq!(expected, actual);

    let address = Address::from_legacyaddress("R9o9xTocqr6CeEDGDH6mEYpwLoMz6jNjMW", &KMD_PREFIXES).unwrap();
    let actual = address_to_scripthash(&address).expect("valid script hash to be built");
    let expected = "a70a7a7041ef172ce4b5f8208aabed44c81e2af75493540f50af7bd9afa9955d".to_owned();
    assert_eq!(expected, actual);

    let address = Address::from_legacyaddress("qcyBHeSct7Wr4mAw18iuQ1zW5mMFYmtmBE", &T_QTUM_PREFIXES).unwrap();
    let actual = address_to_scripthash(&address).expect("valid script hash to be built");
    let expected = "c5b5922c86830289231539d1681d8ce621aac8326c96d6ac55400b4d1485f769".to_owned();
    assert_eq!(expected, actual);
}
