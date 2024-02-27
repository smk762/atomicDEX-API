//! Module containing implementation for Tendermint Tokens. They include native assets + IBC

use super::ibc::transfer_v1::MsgTransfer;
use super::ibc::IBC_GAS_LIMIT_DEFAULT;
use super::{TendermintCoin, TendermintFeeDetails, GAS_LIMIT_DEFAULT, MIN_TX_SATOSHIS, TIMEOUT_HEIGHT_DELTA,
            TX_DEFAULT_MEMO};
use crate::coin_errors::ValidatePaymentResult;
use crate::rpc_command::tendermint::IBCWithdrawRequest;
use crate::tendermint::account_id_from_privkey;
use crate::utxo::utxo_common::big_decimal_from_sat;
use crate::{big_decimal_from_sat_unsigned, utxo::sat_from_big_decimal, BalanceFut, BigDecimal,
            CheckIfMyPaymentSentArgs, CoinBalance, CoinFutSpawner, ConfirmPaymentInput, FeeApproxStage,
            FoundSwapTxSpend, HistorySyncState, MakerSwapTakerCoin, MarketCoinOps, MmCoin, MyAddressError,
            NegotiateSwapContractAddrErr, PaymentInstructions, PaymentInstructionsErr, RawTransactionError,
            RawTransactionFut, RawTransactionRequest, RawTransactionResult, RefundError, RefundPaymentArgs,
            RefundResult, SearchForSwapTxSpendInput, SendMakerPaymentSpendPreimageInput, SendPaymentArgs,
            SignRawTransactionRequest, SignatureResult, SpendPaymentArgs, SwapOps, TakerSwapMakerCoin, TradeFee,
            TradePreimageFut, TradePreimageResult, TradePreimageValue, TransactionDetails, TransactionEnum,
            TransactionErr, TransactionFut, TransactionResult, TransactionType, TxFeeDetails, TxMarshalingErr,
            UnexpectedDerivationMethod, ValidateAddressResult, ValidateFeeArgs, ValidateInstructionsErr,
            ValidateOtherPubKeyErr, ValidatePaymentError, ValidatePaymentFut, ValidatePaymentInput,
            VerificationResult, WaitForHTLCTxSpendArgs, WatcherOps, WatcherSearchForSwapTxSpendInput,
            WatcherValidatePaymentInput, WatcherValidateTakerFeeInput, WithdrawError, WithdrawFrom, WithdrawFut,
            WithdrawRequest};
use crate::{DexFee, MmCoinEnum, PaymentInstructionArgs, ValidateWatcherSpendInput, WatcherReward, WatcherRewardError};
use async_trait::async_trait;
use bitcrypto::sha256;
use common::executor::abortable_queue::AbortableQueue;
use common::executor::{AbortableSystem, AbortedError};
use common::log::warn;
use common::Future01CompatExt;
use cosmrs::{bank::MsgSend,
             tx::{Fee, Msg},
             AccountId, Coin, Denom};
use futures::{FutureExt, TryFutureExt};
use futures01::Future;
use keys::KeyPair;
use mm2_core::mm_ctx::MmArc;
use mm2_err_handle::prelude::*;
use mm2_number::MmNumber;
use rpc::v1::types::Bytes as BytesJson;
use serde_json::Value as Json;
use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;

pub struct TendermintTokenImpl {
    pub ticker: String,
    pub platform_coin: TendermintCoin,
    pub decimals: u8,
    pub denom: Denom,
    /// This spawner is used to spawn coin's related futures that should be aborted on coin deactivation
    /// or on [`MmArc::stop`].
    abortable_system: AbortableQueue,
}

#[derive(Clone)]
pub struct TendermintToken(Arc<TendermintTokenImpl>);

impl Deref for TendermintToken {
    type Target = TendermintTokenImpl;

    fn deref(&self) -> &Self::Target { &self.0 }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TendermintTokenProtocolInfo {
    pub platform: String,
    pub decimals: u8,
    pub denom: String,
}

#[derive(Clone, Deserialize)]
pub struct TendermintTokenActivationParams {}

pub enum TendermintTokenInitError {
    Internal(String),
    InvalidDenom(String),
    MyAddressError(String),
    CouldNotFetchBalance(String),
}

impl From<MyAddressError> for TendermintTokenInitError {
    fn from(err: MyAddressError) -> Self { TendermintTokenInitError::MyAddressError(err.to_string()) }
}

impl From<AbortedError> for TendermintTokenInitError {
    fn from(e: AbortedError) -> Self { TendermintTokenInitError::Internal(e.to_string()) }
}

impl TendermintToken {
    pub fn new(
        ticker: String,
        platform_coin: TendermintCoin,
        decimals: u8,
        denom: String,
    ) -> MmResult<Self, TendermintTokenInitError> {
        let denom = Denom::from_str(&denom).map_to_mm(|e| TendermintTokenInitError::InvalidDenom(e.to_string()))?;
        let token_impl = TendermintTokenImpl {
            abortable_system: platform_coin.abortable_system.create_subsystem()?,
            ticker,
            platform_coin,
            decimals,
            denom,
        };
        Ok(TendermintToken(Arc::new(token_impl)))
    }

    pub fn ibc_withdraw(&self, req: IBCWithdrawRequest) -> WithdrawFut {
        let platform = self.platform_coin.clone();
        let token = self.clone();
        let fut = async move {
            let to_address =
                AccountId::from_str(&req.to).map_to_mm(|e| WithdrawError::InvalidAddress(e.to_string()))?;

            let (account_id, priv_key) = match req.from {
                Some(WithdrawFrom::HDWalletAddress(ref path_to_address)) => {
                    let priv_key = platform
                        .priv_key_policy
                        .hd_wallet_derived_priv_key_or_err(path_to_address)?;
                    let account_id = account_id_from_privkey(priv_key.as_slice(), &platform.account_prefix)
                        .map_err(|e| WithdrawError::InternalError(e.to_string()))?;
                    (account_id, priv_key)
                },
                Some(WithdrawFrom::AddressId(_)) | Some(WithdrawFrom::DerivationPath { .. }) => {
                    return MmError::err(WithdrawError::UnexpectedFromAddress(
                        "Withdraw from 'AddressId' or 'DerivationPath' is not supported yet for Tendermint!"
                            .to_string(),
                    ))
                },
                None => (
                    platform.account_id.clone(),
                    *platform.priv_key_policy.activated_key_or_err()?,
                ),
            };

            let (base_denom_balance, base_denom_balance_dec) = platform
                .get_balance_as_unsigned_and_decimal(&account_id, &platform.denom, token.decimals())
                .await?;

            let (balance_denom, balance_dec) = platform
                .get_balance_as_unsigned_and_decimal(&account_id, &token.denom, token.decimals())
                .await?;

            let (amount_denom, amount_dec, total_amount) = if req.max {
                (
                    balance_denom,
                    big_decimal_from_sat_unsigned(balance_denom, token.decimals),
                    balance_dec,
                )
            } else {
                if balance_dec < req.amount {
                    return MmError::err(WithdrawError::NotSufficientBalance {
                        coin: token.ticker.clone(),
                        available: balance_dec,
                        required: req.amount,
                    });
                }

                (
                    sat_from_big_decimal(&req.amount, token.decimals())?,
                    req.amount.clone(),
                    req.amount,
                )
            };

            if !platform.is_tx_amount_enough(token.decimals, &amount_dec) {
                return MmError::err(WithdrawError::AmountTooLow {
                    amount: amount_dec,
                    threshold: token.min_tx_amount(),
                });
            }

            let received_by_me = if to_address == account_id {
                amount_dec
            } else {
                BigDecimal::default()
            };

            let memo = req.memo.unwrap_or_else(|| TX_DEFAULT_MEMO.into());

            let msg_transfer = MsgTransfer::new_with_default_timeout(
                req.ibc_source_channel.clone(),
                account_id.clone(),
                to_address.clone(),
                Coin {
                    denom: token.denom.clone(),
                    amount: amount_denom.into(),
                },
            )
            .to_any()
            .map_to_mm(|e| WithdrawError::InternalError(e.to_string()))?;

            let current_block = token
                .current_block()
                .compat()
                .await
                .map_to_mm(WithdrawError::Transport)?;

            let timeout_height = current_block + TIMEOUT_HEIGHT_DELTA;

            let (_, gas_limit) = platform.gas_info_for_withdraw(&req.fee, IBC_GAS_LIMIT_DEFAULT);

            let fee_amount_u64 = platform
                .calculate_account_fee_amount_as_u64(
                    &account_id,
                    &priv_key,
                    msg_transfer.clone(),
                    timeout_height,
                    memo.clone(),
                    req.fee,
                )
                .await?;

            let fee_amount_dec = big_decimal_from_sat_unsigned(fee_amount_u64, platform.decimals());

            if base_denom_balance < fee_amount_u64 {
                return MmError::err(WithdrawError::NotSufficientPlatformBalanceForFee {
                    coin: platform.ticker().to_string(),
                    available: base_denom_balance_dec,
                    required: fee_amount_dec,
                });
            }

            let fee_amount = Coin {
                denom: platform.denom.clone(),
                amount: fee_amount_u64.into(),
            };

            let fee = Fee::from_amount_and_gas(fee_amount, gas_limit);

            let account_info = platform.account_info(&account_id).await?;
            let tx_raw = platform
                .any_to_signed_raw_tx(&priv_key, account_info, msg_transfer, fee, timeout_height, memo.clone())
                .map_to_mm(|e| WithdrawError::InternalError(e.to_string()))?;

            let tx_bytes = tx_raw
                .to_bytes()
                .map_to_mm(|e| WithdrawError::InternalError(e.to_string()))?;

            let hash = sha256(&tx_bytes);
            Ok(TransactionDetails {
                tx_hash: hex::encode_upper(hash.as_slice()),
                tx_hex: tx_bytes.into(),
                from: vec![account_id.to_string()],
                to: vec![req.to],
                my_balance_change: &received_by_me - &total_amount,
                spent_by_me: total_amount.clone(),
                total_amount,
                received_by_me,
                block_height: 0,
                timestamp: 0,
                fee_details: Some(TxFeeDetails::Tendermint(TendermintFeeDetails {
                    coin: platform.ticker().to_string(),
                    amount: fee_amount_dec,
                    uamount: fee_amount_u64,
                    gas_limit,
                })),
                coin: token.ticker.clone(),
                internal_id: hash.to_vec().into(),
                kmd_rewards: None,
                transaction_type: TransactionType::default(),
                memo: Some(memo),
            })
        };
        Box::new(fut.boxed().compat())
    }
}

#[async_trait]
#[allow(unused_variables)]
impl SwapOps for TendermintToken {
    fn send_taker_fee(&self, fee_addr: &[u8], dex_fee: DexFee, uuid: &[u8]) -> TransactionFut {
        self.platform_coin.send_taker_fee_for_denom(
            fee_addr,
            dex_fee.fee_amount().into(),
            self.denom.clone(),
            self.decimals,
            uuid,
        )
    }

    fn send_maker_payment(&self, maker_payment_args: SendPaymentArgs) -> TransactionFut {
        self.platform_coin.send_htlc_for_denom(
            maker_payment_args.time_lock_duration,
            maker_payment_args.other_pubkey,
            maker_payment_args.secret_hash,
            maker_payment_args.amount,
            self.denom.clone(),
            self.decimals,
        )
    }

    fn send_taker_payment(&self, taker_payment_args: SendPaymentArgs) -> TransactionFut {
        self.platform_coin.send_htlc_for_denom(
            taker_payment_args.time_lock_duration,
            taker_payment_args.other_pubkey,
            taker_payment_args.secret_hash,
            taker_payment_args.amount,
            self.denom.clone(),
            self.decimals,
        )
    }

    fn send_maker_spends_taker_payment(&self, maker_spends_payment_args: SpendPaymentArgs) -> TransactionFut {
        self.platform_coin
            .send_maker_spends_taker_payment(maker_spends_payment_args)
    }

    fn send_taker_spends_maker_payment(&self, taker_spends_payment_args: SpendPaymentArgs) -> TransactionFut {
        self.platform_coin
            .send_taker_spends_maker_payment(taker_spends_payment_args)
    }

    async fn send_taker_refunds_payment(&self, taker_refunds_payment_args: RefundPaymentArgs<'_>) -> TransactionResult {
        Err(TransactionErr::Plain(
            "Doesn't need transaction broadcast to be refunded".into(),
        ))
    }

    async fn send_maker_refunds_payment(&self, maker_refunds_payment_args: RefundPaymentArgs<'_>) -> TransactionResult {
        Err(TransactionErr::Plain(
            "Doesn't need transaction broadcast to be refunded".into(),
        ))
    }

    fn validate_fee(&self, validate_fee_args: ValidateFeeArgs) -> ValidatePaymentFut<()> {
        self.platform_coin.validate_fee_for_denom(
            validate_fee_args.fee_tx,
            validate_fee_args.expected_sender,
            validate_fee_args.fee_addr,
            &validate_fee_args.dex_fee.fee_amount().into(),
            self.decimals,
            validate_fee_args.uuid,
            self.denom.to_string(),
        )
    }

    async fn validate_maker_payment(&self, input: ValidatePaymentInput) -> ValidatePaymentResult<()> {
        self.platform_coin
            .validate_payment_for_denom(input, self.denom.clone(), self.decimals)
            .await
    }

    async fn validate_taker_payment(&self, input: ValidatePaymentInput) -> ValidatePaymentResult<()> {
        self.platform_coin
            .validate_payment_for_denom(input, self.denom.clone(), self.decimals)
            .await
    }

    fn check_if_my_payment_sent(
        &self,
        if_my_payment_sent_args: CheckIfMyPaymentSentArgs,
    ) -> Box<dyn Future<Item = Option<TransactionEnum>, Error = String> + Send> {
        self.platform_coin.check_if_my_payment_sent_for_denom(
            self.decimals,
            self.denom.clone(),
            if_my_payment_sent_args.other_pub,
            if_my_payment_sent_args.secret_hash,
            if_my_payment_sent_args.amount,
        )
    }

    async fn search_for_swap_tx_spend_my(
        &self,
        input: SearchForSwapTxSpendInput<'_>,
    ) -> Result<Option<FoundSwapTxSpend>, String> {
        self.platform_coin.search_for_swap_tx_spend_my(input).await
    }

    async fn search_for_swap_tx_spend_other(
        &self,
        input: SearchForSwapTxSpendInput<'_>,
    ) -> Result<Option<FoundSwapTxSpend>, String> {
        self.platform_coin.search_for_swap_tx_spend_other(input).await
    }

    async fn extract_secret(
        &self,
        secret_hash: &[u8],
        spend_tx: &[u8],
        watcher_reward: bool,
    ) -> Result<Vec<u8>, String> {
        self.platform_coin
            .extract_secret(secret_hash, spend_tx, watcher_reward)
            .await
    }

    fn check_tx_signed_by_pub(&self, tx: &[u8], expected_pub: &[u8]) -> Result<bool, MmError<ValidatePaymentError>> {
        unimplemented!();
    }

    // Todo
    fn is_auto_refundable(&self) -> bool { false }

    // Todo
    async fn wait_for_htlc_refund(&self, _tx: &[u8], _locktime: u64) -> RefundResult<()> {
        MmError::err(RefundError::Internal(
            "wait_for_htlc_refund is not supported for this coin!".into(),
        ))
    }

    fn negotiate_swap_contract_addr(
        &self,
        other_side_address: Option<&[u8]>,
    ) -> Result<Option<BytesJson>, MmError<NegotiateSwapContractAddrErr>> {
        self.platform_coin.negotiate_swap_contract_addr(other_side_address)
    }

    #[inline]
    fn derive_htlc_key_pair(&self, swap_unique_data: &[u8]) -> KeyPair {
        self.platform_coin.derive_htlc_key_pair(swap_unique_data)
    }

    #[inline]
    fn derive_htlc_pubkey(&self, swap_unique_data: &[u8]) -> Vec<u8> {
        self.derive_htlc_key_pair(swap_unique_data).public_slice().to_vec()
    }

    fn validate_other_pubkey(&self, raw_pubkey: &[u8]) -> MmResult<(), ValidateOtherPubKeyErr> {
        self.platform_coin.validate_other_pubkey(raw_pubkey)
    }

    async fn maker_payment_instructions(
        &self,
        args: PaymentInstructionArgs<'_>,
    ) -> Result<Option<Vec<u8>>, MmError<PaymentInstructionsErr>> {
        Ok(None)
    }

    async fn taker_payment_instructions(
        &self,
        args: PaymentInstructionArgs<'_>,
    ) -> Result<Option<Vec<u8>>, MmError<PaymentInstructionsErr>> {
        Ok(None)
    }

    fn validate_maker_payment_instructions(
        &self,
        _instructions: &[u8],
        args: PaymentInstructionArgs,
    ) -> Result<PaymentInstructions, MmError<ValidateInstructionsErr>> {
        MmError::err(ValidateInstructionsErr::UnsupportedCoin(self.ticker().to_string()))
    }

    fn validate_taker_payment_instructions(
        &self,
        _instructions: &[u8],
        args: PaymentInstructionArgs,
    ) -> Result<PaymentInstructions, MmError<ValidateInstructionsErr>> {
        MmError::err(ValidateInstructionsErr::UnsupportedCoin(self.ticker().to_string()))
    }
}

#[async_trait]
impl TakerSwapMakerCoin for TendermintToken {
    async fn on_taker_payment_refund_start(&self, _maker_payment: &[u8]) -> RefundResult<()> { Ok(()) }

    async fn on_taker_payment_refund_success(&self, _maker_payment: &[u8]) -> RefundResult<()> { Ok(()) }
}

#[async_trait]
impl MakerSwapTakerCoin for TendermintToken {
    async fn on_maker_payment_refund_start(&self, _taker_payment: &[u8]) -> RefundResult<()> { Ok(()) }

    async fn on_maker_payment_refund_success(&self, _taker_payment: &[u8]) -> RefundResult<()> { Ok(()) }
}

#[async_trait]
impl WatcherOps for TendermintToken {
    fn create_maker_payment_spend_preimage(
        &self,
        _maker_payment_tx: &[u8],
        _time_lock: u64,
        _maker_pub: &[u8],
        _secret_hash: &[u8],
        _swap_unique_data: &[u8],
    ) -> TransactionFut {
        unimplemented!();
    }

    fn send_maker_payment_spend_preimage(&self, _input: SendMakerPaymentSpendPreimageInput) -> TransactionFut {
        unimplemented!();
    }

    fn create_taker_payment_refund_preimage(
        &self,
        _taker_payment_tx: &[u8],
        _time_lock: u64,
        _maker_pub: &[u8],
        _secret_hash: &[u8],
        _swap_contract_address: &Option<BytesJson>,
        _swap_unique_data: &[u8],
    ) -> TransactionFut {
        unimplemented!();
    }

    fn send_taker_payment_refund_preimage(&self, _watcher_refunds_payment_args: RefundPaymentArgs) -> TransactionFut {
        unimplemented!();
    }

    fn watcher_validate_taker_fee(&self, _input: WatcherValidateTakerFeeInput) -> ValidatePaymentFut<()> {
        unimplemented!();
    }

    fn watcher_validate_taker_payment(&self, _input: WatcherValidatePaymentInput) -> ValidatePaymentFut<()> {
        unimplemented!();
    }

    fn taker_validates_payment_spend_or_refund(&self, _input: ValidateWatcherSpendInput) -> ValidatePaymentFut<()> {
        unimplemented!();
    }

    async fn watcher_search_for_swap_tx_spend(
        &self,
        _input: WatcherSearchForSwapTxSpendInput<'_>,
    ) -> Result<Option<FoundSwapTxSpend>, String> {
        unimplemented!();
    }

    async fn get_taker_watcher_reward(
        &self,
        _other_coin: &MmCoinEnum,
        _coin_amount: Option<BigDecimal>,
        _other_coin_amount: Option<BigDecimal>,
        _reward_amount: Option<BigDecimal>,
        _wait_until: u64,
    ) -> Result<WatcherReward, MmError<WatcherRewardError>> {
        unimplemented!()
    }

    async fn get_maker_watcher_reward(
        &self,
        _other_coin: &MmCoinEnum,
        _reward_amount: Option<BigDecimal>,
        _wait_until: u64,
    ) -> Result<Option<WatcherReward>, MmError<WatcherRewardError>> {
        unimplemented!()
    }
}

#[async_trait]
impl MarketCoinOps for TendermintToken {
    fn ticker(&self) -> &str { &self.ticker }

    fn my_address(&self) -> MmResult<String, MyAddressError> { self.platform_coin.my_address() }

    fn get_public_key(&self) -> Result<String, MmError<UnexpectedDerivationMethod>> {
        self.platform_coin.get_public_key()
    }

    fn sign_message_hash(&self, message: &str) -> Option<[u8; 32]> { self.platform_coin.sign_message_hash(message) }

    fn sign_message(&self, message: &str) -> SignatureResult<String> { self.platform_coin.sign_message(message) }

    fn verify_message(&self, signature: &str, message: &str, address: &str) -> VerificationResult<bool> {
        self.platform_coin.verify_message(signature, message, address)
    }

    fn my_balance(&self) -> BalanceFut<CoinBalance> {
        let coin = self.clone();
        let fut = async move {
            let balance_denom = coin
                .platform_coin
                .account_balance_for_denom(&coin.platform_coin.account_id, coin.denom.to_string())
                .await?;
            Ok(CoinBalance {
                spendable: big_decimal_from_sat_unsigned(balance_denom, coin.decimals),
                unspendable: BigDecimal::default(),
            })
        };
        Box::new(fut.boxed().compat())
    }

    fn base_coin_balance(&self) -> BalanceFut<BigDecimal> { self.platform_coin.my_spendable_balance() }

    fn platform_ticker(&self) -> &str { self.platform_coin.ticker() }

    fn send_raw_tx(&self, tx: &str) -> Box<dyn Future<Item = String, Error = String> + Send> {
        self.platform_coin.send_raw_tx(tx)
    }

    fn send_raw_tx_bytes(&self, tx: &[u8]) -> Box<dyn Future<Item = String, Error = String> + Send> {
        self.platform_coin.send_raw_tx_bytes(tx)
    }

    #[inline(always)]
    async fn sign_raw_tx(&self, _args: &SignRawTransactionRequest) -> RawTransactionResult {
        MmError::err(RawTransactionError::NotImplemented {
            coin: self.ticker().to_string(),
        })
    }

    fn wait_for_confirmations(&self, input: ConfirmPaymentInput) -> Box<dyn Future<Item = (), Error = String> + Send> {
        self.platform_coin.wait_for_confirmations(input)
    }

    fn wait_for_htlc_tx_spend(&self, args: WaitForHTLCTxSpendArgs<'_>) -> TransactionFut {
        self.platform_coin.wait_for_htlc_tx_spend(WaitForHTLCTxSpendArgs {
            tx_bytes: args.tx_bytes,
            secret_hash: args.secret_hash,
            wait_until: args.wait_until,
            from_block: args.from_block,
            swap_contract_address: args.swap_contract_address,
            check_every: args.check_every,
            watcher_reward: false,
        })
    }

    fn tx_enum_from_bytes(&self, bytes: &[u8]) -> Result<TransactionEnum, MmError<TxMarshalingErr>> {
        self.platform_coin.tx_enum_from_bytes(bytes)
    }

    fn current_block(&self) -> Box<dyn Future<Item = u64, Error = String> + Send> { self.platform_coin.current_block() }

    fn display_priv_key(&self) -> Result<String, String> { self.platform_coin.display_priv_key() }

    #[inline]
    fn min_tx_amount(&self) -> BigDecimal { big_decimal_from_sat(MIN_TX_SATOSHIS, self.decimals) }

    #[inline]
    fn min_trading_vol(&self) -> MmNumber { self.min_tx_amount().into() }
}

#[async_trait]
#[allow(unused_variables)]
impl MmCoin for TendermintToken {
    fn is_asset_chain(&self) -> bool { false }

    fn spawner(&self) -> CoinFutSpawner { CoinFutSpawner::new(&self.abortable_system) }

    fn withdraw(&self, req: WithdrawRequest) -> WithdrawFut {
        let platform = self.platform_coin.clone();
        let token = self.clone();
        let fut = async move {
            let to_address =
                AccountId::from_str(&req.to).map_to_mm(|e| WithdrawError::InvalidAddress(e.to_string()))?;
            if to_address.prefix() != platform.account_prefix {
                return MmError::err(WithdrawError::InvalidAddress(format!(
                    "expected {} address prefix",
                    platform.account_prefix
                )));
            }

            let (account_id, priv_key) = match req.from {
                Some(WithdrawFrom::HDWalletAddress(ref path_to_address)) => {
                    let priv_key = platform
                        .priv_key_policy
                        .hd_wallet_derived_priv_key_or_err(path_to_address)?;
                    let account_id = account_id_from_privkey(priv_key.as_slice(), &platform.account_prefix)
                        .map_err(|e| WithdrawError::InternalError(e.to_string()))?;
                    (account_id, priv_key)
                },
                Some(WithdrawFrom::AddressId(_)) | Some(WithdrawFrom::DerivationPath { .. }) => {
                    return MmError::err(WithdrawError::UnexpectedFromAddress(
                        "Withdraw from 'AddressId' or 'DerivationPath' is not supported yet for Tendermint!"
                            .to_string(),
                    ))
                },
                None => (
                    platform.account_id.clone(),
                    *platform.priv_key_policy.activated_key_or_err()?,
                ),
            };

            let (base_denom_balance, base_denom_balance_dec) = platform
                .get_balance_as_unsigned_and_decimal(&account_id, &platform.denom, token.decimals())
                .await?;

            let (balance_denom, balance_dec) = platform
                .get_balance_as_unsigned_and_decimal(&account_id, &token.denom, token.decimals())
                .await?;

            let (amount_denom, amount_dec, total_amount) = if req.max {
                (
                    balance_denom,
                    big_decimal_from_sat_unsigned(balance_denom, token.decimals),
                    balance_dec,
                )
            } else {
                if balance_dec < req.amount {
                    return MmError::err(WithdrawError::NotSufficientBalance {
                        coin: token.ticker.clone(),
                        available: balance_dec,
                        required: req.amount,
                    });
                }

                (
                    sat_from_big_decimal(&req.amount, token.decimals())?,
                    req.amount.clone(),
                    req.amount,
                )
            };

            if !platform.is_tx_amount_enough(token.decimals, &amount_dec) {
                return MmError::err(WithdrawError::AmountTooLow {
                    amount: amount_dec,
                    threshold: token.min_tx_amount(),
                });
            }

            let received_by_me = if to_address == account_id {
                amount_dec
            } else {
                BigDecimal::default()
            };

            let msg_send = MsgSend {
                from_address: account_id.clone(),
                to_address,
                amount: vec![Coin {
                    denom: token.denom.clone(),
                    amount: amount_denom.into(),
                }],
            }
            .to_any()
            .map_to_mm(|e| WithdrawError::InternalError(e.to_string()))?;

            let memo = req.memo.unwrap_or_else(|| TX_DEFAULT_MEMO.into());
            let current_block = token
                .current_block()
                .compat()
                .await
                .map_to_mm(WithdrawError::Transport)?;

            let timeout_height = current_block + TIMEOUT_HEIGHT_DELTA;

            let (_, gas_limit) = platform.gas_info_for_withdraw(&req.fee, GAS_LIMIT_DEFAULT);

            let fee_amount_u64 = platform
                .calculate_account_fee_amount_as_u64(
                    &account_id,
                    &priv_key,
                    msg_send.clone(),
                    timeout_height,
                    memo.clone(),
                    req.fee,
                )
                .await?;

            let fee_amount_dec = big_decimal_from_sat_unsigned(fee_amount_u64, platform.decimals());

            if base_denom_balance < fee_amount_u64 {
                return MmError::err(WithdrawError::NotSufficientPlatformBalanceForFee {
                    coin: platform.ticker().to_string(),
                    available: base_denom_balance_dec,
                    required: fee_amount_dec,
                });
            }

            let fee_amount = Coin {
                denom: platform.denom.clone(),
                amount: fee_amount_u64.into(),
            };

            let fee = Fee::from_amount_and_gas(fee_amount, gas_limit);

            let account_info = platform.account_info(&account_id).await?;
            let tx_raw = platform
                .any_to_signed_raw_tx(&priv_key, account_info, msg_send, fee, timeout_height, memo.clone())
                .map_to_mm(|e| WithdrawError::InternalError(e.to_string()))?;

            let tx_bytes = tx_raw
                .to_bytes()
                .map_to_mm(|e| WithdrawError::InternalError(e.to_string()))?;

            let hash = sha256(&tx_bytes);
            Ok(TransactionDetails {
                tx_hash: hex::encode_upper(hash.as_slice()),
                tx_hex: tx_bytes.into(),
                from: vec![account_id.to_string()],
                to: vec![req.to],
                my_balance_change: &received_by_me - &total_amount,
                spent_by_me: total_amount.clone(),
                total_amount,
                received_by_me,
                block_height: 0,
                timestamp: 0,
                fee_details: Some(TxFeeDetails::Tendermint(TendermintFeeDetails {
                    coin: platform.ticker().to_string(),
                    amount: fee_amount_dec,
                    uamount: fee_amount_u64,
                    gas_limit,
                })),
                coin: token.ticker.clone(),
                internal_id: hash.to_vec().into(),
                kmd_rewards: None,
                transaction_type: TransactionType::default(),
                memo: Some(memo),
            })
        };
        Box::new(fut.boxed().compat())
    }

    fn get_raw_transaction(&self, req: RawTransactionRequest) -> RawTransactionFut {
        self.platform_coin.get_raw_transaction(req)
    }

    fn get_tx_hex_by_hash(&self, tx_hash: Vec<u8>) -> RawTransactionFut { unimplemented!() }

    fn decimals(&self) -> u8 { self.decimals }

    fn convert_to_address(&self, from: &str, to_address_format: Json) -> Result<String, String> {
        self.platform_coin.convert_to_address(from, to_address_format)
    }

    fn validate_address(&self, address: &str) -> ValidateAddressResult { self.platform_coin.validate_address(address) }

    fn process_history_loop(&self, ctx: MmArc) -> Box<dyn Future<Item = (), Error = ()> + Send> {
        warn!("process_history_loop is deprecated, tendermint uses tx_history_v2");
        Box::new(futures01::future::err(()))
    }

    fn history_sync_status(&self) -> HistorySyncState { HistorySyncState::NotEnabled }

    fn get_trade_fee(&self) -> Box<dyn Future<Item = TradeFee, Error = String> + Send> {
        Box::new(futures01::future::err("Not implemented".into()))
    }

    async fn get_sender_trade_fee(
        &self,
        value: TradePreimageValue,
        _stage: FeeApproxStage,
    ) -> TradePreimageResult<TradeFee> {
        let amount = match value {
            TradePreimageValue::Exact(decimal) | TradePreimageValue::UpperBound(decimal) => decimal,
        };

        self.platform_coin
            .get_sender_trade_fee_for_denom(self.ticker.clone(), self.denom.clone(), self.decimals, amount)
            .await
    }

    fn get_receiver_trade_fee(&self, _stage: FeeApproxStage) -> TradePreimageFut<TradeFee> {
        let token = self.clone();
        let fut = async move {
            // We can't simulate Claim Htlc without having information about broadcasted htlc tx.
            // Since create and claim htlc fees are almost same, we can simply simulate create htlc tx.
            token
                .platform_coin
                .get_sender_trade_fee_for_denom(
                    token.ticker.clone(),
                    token.denom.clone(),
                    token.decimals,
                    token.min_tx_amount(),
                )
                .await
        };
        Box::new(fut.boxed().compat())
    }

    async fn get_fee_to_send_taker_fee(
        &self,
        dex_fee_amount: DexFee,
        _stage: FeeApproxStage,
    ) -> TradePreimageResult<TradeFee> {
        self.platform_coin
            .get_fee_to_send_taker_fee_for_denom(self.ticker.clone(), self.denom.clone(), self.decimals, dex_fee_amount)
            .await
    }

    fn required_confirmations(&self) -> u64 { self.platform_coin.required_confirmations() }

    fn requires_notarization(&self) -> bool { self.platform_coin.requires_notarization() }

    fn set_required_confirmations(&self, confirmations: u64) {
        warn!("set_required_confirmations is not supported for tendermint")
    }

    fn set_requires_notarization(&self, requires_nota: bool) {
        self.platform_coin.set_requires_notarization(requires_nota)
    }

    fn swap_contract_address(&self) -> Option<BytesJson> { self.platform_coin.swap_contract_address() }

    fn fallback_swap_contract(&self) -> Option<BytesJson> { self.platform_coin.fallback_swap_contract() }

    fn mature_confirmations(&self) -> Option<u32> { None }

    fn coin_protocol_info(&self, amount_to_receive: Option<MmNumber>) -> Vec<u8> {
        self.platform_coin.coin_protocol_info(amount_to_receive)
    }

    fn is_coin_protocol_supported(
        &self,
        info: &Option<Vec<u8>>,
        amount_to_send: Option<MmNumber>,
        locktime: u64,
        is_maker: bool,
    ) -> bool {
        self.platform_coin
            .is_coin_protocol_supported(info, amount_to_send, locktime, is_maker)
    }

    fn on_disabled(&self) -> Result<(), AbortedError> { self.abortable_system.abort_all() }

    fn on_token_deactivated(&self, _ticker: &str) {}
}
