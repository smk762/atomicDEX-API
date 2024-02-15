use std::sync::Arc;

use crate::hd_wallet::NewAccountCreatingError;
use async_trait::async_trait;
use crypto::hw_rpc_task::HwConnectStatuses;
use crypto::trezor::trezor_rpc_task::{TrezorRpcTaskProcessor, TryIntoUserAction};
use crypto::trezor::utxo::IGNORE_XPUB_MAGIC;
use crypto::trezor::{ProcessTrezorResponse, TrezorError, TrezorProcessingError};
use crypto::{CryptoCtx, CryptoCtxError, DerivationPath, EcdsaCurve, HardwareWalletArc, HwError, HwProcessingError,
             XPub, XPubConverter, XpubError};
use mm2_core::mm_ctx::MmArc;
use mm2_err_handle::prelude::*;
use rpc_task::{RpcTask, RpcTaskError, RpcTaskHandleShared};

const SHOW_PUBKEY_ON_DISPLAY: bool = false;

#[derive(Clone)]
pub enum HDExtractPubkeyError {
    HwContextNotInitialized,
    CoinDoesntSupportTrezor,
    RpcTaskError(RpcTaskError),
    HardwareWalletError(HwError),
    InvalidXpub(String),
    Internal(String),
}

impl From<CryptoCtxError> for HDExtractPubkeyError {
    fn from(e: CryptoCtxError) -> Self { HDExtractPubkeyError::Internal(e.to_string()) }
}

impl From<TrezorError> for HDExtractPubkeyError {
    fn from(e: TrezorError) -> Self { HDExtractPubkeyError::HardwareWalletError(HwError::from(e)) }
}

impl From<HwError> for HDExtractPubkeyError {
    fn from(e: HwError) -> Self { HDExtractPubkeyError::HardwareWalletError(e) }
}

impl From<TrezorProcessingError<RpcTaskError>> for HDExtractPubkeyError {
    fn from(e: TrezorProcessingError<RpcTaskError>) -> Self {
        match e {
            TrezorProcessingError::TrezorError(trezor) => HDExtractPubkeyError::from(HwError::from(trezor)),
            TrezorProcessingError::ProcessorError(rpc) => HDExtractPubkeyError::RpcTaskError(rpc),
        }
    }
}

impl From<HwProcessingError<RpcTaskError>> for HDExtractPubkeyError {
    fn from(e: HwProcessingError<RpcTaskError>) -> Self {
        match e {
            HwProcessingError::HwError(hw) => HDExtractPubkeyError::from(hw),
            HwProcessingError::ProcessorError(rpc) => HDExtractPubkeyError::RpcTaskError(rpc),
            HwProcessingError::InternalError(err) => HDExtractPubkeyError::Internal(err),
        }
    }
}

impl From<XpubError> for HDExtractPubkeyError {
    fn from(e: XpubError) -> Self { HDExtractPubkeyError::InvalidXpub(e.to_string()) }
}

impl From<HDExtractPubkeyError> for NewAccountCreatingError {
    fn from(e: HDExtractPubkeyError) -> Self {
        match e {
            HDExtractPubkeyError::HwContextNotInitialized => NewAccountCreatingError::HwContextNotInitialized,
            HDExtractPubkeyError::CoinDoesntSupportTrezor => NewAccountCreatingError::CoinDoesntSupportTrezor,
            HDExtractPubkeyError::RpcTaskError(rpc) => NewAccountCreatingError::RpcTaskError(rpc),
            HDExtractPubkeyError::HardwareWalletError(hw) => NewAccountCreatingError::HardwareWalletError(hw),
            HDExtractPubkeyError::InvalidXpub(xpub) => {
                NewAccountCreatingError::HardwareWalletError(HwError::InvalidXpub(xpub))
            },
            HDExtractPubkeyError::Internal(internal) => NewAccountCreatingError::Internal(internal),
        }
    }
}

#[async_trait]
pub trait ExtractExtendedPubkey {
    type ExtendedPublicKey;

    async fn extract_extended_pubkey<XPubExtractor>(
        &self,
        xpub_extractor: &XPubExtractor,
        derivation_path: DerivationPath,
    ) -> MmResult<Self::ExtendedPublicKey, HDExtractPubkeyError>
    where
        XPubExtractor: HDXPubExtractor;
}

#[async_trait]
pub trait HDXPubExtractor: Sync {
    async fn extract_utxo_xpub(
        &self,
        trezor_utxo_coin: String,
        derivation_path: DerivationPath,
    ) -> MmResult<XPub, HDExtractPubkeyError>;
}

pub enum RpcTaskXPubExtractor<Task: RpcTask> {
    Trezor {
        hw_ctx: HardwareWalletArc,
        task_handle: RpcTaskHandleShared<Task>,
        statuses: HwConnectStatuses<Task::InProgressStatus, Task::AwaitingStatus>,
    },
}

#[async_trait]
impl<Task> HDXPubExtractor for RpcTaskXPubExtractor<Task>
where
    Task: RpcTask,
    Task::UserAction: TryIntoUserAction + Send,
{
    async fn extract_utxo_xpub(
        &self,
        trezor_utxo_coin: String,
        derivation_path: DerivationPath,
    ) -> MmResult<XPub, HDExtractPubkeyError> {
        match self {
            RpcTaskXPubExtractor::Trezor {
                hw_ctx,
                task_handle,
                statuses,
            } => {
                Self::extract_utxo_xpub_from_trezor(
                    hw_ctx,
                    task_handle.clone(),
                    statuses,
                    trezor_utxo_coin,
                    derivation_path,
                )
                .await
            },
        }
    }
}

impl<Task> RpcTaskXPubExtractor<Task>
where
    Task: RpcTask,
    Task::UserAction: TryIntoUserAction + Send,
{
    pub fn new(
        ctx: &MmArc,
        task_handle: RpcTaskHandleShared<Task>,
        statuses: HwConnectStatuses<Task::InProgressStatus, Task::AwaitingStatus>,
    ) -> MmResult<RpcTaskXPubExtractor<Task>, HDExtractPubkeyError> {
        let crypto_ctx = CryptoCtx::from_ctx(ctx)?;
        let hw_ctx = crypto_ctx
            .hw_ctx()
            .or_mm_err(|| HDExtractPubkeyError::HwContextNotInitialized)?;
        Ok(RpcTaskXPubExtractor::Trezor {
            hw_ctx,
            task_handle,
            statuses,
        })
    }

    /// Constructs an Xpub extractor without checking if the MarketMaker is initialized with a hardware wallet.
    pub fn new_unchecked(
        ctx: &MmArc,
        task_handle: RpcTaskHandleShared<Task>,
        statuses: HwConnectStatuses<Task::InProgressStatus, Task::AwaitingStatus>,
    ) -> XPubExtractorUnchecked<RpcTaskXPubExtractor<Task>> {
        XPubExtractorUnchecked(Self::new(ctx, task_handle, statuses))
    }

    async fn extract_utxo_xpub_from_trezor(
        hw_ctx: &HardwareWalletArc,
        task_handle: RpcTaskHandleShared<Task>,
        statuses: &HwConnectStatuses<Task::InProgressStatus, Task::AwaitingStatus>,
        trezor_coin: String,
        derivation_path: DerivationPath,
    ) -> MmResult<XPub, HDExtractPubkeyError> {
        let pubkey_processor = TrezorRpcTaskProcessor::new(task_handle, statuses.to_trezor_request_statuses());
        let pubkey_processor = Arc::new(pubkey_processor);
        let mut trezor_session = hw_ctx.trezor(pubkey_processor.clone()).await?;
        let xpub = trezor_session
            .get_public_key(
                derivation_path,
                trezor_coin,
                EcdsaCurve::Secp256k1,
                SHOW_PUBKEY_ON_DISPLAY,
                IGNORE_XPUB_MAGIC,
            )
            .await?
            .process(pubkey_processor.clone())
            .await?;

        // Despite we pass `IGNORE_XPUB_MAGIC` to the [`TrezorSession::get_public_key`] method,
        // Trezor sometimes returns pubkeys with magic prefixes like `dgub` prefix for DOGE coin.
        // So we need to replace the magic prefix manually.
        XPubConverter::replace_magic_prefix(xpub).mm_err(HDExtractPubkeyError::from)
    }
}

/// This is a wrapper over `XPubExtractor`. The main goal of this structure is to allow construction of an Xpub extractor
/// even if HD wallet is not supported. But if someone tries to extract an Xpub despite HD wallet is not supported,
/// it fails with an inner `HDExtractPubkeyError` error.
pub struct XPubExtractorUnchecked<XPubExtractor>(MmResult<XPubExtractor, HDExtractPubkeyError>);

#[async_trait]
impl<XPubExtractor> HDXPubExtractor for XPubExtractorUnchecked<XPubExtractor>
where
    XPubExtractor: HDXPubExtractor + Send + Sync,
{
    async fn extract_utxo_xpub(
        &self,
        trezor_utxo_coin: String,
        derivation_path: DerivationPath,
    ) -> MmResult<XPub, HDExtractPubkeyError> {
        self.0
            .as_ref()
            .map_err(Clone::clone)?
            .extract_utxo_xpub(trezor_utxo_coin, derivation_path)
            .await
    }
}
