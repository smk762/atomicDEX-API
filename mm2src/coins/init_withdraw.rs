use crate::{lp_coinfind_or_err, CoinFindError, MmCoinEnum};
use crate::{TransactionDetails, WithdrawError, WithdrawRequest};
use async_trait::async_trait;
use bigdecimal::BigDecimal;
use common::mm_ctx::MmArc;
use common::mm_error::prelude::*;
use common::rpc_task::{spawn_rpc_task, RpcTask, RpcTaskError, RpcTaskHandle, RpcTaskStatus, TaskId};
use common::HttpStatusCode;
use crypto::trezor::TrezorPinMatrix3x3Response;
use derive_more::Display;
use http::StatusCode;
use std::time::Duration;

pub type WithdrawTaskResult<T> = Result<T, MmError<WithdrawTaskError>>;

#[derive(Debug, Display, Serialize, SerializeErrorType)]
#[serde(tag = "error_type", content = "error_data")]
pub enum WithdrawTaskError {
    /*                                         */
    /*------------ RPC task errors ------------*/
    /*                                         */
    #[display(fmt = "Canceled")]
    Canceled,
    #[display(fmt = "Initialization timeout {:?}", _0)]
    Timeout(Duration),
    #[display(fmt = "Unexpected user action. Expected '{}'", expected)]
    UnexpectedUserAction { expected: String },
    #[display(fmt = "Error deserializing user action: '{}'", _0)]
    ErrorDeserializingUserAction(String),
    /// TODO put a device info
    #[display(fmt = "Trezor device disconnected")]
    TrezorDisconnected,
    #[display(fmt = "Trezor internal error: {}", _0)]
    TrezorInternal(String),
    /*                                         */
    /*------------- WithdrawError -------------*/
    /*                                         */
    #[display(
        fmt = "Not enough {} to withdraw: available {}, required at least {}",
        coin,
        available,
        required
    )]
    NotSufficientBalance {
        coin: String,
        available: BigDecimal,
        required: BigDecimal,
    },
    #[display(fmt = "Balance is zero")]
    ZeroBalanceToWithdrawMax,
    #[display(fmt = "The amount {} is too small, required at least {}", amount, threshold)]
    AmountTooLow { amount: BigDecimal, threshold: BigDecimal },
    #[display(fmt = "Invalid address: {}", _0)]
    InvalidAddress(String),
    #[display(fmt = "Invalid fee policy: {}", _0)]
    InvalidFeePolicy(String),
    #[display(fmt = "No such coin {}", coin)]
    NoSuchCoin { coin: String },
    #[display(fmt = "Transport error: {}", _0)]
    Transport(String),
    #[display(fmt = "Internal error: {}", _0)]
    InternalError(String),
}

impl From<RpcTaskError> for WithdrawTaskError {
    fn from(e: RpcTaskError) -> Self {
        let error = e.to_string();
        match e {
            RpcTaskError::Canceled => WithdrawTaskError::Canceled,
            RpcTaskError::Timeout(timeout) => WithdrawTaskError::Timeout(timeout),
            RpcTaskError::ErrorDeserializingUserAction(e) => WithdrawTaskError::ErrorDeserializingUserAction(e),
            RpcTaskError::NoSuchTask(_)
            | RpcTaskError::UnexpectedTaskStatus { .. }
            | RpcTaskError::ErrorSerializingStatus(_) => WithdrawTaskError::InternalError(error),
            RpcTaskError::Internal(internal) => WithdrawTaskError::InternalError(internal),
        }
    }
}

impl From<CoinFindError> for WithdrawTaskError {
    fn from(e: CoinFindError) -> Self {
        match e {
            CoinFindError::NoSuchCoin { coin } => WithdrawTaskError::NoSuchCoin { coin },
        }
    }
}

// TODO move it
// impl From<UtxoSignTxError> for WithdrawTaskError {
//     fn from(e: UtxoSignTxError) -> Self {
//         match e {
//             UtxoSignTxError::TrezorError(TrezorError::DeviceDisconnected) => DelegationError::TrezorDisconnected,
//             UtxoSignTxError::TrezorError(trezor_error) => DelegationError::TrezorInternal(trezor_error.to_string()),
//             UtxoSignTxError::Transport(transport) => DelegationError::Transport(transport),
//             e => DelegationError::InternalError(e.to_string()),
//         }
//     }
// }

impl HttpStatusCode for WithdrawTaskError {
    fn status_code(&self) -> StatusCode {
        match self {
            WithdrawTaskError::NoSuchCoin { .. } => StatusCode::NOT_FOUND,
            WithdrawTaskError::Timeout(_) => StatusCode::REQUEST_TIMEOUT,
            WithdrawTaskError::UnexpectedUserAction { .. }
            | WithdrawTaskError::ErrorDeserializingUserAction(_)
            | WithdrawTaskError::NotSufficientBalance { .. }
            | WithdrawTaskError::ZeroBalanceToWithdrawMax
            | WithdrawTaskError::AmountTooLow { .. }
            | WithdrawTaskError::InvalidAddress(_)
            | WithdrawTaskError::InvalidFeePolicy(_) => StatusCode::BAD_REQUEST,
            WithdrawTaskError::TrezorDisconnected => StatusCode::GONE,
            WithdrawTaskError::Canceled
            | WithdrawTaskError::TrezorInternal(_)
            | WithdrawTaskError::Transport(_)
            | WithdrawTaskError::InternalError(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

#[derive(Debug, Display, Serialize, SerializeErrorType)]
#[serde(tag = "error_type", content = "error_data")]
pub enum WithdrawStatusError {
    NoSuchTask(TaskId),
}

impl HttpStatusCode for WithdrawStatusError {
    fn status_code(&self) -> StatusCode { StatusCode::NOT_FOUND }
}

#[derive(Serialize)]
pub struct InitWithdrawResponse {
    task_id: TaskId,
}

pub async fn init_withdraw(ctx: MmArc, request: WithdrawRequest) -> WithdrawTaskResult<InitWithdrawResponse> {
    let coin = lp_coinfind_or_err(&ctx, &request.coin).await?;
    let task = WithdrawTask {
        ctx: ctx.clone(),
        coin,
        request,
    };
    let task_id = spawn_rpc_task(ctx, task)?;
    Ok(InitWithdrawResponse { task_id })
}

#[derive(Deserialize)]
pub struct WithdrawStatusRequest {
    task_id: TaskId,
    #[serde(default = "true_f")]
    forget_if_finished: bool,
}

pub async fn withdraw_status(
    ctx: MmArc,
    req: WithdrawStatusRequest,
) -> Result<RpcTaskStatus, MmError<WithdrawStatusError>> {
    let mut rpc_manager = ctx.rpc_task_manager();
    rpc_manager
        .task_status(req.task_id, req.forget_if_finished)
        .or_mm_err(|| WithdrawStatusError::NoSuchTask(req.task_id))
}

#[derive(Serialize)]
pub enum WithdrawInProgressStatus {
    Preparing,
    GeneratingTransaction,
    SigningTransaction,
    /// This status doesn't require the user to send `UserAction`,
    /// but it tells the user that he should confirm/decline the operation on his device.
    WaitingForUserToConfirmSigning,
}

#[derive(Deserialize, Serialize)]
pub enum WithdrawAwaitingStatus {
    WaitForTrezorPin,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "action_type")]
pub enum WithdrawUserAction {
    TrezorPin(TrezorPinMatrix3x3Response),
}

pub struct WithdrawTask {
    ctx: MmArc,
    coin: MmCoinEnum,
    request: WithdrawRequest,
}

#[async_trait]
impl RpcTask for WithdrawTask {
    type Item = TransactionDetails;
    type Error = WithdrawError;
    type InProgressStatus = WithdrawInProgressStatus;
    type AwaitingStatus = WithdrawAwaitingStatus;
    type UserAction = WithdrawUserAction;

    fn initial_status(&self) -> Self::InProgressStatus { WithdrawInProgressStatus::Preparing }

    #[allow(clippy::type_complexity)]
    async fn run(
        self,
        _task_handle: &RpcTaskHandle<
            Self::Item,
            Self::Error,
            Self::InProgressStatus,
            Self::AwaitingStatus,
            Self::UserAction,
        >,
    ) -> Result<Self::Item, MmError<Self::Error>> {
        todo!()
    }
}

fn true_f() -> bool { true }
