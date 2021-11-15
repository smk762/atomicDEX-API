use crate::{lp_coinfind_or_err, MmCoinEnum, WithdrawError};
use crate::{TransactionDetails, WithdrawRequest};
use async_trait::async_trait;
use common::mm_ctx::MmArc;
use common::mm_error::prelude::*;
use common::rpc_task::{spawn_rpc_task, RpcTask, RpcTaskError, RpcTaskHandle, RpcTaskStatus, TaskId};
use common::{HttpStatusCode, SuccessResponse};
use crypto::trezor::trezor_rpc_task::TrezorInteractionError;
use crypto::trezor::TrezorPinMatrix3x3Response;
use derive_more::Display;
use http::StatusCode;
use serde_json as json;
use std::convert::TryFrom;

pub type WithdrawTaskHandle = RpcTaskHandle<
    TransactionDetails,
    WithdrawError,
    WithdrawInProgressStatus,
    WithdrawAwaitingStatus,
    WithdrawUserAction,
>;
pub type WithdrawInitResult<T> = Result<T, MmError<WithdrawError>>;

#[derive(Debug, Display, Serialize, SerializeErrorType)]
#[serde(tag = "error_type", content = "error_data")]
pub enum WithdrawStatusError {
    NoSuchTask(TaskId),
}

impl HttpStatusCode for WithdrawStatusError {
    fn status_code(&self) -> StatusCode { StatusCode::NOT_FOUND }
}

#[derive(Display, Serialize, SerializeErrorType)]
#[serde(tag = "error_type", content = "error_data")]
pub enum WithdrawUserActionError {
    NoSuchTask(TaskId),
    // UnexpectedUserAction,
    Internal(String),
}

impl From<RpcTaskError> for WithdrawUserActionError {
    fn from(e: RpcTaskError) -> Self {
        match e {
            RpcTaskError::NoSuchTask(task_id) => WithdrawUserActionError::NoSuchTask(task_id),
            error => WithdrawUserActionError::Internal(error.to_string()),
        }
    }
}

impl HttpStatusCode for WithdrawUserActionError {
    fn status_code(&self) -> StatusCode { StatusCode::INTERNAL_SERVER_ERROR }
}

#[async_trait]
pub trait CoinWithdrawInit {
    fn init_withdraw(
        ctx: MmArc,
        req: WithdrawRequest,
        rpc_task_handle: &WithdrawTaskHandle,
    ) -> WithdrawInitResult<TransactionDetails>;
}

#[derive(Serialize)]
pub struct InitWithdrawResponse {
    task_id: TaskId,
}

pub async fn init_withdraw(ctx: MmArc, request: WithdrawRequest) -> WithdrawInitResult<InitWithdrawResponse> {
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

#[derive(Clone, Serialize)]
pub enum WithdrawInProgressStatus {
    Preparing,
    GeneratingTransaction,
    SigningTransaction,
    Finishing,
    /// The following statuses don't require the user to send `UserAction`,
    /// but they tell the user that he should confirm/decline the operation on his device.
    WaitingForTrezorToConnect,
    WaitingForUserToConfirmPubkey,
    WaitingForUserToConfirmSigning,
    WaitingForUserToConnectToTrezor,
}

#[derive(Clone, Deserialize, Serialize)]
pub enum WithdrawAwaitingStatus {
    WaitForTrezorPin,
}

#[derive(Deserialize, Serialize)]
#[serde(tag = "action_type")]
pub enum WithdrawUserAction {
    TrezorPin(TrezorPinMatrix3x3Response),
}

impl TryFrom<WithdrawUserAction> for TrezorPinMatrix3x3Response {
    type Error = TrezorInteractionError;

    fn try_from(value: WithdrawUserAction) -> Result<Self, Self::Error> {
        match value {
            WithdrawUserAction::TrezorPin(pin) => Ok(pin),
        }
    }
}

#[derive(Deserialize)]
pub struct WithdrawUserActionRequest {
    task_id: TaskId,
    user_action: WithdrawUserAction,
}

pub async fn withdraw_user_action(
    ctx: MmArc,
    req: WithdrawUserActionRequest,
) -> Result<SuccessResponse, MmError<WithdrawUserActionError>> {
    let mut rpc_manager = ctx.rpc_task_manager();
    // TODO refactor it when `RpcTaskManager` is generic
    let response_json =
        json::to_value(req.user_action).map_to_mm(|e| WithdrawUserActionError::Internal(e.to_string()))?;
    rpc_manager.on_user_action(req.task_id, response_json)?;
    Ok(SuccessResponse::new())
}

#[async_trait]
pub trait InitWithdrawCoin {
    async fn init_withdraw(
        &self,
        ctx: MmArc,
        req: WithdrawRequest,
        task_handle: &WithdrawTaskHandle,
    ) -> Result<TransactionDetails, MmError<WithdrawError>>;
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

    async fn run(self, task_handle: &WithdrawTaskHandle) -> Result<Self::Item, MmError<Self::Error>> {
        match self.coin {
            MmCoinEnum::UtxoCoin(ref standard_utxo) => {
                standard_utxo.init_withdraw(self.ctx, self.request, task_handle).await
            },
            MmCoinEnum::QtumCoin(ref qtum) => qtum.init_withdraw(self.ctx, self.request, task_handle).await,
            _ => MmError::err(WithdrawError::CoinDoesntSupportInitWithdraw {
                coin: self.coin.ticker().to_owned(),
            }),
        }
    }
}

fn true_f() -> bool { true }
