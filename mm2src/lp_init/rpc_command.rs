use crate::mm2::lp_native_dex::rpc_task::MmInitUserAction;
use common::mm_ctx::MmArc;
use common::mm_error::prelude::*;
use common::rpc_task::{RpcTaskError, RpcTaskStatus};
use common::{HttpStatusCode, SuccessResponse};
use derive_more::Display;
use http::StatusCode;
use serde_json as json;

fn true_f() -> bool { true }

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MmInitStatusReq {
    #[serde(default = "true_f")]
    forget_if_finished: bool,
}

#[derive(Display, Serialize, SerializeErrorType)]
#[serde(tag = "error_type", content = "error_data")]
pub enum MmInitStatusError {
    InitializationNotStartedYet,
}

impl HttpStatusCode for MmInitStatusError {
    fn status_code(&self) -> StatusCode { StatusCode::INTERNAL_SERVER_ERROR }
}

pub async fn mm_init_status(ctx: MmArc, req: MmInitStatusReq) -> Result<RpcTaskStatus, MmError<MmInitStatusError>> {
    let init_task_id = *ctx
        .mm_init_task_id
        .ok_or(MmInitStatusError::InitializationNotStartedYet)?;

    let mut rpc_manager = ctx.rpc_task_manager();
    rpc_manager
        .task_status(init_task_id, req.forget_if_finished)
        .or_mm_err(|| MmInitStatusError::InitializationNotStartedYet)
}

#[derive(Display, Serialize, SerializeErrorType)]
#[serde(tag = "error_type", content = "error_data")]
pub enum MmInitUserActionError {
    InitializationNotStartedYet,
    // UnexpectedUserAction,
    Internal(String),
}

impl From<RpcTaskError> for MmInitUserActionError {
    fn from(e: RpcTaskError) -> Self {
        match e {
            RpcTaskError::NoSuchTask(_) => MmInitUserActionError::InitializationNotStartedYet,
            error => MmInitUserActionError::Internal(error.to_string()),
        }
    }
}

impl HttpStatusCode for MmInitUserActionError {
    fn status_code(&self) -> StatusCode { StatusCode::INTERNAL_SERVER_ERROR }
}

pub async fn mm_init_user_action(
    ctx: MmArc,
    req: MmInitUserAction,
) -> Result<SuccessResponse, MmError<MmInitUserActionError>> {
    let init_task_id = *ctx
        .mm_init_task_id
        .ok_or(MmInitUserActionError::InitializationNotStartedYet)?;

    let mut rpc_manager = ctx.rpc_task_manager();
    // TODO refactor it when `RpcTaskManager` is generic
    let response_json = json::to_value(req).map_to_mm(|e| MmInitUserActionError::Internal(e.to_string()))?;
    rpc_manager.on_user_action(init_task_id, response_json)?;
    Ok(SuccessResponse::new())
}
