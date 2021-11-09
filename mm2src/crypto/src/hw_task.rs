use crate::hw_client::{HwDelayedResponse, HwError};
use async_trait::async_trait;
use common::mm_error::prelude::*;
use common::rpc_task::{RpcTaskError, RpcTaskHandle};
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use std::convert::{TryFrom, TryInto};
use std::time::Duration;
use trezor::{TrezorError, TrezorPinMatrix3x3Response, TrezorUserInteraction};

pub type HwInteractionResult<T> = Result<T, MmError<HwInteractionError>>;

pub enum HwInteractionError {
    HwError(HwError),
    RpcTaskError(RpcTaskError),
    UnexpectedUserAction { expected: String },
}

impl From<HwError> for HwInteractionError {
    fn from(hw: HwError) -> Self { HwInteractionError::HwError(hw) }
}

impl From<RpcTaskError> for HwInteractionError {
    fn from(rpc: RpcTaskError) -> Self { HwInteractionError::RpcTaskError(rpc) }
}

impl From<TrezorError> for HwInteractionError {
    fn from(trezor: TrezorError) -> Self { HwInteractionError::HwError(HwError::from(trezor)) }
}

pub enum HwUserAction {
    TrezorPin(TrezorPinMatrix3x3Response),
}

#[async_trait]
pub trait HwInteractWithUser<T, Item, Error, InProgressStatus, AwaitingStatus, UserAction>: Sized {
    async fn interact_with_user_if_required(
        self,
        timeout: Duration,
        task_handle: &RpcTaskHandle<Item, Error, InProgressStatus, AwaitingStatus, UserAction>,
        status_on_button_request: InProgressStatus,
        status_on_pin_request: AwaitingStatus,
    ) -> HwInteractionResult<T>;
}

#[async_trait]
impl<T, Item, Error, InProgressStatus, AwaitingStatus, UserAction>
    HwInteractWithUser<T, Item, Error, InProgressStatus, AwaitingStatus, UserAction> for HwDelayedResponse<T>
where
    Item: Send + Sync,
    Error: Send + Sync,
    T: Send + 'static,
    InProgressStatus: Serialize + Send + Sync,
    AwaitingStatus: Serialize + Send + Sync,
    UserAction: DeserializeOwned + Send + Sync,
    HwUserAction: TryFrom<UserAction, Error = HwInteractionError> + Send,
{
    async fn interact_with_user_if_required(
        self,
        timeout: Duration,
        task_handle: &RpcTaskHandle<Item, Error, InProgressStatus, AwaitingStatus, UserAction>,
        status_on_button_request: InProgressStatus,
        status_on_pin_request: AwaitingStatus,
    ) -> HwInteractionResult<T> {
        match self {
            HwDelayedResponse::TrezorButtonRequest(button_request) => {
                // Notify the user should accept/decline the operation on his Trezor.
                task_handle.update_in_progress_status(status_on_button_request)?;
                Ok(button_request.ack_all().await?)
            },
            HwDelayedResponse::TrezorPinMatrixRequest(pin_request) => {
                // Notify the user should enter a pin and wait until he sends it.
                let user_action = task_handle.wait_for_user_action(timeout, status_on_pin_request).await?;
                let HwUserAction::TrezorPin(TrezorPinMatrix3x3Response { pin }) = user_action.try_into()?;
                // We don't expect another PIN request
                match pin_request.ack_pin(pin).await? {
                    trezor::TrezorResponse::Ok(xpub) => Ok(xpub),
                    trezor::TrezorResponse::ButtonRequest(button_request) => {
                        // Notify the user should also accept/decline the operation on his Trezor.
                        task_handle.update_in_progress_status(status_on_button_request)?;
                        Ok(button_request.ack_all().await?)
                    },
                    trezor::TrezorResponse::PinMatrixRequest(_) => MmError::err(HwInteractionError::HwError(
                        HwError::UnexpectedUserInteractionRequest(TrezorUserInteraction::PinMatrix3x3),
                    )),
                }
            },
        }
    }
}
