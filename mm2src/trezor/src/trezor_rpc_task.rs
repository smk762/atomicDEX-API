use crate::{TrezorError, TrezorEvent, TrezorPinMatrix3x3Response, TrezorResponseReceiver};
use async_trait::async_trait;
use common::mm_error::prelude::*;
use common::rpc_task::{RpcTaskError, RpcTaskHandle};
use derive_more::Display;
use futures::StreamExt;
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use std::convert::{TryFrom, TryInto};
use std::time::Duration;

pub type TrezorInteractionResult<T> = Result<T, MmError<TrezorInteractionError>>;

#[derive(Display)]
pub enum TrezorInteractionError {
    TrezorError(TrezorError),
    RpcTaskError(RpcTaskError),
    UnexpectedUserAction { expected: String },
    Internal(String),
}

impl From<TrezorError> for TrezorInteractionError {
    fn from(trezor: TrezorError) -> Self { TrezorInteractionError::TrezorError(trezor) }
}

impl From<RpcTaskError> for TrezorInteractionError {
    fn from(rpc: RpcTaskError) -> Self { TrezorInteractionError::RpcTaskError(rpc) }
}

#[async_trait]
pub trait TrezorInteractWithUser<T, Item, Error, InProgressStatus, AwaitingStatus, UserAction>: Sized {
    async fn interact_with_user_if_required(
        self,
        timeout: Duration,
        task_handle: &RpcTaskHandle<Item, Error, InProgressStatus, AwaitingStatus, UserAction>,
        status_on_button_request: InProgressStatus,
        status_on_pin_request: AwaitingStatus,
    ) -> TrezorInteractionResult<T>;
}

#[async_trait]
impl<T, Item, Error, InProgressStatus, AwaitingStatus, UserAction>
    TrezorInteractWithUser<T, Item, Error, InProgressStatus, AwaitingStatus, UserAction> for TrezorResponseReceiver<T>
where
    Item: Send + Sync,
    Error: Send + Sync,
    T: Send + 'static,
    InProgressStatus: Clone + Serialize + Send + Sync,
    AwaitingStatus: Clone + Serialize + Send + Sync,
    UserAction: DeserializeOwned + Send + Sync,
    TrezorPinMatrix3x3Response: TryFrom<UserAction, Error = TrezorInteractionError> + Send,
{
    async fn interact_with_user_if_required(
        mut self,
        timeout: Duration,
        task_handle: &RpcTaskHandle<Item, Error, InProgressStatus, AwaitingStatus, UserAction>,
        status_on_button_request: InProgressStatus,
        status_on_pin_request: AwaitingStatus,
    ) -> TrezorInteractionResult<T> {
        while let Some(trezor_event) = self.next().await {
            match trezor_event {
                TrezorEvent::Ready(result) => return Ok(result),
                TrezorEvent::ButtonRequest => {
                    // Notify the user should accept/decline the operation on his Trezor.
                    task_handle.update_in_progress_status(status_on_button_request.clone())?;
                },
                TrezorEvent::PinMatrix3x3Request { pin_response_tx } => {
                    // Notify the user should enter a pin and wait until he sends it.
                    let user_action = task_handle
                        .wait_for_user_action(timeout, status_on_pin_request.clone())
                        .await?;
                    let pin_response: TrezorPinMatrix3x3Response = user_action.try_into()?;
                    pin_response_tx.send(pin_response).ok();
                },
            }
        }
        MmError::err(TrezorInteractionError::Internal(
            "Event loop finished unexpectedly".to_owned(),
        ))
    }
}
