use crate::custom_futures::{FutureTimerExt, TimeoutError};
use crate::executor::spawn;
use crate::log::{debug, warn, LogOnError};
use crate::mm_ctx::{MmArc, MmWeak};
use crate::mm_error::prelude::*;
use crate::mm_rpc_protocol::MmRpcResult;
use async_trait::async_trait;
use derive_more::Display;
use futures::channel::oneshot;
use futures::future::{select, Either};
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{self as json, Error as JsonError, Value as Json};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::marker::PhantomData;
use std::time::Duration;

pub type FinishedTaskResult = MmRpcResult<Json, MmJsonError>;
pub type RpcTaskResult<T> = Result<T, MmError<RpcTaskError>>;
pub type TaskId = u64;

type UserActionSender = oneshot::Sender<Json>;
type TaskAbortHandle = oneshot::Sender<()>;
type TaskAbortHandler = oneshot::Receiver<()>;

#[derive(Display)]
pub enum RpcTaskError {
    #[display(fmt = "RPC task timeout '{:?}'", _0)]
    Timeout(Duration),
    NoSuchTask(TaskId),
    #[display(
        fmt = "RPC '{}' task is in unexpected status. Actual: '{}', expected: '{}'",
        task_id,
        actual,
        expected
    )]
    UnexpectedTaskStatus {
        task_id: TaskId,
        actual: TaskStatusError,
        expected: TaskStatusError,
    },
    ErrorDeserializingUserAction(String),
    ErrorSerializingStatus(JsonError),
    Canceled,
    Internal(String),
}

#[derive(Display)]
pub enum TaskStatusError {
    Idle,
    InProgress,
    AwaitingUserAction,
    Finished,
}

impl From<TimeoutError> for RpcTaskError {
    fn from(e: TimeoutError) -> Self { RpcTaskError::Timeout(e.duration) }
}

/// Create new instance of `RpcTaskHandle` attached to the only one `RpcTask`.
/// This function registers corresponding RPC task in the `RpcTaskManager` and returns the task id.
pub fn spawn_rpc_task<Task, Item, Error, InProgressStatus, AwaitingStatus, UserAction>(
    ctx: MmArc,
    task: Task,
) -> RpcTaskResult<TaskId>
where
    Task: RpcTask<
            Item = Item,
            Error = Error,
            InProgressStatus = InProgressStatus,
            AwaitingStatus = AwaitingStatus,
            UserAction = UserAction,
        > + Send
        + 'static,
    Item: Serialize + Send + Sync + 'static,
    Error: SerMmErrorType + Send + Sync + 'static,
    InProgressStatus: Serialize + Send + Sync + 'static,
    AwaitingStatus: Serialize + Send + Sync + 'static,
    UserAction: DeserializeOwned + Send + Sync + 'static,
{
    let initial_task_status = task.initial_status();
    let initial_task_status_json =
        json::to_value(initial_task_status).map_to_mm(RpcTaskError::ErrorSerializingStatus)?;

    let (task_id, task_abort_handler) = {
        let mut task_manager = ctx.rpc_task_manager();
        task_manager.register_task(initial_task_status_json)?
    };
    let task_handle = RpcTaskHandle {
        ctx: ctx.weak(),
        task_id,
        phantom: PhantomData::default(),
    };

    let fut = async move {
        debug!("Spawn RPC task '{}'", task_id);
        let task_fut = task.run(&task_handle);
        let task_result = match select(task_fut, task_abort_handler).await {
            // The task has finished.
            Either::Left((task_result, _abort_handler)) => Some(task_result),
            // The task has been aborted from outside.
            Either::Right((_aborted, _task)) => None,
        };
        // We can't finish or abort the task in the match statement above since `task_handle` is borrowed here:
        // `task.run(&task_handle)`.
        match task_result {
            Some(task_result) => {
                debug!("RPC task '{}' has been finished", task_id);
                task_handle.finish(task_result);
            },
            None => {
                debug!("RPC task '{}' has been aborted", task_id);
                task_handle.abort();
            },
        }
    };
    spawn(fut);
    Ok(task_id)
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", content = "details")]
pub enum RpcTaskStatus {
    Ready(FinishedTaskResult),
    InProgress(Json),
    UserActionRequired(Json),
}

/// TODO refactor `RpcTaskManager` to make it generic with
/// `Item`, `Error`, `InProgressStatus`, `AwaitingStatus` and `UserAction` type params.
/// It will avoid using `Json` and `MmJsonError` when communicating with the user.
#[derive(Default)]
pub struct RpcTaskManager {
    in_progress: HashMap<TaskId, (Json, TaskAbortHandle)>,
    awaiting: HashMap<TaskId, (Json, UserActionSender)>,
    finished: HashMap<TaskId, FinishedTaskResult>,
    next_task_id: TaskId,
}

impl RpcTaskManager {
    pub fn contains(&self, task_id: TaskId) -> bool {
        self.in_progress.contains_key(&task_id)
            || self.awaiting.contains_key(&task_id)
            || self.finished.contains_key(&task_id)
    }

    /// Returns a task status if it exists, otherwise returns `None`.
    pub fn task_status(&mut self, task_id: TaskId, forget_if_ready: bool) -> Option<RpcTaskStatus> {
        // First, check if the task is awaiting for a user action.
        if let Some((awaiting_status, _action_tx)) = self.awaiting.get(&task_id) {
            return Some(RpcTaskStatus::UserActionRequired(awaiting_status.clone()));
        }
        // Second, check if the task is still ongoing.
        if let Some((status, _handle)) = self.in_progress.get(&task_id) {
            return Some(RpcTaskStatus::InProgress(status.clone()));
        }
        // Third, return a result of the task if it exists.
        if forget_if_ready {
            self.finished.remove(&task_id).map(RpcTaskStatus::Ready)
        } else {
            self.finished
                .get(&task_id)
                .map(|ready| RpcTaskStatus::Ready(ready.clone()))
        }
    }

    /// Cancel task if it's in progress.
    pub fn cancel_task(&mut self, task_id: TaskId) -> RpcTaskResult<()> {
        self.in_progress
            .remove(&task_id)
            .map(|_| ())
            .or_mm_err(|| self.rpc_task_error_if_not_found(task_id, TaskStatusError::InProgress))
    }

    /// Notify a spawned interrupted RPC task about the user action if it await the action.
    pub fn on_user_action(&mut self, task_id: TaskId, user_action: Json) -> RpcTaskResult<()> {
        let (_status, user_action_sender) = self
            .awaiting
            .remove(&task_id)
            .or_mm_err(|| self.rpc_task_error_if_not_found(task_id, TaskStatusError::AwaitingUserAction))?;
        user_action_sender
            .send(user_action)
            // The task seems to be canceled/aborted for some reason.
            .map_to_mm(|_user_action| RpcTaskError::Canceled)
    }

    fn rpc_task_error_if_not_found(&self, task_id: TaskId, expected: TaskStatusError) -> RpcTaskError {
        if self.finished.contains_key(&task_id) {
            RpcTaskError::UnexpectedTaskStatus {
                task_id,
                actual: TaskStatusError::Finished,
                expected,
            }
        } else if self.awaiting.contains_key(&task_id) {
            RpcTaskError::UnexpectedTaskStatus {
                task_id,
                actual: TaskStatusError::AwaitingUserAction,
                expected,
            }
        } else if self.in_progress.contains_key(&task_id) {
            RpcTaskError::UnexpectedTaskStatus {
                task_id,
                actual: TaskStatusError::InProgress,
                expected,
            }
        } else {
            RpcTaskError::NoSuchTask(task_id)
        }
    }

    fn next_task_id(&mut self) -> TaskId {
        let id = self.next_task_id;
        self.next_task_id += 1;
        id
    }

    fn register_task(&mut self, task_initial_in_progress_status: Json) -> RpcTaskResult<(TaskId, TaskAbortHandler)> {
        let task_id = self.next_task_id();
        let (task_abort_handle, task_abort_handler) = oneshot::channel();
        match self.in_progress.entry(task_id) {
            Entry::Occupied(_entry) => MmError::err(RpcTaskError::UnexpectedTaskStatus {
                task_id,
                actual: TaskStatusError::InProgress,
                expected: TaskStatusError::Idle,
            }),
            Entry::Vacant(entry) => {
                entry.insert((task_initial_in_progress_status, task_abort_handle));
                Ok((task_id, task_abort_handler))
            },
        }
    }

    fn update_task_status(&mut self, task_id: TaskId, status: TaskStatus) -> RpcTaskResult<()> {
        match status {
            TaskStatus::Ready(result) => self.on_task_finished(task_id, result),
            TaskStatus::InProgress(in_progress) => self.update_in_progress_status(task_id, in_progress),
            TaskStatus::UserActionRequired {
                awaiting_status: action,
                user_action_tx: action_tx,
            } => self.set_task_is_waiting_for_user_action(task_id, action, action_tx),
        }
    }

    fn on_task_aborted(&mut self, task_id: TaskId) {
        self.in_progress.remove(&task_id);
        self.awaiting.remove(&task_id);
    }

    fn on_task_finished(&mut self, task_id: TaskId, task_result: FinishedTaskResult) -> RpcTaskResult<()> {
        match self.finished.entry(task_id) {
            Entry::Occupied(_entry) => {
                return MmError::err(RpcTaskError::UnexpectedTaskStatus {
                    task_id,
                    actual: TaskStatusError::Finished,
                    expected: TaskStatusError::InProgress,
                });
            },
            Entry::Vacant(entry) => {
                entry.insert(task_result);
            },
        }
        if self.in_progress.remove(&task_id).is_none() {
            warn!("Finished task '{}' was not ongoing", task_id);
        }
        if self.awaiting.remove(&task_id).is_some() {
            warn!("Finished task '{}' was waiting for a user action", task_id);
        }
        Ok(())
    }

    fn update_in_progress_status(&mut self, task_id: TaskId, in_progress_status: Json) -> RpcTaskResult<()> {
        let status = match self.in_progress.get_mut(&task_id) {
            Some((status, _handle)) => status,
            None => return MmError::err(RpcTaskError::NoSuchTask(task_id)),
        };
        *status = in_progress_status;
        Ok(())
    }

    fn set_task_is_waiting_for_user_action(
        &mut self,
        task_id: TaskId,
        awaiting_status: Json,
        user_action_tx: UserActionSender,
    ) -> RpcTaskResult<()> {
        match self.awaiting.entry(task_id) {
            Entry::Occupied(_entry) => MmError::err(RpcTaskError::UnexpectedTaskStatus {
                task_id,
                actual: TaskStatusError::AwaitingUserAction,
                expected: TaskStatusError::InProgress,
            }),
            Entry::Vacant(entry) => {
                entry.insert((awaiting_status, user_action_tx));
                Ok(())
            },
        }
    }
}

pub struct RpcTaskHandle<Item, Error, InProgressStatus, AwaitingStatus, UserAction> {
    ctx: MmWeak,
    task_id: TaskId,
    phantom: PhantomData<(Item, Error, InProgressStatus, AwaitingStatus, UserAction)>,
}

impl<Item, Error, InProgressStatus, AwaitingStatus, UserAction>
    RpcTaskHandle<Item, Error, InProgressStatus, AwaitingStatus, UserAction>
{
    fn mm_ctx(&self) -> RpcTaskResult<MmArc> {
        MmArc::from_weak(&self.ctx).or_mm_err(|| RpcTaskError::Internal("MmCtx is not available".to_owned()))
    }

    fn update_task_status(&self, status: TaskStatus) -> RpcTaskResult<()> {
        let ctx = self.mm_ctx()?;
        let mut task_manager = ctx.rpc_task_manager();
        task_manager.update_task_status(self.task_id, status)
    }

    fn abort(self) {
        if let Ok(ctx) = self.mm_ctx() {
            let mut task_manager = ctx.rpc_task_manager();
            task_manager.on_task_aborted(self.task_id);
        }
    }
}

impl<Item, Error, InProgressStatus, AwaitingStatus, UserAction>
    RpcTaskHandle<Item, Error, InProgressStatus, AwaitingStatus, UserAction>
where
    InProgressStatus: Serialize,
{
    pub fn update_in_progress_status(&self, in_progress: InProgressStatus) -> RpcTaskResult<()> {
        let in_progress = json::to_value(in_progress).map_to_mm(RpcTaskError::ErrorSerializingStatus)?;
        self.update_task_status(TaskStatus::InProgress(in_progress))
    }
}

impl<Item, Error, InProgressStatus, AwaitingStatus, UserAction>
    RpcTaskHandle<Item, Error, InProgressStatus, AwaitingStatus, UserAction>
where
    InProgressStatus: Serialize,
    AwaitingStatus: Serialize,
    UserAction: DeserializeOwned,
{
    pub async fn wait_for_user_action(
        &self,
        timeout: Duration,
        awaiting_status: AwaitingStatus,
    ) -> RpcTaskResult<UserAction> {
        let awaiting_status = json::to_value(awaiting_status).map_to_mm(RpcTaskError::ErrorSerializingStatus)?;

        let (user_action_tx, user_action_rx) = oneshot::channel();
        // Set the status to 'UserActionRequired' to let the user know that we are waiting for an action.
        self.update_task_status(TaskStatus::UserActionRequired {
            awaiting_status,
            user_action_tx,
        })?;

        // Wait for the user action.
        let user_action = match user_action_rx.timeout(timeout).await? {
            Ok(user_action) => user_action,
            Err(_canceled) => return MmError::err(RpcTaskError::Canceled),
        };
        let user_action =
            json::from_value(user_action).map_to_mm(|e| RpcTaskError::ErrorDeserializingUserAction(e.to_string()))?;
        Ok(user_action)
    }
}

impl<Item, Error, InProgressStatus, AwaitingStatus, UserAction>
    RpcTaskHandle<Item, Error, InProgressStatus, AwaitingStatus, UserAction>
where
    Item: Serialize,
    Error: SerMmErrorType,
{
    fn prepare_task_result(result: Result<Item, MmError<Error>>) -> FinishedTaskResult {
        match result {
            Ok(task_item) => Self::prepare_task_item(task_item),
            Err(task_error) => Self::prepare_task_error(task_error),
        }
    }

    /// Try to serialize the successful result of a task.
    fn prepare_task_item(task_item: Item) -> FinishedTaskResult {
        match json::to_value(task_item) {
            Ok(serialized_item) => FinishedTaskResult::ok(serialized_item),
            // Else return a serialization error wrapped into `MmJsonError`.
            Err(serialization_error) => {
                FinishedTaskResult::mm_err(MmJsonError::serialization_error(serialization_error))
            },
        }
    }

    /// Try to serialize the task error.
    fn prepare_task_error(task_error: MmError<Error>) -> FinishedTaskResult {
        match MmJsonError::from_mm_error(task_error) {
            Ok(serialized) => FinishedTaskResult::Err(serialized),
            Err(serialization_error) => {
                FinishedTaskResult::mm_err(MmJsonError::serialization_error(serialization_error))
            },
        }
    }

    fn finish(self, result: Result<Item, MmError<Error>>) {
        let ctx = match self.mm_ctx() {
            Ok(ctx) => ctx,
            Err(e) => {
                warn!("{}", e);
                return;
            },
        };
        let task_result = Self::prepare_task_result(result);
        let mut task_manager = ctx.rpc_task_manager();
        task_manager
            .update_task_status(self.task_id, TaskStatus::Ready(task_result))
            .warn_log();
    }
}

#[async_trait]
pub trait RpcTask: Sized {
    type Item: Serialize;
    type Error: SerMmErrorType;
    type InProgressStatus: Serialize;
    type AwaitingStatus: Serialize;
    type UserAction: DeserializeOwned;

    fn initial_status(&self) -> Self::InProgressStatus;

    /// # Clippy
    ///
    /// Currently, there is no way to simplify the task handle type:
    /// https://github.com/rust-lang/rust-clippy/issues/1013#issuecomment-587054810
    #[allow(clippy::type_complexity)]
    async fn run(
        self,
        task_handle: &RpcTaskHandle<
            Self::Item,
            Self::Error,
            Self::InProgressStatus,
            Self::AwaitingStatus,
            Self::UserAction,
        >,
    ) -> Result<Self::Item, MmError<Self::Error>>;
}

enum TaskStatus {
    Ready(FinishedTaskResult),
    InProgress(Json),
    UserActionRequired {
        awaiting_status: Json,
        user_action_tx: UserActionSender,
    },
}
