use crate::custom_futures::{FutureTimerExt, TimeoutError};
use crate::executor::spawn;
use crate::log::{debug, info, warn, LogOnError};
use crate::mm_ctx::{MmArc, MmWeak};
use crate::mm_error::prelude::*;
use crate::SerializationError;
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

pub type RpcTaskResult<T> = Result<T, MmError<RpcTaskError>>;
pub type FinishedTaskResult = Result<Json, MmError<MmJsonError>>;

type UserActionSender = oneshot::Sender<Json>;
type TaskAbortHandle = oneshot::Sender<()>;
type TaskAbortHandler = oneshot::Receiver<()>;
type TaskId = u64;

#[derive(Display)]
pub enum RpcTaskError {
    #[display(fmt = "RPC task timeout '{:?}'", _0)]
    Timeout(Duration),
    NoSuchTask(TaskId),
    TaskIsInProgressAlready(TaskId),
    TaskIsPendingAlready(TaskId),
    TaskIsFinishedAlready(TaskId),
    ErrorDeserializingUserAction(JsonError),
    ErrorSerializingStatus(JsonError),
    Canceled,
    Internal(String),
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
    let mut task_manager = ctx.rpc_task_manager();
    let initial_task_status = task.initial_status();
    let initial_task_status_json =
        json::to_value(initial_task_status).map_to_mm(RpcTaskError::ErrorSerializingStatus)?;

    let (task_id, task_abort_handler) = task_manager.register_task(initial_task_status_json)?;
    let task_handle = RpcTaskHandle {
        ctx: ctx.weak(),
        task_id,
        phantom: PhantomData::default(),
    };

    let fut = async move {
        info!("Spawn RPC task '{}'", task_id);
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
                info!("RPC task '{}' has been finished", task_id);
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
pub enum RpcTaskStatus {
    Ready(FinishedTaskResult),
    InProgress(Json),
    UserActionRequired(Json),
}

#[derive(Default)]
pub struct RpcTaskManager {
    in_progress: HashMap<TaskId, (Json, TaskAbortHandle)>,
    awaiting: HashMap<TaskId, (Json, UserActionSender)>,
    finished: HashMap<TaskId, FinishedTaskResult>,
    next_task_id: TaskId,
}

impl RpcTaskManager {
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

    fn next_task_id(&mut self) -> TaskId {
        let id = self.next_task_id;
        self.next_task_id += 1;
        id
    }

    fn register_task(&mut self, task_initial_in_progress_status: Json) -> RpcTaskResult<(TaskId, TaskAbortHandler)> {
        let task_id = self.next_task_id();
        let (task_abort_handle, task_abort_handler) = oneshot::channel();
        match self.in_progress.entry(task_id) {
            Entry::Occupied(_entry) => MmError::err(RpcTaskError::TaskIsInProgressAlready(task_id)),
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
                return MmError::err(RpcTaskError::TaskIsFinishedAlready(task_id));
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
            Entry::Occupied(_entry) => MmError::err(RpcTaskError::TaskIsPendingAlready(task_id)),
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
}

impl<Item, Error, InProgressStatus, AwaitingStatus, UserAction>
    RpcTaskHandle<Item, Error, InProgressStatus, AwaitingStatus, UserAction>
where
    Item: Serialize,
    Error: SerMmErrorType,
    InProgressStatus: Serialize,
    AwaitingStatus: Serialize,
    UserAction: DeserializeOwned,
{
    pub fn update_in_progress_status(&self, in_progress: InProgressStatus) -> RpcTaskResult<()> {
        let in_progress = json::to_value(in_progress).map_to_mm(RpcTaskError::ErrorSerializingStatus)?;
        self.update_task_status(TaskStatus::InProgress(in_progress))
    }

    pub async fn wait_for_user_action(
        &mut self,
        timeout: Duration,
        awaiting_status: AwaitingStatus,
        next_status: InProgressStatus,
    ) -> RpcTaskResult<UserAction> {
        let awaiting_status = json::to_value(awaiting_status).map_to_mm(RpcTaskError::ErrorSerializingStatus)?;
        let next_status = json::to_value(next_status).map_to_mm(RpcTaskError::ErrorSerializingStatus)?;

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
        let user_action = json::from_value(user_action).map_to_mm(RpcTaskError::ErrorDeserializingUserAction)?;

        // Set the next 'InProgress' status.
        self.update_task_status(TaskStatus::InProgress(next_status))?;
        Ok(user_action)
    }

    fn update_task_status(&self, status: TaskStatus) -> RpcTaskResult<()> {
        let ctx = self.mm_ctx()?;
        let mut task_manager = ctx.rpc_task_manager();
        task_manager.update_task_status(self.task_id, status)
    }

    fn prepare_task_result(result: Result<Item, MmError<Error>>) -> FinishedTaskResult {
        match result {
            Ok(task_item) => Self::prepare_task_item(task_item),
            Err(task_error) => Self::prepare_task_error(task_error),
        }
    }

    /// Try to serialize the successful result of a task.
    fn prepare_task_item(task_item: Item) -> FinishedTaskResult {
        match json::to_value(task_item) {
            Ok(serialized_item) => Ok(serialized_item),
            // Else return a serialization error wrapped into `MmJsonError`.
            Err(serialization_error) => MmError::err(Self::mm_json_serialization_error(serialization_error)),
        }
    }

    /// Try to serialize the task error.
    fn prepare_task_error(task_error: MmError<Error>) -> FinishedTaskResult {
        match MmJsonError::from_mm_error(task_error) {
            Ok(serialized) => Err(serialized),
            Err(serialization_error) => MmError::err(Self::mm_json_serialization_error(serialization_error)),
        }
    }

    /// Generate `MmJsonError` from a serialization error.
    fn mm_json_serialization_error<E: serde::ser::Error>(e: E) -> MmJsonError {
        MmJsonError::new(SerializationError::from_error(e))
            .expect("serialization of 'SerializationError' is expected to be successful")
    }

    fn abort(self) {
        if let Ok(ctx) = self.mm_ctx() {
            let mut task_manager = ctx.rpc_task_manager();
            task_manager.on_task_aborted(self.task_id);
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
