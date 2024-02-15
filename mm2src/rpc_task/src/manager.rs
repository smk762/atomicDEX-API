use crate::task::RpcTaskTypes;
use crate::{AtomicTaskId, RpcTask, RpcTaskError, RpcTaskHandle, RpcTaskResult, RpcTaskStatus, RpcTaskStatusAlias,
            TaskAbortHandle, TaskAbortHandler, TaskId, TaskStatus, TaskStatusError, UserActionSender};
use common::executor::SpawnFuture;
use common::log::{debug, info};
use futures::channel::oneshot;
use futures::future::{select, Either};
use mm2_err_handle::prelude::*;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, Weak};

macro_rules! unexpected_task_status {
    ($task_id:expr, actual = $actual:ident, expected = $expected:ident) => {
        MmError::err(RpcTaskError::UnexpectedTaskStatus {
            task_id: $task_id,
            actual: TaskStatusError::$actual,
            expected: TaskStatusError::$expected,
        })
    };
}

pub type RpcTaskManagerShared<Task> = Arc<Mutex<RpcTaskManager<Task>>>;
pub(crate) type RpcTaskManagerWeak<Task> = Weak<Mutex<RpcTaskManager<Task>>>;

static NEXT_RPC_TASK_ID: AtomicTaskId = AtomicTaskId::new(0);

fn next_rpc_task_id() -> TaskId { NEXT_RPC_TASK_ID.fetch_add(1, Ordering::Relaxed) }

pub struct RpcTaskManager<Task: RpcTask> {
    tasks: HashMap<TaskId, TaskStatusExt<Task>>,
}

impl<Task: RpcTask> Default for RpcTaskManager<Task> {
    fn default() -> Self { RpcTaskManager { tasks: HashMap::new() } }
}

impl<Task: RpcTask> RpcTaskManager<Task> {
    /// Create new instance of `RpcTaskHandle` attached to the only one `RpcTask`.
    /// This function registers corresponding RPC task in the `RpcTaskManager` and returns the task id.
    pub fn spawn_rpc_task<F>(this: &RpcTaskManagerShared<Task>, spawner: &F, mut task: Task) -> RpcTaskResult<TaskId>
    where
        F: SpawnFuture,
    {
        let initial_task_status = task.initial_status();
        let (task_id, task_abort_handler) = {
            let mut task_manager = this
                .lock()
                .map_to_mm(|e| RpcTaskError::Internal(format!("RpcTaskManager is not available: {}", e)))?;
            task_manager.register_task(initial_task_status)?
        };
        let task_handle = Arc::new(RpcTaskHandle {
            task_manager: RpcTaskManagerShared::downgrade(this),
            task_id,
        });

        let fut = async move {
            debug!("Spawn RPC task '{}'", task_id);
            let task_fut = task.run(task_handle.clone());
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
                    info!("RPC task '{}' has been aborted", task_id);
                    task.cancel().await;
                    task_handle.on_cancelled();
                },
            }
        };
        spawner.spawn(fut);
        Ok(task_id)
    }

    /// Returns a task status if it exists, otherwise returns `None`.
    pub fn task_status(&mut self, task_id: TaskId, forget_if_ready: bool) -> Option<RpcTaskStatusAlias<Task>> {
        let entry = match self.tasks.entry(task_id) {
            Entry::Occupied(entry) => entry,
            Entry::Vacant(_) => return None,
        };
        let rpc_status = match entry.get() {
            TaskStatusExt::InProgress { status, .. } => RpcTaskStatus::InProgress(status.clone()),
            TaskStatusExt::Awaiting { status, .. } => RpcTaskStatus::UserActionRequired(status.clone()),
            // Don't return an `RpcTaskStatus::Cancelled` status,
            // instead return `None` as there is no such task for the user already.
            TaskStatusExt::Cancelling { .. } => return None,
            TaskStatusExt::Ok(result) => RpcTaskStatus::Ok(result.clone()),
            TaskStatusExt::Error(error) => RpcTaskStatus::Error(error.clone()),
        };
        if rpc_status.is_ready() && forget_if_ready {
            entry.remove();
        }
        Some(rpc_status)
    }

    pub fn new_shared() -> RpcTaskManagerShared<Task> { Arc::new(Mutex::new(Self::default())) }

    pub fn contains(&self, task_id: TaskId) -> bool { self.tasks.contains_key(&task_id) }

    /// Cancel task if it's in progress.
    pub fn cancel_task(&mut self, task_id: TaskId) -> RpcTaskResult<()> {
        let task = self.tasks.remove(&task_id);

        match task {
            Some(finished_task @ TaskStatusExt::Ok(_) | finished_task @ TaskStatusExt::Error(_)) => {
                // Return the task result to the `tasks` container.
                self.tasks.insert(task_id, finished_task);
                unexpected_task_status!(task_id, actual = Finished, expected = InProgress)
            },
            Some(TaskStatusExt::InProgress { .. }) => {
                let new_task = TaskStatusExt::Cancelling { _action_sender: None };
                self.tasks.insert(task_id, new_task);
                Ok(())
            },
            Some(TaskStatusExt::Awaiting { action_sender, .. }) => {
                let new_task = TaskStatusExt::Cancelling {
                    _action_sender: Some(action_sender),
                };
                self.tasks.insert(task_id, new_task);
                Ok(())
            },
            Some(cancelling_task @ TaskStatusExt::Cancelling { .. }) => {
                // Return the task result to the `tasks` container.
                self.tasks.insert(task_id, cancelling_task);
                unexpected_task_status!(task_id, actual = Cancelled, expected = InProgress)
            },
            None => MmError::err(RpcTaskError::NoSuchTask(task_id)),
        }
    }

    pub(crate) fn register_task(
        &mut self,
        task_initial_in_progress_status: Task::InProgressStatus,
    ) -> RpcTaskResult<(TaskId, TaskAbortHandler)> {
        let task_id = next_rpc_task_id();
        let (abort_handle, abort_handler) = oneshot::channel();
        match self.tasks.entry(task_id) {
            Entry::Occupied(_entry) => unexpected_task_status!(task_id, actual = InProgress, expected = Idle),
            Entry::Vacant(entry) => {
                entry.insert(TaskStatusExt::InProgress {
                    status: task_initial_in_progress_status,
                    abort_handle,
                });
                Ok((task_id, abort_handler))
            },
        }
    }

    pub(crate) fn update_task_status(&mut self, task_id: TaskId, status: TaskStatus<Task>) -> RpcTaskResult<()> {
        match status {
            TaskStatus::Ok(result) => self.on_task_finished(task_id, Ok(result)),
            TaskStatus::Error(error) => self.on_task_finished(task_id, Err(error)),
            TaskStatus::InProgress(in_progress) => self.update_in_progress_status(task_id, in_progress),
            TaskStatus::UserActionRequired {
                awaiting_status,
                user_action_tx,
            } => self.set_task_is_waiting_for_user_action(task_id, awaiting_status, user_action_tx),
        }
    }

    pub(crate) fn on_task_cancelling_finished(&mut self, task_id: TaskId) -> RpcTaskResult<()> {
        match self.tasks.remove(&task_id) {
            Some(TaskStatusExt::Cancelling { .. }) => Ok(()),
            _ => {
                let error = format!("Cancelled task '{task_id}' was not in `Cancelling` status");
                MmError::err(RpcTaskError::Internal(error))
            },
        }
    }

    fn on_task_finished(
        &mut self,
        task_id: TaskId,
        task_result: MmResult<Task::Item, Task::Error>,
    ) -> RpcTaskResult<()> {
        let task_status = match task_result {
            Ok(result) => TaskStatusExt::Ok(result),
            Err(error) => TaskStatusExt::Error(error),
        };
        if self.tasks.insert(task_id, task_status).is_none() {
            let error = format!("Finished task '{task_id}' was not ongoing");
            return MmError::err(RpcTaskError::Internal(error));
        }
        Ok(())
    }

    fn update_in_progress_status(&mut self, task_id: TaskId, status: Task::InProgressStatus) -> RpcTaskResult<()> {
        match self.tasks.remove(&task_id) {
            Some(TaskStatusExt::InProgress { abort_handle, .. })
            | Some(TaskStatusExt::Awaiting { abort_handle, .. }) => {
                // Insert new in-progress status to the tasks container.
                self.tasks
                    .insert(task_id, TaskStatusExt::InProgress { status, abort_handle });
                Ok(())
            },
            Some(cancelling @ TaskStatusExt::Cancelling { .. }) => {
                // Return the task result to the tasks container.
                self.tasks.insert(task_id, cancelling);
                unexpected_task_status!(task_id, actual = Cancelled, expected = InProgress)
            },
            Some(ready @ TaskStatusExt::Ok(_) | ready @ TaskStatusExt::Error(_)) => {
                // Return the task result to the tasks container.
                self.tasks.insert(task_id, ready);
                unexpected_task_status!(task_id, actual = Finished, expected = InProgress)
            },
            None => MmError::err(RpcTaskError::NoSuchTask(task_id)),
        }
    }

    fn set_task_is_waiting_for_user_action(
        &mut self,
        task_id: TaskId,
        status: Task::AwaitingStatus,
        action_sender: UserActionSender<Task::UserAction>,
    ) -> RpcTaskResult<()> {
        match self.tasks.remove(&task_id) {
            Some(TaskStatusExt::InProgress {
                status: next_in_progress_status,
                abort_handle,
            }) => {
                // Insert new awaiting status to the tasks container.
                self.tasks.insert(task_id, TaskStatusExt::Awaiting {
                    status,
                    abort_handle,
                    action_sender,
                    next_in_progress_status,
                });
                Ok(())
            },
            Some(unexpected) => {
                let actual_status = unexpected.task_status_err();

                // Return the status to the tasks container.
                self.tasks.insert(task_id, unexpected);

                let error = RpcTaskError::UnexpectedTaskStatus {
                    task_id,
                    actual: actual_status,
                    expected: TaskStatusError::InProgress,
                };
                MmError::err(error)
            },
            None => MmError::err(RpcTaskError::NoSuchTask(task_id)),
        }
    }

    /// Notify a spawned interrupted RPC task about the user action if it await the action.
    pub fn on_user_action(&mut self, task_id: TaskId, user_action: Task::UserAction) -> RpcTaskResult<()> {
        match self.tasks.remove(&task_id) {
            Some(TaskStatusExt::Awaiting {
                action_sender,
                abort_handle,
                next_in_progress_status: status,
                ..
            }) => {
                let result = action_sender
                    .send(user_action)
                    // The task seems to be canceled/aborted for some reason.
                    .map_to_mm(|_user_action| RpcTaskError::Cancelled);
                // Insert new in-progress status to the tasks container.
                self.tasks
                    .insert(task_id, TaskStatusExt::InProgress { status, abort_handle });
                result
            },
            Some(unexpected) => {
                let actual_status = unexpected.task_status_err();

                // Return the unexpected status to the tasks container.
                self.tasks.insert(task_id, unexpected);

                let error = RpcTaskError::UnexpectedTaskStatus {
                    task_id,
                    actual: actual_status,
                    expected: TaskStatusError::AwaitingUserAction,
                };
                MmError::err(error)
            },
            None => MmError::err(RpcTaskError::NoSuchTask(task_id)),
        }
    }
}

/// `TaskStatus` extended with `TaskAbortHandle`.
/// This is stored in the [`RpcTaskManager::tasks`] container.
enum TaskStatusExt<Task: RpcTaskTypes> {
    Ok(Task::Item),
    Error(MmError<Task::Error>),
    InProgress {
        status: Task::InProgressStatus,
        abort_handle: TaskAbortHandle,
    },
    Awaiting {
        status: Task::AwaitingStatus,
        action_sender: UserActionSender<Task::UserAction>,
        abort_handle: TaskAbortHandle,
        next_in_progress_status: Task::InProgressStatus,
    },
    /// `Cancelling` status is set on [`RpcTaskManager::cancel_task`].
    /// This status is used to save the task state before it's actually canceled on [`RpcTaskHandle::on_canceled`],
    /// in particular, to fix https://github.com/KomodoPlatform/atomicDEX-API/issues/1580.
    Cancelling {
        _action_sender: Option<UserActionSender<Task::UserAction>>,
    },
}

impl<Task: RpcTaskTypes> TaskStatusExt<Task> {
    fn task_status_err(&self) -> TaskStatusError {
        match self {
            TaskStatusExt::Ok(_) | TaskStatusExt::Error(_) => TaskStatusError::Finished,
            TaskStatusExt::InProgress { .. } => TaskStatusError::InProgress,
            TaskStatusExt::Awaiting { .. } => TaskStatusError::AwaitingUserAction,
            TaskStatusExt::Cancelling { .. } => TaskStatusError::Cancelled,
        }
    }
}
