use super::RequestTxHistoryResult;
use crate::utxo::bch::BchCoin;
use crate::utxo::UtxoStandardOps;
use crate::{MarketCoinOps, TxHistoryStorage};
use async_trait::async_trait;
use common::executor::Timer;
use common::log::error;
use common::mm_metrics::MetricsArc;
use common::state_machine::prelude::*;
use rpc::v1::types::H256 as H256Json;

struct BchAndSlpHistoryCtx<Storage: TxHistoryStorage> {
    coin: BchCoin,
    storage: Storage,
    metrics: MetricsArc,
}

// States have to be generic over storage type because BchAndSlpHistoryCtx is generic over it
struct FetchingTxes<T> {
    phantom: std::marker::PhantomData<T>,
}

impl<T> FetchingTxes<T> {
    fn new() -> Self {
        FetchingTxes {
            phantom: Default::default(),
        }
    }
}

// States have to be generic over storage type because BchAndSlpHistoryCtx is generic over it
struct Waiting<T> {
    phantom: std::marker::PhantomData<T>,
}

impl<T> Waiting<T> {
    fn new() -> Self {
        Waiting {
            phantom: Default::default(),
        }
    }
}

struct UpdatingUnconfirmedTxes<T> {
    phantom: std::marker::PhantomData<T>,
    all_tx_ids_with_height: Vec<(H256Json, u64)>,
}

impl<T> UpdatingUnconfirmedTxes<T> {
    fn new(all_tx_ids_with_height: Vec<(H256Json, u64)>) -> Self {
        UpdatingUnconfirmedTxes {
            phantom: Default::default(),
            all_tx_ids_with_height,
        }
    }
}

enum StopReason<E> {
    HistoryTooLarge,
    StorageError(E),
    UnknownError(String),
}

struct Stopped<T, E> {
    phantom: std::marker::PhantomData<T>,
    stop_reason: StopReason<E>,
}

impl<T, E> Stopped<T, E> {
    fn history_too_large() -> Self {
        Stopped {
            phantom: Default::default(),
            stop_reason: StopReason::HistoryTooLarge,
        }
    }

    fn storage_error(e: E) -> Self {
        Stopped {
            phantom: Default::default(),
            stop_reason: StopReason::StorageError(e),
        }
    }

    fn unknown(e: String) -> Self {
        Stopped {
            phantom: Default::default(),
            stop_reason: StopReason::UnknownError(e),
        }
    }
}

impl<T> TransitionFrom<FetchingTxes<T>> for UpdatingUnconfirmedTxes<T> {}
impl<T> TransitionFrom<FetchingTxes<T>> for Waiting<T> {}
impl<T> TransitionFrom<Waiting<T>> for FetchingTxes<T> {}
impl<T, E> TransitionFrom<FetchingTxes<T>> for Stopped<T, E> {}
impl<T, E> TransitionFrom<UpdatingUnconfirmedTxes<T>> for Stopped<T, E> {}

#[async_trait]
impl<T: TxHistoryStorage> State for FetchingTxes<T> {
    type Ctx = BchAndSlpHistoryCtx<T>;
    type Result = ();

    async fn on_changed(self: Box<Self>, ctx: &mut BchAndSlpHistoryCtx<T>) -> StateResult<BchAndSlpHistoryCtx<T>, ()> {
        if let Err(e) = ctx.storage.init_collection(ctx.coin.ticker()).await {
            return Self::change_state(Stopped::storage_error(e));
        }

        let maybe_tx_ids = ctx.coin.request_tx_history(ctx.metrics.clone()).await;
        match maybe_tx_ids {
            RequestTxHistoryResult::Ok(all_tx_ids_with_height) => {
                Self::change_state(UpdatingUnconfirmedTxes::new(all_tx_ids_with_height))
            },
            RequestTxHistoryResult::HistoryTooLarge => Self::change_state(Stopped::<T, T::Error>::history_too_large()),
            RequestTxHistoryResult::Retry { error } => {
                error!("Error {} on requesting tx history for {}", error, ctx.coin.ticker());
                Self::change_state(Waiting::new())
            },
            RequestTxHistoryResult::UnknownError(e) => {
                error!("Error {} on requesting tx history for {}", e, ctx.coin.ticker());
                Self::change_state(Stopped::<T, T::Error>::unknown(e))
            },
        }
    }
}

#[async_trait]
impl<T: TxHistoryStorage> State for Waiting<T> {
    type Ctx = BchAndSlpHistoryCtx<T>;
    type Result = ();

    async fn on_changed(self: Box<Self>, _ctx: &mut Self::Ctx) -> StateResult<Self::Ctx, Self::Result> {
        Timer::sleep(30.).await;
        Self::change_state(FetchingTxes::new())
    }
}

#[async_trait]
impl<T: TxHistoryStorage> State for UpdatingUnconfirmedTxes<T> {
    type Ctx = BchAndSlpHistoryCtx<T>;
    type Result = ();

    async fn on_changed(self: Box<Self>, ctx: &mut BchAndSlpHistoryCtx<T>) -> StateResult<BchAndSlpHistoryCtx<T>, ()> {
        match ctx.storage.get_unconfirmed_transactions(ctx.coin.ticker()).await {
            Ok(unconfirmed) => {
                for mut tx in unconfirmed {
                    let found = self
                        .all_tx_ids_with_height
                        .iter()
                        .find(|(hash, height)| hash.0.as_ref() == tx.tx_hash.0.as_slice());
                    match found {
                        Some((_, height)) => {
                            tx.block_height = *height;
                            if let Err(e) = ctx.storage.update_transaction(ctx.coin.ticker(), &tx).await {
                                return Self::change_state(Stopped::storage_error(e));
                            }
                        },
                        None => {
                            // This can potentially happen when unconfirmed tx is removed from mempool for some reason.
                            // We should remove it from storage too.
                            if let Err(e) = ctx.storage.remove_transaction(ctx.coin.ticker(), &tx.internal_id).await {
                                return Self::change_state(Stopped::storage_error(e));
                            }
                        },
                    }
                }
                unimplemented!()
            },
            Err(e) => Self::change_state(Stopped::storage_error(e)),
        }
    }
}

#[async_trait]
impl<T: TxHistoryStorage, E: Send + 'static> LastState for Stopped<T, E> {
    type Ctx = BchAndSlpHistoryCtx<T>;
    type Result = ();

    async fn on_changed(self: Box<Self>, ctx: &mut Self::Ctx) -> Self::Result { todo!() }
}

pub async fn bch_and_slp_history_loop(coin: BchCoin, storage: impl TxHistoryStorage, metrics: MetricsArc) {
    let ctx = BchAndSlpHistoryCtx { coin, storage, metrics };
    let state_machine: StateMachine<_, ()> = StateMachine::from_ctx(ctx);
    state_machine.run(FetchingTxes::new()).await;
}
