use super::RequestTxHistoryResult;
use crate::utxo::bch::BchCoin;
use crate::utxo::UtxoStandardOps;
use crate::{MarketCoinOps, TxHistoryStorage};
use async_trait::async_trait;
use common::executor::Timer;
use common::log::error;
use common::mm_metrics::MetricsArc;
use common::mm_number::BigDecimal;
use common::state_machine::prelude::*;
use futures::compat::Future01CompatExt;
use rpc::v1::types::H256 as H256Json;

struct BchAndSlpHistoryCtx<Storage: TxHistoryStorage> {
    coin: BchCoin,
    storage: Storage,
    metrics: MetricsArc,
}

// States have to be generic over storage type because BchAndSlpHistoryCtx is generic over it
struct Init<T> {
    phantom: std::marker::PhantomData<T>,
}

impl<T> Init<T> {
    fn new() -> Self {
        Init {
            phantom: Default::default(),
        }
    }
}

impl<T, E> TransitionFrom<Init<T>> for Stopped<T, E> {}

#[async_trait]
impl<T: TxHistoryStorage> State for Init<T> {
    type Ctx = BchAndSlpHistoryCtx<T>;
    type Result = ();

    async fn on_changed(self: Box<Self>, ctx: &mut BchAndSlpHistoryCtx<T>) -> StateResult<BchAndSlpHistoryCtx<T>, ()> {
        if let Err(e) = ctx.storage.init_collection(ctx.coin.ticker()).await {
            return Self::change_state(Stopped::storage_error(e));
        }

        let initial_balance = loop {
            match ctx.coin.my_balance().compat().await {
                Ok(coin_balance) => break coin_balance.into_total(),
                Err(e) => {
                    error!("Error {} on balance fetching for the coin {}", e, ctx.coin.ticker());
                    Timer::sleep(30.).await;
                },
            }
        };
        Self::change_state(FetchingTxHashes::new(initial_balance))
    }
}

// States have to be generic over storage type because BchAndSlpHistoryCtx is generic over it
struct FetchingTxHashes<T> {
    phantom: std::marker::PhantomData<T>,
    current_balance: BigDecimal,
}

impl<T> FetchingTxHashes<T> {
    fn new(current_balance: BigDecimal) -> Self {
        FetchingTxHashes {
            phantom: Default::default(),
            current_balance,
        }
    }
}

impl<T> TransitionFrom<Init<T>> for FetchingTxHashes<T> {}
impl<T> TransitionFrom<OnIoErrorCooldown<T>> for FetchingTxHashes<T> {}
impl<T> TransitionFrom<WaitForHistoryUpdateTrigger<T>> for FetchingTxHashes<T> {}

#[async_trait]
impl<T: TxHistoryStorage> State for FetchingTxHashes<T> {
    type Ctx = BchAndSlpHistoryCtx<T>;
    type Result = ();

    async fn on_changed(self: Box<Self>, ctx: &mut BchAndSlpHistoryCtx<T>) -> StateResult<BchAndSlpHistoryCtx<T>, ()> {
        if let Err(e) = ctx.storage.init_collection(ctx.coin.ticker()).await {
            return Self::change_state(Stopped::storage_error(e));
        }

        let maybe_tx_ids = ctx.coin.request_tx_history(ctx.metrics.clone()).await;
        match maybe_tx_ids {
            RequestTxHistoryResult::Ok(all_tx_ids_with_height) => Self::change_state(UpdatingUnconfirmedTxes::new(
                all_tx_ids_with_height,
                self.current_balance,
            )),
            RequestTxHistoryResult::HistoryTooLarge => Self::change_state(Stopped::<T, T::Error>::history_too_large()),
            RequestTxHistoryResult::Retry { error } => {
                error!("Error {} on requesting tx history for {}", error, ctx.coin.ticker());
                Self::change_state(OnIoErrorCooldown::new(self.current_balance))
            },
            RequestTxHistoryResult::CriticalError(e) => {
                error!(
                    "Critical error {} on requesting tx history for {}",
                    e,
                    ctx.coin.ticker()
                );
                Self::change_state(Stopped::<T, T::Error>::unknown(e))
            },
        }
    }
}

// States have to be generic over storage type because BchAndSlpHistoryCtx is generic over it
struct OnIoErrorCooldown<T> {
    phantom: std::marker::PhantomData<T>,
    current_balance: BigDecimal,
}

impl<T> OnIoErrorCooldown<T> {
    fn new(current_balance: BigDecimal) -> Self {
        OnIoErrorCooldown {
            phantom: Default::default(),
            current_balance,
        }
    }
}

impl<T> TransitionFrom<FetchingTxHashes<T>> for OnIoErrorCooldown<T> {}

#[async_trait]
impl<T: TxHistoryStorage> State for OnIoErrorCooldown<T> {
    type Ctx = BchAndSlpHistoryCtx<T>;
    type Result = ();

    async fn on_changed(self: Box<Self>, _ctx: &mut BchAndSlpHistoryCtx<T>) -> StateResult<BchAndSlpHistoryCtx<T>, ()> {
        Timer::sleep(30.).await;
        Self::change_state(FetchingTxHashes::new(self.current_balance))
    }
}

// States have to be generic over storage type because BchAndSlpHistoryCtx is generic over it
struct WaitForHistoryUpdateTrigger<T> {
    phantom: std::marker::PhantomData<T>,
    current_balance: BigDecimal,
}

impl<T> WaitForHistoryUpdateTrigger<T> {
    fn new(current_balance: BigDecimal) -> Self {
        WaitForHistoryUpdateTrigger {
            phantom: Default::default(),
            current_balance,
        }
    }
}

#[async_trait]
impl<T: TxHistoryStorage> State for WaitForHistoryUpdateTrigger<T> {
    type Ctx = BchAndSlpHistoryCtx<T>;
    type Result = ();

    async fn on_changed(self: Box<Self>, ctx: &mut BchAndSlpHistoryCtx<T>) -> StateResult<Self::Ctx, Self::Result> {
        loop {
            Timer::sleep(30.).await;
            match ctx.storage.contains_unconfirmed_transactions(ctx.coin.ticker()).await {
                Ok(contains) => {
                    if contains {
                        return Self::change_state(FetchingTxHashes::new(self.current_balance));
                    }
                },
                Err(e) => return Self::change_state(Stopped::storage_error(e)),
            }

            match ctx.coin.my_balance().compat().await {
                Ok(balance) => {
                    let total_balance = balance.into_total();
                    if self.current_balance != total_balance {
                        return Self::change_state(FetchingTxHashes::new(total_balance));
                    }
                },
                Err(e) => {
                    error!("Error {} on balance fetching for the coin {}", e, ctx.coin.ticker());
                },
            }
        }
    }
}

// States have to be generic over storage type because BchAndSlpHistoryCtx is generic over it
struct UpdatingUnconfirmedTxes<T> {
    phantom: std::marker::PhantomData<T>,
    all_tx_ids_with_height: Vec<(H256Json, u64)>,
    current_balance: BigDecimal,
}

impl<T> UpdatingUnconfirmedTxes<T> {
    fn new(all_tx_ids_with_height: Vec<(H256Json, u64)>, current_balance: BigDecimal) -> Self {
        UpdatingUnconfirmedTxes {
            phantom: Default::default(),
            all_tx_ids_with_height,
            current_balance,
        }
    }
}

impl<T> TransitionFrom<FetchingTxHashes<T>> for UpdatingUnconfirmedTxes<T> {}

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
                Self::change_state(FetchingTransactionsData::new(
                    self.all_tx_ids_with_height,
                    self.current_balance,
                ))
            },
            Err(e) => Self::change_state(Stopped::storage_error(e)),
        }
    }
}

// States have to be generic over storage type because BchAndSlpHistoryCtx is generic over it
struct FetchingTransactionsData<T> {
    phantom: std::marker::PhantomData<T>,
    all_tx_ids_with_height: Vec<(H256Json, u64)>,
    current_balance: BigDecimal,
}

impl<T> TransitionFrom<UpdatingUnconfirmedTxes<T>> for FetchingTransactionsData<T> {}

impl<T> FetchingTransactionsData<T> {
    fn new(all_tx_ids_with_height: Vec<(H256Json, u64)>, current_balance: BigDecimal) -> Self {
        FetchingTransactionsData {
            phantom: Default::default(),
            all_tx_ids_with_height,
            current_balance,
        }
    }
}

#[async_trait]
impl<T: TxHistoryStorage> State for FetchingTransactionsData<T> {
    type Ctx = BchAndSlpHistoryCtx<T>;
    type Result = ();

    async fn on_changed(self: Box<Self>, ctx: &mut BchAndSlpHistoryCtx<T>) -> StateResult<BchAndSlpHistoryCtx<T>, ()> {
        unimplemented!()
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

impl<T, E> TransitionFrom<FetchingTxHashes<T>> for Stopped<T, E> {}
impl<T, E> TransitionFrom<UpdatingUnconfirmedTxes<T>> for Stopped<T, E> {}
impl<T, E> TransitionFrom<WaitForHistoryUpdateTrigger<T>> for Stopped<T, E> {}

#[async_trait]
impl<T: TxHistoryStorage, E: Send + 'static> LastState for Stopped<T, E> {
    type Ctx = BchAndSlpHistoryCtx<T>;
    type Result = ();

    async fn on_changed(self: Box<Self>, ctx: &mut Self::Ctx) -> Self::Result { todo!() }
}

pub async fn bch_and_slp_history_loop(coin: BchCoin, storage: impl TxHistoryStorage, metrics: MetricsArc) {
    let ctx = BchAndSlpHistoryCtx { coin, storage, metrics };
    let state_machine: StateMachine<_, ()> = StateMachine::from_ctx(ctx);
    state_machine.run(Init::new()).await;
}
