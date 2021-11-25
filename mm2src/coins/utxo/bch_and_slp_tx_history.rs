use crate::utxo::bch::BchCoin;
use crate::TxHistoryStorage;
use common::mm_metrics::MetricsArc;

pub async fn bch_and_slp_history_loop(_coin: BchCoin, _storage: impl TxHistoryStorage, _metrics: MetricsArc) {}
