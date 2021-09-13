//
//  lp_bot.rs
//  marketmaker
//

use common::mm_ctx::{from_ctx, MmArc};
use derive_more::Display;
use futures::lock::Mutex as AsyncMutex;
use std::{collections::HashMap, sync::atomic::AtomicBool, sync::Arc};

#[cfg(test)] use mocktopus::macros::*;

#[path = "lp_bot/simple_market_maker.rs"]
mod simple_market_maker_bot;
pub use simple_market_maker_bot::{start_simple_market_maker_bot, stop_simple_market_maker_bot};

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "lp_bot_tests.rs"]
mod lp_bot_tests;

#[derive(Default)]
struct TradingBotStates {
    /// Used to determine if the bot is running
    pub is_running: AtomicBool,

    /// Used to determine if the bot is shutting down
    pub is_stopping: AtomicBool,
}

pub type SimpleMakerBotRegistry = HashMap<String, SimpleCoinMarketMakerCfg>;

#[derive(Debug, Serialize, Deserialize, Display, Clone)]
#[display(fmt = "{} {} {} {}", base, rel, min_volume, spread)]
pub struct SimpleCoinMarketMakerCfg {
    base: String,
    rel: String,
    min_volume: String,
    spread: String,
    base_confs: i64,
    base_nota: bool,
    rel_confs: i64,
    rel_nota: bool,
    enable: bool,
    price_elapsed_validity: Option<f64>,
    check_last_bidirectional_trade_thresh_hold: Option<bool>,
    max: Option<bool>,
    balance_percent: Option<String>,
}

pub type TickerInfosRegistry = HashMap<String, TickerInfos>;

#[derive(Debug, Serialize, Deserialize)]
pub struct TickerInfos {
    ticker: String,
    last_price: String,
    last_updated: String,
    last_updated_timestamp: i64,
    #[serde(rename = "volume24h")]
    volume24_h: String,
    price_provider: Provider,
    volume_provider: Provider,
    #[serde(rename = "sparkline_7d")]
    sparkline_7_d: Option<Vec<f64>>,
    sparkline_provider: Provider,
    #[serde(rename = "change_24h")]
    change_24_h: String,
    #[serde(rename = "change_24h_provider")]
    change_24_h_provider: Provider,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Provider {
    #[serde(rename = "binance")]
    Binance,
    #[serde(rename = "coingecko")]
    Coingecko,
    #[serde(rename = "coinpaprika")]
    Coinpaprika,
    #[serde(rename = "unknown")]
    Unknown,
}

#[derive(Default)]
struct TradingBotContext {
    pub trading_bot_states: AsyncMutex<TradingBotStates>,
    pub trading_bot_cfg: AsyncMutex<SimpleMakerBotRegistry>,
    pub price_tickers_registry: AsyncMutex<TickerInfosRegistry>,
}

#[cfg_attr(test, mockable)]
impl TradingBotContext {
    /// Obtains a reference to this crate context, creating it if necessary.
    fn from_ctx(ctx: &MmArc) -> Result<Arc<TradingBotContext>, String> {
        Ok(try_s!(from_ctx(&ctx.simple_market_maker_bot_ctx, move || {
            Ok(TradingBotContext::default())
        })))
    }
}
