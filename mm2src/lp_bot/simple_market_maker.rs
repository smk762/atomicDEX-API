use crate::mm2::lp_bot::{SimpleMakerBotRegistry, TickerInfosRegistry, TradingBotContext};
use common::{executor::{spawn, Timer},
             log::{error, info},
             mm_ctx::MmArc,
             mm_error::MmError,
             slurp_url, HttpStatusCode};
use derive_more::Display;
use http::{HeaderMap, StatusCode};
use serde_json::Value as Json;
use std::collections::HashSet;
use std::{str::Utf8Error,
          sync::atomic::{AtomicBool, Ordering}};

// !< constants
const KMD_PRICE_ENDPOINT: &str = "http://95.217.208.239:1313/api/v1/tickers";

// !< Type definitions
pub type StartSimpleMakerBotResult = Result<StartSimpleMakerBotAnswer, MmError<StartSimpleMakerBotError>>;
pub type StopSimpleMakerBotResult = Result<StopSimpleMakerBotAnswer, MmError<StopSimpleMakerBotError>>;

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct StartSimpleMakerBotRequest {
    cfg: SimpleMakerBotRegistry,
}

#[cfg(test)]
impl StartSimpleMakerBotRequest {
    pub fn new() -> StartSimpleMakerBotRequest {
        return StartSimpleMakerBotRequest {
            cfg: Default::default(),
        };
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct StopSimpleMakerBotAnswer {
    result: String,
}

#[cfg(test)]
impl StopSimpleMakerBotAnswer {
    pub fn get_result(&self) -> String { return self.result.clone(); }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct StartSimpleMakerBotAnswer {
    result: String,
}

#[cfg(test)]
impl StartSimpleMakerBotAnswer {
    pub fn get_result(&self) -> String { return self.result.clone(); }
}

#[derive(Debug, Deserialize, Display, Serialize, SerializeErrorType)]
#[serde(tag = "error_type", content = "error_data")]
pub enum StopSimpleMakerBotError {
    #[display(fmt = "The bot is already stopped")]
    AlreadyStopped,
    #[display(fmt = "The bot is already stopping")]
    AlreadyStopping,
    #[display(fmt = "Transport error: {}", _0)]
    Transport(String),
    #[display(fmt = "Internal error: {}", _0)]
    InternalError(String),
}

#[derive(Debug, Deserialize, Display, Serialize, SerializeErrorType)]
#[serde(tag = "error_type", content = "error_data")]
pub enum StartSimpleMakerBotError {
    #[display(fmt = "The bot is already started")]
    AlreadyStarted,
    #[display(fmt = "Invalid bot configuration")]
    InvalidBotConfiguration,
    #[display(fmt = "Transport error: {}", _0)]
    Transport(String),
    #[display(fmt = "Internal error: {}", _0)]
    InternalError(String),
}

#[derive(Debug)]
pub enum PriceServiceRequestError {
    HttpProcessError(String),
}

impl From<std::string::String> for PriceServiceRequestError {
    fn from(error: String) -> Self { return PriceServiceRequestError::HttpProcessError(error); }
}

impl From<std::str::Utf8Error> for PriceServiceRequestError {
    fn from(error: Utf8Error) -> Self { return PriceServiceRequestError::HttpProcessError(error.to_string()); }
}

impl HttpStatusCode for StartSimpleMakerBotError {
    fn status_code(&self) -> StatusCode {
        match self {
            StartSimpleMakerBotError::AlreadyStarted | StartSimpleMakerBotError::InvalidBotConfiguration => {
                StatusCode::BAD_REQUEST
            },
            StartSimpleMakerBotError::Transport(_) | StartSimpleMakerBotError::InternalError(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            },
        }
    }
}

impl HttpStatusCode for StopSimpleMakerBotError {
    fn status_code(&self) -> StatusCode {
        match self {
            // maybe bad request is not adapted for the first errors.
            StopSimpleMakerBotError::AlreadyStopped | StopSimpleMakerBotError::AlreadyStopping => {
                StatusCode::BAD_REQUEST
            },
            StopSimpleMakerBotError::Transport(_) | StopSimpleMakerBotError::InternalError(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            },
        }
    }
}

pub async fn tear_down_bot(ctx: MmArc) {
    let simple_market_maker_bot_ctx = TradingBotContext::from_ctx(&ctx).unwrap();
    {
        let mut trading_bot_cfg = simple_market_maker_bot_ctx.trading_bot_cfg.lock().await;
        // todo: check if clear is adapted, if i understand its keep the memory allocated for later usage.
        trading_bot_cfg.clear();
    }
    // todo: cancel all pending orders
}

async fn process_bot_logic(ctx: &MmArc) {
    let simple_market_maker_bot_ctx = TradingBotContext::from_ctx(ctx).unwrap();
    // note: Copy the cfg here will not be expensive, and this will be thread safe.
    let cfg = simple_market_maker_bot_ctx.trading_bot_cfg.lock().await.clone();
    //let coins_ctx = OrderMatchContext
    //let memoization_pair_registry: HashSet<String>;
    //let to_skip_pairs_registry: HashSet<String>;
}

pub async fn lp_bot_loop(ctx: MmArc) {
    info!("lp_bot_loop successfully started");
    loop {
        // todo: this log should probably in debug
        info!("tick lp_bot_loop");
        if ctx.is_stopping() {
            // todo: can we cancel all the pending orders when the ctx is stopping or call tear_down ?
            break;
        }
        let simple_market_maker_bot_ctx = TradingBotContext::from_ctx(&ctx).unwrap();
        let mut states = simple_market_maker_bot_ctx.trading_bot_states.lock().await;
        if states.is_stopping.load(Ordering::Relaxed) {
            states.is_running = AtomicBool::new(false);
            states.is_stopping = AtomicBool::new(false);
            // todo: verify if there is a possible deadlock here if i use states inside tear_down_bot
            tear_down_bot(ctx).await;
            break;
        }
        drop(states);
        process_bot_logic(&ctx).await;
        Timer::sleep(30.0).await;
    }
    info!("lp_bot_loop successfully stopped");
}

pub async fn process_price_request() -> Result<(StatusCode, String, HeaderMap), MmError<PriceServiceRequestError>> {
    info!("Fetching price from: {}", KMD_PRICE_ENDPOINT);
    let (status, headers, body) = slurp_url(KMD_PRICE_ENDPOINT).await?;
    Ok((status, std::str::from_utf8(&body)?.trim().into(), headers))
}

async fn fetch_price_tickers(ctx: &MmArc) {
    let (status_code, body, _) = match process_price_request().await {
        Ok(x) => x,
        Err(_) => return,
    };
    if status_code == StatusCode::OK {
        // todo: here there is not any chance that the unwrap fail i guess because the status code is OK
        let model: TickerInfosRegistry = serde_json::from_str(&body).unwrap();
        let simple_market_maker_bot_ctx = TradingBotContext::from_ctx(&ctx).unwrap();
        let mut price_registry = simple_market_maker_bot_ctx.price_tickers_registry.lock().await;
        *price_registry = model;
        info!("registry size: {}", price_registry.len());
    } else {
        error!("error from price request: {} - {}", status_code, body);
    }
}

pub async fn lp_price_service_loop(ctx: MmArc) {
    info!("lp_price_service successfully started");
    loop {
        // todo: this log should probably in debug
        info!("tick lp_price_service_loop");
        if ctx.is_stopping() {
            break;
        }

        let simple_market_maker_bot_ctx = TradingBotContext::from_ctx(&ctx).unwrap();
        let states = simple_market_maker_bot_ctx.trading_bot_states.lock().await;
        if states.is_stopping.load(Ordering::Relaxed) {
            info!("stop price service loop");
            break;
        }
        drop(states);
        fetch_price_tickers(&ctx).await;
        Timer::sleep(20.0).await;
    }
    info!("lp_price_service successfully stopped");
}

pub async fn start_simple_market_maker_bot(ctx: MmArc, req: StartSimpleMakerBotRequest) -> StartSimpleMakerBotResult {
    let simple_market_maker_bot_ctx = TradingBotContext::from_ctx(&ctx).unwrap();
    {
        let mut states = simple_market_maker_bot_ctx.trading_bot_states.lock().await;
        if states.is_running.load(Ordering::Relaxed) {
            return MmError::err(StartSimpleMakerBotError::AlreadyStarted);
        }
        let mut trading_bot_cfg = simple_market_maker_bot_ctx.trading_bot_cfg.lock().await;
        *trading_bot_cfg = req.cfg;
        states.is_running = AtomicBool::new(true);
    }

    info!("simple_market_maker_bot successfully started");
    spawn(lp_price_service_loop(ctx.clone()));
    spawn(lp_bot_loop(ctx.clone()));
    return Ok(StartSimpleMakerBotAnswer {
        result: "Success".to_string(),
    });
}

pub async fn stop_simple_market_maker_bot(ctx: MmArc, _req: Json) -> StopSimpleMakerBotResult {
    let simple_market_maker_bot_ctx = TradingBotContext::from_ctx(&ctx).unwrap();
    {
        let mut states = simple_market_maker_bot_ctx.trading_bot_states.lock().await;
        if !states.is_running.load(Ordering::Relaxed) {
            return MmError::err(StopSimpleMakerBotError::AlreadyStopped);
        } else if states.is_stopping.load(Ordering::Relaxed) {
            return MmError::err(StopSimpleMakerBotError::AlreadyStopping);
        }

        states.is_stopping = AtomicBool::new(true);
    }
    info!("simple_market_maker_bot will stop within 30 seconds");
    return Ok(StopSimpleMakerBotAnswer {
        result: "Success".to_string(),
    });
}
