use crate::l2::{EnableL2Error, L2ActivationOps, L2ProtocolParams};
use crate::prelude::*;
use async_trait::async_trait;
use coins::lightning::ln_errors::EnableLightningError;
use coins::lightning::ln_utils::{network_from_string, start_lightning};
use coins::lightning::{LightningActivationParams, LightningActivationRequest, LightningCoin, LightningFromReqErr,
                       LightningProtocolConf};
use coins::utxo::utxo_standard::UtxoStandardCoin;
use coins::{CoinProtocol, MarketCoinOps, MmCoinEnum};
use common::mm_ctx::MmArc;
use common::mm_error::prelude::*;
use serde_derive::Serialize;

impl TryPlatformCoinFromMmCoinEnum for UtxoStandardCoin {
    fn try_from_mm_coin(coin: MmCoinEnum) -> Option<Self>
    where
        Self: Sized,
    {
        match coin {
            MmCoinEnum::UtxoCoin(coin) => Some(coin),
            _ => None,
        }
    }
}

impl TryFromCoinProtocol for LightningProtocolConf {
    fn try_from_coin_protocol(proto: CoinProtocol) -> Result<Self, MmError<CoinProtocol>>
    where
        Self: Sized,
    {
        match proto {
            CoinProtocol::LIGHTNING { platform, network } => Ok(LightningProtocolConf {
                platform_coin_ticker: platform,
                network,
            }),
            proto => MmError::err(proto),
        }
    }
}

impl L2ProtocolParams for LightningProtocolConf {
    fn platform_coin_ticker(&self) -> &str { &self.platform_coin_ticker }
}

#[derive(Debug, Serialize)]
pub struct LightningInitResult {
    platform_coin: String,
}

#[derive(Debug)]
pub enum LightningInitError {
    EnableLightningError(EnableLightningError),
    LightningFromReqErr(LightningFromReqErr),
}

impl From<LightningInitError> for EnableL2Error {
    fn from(err: LightningInitError) -> Self {
        match err {
            LightningInitError::EnableLightningError(enable_err) => match enable_err {
                EnableLightningError::RpcError(rpc_err) => EnableL2Error::Transport(rpc_err),
                enable_error => EnableL2Error::Internal(enable_error.to_string()),
            },
            LightningInitError::LightningFromReqErr(req_err) => EnableL2Error::Internal(req_err.to_string()),
        }
    }
}

impl From<EnableLightningError> for LightningInitError {
    fn from(err: EnableLightningError) -> Self { LightningInitError::EnableLightningError(err) }
}

impl From<LightningFromReqErr> for LightningInitError {
    fn from(err: LightningFromReqErr) -> Self { LightningInitError::LightningFromReqErr(err) }
}

#[async_trait]
impl L2ActivationOps for LightningCoin {
    type PlatformCoin = UtxoStandardCoin;
    type ActivationParams = LightningActivationRequest;
    type ProtocolInfo = LightningProtocolConf;
    type ActivationResult = LightningInitResult;
    type ActivationError = LightningInitError;

    async fn init_l2(
        ctx: &MmArc,
        ticker: String,
        platform_coin: Self::PlatformCoin,
        activation_params: Self::ActivationParams,
        protocol_conf: Self::ProtocolInfo,
    ) -> Result<(Self, Self::ActivationResult), MmError<Self::ActivationError>> {
        let network = network_from_string(protocol_conf.network)?;
        let params = LightningActivationParams::from_activation_req(platform_coin.clone(), activation_params)?;
        let lightning_coin = start_lightning(ctx, platform_coin.clone(), ticker, params, network).await?;
        let init_result = LightningInitResult {
            platform_coin: platform_coin.ticker().into(),
        };
        Ok((lightning_coin, init_result))
    }
}
