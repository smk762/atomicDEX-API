#[cfg(not(target_arch = "wasm32"))]
use crate::utxo::rpc_clients::UtxoRpcClientEnum;
#[cfg(not(target_arch = "wasm32"))]
use crate::utxo::{sat_from_big_decimal, FeePolicy, UtxoCommonOps, UTXO_LOCK};
#[cfg(not(target_arch = "wasm32"))] use crate::MarketCoinOps;
use bigdecimal::BigDecimal;
#[cfg(not(target_arch = "wasm32"))]
use common::ip_addr::myipaddr;
use common::mm_ctx::MmArc;
use common::mm_error::prelude::*;
#[cfg(not(target_arch = "wasm32"))]
use futures::compat::Future01CompatExt;
use ln_errors::{ConnectToNodeError, ConnectToNodeResult, EnableLightningError, EnableLightningResult,
                OpenChannelError, OpenChannelResult};
#[cfg(not(target_arch = "wasm32"))]
use ln_utils::{connect_to_node, network_from_string, nodes_data_path, open_ln_channel, parse_node_info,
               read_nodes_data_from_file, save_node_data_to_file, start_lightning, LightningConf, LightningContext};
use std::sync::atomic::AtomicU64;
#[cfg(not(target_arch = "wasm32"))]
use std::sync::atomic::Ordering;
use std::sync::Arc;

#[cfg(not(target_arch = "wasm32"))]
use super::{lp_coinfind_or_err, MmCoinEnum};

mod ln_errors;
mod ln_rpc;
#[cfg(not(target_arch = "wasm32"))] mod ln_utils;

lazy_static! {
    static ref REQUEST_IDX: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
}

#[derive(Deserialize)]
pub struct EnableLightningRequest {
    pub coin: String,
    pub port: Option<u16>,
    pub name: String,
    pub color: Option<String>,
}

#[cfg(target_arch = "wasm32")]
pub async fn enable_lightning(_ctx: MmArc, _req: EnableLightningRequest) -> EnableLightningResult<String> {
    MmError::err(EnableLightningError::UnsupportedMode(
        "'enable_lightning'".into(),
        "native".into(),
    ))
}

/// Start a BTC lightning node (LTC should be added later).
#[cfg(not(target_arch = "wasm32"))]
pub async fn enable_lightning(ctx: MmArc, req: EnableLightningRequest) -> EnableLightningResult<String> {
    // coin has to be enabled in electrum to start a lightning node
    let coin = lp_coinfind_or_err(&ctx, &req.coin).await?;

    let utxo_coin = match coin {
        MmCoinEnum::UtxoCoin(utxo) => utxo,
        _ => {
            return MmError::err(EnableLightningError::UnsupportedCoin(
                req.coin,
                "Only utxo coins are supported in lightning".into(),
            ))
        },
    };

    if !utxo_coin.as_ref().conf.lightning {
        return MmError::err(EnableLightningError::UnsupportedCoin(
            req.coin,
            "'lightning' field not found in coin config".into(),
        ));
    }

    // Channel funding transactions need to spend segwit outputs
    // and while the witness script can be generated from pubkey and be used
    // it's better for the coin to be enabled in segwit to check if balance is enough for funding transaction, etc...
    // TODO: when merging with the "mm2.1-orderbook-ticker-btc-segwit" PR, we should have a different coin called BTC-Lightning
    // with same ticker as BTC and to open a channel the BTC-Segwit wallet should be used to fund the transaction
    if !utxo_coin.as_ref().my_address.addr_format.is_segwit() {
        return MmError::err(EnableLightningError::UnsupportedMode(
            "Lightning network".into(),
            "segwit".into(),
        ));
    }

    let client = match &utxo_coin.as_ref().rpc_client {
        UtxoRpcClientEnum::Electrum(c) => c,
        UtxoRpcClientEnum::Native(_) => {
            return MmError::err(EnableLightningError::UnsupportedMode(
                "Lightning network".into(),
                "electrum".into(),
            ))
        },
    };

    let network = match &utxo_coin.as_ref().conf.network {
        Some(n) => network_from_string(n.clone())?,
        None => {
            return MmError::err(EnableLightningError::UnsupportedCoin(
                req.coin,
                "'network' field not found in coin config".into(),
            ))
        },
    };

    if req.name.len() > 32 {
        return MmError::err(EnableLightningError::InvalidRequest(
            "Node name length can't be more than 32 characters".into(),
        ));
    }
    let node_name = format!("{}{:width$}", req.name, " ", width = 32 - req.name.len());

    let mut node_color = [0u8; 3];
    hex::decode_to_slice(
        req.color.unwrap_or_else(|| "000000".into()),
        &mut node_color as &mut [u8],
    )
    .map_to_mm(|_| EnableLightningError::InvalidRequest("Invalid Hex Color".into()))?;

    let listen_addr = myipaddr(ctx.clone())
        .await
        .map_to_mm(EnableLightningError::InvalidAddress)?;
    let port = req.port.unwrap_or(9735);

    let conf = LightningConf::new(client.clone(), network, listen_addr, port, node_name, node_color);
    start_lightning(ctx, utxo_coin, conf).await?;

    Ok("success".into())
}

#[derive(Deserialize)]
pub struct ConnectToNodeRequest {
    pub coin: String,
    pub node_id: String,
}

#[cfg(target_arch = "wasm32")]
pub async fn connect_to_lightning_node(_ctx: MmArc, _req: ConnectToNodeRequest) -> ConnectToNodeResult<String> {
    MmError::err(ConnectToNodeError::UnsupportedMode(
        "'connect_to_lightning_node'".into(),
        "native".into(),
    ))
}

/// Connect to a certain node on the lightning network.
#[cfg(not(target_arch = "wasm32"))]
pub async fn connect_to_lightning_node(ctx: MmArc, req: ConnectToNodeRequest) -> ConnectToNodeResult<String> {
    let lightning_ctx = LightningContext::from_ctx(&ctx).unwrap();

    {
        let background_processor = lightning_ctx.background_processors.lock().await;
        if !background_processor.contains_key(&req.coin) {
            return MmError::err(ConnectToNodeError::LightningNotEnabled(req.coin));
        }
    }

    let (node_pubkey, node_addr) = parse_node_info(req.node_id.clone())?;

    let peer_managers = lightning_ctx.peer_managers.lock().await;
    let peer_manager = peer_managers
        .get(&req.coin)
        .ok_or(ConnectToNodeError::LightningNotEnabled(req.coin))?;
    let res = connect_to_node(node_pubkey, node_addr, peer_manager.clone()).await?;

    Ok(res.to_string())
}

mod named_unit_variant {
    named_unit_variant!(max);
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum ChannelOpenAmount {
    Exact(BigDecimal),
    #[serde(with = "named_unit_variant::max")]
    Max,
}

fn get_true() -> bool { true }

#[allow(dead_code)]
#[derive(Debug, Deserialize, PartialEq)]
pub struct OpenChannelRequest {
    pub coin: String,
    pub node_id: String,
    pub amount: ChannelOpenAmount,
    #[serde(default = "get_true")]
    pub announce_channel: bool,
}

#[cfg(target_arch = "wasm32")]
pub async fn open_channel(_ctx: MmArc, _req: OpenChannelRequest) -> OpenChannelResult<String> {
    MmError::err(OpenChannelError::UnsupportedMode(
        "'open_channel'".into(),
        "native".into(),
    ))
}

/// Opens a channel on the lightning network.
#[cfg(not(target_arch = "wasm32"))]
pub async fn open_channel(ctx: MmArc, req: OpenChannelRequest) -> OpenChannelResult<String> {
    let coin = lp_coinfind_or_err(&ctx, &req.coin).await?;

    let utxo_coin = match coin {
        MmCoinEnum::UtxoCoin(utxo) => utxo,
        _ => {
            return MmError::err(OpenChannelError::UnsupportedCoin(
                req.coin,
                "Only utxo coins are supported in lightning".into(),
            ))
        },
    };

    let lightning_ctx = LightningContext::from_ctx(&ctx).unwrap();

    {
        let background_processor = lightning_ctx.background_processors.lock().await;
        if !background_processor.contains_key(&req.coin) {
            return MmError::err(OpenChannelError::LightningNotEnabled(req.coin));
        }
    }

    let decimals = utxo_coin.as_ref().decimals;
    let (amount, fee_policy) = match req.amount.clone() {
        ChannelOpenAmount::Exact(value) => {
            let balance = utxo_coin.my_spendable_balance().compat().await?;
            if balance < value {
                return MmError::err(OpenChannelError::BalanceError(format!(
                    "Not enough balance to open channel, Current balance: {}",
                    balance
                )));
            }
            let amount = sat_from_big_decimal(&value, decimals)?;
            (amount, FeePolicy::SendExact)
        },
        ChannelOpenAmount::Max => {
            let _utxo_lock = UTXO_LOCK.lock().await;
            let (unspents, _) = utxo_coin
                .ordered_mature_unspents(&utxo_coin.as_ref().my_address)
                .await?;
            (
                unspents.iter().fold(0, |sum, unspent| sum + unspent.value),
                FeePolicy::DeductFromOutput(0),
            )
        },
    };

    let (node_pubkey, node_addr) = parse_node_info(req.node_id.clone())?;

    {
        let peer_managers = lightning_ctx.peer_managers.lock().await;
        let peer_manager = peer_managers
            .get(&req.coin)
            .ok_or_else(|| ConnectToNodeError::LightningNotEnabled(req.coin.clone()))?;
        connect_to_node(node_pubkey, node_addr, peer_manager.clone()).await?;
    }

    let nodes_data = read_nodes_data_from_file(&nodes_data_path(&ctx))?;
    if !nodes_data.contains_key(&node_pubkey) {
        save_node_data_to_file(&nodes_data_path(&ctx), &req.node_id)?;
    }

    // Helps in tracking which FundingGenerationReady events corresponds to which open_channel call
    let request_id = REQUEST_IDX.fetch_add(1, Ordering::Relaxed);

    {
        let mut funding_tx_params = lightning_ctx.funding_tx_params.lock().await;
        funding_tx_params.insert(request_id, fee_policy);
    }

    let temporary_channel_id = {
        let channel_managers = lightning_ctx.channel_managers.lock().await;
        let channel_manager = channel_managers
            .get(&req.coin)
            .ok_or(ConnectToNodeError::LightningNotEnabled(req.coin))?;
        open_ln_channel(
            node_pubkey,
            amount,
            request_id,
            req.announce_channel,
            channel_manager.clone(),
        )?
    };

    Ok(format!(
        "Initiated opening channel with temporary ID: {:?} with node: {} and request id: {}",
        temporary_channel_id, req.node_id, request_id
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{self as json};

    #[test]
    fn test_deserialize_open_channel_request() {
        let req = json!({
            "coin":"test",
            "node_id": "pubkey@ip",
            "amount": 0.1,
        });

        let expected = OpenChannelRequest {
            coin: "test".into(),
            node_id: "pubkey@ip".into(),
            amount: ChannelOpenAmount::Exact(0.1.into()),
            fee: None,
            announce_channel: true,
        };

        let actual: OpenChannelRequest = json::from_value(req).unwrap();

        assert_eq!(expected, actual);

        let req = json!({
            "coin":"test",
            "node_id": "pubkey@ip",
            "amount": "max",
        });

        let expected = OpenChannelRequest {
            coin: "test".into(),
            node_id: "pubkey@ip".into(),
            amount: ChannelOpenAmount::Max,
            fee: None,
            announce_channel: true,
        };

        let actual: OpenChannelRequest = json::from_value(req).unwrap();

        assert_eq!(expected, actual);
    }
}
