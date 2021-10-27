#[cfg(not(target_arch = "wasm32"))]
use crate::utxo::rpc_clients::UtxoRpcClientEnum;
#[cfg(not(target_arch = "wasm32"))]
use common::ip_addr::myipaddr;
use common::mm_ctx::MmArc;
use common::mm_error::prelude::*;
use ln_errors::{ConnectToNodeError, ConnectToNodeResult, EnableLightningError, EnableLightningResult};
#[cfg(not(target_arch = "wasm32"))]
use ln_utils::{connect_to_node, network_from_string, nodes_data_path, parse_node_info, save_node_data_to_file,
               start_lightning, LightningConf, LightningContext};

#[cfg(not(target_arch = "wasm32"))]
use super::{lp_coinfind_or_err, MmCoinEnum};

mod ln_errors;
mod ln_rpc;
#[cfg(not(target_arch = "wasm32"))] mod ln_utils;

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
    start_lightning(&ctx, utxo_coin, conf).await?;

    Ok("success".into())
}

#[derive(Deserialize)]
pub struct ConnectToNodeRequest {
    pub coin: String,
    pub node_id: String,
    #[serde(default)]
    pub reconnect_on_restart: bool,
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
    if ctx.ln_background_processor.is_none() {
        return MmError::err(ConnectToNodeError::LightningNotEnabled(req.coin));
    }

    let (node_pubkey, node_addr) = parse_node_info(req.node_id.clone())?;

    if req.reconnect_on_restart {
        save_node_data_to_file(&nodes_data_path(&ctx), &req.node_id)?
    }

    let lightning_ctx = LightningContext::from_ctx(&ctx).unwrap();
    let peer_managers = lightning_ctx.peer_managers.lock().await;
    let peer_manager = peer_managers
        .get(&req.coin)
        .ok_or(ConnectToNodeError::LightningNotEnabled(req.coin))?;
    connect_to_node(node_pubkey, node_addr, peer_manager.clone()).await?;

    Ok("success".into())
}
