#[cfg(not(target_arch = "wasm32"))]
use super::{lp_coinfind_or_err, MmCoinEnum};
use crate::utxo::rpc_clients::UtxoRpcClientEnum;
#[cfg(not(target_arch = "wasm32"))]
use crate::utxo::{sat_from_big_decimal, UtxoCommonOps, UtxoTxGenerationOps};
use crate::{BalanceFut, CoinBalance, FeeApproxStage, FoundSwapTxSpend, HistorySyncState, MarketCoinOps, MmCoin,
            NegotiateSwapContractAddrErr, SwapOps, TradeFee, TradePreimageFut, TradePreimageValue, TransactionEnum,
            TransactionFut, UtxoStandardCoin, ValidateAddressResult, WithdrawFut, WithdrawRequest};
use bigdecimal::BigDecimal;
use bitcoin::blockdata::script::Script;
use bitcoin::hash_types::Txid;
#[cfg(not(target_arch = "wasm32"))]
use common::ip_addr::myipaddr;
use common::mm_ctx::MmArc;
use common::mm_error::prelude::*;
use common::mm_number::MmNumber;
use derive_more::Display;
#[cfg(not(target_arch = "wasm32"))]
use futures::compat::Future01CompatExt;
use futures::lock::Mutex as AsyncMutex;
use futures01::Future;
use lightning::chain::WatchedOutput;
#[cfg(not(target_arch = "wasm32"))]
use lightning_background_processor::BackgroundProcessor;
use ln_errors::{ConnectToNodeError, ConnectToNodeResult, EnableLightningError, EnableLightningResult,
                OpenChannelError, OpenChannelResult};
#[cfg(not(target_arch = "wasm32"))]
use ln_utils::{connect_to_node, last_request_id_path, nodes_data_path, open_ln_channel, parse_node_info,
               read_last_request_id_from_file, read_nodes_data_from_file, save_last_request_id_to_file,
               save_node_data_to_file, ChannelManager, PeerManager};
use rpc::v1::types::Bytes as BytesJson;
use serde_json::{self as json, Value as Json};
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::fmt;
use std::sync::Arc;

mod ln_errors;
mod ln_rpc;
pub mod ln_utils;

#[derive(Debug)]
pub struct PlatformFields {
    pub platform_coin: UtxoStandardCoin,
    // This cache stores the transactions that the LN node has interest in.
    pub registered_txs: AsyncMutex<HashMap<Txid, HashSet<Script>>>,
    // This cache stores the outputs that the LN node has interest in.
    pub registered_outputs: AsyncMutex<Vec<WatchedOutput>>,
}

impl PlatformFields {
    pub async fn add_tx(&self, txid: &Txid, script_pubkey: &Script) {
        let mut registered_txs = self.registered_txs.lock().await;
        match registered_txs.get_mut(txid) {
            Some(h) => {
                h.insert(script_pubkey.clone());
            },
            None => {
                let mut script_pubkeys = HashSet::new();
                script_pubkeys.insert(script_pubkey.clone());
                registered_txs.insert(*txid, script_pubkeys);
            },
        }
    }

    pub async fn add_output(&self, output: WatchedOutput) {
        let mut registered_outputs = self.registered_outputs.lock().await;
        registered_outputs.push(output);
    }
}

#[derive(Debug)]
pub struct LightningCoinConf {
    ticker: String,
}

#[derive(Clone)]
pub struct LightningCoin {
    pub platform_fields: Arc<PlatformFields>,
    pub conf: Arc<LightningCoinConf>,
    /// The lightning node peer manager that takes care of connecting to peers, etc..
    #[cfg(not(target_arch = "wasm32"))]
    pub peer_manager: Arc<PeerManager>,
    /// The lightning node background processor that takes care of tasks that need to happen periodically
    #[cfg(not(target_arch = "wasm32"))]
    pub background_processor: Arc<BackgroundProcessor>,
    /// The lightning node channel manager which keeps track of the number of open channels and sends messages to the appropriate
    /// channel, also tracks HTLC preimages and forwards onion packets appropriately.
    #[cfg(not(target_arch = "wasm32"))]
    pub channel_manager: Arc<ChannelManager>,
}

impl fmt::Debug for LightningCoin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LightningCoin {{ platform_fields: {:?}, conf: {:?} }}",
            self.platform_fields, self.conf
        )
    }
}

impl LightningCoin {
    fn platform_coin(&self) -> &UtxoStandardCoin { &self.platform_fields.platform_coin }
}

impl SwapOps for LightningCoin {
    fn send_taker_fee(&self, _fee_addr: &[u8], _amount: BigDecimal, _uuid: &[u8]) -> TransactionFut { unimplemented!() }

    fn send_maker_payment(
        &self,
        _time_lock: u32,
        _taker_pub: &[u8],
        _secret_hash: &[u8],
        _amount: BigDecimal,
        _swap_contract_address: &Option<BytesJson>,
    ) -> TransactionFut {
        unimplemented!()
    }

    fn send_taker_payment(
        &self,
        _time_lock: u32,
        _maker_pub: &[u8],
        _secret_hash: &[u8],
        _amount: BigDecimal,
        _swap_contract_address: &Option<BytesJson>,
    ) -> TransactionFut {
        unimplemented!()
    }

    fn send_maker_spends_taker_payment(
        &self,
        _taker_payment_tx: &[u8],
        _time_lock: u32,
        _taker_pub: &[u8],
        _secret: &[u8],
        _swap_contract_address: &Option<BytesJson>,
    ) -> TransactionFut {
        unimplemented!()
    }

    fn send_taker_spends_maker_payment(
        &self,
        _maker_payment_tx: &[u8],
        _time_lock: u32,
        _maker_pub: &[u8],
        _secret: &[u8],
        _swap_contract_address: &Option<BytesJson>,
    ) -> TransactionFut {
        unimplemented!()
    }

    fn send_taker_refunds_payment(
        &self,
        _taker_payment_tx: &[u8],
        _time_lock: u32,
        _maker_pub: &[u8],
        _secret_hash: &[u8],
        _swap_contract_address: &Option<BytesJson>,
    ) -> TransactionFut {
        unimplemented!()
    }

    fn send_maker_refunds_payment(
        &self,
        _maker_payment_tx: &[u8],
        _time_lock: u32,
        _taker_pub: &[u8],
        _secret_hash: &[u8],
        _swap_contract_address: &Option<BytesJson>,
    ) -> TransactionFut {
        unimplemented!()
    }

    fn validate_fee(
        &self,
        _fee_tx: &TransactionEnum,
        _expected_sender: &[u8],
        _fee_addr: &[u8],
        _amount: &BigDecimal,
        _min_block_number: u64,
        _uuid: &[u8],
    ) -> Box<dyn Future<Item = (), Error = String> + Send> {
        unimplemented!()
    }

    fn validate_maker_payment(
        &self,
        _payment_tx: &[u8],
        _time_lock: u32,
        _maker_pub: &[u8],
        _secret_hash: &[u8],
        _amount: BigDecimal,
        _swap_contract_address: &Option<BytesJson>,
    ) -> Box<dyn Future<Item = (), Error = String> + Send> {
        unimplemented!()
    }

    fn validate_taker_payment(
        &self,
        _payment_tx: &[u8],
        _time_lock: u32,
        _taker_pub: &[u8],
        _secret_hash: &[u8],
        _amount: BigDecimal,
        _swap_contract_address: &Option<BytesJson>,
    ) -> Box<dyn Future<Item = (), Error = String> + Send> {
        unimplemented!()
    }

    fn check_if_my_payment_sent(
        &self,
        _time_lock: u32,
        _other_pub: &[u8],
        _secret_hash: &[u8],
        _search_from_block: u64,
        _swap_contract_address: &Option<BytesJson>,
    ) -> Box<dyn Future<Item = Option<TransactionEnum>, Error = String> + Send> {
        unimplemented!()
    }

    fn search_for_swap_tx_spend_my(
        &self,
        _time_lock: u32,
        _other_pub: &[u8],
        _secret_hash: &[u8],
        _tx: &[u8],
        _search_from_block: u64,
        _swap_contract_address: &Option<BytesJson>,
    ) -> Result<Option<FoundSwapTxSpend>, String> {
        unimplemented!()
    }

    fn search_for_swap_tx_spend_other(
        &self,
        _time_lock: u32,
        _other_pub: &[u8],
        _secret_hash: &[u8],
        _tx: &[u8],
        _search_from_block: u64,
        _swap_contract_address: &Option<BytesJson>,
    ) -> Result<Option<FoundSwapTxSpend>, String> {
        unimplemented!()
    }

    fn extract_secret(&self, _secret_hash: &[u8], _spend_tx: &[u8]) -> Result<Vec<u8>, String> { unimplemented!() }

    fn negotiate_swap_contract_addr(
        &self,
        _other_side_address: Option<&[u8]>,
    ) -> Result<Option<BytesJson>, MmError<NegotiateSwapContractAddrErr>> {
        unimplemented!()
    }
}

impl MarketCoinOps for LightningCoin {
    fn ticker(&self) -> &str { &self.conf.ticker }

    // Returns platform_coin address for now
    fn my_address(&self) -> Result<String, String> { self.platform_coin().my_address() }

    // Returns platform_coin balance for now
    fn my_balance(&self) -> BalanceFut<CoinBalance> { self.platform_coin().my_balance() }

    fn base_coin_balance(&self) -> BalanceFut<BigDecimal> { unimplemented!() }

    fn send_raw_tx(&self, _tx: &str) -> Box<dyn Future<Item = String, Error = String> + Send> { unimplemented!() }

    fn wait_for_confirmations(
        &self,
        _tx: &[u8],
        _confirmations: u64,
        _requires_nota: bool,
        _wait_until: u64,
        _check_every: u64,
    ) -> Box<dyn Future<Item = (), Error = String> + Send> {
        unimplemented!()
    }

    fn wait_for_tx_spend(
        &self,
        _transaction: &[u8],
        _wait_until: u64,
        _from_block: u64,
        _swap_contract_address: &Option<BytesJson>,
    ) -> TransactionFut {
        unimplemented!()
    }

    fn tx_enum_from_bytes(&self, _bytes: &[u8]) -> Result<TransactionEnum, String> { unimplemented!() }

    fn current_block(&self) -> Box<dyn Future<Item = u64, Error = String> + Send> {
        self.platform_coin().current_block()
    }

    fn display_priv_key(&self) -> String { unimplemented!() }

    fn min_tx_amount(&self) -> BigDecimal { unimplemented!() }

    fn min_trading_vol(&self) -> MmNumber { unimplemented!() }
}

impl MmCoin for LightningCoin {
    fn is_asset_chain(&self) -> bool { unimplemented!() }

    fn withdraw(&self, _req: WithdrawRequest) -> WithdrawFut { unimplemented!() }

    fn decimals(&self) -> u8 { unimplemented!() }

    fn convert_to_address(&self, _from: &str, _to_address_format: Json) -> Result<String, String> { unimplemented!() }

    fn validate_address(&self, _address: &str) -> ValidateAddressResult { unimplemented!() }

    fn process_history_loop(&self, _ctx: MmArc) -> Box<dyn Future<Item = (), Error = ()> + Send> { unimplemented!() }

    fn history_sync_status(&self) -> HistorySyncState { unimplemented!() }

    fn get_trade_fee(&self) -> Box<dyn Future<Item = TradeFee, Error = String> + Send> { unimplemented!() }

    fn get_sender_trade_fee(&self, _value: TradePreimageValue, _stage: FeeApproxStage) -> TradePreimageFut<TradeFee> {
        unimplemented!()
    }

    fn get_receiver_trade_fee(&self, _stage: FeeApproxStage) -> TradePreimageFut<TradeFee> { unimplemented!() }

    fn get_fee_to_send_taker_fee(
        &self,
        _dex_fee_amount: BigDecimal,
        _stage: FeeApproxStage,
    ) -> TradePreimageFut<TradeFee> {
        unimplemented!()
    }

    fn required_confirmations(&self) -> u64 { self.platform_coin().required_confirmations() }

    fn requires_notarization(&self) -> bool { self.platform_coin().requires_notarization() }

    fn set_required_confirmations(&self, _confirmations: u64) { unimplemented!() }

    fn set_requires_notarization(&self, _requires_nota: bool) { unimplemented!() }

    fn swap_contract_address(&self) -> Option<BytesJson> { unimplemented!() }

    fn mature_confirmations(&self) -> Option<u32> { self.platform_coin().mature_confirmations() }

    fn coin_protocol_info(&self) -> Vec<u8> { unimplemented!() }

    fn is_coin_protocol_supported(&self, _info: &Option<Vec<u8>>) -> bool { unimplemented!() }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LightningActivationParams {
    // The listening port for the p2p LN node
    pub listening_port: u16,
    // Printable human-readable string to describe this node to other users.
    pub node_name: [u8; 32],
    // Node's RGB color. This is used for showing the node in a network graph with the desired color.
    pub node_color: [u8; 3],
}

#[derive(Debug, Deserialize, Display, Serialize, SerializeErrorType)]
#[serde(tag = "error_type", content = "error_data")]
pub enum LightningFromLegacyReqErr {
    #[display(fmt = "Platform coin {} activated in {} mode", _0, _1)]
    UnexpectedMethod(String, String),
    #[display(fmt = "{} is only supported in {} mode", _0, _1)]
    UnsupportedMode(String, String),
    #[display(fmt = "Invalid request: {}", _0)]
    InvalidRequest(String),
    #[display(fmt = "Invalid address: {}", _0)]
    InvalidAddress(String),
}

impl From<serde_json::Error> for LightningFromLegacyReqErr {
    fn from(e: serde_json::Error) -> Self { LightningFromLegacyReqErr::InvalidRequest(e.to_string()) }
}

impl LightningActivationParams {
    pub fn from_legacy_req(
        platform_coin: UtxoStandardCoin,
        req: &Json,
    ) -> Result<Self, MmError<LightningFromLegacyReqErr>> {
        match (req["method"].as_str(), platform_coin.as_ref().rpc_client.clone()) {
            // TODO: Remove this error when Native mode is supported for lightning
            (Some("enable"), UtxoRpcClientEnum::Native(_)) => {
                return MmError::err(LightningFromLegacyReqErr::UnsupportedMode(
                    "For now lightning network".into(),
                    "electrum".into(),
                ))
            },
            (Some("electrum"), UtxoRpcClientEnum::Electrum(_)) => (),
            (Some("enable"), UtxoRpcClientEnum::Electrum(_)) => {
                return MmError::err(LightningFromLegacyReqErr::UnexpectedMethod(
                    platform_coin.ticker().to_string(),
                    "electrum".into(),
                ))
            },
            (Some("electrum"), UtxoRpcClientEnum::Native(_)) => {
                return MmError::err(LightningFromLegacyReqErr::UnexpectedMethod(
                    platform_coin.ticker().to_string(),
                    "native".into(),
                ))
            },
            _ => return MmError::err(LightningFromLegacyReqErr::UnexpectedMethod("".into(), "".into())),
        };

        // Channel funding transactions need to spend segwit outputs
        // and while the witness script can be generated from pubkey and be used
        // it's better for the coin to be enabled in segwit to check if balance is enough for funding transaction, etc...
        if !platform_coin.as_ref().my_address.addr_format.is_segwit() {
            return MmError::err(LightningFromLegacyReqErr::UnsupportedMode(
                "Lightning network".into(),
                "segwit".into(),
            ));
        }

        let name: String = json::from_value(req["name"].clone())?;
        if name.len() > 32 {
            return MmError::err(LightningFromLegacyReqErr::InvalidRequest(
                "Node name length can't be more than 32 characters".into(),
            ));
        }
        let node_name = format!("{}{:width$}", name, " ", width = 32 - name.len());

        let color: String = json::from_value(req["color"].clone()).unwrap_or_else(|_| "000000".into());
        let mut node_color = [0u8; 3];
        hex::decode_to_slice(color, &mut node_color as &mut [u8])
            .map_to_mm(|_| LightningFromLegacyReqErr::InvalidRequest("Invalid Hex Color".into()))?;

        let listening_port = json::from_value(req["port"].clone()).unwrap_or(9735);

        Ok(LightningActivationParams {
            listening_port,
            node_name: node_name.as_bytes().try_into().expect("Node name has incorrect length"),
            node_color,
        })
    }
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
    let coin = lp_coinfind_or_err(&ctx, &req.coin).await?;
    let ln_coin = match coin {
        MmCoinEnum::LightningCoin(c) => c,
        _ => return MmError::err(ConnectToNodeError::UnsupportedCoin(coin.ticker().to_string())),
    };

    let (node_pubkey, node_addr) = parse_node_info(req.node_id.clone())?;
    let res = connect_to_node(node_pubkey, node_addr, ln_coin.peer_manager.clone()).await?;

    Ok(res.to_string())
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(tag = "type", content = "value")]
pub enum ChannelOpenAmount {
    Exact(BigDecimal),
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
    use crate::utxo::ActualTxFee;

    let coin = lp_coinfind_or_err(&ctx, &req.coin).await?;
    let ln_coin = match coin {
        MmCoinEnum::LightningCoin(c) => c,
        _ => return MmError::err(OpenChannelError::UnsupportedCoin(coin.ticker().to_string())),
    };

    let platform_coin = ln_coin.platform_coin().clone();
    let decimals = platform_coin.as_ref().decimals;
    let amount = match req.amount.clone() {
        ChannelOpenAmount::Exact(value) => {
            let balance = platform_coin.my_spendable_balance().compat().await?;
            if balance < value {
                return MmError::err(OpenChannelError::BalanceError(format!(
                    "Not enough balance to open channel, Current balance: {}",
                    balance
                )));
            }
            sat_from_big_decimal(&value, decimals)?
        },
        ChannelOpenAmount::Max => {
            let fee = match platform_coin.get_tx_fee().await {
                Ok(ActualTxFee::Fixed(f)) => f,
                // P2WSH transactions are measured in vbytes and are always equal to 153 for BTC,
                // but since the UtxoTxBuilder in generate_funding_transaction uses the actual bytes size
                // which is equal to 234, 234 will be used for now.
                // TODO: after the hotfix for update_fee_and_check_completeness to calculate the tx_size in vbytes,
                // the vbytes size can be used here for this to reduce fees and to be generic over any other coin
                Ok(ActualTxFee::Dynamic(f)) => f * 234 / 1000,
                Ok(ActualTxFee::FixedPerKb(f)) => f * 234 / 1000,
                Err(e) => return MmError::err(OpenChannelError::RpcError(e.to_string())),
            };
            let (unspents, _) = platform_coin
                .ordered_mature_unspents(&platform_coin.as_ref().my_address)
                .await?;
            unspents.iter().fold(0, |sum, unspent| sum + unspent.value) - fee
        },
    };

    let (node_pubkey, node_addr) = parse_node_info(req.node_id.clone())?;

    connect_to_node(node_pubkey, node_addr, ln_coin.peer_manager.clone()).await?;

    let ticker = ln_coin.ticker();
    let nodes_data = read_nodes_data_from_file(&nodes_data_path(&ctx, ticker))?;
    if !nodes_data.contains_key(&node_pubkey) {
        save_node_data_to_file(&nodes_data_path(&ctx, ticker), &req.node_id)?;
    }

    // Helps in tracking which FundingGenerationReady events corresponds to which open_channel call
    let request_id = match read_last_request_id_from_file(&last_request_id_path(&ctx, ticker)) {
        Ok(id) => id + 1,
        Err(e) => match e.get_inner() {
            OpenChannelError::InvalidPath(_) => 1,
            _ => return Err(e),
        },
    };
    save_last_request_id_to_file(&last_request_id_path(&ctx, ticker), request_id)?;

    let temporary_channel_id = open_ln_channel(
        node_pubkey,
        amount,
        request_id,
        req.announce_channel,
        ln_coin.channel_manager.clone(),
    )?;

    Ok(format!(
        "Initiated opening channel with temporary ID: {:?} with node: {} and request id: {}",
        temporary_channel_id, req.node_id, request_id
    ))
}
