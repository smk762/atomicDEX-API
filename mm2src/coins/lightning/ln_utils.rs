use super::*;
use crate::utxo::rpc_clients::{BestBlock as RpcBestBlock, ElectrumBlockHeader, ElectrumClient, ElectrumNonce,
                               UtxoRpcClientOps};
use crate::utxo::utxo_common::{big_decimal_from_sat, withdraw};
use crate::utxo::utxo_standard::UtxoStandardCoin;
use crate::{MarketCoinOps, WithdrawError, WithdrawRequest};
use bitcoin::blockdata::block::BlockHeader;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::blockdata::script::Script;
use bitcoin::blockdata::transaction::{Transaction, TxOut};
use bitcoin::consensus::encode::deserialize;
use bitcoin::hash_types::{BlockHash, TxMerkleNode};
use bitcoin::network::constants::Network;
use bitcoin_hashes::{sha256d, Hash};
use common::executor::{spawn, Timer};
use common::ip_addr::fetch_external_ip;
use common::log;
use common::log::LogState;
use common::mm_ctx::{from_ctx, MmArc};
use derive_more::Display;
use futures::{compat::Future01CompatExt, lock::Mutex as AsyncMutex};
use keys::{AddressHashEnum, SegwitAddress};
use lightning::chain::keysinterface::{InMemorySigner, KeysInterface, KeysManager};
use lightning::chain::transaction::OutPoint;
use lightning::chain::{chainmonitor, Access, BestBlock, Confirm, Filter, Watch, WatchedOutput};
use lightning::ln::channelmanager;
use lightning::ln::channelmanager::{ChainParameters, ChannelManagerReadArgs, SimpleArcChannelManager};
use lightning::ln::msgs::NetAddress;
use lightning::ln::peer_handler::{IgnoringMessageHandler, MessageHandler, SimpleArcPeerManager};
use lightning::routing::network_graph::{NetGraphMsgHandler, NetworkGraph};
use lightning::util::config::UserConfig;
use lightning::util::events::Event;
use lightning::util::ser::ReadableArgs;
use lightning_background_processor::BackgroundProcessor;
use lightning_net_tokio::SocketDescriptor;
use lightning_persister::FilesystemPersister;
use primitives::hash::H256;
use rand::RngCore;
use secp256k1::PublicKey;
use std::collections::HashMap;
use std::convert::TryInto;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::net::TcpListener;

const CHECK_FOR_NEW_BEST_BLOCK_INTERVAL: u64 = 60;
const BROADCAST_NODE_ANNOUNCEMENT_INTERVAL: u64 = 60;
const TRY_RECONNECTING_TO_NODE_INTERVAL: u64 = 60;

type ChainMonitor = chainmonitor::ChainMonitor<
    InMemorySigner,
    Arc<UtxoStandardCoin>,
    Arc<ElectrumClient>,
    Arc<ElectrumClient>,
    Arc<LogState>,
    Arc<FilesystemPersister>,
>;

type ChannelManager = channelmanager::ChannelManager<
    InMemorySigner,
    Arc<ChainMonitor>,
    Arc<ElectrumClient>,
    Arc<KeysManager>,
    Arc<ElectrumClient>,
    Arc<LogState>,
>;

type PeerManager = SimpleArcPeerManager<
    SocketDescriptor,
    ChainMonitor,
    ElectrumClient,
    ElectrumClient,
    dyn Access + Send + Sync,
    LogState,
>;

type SimpleChannelManager = SimpleArcChannelManager<ChainMonitor, ElectrumClient, ElectrumClient, LogState>;

#[derive(Default)]
pub struct LightningContext {
    /// The lightning nodes peer managers that take care of connecting to peers, etc..
    pub peer_managers: AsyncMutex<HashMap<String, Arc<PeerManager>>>,
    /// The lightning nodes background processors that take care of tasks that need to happen periodically
    pub background_processors: AsyncMutex<HashMap<String, BackgroundProcessor>>,
    /// The lightning nodes channel managers which keep track of the number of open channels and sends messages to the appropriate
    /// channel, also tracks HTLC preimages and forwards onion packets appropriately.
    pub channel_managers: AsyncMutex<HashMap<String, Arc<ChannelManager>>>,
}

impl LightningContext {
    /// Obtains a reference to this crate context, creating it if necessary.
    pub fn from_ctx(ctx: &MmArc) -> Result<Arc<LightningContext>, String> {
        Ok(try_s!(from_ctx(&ctx.lightning_ctx, move || {
            Ok(LightningContext::default())
        })))
    }
}

#[derive(Debug)]
pub struct LightningConf {
    /// RPC client (Using only electrum for now as part of the PoC)
    pub rpc_client: ElectrumClient,
    // Mainnet/Testnet/Signet/RegTest
    pub network: Network,
    // The listening port for the p2p LN node
    pub listening_port: u16,
    /// The set (possibly empty) of socket addresses on which this node accepts incoming connections.
    /// If the user wishes to preserve privacy, addresses should likely contain only Tor Onion addresses.
    pub listening_addr: IpAddr,
    // Printable human-readable string to describe this node to other users.
    pub node_name: [u8; 32],
    // Node's RGB color. This is used for showing the node in a network graph with the desired color.
    pub node_color: [u8; 3],
}

impl LightningConf {
    pub fn new(
        rpc_client: ElectrumClient,
        network: Network,
        listening_addr: IpAddr,
        listening_port: u16,
        node_name: String,
        node_color: [u8; 3],
    ) -> Self {
        LightningConf {
            rpc_client,
            network,
            listening_port,
            listening_addr,
            node_name: node_name.as_bytes().try_into().expect("Node name has incorrect length"),
            node_color,
        }
    }
}

pub fn network_from_string(network: String) -> EnableLightningResult<Network> {
    network
        .as_str()
        .parse::<Network>()
        .map_to_mm(|e| EnableLightningError::InvalidRequest(e.to_string()))
}

// TODO: add TOR address option
fn netaddress_from_ipaddr(addr: IpAddr, port: u16) -> Vec<NetAddress> {
    if addr == Ipv4Addr::new(0, 0, 0, 0) || addr == Ipv4Addr::new(127, 0, 0, 1) {
        return Vec::new();
    }
    let mut addresses = Vec::new();
    let address = match addr {
        IpAddr::V4(addr) => NetAddress::IPv4 {
            addr: u32::from(addr).to_be_bytes(),
            port,
        },
        IpAddr::V6(addr) => NetAddress::IPv6 {
            addr: u128::from(addr).to_be_bytes(),
            port,
        },
    };
    addresses.push(address);
    addresses
}

fn my_ln_data_dir(ctx: &MmArc) -> PathBuf { ctx.dbdir().join("LIGHTNING") }

pub fn nodes_data_path(ctx: &MmArc) -> PathBuf { my_ln_data_dir(ctx).join("channel_nodes_data") }

// TODO: Implement all the cases
async fn handle_ln_events(
    event: &Event,
    channel_manager: Arc<ChannelManager>,
    network: Network,
    coin: Arc<UtxoStandardCoin>,
) {
    // TODO: remove clone
    match event.clone() {
        Event::FundingGenerationReady {
            temporary_channel_id,
            channel_value_satoshis,
            output_script,
            user_channel_id,
        } => {
            let funding_tx = match generate_funding_transaction(
                temporary_channel_id,
                channel_value_satoshis,
                output_script.clone(),
                user_channel_id,
                network,
                coin.clone(),
            )
            .await
            {
                Ok(tx) => tx,
                Err(e) => {
                    log::error!(
                        "Error generating funding transaction for temporary channel id {:?}: {}",
                        temporary_channel_id,
                        e.to_string()
                    );
                    // TODO: When the task management feature is merged maybe I can return a failed status with the transaction hex to be broadcasted when
                    // the reason for failure is resolved (e.g. not enough balance due to other withdraws before broadcasting the funding transaction,
                    // the transaction can be broadcasted again when the balance is enough)
                    return;
                },
            };
            // Give the funding transaction back to LDK for opening the channel.
            match channel_manager.funding_transaction_generated(&temporary_channel_id, funding_tx.clone()) {
                Ok(_) => {
                    let txid = funding_tx.txid();
                    coin.register_tx(&txid, &output_script);
                    let output_to_be_registered = TxOut {
                        value: channel_value_satoshis,
                        script_pubkey: output_script.clone(),
                    };
                    let output_index = funding_tx
                        .output
                        .iter()
                        .position(|tx_out| tx_out == &output_to_be_registered)
                        .expect("Output to register should be found in the transaction output");
                    coin.register_output(WatchedOutput {
                        block_hash: None,
                        outpoint: OutPoint {
                            txid,
                            index: output_index as u16,
                        },
                        script_pubkey: output_script,
                    });
                },
                // TODO: More verbose error for mm2 (Check LDK APIError and provide better error description for the logs)
                Err(e) => log::error!("{:?}", e),
            }
        },
        Event::PaymentReceived { .. } => (),
        Event::PaymentSent { .. } => (),
        Event::PaymentPathFailed { .. } => (),
        Event::PendingHTLCsForwardable { .. } => (),
        Event::SpendableOutputs { .. } => (),
        Event::PaymentForwarded { .. } => (),
        Event::ChannelClosed { .. } => (),
    }
}

pub async fn start_lightning(ctx: &MmArc, coin: UtxoStandardCoin, conf: LightningConf) -> EnableLightningResult<()> {
    let lightning_ctx = LightningContext::from_ctx(&ctx).unwrap();
    let ticker = coin.ticker().to_string();

    {
        let background_processor = lightning_ctx.background_processors.lock().await;
        if background_processor.contains_key(&ticker) {
            return MmError::err(EnableLightningError::AlreadyRunning(ticker.clone()));
        }
    }

    // Initialize the FeeEstimator. rpc_client implements the FeeEstimator trait, so it'll act as our fee estimator.
    let fee_estimator = Arc::new(conf.rpc_client.clone());

    // Initialize the Logger
    let logger = ctx.log.clone();

    // Initialize the BroadcasterInterface. rpc_client implements the BroadcasterInterface trait, so it'll act as our transaction
    // broadcaster.
    let broadcaster = Arc::new(conf.rpc_client.clone());

    // Initialize Persist
    let ln_data_dir = my_ln_data_dir(ctx)
        .as_path()
        .to_str()
        .ok_or("Data dir is a non-UTF-8 string")
        .map_to_mm(|e| EnableLightningError::InvalidPath(e.into()))?
        .to_string();
    let persister = Arc::new(FilesystemPersister::new(ln_data_dir.clone()));

    // Initialize the Filter. rpc_client implements the Filter trait, so it'll act as our filter.
    let filter = Some(Arc::new(coin.clone()));

    // Initialize the ChainMonitor
    let chain_monitor: Arc<ChainMonitor> = Arc::new(chainmonitor::ChainMonitor::new(
        filter.clone(),
        broadcaster.clone(),
        logger.0.clone(),
        fee_estimator.clone(),
        persister.clone(),
    ));

    let seed: [u8; 32] = ctx.secp256k1_key_pair().private().secret.into();

    // Lock context and wait 1ms before dropping to insure randomness for different coins
    // when starting multiple lightning nodes for different coins at the same time
    let background_processor = lightning_ctx.background_processors.lock().await;
    // The current time is used to derive random numbers from the seed where required, to ensure all random generation is unique across restarts.
    let cur = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_to_mm(|e| EnableLightningError::SystemTimeError(e.to_string()))?;

    // Initialize the KeysManager
    let keys_manager = Arc::new(KeysManager::new(&seed, cur.as_secs(), cur.subsec_nanos()));
    Timer::sleep_ms(1).await;
    drop(background_processor);

    // Read ChannelMonitor state from disk, important for lightning node is restarting and has at least 1 channel
    let mut channelmonitors = persister
        .read_channelmonitors(keys_manager.clone())
        .map_to_mm(|e| EnableLightningError::IOError(e.to_string()))?;

    // This is used for Electrum only to prepare for chain synchronization
    if let Some(ref filter) = filter {
        for (_, chan_mon) in channelmonitors.iter() {
            chan_mon.load_outputs_to_watch(filter);
        }
    }

    let best_block = conf
        .rpc_client
        .get_best_block()
        .compat()
        .await
        .mm_err(|e| EnableLightningError::RpcError(e.to_string()))?;

    let mut user_config = UserConfig::default();
    // When set to false an incoming channel doesn't have to match our announced channel preference which allows public channels
    // TODO: Add user config to LightningConf maybe get it from coin config / also add to lightning context
    user_config
        .peer_channel_config_limits
        .force_announced_channel_preference = false;

    let mut restarting_node = true;
    let network = conf.network;
    // TODO: use channel_manager_blockhash to know where to start looking for outputs from
    let (_channel_manager_blockhash, channel_manager) = {
        if let Ok(mut f) = File::open(format!("{}/manager", ln_data_dir.clone())) {
            let mut channel_monitor_mut_references = Vec::new();
            for (_, channel_monitor) in channelmonitors.iter_mut() {
                channel_monitor_mut_references.push(channel_monitor);
            }
            // Read ChannelManager data from the file
            let read_args = ChannelManagerReadArgs::new(
                keys_manager.clone(),
                fee_estimator.clone(),
                chain_monitor.clone(),
                broadcaster.clone(),
                logger.0.clone(),
                user_config,
                channel_monitor_mut_references,
            );
            <(BlockHash, SimpleChannelManager)>::read(&mut f, read_args)
                .map_to_mm(|e| EnableLightningError::IOError(e.to_string()))?
        } else {
            // Initialize the ChannelManager to starting a new node without history
            restarting_node = false;
            let best_block_hash = sha256d::Hash::from_slice(&best_block.hash.0)
                .map_to_mm(|e| EnableLightningError::HashError(e.to_string()))?;
            let chain_params = ChainParameters {
                network,
                best_block: BestBlock::new(BlockHash::from_hash(best_block_hash), best_block.height as u32),
            };
            let new_channel_manager = channelmanager::ChannelManager::new(
                fee_estimator.clone(),
                chain_monitor.clone(),
                broadcaster.clone(),
                logger.0.clone(),
                keys_manager.clone(),
                user_config,
                chain_params,
            );
            (BlockHash::from_hash(best_block_hash), new_channel_manager)
        }
    };

    let channel_manager: Arc<ChannelManager> = Arc::new(channel_manager);

    // Sync ChannelMonitors and ChannelManager to chain tip if the node is restarting and has open channels
    if restarting_node {
        process_txs_confirmations(
            filter.clone().unwrap().clone(),
            conf.rpc_client.clone(),
            chain_monitor.clone(),
            channel_manager.clone(),
            best_block.height,
        )
        .await;
        let best_header = get_best_header(conf.rpc_client.clone()).await?;
        update_best_block(chain_monitor.clone(), channel_manager.clone(), best_header).await;
    }

    // Give ChannelMonitors to ChainMonitor
    for (_, channel_monitor) in channelmonitors.drain(..) {
        let funding_outpoint = channel_monitor.get_funding_txo().0;
        chain_monitor
            .watch_channel(funding_outpoint, channel_monitor)
            .map_to_mm(|e| EnableLightningError::IOError(format!("{:?}", e)))?;
    }

    // Initialize the NetGraphMsgHandler. This is used for providing routes to send payments over
    let genesis = genesis_block(network).header.block_hash();
    let router = Arc::new(NetGraphMsgHandler::new(
        NetworkGraph::new(genesis),
        None::<Arc<dyn Access + Send + Sync>>,
        logger.0.clone(),
    ));

    // Initialize the PeerManager
    // ephemeral_random_data is used to derive per-connection ephemeral keys
    let mut ephemeral_bytes = [0; 32];
    rand::thread_rng().fill_bytes(&mut ephemeral_bytes);
    let lightning_msg_handler = MessageHandler {
        chan_handler: channel_manager.clone(),
        route_handler: router.clone(),
    };
    // IgnoringMessageHandler is used as custom message types (experimental and application-specific messages) is not needed
    let peer_manager: Arc<PeerManager> = Arc::new(PeerManager::new(
        lightning_msg_handler,
        keys_manager.get_node_secret(),
        &ephemeral_bytes,
        logger.0.clone(),
        Arc::new(IgnoringMessageHandler {}),
    ));

    // Initialize p2p networking
    let listener = TcpListener::bind(format!("{}:{}", conf.listening_addr, conf.listening_port))
        .await
        .map_to_mm(|e| EnableLightningError::IOError(e.to_string()))?;
    spawn(ln_p2p_loop(ctx.clone(), peer_manager.clone(), listener));

    // Update best block whenever there's a new chain tip or a block has been newly disconnected
    spawn(ln_best_block_update_loop(
        ctx.clone(),
        filter.clone().unwrap(),
        chain_monitor.clone(),
        channel_manager.clone(),
        conf.rpc_client.clone(),
        best_block,
    ));

    // Handle LN Events
    // TODO: Implement EventHandler trait instead of this
    let handle = tokio::runtime::Handle::current();
    let channel_manager_event_listener = channel_manager.clone();
    let event_handler = move |event: &Event| {
        handle.block_on(handle_ln_events(
            event,
            channel_manager_event_listener.clone(),
            network,
            filter.clone().unwrap(),
        ))
    };

    // Persist ChannelManager
    // Note: if the ChannelManager is not persisted properly to disk, there is risk of channels force closing the next time LN starts up
    let persist_channel_manager_callback =
        move |node: &SimpleChannelManager| FilesystemPersister::persist_manager(ln_data_dir.clone(), &*node);

    // Start Background Processing. Runs tasks periodically in the background to keep LN node operational
    let background_processor = BackgroundProcessor::start(
        persist_channel_manager_callback,
        event_handler,
        chain_monitor,
        channel_manager.clone(),
        Some(router),
        peer_manager.clone(),
        logger.0,
    );

    {
        let mut background_processors = lightning_ctx.background_processors.lock().await;
        background_processors.insert(ticker.clone(), background_processor);
    }

    // If node is restarting read other nodes data from disk and reconnect to channel nodes/peers if possible.
    if restarting_node {
        let mut nodes_data = read_nodes_data_from_file(&nodes_data_path(ctx))?;
        for (pubkey, node_addr) in nodes_data.drain() {
            for chan_info in channel_manager.list_channels() {
                if pubkey == chan_info.counterparty.node_id {
                    spawn(connect_to_node_loop(
                        ctx.clone(),
                        pubkey,
                        node_addr,
                        peer_manager.clone(),
                    ));
                }
            }
        }
    }

    {
        let mut peer_managers = lightning_ctx.peer_managers.lock().await;
        peer_managers.insert(ticker.clone(), peer_manager);
    }

    // Broadcast Node Announcement
    spawn(ln_node_announcement_loop(
        ctx.clone(),
        channel_manager.clone(),
        conf.node_name,
        conf.node_color,
        conf.listening_addr,
        conf.listening_port,
    ));

    {
        let mut channel_managers = lightning_ctx.channel_managers.lock().await;
        channel_managers.insert(ticker, channel_manager);
    }

    Ok(())
}

async fn ln_p2p_loop(ctx: MmArc, peer_manager: Arc<PeerManager>, listener: TcpListener) {
    loop {
        if ctx.is_stopping() {
            break;
        }
        let peer_mgr = peer_manager.clone();
        let tcp_stream = match listener.accept().await {
            Ok((stream, addr)) => {
                log::debug!("New incoming lightning connection from node address: {}", addr);
                stream
            },
            Err(e) => {
                log::error!("Error on accepting lightning connection: {}", e);
                continue;
            },
        };
        if let Ok(stream) = tcp_stream.into_std() {
            spawn(async move {
                lightning_net_tokio::setup_inbound(peer_mgr.clone(), stream).await;
            })
        };
    }
}

async fn process_txs_confirmations(
    filter: Arc<UtxoStandardCoin>,
    client: ElectrumClient,
    chain_monitor: Arc<ChainMonitor>,
    channel_manager: Arc<ChannelManager>,
    current_height: u64,
) {
    // Retrieve transaction IDs to check the chain for un-confirmations
    // TODO: The following code needs to be run with every new block also
    let channel_manager_relevant_txids = channel_manager.get_relevant_txids();
    let chain_monitor_relevant_txids = chain_monitor.get_relevant_txids();

    for txid in channel_manager_relevant_txids {
        if filter
            .as_ref()
            .as_ref()
            .rpc_client
            .get_transaction_bytes(txid.as_hash().into_inner().into())
            .compat()
            .await
            .is_ok()
        {
            channel_manager.transaction_unconfirmed(&txid);
        }
    }

    for txid in chain_monitor_relevant_txids {
        if filter
            .as_ref()
            .as_ref()
            .rpc_client
            .get_transaction_bytes(txid.as_hash().into_inner().into())
            .compat()
            .await
            .is_ok()
        {
            chain_monitor.transaction_unconfirmed(&txid);
        }
    }

    let mut ln_registry = filter.as_ref().as_ref().ln_registry.lock().await;
    // TODO: Get the results in a vec then call transactions_confirmed for each header tx_list
    // also order results to call transactions_confirmed by headers/other required order
    // TODO: loop through ln_registry.registered_outputs also
    for (txid, scripts) in ln_registry.registered_txs.clone() {
        match filter
            .as_ref()
            .as_ref()
            .rpc_client
            .get_verbose_transaction(&H256::from(txid.as_hash().into_inner()).reversed().into())
            .compat()
            .await
        {
            Ok(tx) => {
                // TODO: find a better way to get the block height as there might be a new mined block after passing current_height and before calling get_verbose_transaction
                let tx_block_height = current_height - tx.confirmations as u64 + 1;
                match client.blockchain_block_header(tx_block_height).compat().await {
                    Ok(h) => {
                        let header = deserialize(&h).expect("Can't deserialize block header");
                        let transaction: Transaction =
                            deserialize(&tx.hex.clone().into_vec()).expect("Can't deserialize transaction");
                        let mut tx_data = Vec::new();
                        for (index, vout) in transaction.output.iter().enumerate() {
                            if scripts.contains(&vout.script_pubkey) {
                                tx_data.push((index, &transaction));
                            }
                        }
                        // TODO: double check that tx_data needs the index of the output script not of the transaction in the block
                        channel_manager.transactions_confirmed(&header, &tx_data, tx_block_height as u32);
                        chain_monitor.transactions_confirmed(&header, &tx_data, tx_block_height as u32);
                        ln_registry.registered_txs.remove(&txid);
                    },
                    Err(_) => continue,
                }
            },
            Err(e) => {
                log::error!("Error getting transaction {} from chain: {}", txid, e);
                continue;
            },
        };
    }

    for output in ln_registry.registered_outputs.clone() {
        let result = ln_rpc::find_watched_output_spend_with_header(&filter.as_ref(), output.0.clone()).await;
        if let Some((header, index, tx, height)) = result {
            channel_manager.transactions_confirmed(&header, &[(index, &tx)], height as u32);
            chain_monitor.transactions_confirmed(&header, &[(index, &tx)], height as u32);
            ln_registry.registered_outputs.remove(&output);
        }
    }
}

async fn get_best_header(best_header_listener: ElectrumClient) -> EnableLightningResult<ElectrumBlockHeader> {
    best_header_listener
        .blockchain_headers_subscribe()
        .compat()
        .await
        .map_to_mm(|e| EnableLightningError::RpcError(e.to_string()))
}

async fn update_best_block(
    chain_monitor: Arc<ChainMonitor>,
    channel_manager: Arc<ChannelManager>,
    best_header: ElectrumBlockHeader,
) {
    {
        let (new_best_header, new_best_height) = match best_header {
            ElectrumBlockHeader::V12(h) => {
                let nonce = match h.nonce {
                    ElectrumNonce::Number(n) => n as u32,
                    ElectrumNonce::Hash(_) => {
                        return;
                    },
                };
                let prev_blockhash = match sha256d::Hash::from_slice(&h.prev_block_hash.0) {
                    Ok(h) => h,
                    Err(e) => {
                        log::error!("Error while parsing previous block hash for lightning node: {}", e);
                        return;
                    },
                };
                let merkle_root = match sha256d::Hash::from_slice(&h.merkle_root.0) {
                    Ok(h) => h,
                    Err(e) => {
                        log::error!("Error while parsing merkle root for lightning node: {}", e);
                        return;
                    },
                };
                (
                    BlockHeader {
                        version: h.version as i32,
                        prev_blockhash: BlockHash::from_hash(prev_blockhash),
                        merkle_root: TxMerkleNode::from_hash(merkle_root),
                        time: h.timestamp as u32,
                        bits: h.bits as u32,
                        nonce,
                    },
                    h.block_height as u32,
                )
            },
            ElectrumBlockHeader::V14(h) => (
                deserialize(&h.hex.into_vec()).expect("Can't deserialize block header"),
                h.height as u32,
            ),
        };
        channel_manager.best_block_updated(&new_best_header, new_best_height);
        chain_monitor.best_block_updated(&new_best_header, new_best_height);
    }
}

async fn ln_best_block_update_loop(
    ctx: MmArc,
    filter: Arc<UtxoStandardCoin>,
    chain_monitor: Arc<ChainMonitor>,
    channel_manager: Arc<ChannelManager>,
    best_header_listener: ElectrumClient,
    best_block: RpcBestBlock,
) {
    let mut current_best_block = best_block;
    loop {
        if ctx.is_stopping() {
            break;
        }
        let best_header = match get_best_header(best_header_listener.clone()).await {
            Ok(h) => h,
            Err(e) => {
                log::error!("Error while requesting best header for lightning node: {}", e);
                Timer::sleep(CHECK_FOR_NEW_BEST_BLOCK_INTERVAL as f64).await;
                continue;
            },
        };
        if current_best_block != best_header.clone().into() {
            process_txs_confirmations(
                filter.clone(),
                best_header_listener.clone(),
                chain_monitor.clone(),
                channel_manager.clone(),
                best_header.block_height(),
            )
            .await;
            current_best_block = best_header.clone().into();
            update_best_block(chain_monitor.clone(), channel_manager.clone(), best_header).await;
        }
        Timer::sleep(CHECK_FOR_NEW_BEST_BLOCK_INTERVAL as f64).await;
    }
}

async fn ln_node_announcement_loop(
    ctx: MmArc,
    channel_manager: Arc<ChannelManager>,
    node_name: [u8; 32],
    node_color: [u8; 3],
    addr: IpAddr,
    port: u16,
) {
    let addresses = netaddress_from_ipaddr(addr, port);
    loop {
        if ctx.is_stopping() {
            break;
        }

        let addresses_to_announce = if addresses.is_empty() {
            // Right now if the node is behind NAT the external ip is fetched on every loop
            // If the node does not announce a public IP, it will not be displayed on the network graph,
            // and other nodes will not be able to open a channel with it. But it can open channels with other nodes.
            // TODO: Fetch external ip on reconnection only
            match fetch_external_ip().await {
                Ok(ip) => netaddress_from_ipaddr(ip, port),
                Err(e) => {
                    log::error!("Error while fetching external ip for node announcement: {}", e);
                    Timer::sleep(BROADCAST_NODE_ANNOUNCEMENT_INTERVAL as f64).await;
                    continue;
                },
            }
        } else {
            addresses.clone()
        };

        channel_manager.broadcast_node_announcement(node_color, node_name, addresses_to_announce);

        Timer::sleep(BROADCAST_NODE_ANNOUNCEMENT_INTERVAL as f64).await;
    }
}

fn pubkey_and_addr_from_str(pubkey_str: &str, addr_str: &str) -> ConnectToNodeResult<(PublicKey, SocketAddr)> {
    // TODO: support connection to onion addresses
    let addr = addr_str
        .to_socket_addrs()
        .map(|mut r| r.next())
        .map_to_mm(|e| ConnectToNodeError::ParseError(e.to_string()))?
        .ok_or_else(|| ConnectToNodeError::ParseError(format!("Couldn't parse {} into a socket address", addr_str)))?;

    let pubkey = PublicKey::from_str(pubkey_str).map_to_mm(|e| ConnectToNodeError::ParseError(e.to_string()))?;

    Ok((pubkey, addr))
}

pub fn parse_node_info(node_pubkey_and_ip_addr: String) -> ConnectToNodeResult<(PublicKey, SocketAddr)> {
    let mut pubkey_and_addr = node_pubkey_and_ip_addr.split('@');

    let pubkey = pubkey_and_addr.next().ok_or_else(|| {
        ConnectToNodeError::ParseError(format!(
            "Incorrect node id format for {}. The format should be `pubkey@host:port`",
            node_pubkey_and_ip_addr
        ))
    })?;

    let node_addr_str = pubkey_and_addr.next().ok_or_else(|| {
        ConnectToNodeError::ParseError(format!(
            "Incorrect node id format for {}. The format should be `pubkey@host:port`",
            node_pubkey_and_ip_addr
        ))
    })?;

    let (pubkey, node_addr) = pubkey_and_addr_from_str(pubkey, node_addr_str)?;
    Ok((pubkey, node_addr))
}

fn read_nodes_data_from_file(path: &Path) -> EnableLightningResult<HashMap<PublicKey, SocketAddr>> {
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let mut nodes_data = HashMap::new();
    let file = File::open(path).map_to_mm(|e| EnableLightningError::IOError(e.to_string()))?;
    let reader = BufReader::new(file);
    for line in reader.lines() {
        let line = line.map_to_mm(|e| EnableLightningError::IOError(e.to_string()))?;
        let (pubkey, socket_addr) = parse_node_info(line)?;
        nodes_data.insert(pubkey, socket_addr);
    }
    Ok(nodes_data)
}

pub fn save_node_data_to_file(path: &Path, node_info: &str) -> ConnectToNodeResult<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_to_mm(|e| ConnectToNodeError::IOError(e.to_string()))?;
    file.write_all(format!("{}\n", node_info).as_bytes())
        .map_to_mm(|e| ConnectToNodeError::IOError(e.to_string()))
}

#[derive(Display)]
pub enum ConnectToNodeRes {
    #[display(fmt = "Already connected to node: {}@{}", _0, _1)]
    AlreadyConnected(String, String),
    #[display(fmt = "Connected successfully to node : {}@{}", _0, _1)]
    ConnectedSuccessfully(String, String),
}

pub async fn connect_to_node(
    pubkey: PublicKey,
    node_addr: SocketAddr,
    peer_manager: Arc<PeerManager>,
) -> ConnectToNodeResult<ConnectToNodeRes> {
    for node_pubkey in peer_manager.get_peer_node_ids() {
        if node_pubkey == pubkey {
            return Ok(ConnectToNodeRes::AlreadyConnected(
                node_pubkey.to_string(),
                node_addr.to_string(),
            ));
        }
    }

    match lightning_net_tokio::connect_outbound(Arc::clone(&peer_manager), pubkey, node_addr).await {
        Some(connection_closed_future) => {
            let mut connection_closed_future = Box::pin(connection_closed_future);
            loop {
                // Make sure the connection is still established.
                match futures::poll!(&mut connection_closed_future) {
                    std::task::Poll::Ready(_) => {
                        return MmError::err(ConnectToNodeError::ConnectionError(format!(
                            "Node {} disconnected before finishing the handshake",
                            pubkey
                        )));
                    },
                    std::task::Poll::Pending => {},
                }
                // Wait for the handshake to complete.
                match peer_manager.get_peer_node_ids().iter().find(|id| **id == pubkey) {
                    Some(_) => break,
                    None => Timer::sleep_ms(10).await,
                }
            }
        },
        None => {
            return MmError::err(ConnectToNodeError::ConnectionError(format!(
                "Failed to connect to node: {}",
                pubkey
            )))
        },
    }

    Ok(ConnectToNodeRes::ConnectedSuccessfully(
        pubkey.to_string(),
        node_addr.to_string(),
    ))
}

async fn connect_to_node_loop(ctx: MmArc, pubkey: PublicKey, node_addr: SocketAddr, peer_manager: Arc<PeerManager>) {
    for node_pubkey in peer_manager.get_peer_node_ids() {
        if node_pubkey == pubkey {
            log::info!("Already connected to node: {}", node_pubkey);
            return;
        }
    }

    loop {
        if ctx.is_stopping() {
            break;
        }

        match connect_to_node(pubkey, node_addr, peer_manager.clone()).await {
            Ok(res) => {
                log::info!("{}", res.to_string());
                break;
            },
            Err(e) => log::error!("{}", e.to_string()),
        }

        Timer::sleep(TRY_RECONNECTING_TO_NODE_INTERVAL as f64).await;
    }
}

pub fn open_ln_channel(
    node_pubkey: PublicKey,
    amount_in_sat: u64,
    events_id: u64,
    announce_channel: bool,
    channel_manager: Arc<ChannelManager>,
) -> OpenChannelResult<()> {
    // TODO: get user_config from context when it's added to it
    let mut user_config = UserConfig::default();
    user_config
        .peer_channel_config_limits
        .force_announced_channel_preference = false;
    user_config.channel_options.announced_channel = announce_channel;

    // TODO: push_msat parameter
    // TODO: check balance before opening channel and also prevent withdraws until transaction is broadcasted
    match channel_manager.create_channel(node_pubkey, amount_in_sat, 0, events_id, Some(user_config)) {
        Ok(_) => {
            log::info!("Initiated opening a channel with node {}", node_pubkey);
            Ok(())
        },
        Err(e) => {
            return MmError::err(OpenChannelError::FailureToOpenChannel(
                node_pubkey.to_string(),
                format!("{:?}", e),
            ));
        },
    }
}

// Generates the raw funding transaction with one output equal to the channel value.
async fn generate_funding_transaction(
    _temporary_channel_id: [u8; 32],
    channel_value_satoshis: u64,
    output_script: Script,
    _user_channel_id: u64,
    _network: Network,
    coin: Arc<UtxoStandardCoin>,
) -> Result<Transaction, WithdrawError> {
    let utxo_coin = coin.as_ref().as_ref();
    let addr = SegwitAddress::new(
        &AddressHashEnum::WitnessScriptHash(output_script[2..].into()),
        utxo_coin
            .conf
            .bech32_hrp
            .clone()
            .expect("Coin should have a bech32_hrp"),
    )
    .to_string();
    // TODO: find a way to use max in the withdraw request
    // TODO: add WithdrawFee to the open_channel request to use with new_with_amount (will need to be passed in the context)
    let amount = big_decimal_from_sat(channel_value_satoshis as i64, utxo_coin.decimals);
    let withdraw_req = WithdrawRequest::new_with_amount(utxo_coin.conf.ticker.clone(), addr, amount);
    let transaction_details = match withdraw(coin.as_ref().clone(), withdraw_req).await {
        Ok(tx) => tx,
        Err(e) => return Err(e.into_inner()),
    };
    let final_tx: Transaction =
        deserialize(&transaction_details.tx_hex.into_vec()).expect("Can't deserialize transaction");

    Ok(final_tx)
}
