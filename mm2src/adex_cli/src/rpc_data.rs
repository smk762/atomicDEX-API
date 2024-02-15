//! Contains rpc data layer structures that are not ready to become a part of the mm2_rpc::data module
//!
//! *Note: it's expected that the following data types will be moved to mm2_rpc::data when mm2 is refactored to be able to handle them*
//!

use mm2_rpc::data::legacy::{ElectrumProtocol, GasStationPricePolicy, UtxoMergeParams};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "method", rename_all = "lowercase")]
pub(crate) enum ActivationRequest {
    Enable(EnableRequest),
    Electrum(ElectrumRequest),
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct EnableRequest {
    coin: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    urls: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    swap_contract_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fallback_swap_contract: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    gas_station_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    gas_station_decimals: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    gas_station_policy: Option<GasStationPricePolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mm2: Option<u8>,
    #[serde(default)]
    tx_history: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    required_confirmations: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    requires_notarization: Option<bool>,
    #[serde(default)]
    contract_supports_watchers: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct ElectrumRequest {
    coin: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(super) servers: Vec<Server>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mm2: Option<u8>,
    #[serde(default)]
    tx_history: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    required_confirmations: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    requires_notarization: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    swap_contract_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fallback_swap_contract: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    utxo_merge_params: Option<UtxoMergeParams>,
}

#[derive(Debug, Deserialize, Serialize)]
pub(super) struct Server {
    url: String,
    #[serde(default)]
    protocol: ElectrumProtocol,
    #[serde(default)]
    disable_cert_verification: bool,
}
