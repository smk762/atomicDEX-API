use crate::utxo::rpc_clients::UtxoRpcError;
use crate::utxo::GenerateTxError;
use crate::{BalanceError, CoinFindError, NumConversError};
use common::mm_error::prelude::*;
use common::HttpStatusCode;
use derive_more::Display;
use http::StatusCode;

pub type EnableLightningResult<T> = Result<T, MmError<EnableLightningError>>;
pub type ConnectToNodeResult<T> = Result<T, MmError<ConnectToNodeError>>;
pub type OpenChannelResult<T> = Result<T, MmError<OpenChannelError>>;

#[derive(Debug, Deserialize, Display, Serialize, SerializeErrorType)]
#[serde(tag = "error_type", content = "error_data")]
pub enum EnableLightningError {
    #[display(fmt = "Invalid request: {}", _0)]
    InvalidRequest(String),
    #[display(fmt = "Invalid address: {}", _0)]
    InvalidAddress(String),
    #[display(fmt = "Invalid path: {}", _0)]
    InvalidPath(String),
    #[display(fmt = "Lightning node already running for coin: {}", _0)]
    AlreadyRunning(String),
    #[display(fmt = "{} is only supported in {} mode", _0, _1)]
    UnsupportedMode(String, String),
    #[display(fmt = "Lightning network is not supported for {}: {}", _0, _1)]
    UnsupportedCoin(String, String),
    #[display(fmt = "No such coin {}", _0)]
    NoSuchCoin(String),
    #[display(fmt = "System time error {}", _0)]
    SystemTimeError(String),
    #[display(fmt = "I/O error {}", _0)]
    IOError(String),
    #[display(fmt = "Hash error {}", _0)]
    HashError(String),
    #[display(fmt = "RPC error {}", _0)]
    RpcError(String),
    ConnectToNodeError(String),
}

impl HttpStatusCode for EnableLightningError {
    fn status_code(&self) -> StatusCode {
        match self {
            EnableLightningError::InvalidRequest(_)
            | EnableLightningError::RpcError(_)
            | EnableLightningError::UnsupportedCoin(_, _) => StatusCode::BAD_REQUEST,
            EnableLightningError::AlreadyRunning(_) | EnableLightningError::UnsupportedMode(_, _) => {
                StatusCode::METHOD_NOT_ALLOWED
            },
            EnableLightningError::InvalidAddress(_)
            | EnableLightningError::InvalidPath(_)
            | EnableLightningError::SystemTimeError(_)
            | EnableLightningError::IOError(_)
            | EnableLightningError::HashError(_)
            | EnableLightningError::ConnectToNodeError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            EnableLightningError::NoSuchCoin(_) => StatusCode::PRECONDITION_REQUIRED,
        }
    }
}

impl From<CoinFindError> for EnableLightningError {
    fn from(e: CoinFindError) -> Self {
        match e {
            CoinFindError::NoSuchCoin { coin } => EnableLightningError::NoSuchCoin(coin),
        }
    }
}

#[derive(Debug, Deserialize, Display, Serialize, SerializeErrorType)]
#[serde(tag = "error_type", content = "error_data")]
pub enum ConnectToNodeError {
    #[display(fmt = "{} is only supported in {} mode", _0, _1)]
    UnsupportedMode(String, String),
    #[display(fmt = "You have to run 'enable_lightning' for {} first", _0)]
    LightningNotEnabled(String),
    #[display(fmt = "Parse error: {}", _0)]
    ParseError(String),
    #[display(fmt = "Error connecting to node: {}", _0)]
    ConnectionError(String),
    #[display(fmt = "I/O error {}", _0)]
    IOError(String),
}

impl HttpStatusCode for ConnectToNodeError {
    fn status_code(&self) -> StatusCode {
        match self {
            ConnectToNodeError::UnsupportedMode(_, _) => StatusCode::METHOD_NOT_ALLOWED,
            ConnectToNodeError::ParseError(_) | ConnectToNodeError::IOError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            ConnectToNodeError::ConnectionError(_) => StatusCode::REQUEST_TIMEOUT,
            ConnectToNodeError::LightningNotEnabled(_) => StatusCode::PRECONDITION_REQUIRED,
        }
    }
}

impl From<ConnectToNodeError> for EnableLightningError {
    fn from(err: ConnectToNodeError) -> EnableLightningError {
        EnableLightningError::ConnectToNodeError(err.to_string())
    }
}

#[derive(Debug, Deserialize, Display, Serialize, SerializeErrorType)]
#[serde(tag = "error_type", content = "error_data")]
pub enum OpenChannelError {
    #[display(fmt = "{} is only supported in {} mode", _0, _1)]
    UnsupportedMode(String, String),
    #[display(fmt = "You have to run 'enable_lightning' for {} first", _0)]
    LightningNotEnabled(String),
    #[display(fmt = "Failure to open channel with node {}: {}", _0, _1)]
    FailureToOpenChannel(String, String),
    ConnectToNodeError(String),
    #[display(fmt = "No such coin {}", _0)]
    NoSuchCoin(String),
    #[display(fmt = "Lightning network is not supported for {}: {}", _0, _1)]
    UnsupportedCoin(String, String),
    #[display(fmt = "Balance Error {}", _0)]
    BalanceError(String),
    #[display(fmt = "Generate Tx Error {}", _0)]
    GenerateTxErr(String),
    #[display(fmt = "RPC error {}", _0)]
    RpcError(String),
    #[display(fmt = "Internal error: {}", _0)]
    InternalError(String),
}

impl HttpStatusCode for OpenChannelError {
    fn status_code(&self) -> StatusCode {
        match self {
            OpenChannelError::UnsupportedCoin(_, _) | OpenChannelError::RpcError(_) => StatusCode::BAD_REQUEST,
            OpenChannelError::UnsupportedMode(_, _) => StatusCode::METHOD_NOT_ALLOWED,
            OpenChannelError::FailureToOpenChannel(_, _)
            | OpenChannelError::ConnectToNodeError(_)
            | OpenChannelError::InternalError(_)
            | OpenChannelError::GenerateTxErr(_) => StatusCode::INTERNAL_SERVER_ERROR,
            OpenChannelError::LightningNotEnabled(_)
            | OpenChannelError::NoSuchCoin(_)
            | OpenChannelError::BalanceError(_) => StatusCode::PRECONDITION_REQUIRED,
        }
    }
}

impl From<ConnectToNodeError> for OpenChannelError {
    fn from(err: ConnectToNodeError) -> OpenChannelError { OpenChannelError::ConnectToNodeError(err.to_string()) }
}

impl From<CoinFindError> for OpenChannelError {
    fn from(e: CoinFindError) -> Self {
        match e {
            CoinFindError::NoSuchCoin { coin } => OpenChannelError::NoSuchCoin(coin),
        }
    }
}

impl From<BalanceError> for OpenChannelError {
    fn from(e: BalanceError) -> Self { OpenChannelError::BalanceError(e.to_string()) }
}

impl From<NumConversError> for OpenChannelError {
    fn from(e: NumConversError) -> Self { OpenChannelError::InternalError(e.to_string()) }
}

impl From<GenerateTxError> for OpenChannelError {
    fn from(e: GenerateTxError) -> Self { OpenChannelError::GenerateTxErr(e.to_string()) }
}

impl From<UtxoRpcError> for OpenChannelError {
    fn from(e: UtxoRpcError) -> Self { OpenChannelError::RpcError(e.to_string()) }
}
