use crate::eip_1193_provider::Eip1193Provider;
use crate::metamask_error::{MetamaskError, MetamaskResult};
use futures::lock::{Mutex as AsyncMutex, MutexGuard as AsyncMutexGuard};
use itertools::Itertools;
use lazy_static::lazy_static;
use mm2_err_handle::prelude::*;
use serde::Serialize;
use serde_json::json;
use std::collections::HashMap;
use std::fmt;
use web3::helpers::CallFuture;
use web3::Transport;

const EIP712_DOMAIN: &str = "EIP712Domain";

lazy_static! {
    /// This mutex is used to limit the number of concurrent requests to one.
    /// It's required to avoid switching ETH chain ID during the request.
    static ref METAMASK_MUTEX: AsyncMutex<()> = AsyncMutex::new(());
}

pub fn detect_metamask_provider() -> MetamaskResult<Eip1193Provider> {
    Eip1193Provider::detect().or_mm_err(|| MetamaskError::EthProviderNotFound)
}

/// `MetamaskSession` is designed the way that there can be only one active session at the moment.
pub struct MetamaskSession<'a> {
    transport: &'a Eip1193Provider,
    _guard: AsyncMutexGuard<'a, ()>,
}

impl<'a> MetamaskSession<'a> {
    /// Locks the global `METAMASK_MUTEX` to prevent simultaneous requests.
    pub async fn lock(transport: &'a Eip1193Provider) -> MetamaskSession<'a> {
        MetamaskSession {
            transport,
            _guard: METAMASK_MUTEX.lock().await,
        }
    }

    /// Invokes the `eth_requestAccounts` method. We expect only one active account.
    /// https://docs.metamask.io/guide/rpc-api.html#eth-requestaccounts
    pub async fn eth_request_account(&self) -> MetamaskResult<EthAccount> {
        let accounts: Vec<String> = CallFuture::new(self.transport.execute("eth_requestAccounts", vec![])).await?;
        accounts
            .into_iter()
            .exactly_one()
            .map(|address| EthAccount { address })
            .map_to_mm(|_| MetamaskError::ExpectedOneEthAccount)
    }

    /// Invokes the `wallet_switchEthereumChain` method.
    /// https://docs.metamask.io/guide/rpc-api.html#wallet-switchethereumchain
    pub async fn wallet_switch_ethereum_chain(&self, chain_id: u64) -> Result<(), web3::Error> {
        let req = json!({
            "chainId": format!("0x{chain_id:x}"),
        });

        CallFuture::new(self.transport.execute("wallet_switchEthereumChain", vec![req])).await
    }

    // * user_address - Must match user's active address.
    /// * types - Defines the types of the domain and data you will be signing.
    /// * domain - Ensures that the signature will be unique across multiple DApps and across Blockchains.
    /// * sign_data - The message signing data content.
    /// * primary_type - name of the `sign_data` structured type.
    pub async fn sign_typed_data_v4<Domain, SignData>(
        &mut self,
        user_address: String,
        types: &[ObjectType],
        domain: Domain,
        sign_data: SignData,
        primary_type: String,
    ) -> MetamaskResult<String>
    where
        Domain: Serialize,
        SignData: Serialize,
    {
        let types = types
            .iter()
            .map(|object_type| (object_type.name.as_str(), object_type.properties.as_slice()))
            .collect();

        let req = SignTypedDataV4Request {
            types,
            domain,
            primary_type,
            message: sign_data,
        };

        let user_address = serde_json::to_value(user_address)
            .map_to_mm(|e| MetamaskError::ErrorSerializingArguments(e.to_string()))?;
        let req = serde_json::to_value(req).map_to_mm(|e| MetamaskError::ErrorSerializingArguments(e.to_string()))?;

        Ok(CallFuture::new(self.transport.execute("eth_signTypedDataV4", vec![user_address, req])).await?)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct EthAccount {
    pub address: String,
}

/// `ObjectType` is used to describes an object type accordingly to:
/// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-712.md#definition-of-typed-structured-data-%F0%9D%95%8A
///
/// # Example
///
/// Let's you need to describe the following types:
///
/// ```rust
/// struct Mail {
///   message: String,
///   from: Person,
///   to: Vec<Person>,
/// }
///
/// struct Person {
///   address: String,
/// }
/// ```
///
/// They can be described as follows:
///
/// ```rust
/// let mut mail_type = ObjectType::new("Mail");
/// mail_type.property("message", PropertyType::String);
/// mail_type.property("from", PropertyType::Custom("Person"));
/// mail_type.property_array("to", PropertyType::Custom("Person"));
///
/// let mut person_type = ObjectType::new("Person");
/// person_type.property("address", PropertyType::Address);
///
/// let types = vec![mail_type, person_type];
/// ```
pub struct ObjectType {
    name: String,
    properties: Vec<ObjectProperty>,
}

impl ObjectType {
    /// Creates an `ObjectType` with the `EIP712Domain` name
    /// (required to be set for a domain typed structure).
    pub fn domain() -> ObjectType {
        ObjectType {
            name: EIP712_DOMAIN.to_string(),
            properties: Vec::new(),
        }
    }

    /// Creates an `ObjectType` with a custom `name`.
    pub fn new(name: &str) -> ObjectType {
        ObjectType {
            name: name.to_string(),
            properties: Vec::new(),
        }
    }

    /// Describes a property.
    pub fn property(&mut self, property_name: &str, property_type: PropertyType) -> &mut ObjectType {
        let property = ObjectProperty {
            name: property_name.to_string(),
            r#type: property_type.to_string(),
        };
        self.properties.push(property);
        self
    }

    /// Describes an array property.
    pub fn property_array(&mut self, property_name: &str, property_type: PropertyType) -> &mut ObjectType {
        let property = ObjectProperty {
            name: property_name.to_string(),
            r#type: format!("{property_type}[]"),
        };
        self.properties.push(property);
        self
    }
}

/// https://github.com/ethereum/EIPs/blob/master/EIPS/eip-712.md#definition-of-typed-structured-data-%F0%9D%95%8A
#[derive(Debug)]
pub enum PropertyType {
    Bool,
    String,
    Int64,
    Uint64,
    Int256,
    Uint256,
    Address,
    Bytes32,
    Custom(String),
}

impl fmt::Display for PropertyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PropertyType::Bool => write!(f, "bool"),
            PropertyType::String => write!(f, "string"),
            PropertyType::Int64 => write!(f, "int64"),
            PropertyType::Uint64 => write!(f, "uint64"),
            PropertyType::Int256 => write!(f, "int256"),
            PropertyType::Uint256 => write!(f, "uint256"),
            PropertyType::Address => write!(f, "address"),
            PropertyType::Bytes32 => write!(f, "bytes32"),
            PropertyType::Custom(custom) => write!(f, "{custom}"),
        }
    }
}

#[derive(Debug, Serialize)]
struct ObjectProperty {
    name: String,
    r#type: String,
}

type ObjectPropertiesRef<'a> = &'a [ObjectProperty];

#[derive(Debug, Serialize)]
struct SignTypedDataV4Request<'a, Domain, SignData> {
    types: HashMap<&'a str, ObjectPropertiesRef<'a>>,
    domain: Domain,
    #[serde(rename = "primaryType")]
    primary_type: String,
    message: SignData,
}
