use bigdecimal::BigDecimal;
use chrono::prelude::*;
use common::executor::Timer;
use common::wio::slurp_reqʹ;
use futures::future::{select, Either};
use gstuff::binprint;
use http;
use http::request::Builder;
use rpc::v1::types::{Bytes as BytesJson};
use serde::{Serialize};
use serde::de::{DeserializeOwned};
use serde_json::{self as json, Value as Json};
use std::convert::TryFrom;
use std::ops::Deref;
use std::str::FromStr;
use std::sync::Arc;
use crate::tezos::{TezosValue, TezosUint};
use num_bigint::BigUint;

#[derive(Debug)]
pub struct TezosRpcClientImpl {
    uris: Vec<http::Uri>,
}

#[derive(Clone, Debug)]
pub struct TezosRpcClient(Arc<TezosRpcClientImpl>);

impl Deref for TezosRpcClient {type Target = TezosRpcClientImpl; fn deref (&self) -> &TezosRpcClientImpl {&*self.0}}

async fn tezos_req<I: Serialize, O: DeserializeOwned + std::fmt::Debug + Send + 'static>(
    base_uris: &[http::Uri],
    path: &str,
    method: http::Method,
    body: I,
) -> Result<O, Vec<String>> {
    let body = if method != http::Method::GET {
        json::to_vec(&body).map_err(|e| vec![ERRL!("{}", e)])?
    } else {
        vec![]
    };
    let mut errors = Vec::new();
    for uri in base_uris.iter() {
        let resulting_uri = format!("{}{}", uri, path);
        let req = Builder::new()
            .method(method.clone())
            .uri(resulting_uri)
            .body(body.clone())
            .map_err(|e| vec![ERRL!("{}", e)])?;
        let timeout = Timer::sleep(60.);
        let req = Box::pin(slurp_reqʹ(req));
        let rc = select(req, timeout).await;
        let res = match rc {
            Either::Left((r, _t)) => r,
            Either::Right((_t, _r)) => {errors.push(ERRL!("timeout")); continue}
        };
        let (status, _headers, body) = match res {Ok(r) => r, Err(err) => {errors.push(err); continue}};
        if !status.is_success() {errors.push(ERRL!("!200: {}, {}", status, binprint(&body, b'.'))); continue}
        match json::from_slice(&body) {
            Ok(b) => {
                return Ok(b)
            },
            Err(e) => {
                errors.push(ERRL!("!deserialize: {}, {}", e, binprint(&body, b'.')));
                continue
            }
        }
    }
    Err(errors)
}

#[derive(Debug, Deserialize)]
pub struct BlockHeader {
    pub protocol: String,
    pub chain_id: String,
    pub hash: String,
    pub level: u64,
    proto: u64,
    predecessor: String,
    pub timestamp: DateTime<Utc>,
    validation_pass: u64,
    operations_hash: String,
    fitness: Vec<String>,
    context: String,
    priority: Option<u64>,
    proof_of_work_nonce: Option<String>,
    seed_nonce_hash: Option<String>,
    signature: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Origination {
    pub balance: TezosUint,
    pub counter: TezosUint,
    pub fee: TezosUint,
    pub gas_limit: TezosUint,
    pub source: String,
    pub storage_limit: TezosUint,
    pub script: Json,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TransactionParameters {
    pub entrypoint: String,
    pub value: TezosValue,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Transaction {
    pub amount: TezosUint,
    pub counter: TezosUint,
    pub destination: String,
    pub fee: TezosUint,
    pub gas_limit: TezosUint,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<TransactionParameters>,
    pub source: String,
    pub storage_limit: TezosUint,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Reveal {
    pub counter: TezosUint,
    pub fee: TezosUint,
    pub gas_limit: TezosUint,
    pub public_key: String,
    pub source: String,
    pub storage_limit: TezosUint,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ActivateAccount {
    pkh: String,
    secret: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Endorsement {
    level: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind")]
pub enum Operation {
    activate_account(ActivateAccount),
    endorsement(Endorsement),
    reveal(Reveal),
    origination(Origination),
    transaction(Transaction),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperationResult {
    #[serde(flatten)]
    pub op: Operation,
    pub metadata: OperationMetadata,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperationsResult {
    protocol: String,
    chain_id: String,
    hash: String,
    pub branch: String,
    pub contents: Vec<OperationResult>,
    pub signature: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ForgeOperationsRequest {
    pub branch: String,
    pub contents: Vec<Operation>
}

#[derive(Debug, Serialize)]
pub struct PreapplyOperation {
    pub branch: String,
    pub contents: Vec<Operation>,
    pub protocol: String,
    pub signature: String,
}

#[derive(Debug, Serialize)]
pub struct PreapplyOperationsRequest(pub Vec<PreapplyOperation>);

#[derive(Debug, Serialize)]
pub struct TezosInputType {
    pub prim: String,
}

#[derive(Debug, Serialize)]
pub struct BigMapReq {
    pub r#type: TezosInputType,
    pub key: TezosValue,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ManagerKeyRes {
    pub manager: String,
    pub key: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum Status {
    applied,
    backtracked,
    failed,
    skipped,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperationStatus {
    pub status: Status,
    pub originated_contracts: Option<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OperationMetadata {
    pub operation_result: Option<OperationStatus>,
}

impl TezosRpcClientImpl {
    pub fn new(urls: Vec<String>) -> Result<Self, String> {
        let mut uris = vec![];
        for url in urls.iter() {
            uris.push(try_s!(url.parse()));
        }
        Ok(TezosRpcClientImpl {
            uris,
        })
    }

    pub async fn block_header(&self, block_id: &str) -> Result<BlockHeader, String> {
        let path = format!("/chains/main/blocks/{}/header", block_id);
        tezos_req(&self.uris, &path, http::Method::GET, ()).await.map_err(|e| ERRL!("{:?}", e))
    }

    pub async fn blocks(&self, min_date: Option<i64>, length: Option<u64>, head: Option<&str>) -> Result<Vec<String>, String> {
        let mut path = "/chains/main/blocks/".to_owned();
        let mut params = vec![];
        if let Some(min_date) = min_date {
            params.push(format!("min_date={}", min_date));
        }
        if let Some(length) = length {
            params.push(format!("length={}", length));
        }
        if let Some(head) = head {
            params.push(format!("head={}", head));
        }
        path.push_str(&build_url_params_string(params));
        let hashes: Vec<Vec<String>> = try_s!(tezos_req(&self.uris, &path, http::Method::GET, ()).await.map_err(|e| ERRL!("{:?}", e)));
        Ok(hashes.into_iter().flatten().collect())
    }

    pub async fn counter(&self, addr: &str) -> Result<BigUint, String> {
        let path = format!("/chains/main/blocks/head/context/contracts/{}/counter", addr);
        let res: String = try_s!(tezos_req(&self.uris, &path, http::Method::GET, ()).await.map_err(|e| ERRL!("{:?}", e)));
        BigUint::from_str(&res).map_err(|e| ERRL!("{}", e))
    }

    pub async fn forge_operations(&self, chain_id: &str, block_id: &str, req: ForgeOperationsRequest) -> Result<BytesJson, String> {
        let path = format!("/chains/{}/blocks/{}/helpers/forge/operations", chain_id, block_id);
        tezos_req(&self.uris, &path, http::Method::POST, req).await.map_err(|e| ERRL!("{:?}", e))
    }

    pub async fn get_balance(&self, addr: &str) -> Result<BigDecimal, String> {
        let path = format!("/chains/main/blocks/head/context/contracts/{}/balance", addr);
        tezos_req(&self.uris, &path, http::Method::GET, ()).await.map_err(|e| ERRL!("{:?}", e))
    }

    pub async fn get_big_map<T: TryFrom<TezosValue>>(&self, addr: &str, req: BigMapReq) -> Result<Option<T>, String>
        where T::Error: std::fmt::Display
    {
        let path = format!("/chains/main/blocks/head/context/contracts/{}/big_map_get", addr);
        let value: Json = try_s!(tezos_req(&self.uris, &path, http::Method::POST, req).await.map_err(|e| ERRL!("{:?}", e)));
        if value == Json::Null {
            Ok(None)
        } else {
            let value: TezosValue = try_s!(json::from_value(value));
            Ok(Some(try_s!(T::try_from(value))))
        }
    }

    pub async fn get_storage<T: TryFrom<TezosValue>>(&self, addr: &str) -> Result<T, String>
        where T::Error: std::fmt::Display
    {
        let path = format!("/chains/main/blocks/head/context/contracts/{}/storage", addr);
        let value: TezosValue = try_s!(tezos_req(&self.uris, &path, http::Method::GET, ()).await.map_err(|e| ERRL!("{:?}", e)));
        Ok(try_s!(T::try_from(value)))
    }

    pub async fn inject_operation(&self, bytes: &str) -> Result<String, String> {
        let path = format!("/injection/operation");
        tezos_req(&self.uris, &path, http::Method::POST, bytes).await.map_err(|e| ERRL!("{:?}", e))
    }

    pub async fn manager_key(&self, contract_id: &str) -> Result<ManagerKeyRes, String> {
        let path = format!("/chains/main/blocks/head/context/contracts/{}/manager_key", contract_id);
        tezos_req(&self.uris, &path, http::Method::GET, ()).await.map_err(|e| ERRL!("{:?}", e))
    }

    pub async fn operation_hashes(&self, block_id: &str) -> Result<Vec<Vec<String>>, String> {
        let path = format!("/chains/main/blocks/{}/operation_hashes", block_id);
        tezos_req(&self.uris, &path, http::Method::GET, ()).await.map_err(|e| ERRL!("{:?}", e))
    }

    pub async fn operations(&self, block_id: &str) -> Result<Vec<OperationsResult>, String> {
        let path = format!("/chains/main/blocks/{}/operations", block_id);
        let hashes: Vec<Vec<OperationsResult>> = try_s!(tezos_req(&self.uris, &path, http::Method::GET, ()).await.map_err(|e| ERRL!("{:?}", e)));
        Ok(hashes.into_iter().flatten().collect())
    }

    pub async fn single_operation(&self, block_id: &str, validation: usize, offset: usize) -> Result<OperationsResult, String> {
        let path = format!("/chains/main/blocks/{}/operations/{}/{}", block_id, validation, offset);
        tezos_req(&self.uris, &path, http::Method::GET, ()).await.map_err(|e| ERRL!("{:?}", e))
    }

    pub async fn preapply_operations(&self, req: PreapplyOperationsRequest) -> Result<Json, String> {
        let path = "/chains/main/blocks/head/helpers/preapply/operations";
        tezos_req(&self.uris, &path, http::Method::POST, req).await.map_err(|e| ERRL!("{:?}", e))
    }
}

impl TezosRpcClient {
    pub fn new(urls: Vec<String>) -> Result<Self, String> {
        Ok(TezosRpcClient(Arc::new(try_s!(TezosRpcClientImpl::new(urls)))))
    }
}

fn build_url_params_string(input: Vec<String>) -> String {
    if input.len() > 0 {
        let mut res = "?".to_owned();
        res.push_str(&input.join("&"));
        res
    } else {
        "".into()
    }
}

#[test]
fn test_build_url_params_string() {
    let params = vec!["param=value".into()];
    let expected = "?param=value";
    let actual = build_url_params_string(params);
    assert_eq!(expected, actual);

    let params = vec![];
    let expected = "";
    let actual = build_url_params_string(params);
    assert_eq!(expected, actual);

    let params = vec!["param=value".into(), "param1=value".into()];
    let expected = "?param=value&param1=value";
    let actual = build_url_params_string(params);
    assert_eq!(expected, actual);
}
