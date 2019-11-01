use bigdecimal::BigDecimal;
use chrono::prelude::*;
use common::block_on;
use common::executor::Timer;
use common::wio::slurp_reqʹ;
use futures::future::{select, Either};
use gstuff::binprint;
use http;
use http::request::Builder;
use rpc::v1::types::{Bytes as BytesJson};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{self as json, Value as Json};
use std::convert::TryFrom;
use std::ops::Deref;
use std::sync::Arc;
use crate::tezos::TezosRpcValue;

#[derive(Debug)]
pub struct TezosRpcClientImpl {
    uris: Vec<http::Uri>,
}

#[derive(Clone, Debug)]
pub struct TezosRpcClient(Arc<TezosRpcClientImpl>);

impl Deref for TezosRpcClient {type Target = TezosRpcClientImpl; fn deref (&self) -> &TezosRpcClientImpl {&*self.0}}

async fn tezos_req<I: Serialize, O: DeserializeOwned + Send + 'static>(
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
            Ok(b) => return Ok(b),
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
    timestamp: DateTime<Utc>,
    validation_pass: u64,
    operations_hash: String,
    fitness: Vec<String>,
    context: String,
    priority: Option<u64>,
    proof_of_work_nonce: Option<String>,
    seed_nonce_hash: Option<String>,
    signature: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Operation {
    pub amount: BigDecimal,
    pub counter: BigDecimal,
    pub destination: String,
    pub fee: BigDecimal,
    pub gas_limit: BigDecimal,
    pub kind: String,
    pub source: String,
    pub storage_limit: BigDecimal,
}

#[derive(Debug, Serialize)]
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
    pub key: TezosRpcValue,
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

    pub async fn counter(&self, addr: &str) -> Result<BigDecimal, String> {
        let path = format!("/chains/main/blocks/head/context/contracts/{}/counter", addr);
        tezos_req(&self.uris, &path, http::Method::GET, ()).await.map_err(|e| ERRL!("{:?}", e))
    }

    pub async fn get_balance(&self, addr: &str) -> Result<BigDecimal, String> {
        let path = format!("/chains/main/blocks/head/context/contracts/{}/balance", addr);
        tezos_req(&self.uris, &path, http::Method::GET, ()).await.map_err(|e| ERRL!("{:?}", e))
    }

    pub async fn get_storage<T: TryFrom<TezosRpcValue>>(&self, addr: &str) -> Result<T, String>
        where T::Error: std::fmt::Display
    {
        let path = format!("/chains/main/blocks/head/context/contracts/{}/storage", addr);
        let value: TezosRpcValue = try_s!(tezos_req(&self.uris, &path, http::Method::GET, ()).await.map_err(|e| ERRL!("{:?}", e)));
        Ok(try_s!(T::try_from(value)))
    }

    pub async fn get_big_map<T: TryFrom<TezosRpcValue>>(&self, addr: &str, req: BigMapReq) -> Result<T, String>
        where T::Error: std::fmt::Display
    {
        let path = format!("/chains/main/blocks/head/context/contracts/{}/big_map_get", addr);
        let value: TezosRpcValue = try_s!(tezos_req(&self.uris, &path, http::Method::POST, req).await.map_err(|e| ERRL!("{:?}", e)));
        Ok(try_s!(T::try_from(value)))
    }

    pub async fn forge_operations(&self, chain_id: &str, block_id: &str, req: ForgeOperationsRequest) -> Result<BytesJson, String> {
        let path = format!("/chains/{}/blocks/{}/helpers/forge/operations", chain_id, block_id);
        log!((json::to_string(&req).unwrap()));
        tezos_req(&self.uris, &path, http::Method::POST, req).await.map_err(|e| ERRL!("{:?}", e))
    }

    pub async fn inject_operation(&self, bytes: &str) -> Result<String, String> {
        let path = format!("/injection/operation");
        tezos_req(&self.uris, &path, http::Method::POST, bytes).await.map_err(|e| ERRL!("{:?}", e))
    }

    pub async fn preapply_operations(&self, req: PreapplyOperationsRequest) -> Result<Json, String> {
        let path = "/chains/main/blocks/head/helpers/preapply/operations";
        log!((json::to_string(&req).unwrap()));
        tezos_req(&self.uris, &path, http::Method::POST, req).await.map_err(|e| ERRL!("{:?}", e))
    }
}

impl TezosRpcClient {
    pub fn new(urls: Vec<String>) -> Result<Self, String> {
        Ok(TezosRpcClient(Arc::new(try_s!(TezosRpcClientImpl::new(urls)))))
    }
}
